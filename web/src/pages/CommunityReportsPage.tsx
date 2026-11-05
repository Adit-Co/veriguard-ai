import {
  ArrowRight,
  CheckCircle2,
  Clock3,
  MessageSquareWarning,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react'
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from 'react'
import { Link, Navigate, useSearchParams } from 'react-router-dom'
import { CopyUrlButton } from '../components/community/CopyUrlButton'
import { MaskedReporterName } from '../components/community/MaskedReporterName'
import { Alert } from '../components/ui/Alert'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { buttonStyles } from '../components/ui/buttonStyles'
import { Card } from '../components/ui/Card'
import { Container } from '../components/ui/Container'
import { Input } from '../components/ui/Input'
import { PageHeader } from '../components/ui/PageHeader'
import { Select } from '../components/ui/Select'
import { Textarea } from '../components/ui/Textarea'
import { useAuth } from '../lib/auth/useAuth'
import { VERIFICATION_EMAIL_PATH } from '../lib/auth/verification'
import {
  CommunityServiceError,
  communityErrorMessage,
  listLatestCommunityReports,
  submitCommunityReport,
} from '../lib/community/communityService'
import {
  COMMUNITY_CATEGORIES,
  COMMUNITY_CATEGORY_LABELS,
  COMMUNITY_DAILY_LIMIT_MESSAGE,
  COMMUNITY_LATEST_EMPTY_MESSAGE,
  MAX_REPORT_REASON_LENGTH,
  MIN_REPORT_REASON_LENGTH,
  type CommunityCategory,
  type CommunityLatestReportEntry,
  type SubmitCommunityReportResult,
} from '../lib/community/types'
import {
  COMMUNITY_DAILY_FEED_LIMIT,
  communityDailyFeedDayId,
  msUntilNextCommunityFeedDay,
} from '../lib/community/sparkProtocol'
import {
  CommunityUrlError,
  normalizeCommunityUrl,
  sanitizeCommunityUrlForDisplay,
} from '../lib/community/url'
import { isFirebaseConfigured } from '../lib/firebase/config'
import { loadPublicModerationStatuses } from '../lib/moderation/moderationService'
import {
  MODERATION_PUBLIC_CAVEAT,
  MODERATION_STATUS_META,
  MODERATION_UNREVIEWED_LABEL,
  type PublicModerationStatus,
} from '../lib/moderation/types'
import { cn } from '../lib/cn'

const dateTimeFormatter = new Intl.DateTimeFormat('id-ID', {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  timeZone: 'Asia/Makassar',
})

type FieldErrors = Partial<Record<'url' | 'category' | 'reason', string>>

function formatDateTime(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'waktu tidak diketahui'
  return `${dateTimeFormatter.format(date)} WITA`
}

function latestReportsErrorMessage(error: unknown): string {
  if (error instanceof CommunityServiceError && error.code === 'permission-denied') {
    return 'Laporan komunitas sedang mengalami kendala saat dimuat. Silakan coba lagi.'
  }
  return communityErrorMessage(error)
}

type ModerationLookupState = 'idle' | 'loading' | 'ready'

function PublicModerationBadge({
  status,
  lookupState,
  unavailable,
}: {
  status: PublicModerationStatus | undefined
  lookupState: ModerationLookupState
  unavailable: boolean
}) {
  if (lookupState !== 'ready') {
    return <Badge tone="neutral">Memeriksa status…</Badge>
  }
  if (status) {
    const meta = MODERATION_STATUS_META[status.status]
    return <Badge tone={meta.tone}>{meta.label}</Badge>
  }
  if (unavailable) {
    return <Badge tone="medium">Status tidak tersedia</Badge>
  }
  return <Badge tone="neutral">{MODERATION_UNREVIEWED_LABEL}</Badge>
}

function LatestReportRow({
  entry,
  status,
  lookupState,
  unavailable,
}: {
  entry: CommunityLatestReportEntry
  status: PublicModerationStatus | undefined
  lookupState: ModerationLookupState
  unavailable: boolean
}) {
  // Sanitasi ulang di lapisan tampilan agar data lama atau rusak tidak pernah
  // menampilkan kredensial, query, atau fragment meskipun tidak melewati parser.
  const sanitizedUrl = sanitizeCommunityUrlForDisplay(entry.reportedUrl)
  const displayedUrl =
    sanitizedUrl ??
    entry.hostname ??
    'Alamat tidak tersedia pada daftar publik.'

  return (
    <li className="rounded-card border border-line bg-canvas p-4 transition-colors hover:border-line-strong sm:p-5">
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-x-4 gap-y-2">
        <div className="min-w-0">
          <p className="text-base leading-snug font-semibold [overflow-wrap:anywhere] text-ink">
            <MaskedReporterName value={entry.userName} />
          </p>
          <p className="mt-1 flex flex-wrap items-center gap-1 text-xs text-ink-muted">
            <Clock3 size={12} aria-hidden="true" className="shrink-0" />
            {formatDateTime(entry.createdAt)}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <Badge tone="neutral">{COMMUNITY_CATEGORY_LABELS[entry.category]}</Badge>
          <PublicModerationBadge
            status={status}
            lookupState={lookupState}
            unavailable={unavailable}
          />
        </div>
      </div>

      <div className="mt-3 min-w-0 rounded-btn border border-line bg-surface px-3 py-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs text-ink-muted">
            <span className="font-medium">Alamat yang dilaporkan</span>
            <span> · sudah disanitasi</span>
          </p>
          {sanitizedUrl ? <CopyUrlButton value={sanitizedUrl} variant="ghost" /> : null}
        </div>
        <p className="mt-1 min-w-0 break-all font-mono text-[13px] leading-relaxed text-ink-soft">
          {displayedUrl}
        </p>
      </div>

      {status?.updatedAt ? (
        <p className="type-caption mt-2">
          Status moderasi diperbarui {formatDateTime(status.updatedAt)}
        </p>
      ) : null}
    </li>
  )
}

export function CommunityReportsPage() {
  const auth = useAuth()
  const [searchParams] = useSearchParams()
  const queryUrl = searchParams.get('url') ?? ''
  const [url, setUrl] = useState(queryUrl)
  const [category, setCategory] = useState<CommunityCategory | ''>('')
  const [reason, setReason] = useState('')
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [dailyLimitReached, setDailyLimitReached] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [submitted, setSubmitted] = useState<SubmitCommunityReportResult | null>(null)
  const [latestReports, setLatestReports] = useState<CommunityLatestReportEntry[]>([])
  const [moderationStatuses, setModerationStatuses] = useState<
    Map<string, PublicModerationStatus>
  >(() => new Map())
  const [moderationLookup, setModerationLookup] =
    useState<ModerationLookupState>('idle')
  const [moderationUnavailable, setModerationUnavailable] = useState(false)
  const [listStatus, setListStatus] = useState<'idle' | 'loading' | 'ready' | 'error' | 'blocked'>(
    'idle',
  )
  const [listError, setListError] = useState<string | null>(null)
  const [listErrorCode, setListErrorCode] = useState<string | null>(null)
  const listRequestId = useRef(0)
  const moderationRequestId = useRef(0)
  const loadedDayRef = useRef<string | null>(null)

  const signedInUser =
    auth.mode === 'firebase' && auth.user && !auth.user.isAnonymous ? auth.user : null
  const firebaseUser = signedInUser?.emailVerified ? signedInUser : null
  const firebaseUid = firebaseUser?.uid ?? null
  const unverifiedUser = signedInUser && !signedInUser.emailVerified ? signedInUser : null
  const demoMode = auth.mode === 'demo'
  const sessionKnown = auth.status === 'ready' && auth.mode === 'firebase'
  const returnTo = `/komunitas${url.trim() ? `?url=${encodeURIComponent(url.trim())}` : ''}`

  const normalizedPreview = useMemo(() => {
    if (!url.trim()) return null
    try {
      return normalizeCommunityUrl(url)
    } catch {
      return null
    }
  }, [url])

  const listBlocked = (sessionKnown || demoMode) && !firebaseUser
  const listActionDisabled =
    !firebaseUser || auth.status !== 'ready' || listStatus === 'loading'

  const loadModerationStatuses = useCallback(
    async (entries: CommunityLatestReportEntry[]) => {
      const ids = entries
        .slice(0, COMMUNITY_DAILY_FEED_LIMIT)
        .map((entry) => entry.id)
      const request = ++moderationRequestId.current

      setModerationStatuses(new Map())
      setModerationUnavailable(false)

      if (ids.length === 0) {
        setModerationLookup('ready')
        return
      }

      setModerationLookup('loading')
      try {
        const lookup = await loadPublicModerationStatuses(ids)
        if (request !== moderationRequestId.current) return
        setModerationStatuses(lookup.statuses)
        setModerationUnavailable(lookup.unavailable)
        setModerationLookup('ready')
      } catch {
        if (request !== moderationRequestId.current) return
        // Kegagalan status tidak boleh berubah menjadi label "Belum diverifikasi";
        // status yang tidak terbaca ditandai tidak tersedia.
        setModerationStatuses(new Map())
        setModerationUnavailable(true)
        setModerationLookup('ready')
      }
    },
    [],
  )

  const loadList = useCallback(
    async (forceRefresh = false) => {
      if (!firebaseUser) {
        setListStatus('blocked')
        return
      }

      const current = ++listRequestId.current
      const requestedDay = communityDailyFeedDayId()
      moderationRequestId.current += 1
      setModerationStatuses(new Map())
      setModerationLookup('idle')
      setModerationUnavailable(false)
      setListStatus('loading')
      setListError(null)
      setListErrorCode(null)

      try {
        const reports = await listLatestCommunityReports({ forceRefresh })
        if (current !== listRequestId.current) return
        setLatestReports(reports)
        loadedDayRef.current = requestedDay
        setListStatus('ready')
        void loadModerationStatuses(reports)
      } catch (cause) {
        if (current !== listRequestId.current) return
        setLatestReports([])
        setListStatus('error')
        setListError(latestReportsErrorMessage(cause))
        // Kode teknis yang aman disimpan sebagai atribut, bukan teks publik, agar
        // kegagalan dapat didiagnosis tanpa membocorkan detail akun atau data.
        setListErrorCode(cause instanceof CommunityServiceError ? cause.code : 'unknown')
      }
    },
    [firebaseUser, loadModerationStatuses],
  )

  // Pergantian akun tidak boleh menyisakan umpan atau status dari akun sebelumnya.
  // Permintaan yang sedang berjalan juga dibatalkan agar hasilnya tidak dipasang
  // setelah sesi baru aktif.
  useEffect(() => {
    listRequestId.current += 1
    moderationRequestId.current += 1
    // oxlint-disable-next-line react/set-state-in-effect -- reset data milik akun sebelumnya
    setLatestReports([])
    setModerationStatuses(new Map())
    setModerationLookup('idle')
    setModerationUnavailable(false)
    setListError(null)
    setListErrorCode(null)
    setListStatus(firebaseUid ? 'idle' : 'blocked')
    loadedDayRef.current = null
  }, [firebaseUid])

  // Satu timer menuju pergantian hari WITA berikutnya; bukan interval polling.
  // Timer dijadwalkan ulang hanya setelah tanggal berganti.
  useEffect(() => {
    if (!firebaseUser) return

    let timer = 0
    const schedule = () => {
      timer = window.setTimeout(() => {
        if (loadedDayRef.current !== null) void loadList(true)
        schedule()
      }, msUntilNextCommunityFeedDay() + 1_000)
    }
    schedule()

    return () => window.clearTimeout(timer)
  }, [firebaseUser, loadList])

  // Tab yang tidur melewati tengah malam tidak selalu menjalankan timer tepat waktu.
  // Saat terlihat kembali, daftar hanya dimuat ulang bila tanggal WITA sudah berganti.
  useEffect(() => {
    if (!firebaseUser) return

    const handleVisibility = () => {
      if (document.visibilityState !== 'visible') return
      if (loadedDayRef.current === null) return
      if (loadedDayRef.current !== communityDailyFeedDayId()) void loadList(true)
    }

    document.addEventListener('visibilitychange', handleVisibility)
    return () => document.removeEventListener('visibilitychange', handleVisibility)
  }, [firebaseUser, loadList])

  const visibleReports = useMemo(
    () => latestReports.slice(0, COMMUNITY_DAILY_FEED_LIMIT),
    [latestReports],
  )

  function clearFieldError(field: keyof FieldErrors) {
    setFieldErrors((current) => {
      if (!current[field]) return current
      const next = { ...current }
      delete next[field]
      return next
    })
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting) return

    setFormError(null)
    setSubmitted(null)
    setDailyLimitReached(false)

    // Lapisan kedua: halaman tanpa konfigurasi Firebase tidak punya halaman masuk untuk
    // dituju, jadi pengiriman tetap diblokir sebelum menyentuh backend.
    if (unverifiedUser) {
      setFormError(
        'Verifikasi email akun terlebih dahulu agar laporan dapat dikirim.',
      )
      return
    }
    if (!firebaseUser) {
      setFormError(
        demoMode
          ? 'Sesi demo lokal tidak dapat mengirim laporan. Masuk dengan akun email untuk melapor.'
          : 'Masuk dengan akun untuk mengirim laporan.',
      )
      return
    }

    const errors: FieldErrors = {}
    let normalizedUrl = ''

    try {
      normalizedUrl = normalizeCommunityUrl(url)
    } catch (cause) {
      errors.url =
        cause instanceof CommunityUrlError ? cause.message : 'Format URL tidak valid.'
    }

    if (!category) {
      errors.category = 'Pilih kategori yang paling sesuai.'
    }

    const trimmedReason = reason.trim()
    if (trimmedReason.length < MIN_REPORT_REASON_LENGTH) {
      errors.reason = `Alasan minimal ${MIN_REPORT_REASON_LENGTH} karakter.`
    } else if (trimmedReason.length > MAX_REPORT_REASON_LENGTH) {
      errors.reason = `Alasan maksimal ${MAX_REPORT_REASON_LENGTH} karakter.`
    }

    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors)
      return
    }

    setFieldErrors({})
    setSubmitting(true)

    try {
      const result = await submitCommunityReport({
        url: normalizedUrl,
        category: category as CommunityCategory,
        reason: trimmedReason,
      })
      setSubmitted(result)
      setUrl(normalizedUrl)
      void loadList(true)
    } catch (cause) {
      // Batas harian adalah status ramah, bukan kegagalan: pesan bakunya dipakai dan tidak
      // ada laporan kedua yang dibuat. Kegagalan layanan tetap punya pesan sendiri.
      if (cause instanceof CommunityServiceError && cause.dailyLimitReached) {
        setDailyLimitReached(true)
      } else {
        setFormError(communityErrorMessage(cause))
      }
    } finally {
      setSubmitting(false)
    }
  }

  // §2: sesi yang tidak berhak melapor dialihkan ke halaman masuk milik aplikasi, dengan
  // alamat balik yang sudah didukung halaman masuk. Akun yang sudah masuk tetapi belum
  // memverifikasi email tidak dialihkan; mereka mendapat status verifikasi yang jelas.
  if (sessionKnown && !signedInUser) {
    return <Navigate to="/masuk" replace state={{ from: returnTo }} />
  }

  return (
    <Container className="pb-16 sm:pb-20">
      <PageHeader
        eyebrow="Komunitas"
        title="Community Reports"
        description="Bagikan indikasi penipuan yang kamu temui dan lihat konteks dari pengguna lain. Laporan komunitas bersifat tambahan, bukan vonis otomatis."
        actions={
          <a href="#community-report-form" className={buttonStyles({ size: 'md' })}>
            <MessageSquareWarning size={16} aria-hidden="true" />
            Laporkan URL
          </a>
        }
      />

      {!isFirebaseConfigured ? (
        <Alert tone="warning" className="mt-6" title="Layanan akun belum tersedia">
          Halaman ini memerlukan layanan akun dan penyimpanan data. Tanpa keduanya, laporan tidak
          dapat dimuat atau dikirim.
        </Alert>
      ) : null}

      {sessionKnown && unverifiedUser ? (
        <Alert tone="warning" className="mt-6" title="Verifikasi email diperlukan">
          <p>
            Community Reports hanya dapat dibaca dan dikirim oleh akun dengan email terverifikasi.
          </p>
          <Link
            to={VERIFICATION_EMAIL_PATH}
            state={{ from: returnTo }}
            className="mt-2 inline-block font-medium text-accent hover:underline"
          >
            Verifikasi email akun
          </Link>
        </Alert>
      ) : null}

      {auth.status === 'error' ? (
        <Alert tone="danger" className="mt-6" title="Layanan akun gagal disiapkan">
          {auth.initializationError ??
            'Layanan akun belum dapat disiapkan. Muat ulang halaman atau hubungi pengelola layanan.'}
        </Alert>
      ) : null}

      {auth.status === 'loading' ? (
        <Alert tone="info" className="mt-6" title="Memulihkan sesi">
          Tunggu sebentar. Formulir dapat dibaca, tetapi pengiriman laporan dinonaktifkan sampai
          status akun diketahui.
        </Alert>
      ) : null}

      {demoMode ? (
        <Alert tone="warning" className="mt-6" title="Sesi demo lokal tidak dapat melapor">
          Laporan komunitas memerlukan akun sungguhan agar tidak dapat disalahgunakan secara
          anonim. Halaman ini memakai login akun bila layanan akun tersedia.
        </Alert>
      ) : null}

      <div className="mt-8 grid gap-5 lg:grid-cols-[minmax(0,1.05fr)_minmax(320px,0.95fr)] lg:items-start">
        <Card
          id="community-report-form"
          className="scroll-mt-24 p-5 sm:p-6"
          aria-labelledby="community-form-title"
        >
          <div className="flex items-start gap-3">
            <span className="grid size-9 shrink-0 place-items-center rounded-full bg-accent-soft text-accent">
              <ShieldAlert size={18} aria-hidden="true" />
            </span>
            <div>
              <h2 id="community-form-title" className="type-h3">
                Laporkan URL
              </h2>
              <p className="type-small mt-1 text-ink-soft">
                Setiap akun dapat mengirim satu laporan per hari. Batas ini berlaku untuk semua
                URL, dan laporan yang sudah dikirim tidak dapat diubah atau dikirim ulang pada
                hari yang sama.
              </p>
            </div>
          </div>

          {submitted ? (
            <Alert tone="success" role="status" className="mt-5" title="Laporan tercatat">
              <p>
                Terima kasih. Laporanmu tersimpan dan tidak menimpa laporan sebelumnya.
              </p>
              <p className="mt-2">
                {submitted.summary
                  ? `Total laporan aktif: ${submitted.summary.reportCount.toLocaleString('id-ID')}.`
                  : 'Jumlah laporan aktif belum dapat dimuat, tetapi laporanmu sudah tersimpan.'}
              </p>
            </Alert>
          ) : null}

          {dailyLimitReached ? (
            <Alert
              tone="info"
              role="status"
              className="mt-5"
              title="Pelaporan harian sudah terpakai"
            >
              <p>{COMMUNITY_DAILY_LIMIT_MESSAGE}</p>
              <p className="mt-2">
                Laporanmu yang sebelumnya tetap tersimpan dan tidak diubah. Kamu dapat mengirim
                laporan baru lagi pada hari berikutnya.
              </p>
            </Alert>
          ) : null}

          {formError ? (
            <Alert tone="danger" role="alert" className="mt-5" title="Laporan belum terkirim">
              <p>{formError}</p>
              {unverifiedUser ? (
                <Link
                  to={VERIFICATION_EMAIL_PATH}
                  state={{ from: returnTo }}
                  className="mt-2 inline-block font-medium text-accent hover:underline"
                >
                  Verifikasi email akun
                </Link>
              ) : !firebaseUser ? (
                <Link
                  to="/masuk"
                  state={{ from: returnTo }}
                  className="mt-2 inline-block font-medium text-accent hover:underline"
                >
                  Masuk dengan email
                </Link>
              ) : null}
            </Alert>
          ) : null}

          <form className="mt-5" onSubmit={handleSubmit} noValidate>
            <label htmlFor="community-url" className="text-sm font-medium text-ink">
              URL yang dilaporkan
            </label>
            <Input
              id="community-url"
              name="url"
              type="text"
              inputMode="url"
              autoComplete="url"
              placeholder="https://contoh.com/halaman"
              value={url}
              onChange={(event) => {
                setUrl(event.target.value)
                clearFieldError('url')
              }}
              aria-invalid={Boolean(fieldErrors.url)}
              aria-describedby="community-url-help"
              className={cn('mt-1.5', fieldErrors.url && 'border-risk-high')}
            />
            <div id="community-url-help" className="mt-2">
              {fieldErrors.url ? (
                <p className="text-sm text-risk-high" role="alert">
                  {fieldErrors.url}
                </p>
              ) : normalizedPreview ? (
                <p className="type-caption break-all">
                  Identitas laporan: <span className="font-mono">{normalizedPreview}</span>
                </p>
              ) : (
                <p className="type-caption">
                  Gunakan alamat publik http atau https. Alamat lokal/privat dan parameter
                  pelacak tidak dilaporkan.
                </p>
              )}
            </div>

            <label
              htmlFor="community-category"
              className="mt-4 block text-sm font-medium text-ink"
            >
              Kategori
            </label>
            <Select
              id="community-category"
              name="category"
              value={category}
              onChange={(event) => {
                setCategory(event.target.value as CommunityCategory | '')
                clearFieldError('category')
              }}
              aria-invalid={Boolean(fieldErrors.category)}
              className={cn('mt-1.5', fieldErrors.category && 'border-risk-high')}
            >
              <option value="">Pilih kategori</option>
              {COMMUNITY_CATEGORIES.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </Select>
            {fieldErrors.category ? (
              <p className="mt-2 text-sm text-risk-high" role="alert">
                {fieldErrors.category}
              </p>
            ) : null}

            <div className="mt-4 flex items-baseline justify-between gap-3">
              <label htmlFor="community-reason" className="text-sm font-medium text-ink">
                Alasan singkat
              </label>
              <span className="type-caption tabular-nums" aria-live="polite">
                {reason.length}/{MAX_REPORT_REASON_LENGTH}
              </span>
            </div>
            <Textarea
              id="community-reason"
              name="reason"
              placeholder="Jelaskan apa yang mencurigakan tanpa menuliskan data pribadi, kata sandi, atau kode OTP."
              maxLength={MAX_REPORT_REASON_LENGTH}
              value={reason}
              onChange={(event) => {
                setReason(event.target.value)
                clearFieldError('reason')
              }}
              aria-invalid={Boolean(fieldErrors.reason)}
              aria-describedby="community-reason-help"
              className={cn('mt-1.5 min-h-28', fieldErrors.reason && 'border-risk-high')}
            />
            <div id="community-reason-help" className="mt-2">
              {fieldErrors.reason ? (
                <p className="text-sm text-risk-high" role="alert">
                  {fieldErrors.reason}
                </p>
              ) : (
                <p className="type-caption">
                  Jangan sertakan nama, email, nomor telepon, kata sandi, atau OTP. Jangan tuduh
                  tanpa bukti.
                </p>
              )}
            </div>

            <div className="mt-5 flex flex-wrap items-center gap-3">
              <Button type="submit" disabled={submitting || auth.status === 'loading'}>
                {submitting
                  ? 'Mengirim…'
                  : firebaseUser
                    ? 'Kirim laporan'
                    : unverifiedUser
                      ? 'Verifikasi email untuk mengirim'
                      : 'Masuk untuk mengirim'}
                {!submitting ? <ArrowRight size={15} aria-hidden="true" /> : null}
              </Button>
              <p className="type-caption">
                Laporan baru adalah dugaan pengguna dan belum diverifikasi moderator saat dikirim.
                Laporan dapat muncul di daftar laporan terbaru yang terlihat oleh akun
                terverifikasi lain.
              </p>
            </div>
          </form>

          <div className="mt-6 border-t border-line pt-4">
            <p className="type-caption">
              Laporan tidak membuktikan suatu URL berbahaya. Jangan buka tautan yang mencurigakan
              hanya untuk memverifikasi isinya.
            </p>
          </div>
        </Card>

        <Card className="p-5 sm:p-6" aria-labelledby="community-list-title">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 id="community-list-title" className="type-h3">
                Laporan terbaru
              </h2>
              <p className="type-small mt-1 text-ink-soft">
                Laporan yang dibagikan hari ini menurut WITA, terbaru lebih dulu. Daftar
                berganti saat ada laporan baru masuk.
              </p>
            </div>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                void loadList(listStatus !== 'idle')
              }}
              disabled={listActionDisabled}
            >
              <RefreshCw size={14} aria-hidden="true" />
              {listStatus === 'ready' || listStatus === 'error'
                ? 'Muat ulang'
                : 'Tampilkan laporan'}
            </Button>
          </div>

          <div className="mt-5" aria-live="polite">
            {listStatus === 'idle' && !listBlocked ? (
              <div className="rounded-card border border-dashed border-line bg-subtle/50 p-5">
                <p className="text-sm font-medium text-ink">Daftar belum dimuat</p>
                <p className="type-small mt-1 text-ink-soft">
                  Pilih “Tampilkan laporan” untuk melihat laporan hari ini dari pengguna lain.
                </p>
              </div>
            ) : null}

            {listStatus === 'loading' ? (
              <div className="space-y-3" role="status">
                <div className="h-24 animate-pulse rounded-card bg-subtle" />
                <div className="h-24 animate-pulse rounded-card bg-subtle" />
                <p className="type-caption">Memuat laporan komunitas…</p>
              </div>
            ) : null}

            {listStatus === 'error' ? (
              <Alert
                tone="warning"
                title="Laporan komunitas belum dapat ditampilkan"
                data-error-code={listErrorCode ?? undefined}
              >
                <p>{listError ?? 'Layanan komunitas tidak dapat dihubungi.'}</p>
                <p className="mt-2">
                  Hasil pemindaian tetap dapat digunakan dan tidak menunjukkan bahwa tautan ini
                  aman.
                </p>
                <button
                  type="button"
                  onClick={() => {
                    void loadList(true)
                  }}
                  disabled={listActionDisabled}
                  className="mt-3 text-sm font-medium text-accent hover:underline disabled:cursor-not-allowed disabled:text-ink-muted disabled:no-underline"
                >
                  Coba lagi
                </button>
              </Alert>
            ) : null}

            {listBlocked ? (
              <div className="rounded-card border border-dashed border-line bg-subtle/50 p-5">
                <p className="text-sm font-medium text-ink">Daftar laporan belum dimuat</p>
                <p className="type-small mt-1 text-ink-soft">
                  {unverifiedUser
                    ? 'Laporan komunitas hanya dapat dibaca oleh akun dengan email terverifikasi. Keadaan ini bukan berarti tidak ada laporan, dan bukan penilaian bahwa tautan aman.'
                    : 'Laporan komunitas hanya dibaca setelah sesi akun yang sah diketahui. Keadaan ini bukan berarti tidak ada laporan, dan bukan pula penilaian bahwa tautan aman.'}
                </p>
                {unverifiedUser ? (
                  <Link
                    to={VERIFICATION_EMAIL_PATH}
                    state={{ from: returnTo }}
                    className="mt-2 inline-block text-sm font-medium text-accent hover:underline"
                  >
                    Verifikasi email akun
                  </Link>
                ) : !isFirebaseConfigured ? null : (
                  <Link
                    to="/masuk"
                    state={{ from: returnTo }}
                    className="mt-2 inline-block text-sm font-medium text-accent hover:underline"
                  >
                    Masuk dengan email
                  </Link>
                )}
              </div>
            ) : null}

            {listStatus === 'ready' && visibleReports.length === 0 ? (
              <div className="rounded-card border border-dashed border-line bg-subtle/50 p-5 text-center">
                <CheckCircle2
                  size={22}
                  className="mx-auto text-ink-muted"
                  aria-hidden="true"
                />
                <p className="mt-3 text-sm font-medium text-ink">
                  {COMMUNITY_LATEST_EMPTY_MESSAGE}
                </p>
                <p className="type-small mt-1 text-ink-soft">
                  Laporan yang dibagikan hari ini akan muncul di sini. Ini bukan jaminan bahwa
                  suatu tautan aman.
                </p>
              </div>
            ) : null}

            {listStatus === 'ready' && visibleReports.length > 0 ? (
              <>
                <div className="mb-3 rounded-btn border border-accent/20 bg-info-bg px-3 py-2">
                  <p className="type-caption text-ink-soft">{MODERATION_PUBLIC_CAVEAT}</p>
                </div>

                {moderationUnavailable ? (
                  <Alert
                    tone="warning"
                    className="mb-3"
                    title="Sebagian status moderasi tidak dapat dimuat"
                  >
                    Status yang gagal dibaca ditandai “Status tidak tersedia”, bukan “Belum
                    diverifikasi”. Muat ulang daftar untuk mencoba lagi.
                  </Alert>
                ) : null}

                <div
                  role="region"
                  aria-label="Daftar laporan terbaru"
                  tabIndex={0}
                  className="max-h-[24rem] overflow-y-auto overscroll-contain pr-1"
                >
                  <ul className="flex flex-col gap-2.5">
                    {visibleReports.map((entry) => (
                      <LatestReportRow
                        key={entry.id}
                        entry={entry}
                        status={moderationStatuses.get(entry.id)}
                        lookupState={moderationLookup}
                        unavailable={moderationUnavailable}
                      />
                    ))}
                  </ul>
                </div>
              </>
            ) : null}
          </div>

          <div className="mt-5 flex flex-col gap-2 border-t border-line pt-4">
            <p className="type-caption">
              Nama pelapor ditampilkan secara tersamarkan dan bukan merupakan identitas yang
              terverifikasi. URL dan hostname berasal dari laporan pengguna dan ditampilkan tanpa
              data masuk atau parameter tambahan serta tidak dapat diklik langsung.
            </p>
            <p className="type-caption">
              Status moderasi menunjukkan hasil peninjauan manual oleh moderator. Kecuali berstatus{' '}
              <strong className="font-semibold text-ink-soft">Terverifikasi berbahaya</strong>,
              status tersebut bukan jaminan bahwa tautan aman.
            </p>
            <p className="type-caption">
              Laporan komunitas tidak secara otomatis mengubah skor atau hasil pemeriksaan
              VERIGUARD.
            </p>
          </div>
        </Card>
      </div>
    </Container>
  )
}

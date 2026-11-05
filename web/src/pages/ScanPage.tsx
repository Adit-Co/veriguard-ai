import {
  ArrowRight,
  Globe,
  Link2,
  MessageSquareText,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { AnalysisProgress } from '../components/ui/AnalysisProgress'
import { Alert } from '../components/ui/Alert'
import { LiveScanPanel } from '../components/scan/LiveScanPanel'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { Card } from '../components/ui/Card'
import { Container } from '../components/ui/Container'
import { Input } from '../components/ui/Input'
import { PageHeader } from '../components/ui/PageHeader'
import { SegmentedControl } from '../components/ui/SegmentedControl'
import { Textarea } from '../components/ui/Textarea'
import { analyze, MAX_LINK_LENGTH, MAX_MESSAGE_LENGTH, validateInput } from '../lib/analysis'
import type { ScanMode } from '../lib/analysis'
import { useAuth } from '../lib/auth/useAuth'
import { isVerifiedAccount } from '../lib/auth/verification'
import { firestoreErrorMessage } from '../lib/firebase/errors'
import { getPreferences } from '../lib/preferences/preferences'
import { saveScanForUser } from '../lib/scans/saveScan'
import {
  isMultiSourceEnabled,
  isWorkerConfigured,
  requestExternalScanStream,
} from '../lib/scanners/client'
import { resolveExternalScanRequest } from '../lib/scanners/consent'
import {
  createExternalScanCancelledError,
  externalScanErrorMessage,
  isCaptchaChallenge,
  isExternalScanCancelled,
} from '../lib/scanners/errors'
import { detectSensitiveUrl } from '../lib/scanners/privacy'
import { buildMultiSourceReport } from '../lib/scanners/report'
import { saveScanReport } from '../lib/scanners/reportStore'
import { TURNSTILE_ACTION } from '../lib/turnstile/action'
import { Turnstile } from '../components/turnstile/Turnstile'
import type {
  ExternalProviderId,
  ExternalProviderResult,
  MultiSourceReport,
  ProviderProgress,
  ScanProgressEvent,
  ScanUrlMultiSourceResponse,
} from '../lib/scanners/types'
import { cn } from '../lib/cn'

const MODE_OPTIONS = [
  { value: 'link', label: 'Tautan', icon: Link2 },
  { value: 'message', label: 'Pesan', icon: MessageSquareText },
] as const

const SAMPLES: Record<ScanMode, { label: string; value: string }[]> = {
  link: [
    { label: 'Contoh situs resmi', value: 'https://www.bca.co.id/id/informasi' },
    {
      label: 'Contoh pola phishing',
      value: 'https://bca-verifikasi-akun.example/login',
    },
  ],
  message: [
    {
      label: 'Contoh pesan wajar',
      value: 'Halo, besok kita meeting jam 10 di kantor ya. Jangan lupa bawa laptop.',
    },
    {
      label: 'Contoh pesan penipuan',
      value:
        'Selamat! Anda menang hadiah Rp10.000.000. Kirim kode OTP Anda sekarang ke bit.ly/klaim-hadiah.',
    },
  ],
}

const CHECKED_ITEMS = [
  'Struktur URL, domain, dan subdomain',
  'Kemiripan nama dengan merek resmi',
  'Kata yang mendesak, mengancam, atau meminta data',
  'Permintaan OTP, PIN, pembayaran, dan data pribadi',
  'Reputasi domain di agen eksternal saat tautan diperiksa',
]

// Jenis pemeriksaan yang tersedia pada panel scanner. Bukan hasil dan bukan status agen,
// jadi ikonnya netral dan tidak ada badge seperti "Aman" atau "Aktif".
const SCAN_CHECKS = [
  {
    icon: Link2,
    title: 'Struktur URL',
    description: 'Domain, subdomain, dan bentuk alamat.',
  },
  {
    icon: Globe,
    title: 'Reputasi domain',
    description:
      'Reputasi dari agen eksternal jika tersedia dan jika tautan dikirim untuk diperiksa.',
  },
  {
    icon: ShieldAlert,
    title: 'Indikasi phishing',
    description: 'Kemiripan nama merek dan penggunaan bahasa yang mendesak.',
  },
] as const

// Label tahap yang mengikuti fase backend yang sebenarnya saat agen reputasi dipakai.
const EXTERNAL_PROGRESS_STEPS = [
  'Menyiapkan pemeriksaan',
  'Memeriksa laporan agen keamanan',
  'Menggabungkan hasil dan menyimpan',
] as const

// Lantai presentasi murni untuk UI; tidak menunda permintaan backend maupun panggilan agen.
const MIN_LOADING_VISIBLE_MS = 1_200

function wait(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(createExternalScanCancelledError())
      return
    }

    const onAbort = () => {
      window.clearTimeout(timer)
      reject(createExternalScanCancelledError())
    }
    const timer = window.setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

function ensureScanActive(signal: AbortSignal): void {
  if (signal.aborted) throw createExternalScanCancelledError()
}

function createScanId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID()
  }

  return `scan-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
}

function upsertProvider(
  current: ProviderProgress[],
  next: ProviderProgress,
): ProviderProgress[] {
  const index = current.findIndex((provider) => provider.id === next.id)
  if (index === -1) return [...current, next]
  return current.map((provider) => (provider.id === next.id ? next : provider))
}

function mergeProviderResult(
  current: ExternalProviderResult[],
  next: ExternalProviderResult,
): ExternalProviderResult[] {
  const index = current.findIndex((provider) => provider.id === next.id)
  if (index === -1) return [...current, next]
  return current.map((provider) => (provider.id === next.id ? next : provider))
}

export function ScanPage() {
  const navigate = useNavigate()
  const auth = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()
  const [defaultMode] = useState<ScanMode>(() => getPreferences().defaultScanMode)
  const requestedMode = searchParams.get('mode')
  const mode: ScanMode =
    requestedMode === 'message' || requestedMode === 'link' ? requestedMode : defaultMode

  const [values, setValues] = useState<Record<ScanMode, string>>({ link: '', message: '' })
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [progressStep, setProgressStep] = useState(0)
  const [keepFullMessage, setKeepFullMessage] = useState(false)
  const [liveProviders, setLiveProviders] = useState<ProviderProgress[]>([])
  const [liveSensitive, setLiveSensitive] = useState(false)
  // Tantangan CAPTCHA hanya ada bila layanan memintanya. Bentuknya: URL dan scanId yang
  // sedang menunggu, supaya permintaan asli dapat diulang apa adanya setelah diverifikasi.
  const [captcha, setCaptcha] = useState<{
    url: string
    scanId: string | null
    reason: string
  } | null>(null)
  const [captchaToken, setCaptchaToken] = useState<string | null>(null)
  const [captchaAttempt, setCaptchaAttempt] = useState(0)

  const inputRef = useRef<HTMLInputElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const activeControllerRef = useRef<AbortController | null>(null)
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      activeControllerRef.current?.abort()
      activeControllerRef.current = null
    }
  }, [])

  const value = values[mode]
  const maxLength = mode === 'link' ? MAX_LINK_LENGTH : MAX_MESSAGE_LENGTH
  const sensitiveUrl = useMemo(
    () =>
      mode === 'link'
        ? detectSensitiveUrl(value)
        : { sensitive: false, reasons: [] as string[] },
    [mode, value],
  )
  const externalFlagEnabled = isMultiSourceEnabled()
  const workerConfigured = isWorkerConfigured()
  const externalFeatureEnabled = externalFlagEnabled && workerConfigured
  const externalDecision = resolveExternalScanRequest({
    mode,
    featureEnabled: externalFeatureEnabled,
    sensitive: sensitiveUrl.sensitive,
  })
  const externalBlockedMessage = !externalFlagEnabled
    ? 'Pemeriksaan reputasi eksternal dinonaktifkan pada versi ini.'
    : !workerConfigured
      ? 'URL layanan pemeriksaan eksternal belum tersedia pada versi ini.'
      : sensitiveUrl.sensitive
        ? 'URL ini tidak dikirim karena memuat token atau data sensitif.'
        : null
  const externalHelp =
    externalBlockedMessage ??
    'URL ini akan diperiksa menggunakan beberapa sumber keamanan dan dianalisis untuk ' +
      'mengetahui informasi teknis serta perilaku situs.'
  const submissionNote =
    mode === 'message'
      ? auth.mode === 'firebase' && isVerifiedAccount(auth.user)
        ? 'Analisis berjalan di browser. Hanya cuplikan sesuai pilihan privasi yang dikirim ke akunmu.'
        : 'Isi pesan tidak dikirim ke layanan mana pun.'
      : externalDecision.send
        ? 'Dengan menekan Periksa tautan, URL akan dikirim ke agen eksternal. Hasil tamu disimpan lokal di browser ini.'
        : (externalBlockedMessage ?? 'Tautan tidak dibuka dan tidak ada permintaan ke alamat tersebut.')

  function handleModeChange(nextMode: ScanMode) {
    if (nextMode === mode || submitting) return
    setSearchParams({ mode: nextMode }, { replace: true })
    setError(null)
    setNotice(null)
  }

  function handleValueChange(nextValue: string) {
    setValues((current) => ({ ...current, [mode]: nextValue }))
    if (error) setError(null)
    if (notice) setNotice(null)
    // Tantangan yang tertunda berlaku untuk satu URL tertentu; begitu isinya berubah,
    // tantangan itu tidak boleh dipakai untuk mengulang permintaan lama.
    if (captcha) {
      setCaptcha(null)
      setCaptchaToken(null)
    }
  }

  function handleCancel() {
    if (!submitting) return
    activeControllerRef.current?.abort()
  }

  function handleSample(sample: string) {
    handleValueChange(sample)
    if (mode === 'link') {
      inputRef.current?.focus()
    } else {
      textareaRef.current?.focus()
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting) return

    const validation = validateInput(mode, value)

    if (!validation.ok) {
      setError(validation.error)
      if (mode === 'link') {
        inputRef.current?.focus()
      } else {
        textareaRef.current?.focus()
      }
      return
    }

    setCaptcha(null)
    setCaptchaToken(null)
    await runScan({ url: validation.normalized, scanId: null, captchaToken: null })
  }

  // Satu percobaan pemeriksaan. captchaToken hanya terisi bila layanan sebelumnya meminta
  // verifikasi, dan permintaan yang diulang memakai URL serta scanId yang sama.
  async function runScan(input: {
    url: string
    scanId: string | null
    captchaToken: string | null
  }) {
    setError(null)
    setNotice(null)
    setSubmitting(true)
    setProgressStep(1)
    setLiveProviders([])
    setLiveSensitive(sensitiveUrl.sensitive)
    const presentationStartedAt = Date.now()

    const sendExternal = externalDecision.send
    const externalRequested = sendExternal
    const scanId = input.scanId ?? (sendExternal ? createScanId() : null)
    const controller = new AbortController()
    const { signal } = controller
    let scanPersisted = false
    let syncNotice: string | null = null
    activeControllerRef.current = controller

    try {
      await wait(320, signal)
      ensureScanActive(signal)
      setProgressStep(2)

      let externalResponse: ScanUrlMultiSourceResponse | null = null
      let externalProviders: ExternalProviderResult[] = []
      let sharedWithProviders: ExternalProviderId[] = []
      let streamSensitive = sensitiveUrl.sensitive
      let streamPrivacyReasons = [...sensitiveUrl.reasons]
      let externalError: string | null =
        mode === 'link' && !sendExternal && !sensitiveUrl.sensitive
          ? externalBlockedMessage
          : null
      let externalDurationMs = 0

      if (sendExternal && scanId) {
        const startedAt = Date.now()
        try {
          externalResponse = await requestExternalScanStream(
            input.url,
            scanId,
            {
              signal,
              captchaToken: input.captchaToken,
              onEvent: (event: ScanProgressEvent) => {
                if (signal.aborted) return

                if (event.type === 'init') {
                  streamSensitive = event.sensitiveUrl
                  setLiveSensitive(event.sensitiveUrl)
                  setLiveProviders(event.providers.map((provider) => ({ ...provider })))
                  streamPrivacyReasons = [
                    ...new Set([...streamPrivacyReasons, ...event.privacyReasons]),
                  ]
                  return
                }

                if (event.type === 'provider') {
                  setLiveProviders((current) => upsertProvider(current, event.provider))
                  if (event.provider.result) {
                    externalProviders = mergeProviderResult(
                      externalProviders,
                      event.provider.result,
                    )
                    if (
                      event.provider.shared &&
                      !sharedWithProviders.includes(event.provider.id)
                    ) {
                      sharedWithProviders = [...sharedWithProviders, event.provider.id]
                    }
                  }
                  return
                }

                externalResponse = event.response
              },
            },
          )
          if (externalResponse) {
            externalProviders = externalResponse.providers
            sharedWithProviders = externalResponse.sharedWithProviders
            streamSensitive = externalResponse.sensitiveUrl
            streamPrivacyReasons = [
              ...new Set([...streamPrivacyReasons, ...externalResponse.privacyReasons]),
            ]
          }
        } catch (cause) {
          if (signal.aborted || isExternalScanCancelled(cause)) {
            throw createExternalScanCancelledError()
          }
          if (isCaptchaChallenge(cause)) {
            // Tidak ada pemeriksaan yang benar-benar berjalan, jadi alur dihentikan di sini
            // dan tidak dilanjutkan sampai muncul hasil yang bisa disalahtafsirkan bersih.
            throw cause
          }
          externalError = externalScanErrorMessage(cause)
        }
        externalDurationMs = Math.max(0, Date.now() - startedAt)
      } else {
        await wait(420, signal)
      }

      ensureScanActive(signal)
      const draft = analyze({ mode, value: input.url })
      setProgressStep(3)
      const activeUid =
        auth.mode === 'firebase' && isVerifiedAccount(auth.user)
          ? (auth.user?.uid ?? null)
          : null
      const { scan, syncError } = await saveScanForUser(
        draft,
        { redactMessageInput: mode === 'message' && !keepFullMessage },
        activeUid,
      )
      scanPersisted = true
      // Sinkronisasi riwayat yang gagal tidak boleh menyembunyikan hasil: pemeriksaan tetap
      // dibuka, dan halaman hasil diberi tahu bahwa salinannya tertahan di perangkat.
      syncNotice = syncError
      ensureScanActive(signal)

      let reportForNavigation: MultiSourceReport | null = null
      if (mode === 'link') {
        const report = buildMultiSourceReport({
          scan,
          externalProviders: externalResponse?.providers ?? externalProviders,
          sharedWithProviders:
            externalResponse?.sharedWithProviders ?? sharedWithProviders,
          externalRequested,
          externalError,
          sensitiveUrl:
            sensitiveUrl.sensitive ||
            streamSensitive ||
            externalResponse?.sensitiveUrl === true,
          privacyReasons: [
            ...new Set([...streamPrivacyReasons, ...(externalResponse?.privacyReasons ?? [])]),
          ],
          generatedAt: externalResponse?.generatedAt,
          durationMs: externalResponse?.durationMs ?? externalDurationMs,
          scanCache: externalResponse?.cache ?? null,
        })
        saveScanReport(scan.id, report)
        reportForNavigation = report
      }

      // Antarmuka loading harus sempat terlihat meski hasil datang sangat cepat
      // (misalnya laporan agen yang sudah tersedia). Permintaan backend tidak ditunda.
      const visibleFloorMs = Math.max(
        260,
        MIN_LOADING_VISIBLE_MS - (Date.now() - presentationStartedAt),
      )
      await wait(visibleFloorMs, signal)
      ensureScanActive(signal)
      if (!mountedRef.current) return
      navigate(`/hasil/${scan.id}`, {
        state: { multiSourceReport: reportForNavigation, syncNotice },
      })
    } catch (cause) {
      if (!mountedRef.current) return

      setProgressStep(0)
      setSubmitting(false)
      setLiveProviders([])

      if (signal.aborted || isExternalScanCancelled(cause)) {
        setError(null)
        setNotice(
          scanPersisted
            ? 'Permintaan dihentikan dari browser ini. Hasil yang sudah tersimpan tetap ada di riwayat; proses yang sudah dimulai di layanan pemeriksaan tidak selalu dapat dihentikan.'
            : 'Permintaan dihentikan dari browser ini dan tidak ada hasil baru yang disimpan. Proses yang sudah dimulai di layanan pemeriksaan tidak selalu dapat dihentikan.',
        )
        return
      }

      if (isCaptchaChallenge(cause)) {
        // Layanan meminta verifikasi sebelum melanjutkan. Tidak ada hasil baru yang
        // disimpan, dan tantangan ditangani lewat kartu verifikasi di bawah form.
        setCaptcha({
          url: input.url,
          scanId,
          reason: externalScanErrorMessage(cause),
        })
        setCaptchaToken(null)
        setCaptchaAttempt((current) => current + 1)
        setError(null)
        return
      }

      setError(
        auth.mode === 'firebase' && auth.user
          ? firestoreErrorMessage(cause)
          : cause instanceof Error
            ? cause.message
            : 'Pemeriksaan gagal dijalankan. Coba lagi beberapa saat.',
      )
    } finally {
      if (activeControllerRef.current === controller) {
        activeControllerRef.current = null
      }
    }
  }

  // Melanjutkan permintaan yang sama dengan token yang baru saja diverifikasi. Token dibuang
  // sebelum dipakai supaya tidak pernah dikirim dua kali, dan tantangan berikutnya kembali
  // menunggu satu klik pengguna, sehingga alur ini tidak dapat berputar sendiri.
  async function resumeAfterCaptcha() {
    if (!captcha || submitting) return
    const token = captchaToken
    if (!token) {
      setError('Selesaikan verifikasi CAPTCHA di atas.')
      return
    }

    const pending = captcha
    setCaptcha(null)
    setCaptchaToken(null)
    setCaptchaAttempt((current) => current + 1)
    await runScan({ url: pending.url, scanId: pending.scanId, captchaToken: token })
  }

  function cancelCaptcha() {
    setCaptcha(null)
    setCaptchaToken(null)
    setError(null)
    setNotice('Verifikasi dibatalkan. Tidak ada pemeriksaan yang dijalankan.')
  }

  return (
    <Container className="pb-16 sm:pb-20">
      <PageHeader
        eyebrow="Pemeriksaan"
        title="Periksa tautan atau pesan"
        description="Tempel tautan atau isi pesan yang mencurigakan. Analisis dasar berjalan di browser; untuk tautan normal, URL juga diperiksa di agen reputasi eksternal setelah tombol ditekan."
        actions={<Badge tone="neutral">Lokal + eksternal</Badge>}
      />

      {/* Dua kolom desktop (kiri fleksibel, rail informasi 340px, gap 24px) di dalam Container
          1120px yang sama dengan navbar dan footer. Grid default meregangkan kedua kolom ke
          tinggi baris yang sama sehingga batas bawah kotak kiri sejajar dengan panel kanan;
          kolom yang lebih pendek menampung sisa ruangnya di bagian bawah, bukan di tengah.
          Saat pemeriksaan berjalan, kotak kiri memanjang untuk menampung progres agen dan
          rataannya dikembalikan ke atas supaya panel kanan tetap pada tinggi naturalnya. */}
      <div
        className={cn(
          'mt-8 grid gap-6 lg:grid-cols-[minmax(0,1fr)_340px]',
          submitting && 'lg:items-start',
        )}
      >
        <Card className="p-5 sm:p-6">
          <SegmentedControl
            options={MODE_OPTIONS}
            value={mode}
            onChange={handleModeChange}
            label="Jenis pemeriksaan"
            disabled={submitting}
          />

          <form className="mt-6" onSubmit={handleSubmit} noValidate aria-busy={submitting}>
            <div className="flex items-end justify-between gap-4">
              <label htmlFor="scan-input" className="text-sm font-medium text-ink">
                {mode === 'link' ? 'Tautan yang diperiksa' : 'Isi pesan'}
              </label>
              <span
                className={cn(
                  'type-caption tabular-nums',
                  value.length > maxLength * 0.9 && 'text-risk-medium',
                )}
              >
                {value.length.toLocaleString('id-ID')} / {maxLength.toLocaleString('id-ID')}
              </span>
            </div>

            {mode === 'link' ? (
              <Input
                ref={inputRef}
                id="scan-input"
                name="link"
                type="url"
                inputMode="url"
                autoComplete="off"
                spellCheck={false}
                maxLength={MAX_LINK_LENGTH}
                placeholder="https://contoh.com/masuk"
                value={value}
                onChange={(event) => handleValueChange(event.target.value)}
                disabled={submitting}
                aria-invalid={Boolean(error)}
                aria-describedby={`scan-input-help${error ? ' scan-input-error' : ''}`}
                className="mt-2"
              />
            ) : (
              <Textarea
                ref={textareaRef}
                id="scan-input"
                name="message"
                rows={7}
                maxLength={MAX_MESSAGE_LENGTH}
                placeholder="Tempel pesan yang kamu terima di sini…"
                value={value}
                onChange={(event) => handleValueChange(event.target.value)}
                disabled={submitting}
                aria-invalid={Boolean(error)}
                aria-describedby={`scan-input-help${error ? ' scan-input-error' : ''}`}
                className="mt-2 min-h-44"
              />
            )}

            <p id="scan-input-help" className="type-caption mt-2">
              {mode === 'link'
                ? 'Sertakan alamat lengkap. Protokol https:// ditambahkan otomatis jika tidak ditulis.'
                : 'Minimal 12 karakter. Salin teks pesan apa adanya, tanpa mengubah tautan di dalamnya.'}
            </p>

            {/* Satu panel ringkas berisi jenis pemeriksaan yang tersedia. Idiom panelnya sama
                dengan blok persetujuan di bawahnya: garis tipis, isian subtle, tanpa badge status. */}
            <div className="mt-4 rounded-card border border-line bg-subtle/60 p-3.5">
              <h2 className="text-sm font-medium text-ink">Pemeriksaan yang dilakukan</h2>
              <ul className="mt-3 flex flex-col gap-3">
                {SCAN_CHECKS.map((row) => (
                  <li key={row.title} className="flex items-start gap-2.5">
                    <span
                      aria-hidden="true"
                      className="grid size-7 shrink-0 place-items-center rounded-lg bg-surface text-accent"
                    >
                      <row.icon size={14} />
                    </span>
                    <span className="min-w-0">
                      <span className="block text-sm font-medium leading-snug text-ink">
                        {row.title}
                      </span>
                      <span className="type-caption mt-1 block leading-snug">
                        {row.description}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>

            {mode === 'message' ? (
              <div className="mt-4 rounded-card border border-line bg-subtle/60 p-3.5">
                <label className="flex items-start gap-2.5">
                  <input
                    type="checkbox"
                    checked={keepFullMessage}
                    onChange={(event) => setKeepFullMessage(event.target.checked)}
                    disabled={submitting}
                    aria-describedby="keep-full-message-help"
                    className="mt-0.5 size-4 shrink-0 rounded border-line text-accent focus:ring-2 focus:ring-accent/20"
                  />
                  <span>
                    <span className="block text-sm font-medium text-ink">
                      Simpan isi pesan lengkap di riwayat
                    </span>
                    <span id="keep-full-message-help" className="type-caption mt-0.5 block">
                      Tanpa izin ini, tautan, email, nomor telepon, dan deretan angka disamarkan
                      sebelum disimpan. Teks lengkap tetap diproses di browser untuk pemeriksaan
                      saat ini.
                    </span>
                  </span>
                </label>
              </div>
            ) : null}

            {mode === 'link' ? (
              <div className="mt-4 rounded-card border border-line bg-subtle/60 p-3.5">
                <p className="text-sm font-medium text-ink">
                  Pemeriksaan reputasi eksternal
                </p>
                <p
                  id="external-scan-help"
                  className={cn(
                    'type-caption mt-1',
                    sensitiveUrl.sensitive && 'text-risk-medium',
                  )}
                >
                  {externalHelp}
                </p>
                {externalDecision.send ? (
                  <p className="type-caption mt-2 border-t border-line pt-2">
                    Dengan memilih Periksa tautan, kamu menyetujui pengiriman URL ini ke layanan
                    pemeriksaan yang digunakan VERIGUARD AI. Pastikan kamu hanya memeriksa URL
                    yang memang berhak kamu periksa.
                  </p>
                ) : null}
              </div>
            ) : null}

            {error ? (
              <Alert
                id="scan-input-error"
                role="alert"
                tone="danger"
                title="Periksa input"
                className="mt-4"
              >
                {error}
              </Alert>
            ) : null}

            {notice ? (
              <Alert tone="info" title="Pemeriksaan dihentikan" className="mt-4">
                {notice}
              </Alert>
            ) : null}

            {captcha ? (
              <div
                className="mt-4 rounded-card border border-line bg-subtle/60 p-3.5"
                role="group"
                aria-labelledby="scan-captcha-title"
              >
                <p id="scan-captcha-title" className="text-sm font-medium text-ink">
                  Verifikasi diperlukan untuk melanjutkan
                </p>
                <p className="type-caption mt-1">
                  {captcha.reason} Pemeriksaan belum dijalankan, jadi belum ada hasil baru yang
                  disimpan.
                </p>
                <Turnstile
                  action={TURNSTILE_ACTION.scan}
                  attempt={captchaAttempt}
                  onToken={(token) => setCaptchaToken(token)}
                  onExpire={() => setCaptchaToken(null)}
                  className="mt-3"
                />
                <div className="mt-3 flex flex-wrap items-center gap-3">
                  <Button
                    type="button"
                    size="sm"
                    onClick={() => void resumeAfterCaptcha()}
                    disabled={!captchaToken || submitting}
                  >
                    Lanjutkan pemeriksaan
                  </Button>
                  <Button type="button" size="sm" variant="ghost" onClick={cancelCaptcha}>
                    Batalkan
                  </Button>
                </div>
              </div>
            ) : null}

            <div className="mt-4 flex flex-wrap items-center gap-2">
              <span className="type-caption">Coba contoh:</span>
              {SAMPLES[mode].map((sample) => (
                <button
                  key={sample.label}
                  type="button"
                  onClick={() => handleSample(sample.value)}
                  disabled={submitting}
                  className="rounded-full border border-line bg-surface px-3 py-1.5 text-xs font-medium text-ink-soft transition-colors hover:border-line-strong hover:text-ink disabled:pointer-events-none disabled:opacity-50"
                >
                  {sample.label}
                </button>
              ))}
            </div>

            {submitting ? (
              <div className="mt-3">
                <AnalysisProgress
                  activeStep={progressStep}
                  title={
                    mode === 'link' && externalDecision.send ? 'Memeriksa tautan…' : undefined
                  }
                  steps={
                    mode === 'link' && externalDecision.send
                      ? EXTERNAL_PROGRESS_STEPS
                      : undefined
                  }
                />
                {mode === 'link' ? (
                  <LiveScanPanel
                    providers={liveProviders}
                    sensitiveUrl={liveSensitive}
                  />
                ) : null}
                <div className="mt-3 flex flex-wrap items-center gap-3">
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    onClick={handleCancel}
                    aria-describedby="scan-cancel-help"
                  >
                    Batalkan pemeriksaan
                  </Button>
                  <p id="scan-cancel-help" className="type-caption max-w-[52ch]">
                    Pembatalan menghentikan permintaan dari browser ini. Proses yang
                    sudah dimulai di layanan pemeriksaan tidak selalu dapat dihentikan.
                  </p>
                </div>
              </div>
            ) : (
              <div className="mt-3 flex flex-col gap-3 sm:flex-row sm:items-center">
                <Button type="submit" size="lg" className="w-full sm:w-auto">
                  {mode === 'link' ? 'Periksa tautan' : 'Periksa pesan'}
                  <ArrowRight size={17} aria-hidden="true" />
                </Button>
                <p className="type-caption max-w-[42ch]">{submissionNote}</p>
              </div>
            )}
          </form>
        </Card>

        <aside className="flex flex-col gap-4">
          <Card className="p-4">
            <div className="flex items-center gap-2">
              <span className="grid size-7 place-items-center rounded-lg bg-accent-soft text-accent">
                <ShieldCheck size={15} aria-hidden="true" />
              </span>
              <h2 className="text-sm font-semibold text-ink">Yang diperiksa</h2>
            </div>
            <ul className="mt-3 flex flex-col gap-2 text-sm leading-snug text-ink-soft">
              {CHECKED_ITEMS.map((item) => (
                <li key={item} className="flex gap-2">
                  <span
                    aria-hidden="true"
                    className="mt-1.5 size-1 shrink-0 rounded-full bg-line-strong"
                  />
                  {item}
                </li>
              ))}
            </ul>
          </Card>

          {/* Card terakhir ikut mengisi sisa tinggi kolom supaya batas bawah panel kanan
              tetap sejajar dengan kotak kiri saat kolom kiri lebih tinggi. */}
          <Card className="flex-1 border-dashed bg-subtle/60 p-4">
            <h2 className="text-sm font-semibold text-ink">Informasi Pemeriksaan</h2>
            <ul className="mt-3 flex flex-col gap-2 text-sm leading-snug text-ink-soft">
              <li>
                VERIGUARD menganalisis tautan berdasarkan indikator keamanan dan reputasi digital.
              </li>
              <li>
                Pemeriksaan didukung oleh agen eksternal untuk mengenali potensi ancaman.
              </li>
              <li>
                Privasi URL dan pesan pengguna tetap menjadi perhatian dalam proses pemeriksaan.
              </li>
              <li>
                Sistem menggunakan aturan keamanan dan indikator heuristik untuk mendeteksi aktivitas
                mencurigakan.
              </li>
              <li>
                Hasil pemeriksaan menunjukkan tingkat risiko sebagai bahan pertimbangan sebelum
                mengakses tautan.
              </li>
            </ul>
            <Link
              to="/edukasi"
              className="mt-3 inline-block text-sm font-medium text-accent underline-offset-4 hover:underline"
            >
              Pelajari pola penipuan
            </Link>
          </Card>
        </aside>
      </div>
    </Container>
  )
}

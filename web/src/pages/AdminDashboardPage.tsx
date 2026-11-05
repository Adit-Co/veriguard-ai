import {
  Clock3,
  FileWarning,
  LockKeyhole,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldX,
} from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { CopyUrlButton } from '../components/community/CopyUrlButton'
import { MaskedReporterName } from '../components/community/MaskedReporterName'
import { DashboardTabs } from '../components/dashboard/DashboardTabs'
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
import { useAdminRole } from '../lib/auth/useAdminRole'
import { useAuth } from '../lib/auth/useAuth'
import {
  COMMUNITY_CATEGORY_LABELS,
} from '../lib/community/types'
import {
  applyModerationDecision,
  describeModerationError,
  loadModerationHistory,
  loadModerationQueue,
  moderationErrorMessage,
  type ModerationErrorInfo,
  type ModerationErrorKind,
  type ModerationQueueSnapshot,
} from '../lib/moderation/moderationService'
import {
  buildModerationMetrics,
  buildModerationTrend,
} from '../lib/moderation/stats'
import {
  MODERATION_STATUS_META,
  MODERATION_UNREVIEWED_DESCRIPTION,
  MODERATION_UNREVIEWED_LABEL,
  allowedModerationActions,
  type AdminModerationReport,
  type ModerationAction,
  type ModerationHistoryEntry,
  type ModerationStatus,
} from '../lib/moderation/types'
import { styleValue } from '../lib/styleValue'

const MAX_NOTE_LENGTH = 1000

const dateTimeFormatter = new Intl.DateTimeFormat('id-ID', {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  timeZone: 'Asia/Makassar',
})

type StatusFilter = 'all' | 'unmoderated' | ModerationStatus
type HistoryStatus = 'idle' | 'loading' | 'ready' | 'error'
type QueueStatus = 'idle' | 'loading' | 'ready' | 'error'

function formatDateTime(value: string | null): string {
  if (!value) return 'Waktu tidak tersedia'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Waktu tidak tersedia'
  return `${dateTimeFormatter.format(date)} WITA`
}

function shortenedUid(value: string): string {
  if (!value) return 'tidak tercatat'
  return value.length > 12 ? `${value.slice(0, 8)}…` : value
}

function matchesStatusFilter(
  report: AdminModerationReport,
  filter: StatusFilter,
): boolean {
  if (filter === 'all') return true
  if (filter === 'unmoderated') return report.moderation === null
  return report.moderation?.status === filter
}

function reportMatchesQuery(report: AdminModerationReport, query: string): boolean {
  if (!query) return true
  const haystack = [
    report.userName,
    report.reportText,
    report.reportedUrl ?? '',
    report.hostname ?? '',
    COMMUNITY_CATEGORY_LABELS[report.category],
  ]
    .join(' ')
    .toLowerCase()
  return haystack.includes(query)
}

const MODERATION_ERROR_KIND_LABELS: Record<ModerationErrorKind, string> = {
  permission: 'Akses ditolak',
  session: 'Sesi berakhir',
  connection: 'Koneksi bermasalah',
  conflict: 'Konflik data',
  configuration: 'Konfigurasi penyimpanan data',
  unknown: 'Penyebab belum dikenali',
}

function ModerationErrorDiagnostics({ error }: { error: ModerationErrorInfo }) {
  return (
    <div className="mt-3 rounded-btn border border-line bg-canvas/70 p-3">
      <p className="type-caption">
        <span className="font-medium text-ink">
          {MODERATION_ERROR_KIND_LABELS[error.kind]}
        </span>
        {' · Kode masalah: '}
        <code className="font-mono">{error.code ?? 'tidak tersedia'}</code>
      </p>
      {error.detail ? (
        <p className="type-caption mt-1.5 [overflow-wrap:anywhere]">{error.detail}</p>
      ) : null}
      {error.indexUrl ? (
        <div className="mt-3">
          <a
            href={error.indexUrl}
            target="_blank"
            rel="noreferrer"
            className={buttonStyles({ variant: 'secondary', size: 'sm' })}
          >
            Buka panduan perbaikan indeks data
          </a>
        </div>
      ) : null}
    </div>
  )
}

function ModerationStatusBadge({ status }: { status: ModerationStatus | null }) {
  if (!status) {
    return <Badge tone="neutral">{MODERATION_UNREVIEWED_LABEL}</Badge>
  }
  const meta = MODERATION_STATUS_META[status]
  return <Badge tone={meta.tone}>{meta.label}</Badge>
}

function HistoryEntry({ entry }: { entry: ModerationHistoryEntry }) {
  const toMeta = MODERATION_STATUS_META[entry.toStatus]
  const fromLabel = entry.fromStatus
    ? MODERATION_STATUS_META[entry.fromStatus].label
    : 'Belum ada catatan'

  return (
    <li className="border-t border-line py-3 first:border-t-0 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <Badge tone={toMeta.tone}>{toMeta.label}</Badge>
        <span className="type-caption">
          {entry.action === 'created' ? 'Catatan dibuat' : `${fromLabel} → ${toMeta.label}`}
        </span>
      </div>
      <p className="type-caption mt-1">
        {formatDateTime(entry.createdAt)} · Aktor UID {shortenedUid(entry.actorUid)}
      </p>
      {entry.note ? (
        <p className="type-small mt-2 rounded-btn bg-subtle px-3 py-2 text-ink-soft">
          {entry.note}
        </p>
      ) : null}
    </li>
  )
}

export function AdminDashboardPage() {
  const auth = useAuth()
  const adminRole = useAdminRole()
  const [snapshot, setSnapshot] = useState<ModerationQueueSnapshot | null>(null)
  const [queueStatus, setQueueStatus] = useState<QueueStatus>('idle')
  const [queueError, setQueueError] = useState<ModerationErrorInfo | null>(null)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [history, setHistory] = useState<ModerationHistoryEntry[]>([])
  const [historyStatus, setHistoryStatus] = useState<HistoryStatus>('idle')
  const [historyError, setHistoryError] = useState<string | null>(null)
  const [note, setNote] = useState('')
  const [pendingAction, setPendingAction] = useState<ModerationAction | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [actionSuccess, setActionSuccess] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const queueRequestRef = useRef(0)
  const historyRequestRef = useRef(0)

  const refreshQueue = useCallback(async (): Promise<ModerationQueueSnapshot | null> => {
    if (!adminRole.isAdmin) return null

    const request = queueRequestRef.current + 1
    queueRequestRef.current = request
    setQueueStatus('loading')
    setQueueError(null)

    try {
      const next = await loadModerationQueue()
      if (queueRequestRef.current !== request) return null
      setSnapshot(next)
      setQueueStatus('ready')
      return next
    } catch (cause) {
      if (queueRequestRef.current !== request) return null
      setQueueStatus('error')
      setQueueError(describeModerationError(cause))
      return null
    }
  }, [adminRole.isAdmin])

  const loadHistoryFor = useCallback(async (reportId: string) => {
    const request = historyRequestRef.current + 1
    historyRequestRef.current = request
    setHistory([])
    setHistoryStatus('loading')
    setHistoryError(null)

    try {
      const entries = await loadModerationHistory(reportId)
      if (historyRequestRef.current !== request) return
      setHistory(entries)
      setHistoryStatus('ready')
    } catch (cause) {
      if (historyRequestRef.current !== request) return
      setHistoryStatus('error')
      setHistoryError(moderationErrorMessage(cause))
    }
  }, [])

  useEffect(() => {
    if (!adminRole.isAdmin) {
      queueRequestRef.current += 1
      historyRequestRef.current += 1
      // oxlint-disable-next-line react/set-state-in-effect -- buang data moderasi saat akses atau sesi berakhir
      setSnapshot(null)
      setQueueStatus('idle')
      setQueueError(null)
      setSelectedId(null)
      setHistory([])
      setHistoryStatus('idle')
      setHistoryError(null)
      setPendingAction(null)
      setActionError(null)
      setActionSuccess(null)
      setNote('')
      return
    }

    void refreshQueue()
    return () => {
      queueRequestRef.current += 1
    }
  }, [adminRole.isAdmin, refreshQueue])

  const reports = snapshot?.reports ?? []
  const metrics = buildModerationMetrics(reports)
  const trend = buildModerationTrend(reports)
  const maxTrendTotal = Math.max(1, ...trend.map((bucket) => bucket.total))

  const normalizedSearch = search.trim().toLowerCase()
  const filteredReports = reports.filter(
    (report) =>
      matchesStatusFilter(report, statusFilter) &&
      reportMatchesQuery(report, normalizedSearch),
  )

  const selectedReport = selectedId
    ? reports.find((report) => report.id === selectedId) ?? null
    : null
  const selectedUrl = selectedReport
    ? selectedReport.reportedUrl ?? null
    : null
  const availableActions = selectedReport
    ? allowedModerationActions(selectedReport.moderation?.status ?? null)
    : []

  function handleSelect(report: AdminModerationReport) {
    if (report.id === selectedId) return
    setSelectedId(report.id)
    setPendingAction(null)
    setActionError(null)
    setActionSuccess(null)
    setNote(report.moderation?.note ?? '')
    void loadHistoryFor(report.id)
  }

  async function handleConfirmDecision() {
    if (!selectedReport || !pendingAction || submitting) return
    const target = pendingAction
    const report = selectedReport

    setSubmitting(true)
    setActionError(null)
    setActionSuccess(null)

    try {
      await applyModerationDecision({
        reportId: report.id,
        urlHash: report.urlHash,
        currentStatus: report.moderation?.status ?? null,
        nextStatus: target.to,
        note,
      })

      const targetLabel = MODERATION_STATUS_META[target.to].label
      setActionSuccess(
        `Keputusan “${targetLabel}” tersimpan. Status publik dan catatan audit diperbarui dalam satu langkah.`,
      )
      setPendingAction(null)

      const next = await refreshQueue()
      if (!next) return

      const updated = next.reports.find((item) => item.id === report.id)
      if (updated) {
        setSelectedId(updated.id)
        setNote(updated.moderation?.note ?? '')
        await loadHistoryFor(updated.id)
      } else {
        historyRequestRef.current += 1
        setSelectedId(null)
        setNote('')
        setHistory([])
        setHistoryStatus('idle')
        setHistoryError(null)
      }
    } catch (cause) {
      setActionError(moderationErrorMessage(cause))
    } finally {
      setSubmitting(false)
    }
  }

  const roleBadge =
    auth.status === 'loading' ? (
      <Badge tone="neutral">Memulihkan sesi</Badge>
    ) : adminRole.status === 'admin' ? (
      <Badge tone="low">
        <ShieldCheck size={12} aria-hidden="true" />
        Admin terverifikasi
      </Badge>
    ) : adminRole.status === 'loading' ? (
      <Badge tone="neutral">Memeriksa akses</Badge>
    ) : adminRole.status === 'error' ? (
      <Badge tone="medium">Peran gagal dibaca</Badge>
    ) : (
      <Badge tone="neutral">Akses terbatas</Badge>
    )

  const pageActions = (
    <>
      {roleBadge}
      {adminRole.isAdmin ? (
        <Button
          variant="secondary"
          size="sm"
          onClick={() => void refreshQueue()}
          disabled={queueStatus === 'loading'}
        >
          <RefreshCw size={14} aria-hidden="true" />
          {queueStatus === 'loading' ? 'Memuat…' : 'Muat ulang'}
        </Button>
      ) : null}
    </>
  )

  let content

  if (auth.status === 'loading') {
    content = (
      <Card className="mt-6 px-6 py-14 text-center" role="status">
        <h2 className="type-h3">Memulihkan sesi akun…</h2>
        <p className="type-small mt-2 text-ink-soft">
          Akses moderator hanya diperiksa setelah status sesi diketahui.
        </p>
      </Card>
    )
  } else if (auth.status === 'error') {
    content = (
      <Alert tone="danger" className="mt-6" title="Layanan akun gagal disiapkan">
        {auth.initializationError ??
          'Layanan akun belum dapat disiapkan. Muat ulang halaman atau hubungi pengelola layanan.'}
      </Alert>
    )
  } else if (adminRole.status === 'loading') {
    content = (
      <Card className="mt-6 px-6 py-14 text-center" role="status">
        <span className="mx-auto grid size-12 place-items-center rounded-full bg-subtle text-ink-muted">
          <LockKeyhole size={22} aria-hidden="true" />
        </span>
        <h2 className="type-h3 mt-5">Memeriksa izin admin…</h2>
        <p className="type-small mt-2 text-ink-soft">
          Peran diverifikasi dari daftar admin pada penyimpanan data, bukan dari email atau data di browser.
        </p>
      </Card>
    )
  } else if (adminRole.status === 'error') {
    content = (
      <Alert tone="danger" className="mt-6" title="Peran admin tidak dapat diverifikasi">
        <p>{adminRole.error ?? 'Penyimpanan data tidak dapat dihubungi.'}</p>
        <p className="mt-2">
          Data moderasi tidak dimuat sebelum peran admin berhasil diverifikasi.
        </p>
        <Button
          variant="secondary"
          size="sm"
          className="mt-3"
          onClick={() => void adminRole.refresh()}
        >
          Coba periksa ulang
        </Button>
      </Alert>
    )
  } else if (!adminRole.isAdmin) {
    content = (
      <>
        <Card className="mt-6 flex flex-col items-center px-6 py-14 text-center">
          <span className="grid size-12 place-items-center rounded-full bg-subtle text-ink-muted">
            <ShieldX size={22} aria-hidden="true" />
          </span>
          <h2 className="type-h3 mt-5">Akses Dashboard Admin diperlukan</h2>
          <p className="type-small mt-2 max-w-[58ch] text-ink-soft">
            {auth.mode === 'demo'
              ? 'Sesi demo lokal bukan autentikasi sungguhan, sehingga tidak dapat membuka data moderasi.'
              : 'Akun ini tidak tercantum pada daftar admin aktif. Membuka alamat ini langsung tidak memberikan akses; seluruh pembacaan dan perubahan tetap ditolak oleh aturan akses data.'}
          </p>
          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <Link to="/dashboard" className={buttonStyles({ variant: 'secondary' })}>
              Kembali ke Dashboard Saya
            </Link>
            <Link to="/komunitas" className={buttonStyles({ variant: 'ghost' })}>
              Buka Community Reports
            </Link>
          </div>
        </Card>
        <Alert tone="info" className="mt-6" title="Penyiapan admin">
          Admin ditetapkan secara manual melalui daftar admin di konsol admin. Data tersebut tidak
          dapat dibuat atau diubah dari aplikasi ini.
        </Alert>
      </>
    )
  } else if (!snapshot && (queueStatus === 'idle' || queueStatus === 'loading')) {
    content = (
      <Card className="mt-6 px-6 py-14 text-center" role="status">
        <h2 className="type-h3">Memuat antrean moderasi…</h2>
        <p className="type-small mt-2 text-ink-soft">
          Membaca laporan komunitas dan catatan moderasi yang dapat diakses admin ini.
        </p>
      </Card>
    )
  } else if (!snapshot && queueStatus === 'error') {
    content = (
      <Alert tone="danger" className="mt-6" title="Antrean moderasi gagal dimuat">
        <p>{queueError?.message ?? 'Data moderasi tidak dapat dibaca.'}</p>
        {queueError ? <ModerationErrorDiagnostics error={queueError} /> : null}
        <Button
          variant="secondary"
          size="sm"
          className="mt-3"
          onClick={() => void refreshQueue()}
        >
          Coba lagi
        </Button>
      </Alert>
    )
  } else if (!snapshot) {
    content = null
  } else {
    content = (
      <>
        {queueStatus === 'error' ? (
          <Alert tone="warning" className="mt-6" title="Muat ulang antrean gagal">
            <p>
              {queueError?.message ?? 'Antrean tidak dapat diperbarui.'} Data yang tampil adalah
              hasil pembacaan terakhir dan mungkin sudah berubah.
            </p>
            {queueError ? <ModerationErrorDiagnostics error={queueError} /> : null}
            <Button
              variant="secondary"
              size="sm"
              className="mt-3"
              onClick={() => void refreshQueue()}
            >
              Coba muat ulang
            </Button>
          </Alert>
        ) : null}

        {snapshot.reportsTruncated || snapshot.moderationTruncated ? (
          <Alert tone="warning" className="mt-6" title="Antrean dibatasi 500 laporan">
            {snapshot.reportsTruncated
              ? 'Batas 500 laporan tercapai, sehingga mungkin masih ada laporan lain yang belum tampil. '
              : null}
            {snapshot.moderationTruncated
              ? 'Batas 500 catatan moderasi tercapai, sehingga sebagian status mungkin belum tergabung. '
              : null}
            Statistik dan tren hanya menghitung data yang termuat.
          </Alert>
        ) : null}

        {actionSuccess ? (
          <Alert
            tone="success"
            role="status"
            className="mt-6"
            title="Keputusan moderasi tersimpan"
          >
            {actionSuccess}
          </Alert>
        ) : null}

        <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {[
            {
              label: 'Laporan termuat',
              value: metrics.total,
              caption: 'Dari antrean yang berhasil dibaca',
            },
            {
              label: 'Belum diputuskan',
              value: metrics.awaiting,
              caption: `${metrics.unmoderated} belum ada catatan · ${metrics.pending} menunggu · ${metrics.review} ditinjau`,
            },
            {
              label: 'Terverifikasi berbahaya',
              value: metrics.confirmed,
              caption: 'Keputusan manual moderator',
            },
            {
              label: 'Sudah diputuskan',
              value: metrics.decided,
              caption: `${metrics.inconclusive} belum cukup bukti · ${metrics.rejected} ditolak`,
            },
          ].map((metric) => (
            <Card key={metric.label} className="p-5">
              <p className="text-sm text-ink-soft">{metric.label}</p>
              <p className="mt-4 text-3xl font-semibold tabular-nums tracking-tight text-ink">
                {metric.value}
              </p>
              <p className="type-caption mt-1">{metric.caption}</p>
            </Card>
          ))}
        </div>

        {metrics.total === 0 ? (
          <Card className="mt-4 flex flex-col items-center px-6 py-14 text-center">
            <span className="grid size-12 place-items-center rounded-full bg-subtle text-ink-muted">
              <FileWarning size={22} aria-hidden="true" />
            </span>
            <h2 className="type-h3 mt-5">Belum ada laporan komunitas</h2>
            <p className="type-small mt-2 max-w-[52ch] text-ink-soft">
              Tidak ada laporan yang dapat dimoderasi pada antrean ini. Laporan baru akan muncul
              setelah pengguna terverifikasi mengirimkannya.
            </p>
            <Button
              variant="secondary"
              size="sm"
              className="mt-5"
              onClick={() => void refreshQueue()}
              disabled={queueStatus === 'loading'}
            >
              <RefreshCw size={14} aria-hidden="true" />
              Periksa lagi
            </Button>
          </Card>
        ) : (
          <>
            <Card className="mt-4 p-5 sm:p-6">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h2 className="type-h3">Tren laporan 7 hari</h2>
                <Badge tone="neutral">WITA</Badge>
              </div>
              <p className="type-caption mt-1">
                Jumlah laporan yang masuk per hari, diwarnai menurut status moderasi saat ini.
                Hanya menghitung laporan yang termuat.
              </p>

              <ul
                aria-label="Tren laporan tujuh hari terakhir"
                className="mt-5 grid grid-cols-7 gap-2 sm:gap-3"
              >
                {trend.map((bucket) => {
                  const height =
                    bucket.total === 0
                      ? 0
                      : Math.max(8, Math.round((bucket.total / maxTrendTotal) * 100))
                  return (
                    <li key={bucket.dayKey} className="min-w-0">
                      <div className="flex h-32 items-end rounded-btn bg-subtle/70 p-1">
                        <div
                          aria-hidden="true"
                          ref={styleValue('height', `${height}%`)}
                          className="flex w-full flex-col-reverse overflow-hidden rounded-[3px]"
                        >
                          {bucket.awaiting > 0 ? (
                            <div
                              className="bg-accent"
                              ref={styleValue('flexGrow', bucket.awaiting)}
                            />
                          ) : null}
                          {bucket.confirmed > 0 ? (
                            <div
                              className="bg-risk-high"
                              ref={styleValue('flexGrow', bucket.confirmed)}
                            />
                          ) : null}
                          {bucket.concluded > 0 ? (
                            <div
                              className="bg-ink-muted"
                              ref={styleValue('flexGrow', bucket.concluded)}
                            />
                          ) : null}
                        </div>
                      </div>
                      <p className="mt-1.5 truncate text-center text-[11px] text-ink-soft">
                        {bucket.label}
                      </p>
                      <p className="text-center text-xs font-semibold tabular-nums text-ink">
                        {bucket.total}
                      </p>
                      <span className="sr-only">
                        {`${bucket.dateLabel}: ${bucket.total} laporan; ${bucket.awaiting} menunggu keputusan, ${bucket.confirmed} terverifikasi berbahaya, ${bucket.concluded} selesai tanpa konfirmasi.`}
                      </span>
                    </li>
                  )
                })}
              </ul>

              <div className="mt-4 flex flex-wrap gap-x-4 gap-y-2 border-t border-line pt-3">
                {[
                  ['Belum diputuskan', 'bg-accent'],
                  ['Terverifikasi berbahaya', 'bg-risk-high'],
                  ['Selesai tanpa konfirmasi', 'bg-ink-muted'],
                ].map(([label, color]) => (
                  <span key={label} className="inline-flex items-center gap-1.5">
                    <span
                      aria-hidden="true"
                      className={`size-2 rounded-full ${color}`}
                    />
                    <span className="type-caption">{label}</span>
                  </span>
                ))}
              </div>
            </Card>

            <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] lg:items-start">
              <Card className="p-4 sm:p-5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h2 className="type-h3">Antrean laporan</h2>
                  <Badge tone="neutral">
                    {filteredReports.length} dari {reports.length}
                  </Badge>
                </div>

                <label htmlFor="moderation-search" className="mt-4 block text-sm font-medium text-ink">
                  Cari antrean
                </label>
                <div className="relative mt-1.5">
                  <Search
                    size={16}
                    aria-hidden="true"
                    className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-ink-muted"
                  />
                  <Input
                    id="moderation-search"
                    type="search"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="URL, hostname, alasan, atau nama tersamar…"
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    className="pl-10"
                  />
                </div>

                <label
                  htmlFor="moderation-status-filter"
                  className="mt-3 block text-sm font-medium text-ink"
                >
                  Status moderasi
                </label>
                <Select
                  id="moderation-status-filter"
                  className="mt-1.5"
                  value={statusFilter}
                  onChange={(event) => setStatusFilter(event.target.value as StatusFilter)}
                >
                  <option value="all">Semua status</option>
                  <option value="unmoderated">{MODERATION_UNREVIEWED_LABEL}</option>
                  <option value="pending">{MODERATION_STATUS_META.pending.label}</option>
                  <option value="review">{MODERATION_STATUS_META.review.label}</option>
                  <option value="confirmed_malicious">
                    {MODERATION_STATUS_META.confirmed_malicious.label}
                  </option>
                  <option value="inconclusive">
                    {MODERATION_STATUS_META.inconclusive.label}
                  </option>
                  <option value="rejected">{MODERATION_STATUS_META.rejected.label}</option>
                </Select>

                {filteredReports.length === 0 ? (
                  <div className="mt-4 rounded-card border border-dashed border-line bg-subtle/50 p-5 text-center">
                    <p className="text-sm font-medium text-ink">
                      Tidak ada laporan yang cocok
                    </p>
                    <p className="type-small mt-1 text-ink-soft">
                      Ubah kata kunci atau status, lalu periksa kembali.
                    </p>
                    <Button
                      variant="secondary"
                      size="sm"
                      className="mt-4"
                      onClick={() => {
                        setSearch('')
                        setStatusFilter('all')
                      }}
                    >
                      Reset filter
                    </Button>
                  </div>
                ) : (
                  <ul aria-label="Daftar antrean moderasi" className="mt-4 flex flex-col gap-2">
                    {filteredReports.map((report) => {
                      const selected = report.id === selectedId
                      return (
                        <li key={report.id}>
                          <button
                            type="button"
                            aria-pressed={selected}
                            onClick={() => handleSelect(report)}
                            className={`w-full rounded-card border p-3.5 text-left transition-colors ${
                              selected
                                ? 'border-accent/60 bg-accent-soft/40'
                                : 'border-line bg-canvas hover:border-line-strong'
                            }`}
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="text-sm font-semibold text-ink">
                                <MaskedReporterName value={report.userName} />
                              </span>
                              <ModerationStatusBadge
                                status={report.moderation?.status ?? null}
                              />
                            </div>
                            <p className="mt-1.5 line-clamp-2 text-sm [overflow-wrap:anywhere] text-ink-soft">
                              {report.reportedUrl ??
                                report.hostname ??
                                'Alamat tidak tersedia pada laporan ini.'}
                            </p>
                            <p className="type-caption mt-1.5">
                              {COMMUNITY_CATEGORY_LABELS[report.category]} ·{' '}
                              {formatDateTime(report.createdAt)}
                            </p>
                          </button>
                        </li>
                      )
                    })}
                  </ul>
                )}
              </Card>

              <Card
                className="p-5 sm:p-6"
                aria-labelledby="moderation-detail-heading"
              >
                {!selectedReport ? (
                  <div className="flex flex-col items-center px-2 py-10 text-center">
                    <span className="grid size-12 place-items-center rounded-full bg-subtle text-ink-muted">
                      <FileWarning size={22} aria-hidden="true" />
                    </span>
                    <h2 id="moderation-detail-heading" className="type-h3 mt-5">
                      Pilih laporan untuk ditinjau
                    </h2>
                    <p className="type-small mt-2 max-w-[46ch] text-ink-soft">
                      Detail bukti, catatan internal, tindakan moderasi, dan audit akan tampil di
                      sini. Membuka detail tidak mengubah status apa pun.
                    </p>
                  </div>
                ) : (
                  <>
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="type-eyebrow text-accent">Detail laporan</p>
                        <h2
                          id="moderation-detail-heading"
                          className="type-h3 mt-1 [overflow-wrap:anywhere]"
                        >
                          <MaskedReporterName value={selectedReport.userName} />
                        </h2>
                      </div>
                      <ModerationStatusBadge
                        status={selectedReport.moderation?.status ?? null}
                      />
                    </div>

                    <p className="type-small mt-2 text-ink-soft">
                      {selectedReport.moderation
                        ? MODERATION_STATUS_META[selectedReport.moderation.status].description
                        : MODERATION_UNREVIEWED_DESCRIPTION}
                    </p>

                    <div className="mt-5 rounded-card border border-line bg-canvas p-4">
                      <p className="type-caption font-medium text-ink">Alamat yang dilaporkan</p>
                      <p className="mt-1 break-all font-mono text-sm text-ink">
                        {selectedUrl ?? 'URL lengkap tidak tersedia pada laporan lama.'}
                      </p>
                      {selectedUrl ? (
                        <div className="mt-3">
                          <CopyUrlButton value={selectedUrl} />
                        </div>
                      ) : null}
                      <p className="type-caption mt-3">
                        URL sudah disanitasi. Kredensial, query, dan fragment tidak ditampilkan
                        atau disalin.
                      </p>
                    </div>

                    <dl className="mt-4 grid gap-3 sm:grid-cols-2">
                      <div>
                        <dt className="type-caption">Hostname</dt>
                        <dd className="mt-0.5 break-all text-sm text-ink">
                          {selectedReport.hostname ?? 'Tidak tercatat'}
                        </dd>
                      </div>
                      <div>
                        <dt className="type-caption">Kategori laporan</dt>
                        <dd className="mt-0.5 text-sm text-ink">
                          {COMMUNITY_CATEGORY_LABELS[selectedReport.category]}
                        </dd>
                      </div>
                      <div>
                        <dt className="type-caption">Waktu laporan</dt>
                        <dd className="mt-0.5 text-sm text-ink">
                          <span className="inline-flex items-center gap-1.5">
                            <Clock3 size={13} aria-hidden="true" />
                            {formatDateTime(selectedReport.createdAt)}
                          </span>
                        </dd>
                      </div>
                      <div>
                        <dt className="type-caption">Terakhir diperbarui</dt>
                        <dd className="mt-0.5 text-sm text-ink">
                          {formatDateTime(selectedReport.moderation?.updatedAt ?? null)}
                        </dd>
                      </div>
                      <div>
                        <dt className="type-caption">ID laporan</dt>
                        <dd className="mt-0.5 break-all font-mono text-xs text-ink-soft">
                          {selectedReport.id}
                        </dd>
                      </div>
                      <div>
                        <dt className="type-caption">Pembaruan terakhir oleh</dt>
                        <dd className="mt-0.5 font-mono text-xs text-ink-soft">
                          {selectedReport.moderation?.updatedBy
                            ? shortenedUid(selectedReport.moderation.updatedBy)
                            : 'Belum ada moderator'}
                        </dd>
                      </div>
                    </dl>

                    <div className="mt-4">
                      <p className="type-caption font-medium text-ink">
                        Alasan yang dilaporkan pengguna
                      </p>
                      <p className="type-small mt-1 whitespace-pre-wrap rounded-card border border-line bg-subtle/50 p-3 text-ink-soft">
                        {selectedReport.reportText || 'Tidak ada alasan yang tersimpan.'}
                      </p>
                    </div>

                    <div className="mt-4 rounded-card border border-line p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <LockKeyhole size={14} aria-hidden="true" className="text-ink-muted" />
                        <p className="text-sm font-medium text-ink">
                          Catatan internal moderator
                        </p>
                        <Badge tone="neutral">Tidak publik</Badge>
                      </div>
                      <p className="type-small mt-2 whitespace-pre-wrap text-ink-soft">
                        {selectedReport.moderation?.note ||
                          'Belum ada catatan internal untuk laporan ini.'}
                      </p>
                    </div>

                    <Alert tone="info" className="mt-4" title="Bukti yang tersedia">
                      Laporan ini berisi alasan, kategori, URL tersanitasi, hostname, dan waktu
                      kirim dari pengguna. Tidak ada hasil pemindai otomatis yang dilampirkan.
                      Status berbahaya hanya boleh ditetapkan melalui peninjauan manual.
                    </Alert>

                    <div className="mt-5 border-t border-line pt-4">
                      <h3 className="text-sm font-semibold text-ink">Tindakan moderasi</h3>

                      {actionError ? (
                        <Alert
                          tone="danger"
                          role="alert"
                          className="mt-3"
                          title="Tindakan tidak tersimpan"
                        >
                          {actionError}
                        </Alert>
                      ) : null}

                      {pendingAction ? (
                        <div
                          role="group"
                          aria-label="Konfirmasi tindakan moderasi"
                          className="mt-3 rounded-card border border-line bg-subtle/40 p-4"
                        >
                          <p className="text-sm font-semibold text-ink">
                            {pendingAction.label}
                          </p>
                          <p className="type-small mt-1 text-ink-soft">
                            {pendingAction.description}
                          </p>

                          <label
                            htmlFor="moderation-note"
                            className="mt-3 block text-sm font-medium text-ink"
                          >
                            Catatan internal (opsional)
                          </label>
                          <Textarea
                            id="moderation-note"
                            value={note}
                            maxLength={MAX_NOTE_LENGTH}
                            disabled={submitting}
                            onChange={(event) => setNote(event.target.value)}
                            placeholder="Alasan keputusan, bukti yang diperiksa, atau konteks untuk moderator lain."
                            className="mt-1.5 min-h-24"
                          />
                          <div className="mt-1 flex flex-wrap items-center justify-between gap-2">
                            <p className="type-caption">
                              Hanya terlihat moderator melalui aturan akses data.
                            </p>
                            <p className="type-caption tabular-nums">
                              {note.length}/{MAX_NOTE_LENGTH}
                            </p>
                          </div>

                          <div className="mt-4 flex flex-wrap gap-2">
                            <Button
                              variant={pendingAction.destructive ? 'danger' : 'primary'}
                              size="sm"
                              onClick={() => void handleConfirmDecision()}
                              disabled={submitting}
                            >
                              {submitting
                                ? 'Menyimpan…'
                                : `Konfirmasi: ${pendingAction.label}`}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setPendingAction(null)}
                              disabled={submitting}
                            >
                              Batal
                            </Button>
                          </div>
                        </div>
                      ) : availableActions.length > 0 ? (
                        <div className="mt-3 grid gap-2 sm:grid-cols-2">
                          {availableActions.map((action) => (
                            <Button
                              key={action.to}
                              variant={action.destructive ? 'secondary' : 'primary'}
                              size="sm"
                              className="justify-start"
                              onClick={() => {
                                setPendingAction(action)
                                setActionError(null)
                                setActionSuccess(null)
                              }}
                            >
                              {action.label}
                            </Button>
                          ))}
                        </div>
                      ) : (
                        <p className="type-small mt-2 text-ink-soft">
                          Status akhir sudah ditetapkan dan tidak dapat dibuka kembali dari
                          dashboard ini. Pembuatan keputusan baru untuk laporan yang sama tidak
                          diizinkan.
                        </p>
                      )}
                    </div>

                    <div className="mt-5 border-t border-line pt-4">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <h3 className="text-sm font-semibold text-ink">Riwayat moderasi</h3>
                        <Badge tone="neutral">Audit admin-only</Badge>
                      </div>
                      <p className="type-caption mt-1">
                        Catatan audit tidak dapat diubah atau dihapus dari aplikasi.
                      </p>

                      {historyStatus === 'loading' ? (
                        <p role="status" className="type-small mt-3 text-ink-soft">
                          Memuat riwayat moderasi…
                        </p>
                      ) : historyStatus === 'error' ? (
                        <div className="mt-3">
                          <Alert tone="warning" title="Riwayat moderasi gagal dimuat">
                            {historyError ?? 'Riwayat tidak dapat dibaca.'}
                          </Alert>
                          <Button
                            variant="secondary"
                            size="sm"
                            className="mt-2"
                            onClick={() => void loadHistoryFor(selectedReport.id)}
                          >
                            Coba muat riwayat
                          </Button>
                        </div>
                      ) : history.length === 0 ? (
                        <p className="type-small mt-3 text-ink-soft">
                          Belum ada tindakan moderasi yang tercatat untuk laporan ini.
                        </p>
                      ) : (
                        <ul aria-label="Riwayat moderasi laporan" className="mt-3">
                          {history.map((entry) => (
                            <HistoryEntry key={entry.id} entry={entry} />
                          ))}
                        </ul>
                      )}
                    </div>
                  </>
                )}
              </Card>
            </div>
          </>
        )}

        <Alert tone="info" className="mt-6" title="Batas dan tanggung jawab moderasi">
          Antrean memuat maksimal 500 laporan dan 500 catatan moderasi per pembacaan. Keputusan
          moderasi bersifat manual, tidak mengubah hasil pemindaian pengguna, dan hanya status
          “Terverifikasi berbahaya” yang dapat dianggap sebagai konfirmasi. Laporan publik tetap
          tidak dapat diubah; catatan internal serta audit hanya dapat dibaca admin.
        </Alert>
      </>
    )
  }

  return (
    <Container className="pb-16 sm:pb-20">
      <PageHeader
        eyebrow="Dashboard admin"
        title="Moderasi komunitas"
        description="Tinjau laporan komunitas, periksa bukti, lalu tetapkan status melalui tindakan yang tercatat. Hanya akun pada daftar admin yang dapat membaca data ini."
        actions={pageActions}
      />

      <DashboardTabs isAdmin={adminRole.isAdmin} />

      {content}
    </Container>
  )
}

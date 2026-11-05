import {
  Download,
  History,
  Link2,
  MessageSquareText,
  Search,
  SearchX,
  Trash2,
  X,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link, Navigate, useLocation } from 'react-router-dom'
import { Alert } from '../components/ui/Alert'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { buttonStyles } from '../components/ui/buttonStyles'
import { Card } from '../components/ui/Card'
import { Container } from '../components/ui/Container'
import { Input } from '../components/ui/Input'
import { PageHeader } from '../components/ui/PageHeader'
import { SegmentedControl } from '../components/ui/SegmentedControl'
import { StatePanel } from '../components/ui/StatePanel'
import { RISK_VISUALS } from '../lib/analysis'
import type { RiskLevel, ScanResult } from '../lib/analysis'
import { useAuth } from '../lib/auth/useAuth'
import { downloadHistoryCsv } from '../lib/export/downloadHistory'
import { firestoreErrorMessage } from '../lib/firebase/errors'
import { useScanHistory } from '../lib/scans/useScanHistory'

const dateFormatter = new Intl.DateTimeFormat('id-ID', {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
})

const TYPE_OPTIONS = [
  { value: 'all', label: 'Semua' },
  { value: 'link', label: 'Tautan' },
  { value: 'message', label: 'Pesan' },
] as const

const RISK_OPTIONS = [
  { value: 'all', label: 'Semua' },
  { value: 'low', label: 'Rendah' },
  { value: 'medium', label: 'Sedang' },
  { value: 'high', label: 'Tinggi' },
] as const

const SORT_OPTIONS = [
  { value: 'newest', label: 'Terbaru' },
  { value: 'oldest', label: 'Terlama' },
] as const

type TypeFilter = (typeof TYPE_OPTIONS)[number]['value']
type RiskFilter = (typeof RISK_OPTIONS)[number]['value']
type SortOrder = (typeof SORT_OPTIONS)[number]['value']

function formatDate(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'Waktu tidak diketahui' : dateFormatter.format(date)
}

function timeValue(value: string): number {
  const time = Date.parse(value)
  return Number.isNaN(time) ? 0 : time
}

function matchesQuery(scan: ScanResult, query: string): boolean {
  if (!query) return true

  const haystack = [
    scan.input,
    scan.displayTarget,
    scan.summary,
    scan.headline,
    scan.mode === 'link' ? 'tautan link url' : 'pesan message',
    ...scan.reasons.flatMap((reason) => [reason.label, reason.detail]),
    ...scan.patterns.map((pattern) => pattern.label),
  ]
    .join(' ')
    .toLowerCase()

  return haystack.includes(query)
}

function riskFilterLabel(value: RiskFilter): string | null {
  if (value === 'all') return null
  return `Risiko ${RISK_VISUALS[value].shortLabel.toLowerCase()}`
}

function typeFilterLabel(value: TypeFilter): string | null {
  if (value === 'all') return null
  return value === 'link' ? 'Jenis: Tautan' : 'Jenis: Pesan'
}

export function HistoryPage() {
  const auth = useAuth()
  const location = useLocation()
  const {
    scans,
    loading,
    error,
    errorKind,
    source,
    pendingLocalCount,
    syncMessage,
    refresh,
    remove,
    clear,
    syncLocalHistory,
  } = useScanHistory()
  const [query, setQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all')
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all')
  const [sortOrder, setSortOrder] = useState<SortOrder>('newest')
  const [exported, setExported] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const exportedResetTimer = useRef<number | null>(null)

  useEffect(
    () => () => {
      if (exportedResetTimer.current !== null) {
        window.clearTimeout(exportedResetTimer.current)
      }
    },
    [],
  )
  const cloud = source === 'cloud'

  const normalizedQuery = query.trim().toLowerCase()
  const hasFilters =
    normalizedQuery.length > 0 || typeFilter !== 'all' || riskFilter !== 'all'

  const filteredScans = scans
    .filter((scan) => {
      if (typeFilter !== 'all' && scan.mode !== typeFilter) return false
      if (riskFilter !== 'all' && scan.riskLevel !== riskFilter) return false
      return matchesQuery(scan, normalizedQuery)
    })
    .sort((a, b) =>
      sortOrder === 'newest'
        ? timeValue(b.createdAt) - timeValue(a.createdAt)
        : timeValue(a.createdAt) - timeValue(b.createdAt),
    )

  async function handleDelete(id: string) {
    setActionError(null)
    try {
      await remove(id)
    } catch (cause) {
      setActionError(
        cloud
          ? firestoreErrorMessage(cause)
          : cause instanceof Error
            ? cause.message
            : 'Pemeriksaan gagal dihapus dari riwayat.',
      )
    }
  }

  async function handleClear() {
    if (scans.length === 0) return
    const target = cloud ? 'akun ini' : 'perangkat ini'
    if (!window.confirm(`Hapus seluruh riwayat pemeriksaan dari ${target}?`)) return

    setActionError(null)
    try {
      await clear()
    } catch (cause) {
      setActionError(
        cloud
          ? firestoreErrorMessage(cause)
          : cause instanceof Error
            ? cause.message
            : 'Riwayat pemeriksaan gagal dihapus.',
      )
    }
  }

  async function handleSyncLocalHistory() {
    setActionError(null)
    const result = await syncLocalHistory()

    if (result.failed > 0) {
      setActionError(result.message ?? 'Riwayat perangkat belum berhasil dikirim ke akun.')
    }
  }

  function resetFilters() {
    setQuery('')
    setTypeFilter('all')
    setRiskFilter('all')
  }

  function handleExport() {
    if (!downloadHistoryCsv(filteredScans)) return

    setExported(true)
    if (exportedResetTimer.current !== null) window.clearTimeout(exportedResetTimer.current)
    exportedResetTimer.current = window.setTimeout(() => {
      exportedResetTimer.current = null
      setExported(false)
    }, 2400)
  }

  const returnTo = `${location.pathname}${location.search}${location.hash}`

  if (auth.mode === 'firebase' && auth.status === 'loading') {
    return (
      <Container className="pb-16 sm:pb-20">
        <PageHeader
          eyebrow="Riwayat"
          title="Riwayat pemeriksaan"
          actions={<Badge tone="neutral">Memulihkan sesi</Badge>}
        />
        <StatePanel
          role="status"
          icon={History}
          tone="neutral"
          title="Memeriksa sesi akun…"
          description="Riwayat akun tidak ditampilkan sebelum status sesi akun diketahui."
          className="mt-8 max-w-[720px]"
        />
      </Container>
    )
  }

  if (auth.mode === 'firebase' && auth.status === 'error') {
    return (
      <Container className="pb-16 sm:pb-20">
        <PageHeader
          eyebrow="Riwayat"
          title="Riwayat pemeriksaan"
          actions={<Badge tone="high">Layanan akun bermasalah</Badge>}
        />
        <Alert tone="danger" className="mt-8" title="Layanan akun gagal disiapkan">
          {auth.initializationError ??
            'Layanan akun belum dapat disiapkan. Muat ulang halaman atau hubungi pengelola layanan.'}
        </Alert>
      </Container>
    )
  }

  if (
    auth.mode === 'firebase' &&
    auth.status === 'ready' &&
    (!auth.user || auth.user.isAnonymous)
  ) {
    return <Navigate to="/masuk" replace state={{ from: returnTo }} />
  }

  return (
    <Container className="pb-16 sm:pb-20">
      <PageHeader
        eyebrow="Riwayat"
        title="Riwayat pemeriksaan"
        description={
          cloud
            ? 'Cari, saring, dan tinjau kembali hasil pemeriksaan yang tersimpan di akunmu.'
            : 'Cari, saring, dan tinjau kembali hasil pemeriksaan yang tersimpan di browser ini.'
        }
        actions={
          scans.length > 0 ? (
            <>
              <Button
                variant="secondary"
                size="sm"
                onClick={handleExport}
                disabled={filteredScans.length === 0}
              >
                <Download size={15} aria-hidden="true" />
                {exported ? 'CSV diunduh' : 'Ekspor CSV'}
              </Button>
              <Button variant="ghost" size="sm" onClick={handleClear}>
                Hapus semua
              </Button>
            </>
          ) : undefined
        }
      />

      {error ? (
        <Alert
          tone="danger"
          className="mt-6"
          title={
            errorKind === 'permission'
              ? 'Akses riwayat ditolak'
              : errorKind === 'session'
                ? 'Sesi akun berakhir'
                : 'Riwayat akun gagal dimuat'
          }
        >
          <p>{error}</p>
          {errorKind === 'permission' ? (
            <ul className="mt-3 list-disc space-y-1.5 pl-4">
              <li>Pastikan kamu masuk dengan akun yang menyimpan pemeriksaan ini.</li>
              <li>Pastikan aplikasi sudah diperbarui ke versi terbaru.</li>
              <li>
                Perubahan aturan dapat memerlukan waktu singkat. Setelah aktif, tekan “Coba
                lagi”.
              </li>
            </ul>
          ) : null}
          {errorKind === 'offline' ? (
            <p className="mt-2">Periksa koneksi internet, lalu muat ulang riwayat.</p>
          ) : null}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Button variant="secondary" size="sm" onClick={refresh}>
              Coba lagi
            </Button>
            {errorKind === 'session' ? (
              <Link
                to="/masuk"
                state={{ from: '/riwayat' }}
                className={buttonStyles({ variant: 'ghost', size: 'sm' })}
              >
                Masuk kembali
              </Link>
            ) : null}
          </div>
        </Alert>
      ) : null}

      {actionError ? (
        <Alert tone="danger" role="alert" className="mt-4" title="Tindakan gagal">
          {actionError}
        </Alert>
      ) : null}

      {cloud && pendingLocalCount > 0 ? (
        <Alert
          tone="warning"
          className="mt-4"
          title={`${pendingLocalCount} pemeriksaan masih tertahan di perangkat ini`}
        >
          <p>
            {syncMessage ??
              'Riwayat ini sudah tersimpan di browser, tetapi belum masuk ke penyimpanan akun.'}{' '}
            Salinan yang dikirim ke akun memakai ID yang sama, jadi mencobanya ulang tidak membuat
            dokumen kembar.
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Button variant="secondary" size="sm" onClick={handleSyncLocalHistory}>
              Sinkronkan sekarang
            </Button>
          </div>
        </Alert>
      ) : null}

      {loading && scans.length === 0 ? (
        <div className="mt-8">
          <StatePanel
            role="status"
            icon={History}
            tone="neutral"
            title="Memuat riwayat akun…"
            description="Mengambil pemeriksaan milik akun yang sedang masuk."
            className="max-w-[720px]"
          />
        </div>
      ) : scans.length === 0 ? (
        error ? null : (
          <div className="mt-8">
            <StatePanel
              icon={History}
              tone="neutral"
              title="Belum ada riwayat"
              actions={
                <Link to="/periksa" className={buttonStyles()}>
                  Mulai pemeriksaan
                </Link>
              }
              className="max-w-[720px]"
            >
              <p className="type-small mt-2 max-w-[62ch] text-ink-soft">
                {cloud
                  ? 'Setelah pemeriksaan pertama saat masuk, hasilnya akan muncul di akun ini dan tersedia di perangkat lain.'
                  : 'Setelah pemeriksaan pertama, hasilnya akan muncul di sini dan dapat dibuka kembali selama data browser ini tidak dihapus.'}
              </p>
              {cloud ? (
                <p className="type-caption mt-3 max-w-[46ch]">
                  Pemeriksaan yang pernah dibuat di perangkat ini dikirim ke akun begitu halaman
                  ini dibuka. Selama pengiriman belum berhasil, salinannya tetap tersimpan di
                  browser dan tidak pernah dihapus lebih dulu.
                </p>
              ) : null}
            </StatePanel>
          </div>
        )
      ) : (
        <>
          <Card className="mt-8 p-4 sm:p-5">
            <div>
              <label htmlFor="history-search" className="text-sm font-medium text-ink">
                Cari riwayat
              </label>
              <div className="relative mt-1.5">
                <Search
                  size={16}
                  aria-hidden="true"
                  className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-ink-muted"
                />
                <Input
                  id="history-search"
                  type="search"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="Cari URL, isi pesan, ringkasan, atau pola…"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  className="pl-10"
                />
              </div>
            </div>

            <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              <div>
                <span className="type-caption mb-1.5 block font-medium">Jenis pemeriksaan</span>
                <SegmentedControl
                  options={TYPE_OPTIONS}
                  value={typeFilter}
                  onChange={setTypeFilter}
                  label="Filter jenis pemeriksaan"
                />
              </div>
              <div>
                <span className="type-caption mb-1.5 block font-medium">Tingkat risiko</span>
                <SegmentedControl
                  options={RISK_OPTIONS}
                  value={riskFilter}
                  onChange={setRiskFilter}
                  label="Filter tingkat risiko"
                />
              </div>
              <div>
                <span className="type-caption mb-1.5 block font-medium">Urutan waktu</span>
                <SegmentedControl
                  options={SORT_OPTIONS}
                  value={sortOrder}
                  onChange={setSortOrder}
                  label="Urutan riwayat"
                />
              </div>
            </div>

            {hasFilters ? (
              <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-line pt-4">
                <span className="type-caption font-medium">Filter aktif:</span>
                {normalizedQuery ? (
                  <Badge tone="accent" className="gap-1 pr-1">
                    Pencarian: “{query.trim()}”
                    <button
                      type="button"
                      onClick={() => setQuery('')}
                      aria-label="Hapus filter pencarian"
                      className="grid size-5 place-items-center rounded-full transition-colors hover:bg-accent/10"
                    >
                      <X size={12} aria-hidden="true" />
                    </button>
                  </Badge>
                ) : null}
                {typeFilter !== 'all' ? (
                  <Badge tone="neutral" className="gap-1 pr-1">
                    {typeFilterLabel(typeFilter)}
                    <button
                      type="button"
                      onClick={() => setTypeFilter('all')}
                      aria-label="Hapus filter jenis pemeriksaan"
                      className="grid size-5 place-items-center rounded-full transition-colors hover:bg-line"
                    >
                      <X size={12} aria-hidden="true" />
                    </button>
                  </Badge>
                ) : null}
                {riskFilter !== 'all' ? (
                  <Badge
                    tone={RISK_VISUALS[riskFilter as RiskLevel].badgeTone}
                    className="gap-1 pr-1"
                  >
                    {riskFilterLabel(riskFilter)}
                    <button
                      type="button"
                      onClick={() => setRiskFilter('all')}
                      aria-label="Hapus filter tingkat risiko"
                      className="grid size-5 place-items-center rounded-full transition-colors hover:bg-surface/60"
                    >
                      <X size={12} aria-hidden="true" />
                    </button>
                  </Badge>
                ) : null}
                <Button variant="ghost" size="sm" className="ml-auto" onClick={resetFilters}>
                  Reset filter
                </Button>
              </div>
            ) : null}
          </Card>

          <div className="mt-6 flex flex-wrap items-end justify-between gap-2">
            <p role="status" aria-live="polite" className="type-small text-ink-soft">
              Menampilkan <span className="font-semibold text-ink">{filteredScans.length}</span> dari{' '}
              <span className="font-semibold text-ink">{scans.length}</span> pemeriksaan.
              {hasFilters ? ' Ekspor CSV mengikuti filter aktif.' : ''}
            </p>
          </div>

          {filteredScans.length === 0 ? (
            <StatePanel
              icon={SearchX}
              tone="neutral"
              title="Tidak ada hasil yang cocok"
              actions={<Button variant="secondary" onClick={resetFilters}>Reset filter</Button>}
              className="mt-4 max-w-[720px]"
            >
              <p className="type-small mt-2 max-w-[62ch] text-ink-soft">
                Coba kata kunci lain, ubah jenis pemeriksaan atau tingkat risiko, lalu periksa
                kembali.
              </p>
            </StatePanel>
          ) : (
            <ul aria-label="Daftar riwayat pemeriksaan" className="mt-4 flex flex-col gap-3">
              {filteredScans.map((scan) => {
                const visual = RISK_VISUALS[scan.riskLevel]
                const Icon = scan.mode === 'link' ? Link2 : MessageSquareText
                const redacted = scan.mode === 'message' && scan.meta.inputStored === 'redacted'

                return (
                  <li
                    key={scan.id}
                    className="rounded-card border border-line bg-surface p-4 shadow-card transition-colors hover:border-line-strong"
                  >
                    <div className="flex items-start gap-3">
                      <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-subtle text-ink-muted">
                        <Icon size={17} aria-hidden="true" />
                      </span>

                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5">
                          <Link
                            to={`/hasil/${scan.id}`}
                            className="min-w-0 truncate text-sm font-medium text-ink hover:text-accent"
                          >
                            {scan.displayTarget}
                          </Link>
                          <Badge tone={visual.badgeTone}>{visual.shortLabel}</Badge>
                        </div>
                        <p className="type-caption mt-1">
                          {formatDate(scan.createdAt)} · Skor indikator {scan.riskScore}/100 ·{' '}
                          {scan.mode === 'link' ? 'Tautan' : 'Pesan'}
                          {redacted ? ' · Isi disamarkan' : ''}
                        </p>
                        <p className="type-small mt-2 line-clamp-2 text-ink-soft">{scan.summary}</p>
                        <Link
                          to={`/hasil/${scan.id}`}
                          className="mt-2 inline-block text-xs font-medium text-accent underline-offset-4 hover:underline"
                        >
                          Lihat detail
                        </Link>
                      </div>

                      <Button
                        variant="ghost"
                        size="sm"
                        className="shrink-0 px-2"
                        aria-label={`Hapus pemeriksaan ${scan.displayTarget}`}
                        onClick={() => handleDelete(scan.id)}
                      >
                        <Trash2 size={16} aria-hidden="true" />
                      </Button>
                    </div>
                  </li>
                )
              })}
            </ul>
          )}
        </>
      )}

      <Alert tone="info" className="mt-6" title="Tentang penyimpanan">
        {cloud
          ? 'Riwayat dimuat dari penyimpanan data akun ini, maksimal 30 pemeriksaan terakhir dan paling lama 90 hari. Pemeriksaan yang pernah dibuat di perangkat ini — sebelum email terverifikasi atau saat sinkronisasi gagal — dikirim ke akun ketika halaman ini dibuka, memakai ID yang sama sehingga tidak pernah dobel. Isi pesan hanya disimpan lengkap jika kamu memberi izin; jika tidak, cuplikan disamarkan sebelum diunggah.'
          : 'Riwayat disimpan di browser perangkat ini, maksimal 30 pemeriksaan terakhir dan paling lama 90 hari. Isi pesan hanya disimpan lengkap jika kamu memberi izin saat memeriksa; jika tidak, cuplikan pesan disamarkan sebelum disimpan. Setelah email terverifikasi, riwayat perangkat ini dikirim ke akun; salinan lokal baru dihapus bila penyimpanan akun sudah mengonfirmasi keberhasilannya.'}
      </Alert>
    </Container>
  )
}

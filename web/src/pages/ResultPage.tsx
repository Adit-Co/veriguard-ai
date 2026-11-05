import {
  Activity,
  ArrowLeft,
  ArrowRight,
  Check,
  Copy,
  FileQuestion,
  Globe2,
  Layers,
  Printer,
  ShieldAlert,
  ShieldCheck,
  Tags,
  TriangleAlert,
} from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import { CommunityContextPanel } from '../components/community/CommunityContextPanel'
import { MultiSourceReportPanel } from '../components/result/MultiSourceReportPanel'
import { RiskFusionSummary, SiteAnalysisArea } from '../components/site/SiteAnalysisArea'
import type { SiteSection } from '../components/site/SiteAnalysisArea'
import { Alert } from '../components/ui/Alert'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { buttonStyles } from '../components/ui/buttonStyles'
import { Card } from '../components/ui/Card'
import { Container } from '../components/ui/Container'
import { PageHeader } from '../components/ui/PageHeader'
import { StatePanel } from '../components/ui/StatePanel'
import { SegmentedControl } from '../components/ui/SegmentedControl'
import { RISK_VISUALS, riskLabel } from '../lib/analysis'
import type { DetectedPattern, PatternConfidence, RiskLevel, ScanResult } from '../lib/analysis'
import { buildLocalReport } from '../lib/scanners/report'
import { getScanReport } from '../lib/scanners/reportStore'
import { agentLabel } from '../lib/scanners/agentLabels'
import { EXTERNAL_PROVIDER_IDS } from '../lib/scanners/types'
import type { MultiSourceReport } from '../lib/scanners/types'
import { isMultiSourceReport } from '../lib/scanners/validate'
import { useScan } from '../lib/scans/useScan'
import { useSiteAnalysis } from '../lib/website/useSiteAnalysis'
import { cn } from '../lib/cn'
import { styleValue } from '../lib/styleValue'

const RISK_ICONS: Record<RiskLevel, typeof ShieldCheck> = {
  low: ShieldCheck,
  medium: TriangleAlert,
  high: ShieldAlert,
}

type DetailTab = 'threat' | SiteSection

const DETAIL_TABS: readonly { value: DetailTab; label: string; icon: typeof Globe2 }[] = [
  { value: 'threat', label: 'Reputasi Ancaman', icon: ShieldCheck },
  { value: 'website', label: 'Website Intelligence', icon: Globe2 },
  { value: 'category', label: 'Kategori Website', icon: Tags },
  { value: 'technology', label: 'Analisis Teknologi', icon: Layers },
  { value: 'behavior', label: 'Analisis Perilaku', icon: Activity },
]

const SEVERITY_DOT: Record<string, string> = {
  danger: 'bg-risk-high',
  warning: 'bg-risk-medium',
  info: 'bg-info',
}

const CONFIDENCE_LABEL: Record<PatternConfidence, string> = {
  high: 'Kuat',
  medium: 'Sedang',
  low: 'Lemah',
}

const CONFIDENCE_TONE: Record<PatternConfidence, 'high' | 'medium' | 'neutral'> = {
  high: 'high',
  medium: 'medium',
  low: 'neutral',
}

const dateFormatter = new Intl.DateTimeFormat('id-ID', {
  day: 'numeric',
  month: 'long',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
})

function formatDate(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'Waktu tidak diketahui' : dateFormatter.format(date)
}

function patternSummary(patterns: DetectedPattern[]): string {
  if (patterns.length === 0) return 'Tidak ada pola spesifik'
  return patterns.map((pattern) => pattern.label).join(', ')
}

// VGL-32A: tiga tingkat vonis laporan — Indikasi Risiko Rendah / Perlu Perhatian / Berbahaya.
const REPORT_VERDICT_LABEL: Record<MultiSourceReport['verdict'], string> = {
  malicious: 'Berbahaya (temuan ancaman terverifikasi)',
  suspicious: 'Perlu Perhatian (indikasi menengah, perlu verifikasi)',
  clean: 'Indikasi Risiko Rendah (bukti bersih mencukupi)',
  inconclusive: 'Perlu Perhatian (bukti belum mencukupi)',
}

function buildCopyText(scan: ScanResult, report?: MultiSourceReport | null): string {
  const reasons = scan.reasons
    .map((reason) => `- ${reason.label}: ${reason.detail}`)
    .join('\n')
  const recommendations = scan.recommendations
    .map((recommendation, index) => `${index + 1}. ${recommendation}`)
    .join('\n')
  const reportLines = report
    ? [
        '',
        'Laporan multi-sumber:',
        `- Verdict gabungan: ${REPORT_VERDICT_LABEL[report.verdict]} (skor ${report.score}/100, bukan probabilitas)`,
        `- Kelengkapan eksternal: ${report.completeness.checked}/${report.completeness.total} agen`,
        `- Sumber: ${report.providers
          .map((provider) => `${agentLabel(provider.id, provider.label)} (${provider.status})`)
          .join(', ')}`,
      ]
    : []

  return [
    'VERIGUARD AI — Hasil pemeriksaan',
    `Diperiksa: ${formatDate(scan.createdAt)}`,
    `Jenis: ${scan.mode === 'link' ? 'Tautan' : 'Pesan'}`,
    `Target: ${scan.input}`,
    `Hasil: ${riskLabel(scan.riskLevel)} (skor heuristik leksikal ${scan.riskScore}/100)`,
    '',
    `Ringkasan: ${scan.summary}`,
    '',
    'Indikator:',
    reasons || '- Tidak ada indikator risiko yang terdeteksi.',
    '',
    'Pola:',
    patternSummary(scan.patterns),
    '',
    'Rekomendasi:',
    recommendations,
    ...reportLines,
    '',
    'Catatan: skor adalah jumlah bobot indikator, bukan probabilitas. Analisis memakai aturan heuristik; AI generatif belum terhubung. Risiko rendah bukan jaminan aman.',
    ...(scan.mode === 'message' && scan.meta.inputStored === 'redacted'
      ? [
          '',
          'Catatan privasi: tautan, email, nomor telepon, dan deretan angka pada isi pesan disamarkan sebelum disimpan.',
        ]
      : []),
  ].join('\n')
}

type SectionCardProps = {
  title: string
  description?: string
  children: ReactNode
  className?: string
}

function SectionCard({ title, description, children, className }: SectionCardProps) {
  return (
    <Card className={cn('p-5 print-avoid-break sm:p-6', className)}>
      <h2 className="type-h3">{title}</h2>
      {description ? <p className="type-caption mt-1">{description}</p> : null}
      <div className="mt-4">{children}</div>
    </Card>
  )
}

export function ResultPage() {
  const { id } = useParams<{ id: string }>()
  const location = useLocation()
  const { scan, loading, error, source, retry } = useScan(id)
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'failed'>('idle')
  const [detailTab, setDetailTab] = useState<DetailTab>('threat')
  const copyResetTimer = useRef<number | null>(null)

  useEffect(
    () => () => {
      if (copyResetTimer.current !== null) window.clearTimeout(copyResetTimer.current)
    },
    [],
  )
  const navigationReport = (location.state as { multiSourceReport?: unknown } | null)
    ?.multiSourceReport
  const stateReport = isMultiSourceReport(navigationReport) ? navigationReport : null
  // Status sinkronisasi hanya datang dari navigasi pemeriksaan yang baru selesai; riwayat yang
  // dibuka kembali tidak boleh menampilkan peringatan tentang koneksi saat ini.
  const navigatedSyncNotice = (location.state as { syncNotice?: unknown } | null)?.syncNotice
  const syncNotice =
    typeof navigatedSyncNotice === 'string' && navigatedSyncNotice.length > 0
      ? navigatedSyncNotice
      : null
  const multiSourceReport = !scan
    ? null
    : scan.mode === 'link'
      ? (getScanReport(scan.id) ?? stateReport ?? buildLocalReport(scan))
      : null
  // URL sensitif disamarkan sebelum masuk penyimpanan, jadi sesi yang baru selesai tetap
  // memakai target asli dari laporan navigasi. Riwayat yang dibuka kembali memakai salinan
  // yang sudah aman: analisis situs dijalankan pada alamat yang tersisa, bukan token aslinya.
  const analysisTarget =
    scan?.mode === 'link' && scan.meta.inputStored === 'redacted' && stateReport?.target
      ? stateReport.target
      : (scan?.input ?? '')
  const siteAnalysis = useSiteAnalysis(scan?.id ?? '', analysisTarget, {
    // Alur yang diminta: URL yang sama dianalisis otomatis setelah agen selesai, yaitu pada
    // navigation yang baru saja menjalankan pemeriksaan. Laporan yang dibuka lagi dari riwayat
    // tidak boleh memicu permintaan keluar baru ke URL target tanpa tindakan pengguna; di
    // sana pengguna menekan "Jalankan analisis" sendiri. Gerbangnya tetap sama: hanya URL yang
    // memang sudah dikirim ke layanan atas tindakan pengguna, bukan URL sensitif.
    autoRun:
      scan?.mode === 'link' &&
      Boolean(scan?.input) &&
      stateReport?.externalRequested === true &&
      stateReport.sensitiveUrl !== true,
  })

  if (loading) {
    return (
      <Container className="pb-16 sm:pb-20">
        <PageHeader
          eyebrow="Hasil"
          title="Hasil pemeriksaan"
          description="Memuat hasil dari perangkat atau akunmu."
          actions={<Badge tone="neutral">Memuat</Badge>}
        />
        <StatePanel
          role="status"
          icon={Activity}
          tone="neutral"
          title="Memuat hasil pemeriksaan…"
          description="Hasil diambil dari penyimpanan lokal tamu atau akun yang sedang masuk."
          className="mt-8 max-w-[720px]"
        />
      </Container>
    )
  }

  if (error) {
    return (
      <Container className="pb-16 sm:pb-20">
        <PageHeader
          eyebrow="Hasil"
          title="Hasil belum dapat dimuat"
          description="Terjadi masalah saat mengambil data pemeriksaan dari akun."
        />
        <StatePanel
          icon={TriangleAlert}
          tone="danger"
          title="Koneksi ke penyimpanan data gagal"
          description={error}
          actions={
            <>
              <Button onClick={retry}>Coba lagi</Button>
              <Link to="/riwayat" className={buttonStyles({ variant: 'secondary', size: 'md' })}>
                Buka riwayat
              </Link>
            </>
          }
          className="mt-8 max-w-[720px]"
        />
      </Container>
    )
  }

  if (!scan) {
    const cloud = source === 'cloud'

    return (
      <Container className="pb-16 sm:pb-20">
        <PageHeader
          eyebrow="Hasil"
          title="Hasil tidak ditemukan"
          description={
            cloud
              ? 'Data pemeriksaan ini tidak tersedia di akun yang sedang masuk.'
              : 'Data pemeriksaan ini tidak tersedia di browser yang sedang kamu gunakan.'
          }
        />

        <StatePanel
          icon={FileQuestion}
          tone="neutral"
          title="Hasil mungkin sudah dihapus"
          actions={
            <div className="contents print:hidden">
              <Link to="/periksa" className={buttonStyles({ size: 'md' })}>
                Mulai pemeriksaan baru
              </Link>
              <Link to="/riwayat" className={buttonStyles({ variant: 'secondary', size: 'md' })}>
                Buka riwayat
              </Link>
            </div>
          }
          className="mt-8 max-w-[720px]"
        >
          <p className="type-small mt-2 max-w-[62ch] text-ink-soft">
            {cloud
              ? 'Hasil mungkin sudah dihapus dari akun ini. Periksa kembali riwayat akun atau mulai pemeriksaan baru.'
              : 'Riwayat pemeriksaan disimpan secara lokal di perangkat ini. Hasil tidak dapat dibuka dari perangkat atau browser lain, dan akan hilang jika data situs dibersihkan.'}
          </p>
          {id ? <p className="type-caption mt-3">ID pemeriksaan: {id}</p> : null}

        </StatePanel>
      </Container>
    )
  }

  const visual = RISK_VISUALS[scan.riskLevel]
  const RiskIcon = RISK_ICONS[scan.riskLevel]
  const modeLabel = scan.mode === 'link' ? 'Tautan' : 'Pesan'
  const inputRedacted = scan.meta.inputStored === 'redacted'
  const messageRedacted = scan.mode === 'message' && inputRedacted
  const linkRedacted = scan.mode === 'link' && inputRedacted
  const copyText = buildCopyText(scan, multiSourceReport)

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(copyText)
      setCopyState('copied')
      if (copyResetTimer.current !== null) window.clearTimeout(copyResetTimer.current)
      copyResetTimer.current = window.setTimeout(() => {
        copyResetTimer.current = null
        setCopyState('idle')
      }, 2200)
    } catch {
      setCopyState('failed')
    }
  }

  return (
    <Container className="pb-16 sm:pb-20">
      <div className="flex flex-col gap-5 border-b border-line pb-8 pt-12 sm:flex-row sm:items-end sm:justify-between sm:pt-16">
        <div className="max-w-[640px]">
          <Link
            to="/riwayat"
            className="type-caption inline-flex items-center gap-1.5 text-ink-muted transition-colors hover:text-ink print:hidden"
          >
            <ArrowLeft size={14} aria-hidden="true" />
            Riwayat pemeriksaan
          </Link>
          <p className="type-eyebrow mt-4 text-accent">Hasil</p>
          <h1 className="type-h1 mt-3">Hasil pemeriksaan</h1>
          <p className="type-small mt-2 text-ink-soft">
            Diperiksa {formatDate(scan.createdAt)} · {modeLabel} ·{' '}
            {scan.meta.inputLength.toLocaleString('id-ID')} karakter dianalisis
          </p>
        </div>

        <div className="flex flex-wrap gap-2 print:hidden">
          <Button variant="secondary" size="sm" onClick={handleCopy}>
            {copyState === 'copied' ? (
              <Check size={15} aria-hidden="true" />
            ) : (
              <Copy size={15} aria-hidden="true" />
            )}
            {copyState === 'copied'
              ? 'Tersalin'
              : copyState === 'failed'
                ? 'Gagal menyalin'
                : 'Salin ringkasan'}
          </Button>
          <Button variant="secondary" size="sm" onClick={() => window.print()}>
            <Printer size={15} aria-hidden="true" />
            Cetak
          </Button>
        </div>
      </div>

      {syncNotice ? (
        <Alert tone="warning" className="mt-6 print:hidden" title="Hasil tersimpan di perangkat ini">
          {syncNotice} Pemeriksaan tetap dapat dibuka dari halaman ini dan riwayat perangkat. Buka
          halaman riwayat untuk mengirimnya ke akun setelah koneksi pulih; salinan di akun dibuat
          dengan ID yang sama sehingga tidak pernah dobel.
        </Alert>
      ) : null}

      {scan.mode === 'link' ? (
        <div className="mt-8 print:hidden">
          <SegmentedControl
            options={DETAIL_TABS}
            value={detailTab}
            onChange={setDetailTab}
            label="Tampilan hasil pemeriksaan"
          />
          <p className="type-caption mt-2">
            Menu tambahan hanya membaca data teknis situs untuk URL yang sama dan berjalan otomatis
            setelah {EXTERNAL_PROVIDER_IDS.length} agen selesai. Berpindah menu tidak menjalankan
            ulang agen mana pun dan tidak mengubah skor maupun verdict.
          </p>
        </div>
      ) : null}

      {scan.mode === 'link' && detailTab !== 'threat' ? (
        <div className="mt-4">
          <SiteAnalysisArea
            section={detailTab}
            analysis={siteAnalysis}
            riskLevelLabel={`${riskLabel(scan.riskLevel)} (heuristik leksikal)`}
          />
        </div>
      ) : (
        <>
          {multiSourceReport ? (
            <div className="mt-8">
              <MultiSourceReportPanel report={multiSourceReport} />
            </div>
          ) : null}
      <section
        aria-labelledby="verdict-title"
        className={cn(
          multiSourceReport ? 'mt-4' : 'mt-8',
          'overflow-hidden rounded-panel border',
          visual.panelClass,
        )}
      >
        <div className="grid gap-6 p-6 sm:p-8 lg:grid-cols-[minmax(0,1fr)_250px] lg:items-center">
          <div>
            <div className="flex items-start gap-3">
              <span
                className={cn(
                  'grid size-11 shrink-0 place-items-center rounded-full border',
                  visual.iconClass,
                )}
              >
                <RiskIcon size={23} aria-hidden="true" />
              </span>
              <div>
                <p className="type-eyebrow text-ink-muted">Indikasi internal · heuristik leksikal</p>
                <h2 id="verdict-title" className={cn('type-h2 mt-1', visual.scoreClass)}>
                  {scan.headline}
                </h2>
              </div>
            </div>

            <p className="mt-4 max-w-[62ch] text-sm leading-relaxed text-ink-soft sm:text-base">
              {scan.summary}
            </p>

            <div className="mt-4 flex flex-wrap gap-2">
              <Badge tone={visual.badgeTone}>{visual.label}</Badge>
              <Badge tone="neutral">{modeLabel}</Badge>
              <Badge tone="neutral">Heuristik leksikal</Badge>
            </div>
          </div>

          <div className="rounded-card border border-glass-line bg-surface/80 p-5">
            <p className="type-caption text-ink-muted">Skor heuristik leksikal</p>
            <p className={cn('mt-1 text-4xl font-semibold tabular-nums tracking-tight', visual.scoreClass)}>
              {scan.riskScore}
              <span className="ml-1 text-base font-normal text-ink-muted">/100</span>
            </p>
            <div
              role="img"
              aria-label={`Skor heuristik leksikal ${scan.riskScore} dari 100`}
              className="mt-3 h-2 overflow-hidden rounded-full bg-line"
            >
              <div
                className={cn('h-full rounded-full', visual.barClass)}
                ref={styleValue('width', `${scan.riskScore}%`)}
              />
            </div>
            <p className="type-caption mt-3">
              Bukan probabilitas. Skor adalah jumlah bobot indikator yang ditemukan pada teks URL atau
              pesan, tanpa membuka DNS, sertifikat, registrasi, maupun halaman. Skor fusi analisis situs
              dan vonis {EXTERNAL_PROVIDER_IDS.length} agen tampil terpisah dan tidak digabung dengan
              angka ini.
            </p>
          </div>
        </div>
      </section>

      {/* Nilai analisis internal (fusi risiko layanan situs) tampil di blok Internal ini,
          bukan sebagai kartu terpisah di setiap menu analisis situs. Angkanya tetap berdiri
          sendiri dan tidak pernah digabung dengan skor heuristik leksikal di atas. */}
      {scan.mode === 'link' && siteAnalysis.data ? (
        <div className="mt-4">
          <RiskFusionSummary risk={siteAnalysis.data.risk} />
        </div>
      ) : null}

      {scan.mode === 'link' ? <CommunityContextPanel url={scan.input} /> : null}

      <Card className="mt-4 p-5 print-avoid-break">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-ink">Yang diperiksa</h2>
          <span className="type-caption">
            {modeLabel} · {scan.meta.signalCount} indikator
          </span>
        </div>
        {scan.mode === 'link' ? (
          <p className="mt-3 break-all rounded-btn bg-subtle px-3 py-2 font-mono text-sm text-ink">
            {scan.input}
          </p>
        ) : (
          <blockquote
            tabIndex={0}
            aria-label={messageRedacted ? 'Cuplikan isi pesan yang tersimpan' : 'Isi pesan yang diperiksa'}
            className="mt-3 max-h-72 overflow-y-auto whitespace-pre-wrap rounded-btn bg-subtle px-3 py-2 text-sm leading-relaxed text-ink-soft"
          >
            {scan.input}
          </blockquote>
        )}

        {messageRedacted ? (
          <Alert tone="info" className="mt-3" title="Isi pesan disamarkan sebelum disimpan">
            Tautan, email, nomor telepon, dan deretan angka pada cuplikan di atas sudah diganti.
            Skor dan indikator tetap dihitung dari teks asli saat pemeriksaan berlangsung.
          </Alert>
        ) : null}
        {linkRedacted ? (
          <Alert tone="info" className="mt-3" title="Sebagian alamat disamarkan sebelum disimpan">
            URL ini terdeteksi memuat data sensitif, jadi parameter kueri, kredensial, dan token pada
            jalurnya diganti sebelum masuk ke riwayat. Skor dan indikator tetap dihitung dari alamat
            asli saat pemeriksaan berlangsung.
          </Alert>
        ) : null}
      </Card>

      <div className="mt-4 grid gap-4 lg:grid-cols-2 lg:items-start">
        <SectionCard
          title="Mengapa hasil ini muncul"
          description={
            scan.reasons.length > 0
              ? 'Indikator diurutkan berdasarkan bobot terbesar.'
              : 'Tidak ada indikator risiko pada aturan yang tersedia.'
          }
        >
          {scan.reasons.length > 0 ? (
            <ul className="divide-y divide-line">
              {scan.reasons.map((reason) => (
                <li key={reason.id} className="flex gap-3 py-3 first:pt-0 last:pb-0">
                  <span
                    aria-hidden="true"
                    className={cn(
                      'mt-1.5 size-2 shrink-0 rounded-full',
                      SEVERITY_DOT[reason.severity] ?? 'bg-line-strong',
                    )}
                  />
                  <div>
                    <p className="text-sm font-medium text-ink">{reason.label}</p>
                    <p className="type-small mt-0.5 text-ink-soft">{reason.detail}</p>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-ink-soft">
              Tidak ada indikator yang terdeteksi. Hasil ini tetap bukan jaminan bahwa input
              tersebut aman.
            </p>
          )}
        </SectionCard>

        <SectionCard
          title="Pola yang terdeteksi"
          description={
            scan.patterns.length > 0
              ? 'Pola yang paling mirip dengan temuan pada input ini.'
              : 'Tidak ada pola penipuan spesifik yang cocok.'
          }
        >
          {scan.patterns.length > 0 ? (
            <ul className="flex flex-col gap-3">
              {scan.patterns.map((pattern) => (
                <li
                  key={pattern.id}
                  className="rounded-card border border-line bg-canvas p-3.5"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-sm font-medium text-ink">{pattern.label}</p>
                    <Badge tone={CONFIDENCE_TONE[pattern.confidence]}>
                      {CONFIDENCE_LABEL[pattern.confidence]}
                    </Badge>
                  </div>
                  <p className="type-small mt-1.5 text-ink-soft">{pattern.description}</p>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-ink-soft">
              Tidak ada pola penipuan spesifik yang cocok. Tetap verifikasi melalui kanal resmi.
            </p>
          )}

          <div className="mt-5 border-t border-line pt-4">
            <h3 className="text-sm font-semibold text-ink">Rincian teknis</h3>
            <dl className="mt-3 grid gap-x-4 gap-y-2 sm:grid-cols-2">
              {scan.technical.map((item) => (
                <div key={item.label} className="flex flex-col gap-0.5">
                  <dt className="type-caption">{item.label}</dt>
                  <dd
                    className={cn(
                      'break-words text-sm',
                      item.tone === 'danger'
                        ? 'text-risk-high'
                        : item.tone === 'warning'
                          ? 'text-risk-medium'
                          : 'text-ink',
                    )}
                  >
                    {item.value}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </SectionCard>
      </div>

      <SectionCard
        title="Langkah berikutnya"
        description="Rekomendasi ini bersifat umum dan menyesuaikan pola yang terdeteksi."
        className="mt-4"
      >
        <ol className="grid gap-3 sm:grid-cols-2">
          {scan.recommendations.map((recommendation, index) => (
            <li
              key={recommendation}
              className="flex gap-3 rounded-card border border-line bg-canvas p-3.5"
            >
              <span className="grid size-6 shrink-0 place-items-center rounded-full bg-accent-soft text-xs font-semibold text-accent">
                {index + 1}
              </span>
              <span className="text-sm leading-relaxed text-ink-soft">{recommendation}</span>
            </li>
          ))}
        </ol>
      </SectionCard>

      <Card className="mt-4 border-dashed bg-subtle/60 p-5 print-avoid-break sm:p-6">
        <h2 className="text-sm font-semibold text-ink">Informasi Pemeriksaan</h2>
        <dl className="mt-3 flex flex-col gap-3 text-sm">
          <div>
            <dt className="font-semibold text-ink">Proses Analisis:</dt>
            <dd className="mt-0.5 leading-relaxed break-words text-ink-soft">
              Pemeriksaan dilakukan berdasarkan indikator keamanan dan karakteristik ancaman digital
              yang teridentifikasi oleh sistem.
            </dd>
          </div>
          <div>
            <dt className="font-semibold text-ink">Pemeriksaan Tautan:</dt>
            <dd className="mt-0.5 leading-relaxed break-words text-ink-soft">
              VERIGUARD AI menganalisis informasi URL tanpa membuka halaman tujuan secara langsung.
              Pemeriksaan tambahan dapat dilakukan melalui layanan eksternal yang tersedia.
            </dd>
          </div>
          <div>
            <dt className="font-semibold text-ink">Privasi Pengguna:</dt>
            <dd className="mt-0.5 leading-relaxed break-words text-ink-soft">
              URL dan informasi sensitif ditangani dengan memperhatikan keamanan serta kebijakan
              privasi pengguna.
            </dd>
          </div>
          <div>
            <dt className="font-semibold text-ink">Metode Deteksi:</dt>
            <dd className="mt-0.5 leading-relaxed break-words text-ink-soft">
              Sistem menggunakan aturan keamanan dan indikator heuristik untuk mengidentifikasi
              potensi phishing, penipuan, dan aktivitas mencurigakan.
            </dd>
          </div>
          <div>
            <dt className="font-semibold text-ink">Interpretasi Hasil:</dt>
            <dd className="mt-0.5 leading-relaxed break-words text-ink-soft">
              Setiap hasil pemeriksaan merupakan dasar pertimbangan keamanan. Risiko rendah bukan
              jaminan bahwa tautan atau pesan tersebut aman.
            </dd>
          </div>
          <div>
            <dt className="font-semibold text-ink">Batas yang perlu diketahui:</dt>
            <dd className="mt-0.5 leading-relaxed break-words text-ink-soft">
              {multiSourceReport?.externalShared
                ? 'Hasil internal memakai aturan heuristik; hasil eksternal berasal dari agen yang menerima URL saat kamu menekan Periksa tautan dan dapat tertinggal dari perubahan situs.'
                : 'Hasil berasal dari aturan heuristik. AI generatif belum terhubung pada versi ini.'}{' '}
              HTTPS bukan bukti situs tepercaya; situs penipuan juga dapat memakai HTTPS.{' '}
              {multiSourceReport?.externalShared
                ? 'Pemeriksaan reputasi tidak membuka halaman tujuan; agen eksternal dapat membukanya saat memeriksa URL.'
                : scan.mode === 'link'
                  ? 'Tautan tidak dibuka pada pemeriksaan reputasi, sehingga isi halaman tujuan tidak diperiksa. Menu analisis situs membuka URL satu kali atas tindakanmu sendiri.'
                  : 'Tautan di dalam pesan tidak dibuka, sehingga isi halaman tujuan tidak diperiksa.'}{' '}
              Selalu verifikasi melalui aplikasi atau situs resmi yang kamu cari sendiri, bukan
              melalui tautan pada pesan.
            </dd>
          </div>
        </dl>

        <div className="mt-4 border-t border-line pt-4">
          <h3 className="text-sm font-semibold text-ink">Butuh informasi lebih lanjut?</h3>
          <Link
            to="/edukasi"
            className="mt-2 inline-block text-sm font-medium text-accent underline-offset-4 hover:underline"
          >
            Pelajari Pola Penipuan
          </Link>
        </div>
      </Card>
        </>
      )}

      <div className="mt-6 flex flex-wrap gap-3 print:hidden">
        <Link to="/periksa" className={buttonStyles({ size: 'md' })}>
          Periksa lagi
          <ArrowRight size={16} aria-hidden="true" />
        </Link>
        <Link to="/riwayat" className={buttonStyles({ variant: 'secondary', size: 'md' })}>
          Buka riwayat
        </Link>
        <Link to="/edukasi" className={buttonStyles({ variant: 'ghost', size: 'md' })}>
          Pelajari pola penipuan
        </Link>
      </div>
    </Container>
  )
}

import { useState } from 'react'
import { Play, RefreshCw } from 'lucide-react'
import { Alert } from '../ui/Alert'
import { Badge } from '../ui/Badge'
import { Button } from '../ui/Button'
import { Card } from '../ui/Card'
import { Spinner } from '../ui/Spinner'
import { BehaviorPanel } from './BehaviorPanel'
import { TechnologyPanel } from './TechnologyPanel'
import { WebsiteCategoryPanel } from './WebsiteCategoryPanel'
import { WebsiteIntelligencePanel } from './WebsiteIntelligencePanel'
import { EmptyHint, NoteList, SectionTitle } from './siteKit'
import type { BadgeTone } from './siteFormat'
import type { UseSiteAnalysisResult } from '../../lib/website/useSiteAnalysis'
import { EXTERNAL_PROVIDER_IDS } from '../../lib/scanners/types'
import type {
  EvidenceStrength,
  RiskFusion,
  ScanStatus,
  SiteAnalysisResponse,
  SiteRiskLevel,
} from '../../lib/website/types'
import { userFacingText } from '../../lib/uiText'
import { styleValue } from '../../lib/styleValue'

export type SiteSection = 'website' | 'category' | 'technology' | 'behavior'

const SECTION_LABEL: Record<SiteSection, string> = {
  website: 'Website Intelligence',
  category: 'Kategori Website',
  technology: 'Analisis Teknologi',
  behavior: 'Analisis Perilaku',
}

function SiteSkeleton({ section }: { section: SiteSection }) {
  return (
    <Card className="p-5 sm:p-6" role="status" aria-busy="true">
      <div className="flex items-center gap-2.5">
        <Spinner label={`Memuat ${SECTION_LABEL[section]}`} />
        <p className="text-sm font-semibold text-ink">{SECTION_LABEL[section]} sedang berjalan</p>
      </div>
      <p className="type-caption mt-2">
        Layanan pemeriksaan sedang membaca DNS, sertifikat, dan satu permintaan HTTP terbatas.
        Pemeriksaan ini tidak mengubah hasil {EXTERNAL_PROVIDER_IDS.length} agen maupun Reputasi
        Ancaman.
      </p>
      <div className="mt-4 flex flex-col gap-3" aria-hidden="true">
        {[0, 1, 2].map((row) => (
          <div key={row} className="h-16 rounded-card border border-line bg-subtle/60 animate-pulse" />
        ))}
      </div>
    </Card>
  )
}

function NotRun({
  section,
  analysis,
  onRun,
}: {
  section: SiteSection
  analysis: UseSiteAnalysisResult
  onRun: () => void
}) {
  return (
    <Card className="p-5 sm:p-6">
      <h2 className="type-h3">{SECTION_LABEL[section]}</h2>
      <p className="type-small mt-2 text-ink-soft">
        Bagian ini membutuhkan layanan pemeriksaan untuk membuka URL tersebut satu kali dengan
        batasan ketat: skema hanya HTTP(S), alamat internal/loopback/metadata diblokir, batas
        waktu, batas ukuran, dan maksimal empat redirect.
      </p>
      <p className="type-small mt-2 text-ink-soft">
        Selama kamu hanya membuka hasil, tidak ada permintaan baru ke target. Tekan tombol di bawah
        untuk menjalankan analisis situs ini.
      </p>
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <Button type="button" onClick={onRun}>
          <Play size={16} aria-hidden="true" />
          Jalankan analisis situs
        </Button>
        <span className="type-caption max-w-[46ch]">
          Menekan tombol adalah persetujuan membuka URL ini untuk pemeriksaan teknis. Hanya periksa
          URL yang berwenang kamu periksa.
        </span>
      </div>
      {analysis.error ? (
        <Alert tone="danger" title="Analisis situs gagal" className="mt-4">
          <p>{userFacingText(analysis.error)}</p>
        </Alert>
      ) : null}
    </Card>
  )
}

function Failed({ analysis, onRun }: { analysis: UseSiteAnalysisResult; onRun: () => void }) {
  return (
    <Card className="p-5 sm:p-6">
      <Alert tone="danger" title="Analisis situs tidak selesai" className="mb-4">
        <p>{userFacingText(analysis.error ?? 'Analisis situs gagal dijalankan.')}</p>
        <p className="mt-1">
          Hasil {EXTERNAL_PROVIDER_IDS.length} agen, Reputasi Ancaman, skor risiko, dan statistik
          tetap seperti sebelumnya.
        </p>
      </Alert>
      <Button type="button" variant="secondary" onClick={onRun}>
        <RefreshCw size={15} aria-hidden="true" />
        Coba lagi
      </Button>
    </Card>
  )
}

function Unavailable({ section }: { section: SiteSection }) {
  return (
    <Card className="p-5 sm:p-6">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="type-h3">{SECTION_LABEL[section]}</h2>
        <Badge tone="neutral">Tidak tersedia</Badge>
      </div>
      <p className="type-small mt-2 text-ink-soft">
        Versi ini tidak terhubung ke layanan pemeriksaan yang dapat membuka URL (DNS, TLS, dan
        HTTP), jadi bagian ini tidak menampilkan data contoh maupun data karangan. Jalankan layanan
        pemeriksaan lokal atau aktifkan layanan pemeriksaan untuk memakai analisis situs.
      </p>
    </Card>
  )
}

const LEVEL_LABEL: Record<SiteRiskLevel, string> = {
  unknown: 'Tidak dapat ditentukan',
  low: 'Rendah',
  medium: 'Sedang',
  high: 'Tinggi',
  critical: 'Kritis',
}

const LEVEL_TONE: Record<SiteRiskLevel, BadgeTone> = {
  unknown: 'neutral',
  low: 'low',
  medium: 'medium',
  high: 'high',
  critical: 'high',
}

const SCAN_STATUS_LABEL: Record<ScanStatus, string> = {
  complete: 'Pemeriksaan lengkap',
  partial: 'Pemeriksaan sebagian',
  limited: 'Cakupan terbatas',
  failed: 'Pemeriksaan gagal',
}

const SCAN_STATUS_TONE: Record<ScanStatus, BadgeTone> = {
  complete: 'low',
  partial: 'medium',
  limited: 'medium',
  failed: 'high',
}

const CONFIDENCE_LABEL: Record<RiskFusion['confidence'], string> = {
  high: 'Keyakinan tinggi',
  medium: 'Keyakinan sedang',
  low: 'Keyakinan rendah',
}

const STRENGTH_LABEL: Record<EvidenceStrength, string> = {
  strong: 'bukti kuat',
  moderate: 'bukti sedang',
  weak: 'bukti lemah',
  mitigating: 'bukti yang meringankan',
}

function coverageText(coverage: RiskFusion['coverage']): string {
  if (coverage.totalChecks <= 0) return 'cakupan tidak dinyatakan'
  const ratio =
    coverage.ratio === null
      ? ''
      : ` (${Math.round(Math.min(1, Math.max(0, coverage.ratio)) * 100)}%)`
  return `${coverage.succeeded}/${coverage.totalChecks} pemeriksaan selesai${ratio}`
}

/**
 * Fusi risiko datang dari layanan pemeriksaan situs, jadi angkanya ditampilkan sendiri dan tidak
 * pernah digabung dengan skor heuristik leksikal maupun vonis agen eksternal. Nilainya sekarang
 * menjadi bagian dari blok Internal di Reputasi Ancaman (`ResultPage`), bukan kartu terpisah di
 * setiap menu analisis situs.
 */
export function RiskFusionSummary({ risk }: { risk: RiskFusion | null }) {
  if (!risk) {
    return (
      <Card className="p-5 sm:p-6">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <SectionTitle description="Skor ini dihitung dari bukti yang berhasil diamati layanan pemeriksaan (DNS, registrasi, TLS, halaman), bukan dari teks URL saja.">
            Skor Analisis Situs
          </SectionTitle>
          <Badge tone="neutral">Belum dinilai</Badge>
        </div>
        <EmptyHint>
          Laporan tersimpan ini belum membawa hasil fusi risiko. Jalankan analisis situs untuk
          memperolehnya; tanpa analisis, tidak ada skor yang dikarang atau dianggap nol.
        </EmptyHint>
      </Card>
    )
  }

  const incomplete = risk.status !== 'complete' || risk.level === 'unknown'

  return (
    <Card className="p-5 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <SectionTitle
          description={`Skor dan bukti berasal dari fusi hasil analisis situs. Ia berdiri sendiri, terpisah dari skor heuristik leksikal maupun vonis ${EXTERNAL_PROVIDER_IDS.length} agen.`}
        >
          Skor Analisis Situs
        </SectionTitle>
        <Badge tone={SCAN_STATUS_TONE[risk.status]}>{SCAN_STATUS_LABEL[risk.status]}</Badge>
      </div>

      <div className="mt-4 grid gap-4 sm:grid-cols-[160px_minmax(0,1fr)] sm:items-start">
        <div className="rounded-card border border-line bg-canvas p-4">
          <p className="type-caption text-ink-muted">Skor fusi</p>
          <p className="mt-1 text-3xl font-semibold tabular-nums tracking-tight text-ink">
            {risk.riskScore === null ? '—' : risk.riskScore}
            {risk.riskScore === null ? null : (
              <span className="ml-1 text-base font-normal text-ink-muted">/100</span>
            )}
          </p>
          {risk.riskScore === null ? null : (
            <div
              role="img"
              aria-label={`Skor fusi analisis situs ${risk.riskScore} dari 100`}
              className="mt-3 h-2 overflow-hidden rounded-full bg-line"
            >
              <div
                className={
                  risk.level === 'high' || risk.level === 'critical'
                    ? 'h-full rounded-full bg-risk-high'
                    : risk.level === 'medium'
                      ? 'h-full rounded-full bg-risk-medium'
                      : 'h-full rounded-full bg-risk-low'
                }
                ref={styleValue('width', `${risk.riskScore}%`)}
              />
            </div>
          )}
          <p className="type-caption mt-3">{coverageText(risk.coverage)}</p>
        </div>

        <div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={LEVEL_TONE[risk.level]}>Tingkat risiko: {LEVEL_LABEL[risk.level]}</Badge>
            <Badge tone="neutral">{CONFIDENCE_LABEL[risk.confidence]}</Badge>
          </div>
          <p className="type-small mt-2 break-words text-ink-soft">
            {userFacingText(risk.confidenceDetail)}
          </p>
        </div>
      </div>

      {incomplete ? (
        <Alert tone="warning" title="Cakupan belum lengkap" className="mt-4">
          <p>
            Status {SCAN_STATUS_LABEL[risk.status].toLowerCase()} dengan{' '}
            {coverageText(risk.coverage)}
            {risk.notEvaluated.length > 0
              ? ` dan ${risk.notEvaluated.length} pemeriksaan tidak dinilai`
              : ''}
            . Level rendah pada cakupan terbatas bukan konfirmasi bahwa target aman.
          </p>
        </Alert>
      ) : null}

      {risk.evidence.length > 0 ? (
        <div className="mt-4">
          <p className="type-caption text-ink-muted">Bukti yang ditemukan</p>
          <ul className="mt-2 flex flex-col gap-2">
            {risk.evidence.map((entry) => (
              <li key={entry.id} className="rounded-card border border-line bg-canvas p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <p className="text-sm font-semibold text-ink">
                    {entry.label || entry.id}
                  </p>
                  <Badge tone={entry.strength === 'strong' ? 'high' : 'neutral'}>
                    {STRENGTH_LABEL[entry.strength]}
                  </Badge>
                </div>
                <p className="type-caption mt-1 break-words text-ink-soft">
                  {userFacingText(entry.detail)}
                </p>
                <p className="type-caption mt-1 break-words text-ink-muted">
                  Sumber: {userFacingText(entry.source)} · sumbu {entry.category}
                  {entry.observed ? ` · teramati ${userFacingText(entry.observed)}` : ''}
                </p>
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <EmptyHint>
          Tidak ada bukti risiko yang dikumpulkan pada pemeriksaan ini. Ketiadaan bukti berarti
          pemeriksaan belum menemukan dasar, bukan konfirmasi bahwa target aman.
        </EmptyHint>
      )}

      {risk.notEvaluated.length > 0 ? (
        <div className="mt-4">
          <p className="type-caption text-ink-muted">Pemeriksaan yang tidak dinilai</p>
          <ul className="mt-2 flex flex-col gap-1.5">
            {risk.notEvaluated.map((item) => (
              <li key={item} className="type-caption flex gap-2">
                <span aria-hidden="true" className="mt-1.5 size-1 shrink-0 rounded-full bg-line-strong" />
                <span>{userFacingText(item)}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <NoteList notes={risk.notes} />
    </Card>
  )
}

function pickSection(
  data: SiteAnalysisResponse,
  section: SiteSection,
  riskLevelLabel: string,
) {
  if (section === 'website') return <WebsiteIntelligencePanel data={data.website} />
  if (section === 'category') {
    return <WebsiteCategoryPanel data={data.category} riskLevelLabel={riskLevelLabel} />
  }
  if (section === 'technology') return <TechnologyPanel data={data.technology} />
  return <BehaviorPanel data={data.behavior} />
}

export function SiteAnalysisArea({
  section,
  analysis,
  riskLevelLabel,
}: {
  section: SiteSection
  analysis: UseSiteAnalysisResult
  riskLevelLabel: string
}) {
  const [confirmRun, setConfirmRun] = useState(false)

  if (!analysis.available) return <Unavailable section={section} />
  if (analysis.state === 'running') return <SiteSkeleton section={section} />
  if (analysis.state === 'failed') return <Failed analysis={analysis} onRun={() => void analysis.run()} />
  if (analysis.state === 'idle') {
    // Analisis berjalan otomatis setelah agen eksternal selesai, jadi jangan tampilkan
    // tombol "jalankan" sesaat sebelum hasilnya datang.
    if (analysis.autoRun && !analysis.error) return <SiteSkeleton section={section} />
    if (!confirmRun) {
      return (
        <NotRun
          section={section}
          analysis={analysis}
          onRun={() => {
            setConfirmRun(true)
            void analysis.run()
          }}
        />
      )
    }
    return <SiteSkeleton section={section} />
  }

  if (!analysis.data) return <NotRun section={section} analysis={analysis} onRun={() => void analysis.run()} />

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-card border border-line bg-surface px-4 py-3">
        <div className="min-w-0">
          <p className="type-caption text-ink-muted">
            Dibuat {new Intl.DateTimeFormat('id-ID', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(analysis.data.generatedAt))}
            {' · '}
            {analysis.data.probe.available
              ? 'layanan pemeriksaan siap'
              : 'layanan pemeriksaan tidak tersedia'}
          </p>
          <p className="type-caption mt-0.5 break-all">
            Target: {analysis.data.target} · durasi {Math.round(analysis.data.durationMs)} ms
          </p>
        </div>
        <Button type="button" variant="secondary" size="sm" onClick={() => void analysis.run()}>
          <RefreshCw size={14} aria-hidden="true" />
          Jalankan ulang
        </Button>
      </div>

      {!analysis.data.probe.available ? (
        <Alert tone="warning" title="Layanan pemeriksaan tidak dapat membaca situs">
          <p>
            {userFacingText(
              analysis.data.probe.detail ??
                'Layanan pemeriksaan yang dipakai tidak dapat menjalankan DNS/TLS/HTTP, jadi bagian ini hanya menampilkan status tidak tersedia.',
            )}
          </p>
        </Alert>
      ) : null}

      {pickSection(analysis.data, section, riskLevelLabel)}
    </div>
  )
}

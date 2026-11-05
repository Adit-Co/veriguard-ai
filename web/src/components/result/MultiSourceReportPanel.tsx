import {
  CircleHelp,
  Clock,
  Globe2,
  Lock,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react'
import { Alert } from '../ui/Alert'
import { Badge } from '../ui/Badge'
import { cn } from '../../lib/cn'
import {
  agentLabel,
  describeAgentProvider,
  sanitizeAgentText,
} from '../../lib/scanners/agentLabels'
import { classifyProviderEvidence, isStaleEvidence, reportDimensions } from '../../lib/scanners/report'
import type {
  EvidenceSufficiency,
  MultiSourceReport,
  NegativeEvidenceClass,
  ProviderResult,
  ProviderSignal,
  ProviderVerdict,
  VerdictConfidence,
} from '../../lib/scanners/types'
import { styleValue } from '../../lib/styleValue'

type BadgeTone = 'neutral' | 'accent' | 'low' | 'medium' | 'high' | 'info'

const VERDICT_VISUALS: Record<
  ProviderVerdict,
  {
    label: string
    description: string
    tone: BadgeTone
    panelClass: string
    scoreClass: string
    barClass: string
    icon: typeof ShieldCheck
  }
> = {
  malicious: {
    label: 'Berbahaya',
    description:
      'Setidaknya satu agen pemeriksaan menandai URL ini sebagai ancaman yang terverifikasi dan relevan dengan alamat ini. Label menggambarkan bukti yang teramati, bukan probabilitas. Lihat daftar bukti dan rincian agen di bawah.',
    tone: 'high',
    panelClass: 'border-risk-high-line bg-risk-high-bg',
    scoreClass: 'text-risk-high',
    barClass: 'bg-risk-high',
    icon: ShieldAlert,
  },
  suspicious: {
    label: 'Perlu Perhatian',
    description:
      'Terdapat indikasi risiko menengah dari agen yang memberi hasil, jadi verifikasi manual masih diperlukan. Label menggambarkan bukti yang teramati, bukan probabilitas.',
    tone: 'medium',
    panelClass: 'border-risk-medium-line bg-risk-medium-bg',
    scoreClass: 'text-risk-medium',
    barClass: 'bg-risk-medium',
    icon: TriangleAlert,
  },
  clean: {
    label: 'Indikasi Risiko Rendah',
    description:
      'Minimal dua provider berbeda dengan sumber bukti independen menyatakan hasil bersih untuk URL ini secara eksplisit dan masih berlaku, tanpa temuan ancaman, tanpa agen gagal, dan heuristik internal tidak menandai risiko. Dua adapter yang hanya meneruskan laporan identik dihitung satu agen. Bukti kedaluwarsa tidak dihitung; hasil "Tidak ada kecocokan data" dihitung sebagai pemeriksaan berhasil, bukan bukti bersih. Risiko rendah bukan jaminan aman; label menggambarkan bukti yang teramati, bukan probabilitas.',
    tone: 'low',
    panelClass: 'border-risk-low-line bg-risk-low-bg',
    scoreClass: 'text-risk-low',
    barClass: 'bg-risk-low',
    icon: ShieldCheck,
  },
  inconclusive: {
    label: 'Perlu Perhatian',
    description:
      'Bukti yang tersedia belum memenuhi syarat klasifikasi Risiko Rendah: jumlah bukti bersih yang valid, kesegarannya, atau kelengkapan pemeriksaan belum cukup. Kekurangan data tidak boleh dibaca sebagai aman maupun berbahaya.',
    tone: 'neutral',
    panelClass: 'border-line bg-subtle/60',
    scoreClass: 'text-ink',
    barClass: 'bg-line-strong',
    icon: CircleHelp,
  },
}

// VGL-31 TAHAP 3 — tiga dimensi tambahan yang ditampilkan TERPISAH dari skor. Skor risiko
// mengukur bukti ancaman; kecukupan bukti mengukur apakah bukti negatif cukup untuk vonis
// bersih; cakupan agen mengukur berapa agen yang benar-benar memberi hasil; keyakinan vonis
// mengukur seberapa kuat dasar vonis itu. Menyatukan keempatnya akan mengulang kesalahan yang
// persis ingin dihindari PATCH ini.
const SUFFICIENCY_LABELS: Record<EvidenceSufficiency['level'], string> = {
  sufficient: 'Cukup untuk Risiko Rendah',
  limited: 'Belum cukup — ada pendukung',
  insufficient: 'Tidak cukup',
}

const CONFIDENCE_LABELS: Record<VerdictConfidence, string> = {
  high: 'Tinggi',
  medium: 'Sedang',
  low: 'Rendah',
}

const EVIDENCE_CLASS_LABELS: Record<NegativeEvidenceClass, string> = {
  scan_verdict: 'vonis pemindaian',
  engine_verdicts: 'hasil kumpulan mesin',
  scanner_verdict: 'vonis pemindai',
  threat_list: 'daftar ancaman',
}

const STATUS_VISUALS: Record<
  ProviderResult['status'],
  { label: string; tone: BadgeTone }
> = {
  success: { label: 'Selesai', tone: 'low' },
  // Aturan global: no-match = PEMERIKSAAN SELESAI dengan temuan "tidak ada kecocokan data".
  // Status eksekusi HARAM berubah menjadi Gagal hanya karena provider tidak punya data.
  // Detail temuan ditampilkan terpisah lewat providerRisk() di bawah.
  not_found: { label: 'Selesai', tone: 'low' },
  not_configured: { label: 'Belum dikonfigurasi', tone: 'neutral' },
  auth_failed: { label: 'Gagal autentikasi', tone: 'high' },
  unavailable: { label: 'Tidak tersedia', tone: 'neutral' },
  rate_limited: { label: 'Dibatasi', tone: 'medium' },
  skipped: { label: 'Tidak dijalankan', tone: 'neutral' },
  timeout: { label: 'Melebihi batas waktu', tone: 'medium' },
  invalid_request: { label: 'Permintaan ditolak', tone: 'medium' },
  error: { label: 'Gagal', tone: 'high' },
}

const PROVIDER_RISK: Record<ProviderVerdict, { label: string; tone: BadgeTone }> = {
  malicious: { label: 'Berbahaya', tone: 'high' },
  suspicious: { label: 'Mencurigakan', tone: 'medium' },
  clean: { label: 'Tidak ditemukan indikasi', tone: 'low' },
  inconclusive: { label: 'Belum konklusif', tone: 'neutral' },
}

function providerRisk(provider: ProviderResult): { label: string; tone: BadgeTone } {
  // VGL-31 TAHAP 2: label mengikuti JENIS bukti, bukan hanya status. "Tidak ada kecocokan"
  // (no_match) dan "bersih secara eksplisit" (confirmed_clean) adalah dua hal berbeda dan tidak
  // boleh tampil dengan kata yang sama.
  const kind = classifyProviderEvidence(provider)
  if (kind === 'no_match') return { label: 'Tidak ada kecocokan data', tone: 'neutral' }
  if (kind === 'unresolved') return { label: 'Tidak dapat dinilai', tone: 'neutral' }
  if (kind === 'confirmed_clean') return { label: 'Bersih dinyatakan provider', tone: 'low' }
  if (kind === 'limited_negative') return { label: 'Bukti negatif terbatas', tone: 'neutral' }

  return PROVIDER_RISK[provider.verdict]
}

const SEVERITY_DOT: Record<string, string> = {
  danger: 'bg-risk-high',
  warning: 'bg-risk-medium',
  info: 'bg-info',
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

function formatDuration(value: number): string {
  if (value < 1_000) return `${Math.round(value)} ms`
  return `${(value / 1_000).toFixed(1)} dtk`
}

function SignalList({
  providerId,
  signals,
}: {
  providerId: string
  signals: ProviderSignal[]
}) {
  return (
    <ul className="mt-2 flex flex-col gap-2">
      {signals.slice(0, 3).map((signal, index) => (
        <li key={`${providerId}-${index}`} className="flex gap-2">
          <span
            aria-hidden="true"
            className={cn(
              'mt-1.5 size-1.5 shrink-0 rounded-full',
              SEVERITY_DOT[signal.severity] ?? 'bg-line-strong',
            )}
          />
          <div>
            <p className="text-xs font-medium text-ink">{signal.label}</p>
            <p className="type-caption">{signal.detail}</p>
          </div>
        </li>
      ))}
    </ul>
  )
}

function ProviderCard({
  provider,
  className,
}: {
  provider: ProviderResult
  className?: string
}) {
  const view = describeAgentProvider(provider)
  const status = STATUS_VISUALS[provider.status]
  const risk = providerRisk(provider)
  const reportTime =
    provider.evidence?.source === 'existing_report' && provider.evidence.observedAt
      ? provider.evidence.observedAt
      : null

  // VGL-30K-R4: pemisahan TAMPILAN mengikuti pemisahan bukti di backend. Sinyal berbobot
  // (warning/danger) adalah bukti tentang alamat ini; sinyal `info` adalah intelijen komunitas
  // (penyebutan laporan, hitungan, cakupan penelusuran) yang secara desain tidak menyumbang
  // skor. Keduanya diberi kepala kelompok supaya hitungan laporan komunitas tidak dibacakan
  // sebagai konfirmasi ancaman, dan bukti yang menilai tidak tersingkir oleh sinyal info.
  const assessing = view.signals.filter((signal) => signal.severity !== 'info')
  const community = view.signals.filter((signal) => signal.severity === 'info')

  return (
    <article className={cn('rounded-card border border-line bg-canvas p-4', className)}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h4 className="text-sm font-semibold text-ink">{view.label}</h4>
          {view.summary ? (
            <p className="type-small mt-1 text-ink-soft">
              <span className="font-medium text-ink">{status.label} — </span>
              {view.summary}
            </p>
          ) : null}
        </div>
        <Badge tone={status.tone}>{status.label}</Badge>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Badge tone={risk.tone}>Risiko: {risk.label}</Badge>
        {provider.durationMs > 0 ? (
          <span className="type-caption inline-flex items-center gap-1">
            <Clock size={12} aria-hidden="true" />
            {formatDuration(provider.durationMs)}
          </span>
        ) : null}
      </div>

      {reportTime ? (
        <p className="type-caption mt-2 inline-flex items-center gap-1">
          <Clock size={12} aria-hidden="true" />
          Waktu laporan {formatDate(reportTime)}
        </p>
      ) : null}

      {provider.negative ? (
        <p className="type-caption mt-2">
          {provider.negative.strength === 'explicit'
            ? 'Bukti negatif eksplisit atas URL ini: '
            : 'Bukti negatif terbatas (pendukung, tidak menilai sendiri): '}
          {provider.negative.basis}
        </p>
      ) : null}

      {assessing.length > 0 ? (
        <div className="mt-3">
          <p className="type-eyebrow text-ink-muted">Bukti yang menilai alamat ini</p>
          <SignalList providerId={provider.id} signals={assessing} />
        </div>
      ) : null}

      {community.length > 0 ? (
        <div className="mt-3">
          <p className="type-eyebrow text-ink-muted">
            Intelijen komunitas — tanpa kontribusi skor
          </p>
          <SignalList providerId={`${provider.id}-community`} signals={community} />
        </div>
      ) : null}

      {view.reason ? (
        <p className="type-caption mt-3 border-t border-line pt-2">{view.reason}</p>
      ) : null}
    </article>
  )
}

// Catatan dari laporan lama bisa masih berisi penjelasan cara pengambilan hasil.
// Penyaringnya tunggal dan ada di lapisan teks agen (`sanitizeAgentText`), sehingga catatan
// yang seluruhnya narasi internal menjadi kosong dan tidak dirender di permukaan mana pun.
export function MultiSourceReportPanel({ report }: { report: MultiSourceReport }) {
  const visual = VERDICT_VISUALS[report.verdict]
  const dimensions = reportDimensions(report)
  const VerdictIcon = visual.icon
  // Laporan hari ini hanya berisi agen eksternal; penyaring ini menjaga riwayat lama yang
  // masih memuat baris "internal" agar tidak muncul sebagai kartu agen di panel multi-sumber.
  const externalProviders = report.providers.filter((provider) => provider.id !== 'internal')
  const notConfigured = report.completeness.notConfigured ?? 0
  const authFailed = report.completeness.authFailed ?? 0
  const skipped = report.completeness.skipped ?? 0
  const timeout = report.completeness.timeout ?? 0
  // VGL-30K-R1 §5: "permintaan ditolak" dihitung dari baris agen yang sebenarnya, lalu
  // dipisahkan dari ember "gagal" supaya bilangan cakupan tidak menyamaratakan penolakan
  // permintaan dengan galat provider. Bentuk kelengkapan laporan tidak diubah.
  const rejected = externalProviders.filter(
    (provider) => provider.status === 'invalid_request',
  ).length
  const unavailableOrError = Math.max(
    0,
    report.completeness.unavailable + report.completeness.error - rejected,
  )
  const reconstructed = report.notes.some((note) => note.startsWith('Laporan ini direkonstruksi'))
  const rateLimited =
    externalProviders.length > 0 &&
    externalProviders.every((provider) => provider.status === 'rate_limited')
  const visibleNotes = [
    ...new Set(
      report.notes
        .map((note) => sanitizeAgentText(note))
        .filter((note) => note.trim().length > 0),
    ),
  ]

  const evidence: string[] = []
  const flagged = externalProviders.filter(
    (provider) => provider.status === 'success' && provider.verdict === 'malicious',
  )
  const suspiciousFlagged = externalProviders.filter(
    (provider) => provider.status === 'success' && provider.verdict === 'suspicious',
  )
  // VGL-32A: daftar bukti memakai KELAS YANG SAMA dengan verdict engine
  // (`classifyProviderEvidence` + batas umur kesegaran), sehingga bukti yang ditampilkan
  // tidak pernah berbeda dari bukti yang dipakai menyimpulkan vonis. Baris `clean` tanpa
  // penanda bukti negatif — atau bukti bersih yang sudah kedaluwarsa — tidak lagi tampil
  // sebagai bukti penilaian.
  const isStale = (provider: ProviderResult): boolean => isStaleEvidence(provider)
  const confirmedClean = externalProviders.filter(
    (provider) => classifyProviderEvidence(provider) === 'confirmed_clean' && !isStale(provider),
  )
  const expiredClean = externalProviders.filter(
    (provider) => classifyProviderEvidence(provider) === 'confirmed_clean' && isStale(provider),
  )
  const noMatchRows = externalProviders.filter(
    (provider) => classifyProviderEvidence(provider) === 'no_match',
  )
  const labelOf = (provider: ProviderResult): string => agentLabel(provider.id, provider.label)

  for (const provider of flagged) {
    evidence.push(`${labelOf(provider)} menandai indikasi berbahaya pada URL ini.`)
  }
  for (const provider of suspiciousFlagged) {
    evidence.push(`${labelOf(provider)} menemukan indikasi yang perlu diperiksa lebih lanjut.`)
  }
  if (flagged.length === 0 && suspiciousFlagged.length === 0) {
    for (const provider of confirmedClean) {
      const klass = provider.negative
        ? (EVIDENCE_CLASS_LABELS[provider.negative.evidenceClass] ?? provider.negative.evidenceClass)
        : 'negatif'
      evidence.push(`${labelOf(provider)} menyatakan hasil bersih untuk URL ini (bukti negatif ${klass}, masih berlaku).`)
    }
    for (const provider of expiredClean) {
      evidence.push(
        `${labelOf(provider)} pernah menyatakan bersih, tetapi bukti itu melewati batas kesegarannya (kedaluwarsa) dan tidak dihitung untuk Risiko Rendah.`,
      )
    }
  }
  if (noMatchRows.length > 0) {
    evidence.push(
      `${noMatchRows.length} agen selesai diperiksa dengan hasil "Tidak ada kecocokan data"; pemeriksaan ini berhasil, tetapi ketiadaan catatan bukan bukti aman maupun kegagalan.`,
    )
  }
  // Cara pengambilan hasil (cache, dedup, laporan ulang) tidak pernah dijadikan "bukti" di
  // antarmuka: asal bukti disimpan sebagai metadata dan hanya waktu laporannya yang nyata
  // ditampilkan, lewat `reportTime` pada kartu agen.
  // Metadata cache tidak pernah tampil sebagai bukti/penjelasan kepada pengguna; ia tetap
  // tersedia di objek laporan untuk kebutuhan internal, bukan untuk dirender.
  const incomplete = report.completeness.total - report.completeness.checked
  if (incomplete > 0) {
    evidence.push(
      `${incomplete} dari ${report.completeness.total} agen tidak memberikan hasil; kondisi itu bukan bukti URL aman.`,
    )
  }
  if (report.sensitiveUrl) {
    evidence.push('URL tidak dikirim ke agen eksternal karena memuat data sensitif.')
  }
  if (report.externalError) {
    evidence.push(
      `Pemeriksaan eksternal tidak selesai: ${sanitizeAgentText(report.externalError)}.`,
    )
  }
  if (evidence.length === 0) {
    evidence.push(
      'Belum ada temuan agen yang dapat dijadikan bukti. Hasil tanpa kecocokan, tidak dijalankan, atau gagal tidak boleh dibaca sebagai aman.',
    )
  }

  return (
    <section
      aria-labelledby="multi-source-title"
      className={cn('overflow-hidden rounded-panel border', visual.panelClass)}
    >
      <div className="p-6 sm:p-8">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex items-start gap-3">
            <span className="grid size-11 shrink-0 place-items-center rounded-full border border-glass-line bg-surface/80">
              <VerdictIcon size={23} className={visual.scoreClass} aria-hidden="true" />
            </span>
            <div>
              <p className="type-eyebrow text-ink-muted">Laporan multi-sumber</p>
              <h2 id="multi-source-title" className={cn('type-h2 mt-1', visual.scoreClass)}>
                {visual.label}
              </h2>
              <p className="type-caption mt-1 inline-flex items-center gap-1.5 break-all">
                <Globe2 size={13} aria-hidden="true" />
                {report.hostname}
              </p>
            </div>
          </div>
          <Badge tone={visual.tone}>Skor gabungan {report.score}/100</Badge>
        </div>

        <p className="mt-3 max-w-[70ch] text-sm leading-relaxed text-ink-soft">
          {visual.description}
        </p>

        {report.externalError ? (
          <Alert tone="danger" title="Pemeriksaan eksternal tidak selesai" className="mt-4 bg-surface/70">
            <p>{sanitizeAgentText(report.externalError)}</p>
            <p className="mt-1">
              Hasil internal tetap ditampilkan. Jalankan{' '}
              <a href="/periksa" className="font-medium underline underline-offset-2">
                pemeriksaan baru
              </a>{' '}
              untuk mencoba lagi.
            </p>
          </Alert>
        ) : null}

        {reconstructed ? (
          <Alert
            tone="warning"
            title="Rincian agen tidak tersimpan"
            className="mt-4 bg-surface/70"
          >
            <p>
              Laporan ini berasal dari hasil analisis internal. Rincian pemeriksaan eksternal
              tidak tersedia, jadi status agen tidak boleh dianggap sebagai kegagalan API.
            </p>
            <p className="mt-1">
              Jalankan{' '}
              <a href="/periksa" className="font-medium underline underline-offset-2">
                pemeriksaan baru
              </a>{' '}
              agar URL normal diperiksa oleh agen eksternal.
            </p>
          </Alert>
        ) : null}

        {!reconstructed &&
        !report.sensitiveUrl &&
        !report.externalError &&
        !report.externalRequested ? (
          <Alert
            tone="warning"
            title="Pemeriksaan eksternal tidak diminta"
            className="mt-4 bg-surface/70"
          >
            <p>
              URL hanya diperiksa dengan aturan internal. Jalankan pemeriksaan baru pada URL
              normal; tombol Periksa tautan akan memulai pemeriksaan eksternal jika fitur dan
              sesi tersedia.
            </p>
            <p className="mt-1">
              <a href="/periksa" className="font-medium underline underline-offset-2">
                Mulai pemeriksaan dengan agen eksternal
              </a>
            </p>
          </Alert>
        ) : null}

        {!reconstructed &&
        !report.sensitiveUrl &&
        !report.externalError &&
        report.externalRequested &&
        !report.externalShared &&
        notConfigured === report.completeness.total ? (
          <Alert
            tone="warning"
            title="Belum ada agen yang dikonfigurasi"
            className="mt-4 bg-surface/70"
          >
            <p>
              Permintaan eksternal sudah diminta, tetapi layanan pemeriksaan eksternal belum
              siap. Hasil internal tetap ditampilkan tanpa disimpulkan sebagai aman.
            </p>
          </Alert>
        ) : null}

        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          <div className="rounded-card border border-glass-line bg-surface/80 p-4">
            <p className="type-caption text-ink-muted">Skor gabungan</p>
            <p className={cn('mt-1 text-3xl font-semibold tabular-nums', visual.scoreClass)}>
              {report.score}
              <span className="ml-1 text-sm font-normal text-ink-muted">/100</span>
            </p>
            <div
              role="img"
              aria-label={`Skor gabungan ${report.score} dari 100`}
              className="mt-3 h-2 overflow-hidden rounded-full bg-line"
            >
              <div
                className={cn('h-full rounded-full', visual.barClass)}
                ref={styleValue('width', `${report.score}%`)}
              />
            </div>
            <p className="type-caption mt-2">
              Bukan probabilitas. Skor memakai bukti terkuat dan korelasi sumber.
            </p>
          </div>

          <div className="rounded-card border border-glass-line bg-surface/80 p-4">
            <div className="flex items-center justify-between gap-2">
              <p className="type-caption text-ink-muted">Kelengkapan data</p>
              <p className="text-sm font-semibold tabular-nums text-ink">
                {report.completeness.percent}%
              </p>
            </div>
            <div
              role="img"
              aria-label={`${report.completeness.checked} dari ${report.completeness.total} agen eksternal memberi hasil`}
              className="mt-3 h-2 overflow-hidden rounded-full bg-line"
            >
              <div
                className="h-full rounded-full bg-accent"
                ref={styleValue('width', `${report.completeness.percent}%`)}
              />
            </div>
            <p className="type-caption mt-2">
              {report.completeness.checked} dari {report.completeness.total} agen eksternal
              memberi hasil.
            </p>
            <p className="type-caption mt-1">
              {report.completeness.success} selesai | {report.completeness.notFound} tanpa
              kecocokan | {notConfigured} belum dikonfigurasi
            </p>
            <p className="type-caption mt-0.5">
              {authFailed} gagal autentikasi | {report.completeness.rateLimited} dibatasi |{' '}
              {timeout} batas waktu habis
            </p>
            <p className="type-caption mt-0.5">
              {skipped} tidak dijalankan | {unavailableOrError} gagal/tidak tersedia | {rejected}{' '}
              permintaan ditolak
            </p>
          </div>
        </div>

        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          <div className="rounded-card border border-glass-line bg-surface/70 p-4">
            <p className="type-caption text-ink-muted">Kecukupan bukti</p>
            <p className="mt-1 text-sm font-semibold text-ink">
              {SUFFICIENCY_LABELS[dimensions.sufficiency.level]}
            </p>
            <p className="type-caption mt-2">
              {dimensions.sufficiency.confirmedClean} dari minimum{' '}
              {dimensions.sufficiency.requiredConfirmedClean} agen berbeda yang menyatakan bersih
              dan masih berlaku |{' '}
              {dimensions.sufficiency.limitedNegatives} bukti negatif terbatas
            </p>
            {dimensions.sufficiency.confirmedCleanClasses.length > 0 ? (
              <p className="type-caption mt-0.5">
                Kelas bukti: {dimensions.sufficiency.confirmedCleanClasses.map(
                  (name) => EVIDENCE_CLASS_LABELS[name] ?? name,
                ).join(', ')}
              </p>
            ) : null}
            {dimensions.sufficiency.blockingReasons.length > 0 ? (
              <ul className="mt-2 flex flex-col gap-1">
                {dimensions.sufficiency.blockingReasons.slice(0, 3).map((reason) => (
                  <li key={reason} className="type-caption text-ink-soft">
                    {reason}
                  </li>
                ))}
              </ul>
            ) : null}
          </div>

          <div className="rounded-card border border-glass-line bg-surface/70 p-4">
            <p className="type-caption text-ink-muted">Cakupan agen</p>
            <p className="mt-1 text-sm font-semibold tabular-nums text-ink">
              {dimensions.coverage.answered}/{dimensions.coverage.total} memberi hasil
            </p>
            <p className="type-caption mt-2">
              {dimensions.coverage.noMatch} tanpa kecocokan (terjawab, bukan bukti aman) |{' '}
              {dimensions.coverage.usableNegativeEvidence} menyumbang bukti negatif
            </p>
            <p className="type-caption mt-0.5">
              {dimensions.coverage.unresolved} belum memberi hasil |{' '}
              {dimensions.coverage.positiveFindings} temuan ancaman
            </p>
          </div>

          <div className="rounded-card border border-glass-line bg-surface/70 p-4">
            <p className="type-caption text-ink-muted">Keyakinan vonis</p>
            <p className="mt-1 text-sm font-semibold text-ink">
              {CONFIDENCE_LABELS[dimensions.confidence]}
            </p>
            <p className="type-caption mt-2">
              Keyakinan menilai dasar vonis ini, bukan probabilitas dan bukan skor risiko. Vonis
              Perlu Perhatian memang berkeyakinan rendah karena sistem tidak menyimpulkan apa
              pun.
            </p>
          </div>
        </div>

        <div className="mt-5 rounded-card border border-glass-line bg-surface/70 p-4">
          <h3 className="text-sm font-semibold text-ink">Bukti penilaian</h3>
          <ul className="mt-2 flex flex-col gap-1.5">
            {evidence.map((item) => (
              <li key={item} className="type-small flex gap-2 text-ink-soft">
                <span aria-hidden="true" className="mt-2 size-1 shrink-0 rounded-full bg-line-strong" />
                {item}
              </li>
            ))}
          </ul>
        </div>

        {report.sensitiveUrl && report.privacyReasons.length > 0 ? (
          <Alert tone="warning" title="URL sensitif tidak dibagikan" className="mt-4 bg-surface/70">
            <ul className="flex flex-col gap-1">
              {report.privacyReasons.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          </Alert>
        ) : null}

        <div className="mt-6">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-sm font-semibold text-ink">Rincian agen</h3>
            <span className="type-caption">
              {externalProviders.length} agen pemeriksaan dalam laporan
            </span>
          </div>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            {externalProviders.map((provider) => (
              <ProviderCard key={provider.id} provider={provider} />
            ))}
          </div>
        </div>

        <div className="mt-4 flex gap-2.5 rounded-card border border-glass-line bg-surface/70 p-3.5">
          <Lock size={16} className="mt-0.5 shrink-0 text-ink-muted" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-ink">
              {report.externalShared
                ? 'URL dibagikan setelah kamu menekan Periksa tautan'
                : rateLimited
                  ? 'Batas pemeriksaan eksternal tercapai'
                  : reconstructed
                    ? 'Rincian agen eksternal tidak tersedia'
                    : 'URL tidak dikirim ke agen eksternal'}
            </p>
            <p className="type-caption mt-0.5">
              {report.externalShared
                ? 'Agen eksternal dapat membuka URL untuk memeriksanya. VERIGUARD tidak membuka halaman tujuan di perangkat ini.'
                : rateLimited
                  ? 'URL tidak diproses oleh agen pada percobaan ini. Coba lagi setelah jendela batas selesai.'
                  : reconstructed
                    ? 'Hasil di atas hanya direkonstruksi dari analisis internal. Rincian pemeriksaan eksternal tidak tersimpan di perangkat ini.'
                    : 'Hasil di atas berasal dari analisis internal dan status agen yang tidak dijalankan.'}
            </p>
          </div>
        </div>

        <ul className="mt-4 flex flex-col gap-1.5">
          {visibleNotes.map((note) => (
            <li key={note} className="type-caption">
              {note}
            </li>
          ))}
        </ul>

        <p className="type-caption mt-4 border-t border-glass-line pt-3">
          Dibuat {formatDate(report.generatedAt)}
          {report.durationMs > 0 ? ` · ${formatDuration(report.durationMs)}` : ''}
        </p>
      </div>
    </section>
  )
}

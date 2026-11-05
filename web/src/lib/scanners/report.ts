import type { ScanResult } from '../analysis/types'
import {
  EXTERNAL_PROVIDER_IDS,
  type EvidenceSufficiency,
  type ExternalProviderId,
  type ExternalProviderResult,
  type MultiSourceReport,
  type NegativeEvidenceClass,
  type ProviderCoverage,
  type ProviderResult,
  type ProviderVerdict,
  type ReportCompleteness,
  type ScanCacheMeta,
  type VerdictConfidence,
} from './types'

const EXTERNAL_PROVIDERS: Array<{ id: ExternalProviderId; label: string }> = [
  { id: 'urlscan', label: 'URLScan.io' },
  { id: 'virustotal', label: 'VirusTotal' },
  { id: 'openphish', label: 'OpenPhish' },
  { id: 'threatfox', label: 'ThreatFox (abuse.ch)' },
  { id: 'radar', label: 'Cloudflare Radar URL Scanner' },
  { id: 'otx', label: 'AlienVault OTX' },
  { id: 'hybrid', label: 'Hybrid Analysis' },
  { id: 'safebrowsing', label: 'Google Safe Browsing' },
]

type BuildReportInput = {
  scan: ScanResult
  externalProviders?: Array<ProviderResult | ExternalProviderResult>
  sharedWithProviders?: ExternalProviderId[]
  externalRequested: boolean
  externalError?: string | null
  sensitiveUrl?: boolean
  privacyReasons?: string[]
  generatedAt?: string
  durationMs?: number
  fallback?: boolean
  scanCache?: ScanCacheMeta | null
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.trim().length > 0))]
}

// Kebijakan kesegaran bukti (VGM-05). Setiap agen punya irama data yang berbeda: laporan
// crowdsourced dan sandbox menua cepat, feed blokir menghing masih beberapa jam. AgeMs dihitung
// dari waktu observasi asli (`evidence.observedAt`/`cache.observedAt`), bukan waktu permintaan,
// sehingga hasil cache tidak pernah tampil sebagai pemindaian baru.
const FRESHNESS_LIMITS_MS: Record<ExternalProviderId, number> = {
  urlscan: 7 * 24 * 60 * 60_000,
  // VGL-32B: batas mesin disejajarkan dengan plafon pemakaian ulang laporan adapter sendiri
  // (DEFAULT_MAX_REPORT_AGE_HOURS = 168). Kontrak provider sudah menyatakan laporan berusia
  // 24–168 jam masih layak dipakai ulang; membuang bukti itu di lapisan mesin berarti vonis
  // bergantung pada umur respons, bukan pada umur data. Umur tetap dibaca dari observedAt
  // milik provider, pemeriksaan stale tidak dihapus.
  virustotal: 7 * 24 * 60 * 60_000,
  openphish: 12 * 60 * 60_000,
  threatfox: 12 * 60 * 60_000,
  radar: 24 * 60 * 60_000,
  otx: 7 * 24 * 60 * 60_000,
  hybrid: 7 * 24 * 60 * 60_000,
  safebrowsing: 60 * 60_000,
}

const HOUR_MS = 60 * 60_000

function providerAgeMs(provider: ProviderResult): number {
  return provider.evidence?.ageMs ?? 0
}

/**
 * Bukti yang melewati batas segar penyedia. Umur dibaca dari `evidence.ageMs` milik backend,
 * yang sudah mempertahankan waktu observasi asli saat hasil dipakai ulang dari cache, jadi
 * mekanisme cache itu sendiri tidak pernah mengubah vonis (kontrak `report.test.ts`).
 *
 * Ini BUKAN penanda aman maupun bahaya: vonis `clean` yang basi tidak boleh lagi menaikkan
 * kepercayaan, sedangkan vonis `malicious`/`suspicious` yang basi tetap dihitung karena
 * menurunkan perlindungan hanya karena umur adalah kegagalan yang lebih berbahaya bagi
 * pengguna.
 */
export function isStaleEvidence(provider: ProviderResult): boolean {
  if (provider.id === 'internal') return false
  const limit = FRESHNESS_LIMITS_MS[provider.id as ExternalProviderId]
  if (!limit) return false
  if (provider.evidence && provider.evidence.source === 'new_scan') return false
  return providerAgeMs(provider) > limit
}

function formatAge(ageMs: number): string {
  if (ageMs < HOUR_MS) return `${Math.max(1, Math.round(ageMs / 60_000))} menit`
  const days = ageMs / (24 * HOUR_MS)
  if (days >= 1) return `${days < 10 ? days.toFixed(1).replace(/\.0$/, '') : Math.round(days)} hari`
  return `${Math.round(ageMs / HOUR_MS)} jam`
}

function skippedProvider(
  provider: { id: ExternalProviderId; label: string },
  reason: string,
): ProviderResult {
  return {
    id: provider.id,
    label: provider.label,
    status: 'skipped',
    verdict: 'inconclusive',
    score: null,
    summary: 'Agen tidak dijalankan.',
    signals: [],
    reason,
    durationMs: 0,
  }
}

function notRunReason(input: BuildReportInput): string {
  if (input.fallback) return 'Rincian agen eksternal tidak tersimpan untuk pemeriksaan ini.'
  if (input.sensitiveUrl) return 'URL tidak dikirim karena memuat data sensitif.'
  if (input.externalError) return `Pemeriksaan eksternal: ${input.externalError}`
  if (!input.externalRequested) return 'Pemeriksaan eksternal tidak diminta.'
  return 'Agen tidak mengembalikan hasil.'
}

function buildCompleteness(providers: ProviderResult[]): ReportCompleteness {
  const total = EXTERNAL_PROVIDER_IDS.length
  let success = 0
  let notFound = 0
  let notConfigured = 0
  let authFailed = 0
  let unavailable = 0
  let rateLimited = 0
  let skipped = 0
  let timeout = 0
  let error = 0

  for (const provider of providers) {
    if (provider.status === 'success') success += 1
    else if (provider.status === 'not_found') notFound += 1
    else if (provider.status === 'not_configured') notConfigured += 1
    else if (provider.status === 'auth_failed') authFailed += 1
    else if (provider.status === 'rate_limited') rateLimited += 1
    else if (provider.status === 'skipped') skipped += 1
    else if (provider.status === 'timeout') timeout += 1
    // Permintaan yang ditolak provider dihitung bersama galat: keduanya "agen tidak memberi
    // hasil", dan tidak ada bilangan kelengkapan baru yang mengubah tampilan. Bedanya tetap
    // terbaca pada status agen di panel rincian.
    else if (provider.status === 'invalid_request') error += 1
    else if (provider.status === 'error') error += 1
    else unavailable += 1
  }

  const checked = success + notFound

  return {
    checked,
    total,
    percent: total > 0 ? Math.round((checked / total) * 100) : 0,
    success,
    notFound,
    notConfigured,
    authFailed,
    unavailable,
    rateLimited,
    skipped,
    timeout,
    error,
  }
}

function buildConflicts(scan: ScanResult, external: ProviderResult[]): string[] {
  // Yang dibandingkan adalah dua lapisan yang berbeda: aturan leksikal (dibaca dari `scan`,
  // bukan dari baris agen) melawan vonis agen eksternal. Ketidaksesuaiannya sengaja tetap
  // dinyatakan supaya pengguna melihat alasan mengapa laporan multi-sumber bisa tenang
  // sementara heuristik menandai risiko.
  const clean = external.filter((provider) => provider.verdict === 'clean')
  const malicious = external.filter((provider) => provider.verdict === 'malicious')
  const suspicious = external.filter((provider) => provider.verdict === 'suspicious')
  const conflicts: string[] = []

  for (const threat of [...malicious, ...suspicious]) {
    for (const safe of clean) {
      conflicts.push(`${threat.label} menandai risiko, sedangkan ${safe.label} tidak menemukan indikasi.`)
    }
  }

  if (scan.riskLevel !== 'low' && clean.length > 0) {
    conflicts.push(
      `Aturan internal menemukan indikasi risiko, sedangkan ${clean
        .map((provider) => provider.label)
        .join(', ')} tidak menemukan indikasi.`,
    )
  }

  return uniqueStrings(conflicts).slice(0, 4)
}

// ---------- VGL-31 TAHAP 3–4 — mesin vonis berbasis bukti ----------
//
// Empat hal yang selama ini direduksi menjadi satu angka dipisah di sini:
//   A skor risiko        -> `combinedScore` (hanya bukti ancaman positif yang menaikkannya)
//   B kecukupan bukti    -> `EvidenceSufficiency` (apakah bukti NEGATIF cukup untuk vonis bersih)
//   C cakupan agen       -> `ProviderCoverage` (berapa agen benar-benar memberi hasil)
//   D keyakinan vonis    -> `VerdictConfidence` (seberapa percaya kita pada vonis itu sendiri)
// Tidak satu pun dari keempatnya boleh disimpulkan dari yang lain: jumlah agen yang menjawab
// BUKAN bukti kebersihan, dan vonis bersih tidak pernah menjadi jaminan situs aman.

// Klasifikasi satu baris agen untuk ditampilkan. Ini adalah TAHAP 2 dalam satu tempat:
// `confirmed_clean` (provider menyatakan negatif secara eksplisit) dipisahkan dari `no_match`
// (tidak ada di basis data), `limited_negative` (konsisten bersih tapi bertumpu pada ketiadaan
// tanda), `community` (intelijen tanpa kontribusi skor), dan `unresolved` (agen tidak memberi
// hasil). Tidak ada jalur yang mengubah `no_match` menjadi `confirmed_clean`.
export type ProviderEvidenceKind =
  | 'confirmed_clean'
  | 'limited_negative'
  | 'no_match'
  | 'positive_threat'
  | 'community'
  | 'unresolved'

export function classifyProviderEvidence(provider: ProviderResult): ProviderEvidenceKind {
  if (provider.verdict === 'malicious' || provider.verdict === 'suspicious') {
    return 'positive_threat'
  }
  if (isUnresolvedStatus(provider)) return 'unresolved'
  if (isConfirmedClean(provider)) return 'confirmed_clean'
  if (isCreditableNegative(provider)) return 'limited_negative'
  if (provider.status === 'not_found') return 'no_match'
  return 'community'
}

export const MIN_CONFIRMED_CLEAN_PROVIDERS = 2

// VGL-32B: independensi diukur dari SUMBER bukti, bukan dari label kelasnya. Dua adapter yang
// meneruskan laporan identik (kelas dan dasar bukti yang sama persis) hanya dihitung satu agen.
function independentSourceKey(provider: ProviderResult): string {
  const negative = provider.negative!
  return `${negative.evidenceClass}::${negative.basis.trim().toLowerCase()}`
}

const UNRESOLVED_NOTE = 'tidak memberi hasil'

function isUnresolvedStatus(provider: ProviderResult): boolean {
  return provider.status !== 'success' && provider.status !== 'not_found'
}

// `confirmed_clean` adalah status verifikasi, BUKAN status provider. Sebuah hasil hanya boleh
// menyandangnya bila agen benar-benar menyatakan hasil negatif untuk URL ini (penanda bukti
// negatif eksplisit, cakupan url) dan vonisnya bersih. `no_match` (status not_found) tidak
// pernah naik sendiri menjadi confirmed_clean: penanda itu justru yang membedakannya.
function isConfirmedClean(provider: ProviderResult): boolean {
  const negative = provider.negative
  return (
    provider.status === 'success' &&
    provider.verdict === 'clean' &&
    negative !== undefined &&
    negative.strength === 'explicit' &&
    negative.scope === 'url'
  )
}

function isCreditableNegative(provider: ProviderResult): boolean {
  return provider.negative !== undefined
}

function isLimitedNegative(provider: ProviderResult): boolean {
  return provider.negative?.strength === 'limited' && !isConfirmedClean(provider)
}

function hasPositiveThreatEvidence(providers: ProviderResult[]): boolean {
  return providers.some((provider) => provider.verdict === 'malicious' || provider.verdict === 'suspicious')
}

export type EvidenceSummary = {
  sufficiency: EvidenceSufficiency
  coverage: ProviderCoverage
  verdict: ProviderVerdict
  confidence: VerdictConfidence
  lowRiskSupported: boolean
}

export function summarizeEvidence(scan: ScanResult, external: ProviderResult[]): EvidenceSummary {
  const total = EXTERNAL_PROVIDER_IDS.length
  const answered = external.filter((provider) => !isUnresolvedStatus(provider))
  const unresolved = external.length - answered.length
  // VGL-32A: kedaluwarsa hanya menggugurkan BUKTI BERSIH. Baris `no_match` yang tua tetap
  // pemeriksaan yang berhasil dan tidak boleh memvonis laporan mentok; sebaliknya bukti
  // bersih yang lewat batas umur tidak dihitung memenuhi syarat minimal dua.
  const confirmedProviders = external.filter(isConfirmedClean)
  const freshConfirmed = confirmedProviders.filter((provider) => !isStaleEvidence(provider))
  const expiredConfirmedCount = confirmedProviders.length - freshConfirmed.length
  // VGL-32B: syarat minimal adalah DUA PROVIDER BERBEDA yang memberikan bukti bersih valid,
  // bukan dua kelas bukti. Korelasi sumber yang NYATA tetap dijaga: dua adapter yang hanya
  // meneruskan laporan identik (evidenceClass DAN basis sama persis) dihitung satu agen.
  const independentSourceKeys = new Set(freshConfirmed.map(independentSourceKey))
  const independentClean = independentSourceKeys.size
  const confirmedClasses = [...new Set(freshConfirmed.map((provider) => provider.negative!.evidenceClass))]
  const limitedNegatives = external.filter(
    (provider) => isLimitedNegative(provider) && !isStaleEvidence(provider),
  ).length
  const positiveFindings = external.filter(
    (provider) => provider.verdict === 'malicious' || provider.verdict === 'suspicious',
  ).length

  const blockingReasons: string[] = []
  if (positiveFindings > 0) {
    blockingReasons.push(`${positiveFindings} agen melaporkan bukti ancaman positif.`)
  }
  if (unresolved > 0 || external.length < total) {
    const missing = Math.max(unresolved, total - external.length)
    blockingReasons.push(
      `${missing} agen ${UNRESOLVED_NOTE}; ketiadaan jawaban tidak dihitung sebagai bukti aman.`,
    )
  }
  if (independentClean < MIN_CONFIRMED_CLEAN_PROVIDERS) {
    const expiredNote =
      expiredConfirmedCount > 0
        ? ` ${expiredConfirmedCount} bukti bersih melewati batas kesegarannya (kedaluwarsa) dan tidak dihitung.`
        : ''
    blockingReasons.push(
      independentClean === 0
        ? expiredConfirmedCount > 0
          ? `Belum ada provider yang menyatakan hasil negatif yang masih berlaku untuk URL ini;${expiredNote}`
          : 'Belum ada provider yang menyatakan hasil negatif secara eksplisit untuk URL ini.'
        : `Baru ${independentClean} agen berbeda yang menyatakan bersih secara valid dan masih berlaku; diperlukan ${MIN_CONFIRMED_CLEAN_PROVIDERS} agen independen.${expiredNote}`,
    )
  }
  if (scan.riskLevel !== 'low') {
    blockingReasons.push('Heuristik internal masih menemukan indikasi risiko pada alamat ini.')
  }

  const lowRiskSupported = blockingReasons.length === 0

  const sufficiency: EvidenceSufficiency = {
    level: lowRiskSupported
      ? 'sufficient'
      : independentClean > 0 || limitedNegatives > 0
        ? 'limited'
        : 'insufficient',
    confirmedClean: freshConfirmed.length,
    confirmedCleanClasses: confirmedClasses as NegativeEvidenceClass[],
    limitedNegatives,
    requiredConfirmedClean: MIN_CONFIRMED_CLEAN_PROVIDERS,
    blockingReasons,
  }

  const coverage: ProviderCoverage = {
    answered: answered.length,
    total,
    noMatch: external.filter((provider) => provider.status === 'not_found').length,
    usableNegativeEvidence: external.filter(isCreditableNegative).length,
    positiveFindings,
    unresolved: Math.max(unresolved, total - external.length),
    percent: total > 0 ? Math.round((answered.length / total) * 100) : 0,
  }

  const verdict = lowRiskSupported && !hasPositiveThreatEvidence(external) ? 'clean' : fallbackVerdict(external)

  const confidence = deriveConfidence(
    verdict,
    external,
    independentClean,
    unresolved,
    expiredConfirmedCount,
  )

  return { sufficiency, coverage, verdict, confidence, lowRiskSupported }
}

// Keyakinan vonis adalah dimensi tersendiri: ia mengukur seberapa kuat dasar vonis itu, bukan
// seberapa tinggi risikonya. Vonis `inconclusive` selalu berkeyakinan rendah justru karena
// sistem tidak berani menyimpulkan apa pun.
function deriveConfidence(
  verdict: ProviderVerdict,
  external: ProviderResult[],
  independentCleanCount: number,
  unresolved: number,
  expiredConfirmedCount = 0,
): VerdictConfidence {
  if (verdict === 'clean') {
    if (independentCleanCount < MIN_CONFIRMED_CLEAN_PROVIDERS || unresolved > 0) return 'medium'
    // VGM-05: bukti bersih yang kedaluwarsa tidak pernah NAIK kepercayaan; vonis yang tetap
    // tercapai dari bukti segar lain turun satu tingkat sebagai tanda jujur.
    return expiredConfirmedCount > 0 ? 'medium' : 'high'
  }
  if (verdict === 'malicious') {
    return external.filter((provider) => provider.verdict === 'malicious').length >= 2 ? 'high' : 'medium'
  }
  if (verdict === 'suspicious') {
    return external.filter(
      (provider) => provider.verdict === 'malicious' || provider.verdict === 'suspicious',
    ).length >= 2
      ? 'medium'
      : 'low'
  }
  return 'low'
}

function fallbackVerdict(external: ProviderResult[]): ProviderVerdict {
  if (external.some((provider) => provider.verdict === 'malicious')) return 'malicious'
  if (external.some((provider) => provider.verdict === 'suspicious')) return 'suspicious'
  return 'inconclusive'
}

function combinedVerdict(scan: ScanResult, external: ProviderResult[]): ProviderVerdict {
  // Bukti ancaman positif selalu menang lebih dahulu; tidak ada aturan minimum bukti yang
  // boleh MENURUNKAN vonis selama masih ada temuan sah dari provider.
  const threat = fallbackVerdict(external)
  if (threat !== 'inconclusive') return threat

  // Vonis bersih hanya boleh lahir dari kecukupan bukti negatif, bukan dari jumlah agen yang
  // menjawab, bukan dari popularitas domain, dan bukan dari HTTP 200.
  return summarizeEvidence(scan, external).lowRiskSupported ? 'clean' : 'inconclusive'
}

function combinedScore(verdict: ProviderVerdict, external: ProviderResult[]): number {
  const scores = external
    .map((provider) => provider.score)
    .filter((score): score is number => score !== null)
  const base = scores.length > 0 ? Math.max(...scores) : 0
  const maliciousCount = external.filter((provider) => provider.verdict === 'malicious').length
  const suspiciousCount = external.filter((provider) => provider.verdict === 'suspicious').length

  if (verdict === 'malicious') {
    return Math.min(100, Math.max(80, base + (maliciousCount > 1 ? 5 : 0)))
  }

  if (verdict === 'suspicious') {
    return Math.min(100, Math.max(35, base + (suspiciousCount > 1 ? 5 : 0)))
  }

  if (verdict === 'clean') {
    // VGL-32A: vonis Risiko Rendah hanya lahir ketika tidak ada sinyal ancaman positif sama
    // sekali, jadi skor risikonya 0 — bukan maks dari skor provider yang bisa saja berisi
    // angka residual dari agen berstatus bersih.
    return 0
  }

  return Math.min(34, Math.max(0, base))
}

export function buildMultiSourceReport(input: BuildReportInput): MultiSourceReport {
  const { scan } = input
  const external = input.externalProviders ?? []
  const externalById = new Map(external.map((provider) => [provider.id, provider]))
  const notRun = notRunReason(input)

  // VGL-30K-R1: roster laporan multi-sumber HANYA agen eksternal. Heuristik leksikal adalah
  // lapisan terpisah (dibaca pengguna pada kartu "Indikasi internal · heuristik leksikal") dan
  // tidak pernah menyamar sebagai agen, membawa skor ke agregasi, atau ikut menghitung
  // kelengkapan.
  const providers: ProviderResult[] = EXTERNAL_PROVIDERS.map(
    (provider) => externalById.get(provider.id) ?? skippedProvider(provider, notRun),
  )

  const verdict = combinedVerdict(scan, providers)
  const summary = summarizeEvidence(scan, providers)
  const completeness = buildCompleteness(providers)
  const sharedWithProviders = input.sharedWithProviders ?? []
  const externalShared = input.externalRequested && sharedWithProviders.length > 0
  const privacyReasons = uniqueStrings(input.privacyReasons ?? [])
  const notes = ['Skor gabungan adalah indikator bukti, bukan probabilitas.']

  if (!externalShared) {
    if (input.fallback) {
      notes.push(
        'Laporan ini direkonstruksi dari hasil analisis internal; rincian agen eksternal tidak tersimpan.',
      )
    } else if (input.sensitiveUrl) {
      notes.push('URL tidak dikirim ke agen eksternal karena memuat data sensitif.')
    } else if (input.externalError) {
      notes.push(`Pemeriksaan eksternal: ${input.externalError}`)
    } else if (!input.externalRequested) {
      notes.push('URL tidak dikirim ke agen eksternal.')
    } else if (
      external.length > 0 &&
      external.every((provider) => provider.status === 'rate_limited')
    ) {
      notes.push('Batas pemeriksaan eksternal tercapai; URL tidak diproses oleh agen.')
    } else if (
      external.length > 0 &&
      external.every((provider) => provider.status === 'not_configured')
    ) {
      notes.push('Tidak ada agen eksternal yang dikonfigurasi pada layanan pemeriksaan.')
    } else {
      notes.push('Pemeriksaan eksternal tidak menghasilkan laporan provider.')
    }
  }

  if (externalShared) {
    notes.push('Agen eksternal dapat membuka URL tanpa membuka halaman di perangkatmu.')
  }

  const scanCache = input.scanCache ?? null

  // Metadata cache tidak pernah ditulis ke `notes`: pengguna melihat satu pemeriksaan yang
  // normal, sedangkan mekanisme cache bekerja di belakang layar. Objek `cache` di bawah tetap
  // dibawa untuk observability internal, dan asal bukti tetap terbaca lewat
  // `provider.evidence.source`/`observedAt` untuk menampilkan waktu laporan yang sebenarnya.

  if (completeness.checked < completeness.total) {
    notes.push('Sebagian agen eksternal tidak memberi hasil; kelengkapan data belum penuh.')
  }

  if (verdict === 'inconclusive') {
    notes.push('Data belum cukup untuk menyimpulkan risiko secara gabungan.')
    const blocking = summary.sufficiency.blockingReasons.slice(0, 2).join(' ')
    if (blocking) notes.push(`Mengapa belum Risiko Rendah: ${blocking}`)
  }

  if (verdict === 'clean') {
    notes.push(
      'Risiko Rendah di sini berarti bukti negatif yang relevan mencukupi, bukan jaminan URL ini aman.',
    )
  }

  const staleProviders = providers.filter((provider) => isStaleEvidence(provider))
  if (staleProviders.length > 0) {
    const detail = staleProviders
      .slice(0, 4)
      .map((provider) => `${provider.label} (${formatAge(providerAgeMs(provider))})`)
      .join(', ')
    notes.push(
      `Bukti berikut melewati batas kesegarannya dan ditampilkan sebagai informasi historis: ${detail}. ` +
        'Vonis gabungan tidak menaikkan kepercayaan dari bukti basi.',
    )
  }

  let hostname = scan.displayTarget
  try {
    hostname = new URL(scan.input).hostname
  } catch {
    hostname = scan.displayTarget
  }

  return {
    version: 2,
    target: scan.input,
    hostname,
    verdict,
    score: combinedScore(verdict, providers),
    completeness,
    evidenceSufficiency: summary.sufficiency,
    providerCoverage: summary.coverage,
    verdictConfidence: summary.confidence,
    providers,
    conflicts: buildConflicts(scan, providers),
    notes: uniqueStrings(notes),
    externalRequested: input.externalRequested,
    externalShared,
    externalError: input.externalError ?? null,
    sensitiveUrl: input.sensitiveUrl === true,
    privacyReasons,
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    durationMs: Math.max(0, input.durationMs ?? 0),
    ...(scanCache ? { cache: scanCache } : {}),
  }
}

export function buildLocalReport(scan: ScanResult): MultiSourceReport {
  return buildMultiSourceReport({
    scan,
    externalRequested: false,
    generatedAt: scan.createdAt,
    fallback: true,
  })
}

export type ReportDimensions = {
  sufficiency: EvidenceSufficiency
  coverage: ProviderCoverage
  confidence: VerdictConfidence
}

// Riwayat laporan versi 1 tersimpan di perangkat pengguna sebelum penanda bukti negatif dan
// tiga dimensi ini ada. Dimensinya diturunkan ulang dari baris agen yang tersimpan, dan vonis
// lama tetap dibaca apa adanya: history tidak pernah ditulis ulang agar cocok dengan skor yang
// sudah dilihat pengguna.
export function deriveReportDimensions(report: MultiSourceReport): ReportDimensions {
  const external = report.providers.filter((provider) => provider.id !== 'internal')
  const confirmed = external.filter(isConfirmedClean)
  const independentClean = new Set(confirmed.map(independentSourceKey)).size
  const classes = [...new Set(confirmed.map((provider) => provider.negative!.evidenceClass))]
  const unresolved = external.filter(isUnresolvedStatus).length
  const positiveFindings = external.filter(
    (provider) => provider.verdict === 'malicious' || provider.verdict === 'suspicious',
  ).length

  const blockingReasons: string[] = []
  if (report.version === 1) {
    blockingReasons.push(
      'Laporan ini dibuat sebelum VERIGUARD mencatat penanda bukti negatif per provider, sehingga kecukupan bukti tidak dapat dibuktikan ulang dari riwayat.',
    )
  }
  if (independentClean < MIN_CONFIRMED_CLEAN_PROVIDERS) {
    blockingReasons.push(
      `Baru ${independentClean} agen berbeda yang menyatakan bersih secara valid; diperlukan ${MIN_CONFIRMED_CLEAN_PROVIDERS} agen independen.`,
    )
  }
  if (positiveFindings > 0) {
    blockingReasons.push(`${positiveFindings} agen melaporkan bukti ancaman positif.`)
  }
  if (unresolved > 0) {
    blockingReasons.push(`${unresolved} agen ${UNRESOLVED_NOTE}.`)
  }

  const sufficiency: EvidenceSufficiency = {
    level:
      blockingReasons.length === 0
        ? 'sufficient'
        : independentClean > 0 || external.some(isLimitedNegative)
          ? 'limited'
          : 'insufficient',
    confirmedClean: confirmed.length,
    confirmedCleanClasses: classes as NegativeEvidenceClass[],
    limitedNegatives: external.filter(isLimitedNegative).length,
    requiredConfirmedClean: MIN_CONFIRMED_CLEAN_PROVIDERS,
    blockingReasons,
  }

  const coverage: ProviderCoverage = {
    answered: external.length - unresolved,
    total: EXTERNAL_PROVIDER_IDS.length,
    noMatch: external.filter((provider) => provider.status === 'not_found').length,
    usableNegativeEvidence: external.filter(isCreditableNegative).length,
    positiveFindings,
    unresolved,
    percent:
      EXTERNAL_PROVIDER_IDS.length > 0
        ? Math.round(((external.length - unresolved) / EXTERNAL_PROVIDER_IDS.length) * 100)
        : 0,
  }

  return {
    sufficiency,
    coverage,
    confidence: deriveConfidence(report.verdict, external, independentClean, unresolved),
  }
}

export function reportDimensions(report: MultiSourceReport): ReportDimensions {
  const { evidenceSufficiency, providerCoverage, verdictConfidence } = report
  if (evidenceSufficiency && providerCoverage && verdictConfidence) {
    return {
      sufficiency: evidenceSufficiency,
      coverage: providerCoverage,
      confidence: verdictConfidence,
    }
  }
  return deriveReportDimensions(report)
}

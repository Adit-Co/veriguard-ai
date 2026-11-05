import { registrableDomain } from './urlSignals.js'
import { parseIpv4 } from './guards.js'
import type {
  BehaviorAnalysis,
  DomainAgeAnalysis,
  EvidenceAvailability,
  EvidenceCategory,
  EvidenceCoverage,
  EvidenceStrength,
  FusedEvidence,
  PageAnalysis,
  RiskFusion,
  RiskLevel,
  ScanStatus,
  SectionStatus,
  UrlStructureAnalysis,
  WebsiteCategoryAssessment,
  WebsiteIntelligence,
} from './types.js'

/**
 * Mesin fusi bukti. Tugasnya hanya menyusun ulang temuan modul analisis menjadi
 * bukti yang dapat ditelusuri, lalu menghitung skor di atas bukti tersebut.
 *
 * Aturan yang dijaga:
 * - Bukti yang tidak tersedia tidak pernah menambah atau mengurangi skor.
 * - Bukti kembar tidak dihitung dua kali (familinya diambil yang terkuat).
 * - Skor risiko, keyakinan, cakupan, dan status pemindaian adalah empat hal berbeda.
 * - Skor tidak pernah dinaikkan supaya scanner terlihat bekerja.
 */

const STRENGTH_WEIGHT: Record<EvidenceStrength, number> = {
  strong: 18,
  moderate: 9,
  weak: 3,
  mitigating: -4,
}

// Satu halaman klon biasanya memicu banyak temuan merek sekaligus (nama di host,
// nama di jalur, logo di halaman). Hitungannya diambil satu, ditambah sedikit
// karena bukti yang berbeda keluarga saling menguatkan, bukan karena dijumlah.
const EVIDENCE_FAMILIES: Array<{ id: string; codes: string[]; boost: number }> = [
  {
    id: 'brand_impersonation',
    codes: [
      'brand_in_host',
      'brand_in_path',
      'typosquat',
      'homoglyph',
      'mixed_script',
      'brand_identity_mismatch',
    ],
    boost: 4,
  },
  {
    id: 'obfuscated_text',
    codes: ['over_encoded', 'encoded_delimiter', 'delimiter_trick', 'special_heavy', 'long_url', 'deep_path'],
    boost: 2,
  },
  {
    id: 'hidden_destination',
    codes: ['embedded_url', 'cross_domain_redirect', 'downgrade_redirect', 'meta_refresh_redirect', 'script_location_redirect', 'shortener'],
    boost: 3,
  },
]

const BRAND_CODES = new Set(EVIDENCE_FAMILIES[0]!.codes)

/**
 * Batas level ditentukan dari bobot di atas, bukan dari keinginan menampilkan
 * level tinggi:
 * - < 15  : satu penanda lemah atau sedang yang belum didukung bukti lain.
 * - >= 15 : penanda sedang (9) yang dikukuhkan minimal satu bukti independent.
 * - >= 35 : dua lapisan moderat/kuat dari kategori berbeda.
 * - >= 60 : rangkaian bukti kuat (merek + panen kredensial + redirect/registrasi).
 */
const LEVEL_THRESHOLDS: Array<{ min: number; level: RiskLevel }> = [
  { min: 60, level: 'critical' },
  { min: 35, level: 'high' },
  { min: 15, level: 'medium' },
  { min: 0, level: 'low' },
]

function structureCategory(code: string): EvidenceCategory {
  return BRAND_CODES.has(code) ? 'brand' : 'url_structure'
}

function pageCategory(code: string): EvidenceCategory {
  if (code === 'credential_request') return 'form'
  if (code === 'script_obfuscation' || code === 'script_location_redirect') return 'script'
  if (code === 'meta_refresh_redirect') return 'redirect'
  if (BRAND_CODES.has(code)) return 'brand'
  return 'page_content'
}

function availabilityOf(status: string): EvidenceAvailability {
  if (status === 'success' || status === 'complete' || status === 'answered' || status === 'observed') return 'observed'
  if (status === 'unavailable' || status === 'not_applicable') return 'unavailable'
  return 'failed'
}

function sectionAvailability(status: SectionStatus): EvidenceAvailability {
  if (status === 'complete') return 'observed'
  if (status === 'partial') return 'observed'
  return status === 'unavailable' ? 'unavailable' : 'failed'
}

function fromStructure(structure: UrlStructureAnalysis, at: string): FusedEvidence[] {
  if (structure.status !== 'complete') {
    return [
      {
        id: 'url_structure:unavailable',
        category: 'url_structure',
        label: 'Pemeriksaan struktur URL tidak berjalan',
        detail: structure.notes[0] ?? 'URL tidak dapat diurai.',
        observed: null,
        source: 'urlSignals.analyzeUrlStructure',
        strength: 'weak',
        availability: sectionAvailability(structure.status),
        observedAt: at,
      },
    ]
  }

  return structure.findings.map((finding) => ({
    id: `${structureCategory(finding.code)}:${finding.code}`,
    category: structureCategory(finding.code),
    label: finding.label,
    detail: finding.detail,
    observed: finding.evidence,
    source: 'urlSignals.analyzeUrlStructure',
    strength: finding.strength,
    availability: 'observed',
    observedAt: at,
  }))
}

function fromRegistration(registration: DomainAgeAnalysis): FusedEvidence[] {
  return registration.findings.map((finding) => ({
    id: `registration:${finding.code}`,
    category: 'registration',
    label: finding.label,
    detail: finding.detail,
    observed: finding.evidence ?? (registration.ageDays === null ? null : `${registration.ageDays} hari`),
    source: registration.lookup.source,
    strength: finding.strength,
    availability: availabilityOf(registration.lookup.status),
    observedAt: registration.lookup.queriedAt,
  }))
}

function fromTls(website: WebsiteIntelligence): FusedEvidence[] {
  const evidence: FusedEvidence[] = []
  const certificate = website.tls.certificate

  if (certificate.status !== 'success' || !certificate.value) {
    // Tidak ada sertifikat yang terbaca berarti tidak ada bukti, bukan bukti aman.
    return evidence
  }

  const value = certificate.value
  const at = certificate.queriedAt

  if (value.expired === true) {
    evidence.push({
      id: 'tls:expired_certificate',
      category: 'tls',
      label: 'Sertifikat TLS sudah kedaluwarsa',
      detail: `Masa berlaku sertifikat berakhir pada ${value.notAfter ?? 'tanggal yang tidak terbaca'}. Sertifikat kedaluwarsa menurunkan keyakinan pengunjung dan bisa terjadi karena kelalaian pemilik situs.`,
      observed: value.notAfter,
      source: certificate.source,
      strength: 'moderate',
      availability: 'observed',
      observedAt: at,
    })
  }

  if (value.verification === 'rejected') {
    evidence.push({
      id: 'tls:verification_rejected',
      category: 'tls',
      label: 'Rantai sertifikat tidak berhasil diverifikasi',
      detail: `Rantai sertifikat ditolak saat diperiksa (${value.verificationDetail ?? 'tanpa rincian'}). Sertifikat mandiri juga dipakai situs uji coba dan situs internal, jadi ini belum otomatis phishing.`,
      observed: value.issuer,
      source: certificate.source,
      strength: 'moderate',
      availability: 'observed',
      observedAt: at,
    })
  }

  // Enkripsi dan CA gratis sengaja TIDAK dinilai: HTTPS bukan jaminan aman dan
  // certificate authority gratis bukan indikator perilaku jahat.
  return evidence
}

function fromPage(page: PageAnalysis, at: string): FusedEvidence[] {
  if (!page.inspected) return []
  return page.findings.map((finding) => ({
    id: `${pageCategory(finding.code)}:${finding.code}`,
    category: pageCategory(finding.code),
    label: finding.label,
    detail: finding.detail,
    observed: finding.evidence,
    source: 'pageSignals.analyzePageContent',
    strength: finding.strength,
    availability: 'observed',
    observedAt: at,
  }))
}

function fromBehavior(behavior: BehaviorAnalysis, at: string): FusedEvidence[] {
  const evidence: FusedEvidence[] = []

  const blockedHop = behavior.redirects.find((hop) => hop.outcome === 'blocked')
  if (blockedHop) {
    evidence.push({
      id: 'redirect:blocked_hop',
      category: 'redirect',
      label: 'Rantai redirect dihentikan karena tujuan tidak diizinkan',
      detail: `Rantai redirect berhenti pada hop ke ${blockedHop.url.slice(0, 120)} karena tujuannya berada di rentang alamat yang diblokir pemeriksaan ini. Rantai tidak dilanjutkan sampai tuntas.`,
      observed: blockedHop.detail ?? blockedHop.location,
      source: 'website.service.followOriginChain',
      strength: 'moderate',
      availability: 'observed',
      observedAt: at,
    })
  }

  if (behavior.redirectOutcome === 'limit' || behavior.redirectOutcome === 'loop') {
    evidence.push({
      id: `redirect:${behavior.redirectOutcome}`,
      category: 'redirect',
      label: behavior.redirectOutcome === 'loop' ? 'Rantai redirect berulang' : 'Rantai redirect melewati batas lompatan',
      detail:
        behavior.redirectOutcome === 'loop'
          ? 'Tujuan yang sama muncul kembali dalam rantai yang diamati. Rantai berulang dipakai untuk mengaburkan tujuan akhir.'
          : `Rantai dihentikan pada ${behavior.redirectCount} lompatan karena batas pemeriksaan reached, jadi tujuan akhir sebenarnya tidak diketahui.`,
      observed: behavior.redirects.map((hop) => hop.url).join(' -> ').slice(0, 120),
      source: 'website.service.followOriginChain',
      strength: 'moderate',
      availability: 'observed',
      observedAt: at,
    })
  }

  return evidence
}

function fromCategory(category: WebsiteCategoryAssessment, at: string): FusedEvidence[] {
  if (category.status === 'unavailable' || category.status === 'failed') return []
  if (!category.riskIndicated || category.primaryId === 'unknown') return []

  return [
    {
      id: `category:${category.primaryId}`,
      category: 'category',
      label: `Isi halaman cocok dengan kategori ${category.primaryLabel}`,
      detail: `${category.summary} Klasifikasi dibaca dari teks dan struktur halaman, bukan dari daftar hitam mana pun.`,
      observed: category.signals
        .slice(0, 3)
        .map((signal) => signal.label)
        .join(', ')
        .slice(0, 120),
      source: 'category.classifyWebsiteCategory',
      strength: category.confidence === 'high' ? 'moderate' : 'weak',
      availability: 'observed',
      observedAt: at,
    },
  ]
}

function codeOf(evidenceId: string): string {
  return evidenceId.split(':')[1] ?? ''
}

function familyOf(evidenceId: string) {
  const code = codeOf(evidenceId)
  return EVIDENCE_FAMILIES.find((family) => family.codes.includes(code)) ?? null
}

/**
 * Peniruan merek hanya dilaporkan bila ada bukti dari sumbu lain yang mendukung
 * (TLD sekali pakai, label berkata kunci, umur registrasi, form kredensial, dan
 * sebagainya). Butir merek yang berdiri sendiri tetap dihitung, tapi tidak diberi
 * tambahan; tambahan dibatasi dua tingkat supaya korelasi tidak berubah menjadi
 * penjumlahan berulang.
 */
function brandCorroboration(items: FusedEvidence[]): number {
  const brand = items.find((item) => familyOf(item.id)?.id === 'brand_impersonation')
  if (!brand) return 0
  const supporting = items.filter(
    (item) => item.id !== brand.id && familyOf(item.id)?.id !== 'brand_impersonation',
  ).length
  if (supporting >= 2) return 4
  if (supporting === 1) return 2
  return 0
}

/**
 * Menghapus bukti kembar (kode yang sama dari modul yang sama) lalu meruntuhkan satu
 * keluarga menjadi satu butir: yang terkuat dipertahankan, sisanya hanya menaikkan
 * sedikit karena saling menguatkan. Tanpa langkah ini, halaman klon yang memicu enam
 * temuan merek sekaligus akan mendapat enam kali bobot yang sama.
 */
function collapseFamilies(evidence: FusedEvidence[]): { items: FusedEvidence[]; adjustments: number } {
  const deduped = new Map<string, FusedEvidence>()
  for (const item of evidence) {
    if (!deduped.has(item.id)) deduped.set(item.id, item)
  }
  const unique = [...deduped.values()]

  const items: FusedEvidence[] = []
  const adjustmentsByFamily = new Map<string, number>()
  const handled = new Set<string>()

  for (const item of unique) {
    const family = familyOf(item.id)
    if (!family) {
      items.push(item)
      continue
    }
    if (handled.has(family.id)) continue
    handled.add(family.id)

    const members = unique.filter(
      (entry) => familyOf(entry.id)?.id === family.id && entry.strength !== 'mitigating',
    )
    if (members.length === 0) continue

    const strongest = members.reduce((best, entry) =>
      STRENGTH_WEIGHT[entry.strength] > STRENGTH_WEIGHT[best.strength] ? entry : best,
    )
    const extra = (members.length - 1) * family.boost
    adjustmentsByFamily.set(family.id, (adjustmentsByFamily.get(family.id) ?? 0) + extra)

    items.push({
      ...strongest,
      detail:
        members.length > 1
          ? `${strongest.detail} Didukung ${members.length - 1} temuan sejenis (${members
              .filter((entry) => entry !== strongest)
              .map((entry) => entry.id)
              .join(', ')}); dihitung satu kali, bukan dijumlah berulang.`
          : strongest.detail,
    })
  }

  return { items, adjustments: [...adjustmentsByFamily.values()].reduce((sum, value) => sum + value, 0) }
}

function buildCoverage(input: {
  structure: UrlStructureAnalysis
  registration: DomainAgeAnalysis
  website: WebsiteIntelligence
  behavior: BehaviorAnalysis
  page: PageAnalysis
  category: WebsiteCategoryAssessment
}): { coverage: EvidenceCoverage; notEvaluated: string[] } {
  const byCategory = new Map<EvidenceCategory, { succeeded: number; total: number }>()
  const notEvaluated: string[] = []

  const tally = (category: EvidenceCategory, succeeded: boolean, total: number, reason?: string) => {
    const entry = byCategory.get(category) ?? { succeeded: 0, total: 0 }
    entry.succeeded += succeeded ? 1 : 0
    entry.total += total
    byCategory.set(category, entry)
    if (!succeeded && reason) notEvaluated.push(reason)
  }

  tally('url_structure', input.structure.status === 'complete', 1, 'Struktur URL tidak dapat dinilai.')

  const dnsLookups = [input.website.identity.addresses, ...input.website.dns.map((set) => set.lookup)]
  const dnsSucceeded = dnsLookups.filter((item) => item.status === 'success' || item.status === 'empty').length
  tally('dns', dnsSucceeded > 0, dnsLookups.length, 'Rekor DNS tidak berhasil dibaca.')

  const registrationSucceeded = input.registration.lookup.status === 'success'
  tally('registration', registrationSucceeded, 1, 'Umur registrasi domain tidak tersedia dari registry RDAP.')

  const tlsChecks = [input.website.tls.httpsAvailable, input.website.tls.certificate]
  const tlsSucceeded = tlsChecks.filter((item) => item.status === 'success').length
  tally('tls', tlsSucceeded > 0, tlsChecks.length, 'Sertifikat TLS tidak terbaca dari runtime ini.')

  tally('network', input.website.response.request.status === 'success', 1, 'Permintaan ke origin tidak berhasil, jadi respons halaman tidak dinilai.')

  tally('page_content', input.page.inspected, 1, 'Dokumen HTML tidak diperiksa, jadi isi halaman tidak dinilai.')
  tally('form', input.page.forms.inspected || input.behavior.forms.inspected, 1, 'Form dan kolom kredensial tidak dapat diperiksa.')

  const redirectObserved = input.behavior.status === 'complete' || input.behavior.status === 'partial'
  tally('redirect', redirectObserved, 1, 'Rantai redirect tidak dapat diamati.')

  tally('category', input.category.status !== 'unavailable', 1, 'Kategori konten tidak dapat ditentukan.')

  const succeeded = [...byCategory.values()].reduce((sum, entry) => sum + entry.succeeded, 0)
  const total = [...byCategory.values()].reduce((sum, entry) => sum + entry.total, 0)
  const failed = [...input.website.dns.map((set) => set.lookup), input.website.identity.addresses, ...tlsChecks]
    .filter((item) => item.status === 'failed' || item.status === 'timeout' || item.status === 'blocked').length

  return {
    coverage: {
      totalChecks: total,
      succeeded,
      unavailable: Math.max(0, total - succeeded - failed),
      failed,
      ratio: total > 0 ? Number((succeeded / total).toFixed(2)) : null,
      byCategory: [...byCategory.entries()].map(([category, entry]) => ({ category, ...entry })),
    },
    notEvaluated,
  }
}

function levelOf(score: number): RiskLevel {
  for (const entry of LEVEL_THRESHOLDS) {
    if (score >= entry.min) return entry.level
  }
  return 'low'
}

export function fuseEvidence(input: {
  generatedAt: string
  structure: UrlStructureAnalysis
  registration: DomainAgeAnalysis
  website: WebsiteIntelligence
  behavior: BehaviorAnalysis
  page: PageAnalysis
  category: WebsiteCategoryAssessment
}): RiskFusion {
  const collected: FusedEvidence[] = [
    ...fromStructure(input.structure, input.generatedAt),
    ...fromRegistration(input.registration),
    ...fromTls(input.website),
    ...fromBehavior(input.behavior, input.generatedAt),
    ...fromPage(input.page, input.generatedAt),
    ...fromCategory(input.category, input.generatedAt),
  ]

  const { items: evidence, adjustments } = collapseFamilies(collected)
  const { coverage, notEvaluated } = buildCoverage(input)

  const observed = evidence.filter((item) => item.availability === 'observed')
  const riskItems = observed.filter((item) => item.strength !== 'mitigating')
  const mitigations = observed.filter((item) => item.strength === 'mitigating')

  const probeAvailable = input.website.response.request.status !== 'unavailable'
  const status: ScanStatus =
    evidence.length === 0 && !probeAvailable
      ? 'failed'
      : coverage.succeeded === coverage.totalChecks && coverage.totalChecks > 0
        ? 'complete'
        : coverage.succeeded >= Math.ceil(coverage.totalChecks / 2)
          ? 'partial'
          : 'limited'

  const positive =
    riskItems.reduce((sum, item) => sum + STRENGTH_WEIGHT[item.strength], 0) + brandCorroboration(riskItems)
  const mitigating = Math.min(12, Math.abs(mitigations.reduce((sum, item) => sum + STRENGTH_WEIGHT[item.strength], 0)))
  const riskScore =
    status === 'failed' ? null : Math.max(0, Math.min(100, Math.round(positive + adjustments - mitigating)))

  const independentCategories = new Set(riskItems.map((item) => item.category)).size
  const confidence: RiskFusion['confidence'] =
    status === 'failed'
      ? 'low'
      : coverage.ratio !== null && coverage.ratio >= 0.6 && independentCategories >= 3 && riskItems.length >= 2
        ? 'high'
        : coverage.ratio !== null && coverage.ratio >= 0.4
          ? 'medium'
          : 'low'

  let level: RiskLevel = riskScore === null ? 'unknown' : levelOf(riskScore)
  // Tanpa data dari jaringan, skor tidak pernah boleh naik menjadi vonis final:
  // halaman belum dibuka, jadi isinya belum terbukti.
  if ((!probeAvailable || status === 'limited') && (level === 'critical' || level === 'high')) {
    level = 'medium'
  }

  const confidenceDetail =
    status === 'failed'
      ? 'Tidak ada pemeriksaan yang berhasil dijalankan, jadi skor tidak dihitung.'
      : `${riskItems.length} bukti risiko dari ${independentCategories} kategori berbeda, cakupan pemeriksaan ${coverage.succeeded}/${coverage.totalChecks}. ` +
        (confidence === 'high'
          ? 'Lapisan bukti saling bebas dan cakupannya lebar.'
          : confidence === 'medium'
            ? 'Sebagian pemeriksaan tidak berhasil dijalankan, jadi kesimpulan masih dapat bergeser.'
            : 'Keyakinan rendah: bukti yang tersedia sedikit atau cakupannya sempit; ini bukan pernyataan bahwa target aman.')

  return {
    status,
    level,
    riskScore,
    confidence,
    confidenceDetail,
    coverage,
    evidence,
    notEvaluated,
    notes: [
      'Skor risiko adalah penjumlahan bobot bukti yang sudah dikonsolidasikan, bukan probabilitas dan bukan vonis.',
      'Nama merek di host dinilai sebagai peniruan hanya bila ada bukti dari sumbu lain yang mendukung; bukti pendukung menambah sedikit, bukan berlipat.',
      'Pemeriksaan yang tidak tersedia tidak dihitung sebagai bukti positif maupun negatif.',
      'Keberadaan HTTPS, nama registrar, atau umur domain panjang tidak menghapus bukti lain; domain lama juga bisa disalahgunakan.',
      'Scanner ini tidak memakai daftar hitam atau layanan reputasi pihak ketiga untuk menghitung skor.',
    ],
  }
}

/**
 * Penilaian hanya-teks untuk target yang tidak boleh atau tidak dapat dibuka.
 * Sengaja dibatasi: tanpa halaman dan tanpa data jaringan, keyakinannya rendah.
 */
export function staticOnlyFusion(input: {
  generatedAt: string
  structure: UrlStructureAnalysis
  registrableDomain: string | null
  hostname: string
  reason: string
}): RiskFusion {
  const evidence = fromStructure(input.structure, input.generatedAt)
  const { items, adjustments } = collapseFamilies(evidence)
  const riskItems = items.filter((item) => item.availability === 'observed' && item.strength !== 'mitigating')
  const positive =
    riskItems.reduce((sum, item) => sum + STRENGTH_WEIGHT[item.strength], 0) + brandCorroboration(riskItems)
  const score = Math.max(0, Math.min(60, positive + adjustments))

  return {
    status: 'limited',
    level: score >= 25 ? 'medium' : 'low',
    riskScore: score,
    confidence: 'low',
    confidenceDetail: `${input.reason} Hanya teks URL yang dinilai, jadi keyakinan tetap rendah apa pun hasilnya.`,
    coverage: {
      totalChecks: 9,
      succeeded: 1,
      unavailable: 8,
      failed: 0,
      ratio: 0.11,
      byCategory: [
        { category: 'url_structure', succeeded: 1, total: 1 },
        { category: 'dns', succeeded: 0, total: 1 },
        { category: 'registration', succeeded: 0, total: 1 },
        { category: 'tls', succeeded: 0, total: 2 },
        { category: 'network', succeeded: 0, total: 1 },
        { category: 'page_content', succeeded: 0, total: 1 },
        { category: 'form', succeeded: 0, total: 1 },
        { category: 'redirect', succeeded: 0, total: 1 },
      ],
    },
    evidence: items,
    notEvaluated: [
      'DNS, RDAP, TLS, halaman, form, dan redirect tidak dinilai karena target tidak dibuka.',
      'Status ini bukan pernyataan bahwa target aman.',
    ],
    notes: [
      'Penilaian ini hanya membaca teks URL; tidak ada permintaan jaringan yang dibuat.',
      input.reason,
    ],
  }
}

export function registrableOf(hostname: string): string | null {
  const clean = hostname.toLowerCase().replace(/\.$/, '')
  if (!clean) return null
  if (parseIpv4(clean) !== null || clean.includes(':') || clean.startsWith('[') || /^\d+$/.test(clean)) return null
  if (/^[0-9.]+$/.test(clean)) return null
  return registrableDomain(clean)
}

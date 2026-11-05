import { fetchJson, type FetchJsonResult } from '../http.js'
import {
  failureCheck,
  isRecord,
  notFoundCheck,
  numberValue,
  recordValue,
  stringList,
  stringValue,
  notConfiguredCheck,
  errorCheck,
} from '../result.js'
import { hostIndicatorCovers, hostOfIndicatorValue } from '../hostIdentity.js'
import { normalizeScanUrl } from '../url.js'
import type {
  ProviderAdapter,
  ProviderCheck,
  ProviderContext,
  ProviderSignal,
} from '../types.js'

const REQUEST_TIMEOUT_MS = 8_000
// Rute /general untuk domain dapat berisi puluhan pulse; batas ini menjaga ukuran sinyalnya.
const MAX_PULSES_READ = 20

// Anggaran permintaan TAMBAHAN per pemeriksaan untuk konfirmasi indikator. Batas ini membuat
// harga satu pemeriksaan tetap dapat diprediksi meski OTX mengembalikan banyak pulse.
const MAX_CONFIRM_REQUESTS = 3
const INDICATOR_PAGE_LIMIT = 100
// Pulse dengan indikator lebih dari batas ini adalah daftar massal (blocklist, pulse
// multi-brand, pulse kampanye besar). Kehadiran target di dalamnya bukan bukti yang khusus
// untuk alamat ini.
const MAX_TARGET_SPECIFIC_INDICATORS = 50

// Satu pulse apa adanya: `id` dibutuhkan untuk konfirmasi indikator, `indicator_count` untuk
// mengenali daftar massal, dan keluarga/tag sebagai konteks ancaman. Rute `/general` TIDAK
// membawa daftar indikator, jadi kecocokan target tidak dapat disimpulkan dari rute itu saja.
type PulseRecord = {
  id: string | null
  name: string | null
  families: string[]
  tags: string[]
  indicatorCount: number | null
}

type PulseSummary = {
  count: number
  malwareFamilies: string[]
  tags: string[]
  names: string[]
  pulses: PulseRecord[]
}

function pulseRecord(value: unknown): PulseRecord | null {
  const pulse = recordValue(value)
  if (!pulse) return null

  const id = stringValue(pulse.id)?.trim()
  const name = stringValue(pulse.name)?.trim()

  return {
    id: id ? id : null,
    name: name ? name : null,
    families: [...new Set(stringList(pulse.malware_families, 4))],
    tags: [...new Set(stringList(pulse.tags, 4))],
    indicatorCount: numberValue(pulse.indicator_count),
  }
}

function summarize(value: unknown): PulseSummary | null {
  const root = recordValue(value)
  const pulseInfo = recordValue(root?.pulse_info)
  if (!pulseInfo) return null

  const pulses = Array.isArray(pulseInfo.pulses)
    ? pulseInfo.pulses
        .map(pulseRecord)
        .filter((pulse): pulse is PulseRecord => pulse !== null)
        .slice(0, MAX_PULSES_READ)
    : []

  return {
    count: numberValue(pulseInfo.count) ?? 0,
    malwareFamilies: [...new Set(pulses.flatMap((pulse) => pulse.families))].slice(0, 4),
    tags: [...new Set(pulses.flatMap((pulse) => pulse.tags))].slice(0, 4),
    names: pulses
      .map((pulse) => pulse.name)
      .filter((name): name is string => Boolean(name))
      .slice(0, 2),
    pulses,
  }
}

type SignalSeverity = ProviderSignal['severity']

const SEVERITY_RANK: Record<SignalSeverity, number> = { info: 0, warning: 1, danger: 2 }

// Batas severity per tingkat bukti. Pulse pada indikator domain hanyalah penyebutan oleh
// komunitas, jadi tidak pernah boleh tampil sekelas konfirmasi ancaman pada URL yang diperiksa.
function capSeverity(severity: SignalSeverity, ceiling: SignalSeverity): SignalSeverity {
  return SEVERITY_RANK[severity] <= SEVERITY_RANK[ceiling] ? severity : ceiling
}

function pulseSignals(summary: PulseSummary, scope: string, ceiling: SignalSeverity): ProviderSignal[] {
  const malicious = summary.malwareFamilies.length > 0
  const signals: ProviderSignal[] = [
    {
      label: 'Pulse komunitas',
      detail: `${summary.count} pulse OTX menyebut ${scope}.`,
      severity: capSeverity(malicious ? 'danger' : 'warning', ceiling),
    },
  ]
  if (summary.malwareFamilies.length > 0) {
    signals.push({
      label: 'Keluarga malware',
      detail: summary.malwareFamilies.join(', '),
      severity: capSeverity('danger', ceiling),
    })
  }
  if (summary.tags.length > 0) {
    signals.push({
      label: 'Tag pulse',
      detail: summary.tags.slice(0, 4).join(', '),
      severity: capSeverity('warning', ceiling),
    })
  }
  if (summary.names.length > 0) {
    signals.push({ label: 'Nama pulse', detail: summary.names.join(' · '), severity: 'info' })
  }

  return signals
}

// Tag yang menyebut KELAS ancaman konkret. 'high', 'suspicious', 'malicious' dan semacamnya
// adalah kata sifat pada pulse, bukan kelas ancaman, jadi tidak pernah menaikkan vonis.
const THREAT_TAGS = new Set([
  'phishing',
  'credential phishing',
  'credential theft',
  'malware',
  'malvertising',
  'botnet',
  'ransomware',
  'trojan',
  'banking trojan',
  'banking-trojan',
  'stealer',
  'infostealer',
  'loader',
  'dropper',
  'exploit',
  'exploit kit',
  'exploitkit',
  'scam',
])

// Konteks ancaman sebuah pulse: keluarga malware terkuat, tag kelas ancaman lebih lemah, dan
// tanpa keduanya pulse hanya menyebut target tanpa menjelaskan ancaman apa pun.
type ThreatGrade = 'malware' | 'phishing'

function threatGradeOf(pulse: PulseRecord): ThreatGrade | null {
  if (pulse.families.length > 0) return 'malware'
  if (pulse.tags.some((tag) => THREAT_TAGS.has(tag.trim().toLowerCase()))) return 'phishing'
  return null
}

function indicatorUrl(type: 'url' | 'domain', value: string): string {
  const encoded = type === 'url' ? encodeURIComponent(value) : value
  return `https://otx.alienvault.com/api/v1/indicators/${type}/${encoded}/general`
}

function pulseIndicatorsUrl(pulseId: string): string {
  return (
    `https://otx.alienvault.com/api/v1/pulses/${encodeURIComponent(pulseId)}/indicators` +
    `?limit=${INDICATOR_PAGE_LIMIT}`
  )
}

// OTX menjawab 200 dengan pulse_info.count = 0 untuk indikator yang tidak dikenal, sehingga
// 404 pada rute ini menandakan kontrak permintaan yang salah, bukan "tidak ada data".
function isRouteNotFound(result: Extract<FetchJsonResult, { ok: false }>): boolean {
  return result.kind === 'not_found'
}

type IndicatorEntry = { value: string; type: string }

// Daftar indikator pulse: { results: [{ indicator, type }], next }. Array di level teratas
// diterima selama butirnya terbaca; bentuk lain mengembalikan null agar caller melapor
// "tidak dapat diverifikasi" alih-alih menyimpulkan tidak ada.
function indicatorEntries(data: unknown): IndicatorEntry[] | null {
  const list = Array.isArray(data) ? data : recordValue(data)?.results
  if (!Array.isArray(list)) return null

  return list.filter(isRecord).map((entry) => ({
    value: (stringValue(entry.indicator) ?? stringValue(entry.content) ?? '').trim(),
    type: (stringValue(entry.type) ?? '').trim().toLowerCase(),
  }))
}

// Tingkat kecocokan satu butir indikator terhadap alamat yang diperiksa. URL persis adalah
// kecocokan terkuat; host yang sama atau induk registrable hanya bukti tingkat domain.
// Tipe indikator lain (IP, hash, URL host lain) BUKAN hubungan dengan alamat ini.
function matchIndicatorLevel(
  entry: IndicatorEntry,
  target: { url: string; hostname: string },
): 'url' | 'domain' | null {
  if (!entry.value) return null

  if (entry.type === 'url' || entry.type === 'uri') {
    try {
      if (normalizeScanUrl(entry.value) === target.url) return 'url'
    } catch {
      // Indikator URL yang tidak dapat dinormalisasi tidak dipakai sebagai kecocokan.
    }
    const host = hostOfIndicatorValue(entry.value)
    return host && hostIndicatorCovers(host, target.hostname) ? 'domain' : null
  }

  if (entry.type === 'domain' || entry.type === 'hostname') {
    const host = hostOfIndicatorValue(entry.value)
    return host && hostIndicatorCovers(host, target.hostname) ? 'domain' : null
  }

  return null
}

// Hasil konfirmasi satu pulse terhadap daftar indikatornya.
// - 'url'/'domain': target terbukti sebagai indikator pulse ini pada tingkat tersebut.
// - 'absent': daftar indikator terbaca dan target tidak ada di dalamnya.
// - 'unavailable': tanpa id, permintaan gagal, atau bentuk/data tidak dapat dibaca.
type PulseVerification = 'url' | 'domain' | 'absent' | 'unavailable'

async function verifyPulse(
  context: ProviderContext,
  headers: Record<string, string>,
  pulse: PulseRecord,
  target: { url: string; hostname: string },
): Promise<PulseVerification> {
  if (!pulse.id) return 'unavailable'

  const result = await fetchJson(
    context.fetchImpl,
    pulseIndicatorsUrl(pulse.id),
    { headers },
    REQUEST_TIMEOUT_MS,
  )
  if (!result.ok) return 'unavailable'

  const entries = indicatorEntries(result.data)
  if (entries === null) return 'unavailable'
  if (entries.length === 0) return 'absent'

  let readable = 0
  let domainMatch = false
  for (const entry of entries) {
    if (!entry.value || !entry.type) continue
    readable += 1
    const level = matchIndicatorLevel(entry, target)
    if (level === 'url') return 'url'
    if (level === 'domain') domainMatch = true
  }
  if (readable === 0) return 'unavailable'

  return domainMatch ? 'domain' : 'absent'
}

type Confirmation = {
  // Kecocokan TERKUAT yang terbukti; null berarti tidak ada bukti indikator.
  level: 'url' | 'domain' | null
  grade: ThreatGrade | null
  pulse: PulseRecord | null
  massList: number
  unavailable: number
  checked: number
  notRequested: number
}

// Kandidat yang layak dikirimi permintaan: hanya pulse yang membawa konteks ancaman. Pulse tanpa
// keluarga malware/tag ancaman tidak akan pernah menaikkan vonis, jadi keputusannya tidak dibeli
// dengan permintaan tambahan.
function candidatesFor(summary: PulseSummary, malwareOnly: boolean): PulseRecord[] {
  const ranked: PulseRecord[] = []
  for (const pulse of summary.pulses) {
    const grade = threatGradeOf(pulse)
    if (grade === null) continue
    if (malwareOnly && grade !== 'malware') continue
    ranked.push(pulse)
  }

  // Keluarga malware dikonfirmasi lebih dahulu: kecocokan pada pulse semacam itu berpotensi
  // menaikkan vonis, sedangkan pulse ber-tag saja tidak pernah naik di atas tingkat domain.
  return ranked.sort((a, b) => {
    const aRank = a.families.length > 0 ? 0 : 1
    const bRank = b.families.length > 0 ? 0 : 1
    return aRank - bRank
  })
}

async function confirmTarget(
  context: ProviderContext,
  headers: Record<string, string>,
  candidates: PulseRecord[],
  target: { url: string; hostname: string },
): Promise<Confirmation> {
  const outcome: Confirmation = {
    level: null,
    grade: null,
    pulse: null,
    massList: 0,
    unavailable: 0,
    checked: 0,
    notRequested: 0,
  }

  for (const pulse of candidates) {
    if (pulse.indicatorCount !== null && pulse.indicatorCount > MAX_TARGET_SPECIFIC_INDICATORS) {
      outcome.massList += 1
      continue
    }

    if (outcome.checked >= MAX_CONFIRM_REQUESTS) {
      outcome.notRequested += 1
      continue
    }

    outcome.checked += 1
    const state = await verifyPulse(context, headers, pulse, target)
    if (state === 'url' || state === 'domain') {
      outcome.level = state
      outcome.grade = threatGradeOf(pulse)
      outcome.pulse = pulse
      return outcome
    }
    if (state === 'unavailable') outcome.unavailable += 1
  }

  return outcome
}

function confirmationDetail(confirmation: Confirmation, scope: string): string {
  if (confirmation.level) {
    return confirmation.level === 'url'
      ? `URL persis tercatat sebagai indikator pada ${scope}.`
      : `${scope} tercatat sebagai indikator tingkat domain, bukan indikator URL persis.`
  }

  const parts: string[] = []
  if (confirmation.massList > 0) {
    parts.push(
      `${confirmation.massList} pulse memuat lebih dari ${MAX_TARGET_SPECIFIC_INDICATORS} indikator sehingga kecocokan di dalamnya tidak khusus untuk alamat ini`,
    )
  }
  if (confirmation.checked > 0) {
    parts.push(`${confirmation.checked} pulse diperiksa daftar indikatornya dan tidak memuat alamat ini`)
  }
  if (confirmation.unavailable > 0) {
    parts.push(`${confirmation.unavailable} pulse tidak dapat diperiksa daftar indikatornya`)
  }
  if (confirmation.notRequested > 0) {
    parts.push(`${confirmation.notRequested} pulse lainnya tidak diminta karena batas permintaan konfirmasi tercapai`)
  }
  if (parts.length === 0) parts.push('tidak ada pulse dengan konteks ancaman yang dapat dikonfirmasi')

  return `Kecocokan indikator tidak terbukti: ${parts.join('; ')}.`
}

// Severity sinyal konfirmasi mengikuti TINGKAT bukti, bukan hanya kelas ancamannya: kecocokan
// pada tingkat domain tidak pernah tampil sekelas konfirmasi ancaman pada URL yang diperiksa.
function confirmationSignal(confirmation: Confirmation, scope: string): ProviderSignal {
  if (!confirmation.level) {
    return { label: 'Konfirmasi indikator', detail: confirmationDetail(confirmation, scope), severity: 'info' }
  }

  const ceiling: SignalSeverity = confirmation.level === 'url' ? 'danger' : 'warning'

  return {
    label: 'Indikator terverifikasi',
    detail: confirmationDetail(confirmation, scope),
    severity: capSeverity(confirmation.grade === 'malware' ? 'danger' : 'warning', ceiling),
  }
}

// Kategori B: intelijen komunitas tanpa kontribusi risiko. Data pulse tetap utuh sebagai sinyal
// info; vonis `inconclusive` dan skor `null` menjaga agar tidak ada angka community intelligence
// yang mengalir ke skor ancaman eksternal.
function communityIntelligence(
  summary: PulseSummary,
  scope: string,
  confirmation: Confirmation | null,
  summaryText: string,
  reason: string,
): ProviderCheck {
  const signals = pulseSignals(summary, scope, 'info')
  if (confirmation) signals.push(confirmationSignal(confirmation, scope))

  return {
    status: 'success',
    verdict: 'inconclusive',
    score: null,
    summary: summaryText,
    signals,
    reason,
  }
}

// Kategori A pada rute indikator URL. Bobotnya mengikuti TINGKAT kecocokan: URL persis dengan
// keluarga malware adalah yang terkuat, kecocokan pada tingkat domain tidak pernah malicious.
function verifiedUrlCheck(
  summary: PulseSummary,
  confirmation: Confirmation,
  hostname: string,
): ProviderCheck {
  const families = (confirmation.pulse?.families ?? []).slice(0, 3).join(', ')

  if (confirmation.level === 'url' && confirmation.grade === 'malware') {
    return {
      status: 'success',
      verdict: 'malicious',
      score: 70,
      summary: `AlienVault OTX menghubungkan URL ini dengan keluarga malware (${families || 'tanpa nama keluarga'}) melalui ${summary.count} pulse.`,
      signals: [...pulseSignals(summary, 'URL ini', 'danger'), confirmationSignal(confirmation, 'URL ini')],
      reason: null,
    }
  }

  if (confirmation.level === 'url') {
    return {
      status: 'success',
      verdict: 'suspicious',
      score: 45,
      summary: `AlienVault OTX mencatat URL ini sebagai indikator pada ${summary.count} pulse komunitas dengan konteks ${
        confirmation.grade === 'malware' ? `keluarga malware (${families})` : 'ancaman yang relevan'
      }; penyebutan saja bukan konfirmasi ancaman.`,
      signals: [...pulseSignals(summary, 'URL ini', 'warning'), confirmationSignal(confirmation, 'URL ini')],
      reason: null,
    }
  }

  return {
    status: 'success',
    verdict: 'suspicious',
    score: 55,
    summary: `AlienVault OTX tidak mencatat URL ini sebagai indikator; yang terbukti adalah host ${hostname} pada indikator tingkat domain dengan keluarga malware (${families || 'tanpa nama keluarga'}).`,
    signals: [...pulseSignals(summary, 'URL ini', 'warning'), confirmationSignal(confirmation, hostname)],
    reason:
      'Bukti berasal dari indikator domain, bukan URL persis yang diperiksa; penyebutan saja bukan konfirmasi ancaman.',
  }
}

export const otxAdapter: ProviderAdapter = {
  id: 'otx',
  label: 'AlienVault OTX',
  requiredEnv: ['OTX_API_KEY'],
  timeoutMs: 20_000,
  isConfigured: (config) => Boolean(config.otxApiKey),
  async check(context, config): Promise<ProviderCheck> {
    if (!config.otxApiKey) {
      return notConfiguredCheck('OTX_API_KEY belum dikonfigurasi di backend.')
    }

    const headers = { 'X-OTX-API-KEY': config.otxApiKey }
    const target = { url: context.url, hostname: context.hostname }
    const urlResult = await fetchJson(
      context.fetchImpl,
      indicatorUrl('url', context.url),
      { headers },
      REQUEST_TIMEOUT_MS,
    )

    if (!urlResult.ok) {
      if (isRouteNotFound(urlResult)) {
        return errorCheck(
          'Rute indikator URL AlienVault OTX tidak dikenali (HTTP 404); ini kegagalan teknis, bukan bukti URL bersih.',
        )
      }
      return failureCheck(urlResult)
    }

    const urlSummary = summarize(urlResult.data)
    if (!urlSummary) {
      return errorCheck('AlienVault OTX mengembalikan respons tanpa informasi pulse.')
    }

    if (urlSummary.count > 0) {
      // Kecocokan pada rute indikator URL adalah kandidat terkuat yang tersedia, tetapi BUKAN
      // vonis otomatis: target harus terbukti ada dalam daftar indikator pulse itu dan pulse itu
      // harus membawa konteks ancaman. Selain itu hasilnya intelijen komunitas tanpa skor.
      const confirmation = await confirmTarget(context, headers, candidatesFor(urlSummary, false), target)

      if (confirmation.level && confirmation.grade) {
        return verifiedUrlCheck(urlSummary, confirmation, context.hostname)
      }

      return communityIntelligence(
        urlSummary,
        'URL ini',
        confirmation,
        `AlienVault OTX menemukan ${urlSummary.count} laporan komunitas yang menyebut URL ini; kecocokan indikator dengan konteks ancaman tidak terbukti, jadi penyebutan tidak dinyatakan sebagai risiko.`,
        'Penyebutan komunitas tanpa indikator yang terbukti cocok dengan URL ini; bukan konfirmasi ancaman maupun bukti bersih.',
      )
    }

    // Indikator URL persis hampir selalu kosong karena pulse ditulis pada tingkat domain,
    // karena itu ditelusuri indikator domain hostname yang sama.
    const hostname = context.hostname
    const isIpHost = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith('[')
    if (isIpHost) {
      return {
        ...notFoundCheck('AlienVault OTX tidak memiliki pulse untuk URL ini.'),
        reason:
          'Tidak ada pulse pada indikator URL; hostname berupa alamat IP sehingga indikator domain tidak dapat diperiksa.',
      }
    }

    const domainResult = await fetchJson(
      context.fetchImpl,
      indicatorUrl('domain', hostname),
      { headers },
      REQUEST_TIMEOUT_MS,
    )

    if (!domainResult.ok) {
      // 400 "Invalid domain" berarti domain tidak dikenal di OTX: tetap tanpa bukti,
      // sedangkan kegagalan lain dilaporkan apa adanya.
      if (domainResult.kind === 'invalid_request' && domainResult.status === 400) {
        return notFoundDomain(hostname)
      }

      if (domainResult.kind === 'not_found') {
        return errorCheck(
          'Rute indikator domain AlienVault OTX tidak dikenali (HTTP 404); ini kegagalan teknis, bukan bukti URL bersih.',
        )
      }

      // Indikator URL memang kosong, tetapi penelusuran domain gagal secara teknis: status
      // kegagalan tetap dilaporkan supaya tidak terbaca sebagai "tidak ada laporan komunitas".
      const failed = failureCheck(domainResult)
      return {
        ...failed,
        reason: `Indikator URL tidak memiliki pulse, namun penelusuran domain ${hostname} gagal: ${failed.reason ?? 'tanpa detail'}.`,
      }
    }

    const domainSummary = summarize(domainResult.data)
    if (!domainSummary || domainSummary.count === 0) {
      return notFoundDomain(hostname)
    }

    // Bukti OTX pada tingkat domain tetap harus terbukti sebagai indikator pulse, dan hanya
    // pulse berkeluarga malware yang boleh menaikkan vonis (sebatas `suspicious`).
    const candidates = candidatesFor(domainSummary, true)
    if (candidates.length === 0) {
      // Penyebutan domain tanpa keluarga malware adalah laporan komunitas, bukan indikasi
      // ancaman pada URL ini. Tidak diberi skor agar tidak mendorong risiko situs resmi.
      return communityIntelligence(
        domainSummary,
        `domain ${hostname}`,
        null,
        `AlienVault OTX tidak menyebut URL ini; domain ${hostname} hanya muncul pada ${domainSummary.count} pulse komunitas tanpa keluarga malware.`,
        'Penyebutan domain oleh komunitas tanpa indikator malware konkret; bukan konfirmasi ancaman maupun bukti bersih.',
      )
    }

    const confirmation = await confirmTarget(context, headers, candidates, target)

    if (confirmation.level && confirmation.grade === 'malware') {
      const families = (confirmation.pulse?.families ?? []).slice(0, 3).join(', ')
      return {
        status: 'success',
        verdict: 'suspicious',
        score: 55,
        summary: `AlienVault OTX tidak menyebut URL ini, tetapi domain ${hostname} terbukti menjadi indikator pulse dengan keluarga malware (${families}) pada ${domainSummary.count} pulse.`,
        signals: [
          ...pulseSignals(domainSummary, `domain ${hostname}`, 'warning'),
          confirmationSignal(confirmation, `domain ${hostname}`),
        ],
        reason:
          'Bukti berasal dari indikator domain, bukan URL persis yang diperiksa; penyebutan saja bukan konfirmasi ancaman.',
      }
    }

    return communityIntelligence(
      domainSummary,
      `domain ${hostname}`,
      confirmation,
      `AlienVault OTX tidak menyebut URL ini; domain ${hostname} muncul pada ${domainSummary.count} pulse komunitas tanpa kecocokan indikator yang terbukti.`,
      'Kecocokan indikator pada domain tidak terbukti (atau hanya berasal dari daftar indikator massal); intelijen komunitas bukan konfirmasi ancaman maupun bukti bersih.',
    )
  },
}

function notFoundDomain(hostname: string): ProviderCheck {
  return {
    ...notFoundCheck('AlienVault OTX tidak memiliki laporan komunitas untuk URL ini.'),
    signals: [
      {
        label: 'Cakupan penelusuran',
        detail: 'Indikator URL persis dan indikator domain diperiksa; keduanya tanpa pulse.',
        severity: 'info',
      },
    ],
    reason: `Tidak ada pulse pada URL ini maupun domain ${hostname}; ketiadaan laporan komunitas bukan bukti situs aman.`,
  }
}

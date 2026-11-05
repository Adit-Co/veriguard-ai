import { fetchJson, type FetchJsonResult } from '../http.js'
import {
  errorCheck,
  failureCheck,
  isRecord,
  numberValue,
  recordValue,
  stringList,
  stringValue,
  notConfiguredCheck,
  withExistingReportEvidence,
} from '../result.js'
import { hostOfIndicatorValue, isSameHost } from '../hostIdentity.js'
import { normalizeScanUrl } from '../url.js'
import type { ProviderAdapter, ProviderCheck, ProviderSignal, ProviderSignalSeverity } from '../types.js'

// Kontrak resmi menurut konektor API penerbit sendiri (hybrid-analysis/VxAPI, api_caller.py)
// dan verifikasi langsung 2026-10-28: POST /api/v2/search/terms, kunci pada header `api-key`,
// body form-urlencoded; level autentikasi `/search/terms` = RESTRICTED (dapat dipanggil kunci
// akun standar). Basis memakai host CANONICAL tanpa `www`: `https://www.hybrid-analysis.com`
// menjawab HTTP 301 normalisasi host ke apex, yang dengan semantik `redirect: 'error'` muncul
// sebagai galat "redirect not allowed". Apex melayani API tanpa redirect (terverifikasi: POST
// tanpa kunci -> HTTP 403, bukan 3xx). Permintaan diarahkan LANGSUNG ke tujuan final sehingga
// kredensial tidak pernah diteruskan ke host redirect dan redirect tidak diikuti secara buta.
const API_BASE = 'https://hybrid-analysis.com/api/v2'
const REQUEST_TIMEOUT_MS = 8_000
const MAX_DOCS_READ = 20
const MAX_SUMMARY_CHARS = 240
// Batas jumlah host lain yang disebutkan pada sinyal. Hanya untuk meringkas tampilan; tidak
// ada angka dari provider yang dipakai sebagai skor.
const MAX_HOSTS_LISTED = 3

// Bentuk respons terdokumentasi /search/terms (HTTP 200, application/json): objek
// { search_terms:[{id,value}], count:<number>, result:[<dok analisis>] }. Tidak ada field
// `threat_level` numerik pada endpoint ini; vonis terbaca pada field string `verdict`,
// dengan `threat_score` (0-100) dan `av_detect` sebagai sinyal pendukung.
type VerdictBand = 'malicious' | 'suspicious' | 'clean' | 'inconclusive'

// Pemetaan string `verdict` resmi (mis. "malicious", "suspicious", "no specific threat",
// "whitelisted", "no verdict", "unknown"). Hanya nilai yang tercantum di sini yang dibaca
// sebagai vonis; apa pun yang tidak dikenal (termasuk "no specific threat"/"no verdict"/
// "unknown") TIDAK pernah dibaca sebagai bukti aman.
function verdictBandOf(doc: Record<string, unknown>): VerdictBand {
  const raw = stringValue(doc.verdict)
  const verdict = raw?.trim().toLowerCase()
  if (verdict === 'malicious') return 'malicious'
  if (verdict === 'suspicious') return 'suspicious'
  if (verdict === 'clean' || verdict === 'whitelisted') return 'clean'
  return 'inconclusive'
}

const BAND_RANK: Record<VerdictBand, number> = {
  inconclusive: 0,
  clean: 1,
  suspicious: 2,
  malicious: 3,
}

// Vonis terburuk di antara seluruh dokumen. `hasReadableVerdict` benar hanya bila ada dokumen
// dengan field `verdict` berupa string tak-kosong (termasuk "no specific threat" yang dipetakan
// `inconclusive`) — laporan semacam itu tetap dilaporkan `success`/`inconclusive`, bukan
// diabaikan. Bila tidak ada satu pun vonis terbaca, caller jatuh ke penelusuran domain dan pada
// akhirnya memperlakukan ketiadaan data sebagai "belum ada bukti", bukan sebagai situs aman.
function worstBand(docs: Record<string, unknown>[]): { band: VerdictBand; hasReadableVerdict: boolean } {
  let worst: VerdictBand = 'inconclusive'
  let hasReadableVerdict = false
  for (const doc of docs) {
    const verdict = stringValue(doc.verdict)
    if (verdict && verdict.trim().length > 0) hasReadableVerdict = true
    const band = verdictBandOf(doc)
    if (BAND_RANK[band] > BAND_RANK[worst]) worst = band
  }
  return { band: worst, hasReadableVerdict }
}

// Ekstraktor daftar hasil yang tahan terhadap varian bentuk terdokumentasi: objek ber-`result`
// (bentuk resmi), `results` jamak, atau array di level teratas. Mengembalikan null bila bentuk
// tidak dapat dikenali, agar caller dapat melaporkan diagnostik alih-alih mengarang vonis.
function extractResultDocs(data: unknown): Record<string, unknown>[] | null {
  if (Array.isArray(data)) return data.filter(isRecord)
  const obj = recordValue(data)
  if (!obj) return null
  const candidate = obj.result ?? obj.results
  if (Array.isArray(candidate)) return candidate.filter(isRecord)
  return null
}

// Diagnostik untuk bentuk tak terduga: HANYA tipe level-teratas dan kunci objek level-teratas.
// Tidak pernah memuat nilai, kunci API, header, maupun isi respons mentah.
function describeShape(data: unknown): string {
  if (Array.isArray(data)) return 'array level-teratas tanpa daftar hasil yang dapat dikenali'
  const obj = recordValue(data)
  if (obj) {
    const keys = Object.keys(obj)
      .slice(0, 12)
      .map((key) => key.slice(0, 40))
    return `objek dengan kunci [${keys.join(', ')}] namun tanpa daftar hasil yang dikenali`
  }
  return `tipe ${typeof data} yang bukan objek/array hasil`
}

function earliestAnalysis(docs: Record<string, unknown>[], now: number): { observedAt: string | null; ageMs: number | null } {
  let newest = Number.NaN
  for (const doc of docs) {
    const stamp = stringValue(doc.analysis_start_time)
    if (!stamp) continue
    const parsed = Date.parse(stamp)
    if (!Number.isNaN(parsed) && (Number.isNaN(newest) || parsed > newest)) newest = parsed
  }
  if (Number.isNaN(newest)) return { observedAt: null, ageMs: null }
  return { observedAt: new Date(newest).toISOString(), ageMs: Math.max(0, now - newest) }
}

function describeMatch(docs: Record<string, unknown>[], scope: 'URL' | 'domain'): string {
  const families = [
    ...new Set(docs.flatMap((doc) => stringList(doc.vx_family, 3)),),
  ].slice(0, 3)
  const tags = [...new Set(docs.flatMap((doc) => stringList(doc.tags, 4)))].slice(0, 4)
  const parts = [
    `${docs.length} analisis pada ${scope}`,
    families.length > 0 ? `keluarga ${families.join(', ')}` : null,
    tags.length > 0 ? `tag ${tags.join(', ')}` : null,
  ].filter((part): part is string => Boolean(part))
  return parts.join('; ')
}

function buildSignals(
  docs: Record<string, unknown>[],
  band: VerdictBand,
  scope: 'URL' | 'domain',
): ProviderSignal[] {
  const severity = band === 'malicious' ? 'danger' : band === 'suspicious' ? 'warning' : 'info'

  // Sinyal pendukung: threat_score tertinggi dan av_detect tertinggi yang terbaca.
  let maxThreatScore: number | null = null
  let maxAvDetect: number | null = null
  for (const doc of docs) {
    const score = numberValue(doc.threat_score)
    if (score !== null && (maxThreatScore === null || score > maxThreatScore)) maxThreatScore = score
    const detect = numberValue(doc.av_detect)
    if (detect !== null && (maxAvDetect === null || detect > maxAvDetect)) maxAvDetect = detect
  }

  const detail = [
    `verdict "${band}"`,
    maxThreatScore !== null ? `threat_score ${maxThreatScore}` : null,
    maxAvDetect !== null ? `av_detect ${maxAvDetect}%` : null,
  ]
    .filter((part): part is string => Boolean(part))
    .join(', ')

  const signals: ProviderSignal[] = [
    {
      label: 'Vonis provider',
      detail: `Hybrid Analysis mencatat ${detail} pada ${scope.toLowerCase()} ini.`,
      severity,
    },
    {
      label: 'Analisis yang cocok',
      detail: describeMatch(docs, scope),
      severity,
    },
  ]

  const urls = [
    ...new Set(
      docs
        .flatMap((doc) => recordedUrls(doc))
        .map((url) => url.slice(0, MAX_SUMMARY_CHARS)),
    ),
  ].slice(0, 3)
  if (urls.length > 0) {
    signals.push({
      label: 'URL yang tercatat provider',
      detail: urls.join(' · '),
      severity: 'info',
    })
  }

  return signals
}

function searchFailureNote(result: Extract<FetchJsonResult, { ok: false }>): string {
  return result.status === null ? result.reason : `${result.reason} (HTTP ${result.status})`
}

// Nilai URL yang tercatat pada dokumen (`url[]`). Pada bentuk terdokumentasi ini adalah URL
// yang TERAMAT selama analisis — sering kali redirect destination atau host tambahan — jadi
// kecocokan host di dalamnya belum berarti analisis itu tentang URL yang kami periksa.
function recordedUrls(doc: Record<string, unknown>): string[] {
  const entries = Array.isArray(doc.url) ? doc.url : []
  const urls: string[] = []
  for (const entry of entries) {
    if (!isRecord(entry)) continue
    const value = stringValue(entry.url)
    if (value) urls.push(value)
  }
  return [...new Set(urls)]
}

type DocumentIdentity = { subjectHosts: string[]; observedHosts: string[] }

// Identitas dokumen: field `host`/`domain` adalah subjek analisis, sedangkan host yang hanya
// muncul di daftar URL teramati adalah bukti tambahan. Keduanya dipisah agar "pernah terlihat
// dalam analisis ini" tidak pernah disamakan dengan "dianalisis pada URL ini". Nilai yang tidak
// dapat diurai tidak dipakai sebagai identitas maupun sebagai kecocokan.
function documentIdentity(doc: Record<string, unknown>): DocumentIdentity {
  const subjectHosts: string[] = []
  for (const field of ['host', 'domain'] as const) {
    const value = stringValue(doc[field])
    const host = value ? hostOfIndicatorValue(value) : null
    if (host && !subjectHosts.includes(host)) subjectHosts.push(host)
  }

  const observedHosts: string[] = []
  for (const url of recordedUrls(doc)) {
    const host = hostOfIndicatorValue(url)
    if (host && !subjectHosts.includes(host) && !observedHosts.includes(host)) observedHosts.push(host)
  }

  return { subjectHosts, observedHosts }
}

function analyzesExactUrl(doc: Record<string, unknown>, targetUrl: string): boolean {
  return recordedUrls(doc).some((value) => {
    try {
      return normalizeScanUrl(value) === targetUrl
    } catch {
      return false
    }
  })
}

/**
 * Hanya dua hal yang membuat sebuah laporan menjadi bukti untuk alamat yang diperiksa:
 * - dokumen mencatat PERSIS URL yang diperiksa (berlaku pada kedua penelusuran), atau
 * - penelusuran dilakukan pada URL persis dan host identitas dokumen adalah host yang sama.
 *
 * Domain induk, subdomain lain, lookalike, dan host redirect TIDAK ikut naik: vonis sandbox
 * host lain tidak diwariskan ke alamat ini.
 */
function isSubjectDoc(
  doc: Record<string, unknown>,
  target: { url: string; hostname: string },
  route: 'url' | 'domain',
): boolean {
  if (analyzesExactUrl(doc, target.url)) return true
  if (route !== 'url') return false

  const identity = documentIdentity(doc)
  return [...identity.subjectHosts, ...identity.observedHosts].some((host) =>
    isSameHost(host, target.hostname),
  )
}

// Kelas bukti per dokumen: subjek (Kategori A), laporan berkaitan (Kategori B), atau dokumen
// tanpa identitas terbaca (Kategori C).
type EvidenceSplit = {
  subject: Record<string, unknown>[]
  sameHostRelated: number
  foreignCount: number
  foreignHosts: string[]
  unidentified: number
}

function splitBySubject(
  docs: Record<string, unknown>[],
  target: { url: string; hostname: string },
  route: 'url' | 'domain',
): EvidenceSplit {
  const split: EvidenceSplit = {
    subject: [],
    sameHostRelated: 0,
    foreignCount: 0,
    foreignHosts: [],
    unidentified: 0,
  }

  for (const doc of docs) {
    if (isSubjectDoc(doc, target, route)) {
      split.subject.push(doc)
      continue
    }

    const identity = documentIdentity(doc)
    const hosts = [...identity.subjectHosts, ...identity.observedHosts]
    if (hosts.length === 0) {
      split.unidentified += 1
      continue
    }

    if (hosts.some((host) => isSameHost(host, target.hostname))) {
      split.sameHostRelated += 1
      continue
    }

    split.foreignCount += 1
    for (const host of hosts) {
      if (!split.foreignHosts.includes(host)) split.foreignHosts.push(host)
    }
  }

  return { ...split, foreignHosts: split.foreignHosts.slice(0, MAX_HOSTS_LISTED) }
}

// Agregat intelijen berkaitan dari kedua penelusuran. Angkanya hanya untuk penjelasan, tidak
// pernah masuk ke skor.
type RelatedIntel = {
  sameHostRelated: number
  foreignCount: number
  foreignHosts: string[]
  unidentified: number
}

function absorbIntel(intel: RelatedIntel, split: EvidenceSplit): void {
  intel.sameHostRelated += split.sameHostRelated
  intel.foreignCount += split.foreignCount
  intel.unidentified += split.unidentified
  for (const host of split.foreignHosts) {
    if (!intel.foreignHosts.includes(host) && intel.foreignHosts.length < MAX_HOSTS_LISTED) {
      intel.foreignHosts.push(host)
    }
  }
}

function hasIntel(intel: RelatedIntel): boolean {
  return intel.sameHostRelated + intel.foreignCount + intel.unidentified > 0
}

// Sinyal Kategori B/C: selalu `info`. Tidak ada jalur dari severity ke skor agen (dijaga oleh
// tes agregasi), vonis agen tetap `inconclusive`, dan skor tetap `null`, jadi laporan berkaitan
// tidak dapat menaikkan risiko maupun dibaca sebagai bukti aman.
function intelSignals(intel: RelatedIntel, queriedHost: string): ProviderSignal[] {
  const signals: ProviderSignal[] = []

  if (intel.sameHostRelated > 0) {
    signals.push({
      label: 'Laporan terkait pada host ini',
      detail:
        `${intel.sameHostRelated} laporan menganalisis URL lain pada ${queriedHost}, bukan URL persis yang diperiksa, ` +
        'sehingga vonisnya tidak dipakai untuk alamat ini.',
      severity: 'info',
    })
  }

  if (intel.foreignCount > 0) {
    const listed = intel.foreignHosts.length > 0 ? ` (${intel.foreignHosts.join(', ')})` : ''
    signals.push({
      label: 'Laporan pada host lain',
      detail:
        `${intel.foreignCount} laporan ikut terkembalikan menunjuk host di luar ${queriedHost}${listed} ` +
        'sehingga tidak dihitung sebagai vonis untuk alamat ini.',
      severity: 'info',
    })
  }

  if (intel.unidentified > 0) {
    signals.push({
      label: 'Identitas laporan',
      detail:
        `${intel.unidentified} laporan dikembalikan tanpa identitas subjek sehingga vonis di dalamnya tidak dapat ` +
        'dikaitkan dengan alamat ini; itu bukan bukti aman maupun bukti ancaman.',
      severity: 'info',
    })
  }

  return signals
}

function withIntel(check: ProviderCheck, intel: RelatedIntel, hostname: string): ProviderCheck {
  const notes = intelSignals(intel, hostname)
  return notes.length > 0 ? { ...check, signals: [...check.signals, ...notes] } : check
}

// Kategori B/C untuk agen ini: data provider tetap ditampilkan, vonis tidak naik, skor kosong.
// `unreadableSubjects` adalah dokumen yang subjeknya cocok tetapi tidak membawa vonis terbaca;
// itu Kategori C, bukan bukti aman.
function intelligenceOnlyCheck(
  intel: RelatedIntel,
  hostname: string,
  unreadableSubjects: number,
): ProviderCheck {
  const related = intel.sameHostRelated + intel.foreignCount + intel.unidentified
  const parts: string[] = []
  if (related > 0) parts.push(`${related} laporan berkaitan tidak menganalisis URL persis ini`)
  if (unreadableSubjects > 0) {
    parts.push(`${unreadableSubjects} laporan pada URL ini tidak membawa vonis yang terbaca`)
  }
  const detail = parts.length > 0 ? parts.join('; ') : 'tidak ada laporan yang dapat dipakai untuk alamat ini'

  return {
    // `success`: kedua penelusuran selesai dan provider menjawab dengan data yang terurai,
    // hanya isinya tidak layak jadi vonis untuk alamat ini. `not_found` dipakai ketika provider
    // benar-benar tidak punya dokumen; membedakan keduanya membuat "agen bekerja tapi tidak
    // memberi bukti" tidak pernah disamakan dengan "agen tidak menemukan apa pun".
    status: 'success',
    verdict: 'inconclusive',
    score: null,
    summary: `Hybrid Analysis tidak memiliki bukti untuk URL persis ini; ${detail}. Data yang ada tetap ditampilkan sebagai informasi.`,
    signals: [
      {
        label: 'Cakupan penelusuran',
        detail: 'Pencarian laporan berdasarkan URL persis dan berdasarkan host; tidak ada subjek yang cocok dengan URL ini.',
        severity: 'info',
      },
      ...intelSignals(intel, hostname),
    ],
    reason:
      'Vonis sandbox hanya dipakai bila subjek analisisnya adalah alamat yang diperiksa. Laporan URL lain pada host yang sama, laporan host berkaitan, dan dokumen tanpa identitas tidak diwariskan ke alamat ini — dan ketiadaan laporan bukan bukti situs aman.',
  }
}

export const hybridAnalysisAdapter: ProviderAdapter = {
  id: 'hybrid',
  label: 'Hybrid Analysis',
  requiredEnv: ['HYBRID_ANALYSIS_API_KEY'],
  timeoutMs: 20_000,
  isConfigured: (config) => Boolean(config.hybridAnalysisApiKey),
  async check(context, config): Promise<ProviderCheck> {
    if (!config.hybridAnalysisApiKey) {
      return notConfiguredCheck('HYBRID_ANALYSIS_API_KEY belum dikonfigurasi di backend.')
    }

    // Hanya pencarian laporan yang SUDAH ada (read-only). Tidak ada pengiriman URL untuk
    // analisis dinamis: agen ini tidak pernah membuat sampel sandbox baru.
    const headers = {
      'api-key': config.hybridAnalysisApiKey,
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
      // Cloudflare di depan hybrid-analysis.com menolak User-Agent bawaan runtime dengan 403.
      'User-Agent': 'veriguard-scanner',
    }

    const search = async (field: 'url' | 'domain', value: string) =>
      fetchJson(
        context.fetchImpl,
        `${API_BASE}/search/terms`,
        { method: 'POST', headers, body: new URLSearchParams({ [field]: value }).toString() },
        REQUEST_TIMEOUT_MS,
      )

    const urlResult = await search('url', context.url)
    if (!urlResult.ok) {
      return failureCheck({ ...urlResult, reason: searchFailureNote(urlResult) })
    }

    const urlDocs = extractResultDocs(urlResult.data)
    if (urlDocs === null) {
      return errorCheck(
        `Respons pencarian Hybrid Analysis tidak dikenali (HTTP ${urlResult.status}; ${describeShape(urlResult.data)}); tidak dapat diurai sebagai daftar hasil.`,
      )
    }

    const hostname = context.hostname
    const target = { url: context.url, hostname }
    const intel: RelatedIntel = {
      sameHostRelated: 0,
      foreignCount: 0,
      foreignHosts: [],
      unidentified: 0,
    }

    // Kategori A: vonis dihitung HANYA dari dokumen yang subjeknya alamat yang diperiksa.
    const cappedUrlDocs = urlDocs.slice(0, MAX_DOCS_READ)
    const urlSplit = splitBySubject(cappedUrlDocs, target, 'url')
    absorbIntel(intel, urlSplit)
    if (urlSplit.subject.length > 0) {
      const { band, hasReadableVerdict } = worstBand(urlSplit.subject)
      if (hasReadableVerdict) {
        return withIntel(
          summarize(urlSplit.subject, band, 'URL', context.url, context.now()),
          intel,
          hostname,
        )
      }
    }

    // Tidak ada subjek yang cocok pada penelusuran URL persis: telusuri laporan pada host ini,
    // sama seperti agen lain. Isinya Kategori B/C, kecuali sebuah dokumen ternyata mencatat
    // persis URL yang diperiksa.
    const isIpHost = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith('[')
    if (isIpHost) {
      return {
        ...notFoundLikeResult('URL/hostname ini belum memiliki laporan yang dapat dipakai sebagai bukti.'),
        signals: intelSignals(intel, hostname),
        reason:
          'Tidak ada laporan dengan vonis terbaca untuk URL ini; hostname berupa alamat IP sehingga penelusuran domain tidak dapat dilakukan. Ketiadaan laporan bukan bukti situs aman.',
      }
    }

    const domainResult = await search('domain', hostname)
    if (!domainResult.ok) {
      const failed = failureCheck(domainResult)
      return {
        ...failed,
        reason: `Penelusuran URL tidak memberi vonis, namun penelusuran domain ${hostname} gagal: ${failed.reason ?? 'tanpa detail'}.`,
      }
    }

    const domainDocs = extractResultDocs(domainResult.data)
    if (domainDocs === null) {
      return errorCheck(
        `Respons pencarian domain Hybrid Analysis tidak dikenali (HTTP ${domainResult.status}; ${describeShape(domainResult.data)}); tidak dapat diurai sebagai daftar hasil.`,
      )
    }

    const cappedDomainDocs = domainDocs.slice(0, MAX_DOCS_READ)
    const domainSplit = splitBySubject(cappedDomainDocs, target, 'domain')
    absorbIntel(intel, domainSplit)
    if (domainSplit.subject.length > 0) {
      const { band, hasReadableVerdict } = worstBand(domainSplit.subject)
      if (hasReadableVerdict) {
        // Dokumen yang mencatat persis URL ini adalah bukti subjek penuh, walaupun term
        // penelusurannya host. Laporan host lain pada domain yang sama tidak sampai ke sini.
        return withIntel(
          summarize(domainSplit.subject, band, 'URL', context.url, context.now()),
          intel,
          hostname,
        )
      }
    }

    const unreadableSubjects = urlSplit.subject.length + domainSplit.subject.length
    if (hasIntel(intel) || unreadableSubjects > 0) {
      return intelligenceOnlyCheck(intel, hostname, unreadableSubjects)
    }

    // Kedua penelusuran mengembalikan nol dokumen: tidak ada bukti sama sekali.
    return {
      ...notFoundLikeResult('Hybrid Analysis tidak memiliki laporan dengan vonis untuk URL ini.'),
      reason: `Tidak ada laporan dengan vonis terbaca untuk URL ini maupun domain ${hostname}; ketiadaan laporan bukan bukti situs aman.`,
      signals: [
        {
          label: 'Cakupan penelusuran',
          detail: 'Pencarian laporan berdasarkan URL persis dan berdasarkan domain; keduanya tanpa vonis yang terbaca.',
          severity: 'info',
        },
      ],
    }
  },
}

function notFoundLikeResult(summary: string): ProviderCheck {
  return {
    status: 'not_found',
    verdict: 'inconclusive',
    score: null,
    summary,
    signals: [],
    reason: null,
  }
}

function summarize(
  docs: Record<string, unknown>[],
  band: VerdictBand,
  scope: 'URL' | 'domain',
  matchedValue: string,
  now: number,
): ProviderCheck {
  const { observedAt, ageMs } = earliestAnalysis(docs, now)

  let verdict: ProviderCheck['verdict']
  let score: number | null
  let reason: string | null = null

  if (band === 'malicious') {
    verdict = 'malicious'
    score = 85
  } else if (band === 'suspicious') {
    verdict = 'suspicious'
    score = 55
  } else if (band === 'clean') {
    verdict = 'clean'
    score = 10
    reason = 'Laporan provider memberi vonis "whitelisted"/"clean"'
  } else {
    // Vonis "no specific threat"/"no verdict"/"unknown" bukan bukti aman maupun ancaman.
    verdict = 'inconclusive'
    score = null
    reason = `Hybrid Analysis hanya mencatat vonis tanpa ancaman spesifik pada ${scope.toLowerCase()} ini; tidak dipakai sebagai bukti aman maupun ancaman.`
  }

  const check: ProviderCheck = {
    status: 'success',
    verdict,
    score,
    summary: `Hybrid Analysis menemukan ${describeMatch(docs, scope)} (verdict ${band}).`,
    signals: buildSignals(docs, band, scope),
    reason,
  }

  // Lookup reputasi selalu membaca dataset laporan yang sudah ada di provider; umur analisis
  // terbaru ikut dikirim sebagai metadata agar antarmuka dapat menampilkan waktu data yang
  // sebenarnya, tanpa menarasikan mekanisme pengambilan hasil kepada pengguna.
  return withExistingReportEvidence(check, observedAt, ageMs)
}

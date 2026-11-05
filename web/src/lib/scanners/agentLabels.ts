import { userFacingText } from '../uiText'
import {
  EXTERNAL_PROVIDER_IDS,
  type ExternalProviderId,
  type ProviderId,
  type ProviderResult,
  type ProviderSignal,
} from './types'

/**
 * Pemetaan stabil provider -> nomor agen, mengikuti urutan registrasi adapter di
 * functions/src/scanners/providers/index.ts (urlscan, virustotal, openphish,
 * threatfox, radar, otx, hybrid, safebrowsing). Nomor tidak pernah bergantung pada urutan hasil atau
 * pada agen mana yang menemukan ancaman.
 *
 * Dokumentasi internal (tidak ditampilkan ke pengguna):
 *   Agen 1 = adapter id `urlscan`      | Agen 5 = adapter id `radar`
 *   Agen 2 = adapter id `virustotal`   | Agen 6 = adapter id `otx`
 *   Agen 3 = adapter id `openphish`    | Agen 7 = adapter id `hybrid` (Hybrid Analysis)
 *   Agen 4 = adapter id `threatfox`    | Agen 8 = adapter id `safebrowsing` (Google Safe Browsing)
 */
const AGENT_NUMBER_BY_PROVIDER_ID = Object.fromEntries(
  EXTERNAL_PROVIDER_IDS.map((id, index) => [id, index + 1]),
) as Record<ExternalProviderId, number>

const PROVIDER_NAMES_BY_AGENT: ReadonlyArray<readonly [ExternalProviderId, readonly string[]]> = [
  ['radar', ['Cloudflare Radar URL Scanner', 'Cloudflare URL Scanner', 'Cloudflare Radar', 'Cloudflare', 'Radar']],
  ['threatfox', ['ThreatFox (abuse.ch)', 'abuse.ch', 'ThreatFox']],
  ['urlscan', ['URLScan.io', 'URLScan']],
  ['virustotal', ['VirusTotal']],
  ['openphish', ['OpenPhish']],
  ['otx', ['AlienVault OTX', 'OTX']],
  ['hybrid', ['Hybrid Analysis', 'HybridAnalysis', 'CrowdStrike Falcon Sandbox', 'Falcon Sandbox', 'Falcon']],
  ['safebrowsing', ['Google Safe Browsing', 'Safe Browsing']],
]

const AGENT_BY_NAME = new Map<string, ExternalProviderId>()
for (const [id, names] of PROVIDER_NAMES_BY_AGENT) {
  for (const name of names) AGENT_BY_NAME.set(name.toLowerCase(), id)
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

const PROVIDER_NAME_PATTERN = new RegExp(
  [...AGENT_BY_NAME.keys()]
    .sort((left, right) => right.length - left.length)
    .map(escapeRegExp)
    .join('|'),
  'gi',
)

const GENERIC_PHRASES: ReadonlyArray<readonly [RegExp, string]> = [
  [/\bdetection ratio(?: agen \d+)?\b/gi, 'Rasio deteksi'],
  [/\bsecurity engines?\b/gi, 'mesin keamanan'],
  [/\bthreat[_ ]level\b/gi, 'tingkat risiko'],
  [/\bengines?\b/gi, 'mesin keamanan'],
  [/\bpulse komunitas\b|\bpulses komunitas\b/gi, 'laporan komunitas'],
  [/\bpulses?\b/gi, 'laporan komunitas'],
  [/\bmalware family\b|\bmalware families\b/gi, 'keluarga malware'],
]

// Penjelasan cara pengambilan hasil (cache, laporan yang dipakai ulang, permintaan yang
// dilewati) adalah metadata internal, bukan temuan agen. Adapter baru berhenti menuliskannya
// ke `summary`/`reason`, tetapi laporan yang sudah tersimpan di penyimpanan data dan riwayat
// milik pengguna memuat kalimat itu secara permanen. Jadi kalimat tersebut dibuang di titik
// rendering, satu kali untuk semua permukaan (hasil langsung, halaman hasil, riwayat, dasbor).
// Pemenggalan bekerja per klausa agar bukti asli tetap utuh: contoh lama
// "Menggunakan laporan URLScan yang sudah ada (dibuat 4 menit lalu). URLScan menilai URL ini
// berbahaya (skor 100/100)." kehilangan klausa pertama dan menyimpan vonisnya.
const CACHE_NARRATIVE =
  /laporan[^.;]{0,40}\b(sudah ada|tersimpan)\b|hasil[^.;]{0,40}\b(dibaca|berasal|dibangun)\b|memakai (hasil|laporan|pemeriksaan)|hasil tersimpan|permintaan (keluar|ke agen)|tidak ada permintaan|tidak diulang|mengembalikan laporan|membaca laporan|menelusuri laporan|sumber laporan|unduhan ulang|bukan pemindaian|tidak ada pemindaian|pemindaian (langsung|ulang)|kebijakan kesegaran|batas segar|umurnya tidak dapat dipastikan|vomis ini berasal|data (hulu|yang dipakai ulang)|bukti hulu|baris agen terkait|berbagi (hasil|satu proses)|pekerjaan ganda|\bcache\b|dibuat [^)]{1,24} lalu|analisis terbaru [^)]{1,24} lalu|(feed|snapshot)[^.]{0,40}berumur/i

const CLAUSE_SPLIT = /(?<=[.;])\s+/

export function isCacheNarrativeText(text: string): boolean {
  return CACHE_NARRATIVE.test(text)
}

function stripCacheNarrative(text: string): string {
  if (!CACHE_NARRATIVE.test(text)) return text

  const kept = text
    .split(CLAUSE_SPLIT)
    .filter((clause) => !CACHE_NARRATIVE.test(clause))
    .join(' ')
    .trim()

  return kept.replace(/\s+([.;])/g, '$1')
}

export function agentNumber(id: ProviderId): number | null {
  if (id === 'internal') return null
  return AGENT_NUMBER_BY_PROVIDER_ID[id as ExternalProviderId] ?? null
}

export function agentLabel(id: ProviderId, fallbackLabel: string): string {
  const number = agentNumber(id)
  return number === null ? fallbackLabel : `Agen ${number}`
}

export function sanitizeAgentText(text: string): string {
  const withoutNarrative = stripCacheNarrative(text)

  let sanitized = withoutNarrative.replace(PROVIDER_NAME_PATTERN, (match) => {
    const id = AGENT_BY_NAME.get(match.toLowerCase())
    return id ? agentLabel(id, match) : match
  })

  for (const [pattern, replacement] of GENERIC_PHRASES) {
    sanitized = sanitized.replace(pattern, replacement)
  }

  return userFacingText(
    sanitized
      .replace(/\bProviders?\b/g, 'Agen')
      .replace(/\bproviders?\b/g, 'agen'),
  )
}

function capitalizeFirst(text: string): string {
  if (!text) return text
  return text.charAt(0).toUpperCase() + text.slice(1)
}

/**
 * Salinan siap-render dari hasil provider: hanya teks yang digeneralisasi.
 * Status, verdict, skor, dan durasi tetap persis seperti hasil scan aslinya.
 */
export function describeAgentProvider<T extends ProviderResult>(provider: T): T {
  const signals: ProviderSignal[] = provider.signals
    .map((signal) => ({
      severity: signal.severity,
      label: capitalizeFirst(sanitizeAgentText(signal.label)),
      detail: sanitizeAgentText(signal.detail),
    }))
    // Sinyal yang seluruh teksnya adalah narasi cara pengambilan hasil tidak meninggalkan
    // apa pun untuk dirender; ia dibuang, bukan ditampilkan sebagai baris kosong.
    .filter((signal) => signal.label.trim().length > 0 || signal.detail.trim().length > 0)

  return {
    ...provider,
    label: agentLabel(provider.id, provider.label),
    summary: sanitizeAgentText(provider.summary),
    signals,
    reason: provider.reason === null ? null : sanitizeAgentText(provider.reason),
  }
}

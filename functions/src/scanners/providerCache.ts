import { sha256Hex } from './hash.js'
import type {
  ProviderCheck,
  ScanCacheConfig,
  ScannerConfig,
  ScannerProviderId,
} from './types.js'

// Cache hasil per agen. Satu-satunya penyimpan hasil pemeriksaan yang sudah selesai di
// sisi backend: entri keyed pada (agen, URL ternormalisasi, kebijakan) sehingga
// "pemeriksaan penuh kena cache" cukup berarti semua agen yang dikonfigurasi punya entri
// segar, tanpa lapisan kedua yang bisa berbeda pendapat tentang kedaluwarsa.
//
// Kunci selalu hash: URL mentah tidak pernah menjadi key, tidak pernah di-log, dan tidak
// pernah disimpan apa adanya. Entri yang tersimpan adalah hasil agen (verdict/sinyal),
// bukan data pengguna.

// Versi v3: VGL-31 menambah penanda bukti negatif pada hasil agen. Entri v2 tidak
// membawanya, sehingga vonis Risiko Rendah tidak akan pernah bisa terbentuk dari cache lama.
// Versi ikut ter-hash ke kunci, jadi seluruh entri tanpa penanda dibuang, bukan ditambal.
const CACHE_VERSION = 'veriguard-scan-cache-v3'

// Status yang tidak PERNAH disimpan:
// - skipped/missing config: bukan jawaban, hanya "agen tidak jalan".
// - auth_failed: kesalahan kredensial permanen; mencoba lagi harus tetap murah.
// - error: kegagalan tak terklasifikasi; tidak boleh menyamar sebagai hasil sah.
// - invalid_request: penolakan bentuk permintaan; diperbaiki di kode kami, bukan diseduh.
// Meng-cache salah satunya membuat kegagalan tampak seperti kesimpulan.
const CACHEABLE_STATUSES = new Set([
  'success',
  'not_found',
  'rate_limited',
  'unavailable',
  'timeout',
])

// Status "positif" yang menjawab pertanyaan pengguna; sisanya negatif sementara dan
// disimpan sebentar saja hanya untuk mencegah spam permintaan, dengan status utuh.
const POSITIVE_STATUSES = new Set(['success', 'not_found'])

export type ProviderCacheEntry = {
  providerId: ScannerProviderId
  check: ProviderCheck
  observedAt: string
  observedAtMs: number
  expiresAtMs: number
}

export type ProviderCacheHit = {
  entry: ProviderCacheEntry
  ageMs: number
}

const store = new Map<string, ProviderCacheEntry>()

// Nilai maksimum kebijakan umur laporan per agen, hanya bila operator mengaturnya lewat
// env. Bila tidak, TTL cache milik kami sudah lebih ketat daripada default adapter
// (urlscan/radar 24 jam, virustotal 168 jam, kami 60 menit), jadi tidak perlu ditebak.
const MAX_REPORT_AGE_ENV_KEY: Partial<Record<ScannerProviderId, keyof ScannerConfig>> = {
  urlscan: 'urlscanMaxReportAgeHours',
  virustotal: 'virusTotalMaxReportAgeHours',
  radar: 'radarMaxReportAgeHours',
}

function maxReportAgeMs(providerId: ScannerProviderId, config: ScannerConfig): number | null {
  const key = MAX_REPORT_AGE_ENV_KEY[providerId]
  if (!key) return null
  const hours = config[key]
  if (typeof hours !== 'number' || !Number.isFinite(hours) || hours <= 0) return null
  return Math.round(hours * 3_600_000)
}

function policyFingerprint(providerId: ScannerProviderId, config: ScannerConfig): string {
  const ttl = config.scanCache?.resultTtlMs[providerId] ?? 0
  const failureTtl = config.scanCache?.failureTtlMs ?? 0
  const maxAge = maxReportAgeMs(providerId, config) ?? 0
  return `${ttl}:${failureTtl}:${maxAge}`
}

export function isCacheableStatus(status: ProviderCheck['status']): boolean {
  return CACHEABLE_STATUSES.has(status)
}

// Kunci opaque. Entri juga menyimpan providerId dan diverifikasi saat dibaca, sehingga
// bahkan tabrakan hash yang mustahil secara praktis tidak dapat menyajikan hasil agen lain.
export function providerCacheKey(
  providerId: ScannerProviderId,
  normalizedUrl: string,
  config: ScannerConfig,
): string {
  return sha256Hex(
    `${CACHE_VERSION}|${providerId}|${normalizedUrl}|${policyFingerprint(providerId, config)}`,
  )
}

// Kunci untuk semua agen sekaligus, atau null bila cache dimatikan. Dipanggil SETELAH
// pemeriksaan URL sensitif, sehingga URL yang memuat data pribadi tidak pernah di-hash
// maupun disimpan.
export function buildProviderCacheKeys(
  providerIds: ScannerProviderId[],
  normalizedUrl: string,
  config: ScannerConfig,
): Partial<Record<ScannerProviderId, string>> | null {
  if (!config.scanCache?.enabled) return null
  const keys: Partial<Record<ScannerProviderId, string>> = {}
  for (const providerId of providerIds) {
    keys[providerId] = providerCacheKey(providerId, normalizedUrl, config)
  }
  return keys
}

// Kunci dedup permintaan yang sedang berjalan. Dua permintaan dianggap setara hanya bila
// URL-nya setara setelah normalisasi DAN akan menjalankan daftar agen yang sama dengan
// tenggat yang sama; kebijakan TTL sengaja tidak ikut karena hanya memengaruhi umur
// entri cache, bukan hasil pelaksanaan.
export function scanDedupKey(input: {
  normalizedUrl: string
  adapterIds: ScannerProviderId[]
  providerTimeoutMs: number
  scanTimeoutMs: number
}): string {
  return sha256Hex(
    [
      'veriguard-inflight-v1',
      input.normalizedUrl,
      [...input.adapterIds].sort().join(','),
      input.providerTimeoutMs,
      input.scanTimeoutMs,
    ].join('|'),
  )
}

export function readProviderCache(
  providerId: ScannerProviderId,
  key: string,
  now: () => number,
): ProviderCacheHit | null {
  const entry = store.get(key)
  if (!entry) return null

  const nowMs = now()
  if (entry.providerId !== providerId || entry.expiresAtMs <= nowMs) {
    store.delete(key)
    return null
  }

  // LRU: sentuhan terbaru dipindah ke ujung sehingga eviction membuang yang paling lama
  // tidak dipakai, bukan yang paling dulu ditulis.
  store.delete(key)
  store.set(key, entry)

  return { entry, ageMs: Math.max(0, nowMs - entry.observedAtMs) }
}

export function writeProviderCache(
  providerId: ScannerProviderId,
  key: string,
  check: ProviderCheck,
  config: ScannerConfig,
  now: () => number,
): ProviderCacheEntry | null {
  if (!isCacheableStatus(check.status)) return null

  const cacheConfig = config.scanCache
  if (!cacheConfig || !cacheConfig.enabled) return null

  const nowMs = now()
  const baseTtl = POSITIVE_STATUSES.has(check.status)
    ? (cacheConfig.resultTtlMs[providerId] ?? 0)
    : cacheConfig.failureTtlMs
  if (baseTtl <= 0) return null

  let ttlMs = baseTtl

  // Rekomendasi umur dari penyedia (Google Safe Browsing `cache_duration`) memotong TTL
  // kami; kami tidak pernah lebih berani daripada yang dijanjikan penyedia.
  const suggested = check.providerCacheSeconds
  if (typeof suggested === 'number' && Number.isFinite(suggested) && suggested > 0) {
    ttlMs = Math.min(ttlMs, Math.round(suggested * 1_000))
  }

  // Batas ganda: laporan milik orang lain tidak boleh hidup di cache kami lebih lama dari
  // kebijakan umur laporan agen itu sendiri.
  if (check.evidence?.source === 'existing_report') {
    const observedMs = check.evidence.observedAt ? Date.parse(check.evidence.observedAt) : NaN
    const ceiling = maxReportAgeMs(providerId, config)
    if (Number.isFinite(observedMs) && ceiling) {
      const remaining = observedMs + ceiling - nowMs
      // Laporan yang sudah lewat batas umur agen tidak layak disimpan sama sekali:
      // menyimpannya berarti mengawetkan bukti yang tidak akan diterima adapter lagi.
      if (remaining <= 0) return null
      ttlMs = Math.min(ttlMs, remaining)
    }
  }

  if (ttlMs <= 0) return null

  const rawObservedAt =
    check.evidence?.source === 'existing_report' && check.evidence.observedAt
      ? Date.parse(check.evidence.observedAt)
      : nowMs
  const observedAtMs = Number.isFinite(rawObservedAt) ? rawObservedAt : nowMs

  const entry: ProviderCacheEntry = {
    providerId,
    check,
    observedAt: new Date(observedAtMs).toISOString(),
    observedAtMs,
    expiresAtMs: nowMs + ttlMs,
  }

  store.set(key, entry)
  evict(cacheConfig, nowMs)

  return readProviderCache(providerId, key, now)?.entry ?? null
}

function evict(cacheConfig: ScanCacheConfig, nowMs: number): void {
  if (store.size <= cacheConfig.maxEntries) return

  for (const [key, entry] of store) {
    if (entry.expiresAtMs <= nowMs) store.delete(key)
  }
  while (store.size > cacheConfig.maxEntries) {
    const oldest = store.keys().next()
    if (oldest.done) break
    store.delete(oldest.value)
  }
}

export function resetProviderCache(): void {
  store.clear()
}

export function providerCacheEntryCount(): number {
  return store.size
}

// Dipakai saat permintaan sedang berjalan (in-flight dedup) maupun saat laporan cache
// disusun: entri yang kedaluwarsa dihapus saat dibaca, tetapi pembersihan eksplisit
// menjaga ukuran tetap terikat antar permintaan.
export function pruneProviderCache(now: () => number): number {
  const nowMs = now()
  let removed = 0
  for (const [key, entry] of store) {
    if (entry.expiresAtMs <= nowMs) {
      store.delete(key)
      removed += 1
    }
  }
  return removed
}

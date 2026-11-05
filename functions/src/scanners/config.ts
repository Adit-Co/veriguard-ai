import type { ScanCacheConfig, ScannerConfig, ScannerProviderId } from './types.js'

type Env = Record<string, string | undefined>

type RuntimeWithProcess = {
  process?: {
    env?: Env
  }
}

function runtimeEnv(): Env {
  return (globalThis as RuntimeWithProcess).process?.env ?? {}
}

function readValue(env: Env, key: string): string | null {
  const value = env[key]?.trim()
  return value ? value : null
}

// Batas umur laporan yang boleh dipakai ulang. Nilai di luar rentang diabaikan agar
// kebijakan tidak dapat dilemahkan menjadi 0 jam atau tidak terbatas.
function readAgeHours(env: Env, key: string, max: number): number | undefined {
  const raw = readValue(env, key)
  if (!raw) return undefined
  const parsed = Number(raw)
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > max) return undefined
  return parsed
}

// Nilai konfigurasi cache mengikuti aturan readAgeHours: hanya bilangan bulat positif di
// dalam rentang yang diterima; apa pun yang tidak valid (0, negatif, NaN, string, melebihi
// cap) jatuh ke default aman dan TIDAK pernah melumpuhkan atau memperluas cache.
function readPositiveInt(env: Env, key: string, fallback: number, max: number): number {
  const raw = readValue(env, key)
  if (!raw) return fallback
  const parsed = Number(raw)
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > max) return fallback
  return parsed
}

function readBoolean(env: Env, key: string, fallback: boolean): boolean {
  const raw = readValue(env, key)
  if (raw === null) return fallback
  const normalized = raw.toLowerCase()
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false
  return fallback
}

const PROVIDER_TTL_ENV_PREFIX: Record<ScannerProviderId, string> = {
  urlscan: 'URLSCAN',
  virustotal: 'VIRUSTOTAL',
  openphish: 'OPENPHISH',
  threatfox: 'THREATFOX',
  radar: 'RADAR',
  otx: 'OTX',
  hybrid: 'HYBRID',
  safebrowsing: 'SAFEBROWSING',
}

// TTL default adalah kebijakan aplikasi, bukan jaminan dari penyedia: setiap nilai dipilih
// jauh di bawah umur maksimum laporan yang boleh dipakai ulang agen itu sendiri, sehingga
// cache tidak pernah lebih berani menyimpulkan kesegaran daripada adapternya.
const PROVIDER_TTL_DEFAULT_MINUTES: Record<ScannerProviderId, number> = {
  urlscan: 60,
  virustotal: 60,
  openphish: 15,
  threatfox: 15,
  radar: 60,
  otx: 60,
  hybrid: 60,
  safebrowsing: 30,
}

const MAX_RESULT_TTL_MINUTES = 720
const MAX_FAILURE_TTL_SECONDS = 300
const MAX_FEED_TTL_MINUTES = 720
const MAX_FEED_STALE_TTL_MINUTES = 4_320
const MAX_CACHE_ENTRIES = 2_000

export function readScanCacheConfig(env: Env): ScanCacheConfig {
  const resultTtlMs: Partial<Record<ScannerProviderId, number>> = {}
  for (const providerId of Object.keys(PROVIDER_TTL_ENV_PREFIX) as ScannerProviderId[]) {
    const minutes = readPositiveInt(
      env,
      `${PROVIDER_TTL_ENV_PREFIX[providerId]}_RESULT_TTL_MINUTES`,
      PROVIDER_TTL_DEFAULT_MINUTES[providerId],
      MAX_RESULT_TTL_MINUTES,
    )
    resultTtlMs[providerId] = minutes * 60_000
  }

  return {
    enabled: readBoolean(env, 'SCAN_CACHE_ENABLED', true),
    maxEntries: readPositiveInt(env, 'SCAN_CACHE_MAX_ENTRIES', 200, MAX_CACHE_ENTRIES),
    resultTtlMs,
    failureTtlMs: readPositiveInt(env, 'PROVIDER_FAILURE_TTL_SECONDS', 30, MAX_FAILURE_TTL_SECONDS) * 1_000,
    openPhishFeedTtlMs: readPositiveInt(env, 'OPENPHISH_FEED_TTL_MINUTES', 15, MAX_FEED_TTL_MINUTES) * 60_000,
    openPhishFeedStaleTtlMs:
      readPositiveInt(env, 'OPENPHISH_FEED_STALE_TTL_MINUTES', 720, MAX_FEED_STALE_TTL_MINUTES) * 60_000,
  }
}

export function readScannerConfig(env: Env = runtimeEnv()): ScannerConfig {
  return {
    urlscanApiKey: readValue(env, 'URLSCAN_API_KEY'),
    virusTotalApiKey: readValue(env, 'VIRUSTOTAL_API_KEY'),
    openPhishApiKey: readValue(env, 'OPENPHISH_API_KEY'),
    threatFoxApiKey: readValue(env, 'THREATFOX_API_KEY'),
    cloudflareApiToken: readValue(env, 'CLOUDFLARE_API_TOKEN'),
    cloudflareAccountId: readValue(env, 'CLOUDFLARE_ACCOUNT_ID'),
    otxApiKey: readValue(env, 'OTX_API_KEY'),
    hybridAnalysisApiKey: readValue(env, 'HYBRID_ANALYSIS_API_KEY'),
    googleSafeBrowsingApiKey: readValue(env, 'GOOGLE_SAFE_BROWSING_API_KEY'),
    urlscanMaxReportAgeHours: readAgeHours(env, 'URLSCAN_MAX_REPORT_AGE_HOURS', 168),
    virusTotalMaxReportAgeHours: readAgeHours(env, 'VIRUSTOTAL_MAX_REPORT_AGE_HOURS', 720),
    radarMaxReportAgeHours: readAgeHours(env, 'RADAR_MAX_REPORT_AGE_HOURS', 168),
    scanCache: readScanCacheConfig(env),
  }
}

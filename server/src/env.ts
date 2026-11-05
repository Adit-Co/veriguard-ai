import type { Env as WorkerEnv } from '../../workers/src/index.js'

export type LocalServerSettings = {
  env: WorkerEnv
  port: number
  host: string
}

const KNOWN_SERVER_KEYS = [
  'ALLOWED_ORIGINS',
  // P1-2: ID proyek Firebase (nilai publik, bukan rahasia) dibutuhkan Worker untuk
  // memverifikasi ID token. Tanpa kunci ini, backend lokal tidak pernah mengenali sesi.
  'FIREBASE_PROJECT_ID',
  // VGL-40: backend lokal harus bisa mengenali sesi dari Auth Emulator. Tanpa kunci ini,
  // nilai di server/.env tidak pernah sampai ke Worker dan setiap permintaan ber-token
  // dipatahkan sebagai "Sesi tidak dikenali".
  'FIREBASE_AUTH_EMULATOR_HOST',
  'RATE_LIMIT_MAX_PER_IP',
  'RATE_LIMIT_WINDOW_SECONDS',
  'PROVIDER_CONCURRENCY',
  'URLSCAN_API_KEY',
  'VIRUSTOTAL_API_KEY',
  'OPENPHISH_API_KEY',
  'THREATFOX_API_KEY',
  'CLOUDFLARE_API_TOKEN',
  'CLOUDFLARE_ACCOUNT_ID',
  'OTX_API_KEY',
  'GOOGLE_SAFE_BROWSING_API_KEY',
  'HYBRID_ANALYSIS_API_KEY',
  // Kebijakan umur laporan dan cache. Tanpa daftar ini, nilai di .env tidak pernah sampai
  // ke readScannerConfig saat backend lokal berjalan.
  'URLSCAN_MAX_REPORT_AGE_HOURS',
  'VIRUSTOTAL_MAX_REPORT_AGE_HOURS',
  'RADAR_MAX_REPORT_AGE_HOURS',
  'SCAN_CACHE_ENABLED',
  'SCAN_CACHE_MAX_ENTRIES',
  'PROVIDER_FAILURE_TTL_SECONDS',
  'URLSCAN_RESULT_TTL_MINUTES',
  'VIRUSTOTAL_RESULT_TTL_MINUTES',
  'OPENPHISH_RESULT_TTL_MINUTES',
  'THREATFOX_RESULT_TTL_MINUTES',
  'RADAR_RESULT_TTL_MINUTES',
  'OTX_RESULT_TTL_MINUTES',
  'HYBRID_RESULT_TTL_MINUTES',
  'SAFEBROWSING_RESULT_TTL_MINUTES',
  'OPENPHISH_FEED_TTL_MINUTES',
  'OPENPHISH_FEED_STALE_TTL_MINUTES',
  // Verifikasi Cloudflare Turnstile. Nilainya rahasia dan hanya boleh ada di sisi server;
  // tanpa pendaftaran di daftar ini, nilai di .env tidak pernah sampai ke runtime.
  'TURNSTILE_SECRET_KEY',
  'TURNSTILE_HOSTNAMES',
] as const

const SERVER_ONLY_KEYS = ['SERVER_PORT', 'SERVER_HOST'] as const

const ENV_LINE_PATTERN = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/

export function parseEnvFile(content: string): Record<string, string> {
  const values: Record<string, string> = {}

  for (const line of content.split(/\r?\n/)) {
    if (!line || line.trim().startsWith('#')) continue
    const match = line.match(ENV_LINE_PATTERN)
    if (!match) continue
    const key = match[1] ?? ''
    let value = match[2] ?? ''
    const quoted = value.match(/^(['"])(.*)\1$/)
    value = quoted ? (quoted[2] ?? '') : value
    if (key && value.length > 0) values[key] = value
  }

  return values
}

export type EnvSourceInput = {
  files: Array<Record<string, string>>
  processEnv?: Record<string, string | undefined>
}

export function buildLocalSettings(source: EnvSourceInput): LocalServerSettings {
  const merged = new Map<string, string>()

  for (const file of source.files) {
    for (const [key, value] of Object.entries(file)) {
      if (!merged.has(key)) merged.set(key, value)
    }
  }

  const processEnv = source.processEnv ?? {}
  for (const key of [...KNOWN_SERVER_KEYS, ...SERVER_ONLY_KEYS]) {
    const value = processEnv[key]
    if (typeof value === 'string' && value.trim().length > 0) merged.set(key, value)
  }

  const env: WorkerEnv = {}
  for (const key of KNOWN_SERVER_KEYS) {
    env[key] = merged.get(key)
  }

  const rawPort = Number.parseInt(merged.get('SERVER_PORT') ?? '', 10)
  const port = Number.isFinite(rawPort) && rawPort > 0 && rawPort < 65_536 ? rawPort : 8787
  const host = merged.get('SERVER_HOST')?.trim() || '127.0.0.1'

  return { env, port, host }
}

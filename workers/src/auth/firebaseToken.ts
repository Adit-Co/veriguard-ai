// P1-2: verifikasi Firebase ID token di sisi Worker tanpa SDK Admin.
//
// Token diperiksa sebagai JWT RS256 biasa: kunci diambil dari endpoint JWKS resmi penerbit
// token Firebase (ditemukan lewat .well-known/openid-configuration securetoken.google.com),
// signature diverifikasi dengan WebCrypto, lalu klaim issuer/audience/subject/exp diteliti.
// Nilai token tidak pernah disimpan, dikirim balik, atau ditulis ke log — yang tersisa hanya
// `uid` hasil verifikasi.
export const FIREBASE_TOKEN_ISSUER_PREFIX = 'https://securetoken.google.com/'

// URL tetap, tidak pernah dibentuk dari input pengguna.
export const FIREBASE_JWKS_URL =
  'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'

const JWKS_MIN_TTL_MS = 5 * 60_000
const JWKS_MAX_TTL_MS = 6 * 60 * 60_000
const JWKS_DEFAULT_TTL_MS = 60 * 60_000
// Penolakan sesaat (kid belum dikenal) tidak boleh berubah menjadi banjir permintaan ke
// Google; satu percobaan ulang per periode ini per isolate.
const JWKS_RETRY_COOLDOWN_MS = 60_000
const CLOCK_SKEW_MS = 5 * 60_000
const MAX_UID_LENGTH = 128
const MAX_TOKEN_BYTES = 4096

export type FirebaseTokenRejectReason =
  | 'project_not_configured'
  | 'malformed'
  | 'too_large'
  | 'unsupported_algorithm'
  | 'key_unavailable'
  | 'signature'  | 'payload_invalid'
  | 'issuer_mismatch'
  | 'audience_mismatch'
  | 'subject_invalid'
  | 'expired'
  | 'not_yet_valid'
  // VGL-40: jalur Emulator Auth lokal. `emulator_unavailable` = emulator tidak dapat
  // dihubungi (token tidak bisa diperiksa → sama arahnya dengan `key_unavailable`),
  // `emulator_unverified` = emulator menjawab bahwa token itu bukan sesinya.
  | 'emulator_unavailable'
  | 'emulator_unverified'

export type FirebaseIdentity =
  | {
      ok: true
      uid: string
      email: string | null
      providerId: string | null
    }
  | { ok: false; reason: FirebaseTokenRejectReason }

// Nama tipe DOM tidak selalu tersedia di tsconfig paket yang mengimpor modul ini
// (backend lokal mengompilasi sumber Worker tanpa lib DOM), jadi tipe kunci
// diturunkan dari hasil importKey itu sendiri.
type VerifyKey = Awaited<ReturnType<typeof crypto.subtle.importKey>>

type JwkRecord = {
  kid: string
  kty: string
  alg?: string
  use?: string
  n?: string
  e?: string
}

export type FirebaseTokenDeps = {
  projectId: string | undefined | null
  fetchImpl?: typeof fetch
  now?: () => number
  importJwk?: (jwk: JwkRecord) => Promise<VerifyKey>
  /**
   * VGL-40: host Auth Emulator yang dipakai backend ini, mis. `127.0.0.1:9099`. Hanya
   * loopback yang dihormati (lihat `emulatorOriginFor`); nilai lain diperlakukan sebagai
   * tidak ter-set. Tanpa nilai ini, perilaku verifikasi persis seperti sebelumnya.
   */
  emulatorHost?: string | null
}

const EMULATOR_LOOKUP_KEY = 'veriguard-lokal'
const EMULATOR_LOOKUP_TIMEOUT_MS = 5_000

/**
 * Only a loopback Auth Emulator may relax signature verification. A non-loopback value is
 * treated as "not configured" so a mistyped or hostile env value can never turn unsigned
 * tokens into credentials for a remote identity service.
 */
export function emulatorOriginFor(value: string | null | undefined): string | null {
  const raw = (value ?? '').trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '')
  if (!raw) return null
  const match = /^(?:\[([0-9a-f:.]+)\]|([A-Za-z0-9_.-]+))(?::(\d{1,5}))?$/.exec(raw)
  if (!match) return null
  const name = (match[1] ?? match[2] ?? '').toLowerCase()
  const port = match[3]
  if (port !== undefined) {
    const numeric = Number(port)
    if (!Number.isInteger(numeric) || numeric < 1 || numeric > 65_535) return null
  }
  if (name === 'localhost' || name === '::1' || /^127\./.test(name)) return `http://${raw}`
  return null
}

const MAX_CACHE_ENTRIES = 16

type KeyCache = {
  keys: Map<string, VerifyKey>
  expiresAt: number
  lastFailureAt: number
}

let keyCache: KeyCache | null = null
let inflight: Promise<KeyCache | null> | null = null
// Kapan terakhir kali cache dipaksa kedaluwarsa karena `kid` tidak dikenal. Dipakai
// resolveKey supaya janji di komentar JWKS_RETRY_COOLDOWN_MS benar-benar berlaku.
let lastForcedRefreshAt = 0

export function resetFirebaseSigningKeys(): void {
  keyCache = null
  inflight = null
  lastForcedRefreshAt = 0
}

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null
  let binary: string
  try {
    binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'))
  } catch {
    return null
  }
  const buffer = new ArrayBuffer(binary.length)
  const bytes = new Uint8Array(buffer)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes
}

function parseCacheMaxAge(value: string | null): number | null {
  if (!value) return null
  const match = /max-age=(\d+)/i.exec(value)
  if (!match) return null
  const seconds = Number.parseInt(match[1] ?? '', 10)
  if (!Number.isFinite(seconds)) return null
  return Math.min(JWKS_MAX_TTL_MS, Math.max(JWKS_MIN_TTL_MS, seconds * 1000))
}

async function defaultImportJwk(jwk: JwkRecord): Promise<VerifyKey> {
  return crypto.subtle.importKey(
    'jwk',
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: jwk.alg ?? 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  )
}

async function loadSigningKeys(deps: FirebaseTokenDeps, now: number): Promise<KeyCache | null> {
  const cached = keyCache
  if (cached && cached.expiresAt > now) return cached
  if (cached && cached.lastFailureAt + JWKS_RETRY_COOLDOWN_MS > now && cached.keys.size === 0) {
    return null
  }
  if (inflight) return inflight

  const pending = (async (): Promise<KeyCache | null> => {
    const fetchImpl = deps.fetchImpl ?? fetch
    const ttl = JWKS_DEFAULT_TTL_MS
    let cache: KeyCache = {
      keys: new Map(),
      expiresAt: now + ttl,
      lastFailureAt: cached?.lastFailureAt ?? 0,
    }
    try {
      const response = await fetchImpl(FIREBASE_JWKS_URL, {
        method: 'GET',
        headers: { accept: 'application/json' },
        credentials: 'omit',
      })
      if (!response.ok) {
        // Pertahankan kunci lama lebih lama sedikit supaya gangguan sesaat tidak langsung
        // menolak pengguna yang sudah masuk.
        cache = {
          keys: cached?.keys ?? new Map(),
          expiresAt: cached ? cached.expiresAt + JWKS_MIN_TTL_MS : now + JWKS_MIN_TTL_MS,
          lastFailureAt: now,
        }
        keyCache = cache
        return cache.keys.size > 0 ? cache : null
      }

      const payload = (await response.json()) as { keys?: unknown }
      const records = Array.isArray(payload.keys) ? payload.keys : []
      const importJwk = deps.importJwk ?? defaultImportJwk
      const keys = new Map<string, VerifyKey>()
      for (const record of records.slice(0, MAX_CACHE_ENTRIES)) {
        if (!record || typeof record !== 'object') continue
        const candidate = record as JwkRecord
        if (candidate.kty !== 'RSA') continue
        if (candidate.use && candidate.use !== 'sig') continue
        if (candidate.alg && candidate.alg !== 'RS256') continue
        if (typeof candidate.kid !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(candidate.kid)) {
          continue
        }
        if (typeof candidate.n !== 'string' || typeof candidate.e !== 'string') continue
        try {
          keys.set(candidate.kid, await importJwk(candidate))
        } catch {
          // Satu kunci rusak tidak boleh membatalkan seluruh daftar.
        }
      }
      if (keys.size === 0) {
        cache = {
          keys: cached?.keys ?? new Map(),
          expiresAt: cached ? cached.expiresAt + JWKS_MIN_TTL_MS : now + JWKS_MIN_TTL_MS,
          lastFailureAt: now,
        }
        keyCache = cache
        return cache.keys.size > 0 ? cache : null
      }
      const ttlMs = parseCacheMaxAge(response.headers.get('cache-control')) ?? ttl
      cache = {
        keys,
        expiresAt: now + ttlMs,
        lastFailureAt: 0,
      }
      keyCache = cache
      return cache
    } catch {
      cache = {
        keys: cached?.keys ?? new Map(),
        expiresAt: cached ? cached.expiresAt + JWKS_MIN_TTL_MS : now + JWKS_MIN_TTL_MS,
        lastFailureAt: now,
      }
      keyCache = cache
      return cache.keys.size > 0 ? cache : null
    } finally {
      inflight = null
    }
  })()

  inflight = pending
  return pending
}

/**
 * Cari kunci sesuai `kid` pada header token. Kunci yang tidak ada di cache memaksa satu
 * penyegaran (Google berganti kunci berkala); hasilnya tetap `key_unavailable` bila kunci
 * benar-benar tidak dikenal, sehingga token tidak pernah diterima tanpa verifikasi.
 *
 * Penyegaran paksa dibatasi satu kali per JWKS_RETRY_COOLDOWN_MS per isolate. Tanpa batas
 * ini, setiap token berisi `kid` acak — input yang sepenuhnya dikendalikan pengirim —
 * memaksa satu permintaan keluar ke Google, dan penolakan yang seharusnya murah berubah
 * menjadi amplifier permintaan. Permintaan berikutnya dalam cooldown dijawab dengan
 * penolakan yang sama (`key_unavailable`), tanpa I/O.
 */
async function resolveKey(
  kid: string,
  deps: FirebaseTokenDeps,
  now: number,
): Promise<VerifyKey | null> {
  const cache = await loadSigningKeys(deps, now)
  const direct = cache?.keys.get(kid) ?? null
  if (direct) return direct

  if (now - lastForcedRefreshAt < JWKS_RETRY_COOLDOWN_MS) return null
  lastForcedRefreshAt = now

  keyCache = cache ? { ...cache, expiresAt: 0, lastFailureAt: now } : null
  const refreshed = await loadSigningKeys(deps, now)
  return refreshed?.keys.get(kid) ?? null
}

function readNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

type IdentityClaims = { uid: string; email: string | null; providerId: string | null }

/**
 * Pemeriksaan klaim yang sama persis untuk kedua jalur (JWKS produksi maupun Emulator Auth).
 * Dipisah supaya jalur emulator tidak pernah memangkas validasi issuer/audience/subject/waktu
 * hanya karena tanda tangannya tidak ada.
 */
function readIdentityClaims(
  payload: Record<string, unknown>,
  projectId: string,
  now: number,
): { ok: true; identity: IdentityClaims } | { ok: false; reason: FirebaseTokenRejectReason } {
  if (!payload || Array.isArray(payload)) return { ok: false, reason: 'payload_invalid' }

  if (payload.iss !== `${FIREBASE_TOKEN_ISSUER_PREFIX}${projectId}`) {
    return { ok: false, reason: 'issuer_mismatch' }
  }
  const audience = payload.aud
  const audienceOk =
    audience === projectId || (Array.isArray(audience) && audience.includes(projectId))
  if (!audienceOk) return { ok: false, reason: 'audience_mismatch' }

  const uid = typeof payload.sub === 'string' ? payload.sub : ''
  if (
    uid.length === 0 ||
    uid.length > MAX_UID_LENGTH ||
    !/^[a-zA-Z0-9_-]+$/.test(uid)
  ) {
    return { ok: false, reason: 'subject_invalid' }
  }

  const expiresAt = readNumber(payload.exp)
  const issuedAt = readNumber(payload.iat)
  const notBefore = readNumber(payload.nbf)
  if (expiresAt === null) return { ok: false, reason: 'payload_invalid' }
  if (expiresAt * 1000 <= now - CLOCK_SKEW_MS) return { ok: false, reason: 'expired' }
  if (notBefore !== null && notBefore * 1000 > now + CLOCK_SKEW_MS) {
    return { ok: false, reason: 'not_yet_valid' }
  }
  if (issuedAt !== null && issuedAt * 1000 > now + CLOCK_SKEW_MS) {
    return { ok: false, reason: 'not_yet_valid' }
  }

  const firebase = payload.firebase
  const providerId =
    firebase && typeof firebase === 'object' && !Array.isArray(firebase)
      ? (firebase as Record<string, unknown>).sign_in_provider
      : undefined

  return {
    ok: true,
    identity: {
      uid,
      email: typeof payload.email === 'string' ? payload.email : null,
      providerId: typeof providerId === 'string' ? providerId : null,
    },
  }
}

/**
 * VGL-40 — jalur Emulator Auth lokal.
 *
 * Emulator Auth menerbitkan ID token tanpa tanda tangan (`alg: "none"`), sehingga verifikasi
 * JWKS produksi selalu menolaknya dan backend lokal menganggap sesi yang sah sebagai "tidak
 * dikenali". Ini bukan pengecualian tanpa pemeriksaan: klaimnya diuji penuh seperti token
 * produksi, lalu keabsahannya dibaca ULANG dari sumber identitasnya sendiri lewat
 * `accounts:lookup`, dan `sub` harus sama dengan `localId` yang diakui emulator. UID tidak
 * pernah diterima hanya karena frontend mengirimnya.
 */
async function verifyViaEmulator(
  token: string,
  payload: Record<string, unknown>,
  deps: FirebaseTokenDeps,
  projectId: string,
  now: number,
  origin: string,
): Promise<FirebaseIdentity> {
  const claims = readIdentityClaims(payload, projectId, now)
  if (!claims.ok) return claims

  const fetchImpl = deps.fetchImpl ?? fetch
  let response: Response
  try {
    response = await fetchImpl(
      `${origin}/identitytoolkit.googleapis.com/v1/accounts:lookup?key=${EMULATOR_LOOKUP_KEY}`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ id_token: token }),
        credentials: 'omit',
        signal: AbortSignal.timeout(EMULATOR_LOOKUP_TIMEOUT_MS),
      },
    )
  } catch {
    return { ok: false, reason: 'emulator_unavailable' }
  }

  if (!response.ok) return { ok: false, reason: 'emulator_unverified' }

  let looked: unknown
  try {
    looked = await response.json()
  } catch {
    return { ok: false, reason: 'emulator_unverified' }
  }
  const users = (looked as { users?: unknown })?.users
  const first = Array.isArray(users) ? users[0] : undefined
  const localId = (first as { localId?: unknown } | undefined)?.localId

  if (typeof localId !== 'string' || localId !== claims.identity.uid) {
    return { ok: false, reason: 'emulator_unverified' }
  }

  return { ok: true, ...claims.identity }
}

export async function verifyFirebaseIdToken(
  rawToken: unknown,
  deps: FirebaseTokenDeps,
): Promise<FirebaseIdentity> {
  const projectId = typeof deps.projectId === 'string' ? deps.projectId.trim() : ''
  if (!projectId) return { ok: false, reason: 'project_not_configured' }

  const now = deps.now?.() ?? Date.now()

  if (typeof rawToken !== 'string') return { ok: false, reason: 'malformed' }
  const token = rawToken.trim()
  if (!token) return { ok: false, reason: 'malformed' }
  if (token.length > MAX_TOKEN_BYTES) return { ok: false, reason: 'too_large' }

  const segments = token.split('.')
  if (segments.length !== 3) return { ok: false, reason: 'malformed' }
  const [encodedHeader, encodedPayload, encodedSignature] = segments as [string, string, string]

  let header: Record<string, unknown>
  try {
    const headerBytes = base64UrlToBytes(encodedHeader)
    if (!headerBytes) return { ok: false, reason: 'malformed' }
    header = JSON.parse(new TextDecoder().decode(headerBytes)) as Record<string, unknown>
  } catch {
    return { ok: false, reason: 'malformed' }
  }
  const payloadBytes = base64UrlToBytes(encodedPayload)
  if (!payloadBytes) return { ok: false, reason: 'malformed' }

  const emulatorOrigin = emulatorOriginFor(deps.emulatorHost)

  if (header.alg !== 'RS256') {
    // VGL-40: Emulator Auth lokal menerbitkan token tanpa tanda tangan. Bentuk itu tetap
    // ditolak bila backend tidak menunjuk emulator loopback secara eksplisit; bila menunjuk,
    // token tidak dipercaya begitu saja — klaimnya diuji penuh lalu dikonfirmasi ke emulator.
    if (emulatorOrigin && header.alg === 'none' && header.typ === 'JWT') {
      let unsignedPayload: Record<string, unknown>
      try {
        unsignedPayload = JSON.parse(new TextDecoder().decode(payloadBytes)) as Record<
          string,
          unknown
        >
      } catch {
        return { ok: false, reason: 'payload_invalid' }
      }
      return verifyViaEmulator(token, unsignedPayload, deps, projectId, now, emulatorOrigin)
    }
    return { ok: false, reason: 'unsupported_algorithm' }
  }

  if (typeof header.kid !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(header.kid)) {
    return { ok: false, reason: 'malformed' }
  }

  const signature = base64UrlToBytes(encodedSignature)
  if (!signature) return { ok: false, reason: 'malformed' }

  const key = await resolveKey(header.kid, deps, now)
  if (!key) return { ok: false, reason: 'key_unavailable' }

  const signingInput = `${encodedHeader}.${encodedPayload}`
  let verified = false
  try {
    verified = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      signature,
      new TextEncoder().encode(signingInput),
    )
  } catch {
    return { ok: false, reason: 'signature' }
  }
  if (!verified) return { ok: false, reason: 'signature' }

  let payload: Record<string, unknown>
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes)) as Record<string, unknown>
  } catch {
    return { ok: false, reason: 'payload_invalid' }
  }

  const claims = readIdentityClaims(payload, projectId, now)
  if (!claims.ok) return claims

  return { ok: true, ...claims.identity }
}

/**
 * Ambil bearer token dari header `Authorization`. Hanya format `Bearer <token>` yang dibaca;
 * nilai lain diabaikan supaya klien lama (tanpa token) tetap diperlakukan sebagai tamu dan
 * tidak pernah memicu 401.
 */
export function readBearerToken(value: string | null | undefined): string | null {
  if (!value) return null
  const trimmed = value.trim()
  if (!/^Bearer\s+\S/i.test(trimmed)) return null
  const token = trimmed.slice(trimmed.indexOf(' ') + 1).trim()
  return token ? token : null
}

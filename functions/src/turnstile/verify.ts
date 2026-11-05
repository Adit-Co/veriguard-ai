import { sha256Hex } from '../scanners/hash.js'
import { STATE_MAX_KEYS } from '../state/stores.js'

export const TURNSTILE_SITEVERIFY_URL =
  'https://challenges.cloudflare.com/turnstile/v0/siteverify'

// Aksi dipasang pada widget dan dibandingkan dengan nilai yang diharapkan server.
// Tanpa pemisahan ini, token yang diselesaikan untuk satu alur bisa dipakai pada alur lain.
export const TURNSTILE_ACTION = {
  register: 'register',
  scan: 'scan',
} as const

export type TurnstileAction = (typeof TURNSTILE_ACTION)[keyof typeof TURNSTILE_ACTION]

const DEFAULT_TIMEOUT_MS = 5_000
// P1-3: konstanta tabel dipakai bersama dengan state lain (retensi juga dikirim ke Durable
// Object lewat RPC), jadi nilainya hidup di satu tempat.
export const TURNSTILE_TOKEN_RETENTION_MS = 10 * 60_000
const REGISTRY_MAX_ENTRIES = STATE_MAX_KEYS

export type TurnstileRejectReason =
  | 'not_configured'
  | 'missing_token'
  | 'invalid_token'
  | 'expired_or_reused'
  | 'hostname_mismatch'
  | 'action_mismatch'
  | 'transport_failure'
  | 'malformed_response'
  | 'registry_full'

export type TurnstileVerification = { ok: true } | { ok: false; reason: TurnstileRejectReason }

export type TurnstileVerifyInput = {
  secretKey: string | undefined | null
  token: unknown
  allowedHostnames?: readonly string[] | null
  expectedAction?: string | null
  remoteIp?: string | null
  fetchImpl?: typeof fetch
  signal?: AbortSignal | null
  now?: () => number
  timeoutMs?: number
  // P1-3: tempat menyimpan reservasi token. Defaultnya memori isolate; Worker menunjuk Durable
  // Object agar token yang sama tidak dapat ditukar dua kali dari dua isolate berbeda.
  tokenRegistry?: TurnstileTokenRegistry | null
}

// Token tidak pernah disimpan sebagai teks: hanya sidik jarinya yang ditahan supaya satu
// token tidak dapat dipakai dua kali pada layanan ini. Sidik jari bukan kredensial, hanya
// kunci tabel, karena token asli tidak boleh tinggal di memori proses.
//
// P1-3: reservasi dibuat melalui objek registry sehingga pemanggil boleh menunjuk penyimpanan
// bersama (Durable Object di Worker) alih-alih memori isolate. Defaultnya tetap memori, jadi
// Cloud Functions dan host Node tidak berubah perilaku.
export type TurnstileTokenReservation = 'reserved' | 'reused' | 'full'

// Versi sinkron dipakai penyimpanan memori; versi asinkron dipakai penyimpanan bersama (DO).
// Keduanya memenuhi TurnstileTokenRegistry, jadi verifier hanya perlu awaitsatu kali.
export type SyncTurnstileTokenRegistry = {
  reserve(fingerprint: string, now: number): TurnstileTokenReservation
  release(fingerprint: string): void
}

export type TurnstileTokenRegistry = {
  reserve(fingerprint: string, now: number): TurnstileTokenReservation | Promise<TurnstileTokenReservation>
  release(fingerprint: string): void | Promise<void>
}

export function createMemoryTurnstileTokenRegistry(
  retentionMs: number = TURNSTILE_TOKEN_RETENTION_MS,
  maxEntries: number = REGISTRY_MAX_ENTRIES,
): SyncTurnstileTokenRegistry {
  const consumed = new Map<string, number>()

  const cleanup = (now: number): void => {
    if (consumed.size < maxEntries) return
    for (const [fingerprint, expiresAt] of consumed) {
      if (expiresAt <= now) consumed.delete(fingerprint)
    }
  }

  return {
    reserve(fingerprint, now) {
      cleanup(now)
      const existing = consumed.get(fingerprint)
      if (existing !== undefined) {
        if (existing > now) return 'reused'
        consumed.delete(fingerprint)
      }
      // Tabel penuh: kunci baru ditolak daripada menghapus entri yang masih hidup, sama seperti
      // kebijakan pembatas lain di proyek ini.
      if (consumed.size >= maxEntries) return 'full'
      consumed.set(fingerprint, now + retentionMs)
      return 'reserved'
    },
    release(fingerprint) {
      consumed.delete(fingerprint)
    },
  }
}

let defaultTokenRegistry = createMemoryTurnstileTokenRegistry()

export function resetTurnstileTokenRegistry(): void {
  // Instance baru = tabel kosong. verifier membaca variabel ini saat dipanggil, jadi reset
  // antar kasus uji tetap berfungsi tanpa metode reset khusus di registry.
  defaultTokenRegistry = createMemoryTurnstileTokenRegistry()
}

export function turnstileTokenFingerprint(token: string): string {
  return sha256Hex(`turnstile:${token}`)
}

function normalizeHostname(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim().toLowerCase()
  return trimmed ? trimmed : null
}

/**
 * VGM-06: aplikasi ini disajikan dari beberapa hostname Firebase Hosting (`*.web.app` dan
 * `*.firebaseapp.com`), sehingga satu nilai `TURNSTILE_HOSTNAME` selalu membuat salah satu
 * hostname ditolak dengan `hostname_mismatch`. Daftarnya dipisah koma dan pencocokan bersifat
 * eksak per entri (bukan akhiran/subdomain) agar token dari situs lain tetap tertolak.
 */
export function parseTurnstileHostnameAllowlist(
  value: string | readonly (string | null | undefined)[] | null | undefined,
): string[] {
  let entries: Iterable<string | null | undefined> = []
  if (typeof value === 'string') entries = value.split(',')
  else if (value) entries = value

  const seen = new Set<string>()
  for (const entry of entries) {
    const hostname = normalizeHostname(entry)
    if (hostname) seen.add(hostname)
  }
  return [...seen]
}

type SiteverifyResult =
  | { ok: false; reason: TurnstileRejectReason }
  | { ok: true; hostname: string | null; action: string | null }

async function requestSiteVerify(
  input: TurnstileVerifyInput,
  secret: string,
  token: string,
): Promise<SiteverifyResult> {
  const controller = new AbortController()
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  const abortFromCaller = () => controller.abort()
  input.signal?.addEventListener('abort', abortFromCaller, { once: true })

  try {
    const form = new URLSearchParams({ secret, response: token })
    const remoteIp = input.remoteIp?.trim()
    if (remoteIp) form.set('remoteip', remoteIp)

    const fetchImpl = input.fetchImpl ?? fetch
    let response: Response
    try {
      response = await fetchImpl(TURNSTILE_SITEVERIFY_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: form.toString(),
        credentials: 'omit',
        signal: controller.signal,
      })
    } catch {
      // Kegagalan jaringan, token kedaluwarsa di sisi Cloudflare, maupun batas waktu
      // diperlakukan sama: verifikasi tidak dianggap berhasil.
      return { ok: false, reason: 'transport_failure' }
    }

    let payload: unknown
    try {
      payload = await response.json()
    } catch {
      return { ok: false, reason: 'malformed_response' }
    }

    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return { ok: false, reason: 'malformed_response' }
    }

    const record = payload as Record<string, unknown>
    if (record.success !== true) {
      const codes = Array.isArray(record['error-codes']) ? record['error-codes'] : []
      const expiredOrUsed = codes.some(
        (code) => typeof code === 'string' && code === 'timeout-or-already-used',
      )
      return { ok: false, reason: expiredOrUsed ? 'expired_or_reused' : 'invalid_token' }
    }

    return {
      ok: true,
      hostname: normalizeHostname(record.hostname),
      action: typeof record.action === 'string' ? record.action.trim() : null,
    }
  } finally {
    clearTimeout(timer)
    input.signal?.removeEventListener('abort', abortFromCaller)
  }
}

export async function verifyTurnstileToken(
  input: TurnstileVerifyInput,
): Promise<TurnstileVerification> {
  const now = input.now?.() ?? Date.now()
  const secret = typeof input.secretKey === 'string' ? input.secretKey.trim() : ''
  if (!secret) return { ok: false, reason: 'not_configured' }

  const token = typeof input.token === 'string' ? input.token.trim() : ''
  if (!token) return { ok: false, reason: 'missing_token' }

  const registry = input.tokenRegistry ?? defaultTokenRegistry
  const fingerprint = turnstileTokenFingerprint(token)
  const reservation = await registry.reserve(fingerprint, now)
  if (reservation === 'reused') return { ok: false, reason: 'expired_or_reused' }
  if (reservation === 'full') return { ok: false, reason: 'registry_full' }

  const outcome = await requestSiteVerify(input, secret, token)
  if (!outcome.ok) {
    // Token dibebaskan lagi bila Cloudflare tidak pernah memprosesnya (mis. jaringan gagal),
    // supaya pengguna tidak dipaksa menyelesaikan CAPTCHA baru untuk permintaan yang sama.
    await registry.release(fingerprint)
    return { ok: false, reason: outcome.reason }
  }

  const allowlist = parseTurnstileHostnameAllowlist(input.allowedHostnames)
  if (allowlist.length > 0 && (outcome.hostname === null || !allowlist.includes(outcome.hostname))) {
    return { ok: false, reason: 'hostname_mismatch' }
  }

  const expectedAction = input.expectedAction?.trim()
  if (expectedAction && outcome.action !== expectedAction) {
    return { ok: false, reason: 'action_mismatch' }
  }

  return { ok: true }
}

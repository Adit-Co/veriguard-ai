import { readScannerConfig } from '../../functions/src/scanners/config.js'
import { SCAN_RATE_LIMIT } from '../../functions/src/scanners/rateLimit.js'
import { runMultiSourceScan, ScanUrlError } from '../../functions/src/scanners/service.js'
import type {
  RunMultiSourceScanInput,
  ScanQuotaConsumer,
} from '../../functions/src/scanners/service.js'
import type {
  MultiSourceScanResponse,
  ScanProgressEvent,
} from '../../functions/src/scanners/types.js'
import { normalizeScanUrl } from '../../functions/src/scanners/url.js'
import { runSiteAnalysis } from '../../functions/src/website/service.js'
import {
  TURNSTILE_ACTION,
  parseTurnstileHostnameAllowlist,
  verifyTurnstileToken,
} from '../../functions/src/turnstile/verify.js'
import type {
  TurnstileAction,
  TurnstileVerification,
} from '../../functions/src/turnstile/verify.js'
import {
  requiresTurnstileScanVerification,
  turnstileScanClearanceKey,
} from '../../functions/src/turnstile/scanGate.js'
import type { SiteProbe } from '../../functions/src/website/types.js'
import { MAX_BODY_BYTES } from './limits.js'
import { createWorkerSiteProbe } from './siteProbe.js'
import { readBearerToken, verifyFirebaseIdToken } from './auth/firebaseToken.js'
import type { FirebaseIdentity } from './auth/firebaseToken.js'
import { createMemoryStateStore, resolveWorkerState } from './state/store.js'
import type { ScanStateNamespace, ScanStateStore, WorkerState } from './state/store.js'

export { ScanStateDurableObject } from './state/scanState.js'

const DEFAULT_IP_LIMIT = 30
const DEFAULT_WINDOW_SECONDS = 60
const DEFAULT_PROVIDER_CONCURRENCY = 4
const SSE_HEARTBEAT_MS = 10_000
const SCAN_ID_PATTERN = /^[a-zA-Z0-9_-]{8,128}$/
const ALLOWED_PATHS = new Set([
  '/',
  '/scan',
  '/scan/stream',
  '/scanUrlMultiSource',
  '/site/analysis',
  '/auth/turnstile/verify',
])
// Jalur yang menjalankan pemeriksaan reputasi. Gerbang CAPTCHA adaptif hanya berlaku di sini;
// analisis situs memakai batasannya sendiri dan tidak ditantang.
const SCAN_PATHS = new Set(['/', '/scan', '/scan/stream', '/scanUrlMultiSource'])

export interface Env {
  ALLOWED_ORIGINS?: string
  RATE_LIMIT_MAX_PER_IP?: string
  RATE_LIMIT_WINDOW_SECONDS?: string
  PROVIDER_CONCURRENCY?: string
  URLSCAN_API_KEY?: string
  VIRUSTOTAL_API_KEY?: string
  OPENPHISH_API_KEY?: string
  THREATFOX_API_KEY?: string
  CLOUDFLARE_API_TOKEN?: string
  CLOUDFLARE_ACCOUNT_ID?: string
  OTX_API_KEY?: string
  GOOGLE_SAFE_BROWSING_API_KEY?: string
  HYBRID_ANALYSIS_API_KEY?: string
  // Kebijakan umur laporan + cache hasil. Semua berupa angka (jam/menit/detik) dan dibaca
  // oleh readScannerConfig. Tidak ada nilai rahasia di dalamnya.
  URLSCAN_MAX_REPORT_AGE_HOURS?: string
  VIRUSTOTAL_MAX_REPORT_AGE_HOURS?: string
  RADAR_MAX_REPORT_AGE_HOURS?: string
  SCAN_CACHE_ENABLED?: string
  SCAN_CACHE_MAX_ENTRIES?: string
  PROVIDER_FAILURE_TTL_SECONDS?: string
  URLSCAN_RESULT_TTL_MINUTES?: string
  VIRUSTOTAL_RESULT_TTL_MINUTES?: string
  OPENPHISH_RESULT_TTL_MINUTES?: string
  THREATFOX_RESULT_TTL_MINUTES?: string
  RADAR_RESULT_TTL_MINUTES?: string
  OTX_RESULT_TTL_MINUTES?: string
  HYBRID_RESULT_TTL_MINUTES?: string
  SAFEBROWSING_RESULT_TTL_MINUTES?: string
  OPENPHISH_FEED_TTL_MINUTES?: string
  OPENPHISH_FEED_STALE_TTL_MINUTES?: string
  // Rahasia Cloudflare Turnstile. Hanya dibaca server untuk siteverify dan tidak pernah
  // dikirim ke browser.
  TURNSTILE_SECRET_KEY?: string
  // Opsional. Bila diisi (daftar terpisah koma), hostname yang dilaporkan Cloudflare harus
  // ada di daftar. Firebase Hosting menyajikan aplikasi dari lebih dari satu hostname, jadi
  // satu nilai saja selalu menolak sebagian pengguna.
  TURNSTILE_HOSTNAMES?: string
  // P1-2: ID proyek Firebase tempat ID token diterbitkan. Nilai ini bukan rahasia dan sudah
  // ada di publik (bundle frontend). Tanpa ID proyek, token tidak dapat diperiksa dan setiap
  // permintaan diperlakukan sebagai tamu.
  FIREBASE_PROJECT_ID?: string
  // VGL-40: host Auth Emulator yang dipakai backend LOKAL ini (mis. 127.0.0.1:9099). Tanpa
  // nilai ini, token emulator (alg "none") tetap ditolak seperti sebelumnya. Tidak pernah
  // diisi pada deployment produksi: hanya loopback yang dihormati, dan Worker produksi tidak
  // membaca variabel ini dari konfigurasi apa pun yang saya ubah di task ini.
  FIREBASE_AUTH_EMULATOR_HOST?: string
  // P1-3: binding Durable Object tempat batas laju, izin CAPTCHA, dan anti-replay token
  // disimpan bersama antar isolate. Bila binding tidak ada (misalnya host Node lokal atau
  // konfigurasi lama), seluruh state kembali ke memori isolate seperti sebelumnya.
  SCAN_STATE?: ScanStateNamespace
}

type RunScan = (input: RunMultiSourceScanInput) => Promise<MultiSourceScanResponse>

type WorkerDependencies = {
  runScan: RunScan
  // P1-3: satu objek state bersama menggantikan dua fungsi batas laju yang sebelumnya
  // tersebar. Implementasi default adalah memori isolate; binding SCAN_STATE menggantikan
  // isinya dengan Durable Object tanpa mengubah jalur pemanggilan.
  state: ScanStateStore
  now: () => number
  siteProbe: SiteProbe | null
  verifyTurnstile: typeof verifyTurnstileToken
  verifyFirebaseToken: typeof verifyFirebaseIdToken
}

class BodyTooLargeError extends Error {}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function parseAllowedOrigins(value: string | undefined): Set<string> {
  return new Set(
    (value ?? '')
      .split(',')
      .map((origin) => origin.trim())
      .filter(Boolean),
  )
}

function applyCors(headers: Headers, origin: string | null, env: Env): boolean {
  if (!origin) return true

  const allowed = parseAllowedOrigins(env.ALLOWED_ORIGINS).has(origin)
  if (!allowed) return false

  headers.set('Access-Control-Allow-Origin', origin)
  headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS')
  headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, Accept')
  headers.set('Access-Control-Max-Age', '600')
  headers.set('Vary', 'Origin')
  return true
}

function baseHeaders(): Headers {
  const headers = new Headers()
  headers.set('Cache-Control', 'no-store')
  headers.set('X-Content-Type-Options', 'nosniff')
  headers.set('Referrer-Policy', 'no-referrer')
  return headers
}

function jsonResponse(
  status: number,
  body: unknown,
  headers: Headers,
): Response {
  headers.set('Content-Type', 'application/json; charset=utf-8')
  return new Response(JSON.stringify(body), { status, headers })
}

function errorResponse(
  status: number,
  code: string,
  message: string,
  headers: Headers,
): Response {
  return jsonResponse(status, { error: { code, message } }, headers)
}

function readInteger(
  value: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const parsed = Number.parseInt(value ?? '', 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(maximum, Math.max(minimum, parsed))
}

async function readLimitedText(request: Request): Promise<string> {
  const contentLength = Number.parseInt(request.headers.get('content-length') ?? '', 10)
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    throw new BodyTooLargeError()
  }

  if (!request.body) return ''

  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0

  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > MAX_BODY_BYTES) {
      await reader.cancel()
      throw new BodyTooLargeError()
    }
    chunks.push(value)
  }

  if (chunks.length === 0) return ''

  const body = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.byteLength
  }

  return new TextDecoder().decode(body)
}

function isJsonContentType(request: Request): boolean {
  const contentType = request.headers.get('content-type')
  return contentType?.split(';', 1)[0]?.trim().toLowerCase() === 'application/json'
}

function readScanId(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const scanId = value.trim()
  return SCAN_ID_PATTERN.test(scanId) ? scanId : null
}

function turnstileSecretKey(env: Env): string {
  return env.TURNSTILE_SECRET_KEY?.trim() ?? ''
}

function readCaptchaToken(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

// Satu-satunya tempat kunci rahasia dibaca: nilai secret diteruskan ke pengverifikasi
// server-side dan tidak pernah masuk respons, header, maupun alur browser.
async function verifyTurnstile(
  dependencies: WorkerDependencies,
  env: Env,
  request: Request,
  ip: string,
  action: TurnstileAction,
  token: unknown,
  workerState: WorkerState,
): Promise<TurnstileVerification> {
  return dependencies.verifyTurnstile({
    secretKey: env.TURNSTILE_SECRET_KEY,
    token,
    allowedHostnames: parseTurnstileHostnameAllowlist(env.TURNSTILE_HOSTNAMES),
    expectedAction: action,
    remoteIp: ip === 'unknown' ? null : ip,
    signal: request.signal,
    now: dependencies.now,
    // P1-3: reservasi anti-replay ikut diambil dari state bersama. Tanpa binding DO,
    // workerState.tokenRegistry tidak terisi dan verifier memakai memori isolate seperti
    // sebelumnya.
    ...(workerState.tokenRegistry ? { tokenRegistry: workerState.tokenRegistry } : {}),
  })
}

type ScanStreamErrorEvent = {
  type: 'error'
  scanId: string
  code: string
  message: string
}

function encodeSseEvent(event: ScanProgressEvent | ScanStreamErrorEvent): string {
  return `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`
}

function createSseResponse(
  headers: Headers,
  request: Request,
  scanId: string,
  runScan: (
    onEvent: (event: ScanProgressEvent) => void | Promise<void>,
  ) => Promise<MultiSourceScanResponse>,
): Response {
  const encoder = new TextEncoder()
  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>()
  const writer = writable.getWriter()
  let closed = false
  let doneSent = false

  const write = async (chunk: string): Promise<void> => {
    if (closed) return
    try {
      await writer.write(encoder.encode(chunk))
    } catch {
      closed = true
    }
  }
  const writeEvent = async (
    event: ScanProgressEvent | ScanStreamErrorEvent,
  ): Promise<void> => {
    if (event.type === 'done') doneSent = true
    await write(encodeSseEvent(event))
  }
  const heartbeat = setInterval(() => {
    void write(': keepalive\n\n')
  }, SSE_HEARTBEAT_MS)
  const onAbort = () => {
    closed = true
    void writer.abort().catch(() => undefined)
  }
  request.signal.addEventListener('abort', onAbort, { once: true })

  void (async () => {
    try {
      if (request.signal.aborted) return
      const response = await runScan(writeEvent)
      if (!doneSent && !closed) {
        await writeEvent({ type: 'done', scanId, response })
      }
    } catch (error) {
      if (!closed) {
        await writeEvent({
          type: 'error',
          scanId,
          code: error instanceof ScanUrlError ? 'invalid_url' : 'internal',
          message:
            error instanceof ScanUrlError
              ? error.message
              : 'Pemeriksaan reputasi gagal diproses.',
        })
      }
    } finally {
      clearInterval(heartbeat)
      request.signal.removeEventListener('abort', onAbort)
      if (!closed) {
        closed = true
        await writer.close().catch(() => undefined)
      }
    }
  })()

  headers.set('Content-Type', 'text/event-stream; charset=utf-8')
  headers.set('Cache-Control', 'no-cache, no-store, no-transform')
  headers.set('X-Accel-Buffering', 'no')
  return new Response(readable, { status: 200, headers })
}

type CallerIdentity = { uid: string; authenticated: boolean }

function siteRateLimitKey(uid: string): string {
  return `site:${uid}`
}

/**
 * Kunci kuota pemeriksaan, dipisah dari kunci batas laju HTTP per-permintaan (`ip:` dan uid
 * polos) supaya satu akun tidak menghabiskan salah satu jendela lewat jalur lain.
 */
function scanQuotaKey(uid: string): string {
  return `scan:${uid}`
}

function guestIdentity(ip: string): CallerIdentity {
  return { uid: `guest:${ip}`, authenticated: false }
}

/**
 * P1-2: pemeriksaan reputasi tetap terbuka untuk tamu (tidak ada login wall), tetapi identitas
 * hanya diterima setelah signature RS256 dan klaim issuer/audience/subject cocok dengan proyek
 * ini. Arah gagalnya dibedakan:
 *  - token jelas tidak sah (tanda tangan/issuer/audience/subject/kedaluwarsa) → 401, supaya
 *    klien tidak diam-diam kehilangan identitas yang dikiranya dipakai;
 *  - token tidak dapat diperiksa (deployment tanpa FIREBASE_PROJECT_ID, atau kunci Google sedang
 *    tidak terambil) → lanjut sebagai TAMU. Tidak ada jalur yang memberi hak lebih tinggi dari
 *    tamu tanpa verifikasi, dan nilai token tidak pernah masuk log maupun respons.
 */
async function resolveIdentity(
  request: Request,
  env: Env,
  dependencies: WorkerDependencies,
  ip: string,
): Promise<{ ok: true; identity: CallerIdentity } | { ok: false; message: string }> {
  const token = readBearerToken(request.headers.get('authorization'))
  if (!token) return { ok: true, identity: guestIdentity(ip) }

  const projectId = env.FIREBASE_PROJECT_ID?.trim()
  if (!projectId) return { ok: true, identity: guestIdentity(ip) }

  const verified: FirebaseIdentity = await dependencies.verifyFirebaseToken(token, {
    projectId,
    now: dependencies.now,
    emulatorHost: env.FIREBASE_AUTH_EMULATOR_HOST,
  })

  if (verified.ok) {
    return { ok: true, identity: { uid: `uid:${verified.uid}`, authenticated: true } }
  }
  if (
    verified.reason === 'key_unavailable' ||
    verified.reason === 'project_not_configured' ||
    verified.reason === 'emulator_unavailable'
  ) {
    return { ok: true, identity: guestIdentity(ip) }
  }
  return {
    ok: false,
    message: 'Sesi tidak dikenali oleh layanan pemeriksaan. Masuk ulang lalu coba lagi.',
  }
}

async function handleRequest(
  request: Request,
  env: Env,
  dependencies: WorkerDependencies,
): Promise<Response> {
  const origin = request.headers.get('origin')
  const headers = baseHeaders()

  if (!applyCors(headers, origin, env)) {
    return errorResponse(403, 'origin_not_allowed', 'Origin tidak diizinkan.', headers)
  }

  const { pathname } = new URL(request.url)
  if (!ALLOWED_PATHS.has(pathname)) {
    return errorResponse(404, 'not_found', 'Endpoint tidak ditemukan.', headers)
  }

  if (request.method === 'OPTIONS') {
    headers.delete('Content-Type')
    return new Response(null, { status: 204, headers })
  }

  if (request.method !== 'POST') {
    headers.set('Allow', 'POST, OPTIONS')
    return errorResponse(405, 'method_not_allowed', 'Gunakan metode POST.', headers)
  }

  if (!isJsonContentType(request)) {
    return errorResponse(
      415,
      'unsupported_media_type',
      'Content-Type harus application/json.',
      headers,
    )
  }

  const ip = request.headers.get('cf-connecting-ip')?.trim() || 'unknown'
  const limit = readInteger(env.RATE_LIMIT_MAX_PER_IP, DEFAULT_IP_LIMIT, 0, 10_000)
  const windowSeconds = readInteger(
    env.RATE_LIMIT_WINDOW_SECONDS,
    DEFAULT_WINDOW_SECONDS,
    1,
    3_600,
  )
  // P1-3: state bersama (Durable Object) bila binding tersedia; tanpa binding, memori
  // isolate — perilaku yang sama seperti sebelum perbaikan ini.
  const workerState = resolveWorkerState(env.SCAN_STATE, dependencies.state)
  const state = workerState.store
  const decision = await state.consumeCounter(
    `ip:${ip}`,
    limit,
    windowSeconds * 1_000,
    dependencies.now(),
  )

  if (!decision.allowed) {
    headers.set('Retry-After', String(decision.retryAfterSeconds))
    return errorResponse(
      429,
      'rate_limited',
      'Terlalu banyak permintaan. Coba lagi setelah jendela rate limit selesai.',
      headers,
    )
  }

  const resolved = await resolveIdentity(request, env, dependencies, ip)
  if (!resolved.ok) {
    return errorResponse(401, 'invalid_token', resolved.message, headers)
  }
  const identity = resolved.identity
  // Kunci izin CAPTCHA dan kunci batas analisis situs diturunkan dari identitas, sehingga
  // tamu tetap per-IP seperti sebelumnya dan pengguna terverifikasi per-uid.
  const clearanceKey = turnstileScanClearanceKey(identity.uid)

  // Batas per-IP tetap berlaku untuk semua orang; pengguna terverifikasi mendapat bucket
  // tambahan atas uid-nya supaya satu alamat bersama (NAT/kampus) tidak saling memblokir,
  // sekaligus tidak bisa menyamar sebagai tamu dengan membuang token.
  if (identity.authenticated) {
    const uidDecision = await state.consumeCounter(
      identity.uid,
      limit,
      windowSeconds * 1_000,
      dependencies.now(),
    )
    if (!uidDecision.allowed) {
      headers.set('Retry-After', String(uidDecision.retryAfterSeconds))
      return errorResponse(
        429,
        'rate_limited',
        'Terlalu banyak permintaan dari akun ini. Coba lagi setelah jendela rate limit selesai.',
        headers,
      )
    }
  }

  let text: string
  try {
    text = await readLimitedText(request)
  } catch (error) {
    if (error instanceof BodyTooLargeError) {
      return errorResponse(413, 'payload_too_large', 'Permintaan terlalu besar.', headers)
    }
    return errorResponse(400, 'invalid_request', 'Permintaan tidak dapat dibaca.', headers)
  }

  let payload: unknown
  try {
    payload = JSON.parse(text) as unknown
  } catch {
    return errorResponse(400, 'invalid_request', 'Body JSON tidak valid.', headers)
  }

  if (!isRecord(payload)) {
    return errorResponse(400, 'invalid_request', 'Permintaan pemeriksaan tidak valid.', headers)
  }

  // Gerbang pendaftaran: token diperiksa server-side sebelum browser melanjutkan pembuatan
  // akun. Batas keras per-IP di atas sudah berlaku untuk jalur ini, jadi endpoint ini tidak
  // dapat dipakai sebagai oracle tanpa batas.
  if (pathname === '/auth/turnstile/verify') {
    if (!turnstileSecretKey(env)) {
      return errorResponse(
        503,
        'captcha_not_configured',
        'Layanan verifikasi CAPTCHA belum dikonfigurasi.',
        headers,
      )
    }

    const verification = await verifyTurnstile(
      dependencies,
      env,
      request,
      ip,
      TURNSTILE_ACTION.register,
      payload.token,
      workerState,
    )

    if (!verification.ok) {
      return errorResponse(
        400,
        'captcha_verification_failed',
        'Verifikasi CAPTCHA tidak berlaku. Selesaikan verifikasi baru lalu coba lagi.',
        headers,
      )
    }

    return jsonResponse(200, { verified: true }, headers)
  }

  if (payload.consent !== true) {
    return errorResponse(
      400,
      'consent_required',
      'Persetujuan untuk mengirim URL ke provider eksternal diperlukan.',
      headers,
    )
  }

  if (typeof payload.url !== 'string') {
    return errorResponse(400, 'invalid_url', 'URL harus berupa teks.', headers)
  }

  // Eskalasi adaptif: CAPTCHA hanya diminta bila alamat ini sudah melampaui pecahan dari
  // batas keras yang ada. Pemeriksaan rate limit di atas tetap berjalan seperti sebelumnya.
  if (
    SCAN_PATHS.has(pathname) &&
    requiresTurnstileScanVerification({
      secretConfigured: Boolean(turnstileSecretKey(env)),
      limitPerWindow: limit,
      used: decision.used,
      clearanceActive: await state.hasClearance(clearanceKey, dependencies.now()),
    })
  ) {
    const token = readCaptchaToken(payload.captchaToken)
    // P1-3: reservasi anti-replay token kini berada di state bersama (lihat verifyTurnstile),
    // sehingga token yang sama dari isolate lain menghasilkan 'expired_or_reused' dan dijawab
    // 428 tanpa memanggil Cloudflare dua kali.
    const verification = token
      ? await verifyTurnstile(
          dependencies,
          env,
          request,
          ip,
          TURNSTILE_ACTION.scan,
          token,
          workerState,
        )
      : null

    if (verification?.ok) {
      await state.issueClearance(clearanceKey, dependencies.now())
    } else {
      const challenged = verification !== null
      return errorResponse(
        428,
        challenged ? 'captcha_invalid' : 'captcha_required',
        challenged
          ? 'Verifikasi CAPTCHA tidak berlaku. Selesaikan verifikasi baru lalu coba lagi.'
          : 'Verifikasi CAPTCHA diperlukan untuk melanjutkan pemeriksaan dari alamat ini.',
        headers,
      )
    }
  }

  const uid = identity.uid

  // Kuota pemeriksaan dihitung di state bersama, bukan di memori satu isolate: tanpa ini,
  // batas "6 pemeriksaan / 10 menit" berlaku per isolate dan bisa terbagi sebanyak isolate
  // yang menampung satu akun. Bila SCAN_STATE tidak terpasang, store sudah jatuh ke memori.
  const consumeRateLimit: ScanQuotaConsumer = (quotaUid, nowMs) =>
    state.consumeCounter(
      scanQuotaKey(quotaUid),
      SCAN_RATE_LIMIT.maxScans,
      SCAN_RATE_LIMIT.windowMs,
      nowMs,
    )

  const config = readScannerConfig(env as Record<string, string | undefined>)

  if (pathname === '/scan/stream') {
    const scanId = readScanId(payload.scanId)
    if (!scanId) {
      return errorResponse(
        400,
        'invalid_scan_id',
        'ID pemeriksaan tidak valid.',
        headers,
      )
    }

    try {
      normalizeScanUrl(payload.url)
    } catch (error) {
      return errorResponse(
        400,
        'invalid_url',
        error instanceof ScanUrlError ? error.message : 'URL tidak valid.',
        headers,
      )
    }

    const concurrency = env.PROVIDER_CONCURRENCY?.trim()
      ? readInteger(
          env.PROVIDER_CONCURRENCY,
          DEFAULT_PROVIDER_CONCURRENCY,
          1,
          8,
        )
      : undefined

    return createSseResponse(headers, request, scanId, (onEvent) =>
      dependencies.runScan({
        uid,
        url: payload.url as string,
        scanId,
        config,
        signal: request.signal,
        consumeRateLimit,
        ...(concurrency === undefined ? {} : { concurrency }),
        onEvent,
      }),
    )
  }

  if (pathname === '/site/analysis') {
    const decision = await state.consumeSiteWindow(
      siteRateLimitKey(identity.uid),
      dependencies.now(),
    )
    if (!decision.allowed) {
      headers.set('Retry-After', String(decision.retryAfterSeconds))
      return errorResponse(
        429,
        'site_rate_limited',
        'Terlalu banyak analisis situs dari alamat ini. Coba lagi setelah jendela batas selesai.',
        headers,
      )
    }

    try {
      const report = await runSiteAnalysis({
        url: payload.url,
        uid,
        probe: dependencies.siteProbe,
        now: dependencies.now,
        signal: request.signal,
      })
      return jsonResponse(200, report, headers)
    } catch (error) {
      if (error instanceof ScanUrlError) {
        return errorResponse(400, 'invalid_url', error.message, headers)
      }
      return errorResponse(
        500,
        'internal',
        'Analisis situs gagal diproses. Data tidak pernah dibuat-buat.',
        headers,
      )
    }
  }

  let result: MultiSourceScanResponse
  try {
    result = await dependencies.runScan({
      uid,
      url: payload.url,
      config,
      consumeRateLimit,
      // Jalur non-stream juga harus berhenti saat koneksi klien ditutup, supaya tidak ada
      // permintaan provider yang terus berjalan setelah pemeriksaan dibatalkan.
      signal: request.signal,
    })
  } catch (error) {
    if (error instanceof ScanUrlError) {
      return errorResponse(400, 'invalid_url', error.message, headers)
    }
    return errorResponse(
      500,
      'internal',
      'Pemeriksaan reputasi gagal diproses.',
      headers,
    )
  }

  return jsonResponse(200, result, headers)
}

// Cloudflare Workers hanya menerima redirect "follow" atau "manual", sedangkan
// adapter bersama memakai "error" yang didukung Node. Shim ini menjaga semantik
// "error" tanpa mengubah adapter yang juga dipakai scanner lokal.
export function createWorkerFetch(baseFetch: typeof fetch = fetch): typeof fetch {
  return (input, init) => {
    if (init?.redirect !== 'error') return baseFetch(input, init)

    return baseFetch(input, { ...init, redirect: 'manual' }).then((response) => {
      if (
        response.type === 'opaqueredirect' ||
        (response.status >= 300 && response.status < 400)
      ) {
        void response.body?.cancel().catch(() => undefined)
        throw new TypeError('fetch failed: redirect not allowed')
      }
      return response
    })
  }
}

export function createWorker(
  overrides: Partial<WorkerDependencies> = {},
): ExportedHandler<Env> {
  const workerFetch = createWorkerFetch()
  const dependencies: WorkerDependencies = {
    runScan: (input) =>
      runMultiSourceScan({ ...input, fetchImpl: input.fetchImpl ?? workerFetch }),
    state: createMemoryStateStore(),
    now: Date.now,
    siteProbe: createWorkerSiteProbe(),
    verifyTurnstile: verifyTurnstileToken,
    verifyFirebaseToken: verifyFirebaseIdToken,
    ...overrides,
  }

  return {
    async fetch(request, env): Promise<Response> {
      return handleRequest(request, env, dependencies)
    },
  }
}

export default createWorker()

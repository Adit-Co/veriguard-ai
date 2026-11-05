import type { ProviderStatus } from './types.js'

export type FetchJsonResult =
  | { ok: true; data: unknown; status: number; contentType?: string | null }
  | {
      ok: false
      status: number | null
      kind: ProviderStatus
      reason: string
      retryAfterMs?: number | null
      rateLimit?: RateLimitInfo | null
    }

const DEFAULT_TIMEOUT_MS = 8_000
const MAX_RETRY_AFTER_MS = 10 * 60_000
const MAX_WINDOW_MS = 24 * 60 * 60_000

// Batas ukuran body yang dibaca dari provider. Body adalah data pihak ketiga: tanpa batas,
// satu respons berupa aliran tak berhingga (atau gzip bombs) akan ditahan seluruhnya di
// memori sebelum pemanggil sempat memotongnya. Batas diperiksa saat aliran dibaca, bukan
// hanya lewat header content-length yang bolehbohong.
export const MAX_RESPONSE_BYTES = 2 * 1024 * 1024

class ResponseTooLargeError extends Error {
  constructor() {
    super('provider response exceeds size limit')
    this.name = 'ResponseTooLargeError'
  }
}

function declaredSize(response: Response): number | null {
  const raw = response.headers.get('content-length')?.trim()
  if (!raw || !/^\d+$/.test(raw)) return null
  return Number(raw)
}

/** Membuang body yang tidak dipakai supaya socket tidak menggantung untuk dibaca ulang. */
export function discardResponseBody(response: Response): void {
  try {
    void response.body?.cancel()?.catch(() => undefined)
  } catch {
    // Body yang sudah terpakai bukan kegagalan yang bisa dilakukan apa pun.
  }
}

/**
 * Bacaan JSON berbatas untuk adapter yang menyusun permintaannya sendiri (Radar). Body yang
 * tidak dapat diurai dikembalikan sebagai `null` seperti sebelumnya; body yang melebihi batas
 * mengangkat galat supaya pemanggil menjawab "tidak tersedia", bukan "tidak ada data".
 */
export async function readBoundedJson(
  response: Response,
  maxBytes = MAX_RESPONSE_BYTES,
): Promise<unknown> {
  let bytes: Uint8Array
  try {
    bytes = await readCapped(response, maxBytes)
  } catch (error) {
    if (error instanceof ResponseTooLargeError) throw error
    return null
  }

  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: false }).decode(bytes)) as unknown
  } catch {
    return null
  }
}

async function readCapped(response: Response, maxBytes: number): Promise<Uint8Array> {
  const declared = declaredSize(response)
  if (declared !== null && declared > maxBytes) throw new ResponseTooLargeError()

  // Tidak ada aliran (mock, atau body yang sudah dibaca): pakai buffer biasa dengan pemeriksaan
  // ukuran setelah baca, lebih baik daripada menolak respons yang sebenarnya sah.
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer())
    if (bytes.byteLength > maxBytes) throw new ResponseTooLargeError()
    return bytes
  }

  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    if (!value) continue
    total += value.byteLength
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined)
      throw new ResponseTooLargeError()
    }
    chunks.push(value)
  }

  const merged = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    merged.set(chunk, offset)
    offset += chunk.byteLength
  }
  return merged
}

// Nilai header kuota dibaca apa adanya; tidak ada angka yang dikarang bila header absen.
export type RateLimitInfo = {
  scope: string | null
  action: string | null
  window: string | null
  limit: number | null
  remaining: number | null
  resetAfterMs: number | null
  resetAt: string | null
}

function headerText(response: Response, name: string): string | null {
  const raw = response.headers.get(name)
  const trimmed = raw?.trim()
  return trimmed ? trimmed.slice(0, 64) : null
}

function headerCount(value: string | null): number | null {
  if (!value) return null
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed >= 0 ? Math.round(parsed) : null
}

function headerDurationMs(value: string | null, nowMs: number): number | null {
  if (!value) return null

  const seconds = Number(value)
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(MAX_WINDOW_MS, Math.max(0, Math.round(seconds * 1_000)))
  }

  const deadline = Date.parse(value)
  if (Number.isNaN(deadline)) return null
  return Math.min(MAX_WINDOW_MS, Math.max(0, Math.round(deadline - nowMs)))
}

export function rateLimitInfo(response: Response, nowMs: number): RateLimitInfo | null {
  const scope = headerText(response, 'x-rate-limit-scope')
  const action = headerText(response, 'x-rate-limit-action')
  const windowValue = headerText(response, 'x-rate-limit-window')
  const limit = headerCount(headerText(response, 'x-rate-limit-limit'))
  const remaining = headerCount(headerText(response, 'x-rate-limit-remaining'))
  const resetAt = headerText(response, 'x-rate-limit-reset')
  const resetAfterMs =
    headerDurationMs(headerText(response, 'x-rate-limit-reset-after'), nowMs) ??
    headerDurationMs(resetAt, nowMs)

  if (
    scope === null &&
    action === null &&
    windowValue === null &&
    limit === null &&
    remaining === null &&
    resetAfterMs === null &&
    resetAt === null
  ) {
    return null
  }

  return {
    scope,
    action,
    window: windowValue,
    limit,
    remaining,
    resetAfterMs,
    resetAt,
  }
}

export function retryAfterMs(response: Response, nowMs: number): number | null {
  const raw = response.headers.get('retry-after')
  if (!raw) return null

  const seconds = Number(raw)
  if (Number.isFinite(seconds)) {
    return Math.min(MAX_RETRY_AFTER_MS, Math.max(0, Math.round(seconds * 1_000)))
  }

  const deadline = Date.parse(raw)
  if (Number.isNaN(deadline)) return null
  return Math.min(MAX_RETRY_AFTER_MS, Math.max(0, Math.round(deadline - nowMs)))
}

export function describeQuota(info: RateLimitInfo | null): string | null {
  if (!info) return null

  const parts: string[] = []
  if (info.remaining !== null && info.limit !== null) {
    parts.push(`sisa ${info.remaining} dari ${info.limit}`)
  }
  if (info.window) parts.push(`per ${info.window}`)
  if (info.action) parts.push(`operasi ${info.action}`)
  if (info.scope) parts.push(`lingkup ${info.scope}`)

  return parts.length > 0 ? parts.join(', ') : null
}

// Teks galat disanitasi sebelum pernah sampai ke antarmuka: URL dibuang, token panjang
// (kunci/rahasia) diganti, spasi diringkas, dan panjang dibatasi. Tidak pernah memuat body,
// header, cookie, maupun nilai kredensial.
export function sanitizeReasonText(value: string): string {
  return value
    .replace(/https?:\/\/\S+/gi, '[url]')
    .replace(/[A-Za-z0-9_-]{20,}/g, '.')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80)
}

// Kode kegagalan jaringan (DNS/TCP/TLS) yang aman ditampilkan: HANYA token huruf besar dengan
// garis bawah/angka (mis. ENOTFOUND, ECONNRESET, UND_ERR_SOCKET, ERR_TLS_CERT_ALTNAME_INVALID).
// Pola ini secara bentuk tidak memuat hostname, URL, header, maupun body, jadi kodenya boleh
// diekspos apa adanya.
const SAFE_ERROR_CODE = /^[A-Z][A-Z0-9_]{2,}$/

function safeErrorCode(value: unknown): string | null {
  if (!value || typeof value !== 'object') return null
  const code = (value as { code?: unknown }).code
  return typeof code === 'string' && SAFE_ERROR_CODE.test(code) ? code : null
}

// undici membungkus kegagalan koneksi sebagai `TypeError: fetch failed` dengan penyebab asli di
// `error.cause`. Kita telusuri rantai cause MAKSIMAL dua level dan mengambil HANYA kode penyebab
// yang dikenali. Pesan mentah cause TIDAK pernah dibaca karena memuat hostname/URL yang dilarang.
function firstSafeErrorCode(error: unknown): string | null {
  let current: unknown = error
  for (let depth = 0; depth <= 2; depth += 1) {
    const code = safeErrorCode(current)
    if (code) return code
    if (!current || typeof current !== 'object') break
    current = (current as { cause?: unknown }).cause
  }
  return null
}

// Deskripsi galat jaringan yang aman untuk antarmuka: nama/tipe, pesan tersanitasi, dan kode
// kegagalan (DNS/TCP/TLS) yang dikenali. Diekspor supaya adapter yang membangun permintaannya
// sendiri (Radar) memakai taksonomi kegagalan yang sama, tidak bercabang.
export function describeError(error: unknown): string {
  const name = error instanceof Error ? error.name : typeof error
  const message = error instanceof Error ? error.message : ''
  const sanitized = sanitizeReasonText(message)
  const base = sanitized ? `${name}: ${sanitized}` : name
  const code = firstSafeErrorCode(error)
  return (code ? `${base} [${code}]` : base).slice(0, 120)
}

// Pemetaan status HTTP yang sama dipakai untuk respons JSON, teks polos, maupun byte mentah,
// supaya kegagalan teknis tidak pernah berubah menjadi "tidak ada data".
// Mode 'bytes' dipakai agen yang layanannya mengembalikan protobuf: body TIDAK boleh didekode
// sebagai UTF-8 karena byte binary rusak dan kontraknya tidak dapat dipulihkan.
export async function fetchJson(
  fetchImpl: typeof fetch,
  input: string,
  init: RequestInit = {},
  timeoutMs = DEFAULT_TIMEOUT_MS,
  expected: 'json' | 'text' | 'bytes' = 'json',
  maxBytes = MAX_RESPONSE_BYTES,
): Promise<FetchJsonResult> {
  const controller = new AbortController()
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeoutMs)

  const externalSignal = init.signal ?? undefined
  const forwardAbort = () => controller.abort()
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort()
    else {
      externalSignal.addEventListener('abort', forwardAbort, { once: true })
    }
  }

  try {
    const response = await fetchImpl(input, {
      ...init,
      redirect: 'error',
      signal: controller.signal,
    })

    if (response.status === 429) {
      const nowMs = Date.now()
      const retryAfter = retryAfterMs(response, nowMs)
      const quota = rateLimitInfo(response, nowMs)
      const waitMs = retryAfter ?? quota?.resetAfterMs ?? null
      const quotaText = describeQuota(quota)
      const hint =
        waitMs === null
          ? null
          : retryAfter !== null
            ? `provider menyarankan jeda ${Math.round(waitMs / 1_000)} detik`
            : `jendela kuota berikutnya terbuka dalam ±${Math.round(waitMs / 1_000)} detik`
      discardResponseBody(response)
      return {
        ok: false,
        status: response.status,
        kind: 'rate_limited',
        reason:
          hint === null
            ? 'Kuota permintaan provider tercapai.'
            : `Kuota permintaan provider tercapai; ${hint}${quotaText ? ` (${quotaText})` : ''}.`,
        retryAfterMs: waitMs,
        rateLimit: quota,
      }
    }

    if (response.status === 401 || response.status === 403) {
      discardResponseBody(response)
      return {
        ok: false,
        status: response.status,
        kind: 'auth_failed',
        reason: 'Kredensial provider ditolak.',
      }
    }

    if (response.status === 404) {
      discardResponseBody(response)
      return {
        ok: false,
        status: response.status,
        kind: 'not_found',
        reason: 'Provider tidak memiliki data untuk URL ini.',
      }
    }

    if (response.status === 400 || response.status === 422) {
      // Permintaan kami ditolak provider karena bentuknya. Body respons TIDAK dibaca:
      // isinya bebas dan bisa membawa URL/parameter permintaan, sedangkan yang dibutuhkan
      // antarmuka hanya "provider menolak permintaan ini" plus status HTTP-nya.
      discardResponseBody(response)
      return {
        ok: false,
        status: response.status,
        kind: 'invalid_request',
        reason: 'Permintaan pemeriksaan ditolak provider.',
      }
    }

    if (!response.ok) {
      const kind: ProviderStatus = response.status >= 500 ? 'unavailable' : 'error'
      discardResponseBody(response)
      return {
        ok: false,
        status: response.status,
        kind,
        reason:
          kind === 'unavailable'
            ? 'Layanan provider sedang tidak tersedia.'
            : `Provider menolak permintaan (HTTP ${response.status}).`,
      }
    }

    const contentType = response.headers.get('content-type')
    try {
      const bytes = await readCapped(response, maxBytes)
      if (expected === 'bytes') {
        return { ok: true, data: bytes, status: response.status, contentType }
      }
      const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
      const data = expected === 'text' ? (text as unknown) : (JSON.parse(text) as unknown)
      return { ok: true, data, status: response.status, contentType }
    } catch (error) {
      if (error instanceof ResponseTooLargeError) {
        return {
          ok: false,
          status: response.status,
          kind: 'error',
          reason: `Respons provider melebihi batas ukuran ${maxBytes} byte.`,
        }
      }
      return {
        ok: false,
        status: response.status,
        kind: 'error',
        reason: 'Respons provider tidak dapat dibaca.',
      }
    }
  } catch (error) {
    if (controller.signal.aborted && !timedOut) {
      return {
        ok: false,
        status: null,
        kind: 'skipped',
        reason: 'Permintaan ke provider dibatalkan saat proses scan berjalan.',
      }
    }

    const timedOutError =
      error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError')

    if (timedOut || timedOutError) {
      return {
        ok: false,
        status: null,
        kind: 'timeout',
        reason: 'Permintaan ke provider melebihi batas waktu.',
      }
    }

    return {
      ok: false,
      status: null,
      kind: 'unavailable',
      reason: `Provider tidak dapat dihubungi. (${describeError(error)})`,
    }
  } finally {
    clearTimeout(timer)
    externalSignal?.removeEventListener('abort', forwardAbort)
  }
}

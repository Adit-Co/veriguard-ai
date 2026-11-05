import { configuredApiBase } from '../scanners/client'
import { ExternalScanRequestError } from '../scanners/errors'
import { authorizationHeader } from '../auth/session'

// Verifikasi token hanya membaca hasil dari server. Kunci situs bersifat publik dan memang
// dibutuhkan browser; kunci rahasia tidak pernah lewat ke sisi klien.
const VERIFY_TIMEOUT_MS = 10_000

export const TURNSTILE_CLIENT_ERROR_MESSAGE =
  'Verifikasi CAPTCHA gagal. Selesaikan verifikasi baru lalu coba lagi.'

export function turnstileSiteKey(
  siteKey: string | undefined = import.meta.env.VITE_TURNSTILE_SITE_KEY,
): string | null {
  const trimmed = siteKey?.trim() ?? ''
  return trimmed ? trimmed : null
}

export function isTurnstileEnabled(
  siteKey: string | null = turnstileSiteKey(),
  apiBase: string | undefined = import.meta.env.VITE_API_BASE_URL,
  workerUrl: string | undefined = import.meta.env.VITE_SCANNER_WORKER_URL,
): boolean {
  return Boolean(siteKey) && Boolean(configuredApiBase(apiBase, workerUrl))
}

export function turnstileVerifyEndpoint(baseUrl: string): string {
  const trimmed = baseUrl.trim().replace(/\/+$/, '')
  if (trimmed.endsWith('/auth/turnstile/verify')) return trimmed
  const origin = trimmed.replace(/\/(scan\/stream|scan|scanUrlMultiSource|site\/analysis)$/, '')
  return `${origin}/auth/turnstile/verify`
}

export type TurnstileVerifyOptions = {
  fetchImpl?: typeof fetch
  signal?: AbortSignal
}

// Menyelesaikan tanpa nilai bila server menyatakan token sah; melempar bila tidak.
export async function requestTurnstileVerification(
  token: string,
  options: TurnstileVerifyOptions = {},
): Promise<void> {
  const baseUrl = configuredApiBase()
  if (!baseUrl) {
    throw new ExternalScanRequestError(
      'worker_not_configured',
      'Layanan verifikasi CAPTCHA belum tersedia pada versi ini.',
    )
  }

  const fetchImpl = options.fetchImpl ?? fetch
  const controller = new AbortController()
  let timedOut = false
  const timer = globalThis.setTimeout(() => {
    timedOut = true
    controller.abort()
  }, VERIFY_TIMEOUT_MS)
  const abortFromCaller = () => controller.abort()
  options.signal?.addEventListener('abort', abortFromCaller, { once: true })

  try {
    const response = await fetchImpl(turnstileVerifyEndpoint(baseUrl), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(await authorizationHeader()) },
      body: JSON.stringify({ token }),
      cache: 'no-store',
      credentials: 'omit',
      signal: controller.signal,
    })

    let payload: unknown = null
    try {
      payload = (await response.json()) as unknown
    } catch {
      payload = null
    }

    if (!response.ok) {
      const code = readErrorCode(payload) ?? fallbackCode(response.status)
      throw new ExternalScanRequestError(code, TURNSTILE_CLIENT_ERROR_MESSAGE)
    }
  } catch (error) {
    if (error instanceof ExternalScanRequestError) throw error
    if (timedOut || options.signal?.aborted) {
      throw new ExternalScanRequestError('timeout', TURNSTILE_CLIENT_ERROR_MESSAGE)
    }
    throw new ExternalScanRequestError('unavailable', TURNSTILE_CLIENT_ERROR_MESSAGE)
  } finally {
    globalThis.clearTimeout(timer)
    options.signal?.removeEventListener('abort', abortFromCaller)
  }
}

function readErrorCode(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null
  const error = (payload as Record<string, unknown>).error
  if (!error || typeof error !== 'object' || Array.isArray(error)) return null
  const code = (error as Record<string, unknown>).code
  return typeof code === 'string' && code.trim() ? code : null
}

function fallbackCode(status: number): string {
  if (status === 429) return 'rate_limited'
  if (status === 503) return 'captcha_not_configured'
  return 'captcha_verification_failed'
}

export function turnstileErrorMessage(error: unknown): string {
  if (error instanceof ExternalScanRequestError) {
    if (error.code === 'captcha_not_configured') {
      return 'Layanan verifikasi CAPTCHA belum disiapkan pada versi ini.'
    }
    if (error.code === 'rate_limited') {
      return 'Terlalu banyak permintaan verifikasi. Coba lagi beberapa saat.'
    }
    if (error.code === 'worker_not_configured') {
      return 'Layanan verifikasi CAPTCHA belum tersedia pada versi ini.'
    }
    if (error.code === 'timeout') {
      return 'Verifikasi CAPTCHA melebihi batas waktu. Coba lagi.'
    }
  }
  return TURNSTILE_CLIENT_ERROR_MESSAGE
}

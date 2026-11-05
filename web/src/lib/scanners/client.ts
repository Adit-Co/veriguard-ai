import {
  createExternalScanCancelledError,
  ExternalScanRequestError,
} from './errors'
import type {
  ScanProgressEvent,
  ScanUrlMultiSourceResponse,
} from './types'
import {
  parseMultiSourceResponse,
  parseScanProgressEvent,
  parseScanStreamErrorEvent,
} from './validate'
import { authorizationHeader } from '../auth/session'

// Harus tetap di atas batas waktu scan di backend (80 detik, lihat DEFAULT_SCAN_TIMEOUT_MS di
// functions/src/scanners/service.ts). Kalau klien berhenti lebih dulu, pemeriksaan yang sedang
// diselesaikan agen lambat terpotong dan tampil sebagai "timeout" padahal tidak ada yang salah.
const CLIENT_TIMEOUT_MS = 90_000
const STREAM_TIMEOUT_MS = 90_000
// Server yang sehat mengirim event pendek. Batas ini mencegah buffer tumbuh tanpa
// batas bila stream mengalirkan data tanpa pemisah event sampai timeout.
const MAX_STREAM_BUFFER_LENGTH = 1_000_000

type WorkerScanOptions = {
  fetchImpl?: typeof fetch
  signal?: AbortSignal
  // Token CAPTCHA yang baru saja diselesaikan pengguna. Hanya dikirim ketika layanan
  // memintanya, jadi pemeriksaan biasa tidak pernah membawa token.
  captchaToken?: string | null
}

type WorkerStreamOptions = WorkerScanOptions & {
  onEvent?: (event: ScanProgressEvent) => void
  signal?: AbortSignal
}

function scanBody(url: string, captchaToken?: string | null, scanId?: string): string {
  return JSON.stringify({
    url,
    consent: true,
    ...(scanId ? { scanId } : {}),
    ...(captchaToken ? { captchaToken } : {}),
  })
}

type SseMessage = {
  event: string
  data: string
}

export function isMultiSourceEnabled(
  flag: string | undefined = import.meta.env.VITE_MULTI_SOURCE_ENABLED,
): boolean {
  return flag?.trim().toLowerCase() !== 'false'
}

export function configuredApiBase(
  apiBase: string | undefined = import.meta.env.VITE_API_BASE_URL,
  workerUrl: string | undefined = import.meta.env.VITE_SCANNER_WORKER_URL,
): string | undefined {
  return apiBase?.trim() || workerUrl?.trim() || undefined
}

export function isWorkerConfigured(
  workerUrl: string | undefined = import.meta.env.VITE_SCANNER_WORKER_URL,
  apiBase: string | undefined = import.meta.env.VITE_API_BASE_URL,
): boolean {
  return Boolean(configuredApiBase(apiBase, workerUrl))
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function workerEndpoint(baseUrl: string): string {
  const trimmed = baseUrl.trim().replace(/\/+$/, '')
  if (trimmed.endsWith('/scan') || trimmed.endsWith('/scanUrlMultiSource')) return trimmed
  return `${trimmed}/scan`
}

function workerStreamEndpoint(baseUrl: string): string {
  const trimmed = baseUrl.trim().replace(/\/+$/, '')
  if (trimmed.endsWith('/scan/stream')) return trimmed
  if (trimmed.endsWith('/scan') || trimmed.endsWith('/scanUrlMultiSource')) {
    return `${trimmed.replace(/\/(scan|scanUrlMultiSource)$/, '')}/scan/stream`
  }
  return `${trimmed}/scan/stream`
}

function parseSseMessage(block: string): SseMessage | null {
  let event = 'message'
  const data: string[] = []

  for (const line of block.split(/\r?\n/)) {
    if (!line || line.startsWith(':')) continue
    const separator = line.indexOf(':')
    const field = separator === -1 ? line : line.slice(0, separator)
    const value = separator === -1 ? '' : line.slice(separator + 1).replace(/^ /, '')

    if (field === 'event') event = value
    else if (field === 'data') data.push(value)
  }

  return data.length > 0 ? { event, data: data.join('\n') } : null
}

async function consumeScanStream(
  response: Response,
  onEvent?: (event: ScanProgressEvent) => void,
  signal?: AbortSignal,
): Promise<ScanUrlMultiSourceResponse> {
  if (signal?.aborted) throw createExternalScanCancelledError()

  const reader = response.body?.getReader()
  if (!reader) {
    throw new ExternalScanRequestError(
      'invalid_response',
      'Respons pemeriksaan eksternal tidak valid.',
    )
  }

  const decoder = new TextDecoder()
  let buffer = ''
  let doneResponse: ScanUrlMultiSourceResponse | null = null
  const abortReader = () => {
    void reader.cancel().catch(() => undefined)
  }
  signal?.addEventListener('abort', abortReader, { once: true })

  const handleMessage = (message: SseMessage): void => {
    let payload: unknown
    try {
      payload = JSON.parse(message.data) as unknown
    } catch {
      throw new ExternalScanRequestError(
        'invalid_response',
        'Respons pemeriksaan eksternal tidak valid.',
      )
    }

    if (message.event === 'error') {
      const error = parseScanStreamErrorEvent(payload)
      throw new ExternalScanRequestError(error.code, error.message)
    }

    let event: ScanProgressEvent
    try {
      event = parseScanProgressEvent(payload)
    } catch {
      throw new ExternalScanRequestError(
        'invalid_response',
        'Respons pemeriksaan eksternal tidak valid.',
      )
    }
    onEvent?.(event)
    if (event.type === 'done') doneResponse = event.response
  }

  try {
    while (true) {
      if (signal?.aborted) throw createExternalScanCancelledError()
      const { done, value } = await reader.read()
      if (signal?.aborted) throw createExternalScanCancelledError()
      if (done) break

      buffer += decoder.decode(value, { stream: true })
      if (buffer.length > MAX_STREAM_BUFFER_LENGTH) {
        await reader.cancel().catch(() => undefined)
        throw new ExternalScanRequestError(
          'invalid_response',
          'Respons pemeriksaan eksternal tidak valid.',
        )
      }
      let boundary = buffer.match(/\r?\n\r?\n/)
      while (boundary?.index !== undefined) {
        const block = buffer.slice(0, boundary.index)
        buffer = buffer.slice(boundary.index + boundary[0].length)
        const message = parseSseMessage(block)
        if (message) handleMessage(message)
        boundary = buffer.match(/\r?\n\r?\n/)
      }
    }

    buffer += decoder.decode()
    const trailing = parseSseMessage(buffer)
    if (trailing) handleMessage(trailing)
  } finally {
    signal?.removeEventListener('abort', abortReader)
    reader.releaseLock()
  }

  if (signal?.aborted) throw createExternalScanCancelledError()
  if (!doneResponse) {
    throw new ExternalScanRequestError(
      'invalid_response',
      'Respons pemeriksaan eksternal tidak valid.',
    )
  }

  return doneResponse
}

function statusErrorCode(status: number): string {
  switch (status) {
    case 401:
      return 'unauthenticated'
    case 403:
      return 'origin_not_allowed'
    case 404:
      return 'not_found'
    case 413:
      return 'payload_too_large'
    case 415:
      return 'unsupported_media_type'
    case 428:
      return 'captcha_required'
    case 429:
      return 'rate_limited'
    default:
      return 'internal'
  }
}

function readWorkerError(payload: unknown, status: number): ExternalScanRequestError {
  if (isRecord(payload) && isRecord(payload.error)) {
    const code =
      typeof payload.error.code === 'string' ? payload.error.code : statusErrorCode(status)
    const message =
      typeof payload.error.message === 'string' && payload.error.message.trim()
        ? payload.error.message
        : 'Pemeriksaan eksternal gagal diproses.'
    return new ExternalScanRequestError(code, message)
  }

  return new ExternalScanRequestError(
    statusErrorCode(status),
    'Pemeriksaan eksternal gagal diproses.',
  )
}

export async function requestWorkerScan(
  workerUrl: string,
  url: string,
  options: WorkerScanOptions = {},
): Promise<ScanUrlMultiSourceResponse> {
  const fetchImpl = options.fetchImpl ?? fetch
  const callerSignal = options.signal
  if (callerSignal?.aborted) throw createExternalScanCancelledError()

  const controller = new AbortController()
  let timedOut = false
  let cancelledByCaller = false
  const timer = globalThis.setTimeout(() => {
    timedOut = true
    controller.abort()
  }, CLIENT_TIMEOUT_MS)
  const abortFromCaller = () => {
    if (timedOut || controller.signal.aborted) return
    cancelledByCaller = true
    controller.abort()
  }
  callerSignal?.addEventListener('abort', abortFromCaller, { once: true })

  let response: Response
  let payload: unknown
  try {
    response = await fetchImpl(workerEndpoint(workerUrl), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(await authorizationHeader()),
      },
      body: scanBody(url, options.captchaToken),
      cache: 'no-store',
      credentials: 'omit',
      signal: controller.signal,
    })

    try {
      payload = (await response.json()) as unknown
    } catch {
      throw new ExternalScanRequestError(
        'invalid_response',
        'Respons pemeriksaan eksternal tidak valid.',
      )
    }
  } catch (error) {
    if (cancelledByCaller) throw createExternalScanCancelledError()
    if (timedOut) throw new Error('timeout')
    if (error instanceof ExternalScanRequestError) throw error
    throw new ExternalScanRequestError(
      'unavailable',
      'Layanan pemeriksaan eksternal tidak dapat dihubungi.',
    )
  } finally {
    globalThis.clearTimeout(timer)
    callerSignal?.removeEventListener('abort', abortFromCaller)
  }

  if (!response.ok) {
    throw readWorkerError(payload, response.status)
  }

  return parseMultiSourceResponse(payload)
}

export async function requestWorkerScanStream(
  workerUrl: string,
  url: string,
  scanId: string,
  options: WorkerStreamOptions = {},
): Promise<ScanUrlMultiSourceResponse> {
  const fetchImpl = options.fetchImpl ?? fetch
  const callerSignal = options.signal
  if (callerSignal?.aborted) throw createExternalScanCancelledError()

  const controller = new AbortController()
  let timedOut = false
  let cancelledByCaller = false
  const timer = globalThis.setTimeout(() => {
    timedOut = true
    controller.abort()
  }, STREAM_TIMEOUT_MS)
  const abortFromCaller = () => {
    if (timedOut || controller.signal.aborted) return
    cancelledByCaller = true
    controller.abort()
  }
  callerSignal?.addEventListener('abort', abortFromCaller, { once: true })

  try {
    const response = await fetchImpl(workerStreamEndpoint(workerUrl), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'text/event-stream',
        ...(await authorizationHeader()),
      },
      body: scanBody(url, options.captchaToken, scanId),
      cache: 'no-store',
      credentials: 'omit',
      signal: controller.signal,
    })

    if (response.status === 404 || response.status === 405) {
      globalThis.clearTimeout(timer)
      if (callerSignal?.aborted) throw createExternalScanCancelledError()
      return await requestWorkerScan(workerUrl, url, {
        fetchImpl,
        signal: callerSignal,
        captchaToken: options.captchaToken,
      })
    }

    if (!response.ok) {
      let payload: unknown = null
      try {
        payload = (await response.json()) as unknown
      } catch {
        payload = null
      }
      throw readWorkerError(payload, response.status)
    }

    const contentType = response.headers.get('content-type') ?? ''
    if (!contentType.toLowerCase().includes('text/event-stream')) {
      let payload: unknown
      try {
        payload = (await response.json()) as unknown
      } catch {
        throw new ExternalScanRequestError(
          'invalid_response',
          'Respons pemeriksaan eksternal tidak valid.',
        )
      }
      return parseMultiSourceResponse(payload)
    }

    return await consumeScanStream(response, options.onEvent, callerSignal)
  } catch (error) {
    if (cancelledByCaller) throw createExternalScanCancelledError()
    if (timedOut) throw new Error('timeout')
    if (error instanceof Error && error.message === 'timeout') throw error
    if (error instanceof ExternalScanRequestError) throw error
    throw new ExternalScanRequestError(
      'unavailable',
      'Layanan pemeriksaan eksternal tidak dapat dihubungi.',
    )
  } finally {
    globalThis.clearTimeout(timer)
    callerSignal?.removeEventListener('abort', abortFromCaller)
  }
}

export async function requestExternalScan(url: string): Promise<ScanUrlMultiSourceResponse> {
  const workerUrl = configuredApiBase()
  if (!workerUrl) {
    throw new ExternalScanRequestError(
      'worker_not_configured',
      'Layanan pemeriksaan eksternal belum tersedia pada versi ini.',
    )
  }

  return requestWorkerScan(workerUrl, url)
}

export async function requestExternalScanStream(
  url: string,
  scanId: string,
  options: WorkerStreamOptions = {},
): Promise<ScanUrlMultiSourceResponse> {
  const workerUrl = configuredApiBase()
  if (!workerUrl) {
    throw new ExternalScanRequestError(
      'worker_not_configured',
      'Layanan pemeriksaan eksternal belum tersedia pada versi ini.',
    )
  }

  return requestWorkerScanStream(workerUrl, url, scanId, options)
}

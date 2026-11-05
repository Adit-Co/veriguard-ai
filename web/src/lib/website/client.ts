import { ExternalScanRequestError } from '../scanners/errors'
import { authorizationHeader } from '../auth/session'
import { configuredApiBase } from '../scanners/client'
import type { SiteAnalysisResponse } from './types'
import { parseSiteAnalysisResponse } from './validate'

const CLIENT_TIMEOUT_MS = 45_000

export type SiteAnalysisOptions = {
  fetchImpl?: typeof fetch
  signal?: AbortSignal
}

function siteEndpoint(baseUrl: string): string {
  const trimmed = baseUrl.trim().replace(/\/+$/, '')
  if (trimmed.endsWith('/site/analysis')) return trimmed
  // Basis URL boleh diisi alamat endpoint scanner lengkap (mis. .../scanUrlMultiSource),
  // sama seperti yang ditoleransi klien scanner, jadi suffix itu dilepas lebih dulu.
  const origin = trimmed.replace(/\/(scan\/stream|scan|scanUrlMultiSource)$/, '')
  return `${origin}/site/analysis`
}

function statusErrorCode(status: number): string {
  switch (status) {
    case 403:
      return 'origin_not_allowed'
    case 404:
      return 'not_found'
    case 413:
      return 'payload_too_large'
    case 429:
      return 'site_rate_limited'
    default:
      return 'internal'
  }
}

function readError(payload: unknown, status: number): ExternalScanRequestError {
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    const record = payload as Record<string, unknown>
    const error = record.error
    if (error && typeof error === 'object' && !Array.isArray(error)) {
      const entry = error as Record<string, unknown>
      const code = typeof entry.code === 'string' ? entry.code : statusErrorCode(status)
      const message =
        typeof entry.message === 'string' && entry.message.trim()
          ? entry.message
          : 'Analisis situs gagal diproses.'
      return new ExternalScanRequestError(code, message)
    }
  }
  return new ExternalScanRequestError(
    statusErrorCode(status),
    'Analisis situs gagal diproses.',
  )
}

export function isSiteAnalysisAvailable(
  apiBase: string | undefined = import.meta.env.VITE_API_BASE_URL,
  workerUrl: string | undefined = import.meta.env.VITE_SCANNER_WORKER_URL,
): boolean {
  return Boolean(configuredApiBase(apiBase, workerUrl))
}

export async function requestSiteAnalysis(
  url: string,
  options: SiteAnalysisOptions = {},
): Promise<SiteAnalysisResponse> {
  const baseUrl = configuredApiBase()
  if (!baseUrl) {
    throw new ExternalScanRequestError(
      'worker_not_configured',
      'Layanan analisis situs belum tersedia pada versi ini.',
    )
  }

  const fetchImpl = options.fetchImpl ?? fetch
  const controller = new AbortController()
  let timedOut = false
  const timer = globalThis.setTimeout(() => {
    timedOut = true
    controller.abort()
  }, CLIENT_TIMEOUT_MS)
  const onCallerAbort = () => controller.abort()
  options.signal?.addEventListener('abort', onCallerAbort, { once: true })

  try {
    const response = await fetchImpl(siteEndpoint(baseUrl), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(await authorizationHeader()) },
      body: JSON.stringify({ url, consent: true }),
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
      throw readError(payload, response.status)
    }

    return parseSiteAnalysisResponse(payload)
  } catch (error) {
    if (timedOut) {
      throw new ExternalScanRequestError(
        'timeout',
        'Analisis situs melebihi batas waktu. Data tidak pernah dibuat-buat.',
      )
    }
    if (error instanceof ExternalScanRequestError) throw error
    throw new ExternalScanRequestError(
      'unavailable',
      'Permintaan analisis situs tidak sampai ke layanan pemeriksaan.',
    )
  } finally {
    globalThis.clearTimeout(timer)
    options.signal?.removeEventListener('abort', onCallerAbort)
  }
}

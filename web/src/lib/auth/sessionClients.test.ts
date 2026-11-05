import { afterEach, describe, expect, it, vi } from 'vitest'

// P1-2: modul sesi di-mock supaya setiap titik permintaan bisa diuji mengirim header
// Authorization tanpa needing Firebase nyata.
vi.mock('./session', () => ({
  authorizationHeader: vi.fn(async () => ({ Authorization: 'Bearer token-sesi-uji' })),
}))

import { authorizationHeader } from './session'
import { requestWorkerScan, requestWorkerScanStream } from '../scanners/client'
import { requestSiteAnalysis } from '../website/client'
import { requestTurnstileVerification } from '../turnstile/client'

const SESSION_TOKEN = 'Bearer token-sesi-uji'

function stubFetch(status = 429): { fetchImpl: typeof fetch; headers: () => Record<string, string> } {
  const calls: Array<RequestInit | undefined> = []
  const fetchImpl = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
    calls.push(init)
    return new Response(JSON.stringify({ error: { code: 'rate_limited', message: 'uji' } }), {
      status,
      headers: { 'content-type': 'application/json' },
    })
  }) as unknown as typeof fetch
  return {
    fetchImpl,
    headers: () => (calls[0]?.headers ?? {}) as Record<string, string>,
  }
}

async function expectRejected(promise: Promise<unknown>): Promise<void> {
  await promise.then(
    () => {
      throw new Error('permintaan seharusnya ditolak backend')
    },
    () => undefined,
  )
}

afterEach(() => {
  vi.clearAllMocks()
  vi.unstubAllEnvs()
})

describe('penyisipan header sesi pada klien backend', () => {
  it('pemeriksaan reputasi non-stream mengirim bearer', async () => {
    const { fetchImpl, headers } = stubFetch()
    await expectRejected(
      requestWorkerScan('https://api.test', 'https://contoh.com', { fetchImpl }),
    )

    expect(headers()['Authorization']).toBe(SESSION_TOKEN)
    expect(headers()['Content-Type']).toBe('application/json')
  })

  it('pemeriksaan reputasi stream mengirim bearer', async () => {
    const { fetchImpl, headers } = stubFetch()
    await expectRejected(
      requestWorkerScanStream('https://api.test', 'https://contoh.com', 'pemeriksaan-uji', {
        fetchImpl,
      }),
    )

    expect(headers()['Authorization']).toBe(SESSION_TOKEN)
    expect(headers().Accept).toBe('text/event-stream')
  })

  it('analisis situs mengirim bearer', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'https://api.test')
    const { fetchImpl, headers } = stubFetch()
    await expectRejected(requestSiteAnalysis('https://contoh.com', { fetchImpl }))

    expect(headers()['Authorization']).toBe(SESSION_TOKEN)
  })

  it('verifikasi Turnstile mengirim bearer', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'https://api.test')
    const { fetchImpl, headers } = stubFetch()
    await expectRejected(requestTurnstileVerification('token-captcha', { fetchImpl }))

    expect(headers()['Authorization']).toBe(SESSION_TOKEN)
  })

  it('tanpa sesi, header Authorization tidak dikirim sama sekali', async () => {
    vi.mocked(authorizationHeader).mockResolvedValueOnce({})
    const { fetchImpl, headers } = stubFetch()
    await expectRejected(
      requestWorkerScan('https://api.test', 'https://contoh.com', { fetchImpl }),
    )

    expect(headers().Authorization).toBeUndefined()
  })
})

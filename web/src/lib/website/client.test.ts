import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ExternalScanRequestError } from '../scanners/errors'
import { isSiteAnalysisAvailable, requestSiteAnalysis } from './client'
import { siteAnalysisErrorMessage } from './errors'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function rawReport(overrides: Record<string, unknown> = {}) {
  const emptyLookup = { status: 'unavailable', source: 'tanpa probe', value: null, detail: null, queriedAt: '1970-01-01T00:00:00.000Z' }
  return {
    version: 1,
    target: 'https://contoh.com/',
    hostname: 'contoh.com',
    generatedAt: '2026-10-24T00:00:00.000Z',
    durationMs: 900,
    probe: { available: true, name: 'node-dns-tls-http', detail: null },
    website: {
      status: 'partial',
      identity: {
        hostname: 'contoh.com',
        addresses: { ...emptyLookup, status: 'success', value: [{ address: '93.184.216.34', kind: 'ipv4' }] },
        withheldAddresses: 0,
        asn: emptyLookup,
        intermediary: { state: 'no_signal', signals: [], note: 'Tidak ada sinyal perantara.' },
      },
      dns: [{ type: 'A', lookup: { ...emptyLookup, status: 'success', value: ['93.184.216.34'] } }],
      tls: { httpsAvailable: emptyLookup, certificate: emptyLookup, certificateSource: null },
      response: {
        request: emptyLookup,
        status: null,
        statusText: null,
        finalUrl: null,
        redirectCount: 0,
        elapsedMs: null,
        contentType: null,
        bytes: null,
        truncated: false,
        headers: [],
        withheldHeaders: 0,
      },
      notes: [],
    },
    technology: {
      status: 'unavailable',
      findings: [],
      categories: [],
      document: { inspected: false, bytesScanned: 0, truncated: false, contentType: null, detail: null },
      notes: [],
    },
    behavior: {
      status: 'unavailable',
      initialUrl: 'https://contoh.com/',
      redirects: [],
      redirectCount: 0,
      redirectOutcome: 'unavailable',
      hosts: [],
      resources: null,
      securityHeaders: [],
      cookies: [{ name: 'session', secure: true, httpOnly: true, sameSite: 'lax', hasExpiry: false, valueShown: true, value: 'isi-rahasia' }],
      cookiesCollected: true,
      observations: [],
      notes: [],
    },
    ...overrides,
  }
}

async function codeOf(action: () => Promise<unknown>): Promise<string> {
  try {
    await action()
  } catch (error) {
    return error instanceof ExternalScanRequestError ? error.code : `unexpected:${String(error)}`
  }
  return 'no-error'
}

describe('ketersediaan analisis situs di frontend', () => {
  beforeEach(() => {
    vi.stubEnv('VITE_API_BASE_URL', '')
    vi.stubEnv('VITE_SCANNER_WORKER_URL', '')
  })

  afterEach(() => {
    vi.unstubAllEnvs()
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('hanya aktif bila ada backend yang dikonfigurasi', () => {
    expect(isSiteAnalysisAvailable()).toBe(false)
    expect(isSiteAnalysisAvailable('   ', '  ')).toBe(false)
    expect(isSiteAnalysisAvailable('http://127.0.0.1:8787')).toBe(true)
    expect(isSiteAnalysisAvailable('', 'https://scanner.test')).toBe(true)
  })

  it('menolak berjalan tanpa backend, tanpa mencoba fetch', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    expect(await codeOf(() => requestSiteAnalysis('https://contoh.com/'))).toBe('worker_not_configured')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('membangun endpoint /site/analysis dari basis API yang dikonfigurasi', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'http://127.0.0.1:8787/')
    const fetchMock = vi.fn(
      async (_input: string | URL | Request, _init?: RequestInit) => jsonResponse(rawReport()),
    )
    vi.stubGlobal('fetch', fetchMock)

    await requestSiteAnalysis('https://contoh.com/')
    expect(fetchMock.mock.calls[0]?.[0]).toBe('http://127.0.0.1:8787/site/analysis')

    vi.stubEnv('VITE_API_BASE_URL', 'https://scanner.test/site/analysis')
    await requestSiteAnalysis('https://contoh.com/')
    expect(fetchMock.mock.calls[1]?.[0]).toBe('https://scanner.test/site/analysis')

    // Basis URL boleh berupa endpoint scanner lengkap; suffix scanner dilepas, bukan ditempel.
    vi.stubEnv('VITE_API_BASE_URL', 'https://scanner.test/scanUrlMultiSource')
    await requestSiteAnalysis('https://contoh.com/')
    expect(fetchMock.mock.calls[2]?.[0]).toBe('https://scanner.test/site/analysis')

    vi.stubEnv('VITE_API_BASE_URL', 'https://scanner.test/scan/stream/')
    await requestSiteAnalysis('https://contoh.com/')
    expect(fetchMock.mock.calls[3]?.[0]).toBe('https://scanner.test/site/analysis')

    vi.stubEnv('VITE_API_BASE_URL', 'https://scanner.test/scan')
    await requestSiteAnalysis('https://contoh.com/')
    expect(fetchMock.mock.calls[4]?.[0]).toBe('https://scanner.test/site/analysis')
  })

  it('mengirim POST dengan persetujuan, tanpa kredensial browser, dan tanpa cache', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'http://127.0.0.1:8787')
    const fetchMock = vi.fn(
      async (_input: string | URL | Request, _init?: RequestInit) => jsonResponse(rawReport()),
    )
    vi.stubGlobal('fetch', fetchMock)

    await requestSiteAnalysis('https://contoh.com/masuk')

    const init = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect(init.method).toBe('POST')
    expect(init.credentials).toBe('omit')
    expect(init.cache).toBe('no-store')
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json')
    expect(JSON.parse(String(init.body))).toEqual({ url: 'https://contoh.com/masuk', consent: true })
  })

  it('mengembalikan laporan yang sudah dinormalkan, bukan payload mentah', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'http://127.0.0.1:8787')
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(rawReport({ hostname: 'contoh.com\r\ndisuntik' }))),
    )

    const report = await requestSiteAnalysis('https://contoh.com/')
    expect(report.website.identity.addresses.value).toEqual([
      { address: '93.184.216.34', kind: 'ipv4' },
    ])
    expect(report.hostname).toBe('contoh.com disuntik')
    // Nilai cookie tidak pernah lolos walaupun backend mengirimnya.
    expect(report.behavior.cookies[0]?.valueShown).toBe(false)
    expect(JSON.stringify(report)).not.toContain('isi-rahasia')
  })

  it('memakai kode error dari backend bila ada', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'http://127.0.0.1:8787')
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse({ error: { code: 'invalid_url', message: 'URL tidak diizinkan.' } }, 400),
      ),
    )

    try {
      await requestSiteAnalysis('http://127.0.0.1/')
      throw new Error('Seharusnya gagal.')
    } catch (error) {
      expect(error).toBeInstanceOf(ExternalScanRequestError)
      const failure = error as ExternalScanRequestError
      expect(failure.code).toBe('invalid_url')
      expect(failure.message).toBe('URL tidak diizinkan.')
    }
  })

  it('memetakan status HTTP ke kode yang dikenal ketika body tidak menjelaskan', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'http://127.0.0.1:8787')

    const cases: Array<[number, string]> = [
      [403, 'origin_not_allowed'],
      [404, 'not_found'],
      [413, 'payload_too_large'],
      [429, 'site_rate_limited'],
      [500, 'internal'],
    ]

    for (const [status, expected] of cases) {
      vi.stubGlobal('fetch', vi.fn(async () => new Response('<html>rusak</html>', { status })))
      expect(await codeOf(() => requestSiteAnalysis('https://contoh.com/'))).toBe(expected)
    }
  })

  it('mengubah payload sampah menjadi laporan kosong, bukan data karangan', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'http://127.0.0.1:8787')
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({ version: 1, target: 42 })))

    const report = await requestSiteAnalysis('https://contoh.com/')
    expect(report.target).toBe('')
    expect(report.website.status).toBe('unavailable')
    expect(report.technology.status).toBe('unavailable')
    expect(report.behavior.status).toBe('unavailable')
    expect(report.website.identity.addresses.value).toBeNull()
  })

  it('menyatakan layanan tidak dapat dihubungi saat body bukan JSON laporan', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'http://127.0.0.1:8787')
    vi.stubGlobal('fetch', vi.fn(async () => new Response('<html>portal</html>', { status: 200 })))

    expect(await codeOf(() => requestSiteAnalysis('https://contoh.com/'))).toBe('unavailable')
  })

  it('melaporkan layanan tidak dapat dihubungi saat fetch gagal', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'http://127.0.0.1:8787')
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch')
      }),
    )

    expect(await codeOf(() => requestSiteAnalysis('https://contoh.com/'))).toBe('unavailable')
  })

  it('mengubah batas waktu klien menjadi error timeout, bukan data kosong', async () => {
    vi.useFakeTimers()
    vi.stubEnv('VITE_API_BASE_URL', 'http://127.0.0.1:8787')

    const fetchMock = vi.fn(
      (_input: string | URL | Request, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal
          const onAbort = () => {
            const error = new Error('aborted')
            error.name = 'AbortError'
            reject(error)
          }
          if (!signal) return
          if (signal.aborted) onAbort()
          else signal.addEventListener('abort', onAbort, { once: true })
        }),
    )
    vi.stubGlobal('fetch', fetchMock)

    let settled = 'pending'
    const request = requestSiteAnalysis('https://contoh.com/').then(
      () => {
        settled = 'resolved'
      },
      (error: unknown) => {
        settled = error instanceof ExternalScanRequestError ? error.code : 'other'
      },
    )

    await vi.advanceTimersByTimeAsync(44_000)
    expect(settled).toBe('pending')

    await vi.advanceTimersByTimeAsync(2_000)
    await request
    expect(settled).toBe('timeout')
  })

  it('membatalkan permintaan ketika pemanggil berhenti', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'http://127.0.0.1:8787')
    const controller = new AbortController()
    let seenSignal: AbortSignal | undefined

    vi.stubGlobal(
      'fetch',
      vi.fn((_input: string | URL | Request, init?: RequestInit) => {
        seenSignal = init?.signal ?? undefined
        return new Promise<Response>((_resolve, reject) => {
          const onAbort = () => {
            const error = new Error('aborted')
            error.name = 'AbortError'
            reject(error)
          }
          init?.signal?.addEventListener('abort', onAbort, { once: true })
        })
      }),
    )

    const request = requestSiteAnalysis('https://contoh.com/', { signal: controller.signal })
    await vi.waitFor(() => expect(seenSignal).toBeDefined())
    controller.abort()

    expect(await codeOf(() => request)).toBe('unavailable')
    expect(seenSignal?.aborted).toBe(true)
  })

  it('menerjemahkan kode galat menjadi pesan yang tidak menutupi penyebab', async () => {
    expect(
      siteAnalysisErrorMessage(new ExternalScanRequestError('invalid_url', 'URL ditolak.')),
    ).toContain('kebijakan keamanan layanan analisis situs')
    expect(siteAnalysisErrorMessage(new ExternalScanRequestError('site_rate_limited', 'x'))).toContain(
      'Coba lagi setelah jendela batas selesai',
    )
    // Kode yang tidak dikenal tidak boleh dibuat terlihat seperti kegagalan keamanan.
    expect(siteAnalysisErrorMessage(new ExternalScanRequestError('aneh', 'Pesan asli backend.'))).toBe(
      'Pesan asli layanan pemeriksaan.',
    )
    expect(siteAnalysisErrorMessage(new Error('boom'))).toContain('Reputasi Ancaman tidak berubah')
  })
})

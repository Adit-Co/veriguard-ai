import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  isMultiSourceEnabled,
  isWorkerConfigured,
  requestExternalScan,
  requestExternalScanStream,
  requestWorkerScan,
  requestWorkerScanStream,
} from './client'
import type { ScanProgressEvent, ScanUrlMultiSourceResponse } from './types'

function externalResponse(): ScanUrlMultiSourceResponse {
  const providers = [
    ['virustotal', 'VirusTotal'],
    ['urlscan', 'URLScan.io'],
    ['openphish', 'OpenPhish'],
    ['threatfox', 'ThreatFox (abuse.ch)'],
    ['radar', 'Cloudflare Radar URL Scanner'],
    ['otx', 'AlienVault OTX'],
    ['hybrid', 'Hybrid Analysis'],
    ['safebrowsing', 'Google Safe Browsing'],
  ] as const

  return {
    providers: providers.map(([id, label]) => ({
      id,
      label,
      status: 'success',
      verdict: 'clean',
      score: 0,
      summary: 'Tidak ditemukan indikasi.',
      signals: [],
      reason: null,
      durationMs: 120,
    })),
    sharedWithProviders: providers.map(([id]) => id),
    sensitiveUrl: false,
    privacyReasons: [],
    generatedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 250,
  }
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function workerFetch() {
  return vi.fn(async (_input: string | URL | Request, _init?: RequestInit) =>
    jsonResponse(externalResponse()),
  )
}

function sseResponse(events: unknown[]): Response {
  const body = events
    .map((event) => {
      const type =
        event && typeof event === 'object' && 'type' in event
          ? String((event as { type: unknown }).type)
          : 'message'
      return `event: ${type}\ndata: ${JSON.stringify(event)}\n\n`
    })
    .join('')

  return new Response(body, {
    status: 200,
    headers: { 'Content-Type': 'text/event-stream; charset=utf-8' },
  })
}

function streamEvents(): ScanProgressEvent[] {
  const response = externalResponse()
  return [
    {
      type: 'init',
      scanId: 'scan-1',
      startedAt: '2026-01-01T00:00:00.000Z',
      sensitiveUrl: false,
      privacyReasons: [],
      providers: [{ id: 'virustotal', label: 'VirusTotal', state: 'queued' }],
    },
    {
      type: 'provider',
      scanId: 'scan-1',
      provider: {
        id: 'virustotal',
        label: 'VirusTotal',
        state: 'completed',
        result: response.providers[0],
        shared: true,
      },
    },
    { type: 'done', scanId: 'scan-1', response },
  ]
}

describe('permintaan pemeriksaan eksternal', () => {
  beforeEach(() => {
    vi.stubEnv('VITE_API_BASE_URL', '')
    vi.stubEnv('VITE_SCANNER_WORKER_URL', '')
  })

  afterEach(() => {
    vi.unstubAllEnvs()
    vi.unstubAllGlobals()
  })

  it('aktif secara default dan hanya nonaktif bila flag eksplisit false', () => {
    expect(isMultiSourceEnabled(undefined)).toBe(true)
    expect(isMultiSourceEnabled('')).toBe(true)
    expect(isMultiSourceEnabled('true')).toBe(true)
    expect(isMultiSourceEnabled('false')).toBe(false)
    expect(isMultiSourceEnabled(' FALSE ')).toBe(false)
  })

  it('menganggap Worker terkonfigurasi hanya bila URL diisi', () => {
    expect(isWorkerConfigured(undefined)).toBe(false)
    expect(isWorkerConfigured('   ')).toBe(false)
    expect(isWorkerConfigured('https://scanner.test')).toBe(true)
    expect(isWorkerConfigured('   ', 'http://127.0.0.1:8787')).toBe(true)
  })

  it('mengutamakan VITE_API_BASE_URL di atas VITE_SCANNER_WORKER_URL', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'http://127.0.0.1:8787')
    vi.stubEnv('VITE_SCANNER_WORKER_URL', 'https://scanner.test')
    const fetchMock = workerFetch()
    vi.stubGlobal('fetch', fetchMock)

    await requestExternalScan('https://contoh.com/path')

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0][0]).toBe('http://127.0.0.1:8787/scan')
  })

  it('mengirim stream scan ke backend lokal yang dikonfigurasi', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'http://127.0.0.1:8787')
    const fetchMock = vi.fn(
      async (_input: string | URL | Request, _init?: RequestInit) => sseResponse(streamEvents()),
    )
    vi.stubGlobal('fetch', fetchMock)

    const result = await requestExternalScanStream('https://contoh.com/path', 'scan-1')

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0][0]).toBe('http://127.0.0.1:8787/scan/stream')
    expect(result.providers[0]?.id).toBe('virustotal')
  })

  it('menolak permintaan bila URL Worker belum dikonfigurasi', async () => {
    await expect(requestExternalScan('https://contoh.com/path')).rejects.toMatchObject({
      code: 'worker_not_configured',
    })
  })

  it('mengirim permintaan eksternal ke Worker yang dikonfigurasi', async () => {
    vi.stubEnv('VITE_SCANNER_WORKER_URL', 'https://scanner.test')
    const fetchMock = workerFetch()
    vi.stubGlobal('fetch', fetchMock)

    const result = await requestExternalScan('https://contoh.com/path')

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledWith(
      'https://scanner.test/scan',
      expect.objectContaining({
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: 'https://contoh.com/path', consent: true }),
      }),
    )
    expect(result.providers[0]?.id).toBe('virustotal')
  })

  it('mengirim URL ke Worker tanpa token dan dengan consent eksplisit', async () => {
    const fetchMock = workerFetch()
    const result = await requestWorkerScan('https://scanner.test/', 'https://contoh.com/path', {
      fetchImpl: fetchMock,
    })

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledWith(
      'https://scanner.test/scan',
      expect.objectContaining({
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: 'https://contoh.com/path', consent: true }),
      }),
    )
    expect(result.providers[0]?.id).toBe('virustotal')
  })

  it('menerjemahkan error Worker menjadi kode yang dapat ditampilkan UI', async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(
        { error: { code: 'rate_limited', message: 'Terlalu banyak permintaan.' } },
        429,
      ),
    )

    await expect(
      requestWorkerScan('https://scanner.test', 'https://contoh.com/path', {
        fetchImpl: fetchMock as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ code: 'rate_limited' })
  })

  it('membaca event SSE dan mengembalikan laporan done', async () => {
    const events = streamEvents()
    const fetchMock = vi.fn(async () => sseResponse(events))
    const onEvent = vi.fn()

    const result = await requestWorkerScanStream(
      'https://scanner.test',
      'https://contoh.com/path',
      'scan-1',
      {
        fetchImpl: fetchMock as unknown as typeof fetch,
        onEvent,
      },
    )

    expect(fetchMock).toHaveBeenCalledWith(
      'https://scanner.test/scan/stream',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          Accept: 'text/event-stream',
        }),
        body: JSON.stringify({
          url: 'https://contoh.com/path',
          consent: true,
          scanId: 'scan-1',
        }),
      }),
    )
    expect(onEvent.mock.calls.map(([event]) => event.type)).toEqual([
      'init',
      'provider',
      'done',
    ])
    expect(result.providers[0]?.id).toBe('virustotal')
  })

  it('memakai done SSE backend lama dengan 6 agen tanpa menyebut layanan tak terhubung', async () => {
    // Regresi: ketika roster frontend bertambah ke 8 agen tetapi backend masih
    // mengirim registry 6 agen, respons lama dulu ditolak validasi ketat dan
    // dibungkus sebagai "Layanan pemeriksaan eksternal tidak dapat dihubungi."
    const legacy = externalResponse()
    legacy.providers = legacy.providers.slice(0, 6)
    legacy.sharedWithProviders = legacy.sharedWithProviders.slice(0, 6)
    const fetchMock = vi.fn(async () =>
      sseResponse([
        {
          type: 'init',
          scanId: 'scan-legacy',
          startedAt: '2026-01-01T00:00:00.000Z',
          sensitiveUrl: false,
          privacyReasons: [],
          providers: legacy.providers.map((provider) => ({
            id: provider.id,
            label: provider.label,
            state: 'queued' as const,
          })),
        },
        ...legacy.providers.map((provider) => ({
          type: 'provider',
          scanId: 'scan-legacy',
          provider: {
            id: provider.id,
            label: provider.label,
            state: 'completed' as const,
            result: provider,
            shared: true,
          },
        })),
        { type: 'done', scanId: 'scan-legacy', response: legacy },
      ]),
    )

    const result = await requestWorkerScanStream(
      'https://scanner.test',
      'https://contoh.com/path',
      'scan-legacy',
      { fetchImpl: fetchMock as unknown as typeof fetch },
    )

    expect(result.providers).toHaveLength(6)
    expect(result.providers.every((provider) => provider.status === 'success')).toBe(true)
  })

  it('menerjemahkan event error SSE menjadi error Worker', async () => {
    const fetchMock = vi.fn(async () =>
      sseResponse([
        {
          type: 'error',
          scanId: 'scan-1',
          code: 'rate_limited',
          message: 'Terlalu banyak permintaan.',
        },
      ]),
    )

    await expect(
      requestWorkerScanStream(
        'https://scanner.test',
        'https://contoh.com/path',
        'scan-1',
        { fetchImpl: fetchMock as unknown as typeof fetch },
      ),
    ).rejects.toMatchObject({ code: 'rate_limited' })
  })

  it('membatasi buffer SSE yang mengalir tanpa pemisah event', async () => {
    const encoder = new TextEncoder()
    const body = new ReadableStream<Uint8Array>({
      start(stream) {
        stream.enqueue(encoder.encode('x'.repeat(1_000_001)))
        stream.close()
      },
    })
    const fetchMock = vi.fn(
      async () =>
        new Response(body, {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        }),
    )

    await expect(
      requestWorkerScanStream(
        'https://scanner.test',
        'https://contoh.com/path',
        'scan-1',
        { fetchImpl: fetchMock as unknown as typeof fetch },
      ),
    ).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('mendukung fallback JSON dari Worker lama', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(externalResponse()))

    const result = await requestWorkerScanStream(
      'https://scanner.test',
      'https://contoh.com/path',
      'scan-1',
      { fetchImpl: fetchMock as unknown as typeof fetch },
    )

    expect(result.providers).toHaveLength(8)
  })

  it('mencoba endpoint JSON bila Worker lama tidak punya route stream', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ error: { code: 'not_found' } }, 404))
      .mockResolvedValueOnce(jsonResponse(externalResponse()))

    const result = await requestWorkerScanStream(
      'https://scanner.test',
      'https://contoh.com/path',
      'scan-1',
      { fetchImpl: fetchMock as unknown as typeof fetch },
    )

    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://scanner.test/scan',
      expect.objectContaining({ method: 'POST' }),
    )
    expect(result.providers).toHaveLength(8)
  })

  it('menolak respons Worker yang tidak valid', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ providers: [] }))

    await expect(
      requestWorkerScan('https://scanner.test', 'https://contoh.com/path', {
        fetchImpl: fetchMock as unknown as typeof fetch,
      }),
    ).rejects.toThrow('Respons pemeriksaan eksternal tidak valid.')
  })

  it('tidak memulai permintaan bila sinyal sudah dibatalkan', async () => {
    const controller = new AbortController()
    controller.abort()
    const fetchMock = vi.fn()

    await expect(
      requestWorkerScanStream('https://scanner.test', 'https://contoh.com/path', 'scan-1', {
        fetchImpl: fetchMock as unknown as typeof fetch,
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ code: 'cancelled' })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('membedakan pembatalan pengguna dari timeout saat stream aktif', async () => {
    const controller = new AbortController()
    const onEvent = vi.fn()
    const encoder = new TextEncoder()
    const initEvent = streamEvents()[0]!
    const body = new ReadableStream<Uint8Array>({
      start(stream) {
        stream.enqueue(
          encoder.encode(`event: init\ndata: ${JSON.stringify(initEvent)}\n\n`),
        )
      },
    })
    const fetchMock = vi.fn(
      async () =>
        new Response(body, {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        }),
    )

    const promise = requestWorkerScanStream(
      'https://scanner.test',
      'https://contoh.com/path',
      'scan-1',
      {
        fetchImpl: fetchMock as unknown as typeof fetch,
        signal: controller.signal,
        onEvent,
      },
    )
    const assertion = expect(promise).rejects.toMatchObject({ code: 'cancelled' })

    await vi.waitFor(() => expect(onEvent).toHaveBeenCalledTimes(1))
    controller.abort()
    await assertion
  })

  it('pembatalan satu permintaan tidak membatalkan permintaan lain', async () => {
    const first = new AbortController()
    const second = new AbortController()
    const seenSignals: AbortSignal[] = []
    const fetchMock = vi.fn(
      (_input: string | URL | Request, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal
          if (!signal) throw new Error('sinyal fetch tidak tersedia')
          seenSignals.push(signal)
          signal.addEventListener(
            'abort',
            () => reject(new DOMException('Aborted', 'AbortError')),
            { once: true },
          )
        }),
    )
    const options = {
      fetchImpl: fetchMock as unknown as typeof fetch,
    }

    const firstRequest = requestWorkerScan('https://scanner.test', 'https://satu.example', {
      ...options,
      signal: first.signal,
    })
    const firstAssertion = expect(firstRequest).rejects.toMatchObject({ code: 'cancelled' })
    const secondRequest = requestWorkerScan('https://scanner.test', 'https://dua.example', {
      ...options,
      signal: second.signal,
    })
    let secondSettled = false
    secondRequest.then(
      () => {
        secondSettled = true
      },
      () => {
        secondSettled = true
      },
    )

    await vi.waitFor(() => expect(seenSignals).toHaveLength(2))
    first.abort()
    await firstAssertion

    expect(seenSignals[0]?.aborted).toBe(true)
    expect(seenSignals[1]?.aborted).toBe(false)
    expect(secondSettled).toBe(false)

    second.abort()
    await expect(secondRequest).rejects.toMatchObject({ code: 'cancelled' })
  })

  it('membatalkan permintaan Worker setelah timeout', async () => {
    vi.useFakeTimers()
    try {
      const fetchMock = vi.fn(
        (_input: RequestInfo | URL, init?: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () => {
              reject(new DOMException('Aborted', 'AbortError'))
            })
          }),
      )
      const promise = requestWorkerScan('https://scanner.test', 'https://contoh.com/path', {
        fetchImpl: fetchMock as unknown as typeof fetch,
      })
      let outcome: 'pending' | 'rejected' = 'pending'
      promise.catch(() => {
        outcome = 'rejected'
      })

      // Anggaran waktu backend (80 detik) harus habis lebih dulu. Klien yang memutus
      // permintaan sebelum batas itu membuat agen yang sebenarnya menjawab tampil sebagai
      // "timeout", jadi batas klien wajib lebih panjang.
      await vi.advanceTimersByTimeAsync(80_000)
      expect(outcome).toBe('pending')

      await vi.advanceTimersByTimeAsync(10_000)
      await expect(promise).rejects.toThrow('timeout')
      expect(outcome).toBe('rejected')
    } finally {
      vi.useRealTimers()
    }
  })

  it('tidak mengirim captchaToken bila tidak diminta', async () => {
    const fetchMock = workerFetch()
    await requestWorkerScan('https://scanner.test', 'https://contoh.com/path', {
      fetchImpl: fetchMock as unknown as typeof fetch,
    })

    const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body)) as Record<string, unknown>
    expect(body).toEqual({ url: 'https://contoh.com/path', consent: true })
    expect('captchaToken' in body).toBe(false)
  })

  it('mengirim token CAPTCHA hasil verifikasi pada permintaan ulang pemeriksaan', async () => {
    const fetchMock = workerFetch()
    await requestWorkerScan('https://scanner.test', 'https://contoh.com/path', {
      fetchImpl: fetchMock as unknown as typeof fetch,
      captchaToken: 'token-captcha',
    })

    const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body)) as Record<string, unknown>
    expect(body).toEqual({
      url: 'https://contoh.com/path',
      consent: true,
      captchaToken: 'token-captcha',
    })
  })

  it('membaca 428 sebagai captcha_required dan tidak menjalankan pemeriksaan', async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ error: { code: 'captcha_required', message: 'Perlu verifikasi.' } }, 428),
    )

    await expect(
      requestWorkerScan('https://scanner.test', 'https://contoh.com/path', {
        fetchImpl: fetchMock as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ code: 'captcha_required' })
  })

  it('memakai kode status 428 bila layanan tidak menyertakan kode pada error', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({}, 428))

    await expect(
      requestWorkerScan('https://scanner.test', 'https://contoh.com/path', {
        fetchImpl: fetchMock as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ code: 'captcha_required' })
  })

  it('meneruskan captchaToken dan token yang sama ke jalur stream dan fallback-nya', async () => {
    const calls: Array<{ url: string; body: Record<string, unknown> }> = []
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>
      calls.push({ url: String(input), body })
      if (body.scanId) return jsonResponse({ error: { code: 'captcha_invalid' } }, 428)
      return jsonResponse(externalResponse())
    })

    await expect(
      requestWorkerScanStream('https://scanner.test', 'https://contoh.com/path', 'scan-abc-123', {
        fetchImpl: fetchMock as unknown as typeof fetch,
        captchaToken: 'token-stream',
      }),
    ).rejects.toMatchObject({ code: 'captcha_invalid' })

    expect(calls[0]?.url).toBe('https://scanner.test/scan/stream')
    expect(calls[0]?.body).toEqual({
      url: 'https://contoh.com/path',
      consent: true,
      scanId: 'scan-abc-123',
      captchaToken: 'token-stream',
    })
  })

  it('meneruskan captchaToken saat worker lama jatuh ke permintaan JSON', async () => {
    const calls: Array<Record<string, unknown>> = []
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>
      calls.push(body)
      // Permintaan stream pertama ditolak 404 (worker lama) lalu fallback JSON dipakai.
      return body.scanId
        ? jsonResponse({ error: { message: 'tidak ada' } }, 404)
        : jsonResponse(externalResponse())
    })

    await requestWorkerScanStream('https://scanner.test', 'https://contoh.com/path', 'scan-abc-123', {
      fetchImpl: fetchMock as unknown as typeof fetch,
      captchaToken: 'token-fallback',
    })

    expect(calls).toHaveLength(2)
    expect(calls[1]).toEqual({
      url: 'https://contoh.com/path',
      consent: true,
      captchaToken: 'token-fallback',
    })
  })
})

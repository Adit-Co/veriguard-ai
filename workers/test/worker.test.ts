import { describe, expect, it, vi } from 'vitest'
import type {
  MultiSourceScanResponse,
  ProviderResult,
  ScanProgressEvent,
} from '../../functions/src/scanners/types.js'
import type { RunMultiSourceScanInput } from '../../functions/src/scanners/service.js'
import type { RateLimitDecision } from '../../functions/src/state/stores.js'
import { ScanUrlError } from '../../functions/src/scanners/url.js'
import { createWorker, createWorkerFetch, type Env } from '../src/index.js'
import { createStateStoreSpy } from './helpers/stateStore.js'

const ORIGIN = 'http://localhost:5173'
const NOW = 1_700_000_000_000

const ENV: Env = {
  ALLOWED_ORIGINS: ORIGIN,
  RATE_LIMIT_MAX_PER_IP: '30',
  RATE_LIMIT_WINDOW_SECONDS: '60',
  URLSCAN_API_KEY: 'urlscan-test',
  VIRUSTOTAL_API_KEY: 'vt-test',
  OPENPHISH_API_KEY: 'op-test',
  THREATFOX_API_KEY: 'tf-test',
  CLOUDFLARE_API_TOKEN: 'cf-test',
  CLOUDFLARE_ACCOUNT_ID: 'cf-account-test',
  OTX_API_KEY: 'otx-test',
  GOOGLE_SAFE_BROWSING_API_KEY: 'gsb-test',
  HYBRID_ANALYSIS_API_KEY: 'hybrid-test',
}

function provider(overrides: Partial<ProviderResult> = {}): ProviderResult {
  return {
    id: 'virustotal',
    label: 'VirusTotal',
    status: 'success',
    verdict: 'clean',
    score: 0,
    summary: 'Tidak ditemukan indikasi.',
    signals: [],
    reason: null,
    durationMs: 120,
    ...overrides,
  }
}

function scanResponse(overrides: Partial<MultiSourceScanResponse> = {}): MultiSourceScanResponse {
  return {
    providers: [provider()],
    sharedWithProviders: ['virustotal'],
    sensitiveUrl: false,
    privacyReasons: [],
    generatedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 250,
    ...overrides,
  }
}

function makeDeps(overrides: Record<string, unknown> = {}) {
  const spy = createStateStoreSpy()
  return {
    runScan: vi.fn(async () => scanResponse()),
    state: spy.store,
    spy,
    now: () => NOW,
    ...overrides,
  }
}

async function invoke(
  worker: ExportedHandler<Env>,
  request: Request,
  env: Env = ENV,
): Promise<Response> {
  if (!worker.fetch) throw new Error('Worker fetch handler tidak tersedia.')
  return worker.fetch(
    request as unknown as Request<unknown, IncomingRequestCfProperties<unknown>>,
    env,
    {} as ExecutionContext,
  )
}

function post(
  body: unknown,
  headers: Record<string, string> = {},
  path = '/scan',
): Request {
  return new Request(`https://worker.test${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'CF-Connecting-IP': '203.0.113.10',
      Origin: ORIGIN,
      ...headers,
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}

function parseSse(text: string): Array<{ event: string; data: unknown }> {
  return text
    .split('\n\n')
    .filter((block) => block.trim() && !block.trim().startsWith(':'))
    .map((block) => {
      const lines = block.split('\n')
      const event = lines.find((line) => line.startsWith('event: '))?.slice(7) ?? ''
      const data = lines.find((line) => line.startsWith('data: '))?.slice(6) ?? ''
      return { event, data: JSON.parse(data) as unknown }
    })
}

describe('Cloudflare Worker scanner', () => {
  it('meneruskan URL, uid tamu, consent, dan config tanpa membocorkan secret', async () => {
    const deps = makeDeps()
    const worker = createWorker(deps)
    const response = await invoke(worker, post({ url: 'https://contoh.com', consent: true }))

    expect(response.status).toBe(200)
    expect(response.headers.get('access-control-allow-origin')).toBe(ORIGIN)
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(await response.json()).toEqual(scanResponse())
    expect(deps.runScan).toHaveBeenCalledWith({
      uid: 'guest:203.0.113.10',
      url: 'https://contoh.com',
      config: {
        urlscanApiKey: 'urlscan-test',
        virusTotalApiKey: 'vt-test',
        openPhishApiKey: 'op-test',
        threatFoxApiKey: 'tf-test',
        cloudflareApiToken: 'cf-test',
        cloudflareAccountId: 'cf-account-test',
        otxApiKey: 'otx-test',
        googleSafeBrowsingApiKey: 'gsb-test',
        hybridAnalysisApiKey: 'hybrid-test',
        // Kebijakan cache ikut diteruskan. Tidak ada nilai rahasia di dalam objek config
        // yang sampai ke scanner, dan scanner tetap menerima seluruh kebijakannya.
        scanCache: expect.objectContaining({ enabled: true }),
      },
      // Sinyal pembatalan klien harus diteruskan supaya permintaan provider berhenti
      // ketika koneksi ditutup; tanpa ini tes akan lolos meski scanner terus berjalan.
      signal: expect.any(AbortSignal),
      // Kuota pemeriksaan diserahkan sebagai konsumen dari state bersama; isinya diuji
      // terpisah di bawah, jadi di sini cukup bentuknya yang dipastikan ada.
      consumeRateLimit: expect.any(Function),
    })
    expect(deps.spy.counters).toEqual([
      { key: 'ip:203.0.113.10', limit: 30, windowMs: 60_000, now: NOW },
    ])
  })

  it('menghitung kuota pemeriksaan di state bersama, bukan di memori isolate', async () => {
    let quota: RunMultiSourceScanInput['consumeRateLimit']
    const deps = makeDeps({
      runScan: vi.fn(async (input: RunMultiSourceScanInput) => {
        quota = input.consumeRateLimit
        return scanResponse()
      }),
    })
    const worker = createWorker(deps)

    await invoke(worker, post({ url: 'https://contoh.com', consent: true }))
    expect(quota).toBeTypeOf('function')

    const decision = await quota?.('uid-terverifikasi', NOW)

    expect(decision?.allowed).toBe(true)
    // Kunci dipisah dari batas laju HTTP per-permintaan supaya satu jendela tidak memakan
    // jendela lain, dan angkanya tetap batas scanner yang sama dengan jalur lokal.
    expect(deps.spy.counters).toContainEqual({
      key: 'scan:uid-terverifikasi',
      limit: 6,
      windowMs: 600_000,
      now: NOW,
    })
  })

  it('kuota bersama yang habis menghentikan provider sebelum ada permintaan keluar', async () => {
    let observed: RateLimitDecision | undefined
    const worker = createWorker(
      makeDeps({
        state: createStateStoreSpy({
          counter: (call) =>
            call.key.startsWith('scan:')
              ? { allowed: false, retryAfterSeconds: 300 }
              : { allowed: true, retryAfterSeconds: 0 },
        }).store,
        runScan: vi.fn(async (input: RunMultiSourceScanInput) => {
          observed = await input.consumeRateLimit?.(input.uid, NOW)
          return scanResponse()
        }),
      }),
    )

    const response = await invoke(worker, post({ url: 'https://contoh.com', consent: true }))

    expect(response.status).toBe(200)
    expect(observed).toEqual({ allowed: false, retryAfterSeconds: 300 })
  })

  it('memproses scan tanpa token autentikasi apa pun', async () => {
    const worker = createWorker(makeDeps())
    const response = await invoke(
      worker,
      post({ url: 'https://contoh.com', consent: true }),
    )
    expect(response.status).toBe(200)
  })

  it('mewajibkan consent eksplisit sebelum memindai', async () => {
    const deps = makeDeps()
    const worker = createWorker(deps)
    const response = await invoke(worker, post({ url: 'https://contoh.com' }))

    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({
      error: { code: 'consent_required' },
    })
    expect(deps.runScan).not.toHaveBeenCalled()
  })

  it('memetakan URL tidak aman dan kegagalan scanner ke error HTTP yang tepat', async () => {
    const invalidUrl = createWorker(
      makeDeps({
        runScan: vi.fn(async () => {
          throw new ScanUrlError('Alamat lokal atau privat tidak dapat diperiksa.')
        }),
      }),
    )
    const invalid = await invoke(
      invalidUrl,
      post({ url: 'http://127.0.0.1', consent: true }),
    )
    expect(invalid.status).toBe(400)
    expect(await invalid.json()).toMatchObject({
      error: { code: 'invalid_url' },
    })

    const failed = createWorker(
      makeDeps({
        runScan: vi.fn(async () => {
          throw new Error('boom')
        }),
      }),
    )
    const internal = await invoke(failed, post({ url: 'https://contoh.com', consent: true }))
    expect(internal.status).toBe(500)
    expect(await internal.json()).toMatchObject({
      error: { code: 'internal' },
    })
  })

  it('mengembalikan status provider gagal tanpa mengubah kontrak respons', async () => {
    const responseBody = scanResponse({
      providers: [
        provider({
          id: 'urlscan',
          label: 'URLScan.io',
          status: 'rate_limited',
          verdict: 'inconclusive',
          score: null,
          summary: 'Kuota provider tercapai.',
          reason: 'Coba lagi nanti.',
        }),
        provider({
          id: 'radar',
          label: 'Cloudflare Radar URL Scanner',
          status: 'not_configured',
          verdict: 'inconclusive',
          score: null,
          summary: 'Belum dikonfigurasi.',
        }),
      ],
      sharedWithProviders: ['urlscan'],
    })
    const worker = createWorker(
      makeDeps({ runScan: vi.fn(async () => responseBody) }),
    )
    const response = await invoke(
      worker,
      post({ url: 'https://contoh.com', consent: true }),
    )

    expect(response.status).toBe(200)
    expect(await response.json()).toEqual(responseBody)
  })

  it('menegakkan rate limit edge dan mengirim Retry-After', async () => {
    const runScan = vi.fn(async () => scanResponse())
    const worker = createWorker(
      makeDeps({
        runScan,
        state: createStateStoreSpy({
          allow: false,
          retryAfterSeconds: 42,
        }).store,
      }),
    )
    const response = await invoke(worker, post({ url: 'https://contoh.com', consent: true }))

    expect(response.status).toBe(429)
    expect(response.headers.get('retry-after')).toBe('42')
    expect(runScan).not.toHaveBeenCalled()
    expect(await response.json()).toMatchObject({
      error: { code: 'rate_limited' },
    })
  })

  it('menangani preflight, origin asing, metode, path, dan payload tidak valid', async () => {
    const worker = createWorker(makeDeps())

    const preflight = await invoke(
      worker,
      new Request('https://worker.test/scan', {
        method: 'OPTIONS',
        headers: {
          Origin: ORIGIN,
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'authorization,content-type',
        },
      }),
    )
    expect(preflight.status).toBe(204)
    expect(preflight.headers.get('access-control-allow-origin')).toBe(ORIGIN)
    expect(preflight.headers.get('access-control-allow-methods')).toContain('POST')

    const foreignOrigin = await invoke(
      worker,
      post({ url: 'https://contoh.com', consent: true }, { Origin: 'https://evil.example' }),
    )
    expect(foreignOrigin.status).toBe(403)
    expect(foreignOrigin.headers.get('access-control-allow-origin')).toBeNull()

    const wrongMethod = await invoke(
      worker,
      new Request('https://worker.test/scan', { method: 'GET' }),
    )
    expect(wrongMethod.status).toBe(405)
    expect(wrongMethod.headers.get('allow')).toContain('POST')

    const wrongPath = await invoke(
      worker,
      new Request('https://worker.test/admin', { method: 'POST' }),
    )
    expect(wrongPath.status).toBe(404)

    const wrongContentType = await invoke(
      worker,
      post({ url: 'https://contoh.com', consent: true }, { 'Content-Type': 'text/plain' }),
    )
    expect(wrongContentType.status).toBe(415)

    const invalidJson = await invoke(worker, post('{bukan-json'))
    expect(invalidJson.status).toBe(400)
    expect(await invalidJson.json()).toMatchObject({
      error: { code: 'invalid_request' },
    })

    const tooLarge = await invoke(
      worker,
      post({ url: 'https://contoh.com', consent: true, padding: 'x'.repeat(17_000) }),
    )
    expect(tooLarge.status).toBe(413)
    expect(await tooLarge.json()).toMatchObject({
      error: { code: 'payload_too_large' },
    })
  })

  it('mengizinkan klien non-browser tanpa Origin tetapi tanpa header CORS', async () => {
    const worker = createWorker(makeDeps())
    const response = await invoke(
      worker,
      post({ url: 'https://contoh.com', consent: true }, { Origin: '' }),
    )

    expect(response.status).toBe(200)
    expect(response.headers.get('access-control-allow-origin')).toBeNull()
  })
})

describe('Cloudflare Worker scan stream', () => {
  const initEvent: ScanProgressEvent = {
    type: 'init',
    scanId: 'scan-stream-1',
    startedAt: '2026-01-01T00:00:00.000Z',
    sensitiveUrl: false,
    privacyReasons: [],
    providers: [{ id: 'virustotal', label: 'VirusTotal', state: 'queued' }],
  }
  const doneEvent: ScanProgressEvent = {
    type: 'done',
    scanId: 'scan-stream-1',
    response: scanResponse(),
  }

  it('mewajibkan scanId dan memvalidasi URL sebelum stream dibuka', async () => {
    const deps = makeDeps()
    const worker = createWorker(deps)

    const missing = await invoke(
      worker,
      post({ url: 'https://contoh.com', consent: true }, {}, '/scan/stream'),
    )
    expect(missing.status).toBe(400)
    expect(await missing.json()).toMatchObject({
      error: { code: 'invalid_scan_id' },
    })

    const invalid = await invoke(
      worker,
      post(
        { url: 'http://127.0.0.1', consent: true, scanId: 'scan-stream-1' },
        {},
        '/scan/stream',
      ),
    )
    expect(invalid.status).toBe(400)
    expect(await invalid.json()).toMatchObject({
      error: { code: 'invalid_url' },
    })
    expect(deps.runScan).not.toHaveBeenCalled()
  })

  it('mengirim event SSE berurutan dengan header yang tidak di-buffer', async () => {
    const events: ScanProgressEvent[] = [
      initEvent,
      {
        type: 'provider',
        scanId: 'scan-stream-1',
        provider: { id: 'virustotal', label: 'VirusTotal', state: 'running' },
      },
      {
        type: 'provider',
        scanId: 'scan-stream-1',
        provider: {
          id: 'virustotal',
          label: 'VirusTotal',
          state: 'completed',
          result: provider(),
          shared: true,
        },
      },
      doneEvent,
    ]
    const runScan = vi.fn(async (input: RunMultiSourceScanInput) => {
      for (const event of events) {
        await input.onEvent?.(event)
      }
      return scanResponse()
    })
    const worker = createWorker(makeDeps({ runScan }))
    const response = await invoke(
      worker,
      post(
        { url: 'https://contoh.com', consent: true, scanId: 'scan-stream-1' },
        { Accept: 'text/event-stream' },
        '/scan/stream',
      ),
      { ...ENV, PROVIDER_CONCURRENCY: '2' },
    )

    expect(response.status).toBe(200)
    expect(response.headers.get('content-type')).toContain('text/event-stream')
    expect(response.headers.get('cache-control')).toContain('no-cache')
    expect(response.headers.get('x-accel-buffering')).toBe('no')
    expect(response.headers.get('access-control-allow-origin')).toBe(ORIGIN)

    const parsed = parseSse(await response.text())
    expect(parsed.map((entry) => entry.event)).toEqual([
      'init',
      'provider',
      'provider',
      'done',
    ])
    expect(parsed[0]?.data).toMatchObject({ type: 'init', scanId: 'scan-stream-1' })
    expect(parsed[3]?.data).toMatchObject({ type: 'done', scanId: 'scan-stream-1' })
    expect(runScan).toHaveBeenCalledWith(
      expect.objectContaining({
        uid: 'guest:203.0.113.10',
        url: 'https://contoh.com',
        scanId: 'scan-stream-1',
        concurrency: 2,
        onEvent: expect.any(Function),
        signal: expect.any(AbortSignal),
      }),
    )
  })

  it('mengirim event error SSE tanpa mengubah status HTTP setelah stream dibuka', async () => {
    const worker = createWorker(
      makeDeps({
        runScan: vi.fn(async () => {
          throw new Error('boom')
        }),
      }),
    )
    const response = await invoke(
      worker,
      post(
        { url: 'https://contoh.com', consent: true, scanId: 'scan-stream-1' },
        {},
        '/scan/stream',
      ),
    )

    expect(response.status).toBe(200)
    const parsed = parseSse(await response.text())
    expect(parsed).toHaveLength(1)
    expect(parsed[0]?.event).toBe('error')
    expect(parsed[0]?.data).toMatchObject({
      type: 'error',
      scanId: 'scan-stream-1',
      code: 'internal',
    })
  })

  it('melengkapi event done bila implementasi runScan tidak mengirimkannya', async () => {
    const worker = createWorker(
      makeDeps({
        runScan: vi.fn(async (input: RunMultiSourceScanInput) => {
          await input.onEvent?.(initEvent)
          return scanResponse()
        }),
      }),
    )
    const response = await invoke(
      worker,
      post(
        { url: 'https://contoh.com', consent: true, scanId: 'scan-stream-1' },
        {},
        '/scan/stream',
      ),
    )

    const parsed = parseSse(await response.text())
    expect(parsed.map((entry) => entry.event)).toEqual(['init', 'done'])
    expect(parsed[1]?.data).toMatchObject({
      type: 'done',
      scanId: 'scan-stream-1',
      response: scanResponse(),
    })
  })
})

describe('createWorkerFetch', () => {
  it('menerjemahkan redirect error menjadi manual untuk Cloudflare', async () => {
    const base = vi.fn(async () => new Response('ok', { status: 200 }))
    const workerFetch = createWorkerFetch(base as unknown as typeof fetch)

    const response = await workerFetch('https://contoh.com/api', {
      method: 'POST',
      redirect: 'error',
    })

    expect(response.status).toBe(200)
    expect(base).toHaveBeenCalledWith(
      'https://contoh.com/api',
      expect.objectContaining({ method: 'POST', redirect: 'manual' }),
    )
  })

  it('menolak respons redirect dengan semantik redirect error', async () => {
    const base = vi.fn(
      async () => new Response(null, { status: 302, headers: { Location: 'https://lain.com' } }),
    )
    const workerFetch = createWorkerFetch(base as unknown as typeof fetch)

    await expect(workerFetch('https://contoh.com', { redirect: 'error' })).rejects.toThrow(
      'redirect not allowed',
    )
  })
})

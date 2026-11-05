import { describe, expect, it, vi } from 'vitest'
import type {
  OriginResult,
  RecordQueryResult,
  ResolveResult,
  SiteAnalysisResponse,
  SiteProbe,
} from '../../functions/src/website/types.js'
import { resetSiteAnalysisRateLimit } from '../../functions/src/website/limits.js'
import { createWorker, type Env } from '../src/index.js'
import { createMemoryStateStore } from '../src/state/store.js'
import { resetEdgeRateLimit } from '../src/rateLimit.js'
import { createStateStoreSpy } from './helpers/stateStore.js'

const ORIGIN = 'http://localhost:5173'
const NOW = 1_700_000_000_000

const ENV: Env = {
  ALLOWED_ORIGINS: ORIGIN,
  RATE_LIMIT_MAX_PER_IP: '30',
  RATE_LIMIT_WINDOW_SECONDS: '60',
}

function fakeProbe(): SiteProbe {
  return {
    name: 'probe-uji',
    dnsSource: 'probe uji',
    resolve: async (): Promise<ResolveResult> => ({ ipv4: ['93.184.216.34'], ipv6: [], detail: null }),
    queryRecords: async (_hostname, type): Promise<RecordQueryResult> =>
      type === 'A'
        ? { records: ['93.184.216.34'], outcome: 'answered', detail: null }
        : { records: [], outcome: 'empty', detail: 'Kueri selesai tanpa record untuk tipe ini.' },
    lookupAsn: async () => ({
      info: { asn: 'AS15133', organization: null, country: 'US', prefix: '93.184.216.0/24', registry: 'arin' },
      outcome: 'answered',
      detail: null,
    }),
    inspectTls: async () => ({
      certificate: null,
      httpsReachable: false,
      outcome: 'empty',
      detail: 'Tidak dicoba karena origin sudah memakai TLS.',
    }),
    openOrigin: async (): Promise<OriginResult> => ({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: [
        ['content-type', 'text/html; charset=utf-8'],
        ['server', 'nginx'],
      ],
      body: '<html><body><script src="https://cdn.example/app.js"></script></body></html>',
      bytes: 60,
      truncated: false,
      elapsedMs: 15,
      tls: {
        protocol: 'TLSv1.3',
        cipher: 'AES-256-GCM',
        issuer: 'R3',
        subject: 'example.com',
        notBefore: '2026-01-01T00:00:00.000Z',
        notAfter: '2026-12-31T00:00:00.000Z',
        authorized: true,
        authorizationError: null,
      },
    }),
  }
}

function makeDeps(overrides: Record<string, unknown> = {}) {
  return {
    runScan: vi.fn(async () => ({
      providers: [],
      sharedWithProviders: [],
      sensitiveUrl: false,
      privacyReasons: [],
      generatedAt: '2026-01-01T00:00:00.000Z',
      durationMs: 1,
    })),
    state: createStateStoreSpy().store,
    now: () => NOW,
    siteProbe: fakeProbe(),
    ...overrides,
  }
}

type Deps = ReturnType<typeof makeDeps>

async function post(
  deps: Deps,
  body: unknown,
  options: { path?: string; headers?: Record<string, string>; method?: string; origin?: string | null } = {},
): Promise<Response> {
  resetEdgeRateLimit()
  const method = options.method ?? 'POST'
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'CF-Connecting-IP': '203.0.113.10',
    ...options.headers,
  }
  if (options.origin !== null) headers.Origin = options.origin ?? ORIGIN

  const init: RequestInit = { method, headers }
  if (method === 'POST') {
    init.body = body === null ? '{}' : typeof body === 'string' ? body : JSON.stringify(body)
  }

  const worker = createWorker(deps as never)
  if (!worker.fetch) throw new Error('Handler fetch tidak tersedia.')
  return worker.fetch(new Request(`https://worker.test${options.path ?? '/site/analysis'}`, init) as never, ENV, {} as never)
}

async function errorCodeOf(response: Response): Promise<string> {
  const body = (await response.json()) as { error?: { code?: string } }
  return body.error?.code ?? ''
}

async function reportOf(response: Response): Promise<SiteAnalysisResponse> {
  return (await response.json()) as unknown as SiteAnalysisResponse
}

describe('POST /site/analysis', () => {
  it('mengembalikan tiga bagian analisis dari probe platform', async () => {
    const response = await post(makeDeps(), { url: 'https://example.com', consent: true })
    expect(response.status).toBe(200)
    expect(response.headers.get('access-control-allow-origin')).toBe(ORIGIN)

    const body = await reportOf(response)
    expect(body.probe).toMatchObject({ available: true, name: 'probe-uji' })
    expect(body.website.identity.addresses.value).toEqual([{ address: '93.184.216.34', kind: 'ipv4' }])
    expect(body.website.tls.certificate.status).toBe('success')
    expect(body.website.dns.find((entry) => entry.type === 'AAAA')?.lookup.status).toBe('empty')
    expect(body.technology.findings.map((entry) => entry.name)).toContain('nginx')
    expect(body.behavior.hosts.map((entry) => entry.host)).toContain('cdn.example')
    expect(body.version).toBe(1)
  })

  it('menyatakan unavailable ketika platform tidak menyediakan probe', async () => {
    const response = await post(makeDeps({ siteProbe: null }), { url: 'https://example.com', consent: true })
    expect(response.status).toBe(200)
    const body = await reportOf(response)
    expect(body.probe.available).toBe(false)
    expect(body.website.status).toBe('unavailable')
    expect(body.behavior.status).toBe('unavailable')
    expect(body.technology.status).toBe('unavailable')
    expect(body.website.notes.join(' ')).toContain('Tidak ada permintaan yang dikirim ke target')
  })

  it('mewajibkan persetujuan eksplisit', async () => {
    const response = await post(makeDeps(), { url: 'https://example.com' })
    expect(response.status).toBe(400)
    expect(await errorCodeOf(response)).toBe('consent_required')
  })

  it('menolak URL non-HTTP dan target internal dengan 400 invalid_url', async () => {
    resetSiteAnalysisRateLimit()
    for (const url of ['http://127.0.0.1/', 'ftp://example.com/', 'bukan-url!!', 'http://localhost:8080/']) {
      const response = await post(makeDeps(), { url, consent: true })
      expect(response.status).toBe(400)
      expect(await errorCodeOf(response)).toBe('invalid_url')
    }
  })

  it('menegakkan batas metode, tipe konten, path, dan ukuran body', async () => {
    const getX = await post(makeDeps(), null, { method: 'GET' })
    expect(getX.status).toBe(405)
    expect(getX.headers.get('allow')).toBe('POST, OPTIONS')

    const form = await post(makeDeps(), 'url=https://example.com', {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    expect(form.status).toBe(415)
    expect(await errorCodeOf(form)).toBe('unsupported_media_type')

    const unknown = await post(makeDeps(), { url: 'https://example.com', consent: true }, { path: '/site/unknown' })
    expect(unknown.status).toBe(404)
    expect(await errorCodeOf(unknown)).toBe('not_found')

    const huge = await post(makeDeps(), { url: `https://example.com/${'a'.repeat(20 * 1_024)}`, consent: true })
    expect(huge.status).toBe(413)
    expect(await errorCodeOf(huge)).toBe('payload_too_large')
  })

  it('menolak origin di luar allowlist sebelum memeriksa path', async () => {
    const response = await post(makeDeps(), { url: 'https://example.com', consent: true }, { origin: 'https://penyerang.test' })
    expect(response.status).toBe(403)
    expect(await errorCodeOf(response)).toBe('origin_not_allowed')
  })

  it('melayani preflight OPTIONS untuk endpoint baru', async () => {
    const response = await post(makeDeps(), null, { method: 'OPTIONS' })
    expect(response.status).toBe(204)
    expect(response.headers.get('access-control-allow-methods')).toContain('POST')
  })

  it('meneruskan Retry-After ketika batas analisis situs tercapai', async () => {
    const spy = createStateStoreSpy({
      siteWindow: () => ({ allowed: false, retryAfterSeconds: 900 }),
    })
    const response = await post(makeDeps({ state: spy.store }), { url: 'https://example.com', consent: true })
    expect(response.status).toBe(429)
    expect(response.headers.get('retry-after')).toBe('900')
    expect(await errorCodeOf(response)).toBe('site_rate_limited')
    // Kunci batas diturunkan dari identitas pemanggil, dan untuk tamu identitasnya per-IP.
    expect(spy.siteWindows).toEqual([{ key: expect.stringContaining('203.0.113.10'), now: NOW }])
  })

  it('hanya mengizinkan empat analisis per sepuluh menit per alamat', async () => {
    resetSiteAnalysisRateLimit()
    let clock = NOW
    // Store memori nyata (bukan spy): pembuktian batas 4 per 10 menit benar-benar bertumpu
    // pada jendela geser, bukan pada angka yang dikarang tes.
    const deps = makeDeps({ state: createMemoryStateStore(), now: () => clock })

    for (let index = 0; index < 4; index += 1) {
      const ok = await post(deps, { url: 'https://example.com', consent: true })
      expect(ok.status).toBe(200)
    }

    const blocked = await post(deps, { url: 'https://example.com', consent: true })
    expect(blocked.status).toBe(429)
    expect(Number(blocked.headers.get('retry-after'))).toBeGreaterThan(0)

    clock = NOW + 10 * 60 * 1_000 + 1_000
    const after = await post(deps, { url: 'https://example.com', consent: true })
    expect(after.status).toBe(200)
    resetSiteAnalysisRateLimit()
  })

  it('tidak menjalankan agen eksternal ketika analisis situs diminta', async () => {
    const deps = makeDeps()
    await post(deps, { url: 'https://example.com', consent: true })
    expect(deps.runScan).not.toHaveBeenCalled()
  })
})

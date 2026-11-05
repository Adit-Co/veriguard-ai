import { afterEach, describe, expect, it, vi } from 'vitest'
import { runSiteAnalysis } from '../../functions/src/website/service.js'
import type { OriginRequest } from '../../functions/src/website/types.js'
import { createWorkerSiteProbe } from '../src/siteProbe.js'

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/dns-json' },
  })
}

function probeFetch(): typeof fetch {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
    )

    if (url.hostname === 'cloudflare-dns.com' || url.hostname === 'dns.google') {
      const name = url.searchParams.get('name') ?? ''
      const type = url.searchParams.get('type') ?? ''
      if (type === 'A') {
        return jsonResponse({
          Status: 0,
          Answer: [{ name, type: 1, data: '93.184.216.34' }],
        })
      }
      if (type === 'AAAA') return jsonResponse({ Status: 0, Answer: [] })
      if (type === 'TXT' && name.endsWith('origin.asn.cymru.com')) {
        return jsonResponse({
          Status: 0,
          Answer: [
            {
              name,
              type: 16,
              data: '"15133 | 93.184.216.0/24 | US | arin | 2010-09-01"',
            },
          ],
        })
      }
      if (type === 'MX') {
        return jsonResponse({
          Status: 0,
          Answer: [{ name, type: 15, data: '10 mail.example.com.' }],
        })
      }
      return jsonResponse({ Status: 0, Answer: [] })
    }

    return new Response(
      '<html><head><title>Example</title><script src="https://cdn.example/app.js"></script></head><body>ok</body></html>',
      {
        status: 200,
        headers: {
          'content-type': 'text/html; charset=utf-8',
          server: 'nginx',
          'set-cookie': 'session=abc; Secure; HttpOnly; SameSite=Lax',
        },
      },
    )
  }) as unknown as typeof fetch
}

function originRequest(overrides: Partial<OriginRequest> = {}): OriginRequest {
  return {
    url: 'https://example.com/',
    address: '93.184.216.34',
    kind: 'ipv4',
    hostname: 'example.com',
    port: 443,
    secure: true,
    maxBytes: 512 * 1024,
    timeoutMs: 10_000,
    userAgent: 'VERIGUARD-AI/4.0 (test)',
    ...overrides,
  }
}

afterEach(() => {
  vi.useRealTimers()
})

describe('createWorkerSiteProbe', () => {
  it('menghasilkan DNS, ASN, TLS, HTTP, teknologi, dan perilaku nyata', async () => {
    const probe = createWorkerSiteProbe({ fetchImpl: probeFetch() })
    const report = await runSiteAnalysis({
      url: 'https://example.com/',
      uid: 'test',
      probe,
    })

    expect(report.probe.available).toBe(true)
    expect(report.website.status).toBe('complete')
    expect(report.website.identity.addresses.status).toBe('success')
    expect(report.website.identity.addresses.value).toEqual([
      { address: '93.184.216.34', kind: 'ipv4' },
    ])
    expect(report.website.identity.asn.value).toMatchObject({
      asn: '15133',
      prefix: '93.184.216.0/24',
      country: 'US',
      registry: 'arin',
    })
    expect(report.website.dns.find((entry) => entry.type === 'MX')?.lookup.value).toEqual([
      '10 mail.example.com.',
    ])
    expect(report.website.tls.httpsAvailable.value).toBe(true)
    expect(report.website.response.status).toBe(200)
    expect(report.technology.findings.map((entry) => entry.name)).toContain('nginx')
    expect(report.behavior.status).toBe('complete')
    expect(report.behavior.hosts.map((entry) => entry.host)).toContain('cdn.example')
    expect(report.behavior.resources?.scripts).toBe(1)
  })

  it('menolak target internal sebelum fetch dijalankan', async () => {
    const fetchImpl = vi.fn()
    const probe = createWorkerSiteProbe({ fetchImpl: fetchImpl as unknown as typeof fetch })
    const result = await probe.openOrigin(
      originRequest({
        url: 'http://127.0.0.1/',
        address: '127.0.0.1',
        hostname: '127.0.0.1',
        port: 80,
        secure: false,
      }),
    )

    expect(result.ok).toBe(false)
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('menangani timeout permintaan origin', async () => {
    vi.useFakeTimers()
    const fetchImpl = vi.fn(
      (_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), {
            once: true,
          })
        }),
    )
    const probe = createWorkerSiteProbe({ fetchImpl: fetchImpl as unknown as typeof fetch })
    const pending = probe.openOrigin(
      originRequest({ timeoutMs: 1_000 }),
    )

    await vi.advanceTimersByTimeAsync(1_001)
    const result = await pending

    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.kind).toBe('timeout')
  })

  it('tidak membocorkan nama secret atau header sensitif ke hasil probe', async () => {
    const probe = createWorkerSiteProbe({ fetchImpl: probeFetch() })
    const report = await runSiteAnalysis({
      url: 'https://example.com/',
      uid: 'test',
      probe,
    })
    const serialized = JSON.stringify(report)

    expect(serialized).not.toContain('VIRUSTOTAL_API_KEY')
    expect(serialized).not.toContain('CLOUDFLARE_API_TOKEN')
    expect(serialized).not.toContain('session=abc')
  })
})

describe('VGM-03: verifikasi alamat sesaat sebelum koneksi (anti DNS rebinding)', () => {
  // Jawaban A dipakai berurutan: openOrigin/inspectTls hanya melakukan satu kueri verifikasi
  // sebelum koneksi, jadi entri pertama adalah jawaban yang dilihat probe.
  function dohFetch(aAnswers: Array<() => unknown>, originBody = '<html></html>') {
    const originCalls: string[] = []
    let aIndex = 0
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(
        typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
      )
      if (url.hostname === 'cloudflare-dns.com' || url.hostname === 'dns.google') {
        const type = url.searchParams.get('type') ?? ''
        if (type === 'A') {
          const next = aAnswers[Math.min(aIndex, aAnswers.length - 1)]
          aIndex += 1
          return jsonResponse(next())
        }
        if (type === 'AAAA') return jsonResponse({ Status: 0, Answer: [] })
        return jsonResponse({ Status: 0, Answer: [] })
      }
      originCalls.push(url.href)
      return new Response(originBody, {
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8' },
      })
    })
    return { fetchImpl: fetchImpl as unknown as typeof fetch, originCalls }
  }

  const stablePublic = () => ({
    Status: 0,
    Answer: [{ name: 'example.com', type: 1, data: '93.184.216.34' }],
  })

  it('menolak ketika DNS menjawab alamat metadata saat koneksi akan dibuat', async () => {
    const { fetchImpl, originCalls } = dohFetch([
      () => ({ Status: 0, Answer: [{ name: 'example.com', type: 1, data: '169.254.169.254' }] }),
    ])
    const probe = createWorkerSiteProbe({ fetchImpl })

    const result = await probe.openOrigin(originRequest())

    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.detail).toMatch(/rebinding|diverifikasi ulang/i)
    expect(originCalls).toEqual([])
  })

  it('menolak ketika alamat beralih ke IP publik lain (rebinding sederhana)', async () => {
    const { fetchImpl, originCalls } = dohFetch([
      () => ({ Status: 0, Answer: [{ name: 'example.com', type: 1, data: '203.0.113.9' }] }),
    ])
    const probe = createWorkerSiteProbe({ fetchImpl })

    const result = await probe.openOrigin(originRequest())

    expect(result.ok).toBe(false)
    expect(originCalls).toEqual([])
  })

  it('menolak bila jawaban terbaru menambahkan alamat terlarang di samping yang valid', async () => {
    const { fetchImpl, originCalls } = dohFetch([
      () => ({
        Status: 0,
        Answer: [
          { name: 'example.com', type: 1, data: '93.184.216.34' },
          { name: 'example.com', type: 1, data: '10.0.0.5' },
        ],
      }),
    ])
    const probe = createWorkerSiteProbe({ fetchImpl })

    const result = await probe.openOrigin(originRequest())

    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.detail).toMatch(/ditolak kebijakan SSRF/i)
    expect(originCalls).toEqual([])
  })

  it('gagal-tutup bila DNS verifikasi tidak dapat dijawab', async () => {
    const originCalls: string[] = []
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(
        typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
      )
      if (url.hostname === 'cloudflare-dns.com' || url.hostname === 'dns.google') {
        throw new Error('doh down')
      }
      originCalls.push(url.href)
      return new Response('<html></html>', { status: 200 })
    })
    const probe = createWorkerSiteProbe({ fetchImpl: fetchImpl as unknown as typeof fetch })

    const result = await probe.openOrigin(originRequest())

    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.detail).toMatch(/tidak dapat diverifikasi ulang/i)
    expect(originCalls).toEqual([])
  })

  it('mengizinkan koneksi ketika jawaban DNS stabil', async () => {
    const { fetchImpl, originCalls } = dohFetch([stablePublic, stablePublic, stablePublic])
    const probe = createWorkerSiteProbe({ fetchImpl })

    const result = await probe.openOrigin(originRequest())

    expect(result.ok).toBe(true)
    expect(originCalls).toEqual(['https://example.com/'])
  })

  it('alamat literal tidak dikueri DNS ulang sebelum koneksi', async () => {
    const dohCalls: string[] = []
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(
        typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
      )
      if (url.hostname === 'cloudflare-dns.com' || url.hostname === 'dns.google') {
        dohCalls.push(url.href)
        return jsonResponse({ Status: 0, Answer: [] })
      }
      return new Response('<html></html>', {
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8' },
      })
    })
    const probe = createWorkerSiteProbe({ fetchImpl: fetchImpl as unknown as typeof fetch })

    const result = await probe.openOrigin(
      originRequest({
        url: 'http://93.184.216.34/',
        address: '93.184.216.34',
        hostname: '93.184.216.34',
        port: 80,
        secure: false,
      }),
    )

    expect(result.ok).toBe(true)
    expect(dohCalls).toEqual([])
  })

  it('inspectTls juga memverifikasi alamat sebelum menghubungi origin', async () => {
    const { fetchImpl, originCalls } = dohFetch([
      () => ({ Status: 0, Answer: [{ name: 'example.com', type: 1, data: '127.0.0.1' }] }),
    ])
    const probe = createWorkerSiteProbe({ fetchImpl })

    const result = await probe.inspectTls('example.com', '93.184.216.34', 'ipv4', 443)

    expect(result.outcome).toBe('failed')
    expect(result.httpsReachable).toBe(false)
    expect(originCalls).toEqual([])
  })
})

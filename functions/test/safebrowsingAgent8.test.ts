import { beforeEach, describe, expect, it, vi } from 'vitest'
import { failureCheck, withHttpStatus } from '../src/scanners/result.js'
import { googleSafeBrowsingAdapter } from '../src/scanners/providers/safebrowsing.js'
import { runMultiSourceScan } from '../src/scanners/service.js'
import type { FetchJsonResult } from '../src/scanners/http.js'
import type {
  ProviderContext,
  ScanCacheConfig,
  ScannerConfig,
} from '../src/scanners/types.js'
import { resetScanState } from './helpers/scanState.js'

// Regresi Agent 8 (Google Safe Browsing). Semua respons dibangun di sini; TIDAK ada panggilan
// API live. Fokus: format respons nyata (protobuf v5), normalisasi status, sufiks HTTP, dan
// interaksi cache — tanpa mengubah vonis gabungan maupun agen lain.

const BASE_TIME = 1_700_000_000_000
const GSB_HOST = 'safebrowsing.googleapis.com'
const SECRET_KEY = 'AIzaSecretLongApiKey0123456789abcdefghij'

function encodeVarint(n: number): number[] {
  const bytes: number[] = []
  let v = n
  while (v > 0x7f) {
    bytes.push((v & 0x7f) | 0x80)
    v >>>= 7
  }
  bytes.push(v & 0x7f)
  return bytes
}

// SearchUrlsResponse sah: field 1 = threats (repeated ThreatUrl), field 2 = cache_duration.
function buildProtobufSearchUrlsResponse(
  threats: Array<{ url: string; threatTypeNumbers: number[] }>,
  cacheSeconds = 300,
): Uint8Array {
  const parts: number[] = []
  for (const threat of threats) {
    const urlBytes = Array.from(new TextEncoder().encode(threat.url))
    const inner: number[] = [0x0a, urlBytes.length, ...urlBytes]
    for (const threatType of threat.threatTypeNumbers) {
      inner.push(0x10, ...encodeVarint(threatType))
    }
    parts.push(0x0a, inner.length, ...inner)
  }
  if (cacheSeconds > 0) {
    const duration = [0x08, ...encodeVarint(cacheSeconds)]
    parts.push(0x12, duration.length, ...duration)
  }
  return new Uint8Array(parts)
}

// Bytes no-match yang diamati pada probe 2026-10-28: hanya cache_duration{seconds:300}.
const LIVE_NO_MATCH_BYTES = new Uint8Array([0x12, 0x03, 0x08, 0xac, 0x02])

function bytesResponse(bytes: Uint8Array, contentType?: string, status = 200): Response {
  const headers = contentType ? { 'Content-Type': contentType } : undefined
  return new Response(bytes as unknown as BodyInit, { status, headers })
}

function brokenBodyResponse(contentType: string): Response {
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new Error('body terputus'))
      },
    }),
    { status: 200, headers: { 'Content-Type': contentType } },
  )
}

function gsbFetch(responder: (url: string) => Response | Promise<Response>) {
  return vi.fn(async (input: string | URL | Request) => responder(String(input)))
}

function context(fetchImpl: typeof fetch, now = () => BASE_TIME): ProviderContext {
  return {
    url: 'https://contoh.com/path',
    hostname: 'contoh.com',
    fetchImpl,
    now,
    sleep: async () => undefined,
  }
}

function makeConfig(overrides: Partial<ScannerConfig> = {}): ScannerConfig {
  return {
    urlscanApiKey: null,
    virusTotalApiKey: null,
    openPhishApiKey: null,
    threatFoxApiKey: null,
    cloudflareApiToken: null,
    cloudflareAccountId: null,
    otxApiKey: null,
    googleSafeBrowsingApiKey: SECRET_KEY,
    hybridAnalysisApiKey: null,
    ...overrides,
  }
}

function cacheConfig(overrides: Partial<ScanCacheConfig> = {}): ScanCacheConfig {
  return {
    enabled: true,
    maxEntries: 200,
    resultTtlMs: {
      urlscan: 60_000,
      virustotal: 60_000,
      openphish: 60_000,
      threatfox: 60_000,
      radar: 60_000,
      otx: 60_000,
      hybrid: 60_000,
      safebrowsing: 60_000,
    },
    failureTtlMs: 30_000,
    openPhishFeedTtlMs: 900_000,
    openPhishFeedStaleTtlMs: 43_200_000,
    ...overrides,
  }
}

function checkWith(responder: (url: string) => Response | Promise<Response>) {
  const fetchMock = gsbFetch(responder)
  return {
    fetchMock,
    check: () =>
      googleSafeBrowsingAdapter.check(
        context(fetchMock as unknown as typeof fetch),
        makeConfig(),
      ),
  }
}

function gsbCalls(fetchMock: ReturnType<typeof gsbFetch>): number {
  return fetchMock.mock.calls.filter(([input]) => String(input).includes(GSB_HOST)).length
}

function httpSuffixCount(reason: string | null | undefined): number {
  return (reason?.match(/\(HTTP \d+\)/g) ?? []).length
}

beforeEach(() => {
  resetScanState()
})

describe('Agent 8: protobuf v5 sah tetap terbaca', () => {
  // 1. Match protobuf.
  it('match MALWARE pada protobuf -> success/malicious dengan satu sinyal', async () => {
    const { check } = checkWith(() =>
      bytesResponse(
        buildProtobufSearchUrlsResponse([
          { url: 'https://contoh.com/path', threatTypeNumbers: [1] },
        ]),
        'application/x-protobuf',
      ),
    )

    const result = await check()
    expect(result.status).toBe('success')
    expect(result.verdict).toBe('malicious')
    expect(result.score).toBe(85)
    expect(result.summary).toContain('MALWARE')
  })

  // 2. No-match protobuf (bytes live + body 0 byte).
  it('no-match protobuf -> not_found/inconclusive, bukan clean dan bukan error', async () => {
    const live = await checkWith(() =>
      bytesResponse(LIVE_NO_MATCH_BYTES, 'application/x-protobuf'),
    ).check()
    expect(live.status).toBe('not_found')
    expect(live.verdict).toBe('inconclusive')
    expect(live.score).toBeNull()
    expect(live.reason).toContain('BUKAN konfirmasi')

    const empty = await checkWith(() =>
      bytesResponse(new Uint8Array(0), 'application/x-protobuf'),
    ).check()
    expect(empty.status).toBe('not_found')
    expect(empty.verdict).toBe('inconclusive')
  })

  // 3. cache_duration terurai tanpa mengubah vonis.
  it('cache_duration terbaca sebagai rekomendasi umur tanpa mengubah vonis', async () => {
    const bytes = buildProtobufSearchUrlsResponse(
      [{ url: 'https://contoh.com/path', threatTypeNumbers: [1] }],
      120,
    )
    const withThreat = await checkWith(() =>
      bytesResponse(bytes, 'application/x-protobuf'),
    ).check()
    expect(withThreat.providerCacheSeconds).toBe(120)
    expect(withThreat.status).toBe('success')
    expect(withThreat.verdict).toBe('malicious')

    const noMatch = await checkWith(() =>
      bytesResponse(LIVE_NO_MATCH_BYTES, 'application/x-protobuf'),
    ).check()
    expect(noMatch.providerCacheSeconds).toBe(300)
    expect(noMatch.status).toBe('not_found')
  })
})

describe('Agent 8: format respons tidak pernah diandaikan', () => {
  // 4. Protobuf cacat -> error terkendali, tidak pernah no-match.
  it('protobuf cacat (length terpotong) -> error, tidak pernah menjadi not_found', async () => {
    const { check } = checkWith(() =>
      bytesResponse(new Uint8Array([0x0a, 0xff, 0x01]), 'application/x-protobuf'),
    )

    const result = await check()
    expect(result.status).toBe('error')
    expect(result.verdict).toBe('inconclusive')
    expect(result.reason).toContain('protobuf')
    expect(JSON.stringify(result)).not.toContain(SECRET_KEY)
  })

  // 5. Content-type mengejutkan.
  it('octet-stream berisi protobuf tetap terurai sebagai protobuf', async () => {
    const { check } = checkWith(() =>
      bytesResponse(LIVE_NO_MATCH_BYTES, 'application/octet-stream'),
    )

    const result = await check()
    expect(result.status).toBe('not_found')
    expect(result.providerCacheSeconds).toBe(300)
  })

  it('content-type absen dengan bytes protobuf tersniff dan tidak menjadi JSON-error', async () => {
    const bytes = buildProtobufSearchUrlsResponse([
      { url: 'https://contoh.com/path', threatTypeNumbers: [2] },
    ])
    const match = await checkWith(() => bytesResponse(bytes)).check()
    expect(match.status).toBe('success')
    expect(match.verdict).toBe('malicious')
    expect(match.summary).toContain('SOCIAL_ENGINEERING')

    const noMatch = await checkWith(() => bytesResponse(LIVE_NO_MATCH_BYTES)).check()
    expect(noMatch.status).toBe('not_found')

    // JSON terselubung content-type tak dikenal tetap terbaca sebagai JSON.
    const json = await checkWith(() =>
      new Response(JSON.stringify({ threats: [] }), { status: 200 }),
    ).check()
    expect(json.status).toBe('not_found')
  })

  it('teks bebas ber-content-type tak dikenal tidak pernah berubah menjadi no-match', async () => {
    const { check } = checkWith(() =>
      new Response('Upstream temporarily unavailable, try later', {
        status: 200,
        headers: { 'Content-Type': 'x-unknown/garbage' },
      }),
    )

    const result = await check()
    expect(result.status).toBe('error')
    expect(result.verdict).toBe('inconclusive')
    expect(result.summary).not.toContain('tidak memiliki entri ancaman')
    expect(JSON.stringify(result)).not.toContain('Upstream')
  })

  it('HTML dari proxy -> error terkendali, bukan no-match dan tanpa isi body', async () => {
    const { check } = checkWith(() =>
      new Response('<html><body>Sign in</body></html>', {
        status: 200,
        headers: { 'Content-Type': 'text/html' },
      }),
    )

    const result = await check()
    expect(result.status).toBe('error')
    const rendered = JSON.stringify(result)
    expect(rendered).not.toContain('Sign in')
    expect(rendered).not.toContain(SECRET_KEY)
  })

  // Body 200 yang gagal dibaca streaming: inilah asal pesan "Respons agen tidak dapat dibaca."
  it('body rusak pada HTTP 200 -> satu error terbaca, bukan no-match', async () => {
    const { check } = checkWith(() => brokenBodyResponse('application/x-protobuf'))

    const result = await check()
    expect(result.status).toBe('error')
    expect(result.verdict).toBe('inconclusive')
    expect(result.reason).toBe('Respons provider tidak dapat dibaca. (HTTP 200)')
    expect(httpSuffixCount(result.reason)).toBe(1)
  })

  // 6. Non-2xx tetap punya status sendiri-sendiri.
  it('non-2xx tetap terpisah: 400 invalid_request, 401 auth_failed, 404 not_found, 429 kuota, 503 unavailable', async () => {
    const cases: Array<[number, string]> = [
      [400, 'invalid_request'],
      [401, 'auth_failed'],
      [404, 'not_found'],
      [429, 'rate_limited'],
      [503, 'unavailable'],
    ]

    for (const [status, expected] of cases) {
      const { check } = checkWith(() =>
        new Response(JSON.stringify({ error: { code: status } }), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      const result = await check()
      expect(result.status, `HTTP ${status}`).toBe(expected)
      expect(result.verdict).toBe('inconclusive')
      expect(result.score).toBeNull()
      expect(httpSuffixCount(result.reason)).toBeLessThanOrEqual(1)
    }
  })

  // 7. Timeout dan kegagalan jaringan.
  it('timeout dan kegagalan transport tetap inconclusive dan tidak membocorkan kunci', async () => {
    const timeoutFetch = vi.fn(async () => {
      const error = new Error('The operation timed out.')
      error.name = 'TimeoutError'
      throw error
    })
    const timeout = await googleSafeBrowsingAdapter.check(
      context(timeoutFetch as unknown as typeof fetch),
      makeConfig(),
    )
    expect(timeout.status).toBe('timeout')
    expect(timeout.verdict).toBe('inconclusive')

    const cause = Object.assign(new Error('getaddrinfo ENOTFOUND safebrowsing.googleapis.com'), {
      code: 'ENOTFOUND',
    })
    const netFetch = vi.fn(async () => {
      throw new TypeError('fetch failed', { cause })
    })
    const net = await googleSafeBrowsingAdapter.check(
      context(netFetch as unknown as typeof fetch),
      makeConfig(),
    )
    expect(net.status).toBe('unavailable')
    expect(net.reason).toContain('ENOTFOUND')
    const rendered = JSON.stringify(net)
    expect(rendered).not.toContain(SECRET_KEY)
    expect(rendered).not.toContain('safebrowsing.googleapis.com/v5/urls:search?key=')
  })
})

describe('Agent 8: sufiks HTTP tidak pernah ganda', () => {
  // 10. Tidak ada lagi "(HTTP 200) (HTTP 200)".
  it('reason yang sudah memuat (HTTP n) tidak ditempeli sufiks kedua', () => {
    const alreadyTagged: Extract<FetchJsonResult, { ok: false }> = {
      ok: false,
      status: 400,
      kind: 'error',
      reason: 'Provider menolak permintaan (HTTP 400).',
    }
    expect(withHttpStatus(alreadyTagged)).toBe('Provider menolak permintaan (HTTP 400).')

    const tagged = failureCheck(alreadyTagged)
    expect(tagged.reason).toBe('Provider menolak permintaan (HTTP 400).')
    expect(httpSuffixCount(tagged.reason)).toBe(1)
  })

  it('reason tanpa status tetap mendapat satu sufiks; status null tidak menambah apa pun', () => {
    const plain: Extract<FetchJsonResult, { ok: false }> = {
      ok: false,
      status: 500,
      kind: 'unavailable',
      reason: 'Layanan provider sedang tidak tersedia.',
    }
    expect(withHttpStatus(plain)).toBe('Layanan provider sedang tidak tersedia. (HTTP 500)')

    const noStatus: Extract<FetchJsonResult, { ok: false }> = {
      ok: false,
      status: null,
      kind: 'timeout',
      reason: 'Permintaan ke provider melebihi batas waktu.',
    }
    expect(withHttpStatus(noStatus)).toBe('Permintaan ke provider melebihi batas waktu.')
  })

  it('galat Agent 8 lewat jalur layanan hanya memuat satu sufiks HTTP', async () => {
    const fetchMock = gsbFetch(() =>
      new Response('server error', { status: 500, headers: { 'Content-Type': 'text/plain' } }),
    )

    const scan = await runMultiSourceScan({
      uid: 'agent8-suffix',
      url: 'https://contoh.com/path',
      config: makeConfig({ scanCache: cacheConfig({ enabled: false }) }),
      adapters: [googleSafeBrowsingAdapter],
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: () => BASE_TIME,
    })

    const provider = scan.providers.find((entry) => entry.id === 'safebrowsing')
    expect(provider?.status).toBe('unavailable')
    expect(provider?.reason).toBe('Layanan provider sedang tidak tersedia. (HTTP 500)')
    expect(httpSuffixCount(provider?.reason)).toBe(1)
  })
})

describe('Agent 8: cache memakai kontrak provider cache', () => {
  async function runScan(fetchMock: ReturnType<typeof gsbFetch>, now: () => number, uid: string) {
    return runMultiSourceScan({
      uid,
      url: 'https://contoh.com/path',
      config: makeConfig({ scanCache: cacheConfig() }),
      adapters: [googleSafeBrowsingAdapter],
      fetchImpl: fetchMock as unknown as typeof fetch,
      now,
    })
  }

  // 8a. Cache miss lalu hit; permintaan keluar tidak terulang.
  it('hasil no-match Agent 8 tersimpan: miss lalu hit tanpa permintaan keluar kedua', async () => {
    const fetchMock = gsbFetch(() => bytesResponse(LIVE_NO_MATCH_BYTES, 'application/x-protobuf'))
    let clock = BASE_TIME
    const now = () => clock

    const first = await runScan(fetchMock, now, 'agent8-cache-a')
    clock += 20_000
    const second = await runScan(fetchMock, now, 'agent8-cache-b')

    expect(first.cache?.status).toBe('miss')
    expect(second.cache?.status).toBe('hit')
    expect(gsbCalls(fetchMock)).toBe(1)

    const cached = second.providers.find((entry) => entry.id === 'safebrowsing')
    expect(cached?.status).toBe('not_found')
    expect(cached?.verdict).toBe('inconclusive')
    expect(cached?.cache?.hit).toBe(true)
    expect(cached?.cache?.ageMs).toBe(20_000)
    expect(cached?.durationMs).toBe(0)
    // field internal provider tidak pernah ikut ke kawat
    expect(JSON.stringify(second)).not.toContain('providerCacheSeconds')
    expect(JSON.stringify(second)).not.toContain(SECRET_KEY)
  })

  // 8b. Rekomendasi cache_duration memotong TTL kami, tidak pernah memanjangkan.
  it('cache_duration 10 detik memotong TTL agen sehingga hasil segar kembali setelahnya', async () => {
    const shortLived = buildProtobufSearchUrlsResponse([], 10)
    const fetchMock = gsbFetch(() => bytesResponse(shortLived, 'application/x-protobuf'))
    let clock = BASE_TIME
    const now = () => clock

    await runScan(fetchMock, now, 'agent8-ttl-a')
    clock += 20_000
    const second = await runScan(fetchMock, now, 'agent8-ttl-b')

    expect(second.cache?.status).toBe('miss')
    expect(gsbCalls(fetchMock)).toBe(2)
  })

  it('TTL agen yang lebih pendek dari cache_duration tetap dipakai', async () => {
    const fetchMock = gsbFetch(() => bytesResponse(LIVE_NO_MATCH_BYTES, 'application/x-protobuf'))
    let clock = BASE_TIME
    const now = () => clock

    await runScan(fetchMock, now, 'agent8-ttl-c')
    clock += 61_000
    const second = await runScan(fetchMock, now, 'agent8-ttl-d')

    expect(second.cache?.status).toBe('miss')
    expect(gsbCalls(fetchMock)).toBe(2)
  })

  // 9. no-match bertahan sampai agregasi layanan.
  it('not_found Agent 8 tidak berubah menjadi clean pada hasil agregat', async () => {
    const fetchMock = gsbFetch(() => bytesResponse(LIVE_NO_MATCH_BYTES, 'application/x-protobuf'))
    const scan = await runScan(fetchMock, () => BASE_TIME, 'agent8-aggregate')

    const provider = scan.providers.find((entry) => entry.id === 'safebrowsing')
    expect(provider?.status).toBe('not_found')
    expect(provider?.verdict).toBe('inconclusive')
    expect(provider?.score).toBeNull()
    // Agregasi tidak pernah mengubah ketiadaan match menjadi vonis bersih.
    expect(scan.providers.every((entry) => entry.verdict !== 'clean')).toBe(true)
    expect(JSON.stringify(scan)).not.toContain(SECRET_KEY)
  })
})

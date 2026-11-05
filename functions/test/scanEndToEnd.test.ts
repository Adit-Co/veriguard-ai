// Alur nyata end-to-end: roster adapter produksi (PROVIDER_ADAPTERS) + fetch yang hanya
// berpura-pura menjadi agen. Tujuannya mengukur hal yang tidak dapat diukur tes per-agen:
// berapa permintaan keluar yang benar-benar tidak terjadi pada pemeriksaan ulang, dan
// apakah metadata cache sampai ke kontrak HTTP tanpa mengubah vonis.
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { readScanCacheConfig } from '../src/scanners/config.js'
import { PROVIDER_ADAPTERS } from '../src/scanners/providers/index.js'
import { FEED_ENDPOINT } from '../src/scanners/providers/openphishFeed.js'
import { runMultiSourceScan } from '../src/scanners/service.js'
import type {
  MultiSourceScanResponse,
  ScanProgressEvent,
  ScannerConfig,
} from '../src/scanners/types.js'
import { resetScanState } from './helpers/scanState.js'

const BASE_TIME = 1_700_000_000_000
const GSB_KEY = 'gsb-test-key'
const URL_A = 'https://tokopedi.example/produk/1'
const URL_B = 'https://berita.example/hari-ini'

type Env = Record<string, string | undefined>

function makeConfig(): ScannerConfig {
  // Hanya OpenPhish (feed publik, tanpa kunci) dan Google Safe Browsing yang terpasang.
  // Agen lain tetap ada pada roster dan tampil as-configured: tidak dikonfigurasi.
  const env: Env = {
    OPENPHISH_API_KEY: '',
    GOOGLE_SAFE_BROWSING_API_KEY: GSB_KEY,
    SCAN_CACHE_ENABLED: 'true',
    OPENPHISH_FEED_TTL_MINUTES: '15',
  }

  return {
    urlscanApiKey: null,
    virusTotalApiKey: null,
    openPhishApiKey: null,
    threatFoxApiKey: null,
    cloudflareApiToken: null,
    cloudflareAccountId: null,
    otxApiKey: null,
    googleSafeBrowsingApiKey: GSB_KEY,
    hybridAnalysisApiKey: null,
    scanCache: readScanCacheConfig(env),
  }
}

function gsbNoMatch(): Response {
  return new Response(JSON.stringify({ threats: [] }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function feedResponse(): Response {
  return new Response('https://phish.example/login\n', {
    status: 200,
    headers: { 'Content-Type': 'text/plain' },
  })
}

function stubbedFetch() {
  return vi.fn(async (input: string | URL | Request) => {
    const url = String(input)
    if (url === FEED_ENDPOINT) return feedResponse()
    if (url.includes('safebrowsing.googleapis.com')) return gsbNoMatch()
    throw new Error(`Permintaan keluar tak terduga: ${url}`)
  })
}

function started(url: string) {
  const config = makeConfig()
  const fetchImpl = stubbedFetch()

  return {
    config,
    fetchImpl,
    run: (scanUrl = url, overrides: Record<string, unknown> = {}) =>
      runMultiSourceScan({
        uid: 'end-to-end',
        url: scanUrl,
        config,
        adapters: PROVIDER_ADAPTERS,
        fetchImpl: fetchImpl as unknown as typeof fetch,
        now: () => BASE_TIME,
        ...overrides,
      }),
    outbound: () => fetchImpl.mock.calls.length,
  }
}

function byId(response: MultiSourceScanResponse, id: string) {
  return response.providers.find((provider) => provider.id === id)
}

beforeEach(() => {
  resetScanState()
})

describe('alur pemeriksaan nyata dengan cache hasil', () => {
  it('pemeriksaan ulang URL yang sama tidak mengirim satu permintaan pun', async () => {
    const t = started(URL_A)

    const first = await t.run()
    const firstCalls = t.outbound()

    expect(firstCalls).toBe(2)
    expect(first.cache?.status).toBe('miss')
    expect(first.cache?.requestsAvoided).toBe(0)

    const second = await t.run()

    // Inti fitur: hasil dibaca SEBELUM agen dijalankan, jadi permintaan keluarnya nol.
    expect(t.outbound()).toBe(firstCalls)
    expect(second.cache?.status).toBe('hit')
    expect(second.cache?.requestsAvoided).toBe(2)
    expect(second.cache?.reusedProviders).toEqual(['openphish', 'safebrowsing'])
    expect(byId(second, 'openphish')?.cache?.hit).toBe(true)
    expect(byId(second, 'safebrowsing')?.cache?.hit).toBe(true)

    // Kontrak vonis tidak berubah karena cache.
    expect(second.providers.map((p) => [p.id, p.status, p.verdict])).toEqual(
      first.providers.map((p) => [p.id, p.status, p.verdict]),
    )
  })

  it('URL baru hanya mengunduh ulang feed yang sudah ada di cache global', async () => {
    const t = started(URL_A)

    await t.run()
    expect(t.outbound()).toBe(2)

    // Feed OpenPhish tidak bergantung URL: hanya permintaan agen per-URL yang baru.
    await t.run(URL_B)
    expect(t.outbound()).toBe(3)

    await t.run(URL_B)
    expect(t.outbound()).toBe(3)
  })

  it('stream progres membawa penanda cache yang sama dengan respons akhir', async () => {
    const t = started(URL_A)
    const events: ScanProgressEvent[] = []

    await t.run(URL_A, { scanId: 'scan-1', onEvent: (event: ScanProgressEvent) => events.push(event) })
    events.length = 0

    const done = await t.run(URL_A, { scanId: 'scan-2', onEvent: (event: ScanProgressEvent) => events.push(event) })
    const providerEvents = events.filter((event) => event.type === 'provider')
    const doneEvent = events.find((event) => event.type === 'done')

    expect(done.cache?.status).toBe('hit')
    expect(providerEvents.filter((event) => event.provider.result?.cache?.hit)).toHaveLength(2)
    expect(providerEvents.every((event) => event.scanId === 'scan-2')).toBe(true)
    if (doneEvent && doneEvent.type === 'done') {
      expect(doneEvent.response.cache?.status).toBe('hit')
    } else {
      throw new Error('Event done tidak dikirim pada akhir stream.')
    }
  })

  it('metadata cache tidak pernah membawa kunci, URL mentah, atau identitas pengguna', async () => {
    const t = started(URL_A)

    const response = await t.run()
    await t.run()
    const serialized = JSON.stringify(response)

    expect(serialized).not.toContain(GSB_KEY)
    expect(serialized).not.toContain(URL_A)
    expect(serialized).not.toContain('end-to-end')
    expect(response.providers.every((provider) => provider.cache === undefined)).toBe(false)
  })

  it('batas pemeriksaan per pemakai tetap berlaku walau hasilnya ada di cache', async () => {
    const t = started(URL_A)

    // SCAN_RATE_LIMIT = 6 pemeriksaan per pemakai per 10 menit. Entri cache sengaja tidak
    // dipakai untuk membebaskan pemakai dari batasnya: yang dibatasi adalah pekerjaan, bukan
    // hanya permintaan keluar.
    const responses: MultiSourceScanResponse[] = []
    for (let index = 0; index < 8; index += 1) {
      responses.push(await t.run())
    }

    expect(t.outbound()).toBe(2)
    expect(responses[0]?.cache?.status).toBe('miss')
    expect(responses.slice(1, 6).every((response) => response.cache?.status === 'hit')).toBe(true)

    const limited = responses[7]!
    expect(limited.providers.every((provider) => provider.status === 'rate_limited')).toBe(true)
    expect(limited.cache).toBeUndefined()
  })
})

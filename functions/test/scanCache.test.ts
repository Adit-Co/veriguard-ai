import { beforeEach, describe, expect, it, vi } from 'vitest'
import { readScanCacheConfig, readScannerConfig } from '../src/scanners/config.js'
import { MAX_INFLIGHT_SCANS, inFlightScanCount, runSharedScan } from '../src/scanners/inFlight.js'
import {
  buildProviderCacheKeys,
  isCacheableStatus,
  pruneProviderCache,
  providerCacheEntryCount,
  providerCacheKey,
  readProviderCache,
  scanDedupKey,
  writeProviderCache,
} from '../src/scanners/providerCache.js'
import {
  FEED_ENDPOINT,
  loadOpenPhishFeed,
  openPhishFeedDownloadCount,
} from '../src/scanners/providers/openphishFeed.js'
import { googleSafeBrowsingAdapter } from '../src/scanners/providers/safebrowsing.js'
import { openPhishAdapter } from '../src/scanners/providers/openphish.js'
import { runMultiSourceScan } from '../src/scanners/service.js'
import type {
  MultiSourceScanResponse,
  ProviderAdapter,
  ProviderCheck,
  ProviderResult,
  ScanCacheConfig,
  ScanProgressEvent,
  ScannerConfig,
} from '../src/scanners/types.js'
import { resetScanState } from './helpers/scanState.js'
import { forbiddenNarrativeHits, reportNarrativeText } from './helpers/narrative.js'
import { normalizeScanUrl } from '../src/scanners/url.js'

const BASE_TIME = 1_700_000_000_000

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function textResponse(body: string, status = 200): Response {
  return new Response(body, { status, headers: { 'Content-Type': 'text/plain' } })
}

function mockFetch(handler: (url: string) => Response | Promise<Response>) {
  return vi.fn(async (input: string | URL | Request) => handler(String(input)))
}

function callsOf(fetchMock: ReturnType<typeof mockFetch>): string[] {
  return fetchMock.mock.calls.map(([input]) => String(input))
}

// Menunggu sampai kondisi terpenuhinya sebuah permintaan (misalnya agen benar-benar
// mulai berjalan) alih-alih menebak jumlah microtask.
async function waitUntil(predicate: () => boolean, label: string): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (predicate()) return
    await new Promise((resolve) => setTimeout(resolve, 0))
  }
  throw new Error(`Kondisi tidak tercapai: ${label}`)
}

function clockAt(start = BASE_TIME) {
  let ms = start
  return {
    now: () => ms,
    set: (value: number) => {
      ms = value
    },
    advance: (delta: number) => {
      ms += delta
    },
  }
}

const CLEAN: ProviderCheck = {
  status: 'success',
  verdict: 'clean',
  score: 0,
  summary: 'Tidak ditemukan indikasi.',
  signals: [],
  reason: null,
}

function makeCacheConfig(overrides: Partial<ScanCacheConfig> = {}): ScanCacheConfig {
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

function makeConfig(overrides: Partial<ScannerConfig> = {}): ScannerConfig {
  return {
    urlscanApiKey: 'urlscan-key',
    virusTotalApiKey: 'vt-key',
    openPhishApiKey: null,
    threatFoxApiKey: null,
    cloudflareApiToken: null,
    cloudflareAccountId: null,
    otxApiKey: null,
    googleSafeBrowsingApiKey: null,
    hybridAnalysisApiKey: null,
    scanCache: makeCacheConfig(),
    ...overrides,
  }
}

// Agen tiruan yang mencatat berapa kali benar-benar diperiksa. `fetchImpl` ikut dihitung
// pada tes tertentu karena yang harus dibuktikan adalah permintaan keluarnya, bukan sekadar
// jumlah pemanggilan adapter.
function countedAdapter(
  id: ProviderAdapter['id'],
  check: () => ProviderCheck | Promise<ProviderCheck>,
): ProviderAdapter & { calls: () => number } {
  let calls = 0
  return {
    id,
    label: id,
    isConfigured: () => true,
    check: async () => {
      calls += 1
      return check()
    },
    calls: () => calls,
  }
}

beforeEach(() => {
  resetScanState()
})

describe('kunci cache opaque dan keamanan URL', () => {
  it('kunci adalah hash heksadesimal 64 karakter tanpa URL mentah', () => {
    const config = makeConfig()
    const url = 'https://contoh.com/masuk?user=adi&token=abc'
    const key = providerCacheKey('urlscan', url, config)

    expect(key).toMatch(/^[0-9a-f]{64}$/)
    expect(key).not.toContain('contoh')
    expect(key.toLowerCase()).not.toContain('adi')
    expect(key.toLowerCase()).not.toContain('abc')
  })

  it('agen yang berbeda untuk URL yang sama memakai kunci yang berbeda', () => {
    const config = makeConfig()
    const url = 'https://contoh.com/'

    expect(providerCacheKey('urlscan', url, config)).not.toBe(
      providerCacheKey('virustotal', url, config),
    )
  })

  it('kebijakan yang berbeda tidak memakai entri yang sama', () => {
    const url = 'https://contoh.com/'
    const before = providerCacheKey('urlscan', url, makeConfig())
    const after = providerCacheKey(
      'urlscan',
      url,
      makeConfig({ scanCache: makeCacheConfig({ resultTtlMs: { urlscan: 120_000 } }) }),
    )

    expect(before).not.toBe(after)
  })

  it('perbedaan yang dinormalisasi (hash, utm, port baku) dianggap target yang sama', () => {
    const config = makeConfig()
    // Kunci selalu dibangun dari URL HASIL normalisasi, jadi yang diuji adalah normalisasi
    // + kunci bersama: variasi yang tidak mengubah target harus menghasilkan kunci identik.
    const keyOf = (raw: string) => providerCacheKey('urlscan', normalizeScanUrl(raw), config)

    expect(keyOf('https://contoh.com/path#fragment')).toBe(keyOf('https://contoh.com/path'))
    expect(keyOf('https://contoh.com/path?utm_source=koran')).toBe(keyOf('https://contoh.com/path'))
    expect(keyOf('https://CONTOH.com:443/path')).toBe(keyOf('https://contoh.com/path'))

    // Target yang berbeda secara material tidak pernah digabung.
    expect(keyOf('https://contoh.com/path')).not.toBe(keyOf('https://contoh.com/'))
    expect(keyOf('https://contoh.com/path')).not.toBe(keyOf('https://lain.example/path'))
    expect(keyOf('https://contoh.com/path?token=rahasia')).not.toBe(
      keyOf('https://contoh.com/path'),
    )
  })

  it('host yang berbeda tidak pernah digabung', () => {
    const config = makeConfig()
    expect(providerCacheKey('urlscan', 'https://a.example/', config)).not.toBe(
      providerCacheKey('urlscan', 'https://b.example/', config),
    )
  })

  it('buildProviderCacheKeys memberi kunci per agen dan null saat cache dimatikan', () => {
    const keys = buildProviderCacheKeys(['urlscan', 'radar'], 'https://contoh.com/', makeConfig())
    expect(Object.keys(keys ?? {})).toEqual(['urlscan', 'radar'])

    const disabled = buildProviderCacheKeys(
      ['urlscan'],
      'https://contoh.com/',
      makeConfig({ scanCache: makeCacheConfig({ enabled: false }) }),
    )
    expect(disabled).toBeNull()
  })

  it('kunci dedup tidak memuat URL mentah dan membedakan daftar agen', () => {
    const base = {
      normalizedUrl: 'https://contoh.com/path',
      adapterIds: ['urlscan' as const],
      providerTimeoutMs: 50_000,
      scanTimeoutMs: 80_000,
    }
    const key = scanDedupKey(base)

    expect(key).toMatch(/^[0-9a-f]{64}$/)
    expect(key).not.toContain('contoh')
    expect(key).toBe(scanDedupKey(base))
    expect(key).not.toBe(scanDedupKey({ ...base, adapterIds: ['urlscan', 'radar'] }))
    expect(key).not.toBe(scanDedupKey({ ...base, providerTimeoutMs: 20_000 }))
  })
})

describe('kelayakan status dan TTL entri', () => {
  it('hanya hasil sah dan kegagalan sementara yang layak cache', () => {
    expect(isCacheableStatus('success')).toBe(true)
    expect(isCacheableStatus('not_found')).toBe(true)
    expect(isCacheableStatus('rate_limited')).toBe(true)
    expect(isCacheableStatus('unavailable')).toBe(true)
    expect(isCacheableStatus('timeout')).toBe(true)
    // Status ini bukan jawaban: tidak boleh pernah menyamar sebagai hasil.
    expect(isCacheableStatus('skipped')).toBe(false)
    expect(isCacheableStatus('error')).toBe(false)
    expect(isCacheableStatus('auth_failed')).toBe(false)
    expect(isCacheableStatus('not_configured')).toBe(false)
  })

  it('kunci tidak dikenal tidak menyajikan entri agen lain', () => {
    const config = makeConfig()
    const clock = clockAt()
    const key = providerCacheKey('urlscan', 'https://contoh.com/', config)
    writeProviderCache('urlscan', key, CLEAN, config, clock.now)

    const other = providerCacheKey('radar', 'https://contoh.com/', config)
    expect(readProviderCache('radar', other, clock.now)).toBeNull()
    // membaca kunci urlscan dengan id agen lain harus ditolak
    expect(readProviderCache('radar', key, clock.now)).toBeNull()
  })

  it('entri kedaluwarsa ditolak saat dibaca dan dibuang dari memori', () => {
    const config = makeConfig()
    const clock = clockAt()
    const key = providerCacheKey('urlscan', 'https://contoh.com/', config)
    writeProviderCache('urlscan', key, CLEAN, config, clock.now)

    expect(readProviderCache('urlscan', key, clock.now)?.entry.check).toEqual(CLEAN)
    clock.advance(60_001)
    expect(readProviderCache('urlscan', key, clock.now)).toBeNull()
    expect(providerCacheEntryCount()).toBe(0)
  })

  it('kegagalan sementara disimpan singkat dan statusnya tidak diubah', () => {
    const config = makeConfig()
    const clock = clockAt()
    const key = providerCacheKey('urlscan', 'https://contoh.com/', config)
    const limited: ProviderCheck = {
      status: 'rate_limited',
      verdict: 'inconclusive',
      score: null,
      summary: 'Kuota provider tercapai.',
      signals: [],
      reason: 'Kuota permintaan provider tercapai.',
    }
    writeProviderCache('urlscan', key, limited, config, clock.now)

    const hit = readProviderCache('urlscan', key, clock.now)
    expect(hit?.entry.check.status).toBe('rate_limited')
    expect(hit?.entry.check.verdict).toBe('inconclusive')

    clock.advance(30_001)
    expect(readProviderCache('urlscan', key, clock.now)).toBeNull()
  })

  it('umur laporan agen memotong TTL cache (tidak pernah lebih lama dari kebijakan agen)', () => {
    const config: ScannerConfig = {
      ...makeConfig(),
      urlscanMaxReportAgeHours: 1,
    }
    const clock = clockAt()
    const key = providerCacheKey('urlscan', 'https://contoh.com/', config)
    const reused: ProviderCheck = {
      ...CLEAN,
      evidence: {
        source: 'existing_report',
        observedAt: new Date(clock.now() - 55 * 60_000).toISOString(),
        ageMs: 55 * 60_000,
      },
    }
    writeProviderCache('urlscan', key, reused, config, clock.now)

    // Laporan berumur 55 menit + kebijakan 1 jam -> sisa 5 menit, meskipun TTL kami 60 menit.
    expect(readProviderCache('urlscan', key, clock.now)).not.toBeNull()
    clock.advance(6 * 60_000)
    expect(readProviderCache('urlscan', key, clock.now)).toBeNull()
  })

  it('entri yang terlalu tua dari kebijakan agen tidak pernah disimpan', () => {
    const config: ScannerConfig = { ...makeConfig(), urlscanMaxReportAgeHours: 1 }
    const clock = clockAt()
    const key = providerCacheKey('urlscan', 'https://contoh.com/', config)
    const stale: ProviderCheck = {
      ...CLEAN,
      evidence: {
        source: 'existing_report',
        observedAt: new Date(clock.now() - 3 * 3_600_000).toISOString(),
        ageMs: 3 * 3_600_000,
      },
    }

    expect(writeProviderCache('urlscan', key, stale, config, clock.now)).toBeNull()
    expect(providerCacheEntryCount()).toBe(0)
  })

  it('memori cache terikat: entri lama dibuang saat batas tercapai', () => {
    const config = makeConfig({ scanCache: makeCacheConfig({ maxEntries: 2 }) })
    const clock = clockAt()

    for (const path of ['/a', '/b', '/c']) {
      const key = providerCacheKey('urlscan', `https://contoh.com${path}`, config)
      writeProviderCache('urlscan', key, CLEAN, config, clock.now)
    }

    expect(providerCacheEntryCount()).toBe(2)
    expect(readProviderCache('urlscan', providerCacheKey('urlscan', 'https://contoh.com/a', config), clock.now)).toBeNull()
    expect(readProviderCache('urlscan', providerCacheKey('urlscan', 'https://contoh.com/c', config), clock.now)).not.toBeNull()
  })

  it('prune membuang hanya entri kedaluwarsa', () => {
    const config = makeConfig()
    const clock = clockAt()
    writeProviderCache('urlscan', providerCacheKey('urlscan', 'https://contoh.com/a', config), CLEAN, config, clock.now)
    writeProviderCache('radar', providerCacheKey('radar', 'https://contoh.com/a', config), CLEAN, config, clock.now)

    clock.advance(60_001)
    writeProviderCache('otx', providerCacheKey('otx', 'https://contoh.com/a', config), CLEAN, config, clock.now)

    expect(pruneProviderCache(clock.now)).toBe(2)
    expect(providerCacheEntryCount()).toBe(1)
  })

  it('cache yang dimatikan tidak menulis dan tidak membaca', () => {
    const config = makeConfig({ scanCache: makeCacheConfig({ enabled: false }) })
    const clock = clockAt()
    const key = providerCacheKey('urlscan', 'https://contoh.com/', config)

    expect(writeProviderCache('urlscan', key, CLEAN, config, clock.now)).toBeNull()
    expect(readProviderCache('urlscan', key, clock.now)).toBeNull()
    expect(providerCacheEntryCount()).toBe(0)
  })

  it('Google Safe Browsing: rekomendasi cache_duration memotong TTL kami', () => {
    const config = makeConfig()
    const clock = clockAt()
    const key = providerCacheKey('safebrowsing', 'https://contoh.com/', config)
    writeProviderCache(
      'safebrowsing',
      key,
      { ...CLEAN, providerCacheSeconds: 10 },
      config,
      clock.now,
    )

    expect(readProviderCache('safebrowsing', key, clock.now)).not.toBeNull()
    clock.advance(11_000)
    expect(readProviderCache('safebrowsing', key, clock.now)).toBeNull()
  })
})

describe('validasi konfigurasi kebijakan cache', () => {
  it('memakai default aman ketika env kosong', () => {
    const cache = readScanCacheConfig({})
    expect(cache.enabled).toBe(true)
    expect(cache.maxEntries).toBe(200)
    expect(cache.failureTtlMs).toBe(30_000)
    expect(cache.resultTtlMs.urlscan).toBe(3_600_000)
    expect(cache.resultTtlMs.openphish).toBe(900_000)
    expect(cache.resultTtlMs.safebrowsing).toBe(1_800_000)
    expect(cache.openPhishFeedTtlMs).toBe(900_000)
    expect(cache.openPhishFeedStaleTtlMs).toBe(43_200_000)
  })

  it('menolak nilai tidak valid dan tetap memakai default', () => {
    const cache = readScanCacheConfig({
      URLSCAN_RESULT_TTL_MINUTES: '0',
      RADAR_RESULT_TTL_MINUTES: '-5',
      OTX_RESULT_TTL_MINUTES: 'bukan-angka',
      HYBRID_RESULT_TTL_MINUTES: '999999',
      SAFEBROWSING_RESULT_TTL_MINUTES: '1.5',
      SCAN_CACHE_MAX_ENTRIES: '0',
      PROVIDER_FAILURE_TTL_SECONDS: '-1',
      OPENPHISH_FEED_TTL_MINUTES: '',
    })

    expect(cache.resultTtlMs.urlscan).toBe(3_600_000)
    expect(cache.resultTtlMs.radar).toBe(3_600_000)
    expect(cache.resultTtlMs.otx).toBe(3_600_000)
    expect(cache.resultTtlMs.hybrid).toBe(3_600_000)
    expect(cache.resultTtlMs.safebrowsing).toBe(1_800_000)
    expect(cache.maxEntries).toBe(200)
    expect(cache.failureTtlMs).toBe(30_000)
    expect(cache.openPhishFeedTtlMs).toBe(900_000)
  })

  it('menerima nilai valid dan mematikan cache secara eksplisit', () => {
    const cache = readScanCacheConfig({
      SCAN_CACHE_ENABLED: 'false',
      URLSCAN_RESULT_TTL_MINUTES: '5',
      SCAN_CACHE_MAX_ENTRIES: '10',
      PROVIDER_FAILURE_TTL_SECONDS: '5',
    })

    expect(cache.enabled).toBe(false)
    expect(cache.resultTtlMs.urlscan).toBe(300_000)
    expect(cache.maxEntries).toBe(10)
    expect(cache.failureTtlMs).toBe(5_000)
  })

  it('readScannerConfig selalu membawa kebijakan cache', () => {
    expect(readScannerConfig({}).scanCache?.enabled).toBe(true)
  })
})

describe('cache hasil di jalur pemeriksaan multi-agen', () => {
  function setup(params: {
    urlscan?: () => ProviderCheck
    virustotal?: () => ProviderCheck
    fetchHandler?: (url: string) => Response
  }) {
    const urlscan = countedAdapter('urlscan', params.urlscan ?? (() => CLEAN))
    const virustotal = countedAdapter('virustotal', params.virustotal ?? (() => CLEAN))
    const fetchMock = mockFetch(params.fetchHandler ?? (() => jsonResponse({})))
    const clock = clockAt()

    return { urlscan, virustotal, fetchMock, clock, adapters: [urlscan, virustotal] }
  }

  it('pemeriksaan ulang URL yang sama tidak memanggil agen sama sekali', async () => {
    const t = setup({})
    const config = makeConfig()

    const first = await runMultiSourceScan({
      uid: 'cache-first',
      url: 'https://contoh.com/a',
      config,
      adapters: t.adapters,
      fetchImpl: t.fetchMock as unknown as typeof fetch,
      now: t.clock.now,
    })
    const second = await runMultiSourceScan({
      uid: 'cache-second',
      url: 'https://contoh.com/a',
      config,
      adapters: t.adapters,
      fetchImpl: t.fetchMock as unknown as typeof fetch,
      now: t.clock.now,
    })

    expect(first.cache?.status).toBe('miss')
    expect(first.cache?.requestsAvoided).toBe(0)
    expect(second.cache?.status).toBe('hit')
    expect(second.cache?.hit).toBe(true)
    expect(second.cache?.requestsAvoided).toBe(2)
    expect(second.cache?.reusedProviders).toEqual(['urlscan', 'virustotal'])
    expect(t.urlscan.calls()).toBe(1)
    expect(t.virustotal.calls()).toBe(1)
    expect(t.fetchMock).not.toHaveBeenCalled()
  })

  it('agen yang memakai hasil cache tetap tampil berjalan lalu selesai di stream progres', async () => {
    const t = setup({})
    const config = makeConfig()
    const events: ScanProgressEvent[] = []

    await runMultiSourceScan({
      uid: 'progress-first',
      url: 'https://contoh.com/a',
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })
    t.clock.advance(10_000)
    await runMultiSourceScan({
      uid: 'progress-second',
      url: 'https://contoh.com/a',
      scanId: 'scan-progress',
      config,
      adapters: t.adapters,
      now: t.clock.now,
      onEvent: (event) => events.push(event),
    })

    const providerEvents = events.filter((event) => event.type === 'provider')
    const states = new Map<string, string[]>()
    for (const event of providerEvents) {
      if (event.type !== 'provider') continue
      states.set(event.provider.id, [
        ...(states.get(event.provider.id) ?? []),
        event.provider.state,
      ])
    }

    // Setiap agen yang diselesaikan pada permintaan ini lewat status berjalan lebih dulu,
    // termasuk agen yang jawabannya diambil dari cache, jadi progresnya terasa normal.
    expect(states.get('urlscan')).toEqual(['running', 'completed'])
    expect(states.get('virustotal')).toEqual(['running', 'completed'])
    expect(providerEvents.filter((event) => event.provider.state === 'completed')).toHaveLength(2)
    expect(t.fetchMock).not.toHaveBeenCalled()
  })

  it('URL berbeda tidak memakai entri agen lain', async () => {
    const t = setup({})
    const config = makeConfig()

    await runMultiSourceScan({
      uid: 'other-url-a',
      url: 'https://contoh.com/a',
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })
    const second = await runMultiSourceScan({
      uid: 'other-url-b',
      url: 'https://contoh.com/b',
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })

    expect(second.cache?.status).toBe('miss')
    expect(t.urlscan.calls()).toBe(2)
  })

  it('hasil cache ditandai di level agen dan tidak disajikan sebagai pemindaian baru', async () => {
    const t = setup({})
    const config = makeConfig()

    await runMultiSourceScan({
      uid: 'stamp-a',
      url: 'https://contoh.com/a',
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })
    t.clock.advance(30_000)
    const second = await runMultiSourceScan({
      uid: 'stamp-b',
      url: 'https://contoh.com/a',
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })

    const cached = second.providers.find((provider) => provider.id === 'urlscan')
    expect(cached?.cache?.hit).toBe(true)
    expect(cached?.cache?.ageMs).toBe(30_000)
    expect(cached?.cache?.observedAt).toBe(new Date(BASE_TIME).toISOString())
    expect(cached?.durationMs).toBe(0)
    // waktu permintaan tetap waktu permintaan; waktu pengamatan terpisah.
    expect(second.generatedAt).toBe(new Date(BASE_TIME + 30_000).toISOString())
    expect(second.cache?.observedAt).toBe(new Date(BASE_TIME).toISOString())
    expect(second.cache?.ageMs).toBe(30_000)
  })

  it('teks agen hasil cache identik dengan hasil baru dan tidak menjelaskan cara pengambilan', async () => {
    // Check yang memakai laporan milik agen sendiri: asal bukti hanya lewat metadata.
    const reused: ProviderCheck = {
      status: 'success',
      verdict: 'malicious',
      score: 100,
      summary: 'URLScan menilai URL ini berbahaya (skor 100/100).',
      signals: [
        {
          label: 'Waktu analisis terakhir',
          detail: 'Analisis terakhir 14 Nov 2023 22:13 UTC.',
          severity: 'info',
        },
      ],
      reason: null,
      evidence: {
        source: 'existing_report',
        observedAt: new Date(BASE_TIME - 60_000).toISOString(),
        ageMs: 60_000,
      },
    }
    const t = setup({ urlscan: () => reused })
    const config = makeConfig()

    const first = await runMultiSourceScan({
      uid: 'text-miss',
      url: 'https://contoh.com/a',
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })
    t.clock.advance(30_000)
    const second = await runMultiSourceScan({
      uid: 'text-hit',
      url: 'https://contoh.com/a',
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })

    // Cache hit: agen tidak dijalankan lagi, jadi tidak ada permintaan keluar tambahan.
    expect(t.urlscan.calls()).toBe(1)
    expect(second.cache?.hit).toBe(true)

    // Teks yang dilihat pengguna identik antara hasil baru dan hasil cache, sehingga
    // pemeriksaan dari cache tidak terasa berbeda dan juga tidak mengklaim hal baru.
    expect(reportNarrativeText(second)).toBe(reportNarrativeText(first))
    expect(forbiddenNarrativeHits(reportNarrativeText(first))).toEqual([])

    // Asal bukti tetap akurat sebagai metadata untuk menampilkan waktu laporan.
    const urlscan = second.providers.find((provider) => provider.id === 'urlscan')
    expect(urlscan?.evidence?.source).toBe('existing_report')
    expect(urlscan?.evidence?.observedAt).toBe(new Date(BASE_TIME - 60_000).toISOString())
    expect(urlscan?.cache?.hit).toBe(true)
  })

  it('setelah TTL lewat, agen diperiksa ulang', async () => {
    const t = setup({})
    const config = makeConfig()

    await runMultiSourceScan({
      uid: 'ttl-a',
      url: 'https://contoh.com/a',
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })
    t.clock.advance(60_001)
    const second = await runMultiSourceScan({
      uid: 'ttl-b',
      url: 'https://contoh.com/a',
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })

    expect(second.cache?.status).toBe('miss')
    expect(t.urlscan.calls()).toBe(2)
  })

  it('pemeriksaan berikutnya membuang entri kedaluwarsa dari memori', async () => {
    const t = setup({})
    const config = makeConfig()

    await runMultiSourceScan({
      uid: 'prune-a',
      url: 'https://contoh.com/a',
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })
    expect(providerCacheEntryCount()).toBe(2)

    t.clock.advance(60_001)
    // URL lain: entri lama tidak akan terbaca lagi, jadi tidak boleh menahan tempat.
    await runMultiSourceScan({
      uid: 'prune-b',
      url: 'https://contoh.com/b',
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })

    expect(providerCacheEntryCount()).toBe(2)
  })

  it('satu agen segar dan satu agen kedaluwarsa menghasilkan status partial', async () => {
    const config = makeConfig({
      scanCache: makeCacheConfig({
        // TTL berbeda per agen supaya salah satu bisa kedaluwarsa lebih dulu.
        resultTtlMs: { urlscan: 120_000, virustotal: 30_000 },
      }),
    })
    const urlscan = countedAdapter('urlscan', () => CLEAN)
    const virustotal = countedAdapter('virustotal', () => CLEAN)
    const clock = clockAt()

    const first = await runMultiSourceScan({
      uid: 'partial-a',
      url: 'https://contoh.com/a',
      config,
      adapters: [urlscan, virustotal],
      now: clock.now,
    })
    expect(first.cache?.status).toBe('miss')

    // 31 menit-ms kemudian hanya entri virustotal yang lewat TTL-nya sendiri.
    clock.advance(31_000)
    const second = await runMultiSourceScan({
      uid: 'partial-b',
      url: 'https://contoh.com/a',
      config,
      adapters: [urlscan, virustotal],
      now: clock.now,
    })

    expect(second.cache?.status).toBe('partial')
    expect(second.cache?.reusedProviders).toEqual(['urlscan'])
    expect(second.cache?.refreshedProviders).toEqual(['virustotal'])
    expect(second.cache?.requestsAvoided).toBe(1)
    expect(urlscan.calls()).toBe(1)
    expect(virustotal.calls()).toBe(2)
    expect(second.providers[0]?.cache?.hit).toBe(true)
    expect(second.providers[1]?.cache?.hit).toBe(false)
  })

  it('tidak ada entri saat cache dimatikan', async () => {
    const t = setup({})
    const config = makeConfig({ scanCache: makeCacheConfig({ enabled: false }) })

    await runMultiSourceScan({
      uid: 'disabled-a',
      url: 'https://contoh.com/a',
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })
    const second = await runMultiSourceScan({
      uid: 'disabled-b',
      url: 'https://contoh.com/a',
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })

    expect(second.cache).toBeUndefined()
    expect(t.urlscan.calls()).toBe(2)
  })

  it('URL sensitif tidak pernah di-cache maupun berbagi hasil', async () => {
    const t = setup({})
    const config = makeConfig()
    const url = 'https://contoh.com/masuk?token=rahasiasekali'

    const first = await runMultiSourceScan({
      uid: 'sensitive-a',
      url,
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })
    const second = await runMultiSourceScan({
      uid: 'sensitive-b',
      url,
      config,
      adapters: t.adapters,
      now: t.clock.now,
    })

    expect(first.sensitiveUrl).toBe(true)
    expect(first.cache).toBeUndefined()
    expect(second.cache).toBeUndefined()
    expect(second.providers.every((provider) => provider.status === 'skipped')).toBe(true)
    expect(t.urlscan.calls()).toBe(0)
  })

  it('agen yang belum dikonfigurasi tidak pernah tampil sebagai hasil cache', async () => {
    const configured = countedAdapter('urlscan', () => CLEAN)
    const unconfigured: ProviderAdapter = {
      id: 'virustotal',
      label: 'VirusTotal',
      isConfigured: () => false,
      check: async () => CLEAN,
    }
    const config = makeConfig()
    const clock = clockAt()

    await runMultiSourceScan({
      uid: 'nc-a',
      url: 'https://contoh.com/a',
      config,
      adapters: [configured, unconfigured],
      now: clock.now,
    })
    const second = await runMultiSourceScan({
      uid: 'nc-b',
      url: 'https://contoh.com/a',
      config,
      adapters: [configured, unconfigured],
      now: clock.now,
    })

    const vt = second.providers.find((provider) => provider.id === 'virustotal')
    expect(vt?.status).toBe('not_configured')
    expect(vt?.cache).toBeUndefined()
    expect(second.cache?.reusedProviders).toEqual(['urlscan'])
    expect(second.cache?.status).toBe('hit')
  })

  it('kegagalan provider disimpan dengan status aslinya dan tidak pernah jadi tidak ada kecocokan', async () => {
    const config = makeConfig()
    const clock = clockAt()
    const failing: ProviderAdapter = {
      id: 'urlscan',
      label: 'URLScan.io',
      isConfigured: () => true,
      check: async () => ({
        status: 'unavailable',
        verdict: 'inconclusive',
        score: null,
        summary: 'Layanan provider sedang tidak tersedia.',
        signals: [],
        reason: 'Layanan provider sedang tidak tersedia.',
      }),
    }

    const first = await runMultiSourceScan({
      uid: 'fail-a',
      url: 'https://contoh.com/a',
      config,
      adapters: [failing],
      now: clock.now,
    })
    const second = await runMultiSourceScan({
      uid: 'fail-b',
      url: 'https://contoh.com/a',
      config,
      adapters: [failing],
      now: clock.now,
    })

    expect(first.providers[0]?.status).toBe('unavailable')
    expect(second.providers[0]?.status).toBe('unavailable')
    expect(second.providers[0]?.status).not.toBe('not_found')
    expect(second.providers[0]?.cache?.hit).toBe(true)
    expect(second.cache?.requestsAvoided).toBe(1)
  })

  it('ketiadaan kecocokan dari cache tidak pernah menaikkan vonis menjadi aman', async () => {
    const config = makeConfig()
    const clock = clockAt()
    const notFound: ProviderAdapter = {
      id: 'urlscan',
      label: 'URLScan.io',
      isConfigured: () => true,
      check: async () => ({
        status: 'not_found',
        verdict: 'inconclusive',
        score: null,
        summary: 'Tidak ada laporan.',
        signals: [],
        reason: 'Tidak tercatat bukan bukti aman.',
      }),
    }

    await runMultiSourceScan({
      uid: 'nf-a',
      url: 'https://contoh.com/a',
      config,
      adapters: [notFound],
      now: clock.now,
    })
    const second = await runMultiSourceScan({
      uid: 'nf-b',
      url: 'https://contoh.com/a',
      config,
      adapters: [notFound],
      now: clock.now,
    })

    expect(second.providers[0]?.status).toBe('not_found')
    expect(second.providers[0]?.verdict).toBe('inconclusive')
    expect(second.providers[0]?.cache?.hit).toBe(true)
  })

  it('temuan berbahaya dari agen lain tetap menang terhadap hasil cache yang bersih', async () => {
    const config = makeConfig()
    const clock = clockAt()
    const clean = countedAdapter('urlscan', () => CLEAN)
    const malicious: ProviderAdapter = {
      id: 'virustotal',
      label: 'VirusTotal',
      isConfigured: () => true,
      check: async () => ({
        status: 'success',
        verdict: 'malicious',
        score: 90,
        summary: 'Ditandai berbahaya.',
        signals: [],
        reason: null,
      }),
    }

    await runMultiSourceScan({
      uid: 'mix-a',
      url: 'https://contoh.com/a',
      config,
      adapters: [clean, malicious],
      now: clock.now,
    })
    const second = await runMultiSourceScan({
      uid: 'mix-b',
      url: 'https://contoh.com/a',
      config,
      adapters: [clean, malicious],
      now: clock.now,
    })

    expect(second.providers.map((provider) => provider.verdict)).toEqual([
      'clean',
      'malicious',
    ])
    expect(second.providers.every((provider) => provider.cache?.hit)).toBe(true)
  })

  it('semua agen gagal tidak pernah menghasilkan hasil bersih', async () => {
    const config = makeConfig()
    const clock = clockAt()
    const failing = (id: ProviderAdapter['id']): ProviderAdapter => ({
      id,
      label: id,
      isConfigured: () => true,
      check: async () => ({
        status: 'error',
        verdict: 'inconclusive',
        score: null,
        summary: 'Gagal.',
        signals: [],
        reason: 'Provider gagal diproses.',
      }),
    })

    const response = await runMultiSourceScan({
      uid: 'allfail',
      url: 'https://contoh.com/a',
      config,
      adapters: [failing('urlscan'), failing('virustotal')],
      now: clock.now,
    })

    expect(response.providers.every((provider) => provider.status === 'error')).toBe(true)
    // error tidak pernah di-cache: permintaan berikutnya mencoba lagi.
    expect(providerCacheEntryCount()).toBe(0)
  })
})

describe('dedup pemeriksaan identik yang berjalan bersamaan', () => {
  // Agen yang tertahan sampai tes membuka gerbangnya. `release()` aman dipanggil kapan
  // pun; tes menunggu `started()` lebih dulu sehingga tidak ada balapan microtask.
  function slowAdapter(id: ProviderAdapter['id']) {
    let calls = 0
    let releaseGate: () => void = () => undefined

    const adapter = {
      id,
      label: id,
      isConfigured: () => true,
      check: async () => {
        calls += 1
        await new Promise<void>((resolve) => {
          releaseGate = resolve
        })
        return CLEAN
      },
      calls: () => calls,
      started: () => calls > 0,
      release: () => releaseGate(),
    }
    return adapter
  }

  it('dua permintaan identik hanya menjalankan satu pemeriksaan agen', async () => {
    const config = makeConfig()
    const adapter = slowAdapter('urlscan')

    const fetchMock = mockFetch(() => jsonResponse({}))
    const first = runMultiSourceScan({
      uid: 'dedup-a',
      url: 'https://contoh.com/a',
      config,
      adapters: [adapter],
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: () => BASE_TIME,
    })
    await waitUntil(adapter.started, 'agen pertama berjalan')
    const second = runMultiSourceScan({
      uid: 'dedup-b',
      url: 'https://contoh.com/a',
      config,
      adapters: [adapter],
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: () => BASE_TIME,
    })

    expect(inFlightScanCount()).toBe(1)
    adapter.release()

    const [a, b] = await Promise.all([first, second])
    expect(adapter.calls()).toBe(1)
    expect(a.providers[0]?.status).toBe('success')
    expect(b.providers[0]?.status).toBe('success')
    expect(a.cache?.deduplicated).toBeUndefined()
    expect(b.cache?.deduplicated).toBe(true)
    expect(inFlightScanCount()).toBe(0)
  })

  it('setiap permintaan punya scanId sendiri dan urutan event yang lengkap', async () => {
    const config = makeConfig()
    const adapter = slowAdapter('urlscan')

    const eventsA: ScanProgressEvent[] = []
    const eventsB: ScanProgressEvent[] = []

    const first = runMultiSourceScan({
      uid: 'fan-a',
      url: 'https://contoh.com/a',
      scanId: 'scan-satu',
      config,
      adapters: [adapter],
      now: () => BASE_TIME,
      onEvent: (event) => eventsA.push(event),
    })
    await waitUntil(adapter.started, 'agen pertama berjalan')
    const second = runMultiSourceScan({
      uid: 'fan-b',
      url: 'https://contoh.com/a',
      scanId: 'scan-dua',
      config,
      adapters: [adapter],
      now: () => BASE_TIME,
      onEvent: (event) => eventsB.push(event),
    })
    adapter.release()
    await Promise.all([first, second])

    expect(eventsA.map((event) => event.type)).toEqual(['init', 'provider', 'provider', 'done'])
    expect(eventsB.map((event) => event.type)).toEqual(['init', 'provider', 'provider', 'done'])
    expect(eventsB.every((event) => event.scanId === 'scan-dua')).toBe(true)
    expect(eventsA.every((event) => event.scanId === 'scan-satu')).toBe(true)
    expect(JSON.stringify(eventsA)).not.toContain('scan-dua')
  })

  it('pembatalan satu klien tidak membatalkan pekerjaan klien lain', async () => {
    const config = makeConfig()
    const adapter = slowAdapter('urlscan')
    const controller = new AbortController()

    const first = runMultiSourceScan({
      uid: 'cancel-a',
      url: 'https://contoh.com/a',
      config,
      adapters: [adapter],
      now: () => BASE_TIME,
      signal: controller.signal,
    })
    await waitUntil(adapter.started, 'agen pertama berjalan')
    const second = runMultiSourceScan({
      uid: 'cancel-b',
      url: 'https://contoh.com/a',
      config,
      adapters: [adapter],
      now: () => BASE_TIME,
    })

    controller.abort()
    adapter.release()

    const [a, b] = await Promise.all([first, second])
    // klien yang menutup koneksi tetap mendapat respons akhir, dan pekerjaan tidak dihentikan
    expect(b.providers[0]?.status).toBe('success')
    expect(b.cache?.deduplicated).toBe(true)
    expect(a.providers.length).toBe(1)
    expect(adapter.calls()).toBe(1)
  })

  it('pekerjaan dihentikan ketika waiter terakhir pergi', async () => {
    const config = makeConfig()
    const never = (): Promise<ProviderCheck> => new Promise<ProviderCheck>(() => undefined)
    const adapter: ProviderAdapter = {
      id: 'urlscan',
      label: 'URLScan.io',
      isConfigured: () => true,
      check: never,
    }
    const controller = new AbortController()

    const scan = runMultiSourceScan({
      uid: 'last-waiter',
      url: 'https://contoh.com/a',
      config,
      adapters: [adapter],
      now: () => BASE_TIME,
      scanTimeoutMs: 60_000,
      providerTimeoutMs: 60_000,
      signal: controller.signal,
    })

    await Promise.resolve()
    controller.abort()
    const result = await scan

    expect(result.providers[0]?.status).toBe('skipped')
    expect(inFlightScanCount()).toBe(0)
  })

  it('URL berbeda tidak pernah digabung', async () => {
    const config = makeConfig()
    const clock = clockAt()
    const adapter = countedAdapter('urlscan', () => {
      clock.advance(1)
      return CLEAN
    })

    const [a, b] = await Promise.all([
      runMultiSourceScan({
        uid: 'diff-a',
        url: 'https://contoh.com/a',
        config,
        adapters: [adapter],
        now: clock.now,
      }),
      runMultiSourceScan({
        uid: 'diff-b',
        url: 'https://contoh.com/b',
        config,
        adapters: [adapter],
        now: clock.now,
      }),
    ])

    expect(adapter.calls()).toBe(2)
    expect(a.cache?.deduplicated).toBeUndefined()
    expect(b.cache?.deduplicated).toBeUndefined()
  })

  it('satu agen berjalan tidak menahan agen lain selamanya saat registry penuh', async () => {
    const key = 'kunci'
    const options = (scanId: string) => ({
      key,
      scanId,
      startedAt: BASE_TIME,
      now: () => BASE_TIME,
      run: async () => {
        await new Promise((resolve) => setTimeout(resolve, 0))
        return responseOf(scanId)
      },
    })

    const pending = Array.from({ length: MAX_INFLIGHT_SCANS }, (_, index) =>
      runSharedScan(options(`shared-${index}`)),
    )

    const extra = await runSharedScan(options('extra'))
    expect(extra.generatedAt).toContain(String(new Date(BASE_TIME).toISOString()))
    await Promise.all(pending)
    expect(inFlightScanCount()).toBe(0)
  })
})

function responseOf(marker: string): MultiSourceScanResponse {
  return {
    providers: [],
    sharedWithProviders: [],
    sensitiveUrl: false,
    privacyReasons: [marker],
    generatedAt: new Date(BASE_TIME).toISOString(),
    durationMs: 0,
  }
}

describe('cache feed OpenPhish', () => {
  function feedResponse(entries: string[]) {
    return textResponse(entries.map((entry) => `${entry}\n`).join(''))
  }

  it('satu snapshot dipakai untuk banyak URL dan banyak pemeriksaan', async () => {
    const clock = clockAt()
    const fetchMock = mockFetch(() => feedResponse(['https://phish.example/login']))
    const options = {
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: clock.now,
      cache: makeCacheConfig(),
    }

    const first = await loadOpenPhishFeed(options)
    const second = await loadOpenPhishFeed(options)

    expect(first.ok && second.ok).toBe(true)
    expect(openPhishFeedDownloadCount()).toBe(1)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('unduhan ulang terjadi setelah TTL dan hanya sekali saat diminta bersamaan', async () => {
    const clock = clockAt()
    const pending: Array<() => void> = []
    const fetchMock = vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          pending.push(() => resolve(feedResponse(['https://phish.example/login'])))
        }),
    ) as unknown as ReturnType<typeof mockFetch>
    const options = {
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: clock.now,
      cache: makeCacheConfig(),
    }
    const releaseLatest = () => pending.at(-1)?.()

    const initial = loadOpenPhishFeed(options)
    await waitUntil(() => pending.length > 0, 'unduhan feed dimulai')
    const concurrent = Promise.all([loadOpenPhishFeed(options), loadOpenPhishFeed(options)])
    releaseLatest()
    await Promise.all([initial, concurrent])

    // Tiga pembaca, satu unduhan: permintaan yang datang saat refresh berjalan dipakai bersama.
    expect(fetchMock.mock.calls.length).toBe(1)

    clock.advance(900_001)
    const refreshed = loadOpenPhishFeed(options)
    await waitUntil(() => pending.length > 1, 'unduhan feed berikutnya dimulai')
    releaseLatest()

    expect((await refreshed).ok).toBe(true)
    expect(fetchMock.mock.calls.length).toBe(2)
  })

  it('feed kosong atau rusak tidak pernah menimpa snapshot yang sah', async () => {
    const clock = clockAt()
    let body = 'https://phish.example/login\n'
    const fetchMock = mockFetch(() => textResponse(body))
    const options = {
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: clock.now,
      cache: makeCacheConfig(),
    }

    await loadOpenPhishFeed(options)
    expect(openPhishFeedDownloadCount()).toBe(1)

    // Unduhan berikutnya rusak/kosong: snapshot lama tetap dipakai dan hasil tetap jujur.
    body = ''
    clock.advance(900_001)
    const stale = await loadOpenPhishFeed(options)
    expect(stale.ok).toBe(true)
    if (stale.ok) {
      expect(stale.snapshot.stale).toBe(true)
      expect(stale.snapshot.lines).toEqual(['https://phish.example/login'])
    }
  })

  it('snapshot basi dilaporkan sebagai basi, bukan sebagai data segar', async () => {
    const clock = clockAt()
    let fail = false
    const fetchMock = mockFetch(() =>
      fail ? jsonResponse({ error: 'unavailable' }, 503) : textResponse('https://phish.example/login\n'),
    )
    const options = {
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: clock.now,
      cache: makeCacheConfig(),
    }

    await loadOpenPhishFeed(options)
    fail = true
    clock.advance(900_001)
    const outcome = await loadOpenPhishFeed(options)

    expect(outcome.ok).toBe(true)
    if (!outcome.ok) return
    expect(outcome.snapshot.stale).toBe(true)
    expect(outcome.snapshot.refreshFailure).toContain('tidak tersedia')
    expect(outcome.snapshot.ageMs).toBe(900_001)
  })

  it('snapshot yang lewat jendela basi tidak pernah dipakai lagi', async () => {
    const clock = clockAt()
    let fail = false
    const fetchMock = mockFetch(() =>
      fail ? jsonResponse({ error: 'unavailable' }, 503) : textResponse('https://phish.example/login\n'),
    )
    const options = {
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: clock.now,
      cache: makeCacheConfig({ openPhishFeedStaleTtlMs: 3_600_000 }),
    }

    await loadOpenPhishFeed(options)
    fail = true
    clock.advance(3_600_001)
    const outcome = await loadOpenPhishFeed(options)

    expect(outcome.ok).toBe(false)
    if (outcome.ok) return
    expect(outcome.reason).toContain('tidak tersedia')
  })

  it('agen OpenPhish menandai hasil yang dibangun dari feed basi', async () => {
    const clock = clockAt()
    let fail = false
    const fetchMock = mockFetch(() =>
      fail
        ? jsonResponse({ error: 'unavailable' }, 503)
        : textResponse('https://lain.example/phish\n'),
    )
    const config = makeConfig({ urlscanApiKey: null })
    const context = () => ({
      url: 'https://contoh.com/login',
      hostname: 'contoh.com',
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: clock.now,
      sleep: async () => undefined,
    })

    const fresh = await openPhishAdapter.check(context(), config)
    expect(fresh.status).toBe('not_found')
    expect(fresh.staleEvidence).toBeUndefined()

    fail = true
    clock.advance(900_001)
    const stale = await openPhishAdapter.check(context(), config)
    expect(stale.status).toBe('not_found')
    expect(stale.staleEvidence).toBe(true)
    const feedSignal = stale.signals.at(-1)
    expect(feedSignal?.label).toBe('Data feed belum terbaru')
    expect(feedSignal?.severity).toBe('warning')
    // Umur data dinyatakan sebagai waktu pengambilan terakhir, bukan umur entri, dan
    // penyebab kegagalan pemulihan data tidak ikut dikirim ke antarmuka.
    expect(feedSignal?.detail).toMatch(/terakhir diperbarui \d/)
    expect(feedSignal?.detail).not.toMatch(/unduhan ulang|berumur|penyebab tidak diketahui/i)
  })

  it('tanpa kebijakan cache, feed diunduh ulang tiap pemeriksaan', async () => {
    const clock = clockAt()
    const fetchMock = mockFetch(() => textResponse('https://phish.example/login\n'))
    const options = {
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: clock.now,
    }

    await loadOpenPhishFeed(options)
    await loadOpenPhishFeed(options)

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(openPhishFeedDownloadCount()).toBe(2)
  })

  it('URL sensitif tidak pernah singgah di jalur cache', async () => {
    const t = mockFetch(() => textResponse('https://phish.example/login\n'))
    const config = makeConfig()

    const response = await runMultiSourceScan({
      uid: 'sensitive-feed',
      url: 'https://contoh.com/masuk?token=rahasiasekali',
      config,
      fetchImpl: t as unknown as typeof fetch,
      now: () => BASE_TIME,
    })

    expect(response.providers.every((provider) => provider.status === 'skipped')).toBe(true)
    expect(callsOf(t)).toEqual([])
    expect(openPhishFeedDownloadCount()).toBe(0)
  })

  it('endpoint feed tidak pernah berubah dan tidak membawa kunci', async () => {
    const t = mockFetch(() => textResponse('https://phish.example/login\n'))
    await loadOpenPhishFeed({
      fetchImpl: t as unknown as typeof fetch,
      now: () => BASE_TIME,
      cache: makeCacheConfig(),
    })

    const [url, init] = t.mock.calls[0] as unknown as [string, RequestInit]
    expect(String(url)).toBe(FEED_ENDPOINT)
    expect(JSON.stringify(init)).not.toMatch(/api[- ]?key|authorization/i)
  })
})

describe('providerCacheSeconds pada Google Safe Browsing', () => {
  function protobufNoMatch(): Uint8Array {
    // SearchUrlsResponse tanpa threats + cache_duration { seconds: 300 }.
    // 0x12 = field 2 (cache_duration), kawat length-delimited, 3 byte: 0x08 300 varint.
    return new Uint8Array([0x12, 0x03, 0x08, 0xac, 0x02])
  }

  it('umur rekomendasi Google dibaca dari protobuf dan tidak ikut ke respons', async () => {
    const config: ScannerConfig = {
      ...makeConfig(),
      googleSafeBrowsingApiKey: 'gsb-key',
      urlscanApiKey: null,
      // TTL kami lebih panjang dari saran Google: yang membatasi harus saran Google.
      scanCache: makeCacheConfig({ resultTtlMs: { safebrowsing: 600_000 } }),
    }
    const check = await googleSafeBrowsingAdapter.check(
      {
        url: 'https://contoh.com/login',
        hostname: 'contoh.com',
        fetchImpl: (async () =>
          new Response(protobufNoMatch(), {
            status: 200,
            headers: { 'Content-Type': 'application/x-protobuf' },
          })) as unknown as typeof fetch,
        now: () => BASE_TIME,
        sleep: async () => undefined,
      },
      config,
    )

    expect(check.status).toBe('not_found')
    expect(check.providerCacheSeconds).toBe(300)

    // `toResult` menyusun objek secara eksplisit: saran umur tidak pernah bocor ke wire.
    const clock = clockAt()
    const key = providerCacheKey('safebrowsing', 'https://contoh.com/login', config)
    const stored = writeProviderCache('safebrowsing', key, check, config, clock.now)
    expect(stored?.expiresAtMs).toBe(BASE_TIME + 300_000)

    const result: ProviderResult = {
      id: 'safebrowsing',
      label: 'Google Safe Browsing',
      status: check.status,
      verdict: check.verdict,
      score: check.score,
      summary: check.summary,
      signals: check.signals,
      reason: check.reason ?? null,
      durationMs: 0,
    }
    expect(JSON.stringify(result)).not.toContain('providerCacheSeconds')
  })

  it('suggestions nol atau tidak ada tidak memotong TTL', () => {
    const config = makeConfig()
    const clock = clockAt()
    const key = providerCacheKey('safebrowsing', 'https://contoh.com/x', config)

    const stored = writeProviderCache(
      'safebrowsing',
      key,
      { ...CLEAN, providerCacheSeconds: 0 },
      config,
      clock.now,
    )
    expect(stored?.expiresAtMs).toBe(BASE_TIME + 60_000)
  })
})

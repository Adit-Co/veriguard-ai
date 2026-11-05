import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { readScannerConfig } from '../src/scanners/config.js'
import { toBase64Url } from '../src/scanners/encoding.js'
import { fetchJson } from '../src/scanners/http.js'
import { detectSensitiveUrl } from '../src/scanners/privacy.js'
import { otxAdapter } from '../src/scanners/providers/otx.js'
import { openPhishAdapter } from '../src/scanners/providers/openphish.js'
import { hybridAnalysisAdapter } from '../src/scanners/providers/hybrid.js'
import { radarAdapter } from '../src/scanners/providers/radar.js'
import { PROVIDER_ADAPTERS } from '../src/scanners/providers/index.js'
import { threatFoxAdapter } from '../src/scanners/providers/threatfox.js'
import { urlScanAdapter } from '../src/scanners/providers/urlscan.js'
import { googleSafeBrowsingAdapter } from '../src/scanners/providers/safebrowsing.js'
import { virusTotalAdapter } from '../src/scanners/providers/virustotal.js'
import { resetScanState } from './helpers/scanState.js'
import { forbiddenNarrativeHits, providerCheckText } from './helpers/narrative.js'
import { failureCheck } from '../src/scanners/result.js'
import { runMultiSourceScan } from '../src/scanners/service.js'
import type {
  ProviderAdapter,
  ProviderCheck,
  ProviderContext,
  ScannerConfig,
} from '../src/scanners/types.js'
import { normalizeScanUrl, ScanUrlError } from '../src/scanners/url.js'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function textResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/plain' },
  })
}

// Teks yang dikirim adapter ikut tersimpan di laporan riwayat dan ter-serialisasi ke klien,
// jadi tidak boleh memuat kalimat tentang cara hasil diperoleh. Kontrak frasanya ada di
// helpers/narrative dan dipakai bersama dengan tes jalur cache.
function notCacheNarrative(check: ProviderCheck): boolean {
  return forbiddenNarrativeHits(providerCheckText(check)).length === 0
}

const OPENPHISH_FEED_URL =
  'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt'

const WEB_SCANNERS_DIR = new URL('../../web/src/lib/scanners/', import.meta.url)

/**
 * Membaca urutan id dari sebuah daftar di sumber frontend. Entri pertama yang berkutip pada
 * setiap baris adalah id provider, jadi label dan nama lain tidak ikut terbaca.
 */
function readFrontendIdList(file: string, exportName: string): string[] {
  const source = readFileSync(fileURLToPath(new URL(file, WEB_SCANNERS_DIR)), 'utf8')
  const marker = source.indexOf(exportName)
  if (marker < 0) throw new Error(`${exportName} tidak ditemukan di ${file}`)
  const open = source.indexOf('[', marker)
  const close = source.indexOf('\n]', open)
  if (open < 0 || close < 0) throw new Error(`Blok ${exportName} tidak dapat dibaca di ${file}`)

  return source
    .slice(open, close)
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => !line.startsWith('//') && !line.startsWith('*'))
    .map((line) => /'([a-z0-9_]+)'/.exec(line)?.[1])
    .filter((id): id is string => typeof id === 'string')
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
    googleSafeBrowsingApiKey: null,
    hybridAnalysisApiKey: null,
    ...overrides,
  }
}

function context(fetchImpl: typeof fetch): ProviderContext {
  return {
    url: 'https://contoh.com/path',
    hostname: 'contoh.com',
    fetchImpl,
    now: () => 1_700_000_000_000,
    sleep: async () => undefined,
  }
}

function mockFetch(handler: (url: string) => Response | Promise<Response>) {
  return vi.fn(async (input: string | URL | Request) => handler(String(input)))
}

// Jam berjalan untuk menguji adapter yang menghentikan polling berdasarkan anggaran waktu.
function tickingContext(
  fetchImpl: typeof fetch,
  onSleep?: (ms: number) => void,
): { context: ProviderContext; elapsed: () => number } {
  let clock = 1_700_000_000_000
  return {
    elapsed: () => clock - 1_700_000_000_000,
    context: {
      url: 'https://contoh.com/path',
      hostname: 'contoh.com',
      fetchImpl,
      now: () => clock,
      sleep: async (ms: number) => {
        clock += ms
        onSleep?.(ms)
      },
    },
  }
}

function callsOf(fetchMock: ReturnType<typeof mockFetch>): string[] {
  return fetchMock.mock.calls.map(([input]) => String(input))
}

describe('konfigurasi kredensial backend', () => {
  it('membaca nama environment variable yang dipakai adapter', () => {
    const config = readScannerConfig({
      URLSCAN_API_KEY: ' urlscan-key ',
      VIRUSTOTAL_API_KEY: ' vt-key ',
      OPENPHISH_API_KEY: ' op-key ',
      THREATFOX_API_KEY: ' tf-key ',
      CLOUDFLARE_API_TOKEN: ' cf-token ',
      CLOUDFLARE_ACCOUNT_ID: ' cf-account ',
      OTX_API_KEY: ' otx-key ',
      GOOGLE_SAFE_BROWSING_API_KEY: ' gsb-key ',
    })

    expect(config).toEqual({
      urlscanApiKey: 'urlscan-key',
      virusTotalApiKey: 'vt-key',
      openPhishApiKey: 'op-key',
      threatFoxApiKey: 'tf-key',
      cloudflareApiToken: 'cf-token',
      cloudflareAccountId: 'cf-account',
      otxApiKey: 'otx-key',
      googleSafeBrowsingApiKey: 'gsb-key',
      hybridAnalysisApiKey: null,
      scanCache: {
        enabled: true,
        maxEntries: 200,
        failureTtlMs: 30_000,
        openPhishFeedTtlMs: 900_000,
        openPhishFeedStaleTtlMs: 43_200_000,
        resultTtlMs: {
          urlscan: 3_600_000,
          virustotal: 3_600_000,
          openphish: 900_000,
          threatfox: 900_000,
          radar: 3_600_000,
          otx: 3_600_000,
          hybrid: 3_600_000,
          safebrowsing: 1_800_000,
        },
      },
    })
  })

  it('menganggap key kosong tidak terkonfigurasi', () => {
    const config = readScannerConfig({
      URLSCAN_API_KEY: '   ',
      CLOUDFLARE_API_TOKEN: '  ',
    })

    expect(config.urlscanApiKey).toBeNull()
    expect(config.cloudflareApiToken).toBeNull()
  })
})

describe('encoding URL untuk provider', () => {
  it('menghasilkan base64url tanpa padding dan aman untuk Worker', () => {
    expect(toBase64Url('https://contoh.com/path')).toBe('aHR0cHM6Ly9jb250b2guY29tL3BhdGg')
    expect(toBase64Url('?>>>')).toBe('Pz4-Pg')
    expect(toBase64Url('')).toBe('')
  })
})

describe('kebijakan URL scanner', () => {
  it('menormalkan URL dan menolak alamat privat', () => {
    expect(normalizeScanUrl('Contoh.COM:443/a/../b?utm_source=x&b=2&a=1#x')).toBe(
      'https://contoh.com/b?a=1&b=2',
    )
    expect(() => normalizeScanUrl('http://192.168.0.1')).toThrow(ScanUrlError)
    expect(() => normalizeScanUrl('http://[::ffff:127.0.0.1]')).toThrow(ScanUrlError)
    expect(() => normalizeScanUrl('http://localhost:3000')).toThrow(ScanUrlError)
    expect(() => normalizeScanUrl('http://metadata.google.internal/computeMetadata')).toThrow(
      ScanUrlError,
    )
    expect(() => normalizeScanUrl('ftp://contoh.com/file')).toThrow(ScanUrlError)
  })

  it('mendeteksi parameter dan jalur yang sensitif', () => {
    expect(detectSensitiveUrl('https://contoh.com/?token=abc').sensitive).toBe(true)
    expect(detectSensitiveUrl('https://contoh.com/?email=user@example.com').sensitive).toBe(true)
    expect(detectSensitiveUrl('https://contoh.com/reset/abcdefghijklmnop123456').sensitive).toBe(
      true,
    )
    expect(detectSensitiveUrl('https://contoh.com/artikel?halaman=2').sensitive).toBe(false)
  })
})

describe('orkestrasi multi-sumber', () => {
  beforeEach(() => {
    resetScanState()
  })

  it('tanpa key hanya OpenPhish non-kunci yang dipanggil, adapter berkredensial tidak', async () => {
    const fetchMock = mockFetch((url) => {
      if (url === OPENPHISH_FEED_URL) return textResponse('https://phish.example.org/login\n')
      throw new Error(`Unexpected URL: ${url}`)
    })
    const result = await runMultiSourceScan({
      uid: 'user-unconfigured',
      url: 'https://contoh.com',
      config: makeConfig(),
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: () => 1_700_000_000_000,
    })

    expect(result.providers).toHaveLength(8)
    expect(callsOf(fetchMock)).toEqual([OPENPHISH_FEED_URL])
    expect(
      result.providers
        .filter((provider) => provider.id !== 'openphish')
        .every((provider) => provider.status === 'not_configured'),
    ).toBe(true)
    expect(result.sharedWithProviders).toEqual(['openphish'])
  })

  it('memakai anggaran waktu khusus adapter, bukan hanya batas default provider', async () => {
    vi.useFakeTimers()
    try {
      const hangingCheck = (): Promise<ProviderCheck> =>
        new Promise<ProviderCheck>(() => undefined)
      const shortBudget: ProviderAdapter = {
        id: 'urlscan',
        label: 'URLScan.io',
        isConfigured: () => true,
        check: hangingCheck,
      }
      const longBudget: ProviderAdapter = {
        ...shortBudget,
        id: 'radar',
        label: 'Cloudflare Radar URL Scanner',
        timeoutMs: 20_000,
      }

      const start = (adapter: ProviderAdapter) => {
        let settled = false
        const promise = runMultiSourceScan({
          uid: `user-budget-${adapter.id}`,
          url: 'https://contoh.com',
          config: makeConfig(),
          fetchImpl: mockFetch(() => jsonResponse({})) as unknown as typeof fetch,
          adapters: [adapter],
          providerTimeoutMs: 2_000,
        }).then((result) => {
          settled = true
          return result
        })
        return { promise, isSettled: () => settled }
      }

      const withoutAdapterBudget = start(shortBudget)
      await vi.advanceTimersByTimeAsync(5_000)
      expect((await withoutAdapterBudget.promise).providers[0]?.status).toBe('timeout')

      const withAdapterBudget = start(longBudget)
      await vi.advanceTimersByTimeAsync(5_000)
      expect(withAdapterBudget.isSettled()).toBe(false)
      await vi.advanceTimersByTimeAsync(20_000)
      expect((await withAdapterBudget.promise).providers[0]?.status).toBe('timeout')
    } finally {
      vi.useRealTimers()
    }
  })

  it('tidak mengirim URL sensitif ke provider', async () => {
    const fetchMock = mockFetch(() => jsonResponse({}))
    const result = await runMultiSourceScan({
      uid: 'user-sensitive',
      url: 'https://contoh.com/?token=rahasia',
      config: makeConfig({ virusTotalApiKey: 'test-key' }),
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: () => 1_700_000_000_000,
    })

    expect(result.sensitiveUrl).toBe(true)
    expect(result.privacyReasons.length).toBeGreaterThan(0)
    expect(result.sharedWithProviders).toEqual([])
    expect(result.providers.every((provider) => provider.status === 'skipped')).toBe(true)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('menggabungkan status provider yang tersedia', async () => {
    const fetchMock = mockFetch((url) => {
      if (url.includes('urlscan.io/api/v1/scan')) {
        return jsonResponse({ uuid: '11111111-1111-1111-1111-111111111111' })
      }
      if (url.includes('urlscan.io/api/v1/result')) {
        return jsonResponse({
          verdicts: {
            overall: { score: 0, malicious: false, categories: [] },
            engines: { malicious: false, maliciousTotal: 0 },
          },
        })
      }
      if (url.includes('virustotal.com')) {
        return jsonResponse({
          data: {
            attributes: {
              last_analysis_stats: {
                malicious: 2,
                suspicious: 0,
                harmless: 60,
                undetected: 3,
              },
            },
          },
        })
      }
      if (url === OPENPHISH_FEED_URL) {
        return textResponse('https://phish.example.org/login\n')
      }
      if (url.includes('api.cloudflare.com/client/v4/accounts')) {
        if (url.includes('/urlscanner/v2/search')) {
          return jsonResponse({ results: [] })
        }
        if (url.endsWith('/urlscanner/v2/scan')) {
          return jsonResponse({
            success: true,
            result: { uuid: '11111111-1111-4111-8111-111111111111' },
          })
        }
        return jsonResponse({
          task: { status: 'finished', reportURL: 'https://radar.cloudflare.com/scan/x' },
          verdicts: { overall: { malicious: false, hasVerdicts: true, categories: [], tags: [] } },
        })
      }
      if (url.includes('threatfox-api')) {
        return jsonResponse({ query_status: 'no_result' })
      }
      if (url.includes('otx.alienvault.com')) {
        return jsonResponse({ pulse_info: { count: 0, pulses: [] } })
      }
      throw new Error(`Unexpected URL: ${url}`)
    })

    const result = await runMultiSourceScan({
      uid: 'user-configured',
      url: 'https://contoh.com',
      config: makeConfig({
        urlscanApiKey: 'urlscan-key',
        virusTotalApiKey: 'vt-key',
        threatFoxApiKey: 'tf-key',
        cloudflareApiToken: 'cf-token',
        cloudflareAccountId: 'cf-account',
        otxApiKey: 'otx-key',
      }),
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: () => 1_700_000_000_000,
      sleep: async () => undefined,
    })

    const byId = new Map(result.providers.map((provider) => [provider.id, provider]))
    expect(result.sharedWithProviders).toHaveLength(6)
    expect(byId.get('urlscan')?.status).toBe('success')
    expect(byId.get('virustotal')?.verdict).toBe('malicious')
    expect(byId.get('openphish')?.verdict).toBe('inconclusive')
    expect(byId.get('openphish')?.status).toBe('not_found')
    expect(byId.get('threatfox')?.status).toBe('not_found')
    expect(byId.get('radar')?.verdict).toBe('clean')
    expect(byId.get('otx')?.status).toBe('not_found')
  })

  it('hanya mencatat provider yang benar-benar menerima request URL', async () => {
    const fetchMock = mockFetch(() =>
      jsonResponse({
        data: {
          attributes: {
            last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 10, undetected: 1 },
          },
        },
      }),
    )

    const result = await runMultiSourceScan({
      uid: 'user-sharing',
      url: 'https://contoh.com',
      config: makeConfig({ virusTotalApiKey: 'vt-key' }),
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: () => 1_700_000_000_000,
      sleep: async () => undefined,
    })

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(result.sharedWithProviders).toEqual(['virustotal', 'openphish'])
  })

  it('tetap mencatat provider yang request-nya gagal setelah dikirim', async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error('network down')
    })

    const result = await runMultiSourceScan({
      uid: 'user-sharing-failed',
      url: 'https://contoh.com',
      config: makeConfig({ virusTotalApiKey: 'vt-key' }),
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: () => 1_700_000_000_000,
      sleep: async () => undefined,
    })

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(result.sharedWithProviders).toEqual(['virustotal', 'openphish'])
  })

  it('melanjutkan provider lain saat satu provider gagal', async () => {
    const fetchMock = mockFetch((url) => {
      if (url.includes('urlscan.io/api/v1/search')) {
        return jsonResponse({ results: [] })
      }
      if (url.includes('urlscan.io/api/v1/scan')) {
        return jsonResponse({ error: 'unavailable' }, 503)
      }
      if (url.includes('virustotal.com')) {
        return jsonResponse({
          data: {
            attributes: {
              last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 10, undetected: 1 },
            },
          },
        })
      }
      if (url === OPENPHISH_FEED_URL) return textResponse('https://phish.example.org/login\n')
      if (url.includes('threatfox-api')) return jsonResponse({ query_status: 'no_result' })
      if (url.includes('api.cloudflare.com/client/v4/accounts')) {
        if (url.endsWith('/urlscanner/v2/scan')) {
          return jsonResponse({
            success: true,
            result: { uuid: '11111111-1111-4111-8111-111111111111' },
          })
        }
        return jsonResponse({
          task: { status: 'finished' },
          verdicts: { overall: { malicious: false, hasVerdicts: true } },
        })
      }
      if (url.includes('otx.alienvault.com')) {
        return jsonResponse({ pulse_info: { count: 0, pulses: [] } })
      }
      throw new Error(`Unexpected URL: ${url}`)
    })

    const result = await runMultiSourceScan({
      uid: 'user-partial-failure',
      url: 'https://contoh.com',
      config: makeConfig({
        urlscanApiKey: 'urlscan-key',
        virusTotalApiKey: 'vt-key',
        threatFoxApiKey: 'tf-key',
        cloudflareApiToken: 'cf-token',
        cloudflareAccountId: 'cf-account',
        otxApiKey: 'otx-key',
      }),
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: () => 1_700_000_000_000,
      sleep: async () => undefined,
    })

    const byId = new Map(result.providers.map((provider) => [provider.id, provider]))
    expect(byId.get('urlscan')?.status).toBe('unavailable')
    expect(byId.get('virustotal')?.status).toBe('success')
    expect(byId.get('openphish')?.status).toBe('not_found')
    expect(byId.get('threatfox')?.status).toBe('not_found')
    expect(byId.get('radar')?.status).toBe('success')
    expect(byId.get('otx')?.status).toBe('not_found')
  })

  it('satu provider yang melempar error tidak menggagalkan provider lain', async () => {
    // Regresi inti: setelah roster jadi 8 agen, satu adapter yang reject/tidak boleh
    // membuat runMultiSourceScan gagal total. Setiap agen harus punya status final.
    resetScanState()
    const throwing: ProviderAdapter = {
      id: 'hybrid',
      label: 'Hybrid Analysis',
      isConfigured: () => true,
      async check(): Promise<ProviderCheck> {
        throw new Error('adapter meledak')
      },
    }
    const timeoutBudget: ProviderAdapter = {
      id: 'safebrowsing',
      label: 'Google Safe Browsing',
      isConfigured: () => true,
      timeoutMs: 1_000,
      check: () => new Promise<ProviderCheck>(() => undefined),
    }
    const okCheck = (): ProviderCheck => ({
      status: 'success',
      verdict: 'clean',
      score: 0,
      summary: 'Tidak ditemukan indikasi.',
      signals: [],
      reason: null,
    })
    const healthy: ProviderAdapter[] = (['urlscan', 'virustotal', 'openphish'] as const).map(
      (id) => ({
        id,
        label: id,
        isConfigured: () => true,
        check: async () => okCheck(),
      }),
    )

    vi.useFakeTimers()
    try {
      const scan = runMultiSourceScan({
        uid: 'user-throw-isolation',
        url: 'https://contoh.com',
        config: makeConfig(),
        fetchImpl: mockFetch(() => jsonResponse({})) as unknown as typeof fetch,
        adapters: [...healthy, throwing, timeoutBudget],
        providerTimeoutMs: 1_000,
        scanTimeoutMs: 5_000,
      })
      await vi.advanceTimersByTimeAsync(6_000)
      const result = await scan
      await vi.runAllTimersAsync()

      const byId = new Map(result.providers.map((provider) => [provider.id, provider]))
      expect(byId.get('hybrid')?.status).toBe('error')
      expect(byId.get('safebrowsing')?.status).toBe('timeout')
      for (const adapter of healthy) {
        expect(byId.get(adapter.id)?.status).toBe('success')
      }
      // Semua lima agen punya baris final — scan tidak gagal total.
      expect(result.providers).toHaveLength(5)
    } finally {
      vi.useRealTimers()
    }
  })

  it('Agen 7 dan Agen 8 yang belum terkonfigurasi tidak menghentikan enam agen lain', async () => {
    resetScanState()
    const fetchMock = mockFetch((url) => {
      if (url.includes('urlscan.io/api/v1/search')) return jsonResponse({ results: [] })
      if (url.includes('urlscan.io/api/v1/scan')) {
        return jsonResponse({ result: 'https://urlscan.io/result/abc/' })
      }
      if (url.includes('urlscan.io/api/v1/result/')) {
        return jsonResponse({
          result: { verdicts: { overall: { malicious: false } }, stats: {}, page: {}, meta: {} },
        })
      }
      if (url.includes('virustotal.com')) {
        return jsonResponse({
          data: {
            attributes: {
              last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 10, undetected: 1 },
            },
          },
        })
      }
      if (url === OPENPHISH_FEED_URL) return textResponse('https://phish.example.org/login\n')
      if (url.includes('threatfox-api')) return jsonResponse({ query_status: 'no_result' })
      if (url.includes('api.cloudflare.com/client/v4/accounts')) {
        if (url.endsWith('/urlscanner/v2/scan')) {
          return jsonResponse({
            success: true,
            result: { uuid: '11111111-1111-4111-8111-111111111111' },
          })
        }
        return jsonResponse({
          task: { status: 'finished' },
          verdicts: { overall: { malicious: false, hasVerdicts: true } },
        })
      }
      if (url.includes('otx.alienvault.com')) {
        return jsonResponse({ pulse_info: { count: 0, pulses: [] } })
      }
      throw new Error(`Unexpected URL: ${url}`)
    })

    const result = await runMultiSourceScan({
      uid: 'user-a7-a8-unconfigured',
      url: 'https://contoh.com',
      // Kunci diisi untuk agen 1-6; agen 7 selalu not_configured, agen 8 tanpa kunci.
      config: makeConfig({
        urlscanApiKey: 'urlscan-key',
        virusTotalApiKey: 'vt-key',
        threatFoxApiKey: 'tf-key',
        cloudflareApiToken: 'cf-token',
        cloudflareAccountId: 'cf-account',
        otxApiKey: 'otx-key',
      }),
      fetchImpl: fetchMock as unknown as typeof fetch,
      now: () => 1_700_000_000_000,
      sleep: async () => undefined,
    })

    const byId = new Map(result.providers.map((provider) => [provider.id, provider]))
    // Agen 7 (hybrid) & Agen 8 (safebrowsing) not_configured — tapi scan tetap selesai.
    expect(byId.get('hybrid')?.status).toBe('not_configured')
    expect(byId.get('safebrowsing')?.status).toBe('not_configured')
    // Enam agen lama tetap menghasilkan status konklusif, tidak ikut mati.
    expect(byId.get('virustotal')?.status).toBe('success')
    expect(byId.get('openphish')?.status).toBe('not_found')
    expect(byId.get('threatfox')?.status).toBe('not_found')
    expect(byId.get('radar')?.status).toBe('success')
    expect(byId.get('otx')?.status).toBe('not_found')
    expect(result.providers).toHaveLength(8)
  })

  it('membatasi jumlah pemeriksaan per pengguna', async () => {
    for (let index = 0; index < 6; index += 1) {
      await runMultiSourceScan({
        uid: 'user-rate-limit',
        url: 'https://contoh.com',
        config: makeConfig(),
        fetchImpl: mockFetch(() => jsonResponse({})) as unknown as typeof fetch,
        now: () => 1_700_000_000_000,
      })
    }

    const limitedFetch = mockFetch(() => jsonResponse({}))
    const result = await runMultiSourceScan({
      uid: 'user-rate-limit',
      url: 'https://contoh.com',
      config: makeConfig(),
      fetchImpl: limitedFetch as unknown as typeof fetch,
      now: () => 1_700_000_000_000,
    })

    expect(result.providers.every((provider) => provider.status === 'rate_limited')).toBe(true)
    expect(result.providers.every((provider) => provider.summary === 'Batas pemeriksaan eksternal tercapai.')).toBe(true)
    // Penolakan datang dari VERIGUARD sebelum agen dipanggil, jadi tidak boleh menyamar
    // sebagai kuota provider dan harus menyebut kapan pengguna boleh mencoba lagi.
    expect(result.providers[0]?.reason).toContain('bukan kuota agen')
    expect(result.providers[0]?.reason).toMatch(/Coba lagi dalam ±\d+ detik\./)
    expect(limitedFetch).not.toHaveBeenCalled()
  })
})

describe('adapter VirusTotal', () => {
  it('menerjemahkan engine berbahaya menjadi verdict malicious', async () => {
    const fetchMock = mockFetch(() =>
      jsonResponse({
        data: {
          attributes: {
            last_analysis_stats: { malicious: 1, suspicious: 0, harmless: 10, undetected: 0 },
          },
        },
      }),
    )
    const check = await virusTotalAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ virusTotalApiKey: 'vt-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('malicious')
    expect(check.score).toBeGreaterThanOrEqual(60)
    expect(check.summary).toContain('1/11 engine mendeteksi berbahaya')
    const ratioSignal = check.signals.find(
      (signal) => signal.label === 'Detection ratio VirusTotal',
    )
    expect(ratioSignal?.detail).toContain('1/11 security engine')
    expect(ratioSignal?.detail).toContain('9.09%')
    expect(fetchMock).toHaveBeenCalledWith(
      'https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly9jb250b2guY29tL3BhdGg',
      expect.anything(),
    )
  })

  it('menandai detection ratio tidak tersedia bila tidak ada engine melaporkan hasil', async () => {
    const fetchMock = mockFetch(() =>
      jsonResponse({
        data: {
          attributes: {
            last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
          },
        },
      }),
    )
    const check = await virusTotalAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ virusTotalApiKey: 'vt-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('inconclusive')
    const ratioSignal = check.signals.find(
      (signal) => signal.label === 'Detection ratio VirusTotal',
    )
    expect(ratioSignal?.detail).toContain('Tidak tersedia')
  })

  it('memperlakukan laporan engine yang sedikit sebagai belum konklusif', async () => {
    const fetchMock = mockFetch(() =>
      jsonResponse({
        data: {
          attributes: {
            last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 2, undetected: 1 },
          },
        },
      }),
    )
    const check = await virusTotalAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ virusTotalApiKey: 'vt-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('inconclusive')
    expect(check.summary).toContain('0/3 engine')
    expect(check.reason).toContain('belum dapat dibaca sebagai aman')
  })

  it('menyatakan tanpa indikasi hanya ketika cukup engine melaporkan hasil', async () => {
    const fetchMock = mockFetch(() =>
      jsonResponse({
        data: {
          attributes: {
            last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 59, undetected: 34 },
          },
        },
      }),
    )
    const check = await virusTotalAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ virusTotalApiKey: 'vt-key' }),
    )

    expect(check.verdict).toBe('clean')
    expect(check.summary).toBe('0/93 engine mendeteksi berbahaya.')
    const quiet = check.signals.find((signal) => signal.label === 'Engine tidak menemukan indikasi')
    expect(quiet?.detail).toContain('59 dari 93')
  })

  it('memetakan 404 dan 429 ke status yang tepat', async () => {
    const missing = await virusTotalAdapter.check(
      context(mockFetch(() => jsonResponse({}, 404)) as unknown as typeof fetch),
      makeConfig({ virusTotalApiKey: 'vt-key' }),
    )
    expect(missing.status).toBe('not_found')

    const limited = await virusTotalAdapter.check(
      context(mockFetch(() => jsonResponse({}, 429)) as unknown as typeof fetch),
      makeConfig({ virusTotalApiKey: 'vt-key' }),
    )
    expect(limited.status).toBe('rate_limited')
  })

  it('menolak kredensial yang tidak valid', async () => {
    const check = await virusTotalAdapter.check(
      context(mockFetch(() => jsonResponse({}, 401)) as unknown as typeof fetch),
      makeConfig({ virusTotalApiKey: 'invalid' }),
    )

    expect(check.status).toBe('auth_failed')
    expect(check.reason).toContain('Kredensial')
  })

  it('mempertahankan waktu laporan asli sebagai metadata, bukan sebagai kalimat di teks hasil', async () => {
    const lastAnalysis = 1_700_000_000_000 - 2 * 60 * 60_000
    const fetchMock = mockFetch(() =>
      jsonResponse({
        data: {
          attributes: {
            last_analysis_date: Math.round(lastAnalysis / 1_000),
            last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 59, undetected: 34 },
          },
        },
      }),
    )
    const check = await virusTotalAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ virusTotalApiKey: 'vt-key' }),
    )

    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence?.observedAt).toBe(new Date(lastAnalysis).toISOString())
    expect(check.evidence?.ageMs).toBe(2 * 60 * 60_000)
    // Waktu analisis yang sebenarnya tetap ditampilkan, sebagai tanggal — bukan sebagai
    // umur entri, dan tanpa penjelasan cara pengambilan hasil.
    const provenance = check.signals.find((signal) => signal.label === 'Waktu analisis terakhir')
    expect(provenance?.detail).toMatch(/^Analisis terakhir \d/)
    expect(provenance?.detail).not.toContain('2 jam')
    expect(provenance?.severity).toBe('info')
    expect(notCacheNarrative(check)).toBe(true)
  })

  it('menandai laporan yang melewati batas umur laporan sebagai bukti lama', async () => {
    const lastAnalysis = 1_700_000_000_000 - 200 * 60 * 60_000
    const check = await virusTotalAdapter.check(
      context(
        mockFetch(() =>
          jsonResponse({
            data: {
              attributes: {
                last_analysis_date: Math.round(lastAnalysis / 1_000),
                last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 59, undetected: 34 },
              },
            },
          }),
        ) as unknown as typeof fetch,
      ),
      makeConfig({ virusTotalApiKey: 'vt-key' }),
    )

    expect(check.evidence?.ageMs).toBe(200 * 60 * 60_000)
    const provenance = check.signals.find((signal) => signal.label === 'Waktu analisis terakhir')
    expect(provenance?.detail).toContain('melewati batas umur laporan 168 jam')
    expect(provenance?.severity).toBe('warning')
    expect(notCacheNarrative(check)).toBe(true)
  })

  it('memakai batas kesegaran laporan VirusTotal dari konfigurasi', async () => {
    const lastAnalysis = 1_700_000_000_000 - 48 * 60 * 60_000
    const body = {
      data: {
        attributes: {
          last_analysis_date: Math.round(lastAnalysis / 1_000),
          last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 59, undetected: 34 },
        },
      },
    }
    const check = await virusTotalAdapter.check(
      context(mockFetch(() => jsonResponse(body)) as unknown as typeof fetch),
      makeConfig({ virusTotalApiKey: 'vt-key', virusTotalMaxReportAgeHours: 24 }),
    )

    const provenance = check.signals.find((signal) => signal.label === 'Waktu analisis terakhir')
    expect(provenance?.detail).toContain('melewati batas umur laporan 24 jam')
    expect(provenance?.severity).toBe('warning')
  })

  it('tidak mengarang waktu analisis ketika VirusTotal tidak melaporkannya', async () => {
    const check = await virusTotalAdapter.check(
      context(
        mockFetch(() =>
          jsonResponse({
            data: {
              attributes: {
                last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 59, undetected: 34 },
              },
            },
          }),
        ) as unknown as typeof fetch,
      ),
      makeConfig({ virusTotalApiKey: 'vt-key' }),
    )

    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence?.observedAt).toBeNull()
    expect(check.evidence?.ageMs).toBeNull()
    const provenance = check.signals.find((signal) => signal.label === 'Waktu analisis terakhir')
    expect(provenance?.detail).toContain('tidak melaporkan waktu analisis terakhir')
  })

  it('hanya melakukan lookup laporan tanpa pernah mengirim analisis baru', async () => {
    const init: RequestInit[] = []
    const fetchMock = vi.fn(
      async (_input: string | URL | Request, requestInit?: RequestInit) => {
        init.push(requestInit ?? {})
        return jsonResponse({
          data: {
            attributes: {
              last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 59, undetected: 34 },
            },
          },
        })
      },
    )

    await virusTotalAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ virusTotalApiKey: 'vt-key' }),
    )

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(init[0]?.method ?? 'GET').toBe('GET')
    expect(String(fetchMock.mock.calls[0]?.[0])).not.toContain('/analyses')
  })

  it('tidak membaca laporan yang belum ada sebagai aman', async () => {
    const missing = await virusTotalAdapter.check(
      context(mockFetch(() => jsonResponse({}, 404)) as unknown as typeof fetch),
      makeConfig({ virusTotalApiKey: 'vt-key' }),
    )

    expect(missing.status).toBe('not_found')
    expect(missing.verdict).toBe('inconclusive')
    expect(missing.evidence).toBeUndefined()
  })
})

describe('adapter URLScan', () => {
  const SCAN_UUID = '11111111-1111-1111-1111-111111111111'
  const REPORT_UUID = '22222222-2222-2222-2222-222222222222'
  const CLEAN_BODY = {
    verdicts: {
      overall: { score: 0, malicious: false, categories: ['business'] },
      engines: { malicious: false, maliciousTotal: 0 },
    },
  }
  // Jam context() = 1_700_000_000_000 → 2023-11-14T22:13:20.000Z.
  const NOW_MS = 1_700_000_000_000

  function scanRecords(ageMs: number, url = 'https://contoh.com/path') {
    return {
      results: [
        {
          page: { url },
          task: {
            uuid: REPORT_UUID,
            url,
            time: new Date(NOW_MS - ageMs).toISOString(),
          },
        },
      ],
    }
  }

  // Router eksplisit agar tiap operasi (search, submit, result) dapat dihitung terpisah.
  function urlscanFetch(
    handlers: Partial<Record<'search' | 'submit' | 'result', (url: string) => Response>>,
    onCall?: (kind: 'search' | 'submit' | 'result') => void,
  ) {
    return mockFetch((url) => {
      if (url.includes('/api/v1/search/')) {
        onCall?.('search')
        return handlers.search?.(url) ?? jsonResponse({ results: [] })
      }
      if (url.includes('/api/v1/scan/')) {
        onCall?.('submit')
        return handlers.submit?.(url) ?? jsonResponse({ uuid: SCAN_UUID })
      }
      onCall?.('result')
      return handlers.result?.(url) ?? jsonResponse(CLEAN_BODY)
    })
  }

  function httpError(status: number, headers: Record<string, string> = {}): Response {
    return new Response(JSON.stringify({ message: 'request rejected' }), { status, headers })
  }

  it('memakai laporan yang sudah ada tanpa mengirim pemindaian baru', async () => {
    const calls: string[] = []
    const fetchMock = urlscanFetch(
      {
        search: () => jsonResponse(scanRecords(3_600_000)),
        result: () => jsonResponse(CLEAN_BODY),
      },
      (kind) => calls.push(kind),
    )

    const check = await urlScanAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(calls).toEqual(['search', 'result'])
    expect(check.status).toBe('success')
    expect(check.verdict).toBe('clean')
    expect(check.evidence?.source).toBe('existing_report')
    // Waktu laporan asli dipertahankan, bukan diganti waktu pemeriksaan ini.
    expect(check.evidence?.observedAt).toBe(new Date(NOW_MS - 3_600_000).toISOString())
    expect(check.evidence?.ageMs).toBe(3_600_000)
    // Vonis agen tetap utuh dan tidak ada kalimat tentang cara hasil diperoleh.
    expect(check.summary).toBe('URLScan tidak menemukan indikasi berbahaya.')
    expect(check.reason).toBeNull()
    expect(notCacheNarrative(check)).toBe(true)
  })

  it('tidak memakai laporan URL lain walau cocok secara pencarian', async () => {
    const calls: string[] = []
    const fetchMock = urlscanFetch(
      {
        // URLScan mengindeks halaman akhir; laporan untuk URL berbeda tidak boleh dipakai.
        search: () => jsonResponse(scanRecords(60_000, 'https://lain.com/path')),
      },
      (kind) => calls.push(kind),
    )

    const check = await urlScanAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(calls).toEqual(['search', 'submit', 'result'])
    expect(check.evidence?.source).toBe('new_scan')
  })

  it('tidak memakai laporan yang lebih tua dari kebijakan kesegaran', async () => {
    const calls: string[] = []
    const fetchMock = urlscanFetch(
      { search: () => jsonResponse(scanRecords(48 * 60 * 60_000)) },
      (kind) => calls.push(kind),
    )

    const check = await urlScanAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(calls).toEqual(['search', 'submit', 'result'])
    expect(check.evidence?.source).toBe('new_scan')
  })

  it('mengizinkan kebijakan kesegaran laporan diganti lewat konfigurasi', async () => {
    const calls: string[] = []
    const fetchMock = urlscanFetch(
      { search: () => jsonResponse(scanRecords(48 * 60 * 60_000)) },
      (kind) => calls.push(kind),
    )

    const check = await urlScanAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key', urlscanMaxReportAgeHours: 72 }),
    )

    expect(calls).toEqual(['search', 'result'])
    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence?.ageMs).toBe(48 * 60 * 60_000)
  })

  it('tidak mengirim ulang pemindaian setelah HTTP 429 pada submit', async () => {
    const calls: string[] = []
    const fetchMock = urlscanFetch(
      {
        submit: () =>
          httpError(429, {
            'x-rate-limit-scope': 'user',
            'x-rate-limit-action': 'private',
            'x-rate-limit-window': 'day',
            'x-rate-limit-limit': '50',
            'x-rate-limit-remaining': '0',
            'x-rate-limit-reset-after': '3600',
          }),
      },
      (kind) => calls.push(kind),
    )

    const check = await urlScanAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(calls).toEqual(['search', 'submit'])
    expect(check.status).toBe('rate_limited')
    // Kegagalan teknis tidak pernah diubah menjadi vonis aman.
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.reason).toContain('HTTP 429')
    expect(check.reason).toContain('sisa 0 dari 50')
    expect(check.reason).toContain('jendela kuota berikutnya terbuka dalam ±3600 detik')
  })

  it('memakai laporan lama sebagai fallback hanya ketika submit dibatasi kuota', async () => {
    const calls: string[] = []
    const fetchMock = urlscanFetch(
      {
        search: () => jsonResponse(scanRecords(48 * 60 * 60_000)),
        submit: () => httpError(429),
      },
      (kind) => calls.push(kind),
    )

    const check = await urlScanAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(calls).toEqual(['search', 'submit', 'result'])
    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence?.ageMs).toBe(48 * 60 * 60_000)
    expect(notCacheNarrative(check)).toBe(true)
  })

  it('berhenti pada 429 lookup tanpa mengirim pemindaian baru', async () => {
    const calls: string[] = []
    const fetchMock = urlscanFetch({ search: () => httpError(429) }, (kind) => calls.push(kind))

    const check = await urlScanAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(calls).toEqual(['search'])
    expect(check.status).toBe('rate_limited')
  })

  it('tetap mengirim pemindaian privat dan tidak menaikkan visibilitas demi kuota', async () => {
    const bodies: string[] = []
    const fetchMock = urlscanFetch({
      submit: () => {
        return jsonResponse({ uuid: SCAN_UUID })
      },
    })

    await urlScanAdapter.check(
      {
        ...context(fetchMock as unknown as typeof fetch),
        fetchImpl: ((input: string | URL | Request, init?: RequestInit) => {
          if (typeof init?.body === 'string') bodies.push(init.body)
          return (fetchMock as unknown as typeof fetch)(input, init)
        }) as typeof fetch,
      },
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(bodies).toHaveLength(1)
    expect(JSON.parse(bodies[0])).toEqual({ url: 'https://contoh.com/path', visibility: 'private' })
  })

  it('mengirim pemindaian private lalu membaca verdict', async () => {
    const fetchMock = urlscanFetch({
      result: (() => {
        let seen = 0
        return () => {
          seen += 1
          return seen === 1 ? httpError(404) : jsonResponse(CLEAN_BODY)
        }
      })(),
    })

    const check = await urlScanAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('clean')
    expect(check.evidence?.source).toBe('new_scan')
  })

  it('menghentikan polling dalam anggarannya lalu menandai timeout', async () => {
    const fetchMock = urlscanFetch({ result: () => httpError(404) })
    const timed = tickingContext(fetchMock as unknown as typeof fetch)

    const check = await urlScanAdapter.check(
      timed.context,
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(check.status).toBe('timeout')
    // Anggaran polling 60 dtk dipakai penuh dan berhenti sendiri, bukan dipotong
    // pembatas waktu provider, sehingga tidak ada `timeout` palsu di tengah antrean.
    // 1 search + 1 submit + 27 percobaan hasil.
    expect(fetchMock).toHaveBeenCalledTimes(29)
    expect(timed.elapsed()).toBeLessThanOrEqual(60_000)
  })

  it('menunda sekali dengan jeda dari Retry-After ketika hasil sementara dibatasi', async () => {
    const delays: number[] = []
    const fetchMock = urlscanFetch({
      result: (() => {
        let seen = 0
        return () => {
          seen += 1
          return seen === 1
            ? httpError(429, { 'Retry-After': '15' })
            : jsonResponse(CLEAN_BODY)
        }
      })(),
    })

    const timed = tickingContext(fetchMock as unknown as typeof fetch, (ms) => delays.push(ms))
    const check = await urlScanAdapter.check(
      timed.context,
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    // Pemindaian yang sudah dikirim tidak boleh dibuang hanya karena satu 429.
    expect(check.status).toBe('success')
    expect(delays).toEqual([2_000, 15_000])
  })

  it('tetap melaporkan kuota ketika 429 terulang dan tidak membalas dengan spam', async () => {
    const delays: number[] = []
    const fetchMock = urlscanFetch({ result: () => httpError(429) })

    const timed = tickingContext(fetchMock as unknown as typeof fetch, (ms) => delays.push(ms))
    const check = await urlScanAdapter.check(
      timed.context,
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(check.status).toBe('rate_limited')
    expect(delays).toEqual([2_000, 8_000])
    // 1 search + 1 submit + 2 percobaan hasil: hanya satu percobaan ulang yang diizinkan.
    expect(fetchMock).toHaveBeenCalledTimes(4)
  })

  it('memulai polling setelah 2 detik lalu memakai interval 2 detik', async () => {
    const delays: number[] = []
    const fetchMock = urlscanFetch({
      result: (() => {
        let seen = 0
        return () => {
          seen += 1
          return seen === 1 ? httpError(404) : jsonResponse(CLEAN_BODY)
        }
      })(),
    })

    await urlScanAdapter.check(
      {
        ...context(fetchMock as unknown as typeof fetch),
        sleep: async (ms) => {
          delays.push(ms)
        },
      },
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(delays).toEqual([2_000, 2_000])
  })

  it('menolak kredensial yang tidak valid tanpa melakukan polling', async () => {
    const fetchMock = mockFetch(() => httpError(403))
    const check = await urlScanAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'invalid' }),
    )

    expect(check.status).toBe('auth_failed')
    expect(check.reason).toContain('Kredensial')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  // Regresi Issue 3: provider mengembalikan malicious=true dengan skor mentah 0 dan tanpa
  // detail engine/kategori/tag. Dulu summary menulis "skor 0/100" sementara field `score`
  // dinaikkan ke 75, membingungkan pengguna. Sekarang summary memakai skor band final dan
  // signal "Skor mentah provider" + "Keterbatasan bukti" menjelaskan apa adanya.
  it('menjelaskan band dan keterbatasan bukti ketika URLScan memberi malicious=true dengan skor mentah 0', async () => {
    const fetchMock = urlscanFetch({
      result: () =>
        jsonResponse({
          verdicts: {
            overall: { score: 0, malicious: true, categories: [] },
            engines: { malicious: true, maliciousTotal: 0 },
          },
        }),
    })

    const check = await urlScanAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('malicious')
    // Skor field dan skor yang ditulis pada summary WAJIB identik.
    expect(check.score).toBe(75)
    expect(check.summary).toBe('URLScan menilai URL ini berbahaya (skor 75/100).')

    const labels = check.signals.map((signal) => signal.label)
    expect(labels).toContain('Makna skor')
    expect(labels).toContain('Skor mentah provider')
    expect(labels).toContain('Keterbatasan bukti')
    // Detail skor mentah provider tidak dikarang — persis angka yang dikirim provider.
    const raw = check.signals.find((signal) => signal.label === 'Skor mentah provider')
    expect(raw?.detail).toContain('skor mentah 0/100')
    expect(raw?.detail).toContain('band menjadi 75/100')
  })

  it('tidak mengarang detail bukti ketika kategori/tag/brand dan maliciousTotal kosong', async () => {
    const fetchMock = urlscanFetch({
      result: () =>
        jsonResponse({
          verdicts: {
            overall: { score: 80, malicious: true },
            engines: { malicious: true },
          },
        }),
    })

    const check = await urlScanAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    const labels = check.signals.map((signal) => signal.label)
    // Signal bukti konkret tidak boleh muncul karena provider memang tidak mengirim datanya.
    expect(labels).not.toContain('Kategori URLScan')
    expect(labels).not.toContain('Tag URLScan')
    expect(labels).not.toContain('Merek yang terdeteksi')
    expect(labels).not.toContain('Mesin URLScan menandai ancaman')
    // Signal penjelas makna skor tetap ada; itu bagian dari kontrak VERIGUARD.
    expect(labels).toContain('Makna skor')
    // Karena malicious=true dan score=80 >= 75, band tidak berubah; "Skor mentah provider"
    // tidak muncul karena skor mentah sudah konsisten dengan vonis.
    expect(labels).not.toContain('Skor mentah provider')
    // Keterbatasan bukti muncul karena tidak ada detail kategori/tag/engine di respons.
    expect(labels).toContain('Keterbatasan bukti')
    expect(check.summary).toBe('URLScan menilai URL ini berbahaya (skor 80/100).')
    expect(check.score).toBe(80)
  })

  it('summary suspicious memakai band yang sama dengan field score', async () => {
    const fetchMock = urlscanFetch({
      result: () =>
        jsonResponse({
          verdicts: {
            overall: { score: 20, malicious: false, categories: ['phishing'] },
            engines: { malicious: false, maliciousTotal: 0 },
          },
        }),
    })

    const check = await urlScanAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(check.verdict).toBe('suspicious')
    expect(check.score).toBe(30)
    expect(check.summary).toBe('URLScan menemukan indikasi risiko (skor 30/100).')
  })
})

describe('adapter tambahan', () => {
  it('OpenPhish membaca feed komunitas resmi tanpa memerlukan kunci', async () => {
    const fetchMock = mockFetch((url) => {
      if (url === OPENPHISH_FEED_URL) return textResponse('https://contoh.com/path\nhttps://lain.example.org/\n')
      throw new Error(`Unexpected URL: ${url}`)
    })

    const check = await openPhishAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig(),
    )

    expect(openPhishAdapter.isConfigured(makeConfig())).toBe(true)
    expect(callsOf(fetchMock)).toEqual([OPENPHISH_FEED_URL])
    expect(check.status).toBe('success')
    expect(check.verdict).toBe('malicious')
    expect(check.summary).toContain('feed komunitas')
  })

  it('OpenPhish menghitung kecocokan tingkat hostname dari seluruh baris feed', async () => {
    // Indeks hostname dibangun sekali saat feed diunduh. Uji ini menjaga hasilnya tetap sama
    // dengan pembacaan baris per baris, termasuk baris yang tidak dapat diurai.
    const fetchMock = mockFetch((url) => {
      if (url === OPENPHISH_FEED_URL) {
        return textResponse(
          'https://contoh.com/masuk\nhttps://contoh.com/unduh\nhttps://lain.example.org/\nhttp://\n',
        )
      }
      throw new Error(`Unexpected URL: ${url}`)
    })

    const check = await openPhishAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig(),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('suspicious')
    expect(check.score).toBe(55)
    expect(check.summary).toContain('2 phish pada hostname yang sama')
    expect(check.reason).toContain('tingkat hostname')
  })

  it('OpenPhish tidak menyebut URL yang tidak tercatat sebagai aman', async () => {
    const check = await openPhishAdapter.check(
      context(
        mockFetch(() => textResponse('https://lain.example.org/login\n')) as unknown as typeof fetch,
      ),
      makeConfig(),
    )

    expect(check.status).toBe('not_found')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.reason).toContain('bukan bukti URL aman')
  })

  it('OpenPhish memberi vonis tingkat hostname bila hanya hostname yang tercatat', async () => {
    const check = await openPhishAdapter.check(
      context(
        mockFetch(() => textResponse('https://contoh.com/login\nhttps://lain.example.org/\n')) as unknown as typeof fetch,
      ),
      makeConfig(),
    )

    expect(check.verdict).toBe('suspicious')
    expect(check.signals[0]?.label).toContain('Hostname')
    expect(check.reason).toContain('tingkat hostname')
  })

  it('OpenPhish mengirim kunci sebagai header Authorization bila tersedia', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input) === OPENPHISH_FEED_URL) return textResponse('https://lain.example.org/\n')
      void init
      return jsonResponse({ found: true })
    })

    const check = await openPhishAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ openPhishApiKey: 'op-key' }),
    )

    const lookupCall = fetchMock.mock.calls.find(([input]) =>
      String(input).includes('openphish.eu/api/check'),
    )
    expect(lookupCall?.[1]?.headers).toMatchObject({ Authorization: 'Bearer op-key' })
    expect(callsOf(fetchMock as unknown as ReturnType<typeof mockFetch>)).toHaveLength(2)
    expect(check.verdict).toBe('malicious')
    expect(check.summary).toContain('phishing aktif')
  })

  it('OpenPhish tetap memakai jawaban lookup saat feed komunitas gagal', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      if (String(input) === OPENPHISH_FEED_URL) return jsonResponse({ error: 'unavailable' }, 503)
      return jsonResponse({ found: false })
    })

    const check = await openPhishAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ openPhishApiKey: 'op-key' }),
    )

    expect(check.status).toBe('not_found')
    expect(check.reason).toContain('Feed komunitas tidak dapat dibaca')
  })

  it('OpenPhish melaporkan kegagalan feed apa adanya tanpa sumber lain', async () => {
    const check = await openPhishAdapter.check(
      context(
        mockFetch(() => jsonResponse({ error: 'unavailable' }, 503)) as unknown as typeof fetch,
      ),
      makeConfig(),
    )

    expect(check.status).toBe('unavailable')
    expect(check.verdict).toBe('inconclusive')
  })

  it('OpenPhish menolak respons tanpa field found', async () => {
    const check = await openPhishAdapter.check(
      context(mockFetch(() => jsonResponse({})) as unknown as typeof fetch),
      makeConfig({ openPhishApiKey: 'op-key' }),
    )

    // Feed juga tidak dapat dibaca (respons JSON dianggap teks tanpa entri) => kegagalan teknis.
    expect(check.status).toBe('error')
    expect(check.reason).toContain('found')
  })

  it('ThreatFox mengirim pencarian IOC eksak dengan Auth-Key', async () => {
    const fetchMock = vi.fn(
      async (_input: string | URL | Request, _init?: RequestInit) =>
        jsonResponse({ query_status: 'no_result' }),
    )

    await threatFoxAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ threatFoxApiKey: 'tf-key' }),
    )

    const [input, init] = fetchMock.mock.calls[0] ?? []
    expect(String(input)).toBe('https://threatfox-api.abuse.ch/api/v1/')
    expect(init?.method).toBe('POST')
    expect(init?.headers).toMatchObject({ 'Auth-Key': 'tf-key' })
    expect(JSON.parse(String(init?.body))).toEqual({
      query: 'search_ioc',
      search_term: 'https://contoh.com/path',
      exact_match: true,
    })
  })

  it('ThreatFox membedakan tidak ada data dan IOC cocok', async () => {
    const missing = await threatFoxAdapter.check(
      context(mockFetch(() => jsonResponse({ query_status: 'no_result' })) as unknown as typeof fetch),
      makeConfig({ threatFoxApiKey: 'tf-key' }),
    )
    expect(missing.status).toBe('not_found')

    const found = await threatFoxAdapter.check(
      context(
        vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
          const term = String(JSON.parse(String(init?.body ?? '{}')).search_term)
          if (term !== 'https://contoh.com/path') return jsonResponse({ query_status: 'no_result' })
          return jsonResponse({
            query_status: 'ok',
            data: [
              {
                ioc: term,
                ioc_type: 'url',
                malware: 'AsyncRAT',
                threat_type: 'malware_download',
                confidence_level: 90,
                first_seen: '2026-01-01T00:00:00Z',
              },
            ],
          })
        }) as unknown as typeof fetch,
      ),
      makeConfig({ threatFoxApiKey: 'tf-key' }),
    )
    expect(found.verdict).toBe('malicious')
    expect(found.score).toBeGreaterThanOrEqual(90)
    expect(found.summary).toContain('1 IOC')
    const typeSignal = found.signals.find((signal) => signal.label === 'Tipe IOC')
    expect(typeSignal?.detail).toBe('url')
    const firstSeenSignal = found.signals.find(
      (signal) => signal.label === 'Indikator pertama tercatat',
    )
    expect(firstSeenSignal?.detail).toBe('2026-01-01T00:00:00Z')
  })

  it('ThreatFox mencari beberapa bentuk IOC dan mencatat bentuk yang cocok', async () => {
    const bodies: string[] = []
    const fetchMock = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      bodies.push(String(init?.body))
      return jsonResponse({ query_status: 'no_result' })
    })

    const check = await threatFoxAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ threatFoxApiKey: 'tf-key' }),
    )

    const terms = bodies.map((body) => String(JSON.parse(body).search_term))
    expect(terms).toContain('https://contoh.com/path')
    expect(terms).toContain('contoh.com')
    expect(bodies.every((body) => JSON.parse(body).exact_match === true)).toBe(true)
    expect(check.status).toBe('not_found')
    expect(check.signals[0]?.detail).toContain('hostname')
    expect(check.reason).toContain('6 bulan')
  })

  it('ThreatFox tidak menyebut tidak ada IOC bila salah satu kueri gagal', async () => {
    const fetchMock = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      const term = String(JSON.parse(String(init?.body ?? '{}')).search_term)
      if (term === 'contoh.com') return jsonResponse({ query_status: 'ok', data: [] }, 500)
      return jsonResponse({ query_status: 'no_result' })
    })

    const check = await threatFoxAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ threatFoxApiKey: 'tf-key' }),
    )

    expect(check.status).toBe('error')
    expect(check.reason).toContain('tidak dapat dipastikan')
  })

  it('ThreatFox memisahkan status yang tidak dikenal dari tidak ada data', async () => {
    const check = await threatFoxAdapter.check(
      context(
        mockFetch(() => jsonResponse({ query_status: 'pending' })) as unknown as typeof fetch,
      ),
      makeConfig({ threatFoxApiKey: 'tf-key' }),
    )

    expect(check.status).toBe('error')
    expect(check.reason).toContain('pending')
  })

  it('ThreatFox memetakan HTTP 429 ke kuota provider', async () => {
    const check = await threatFoxAdapter.check(
      context(
        mockFetch(() => jsonResponse({ errors: [] }, 429)) as unknown as typeof fetch,
      ),
      makeConfig({ threatFoxApiKey: 'tf-key' }),
    )

    expect(check.status).toBe('rate_limited')
    expect(check.summary).toBe('Kuota provider tercapai.')
  })

  it('ThreatFox menolak Auth-Key yang tidak valid', async () => {
    const check = await threatFoxAdapter.check(
      context(
        mockFetch(() =>
          jsonResponse({ query_status: 'illegal_auth_key' }),
        ) as unknown as typeof fetch,
      ),
      makeConfig({ threatFoxApiKey: 'invalid' }),
    )

    expect(check.status).toBe('auth_failed')
    expect(check.reason).toContain('Kredensial')
  })

  it('ThreatFox tidak menaikkan IOC tingkat host menjadi malicious', async () => {
    // Host bersama bisa menampung banyak resource; hanya satu yang terdaftar sebagai IOC.
    const check = await threatFoxAdapter.check(
      context(
        vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
          const term = String(JSON.parse(String(init?.body ?? '{}')).search_term)
          if (term !== 'https://contoh.com/path') return jsonResponse({ query_status: 'no_result' })
          return jsonResponse({
            query_status: 'ok',
            data: [{ ioc: 'https://contoh.com/unduh-malware.exe', ioc_type: 'url', malware: 'AsyncRAT' }],
          })
        }) as unknown as typeof fetch,
      ),
      makeConfig({ threatFoxApiKey: 'tf-key' }),
    )

    expect(check.verdict).toBe('suspicious')
    expect(check.score).toBe(55)
    expect(check.reason).toContain('tingkat host')
    expect(check.summary).toContain('pada host yang sama')
    expect(check.signals.some((signal) => signal.label === 'Tingkat kecocokan')).toBe(true)
  })

  it('ThreatFox memperlakukan IOC yang tidak sesuai kata yang dicari sebagai kegagalan teknis', async () => {
    const check = await threatFoxAdapter.check(
      context(
        vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
          const term = String(JSON.parse(String(init?.body ?? '{}')).search_term)
          if (term !== 'https://contoh.com/path') return jsonResponse({ query_status: 'no_result' })
          return jsonResponse({
            query_status: 'ok',
            data: [{ ioc: 'https://lain.example/other', ioc_type: 'url' }],
          })
        }) as unknown as typeof fetch,
      ),
      makeConfig({ threatFoxApiKey: 'tf-key' }),
    )

    expect(check.status).toBe('error')
    expect(check.verdict).toBe('inconclusive')
    expect(check.reason).toContain('tidak dapat dipastikan')
  })

  it('ThreatFox membatasi teks dan jumlah baris yang diambil dari respons provider', async () => {
    const longMalware = 'A'.repeat(500)
    const check = await threatFoxAdapter.check(
      context(
        vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
          const term = String(JSON.parse(String(init?.body ?? '{}')).search_term)
          if (term !== 'https://contoh.com/path') return jsonResponse({ query_status: 'no_result' })
          return jsonResponse({
            query_status: 'ok',
            data: Array.from({ length: 25 }, () => ({
              ioc: term,
              ioc_type: 'url',
              malware: longMalware,
              malware_printable: longMalware,
            })),
          })
        }) as unknown as typeof fetch,
      ),
      makeConfig({ threatFoxApiKey: 'tf-key' }),
    )

    expect(check.verdict).toBe('malicious')
    // 25 baris diterima, hanya 20 yang dipakai untuk membangun laporan.
    expect(check.summary).toContain('20 IOC')
    const family = check.signals.find((signal) => signal.label === 'Keluarga malware')
    expect(family?.detail).toBeDefined()
    expect((family?.detail ?? '').length).toBeLessThanOrEqual(121)
  })

  it('Radar mengirim scan baru lalu membaca vonis hasil pemindaian', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input)
      calls.push({ url, init })
      if (url.includes('/urlscanner/v2/search')) {
        return jsonResponse({ results: [] })
      }
      if (url.endsWith('/urlscanner/v2/scan')) {
        return jsonResponse({ success: true, result: { uuid: 'aaaa1111-2222-4333-8444-555566667777' } })
      }
      return jsonResponse({
        task: { status: 'finished', reportURL: 'https://radar.cloudflare.com/scan/aaaa1111' },
        verdicts: {
          overall: {
            malicious: true,
            hasVerdicts: true,
            categories: ['malware'],
            tags: ['c2'],
          },
        },
      })
    })

    const check = await radarAdapter.check(
      { ...context(fetchMock as unknown as typeof fetch), sleep: async () => undefined },
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    expect(calls[0]?.url).toBe(
      'https://api.cloudflare.com/client/v4/accounts/cf-account/urlscanner/v2/search?q=task.url%3A%22https%3A%2F%2Fcontoh.com%2Fpath%22&size=3',
    )
    expect(calls[1]?.url).toBe(
      'https://api.cloudflare.com/client/v4/accounts/cf-account/urlscanner/v2/scan',
    )
    expect(calls[1]?.init?.method).toBe('POST')
    expect(calls[1]?.init?.headers).toMatchObject({ Authorization: 'Bearer cf-token' })
    expect(JSON.parse(String(calls[1]?.init?.body))).toEqual({
      url: 'https://contoh.com/path',
      visibility: 'unlisted',
    })
    expect(calls[2]?.url).toBe(
      'https://api.cloudflare.com/client/v4/accounts/cf-account/urlscanner/v2/result/aaaa1111-2222-4333-8444-555566667777',
    )
    expect(check.verdict).toBe('malicious')
    expect(check.summary).toContain('berbahaya')
  })

  it('Radar memakai uuid dari konflik 409 tanpa mengirim scan kedua', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      if (String(input).endsWith('/urlscanner/v2/scan')) {
        return jsonResponse(
          {
            success: false,
            errors: [{ code: 8000036, message: 'this URL has been recently scanned' }],
            result: {
              tasks: [{ uuid: 'bbbb2222-3333-4444-8555-666677778888', status: 'Queued' }],
            },
          },
          409,
        )
      }
      return jsonResponse({
        task: { status: 'finished' },
        verdicts: { overall: { malicious: false, hasVerdicts: true } },
      })
    })

    const check = await radarAdapter.check(
      { ...context(fetchMock as unknown as typeof fetch), sleep: async () => undefined },
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    expect(check.verdict).toBe('clean')
    const polled = callsOf(fetchMock).find((url) => url.includes('/result/'))
    expect(polled).toContain('bbbb2222-3333-4444-8555-666677778888')
  })

  it('Radar tanpa token atau account tidak memanggil jaringan', async () => {
    const fetchMock = mockFetch(() => jsonResponse({}))
    const check = await radarAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ cloudflareApiToken: 'cf-token' }),
    )

    expect(check.status).toBe('not_configured')
    expect(check.reason).toContain('CLOUDFLARE_ACCOUNT_ID')
    expect(check.reason).not.toContain('CLOUDFLARE_API_TOKEN')
    expect(check.reason).not.toContain('cf-token')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('Radar memperlakukan pemindaian tanpa vonis sebagai inconclusive', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      if (String(input).endsWith('/urlscanner/v2/scan')) {
        return jsonResponse({ success: true, result: { uuid: 'cccc3333-4444-4555-8666-777788889999' } })
      }
      return jsonResponse({
        task: { status: 'finished' },
        verdicts: { overall: { malicious: false, hasVerdicts: false } },
      })
    })

    const check = await radarAdapter.check(
      { ...context(fetchMock as unknown as typeof fetch), sleep: async () => undefined },
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    expect(check.verdict).toBe('inconclusive')
    expect(check.reason).toContain('tidak menjamin')
  })

  it('Radar memetakan HTTP 429 ke kuota, bukan kegagalan umum', async () => {
    const delays: number[] = []
    let resultCalls = 0
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      if (url.endsWith('/urlscanner/v2/scan')) {
        return jsonResponse({ success: true, result: { uuid: 'dddd4444-5555-4666-8777-888899990000' } })
      }
      if (url.includes('/urlscanner/v2/search')) return jsonResponse({ results: [] })
      resultCalls += 1
      if (resultCalls === 1) {
        return new Response(JSON.stringify({ success: false, errors: [] }), {
          status: 429,
          headers: { 'Retry-After': '5' },
        })
      }
      return jsonResponse({
        task: { status: 'finished' },
        verdicts: { overall: { malicious: false, hasVerdicts: true } },
      })
    })

    const timed = tickingContext(fetchMock as unknown as typeof fetch, (ms) => delays.push(ms))
    const check = await radarAdapter.check(
      timed.context,
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    expect(check.status).toBe('success')
    // Retry-After 5 dtk lebih pendek dari jeda minimum adapter, jadi jeda 8 dtk yang dipakai.
    expect(delays).toEqual([2_000, 8_000])
  })

  it('Radar melaporkan kuota ketika 429 terulang dan berhenti mencoba', async () => {
    const delays: number[] = []
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      if (String(input).endsWith('/urlscanner/v2/scan')) {
        return jsonResponse({ success: true, result: { uuid: 'eeee5555-6666-4777-8888-999900001111' } })
      }
      if (String(input).includes('/urlscanner/v2/search')) return jsonResponse({ results: [] })
      return jsonResponse({ success: false, errors: [{ message: 'rate limited' }] }, 429)
    })

    const timed = tickingContext(fetchMock as unknown as typeof fetch, (ms) => delays.push(ms))
    const check = await radarAdapter.check(
      timed.context,
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    expect(check.status).toBe('rate_limited')
    expect(check.summary).toBe('Kuota provider tercapai.')
    expect(check.reason).toContain('Cloudflare tercapai')
    expect(check.reason).toContain('HTTP 429')
    expect(delays).toEqual([2_000, 8_000])
    expect(fetchMock).toHaveBeenCalledTimes(4)
  })

  it('Radar melaporkan kuota tanpa polling ketika scan awal dibatasi', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ success: false, errors: [] }, 429))

    const check = await radarAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    expect(check.status).toBe('rate_limited')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('Radar tetap memisahkan galat server, penolakan permintaan, dan kredensial', async () => {
    // VGL-30K-R1 §3/§4: pemisahan tiga kelas kegagalan tetap dijaga, hanya kelas tengahnya yang
    // kini punya status sendiri. HTTP 400 adalah penolakan bentuk permintaan (invalid_request),
    // bukan galat umum, dan body respons tidak pernah dibaca sehingga isinya tidak mungkin ikut
    // terbaca ke antarmuka.
    const radarFetch = (status: number, body: unknown = {}) =>
      vi.fn(async (input: string | URL | Request) => {
        if (String(input).endsWith('/urlscanner/v2/scan')) {
          return jsonResponse({ success: true, result: { uuid: 'ffff6666-7777-4888-8999-000011112222' } })
        }
        return jsonResponse(body, status)
      })

    const serverError = await radarAdapter.check(
      context(radarFetch(500) as unknown as typeof fetch),
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )
    const clientError = await radarAdapter.check(
      context(radarFetch(400, { success: false, errors: [{ message: 'bad request' }] }) as unknown as typeof fetch),
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    expect(serverError.status).toBe('unavailable')
    expect(clientError.status).toBe('invalid_request')
    expect(clientError.summary).toBe('Permintaan pemeriksaan ditolak provider.')
    expect(clientError.reason).toContain('400')
    expect(clientError.reason).not.toContain('bad request')
    expect(clientError.reason).not.toContain('cf-token')
  })

  const NOW = 1_700_000_000_000
  const REUSE_UUID = 'ab12cd34-1111-4aaa-8bbb-222233334444'

  function radarFinishedBody(malicious: boolean) {
    return jsonResponse({
      task: { status: 'finished', success: true, reportURL: 'https://radar.cloudflare.com/scan/ab12cd34' },
      verdicts: { overall: { malicious, hasVerdicts: true, categories: malicious ? ['malware'] : [], tags: [] } },
    })
  }

  // Cloudflare mengembalikan laporan selesai pada root.results[]; umur laporan dihitung
  // dari task.time relatif terhadap jam konteks adapter.
  function radarSearchBody(ageMs: number, url = 'https://contoh.com/path', uuid = REUSE_UUID) {
    return jsonResponse({
      results: [
        {
          task: {
            uuid,
            url,
            status: 'Finished',
            success: true,
            time: new Date(NOW - ageMs).toISOString(),
          },
        },
      ],
    })
  }

  function radarFetch(
    onCall: (kind: 'search' | 'scan' | 'result', url: string) => void,
    handlers: Partial<Record<'search' | 'scan' | 'result', () => Response>> = {},
  ) {
    return vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input)
      if (url.includes('/urlscanner/v2/search')) {
        onCall('search', url)
        return handlers.search?.() ?? jsonResponse({ results: [] })
      }
      if (url.endsWith('/urlscanner/v2/scan')) {
        onCall('scan', url)
        return (
          handlers.scan?.() ??
          jsonResponse({ success: true, result: { uuid: 'cccc3333-4444-4555-8666-777788889999' } })
        )
      }
      onCall('result', url)
      return handlers.result?.() ?? radarFinishedBody(false)
    })
  }

  // sleep dummy: adapter masih boleh menjeda, jumlah permintaan yang membuktikan bahwa
  // polling berhenti begitu vonis tersedia.
  const idleSleep = { sleep: async () => undefined }

  it('membersihkan URL dan token dari pesan penolakan Cloudflare', async () => {
    const fetchMock = mockFetch(() =>
      jsonResponse(
        {
          success: false,
          errors: [
            {
              message:
                'Gagal memeriksa https://target.example/path?token=abcdefghijklmnopqrstuvwxyz012345 karena kebijakan akun',
            },
          ],
        },
        400,
      ),
    )

    const check = await radarAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    // VGL-30K-R1: HTTP 400 kini diklasifikasikan invalid_request (bukan "error" umum) dan reason
    // berasal dari teks tetap, jadi pesan mentah provider tidak pernah dibaca ke antarmuka.
    expect(check.status).toBe('invalid_request')
    // Body provider tidak pernah ditempel apa adanya: URL dibuang, token panjang disamarkan.
    expect(check.reason).not.toContain('https://')
    expect(check.reason).not.toContain('target.example')
    expect(check.reason).not.toContain('abcdefghijklmnopqrstuvwxyz012345')
    expect(check.reason).not.toContain('kebijakan akun')
    expect(check.reason).toContain('Permintaan pemeriksaan ditolak provider.')
    expect(check.summary).toBe('Permintaan pemeriksaan ditolak provider.')
    // Sufiks HTTP tidak boleh dobel: reason dari adapter dan tempelan failureCheck.
    expect((check.reason?.match(/\(HTTP \d+\)/g) ?? []).length).toBeLessThanOrEqual(1)
  })

  it('Radar memakai laporan yang sudah ada tanpa mengirim pemindaian baru', async () => {
    const calls: string[] = []
    const fetchMock = radarFetch((kind) => calls.push(kind), {
      search: () => radarSearchBody(3_600_000),
      result: () => radarFinishedBody(true),
    })

    const check = await radarAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    expect(calls).toEqual(['search', 'result'])
    expect(check.status).toBe('success')
    expect(check.verdict).toBe('malicious')
    expect(check.evidence?.source).toBe('existing_report')
    // Waktu observasi laporan asli dipertahankan, bukan diganti waktu pemeriksaan ini.
    expect(check.evidence?.observedAt).toBe(new Date(NOW - 3_600_000).toISOString())
    expect(check.evidence?.ageMs).toBe(3_600_000)
    // Bukti ancamannya tetap utuh; yang hilang hanya kalimat tentang cara hasil diperoleh.
    expect(check.summary).toContain('berbahaya')
    expect(notCacheNarrative(check)).toBe(true)
  })

  it('Radar tidak memakai laporan URL lain walau muncul pada pencarian', async () => {
    const calls: string[] = []
    const fetchMock = radarFetch((kind) => calls.push(kind), {
      // task.url dibandingkan setelah normalisasi; laporan untuk target lain tidak sah.
      search: () => radarSearchBody(60_000, 'https://lain.com/path'),
    })

    const check = await radarAdapter.check(
      { ...context(fetchMock as unknown as typeof fetch), ...idleSleep },
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    expect(calls).toEqual(['search', 'scan', 'result'])
    expect(check.evidence?.source).toBe('new_scan')
  })

  it('Radar tidak memakai laporan yang lebih tua dari kebijakan kesegaran', async () => {
    const calls: string[] = []
    const fetchMock = radarFetch((kind) => calls.push(kind), {
      search: () => radarSearchBody(48 * 60 * 60_000),
    })

    const check = await radarAdapter.check(
      { ...context(fetchMock as unknown as typeof fetch), ...idleSleep },
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    expect(calls).toEqual(['search', 'scan', 'result'])
    expect(check.evidence?.source).toBe('new_scan')
  })

  it('Radar mengizinkan kebijakan kesegaran laporan diganti lewat konfigurasi', async () => {
    const calls: string[] = []
    const fetchMock = radarFetch((kind) => calls.push(kind), {
      search: () => radarSearchBody(48 * 60 * 60_000),
      result: () => radarFinishedBody(false),
    })

    const check = await radarAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({
        cloudflareApiToken: 'cf-token',
        cloudflareAccountId: 'cf-account',
        radarMaxReportAgeHours: 72,
      }),
    )

    expect(calls).toEqual(['search', 'result'])
    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence?.ageMs).toBe(48 * 60 * 60_000)
    expect(notCacheNarrative(check)).toBe(true)
  })

  it('Radar tidak mengirim pemindaian baru ketika pencarian dibatasi kuota', async () => {
    const calls: string[] = []
    const fetchMock = radarFetch((kind) => calls.push(kind), {
      search: () => jsonResponse({ success: false, errors: [] }, 429),
    })

    const check = await radarAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    expect(calls).toEqual(['search'])
    expect(check.status).toBe('rate_limited')
    expect(check.verdict).toBe('inconclusive')
  })

  it('Radar memakai laporan lama hanya ketika submit dibatasi kuota', async () => {
    const calls: string[] = []
    const fetchMock = radarFetch((kind) => calls.push(kind), {
      search: () => radarSearchBody(48 * 60 * 60_000),
      scan: () => jsonResponse({ success: false, errors: [] }, 429),
      result: () => radarFinishedBody(true),
    })

    const check = await radarAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    expect(calls).toEqual(['search', 'scan', 'result'])
    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence?.ageMs).toBe(48 * 60 * 60_000)
    expect(notCacheNarrative(check)).toBe(true)
  })

  it('Radar melaporkan pemindaian gagal tanpa polling lanjutan', async () => {
    let resultCalls = 0
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      if (url.includes('/urlscanner/v2/search')) return jsonResponse({ results: [] })
      if (url.endsWith('/urlscanner/v2/scan')) {
        return jsonResponse({ success: true, result: { uuid: 'dddd4444-5555-4666-8777-888899990000' } })
      }
      resultCalls += 1
      // success:false berarti pemindaian selesai dengan kesalahan (misalnya DNS gagal).
      return jsonResponse({
        task: { status: 'finished', success: false },
        verdicts: { overall: { malicious: false, hasVerdicts: false } },
      })
    })

    const check = await radarAdapter.check(
      { ...context(fetchMock as unknown as typeof fetch), ...idleSleep },
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    expect(resultCalls).toBe(1)
    expect(check.status).toBe('error')
    expect(check.verdict).toBe('inconclusive')
    expect(check.reason).toContain('status gagal')
  })

  it('Radar mengenali status vonis tanpa bergantung pada huruf', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      if (url.includes('/urlscanner/v2/search')) return jsonResponse({ results: [] })
      if (url.endsWith('/urlscanner/v2/scan')) {
        return jsonResponse({ success: true, result: { uuid: 'eeee5555-6666-4777-8888-999900001111' } })
      }
      return jsonResponse({
        task: { status: 'Finished', success: true },
        verdicts: { overall: { malicious: false, hasVerdicts: true } },
      })
    })

    const check = await radarAdapter.check(
      { ...context(fetchMock as unknown as typeof fetch), ...idleSleep },
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    expect(check.verdict).toBe('clean')
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('Radar menghindari kueri pencarian yang rusak untuk URL dengan tanda kutip', async () => {
    const calls: string[] = []
    const fetchMock = radarFetch((kind, url) => calls.push(`${kind}:${url}`))

    const check = await radarAdapter.check(
      {
        ...context(fetchMock as unknown as typeof fetch),
        url: 'https://contoh.com/path?q=a"b',
        ...idleSleep,
      },
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )

    // Tanda kutip mematahkan sintaks q= Cloudflare, jadi pencarian dilewati bukan dikirim rusak.
    expect(calls.some((call) => call.startsWith('search:'))).toBe(false)
    expect(calls.some((call) => call.startsWith('scan:'))).toBe(true)
    expect(check.status).toBe('success')
  })

  // VGL-30K-R4: rute `/general` hanya menunjukkan OTX mengaitkan alamat dengan pulse. Vonis
  // menuntut target TERBUKA ADA di daftar indikator pulse itu (`/pulses/{id}/indicators`) dan
  // pulse itu membawa konteks ancaman. Selain itu hasilnya intelijen komunitas tanpa skor.
  function otxFetch(pulses: unknown[], indicators: Array<{ indicator: string; type: string }>) {
    return mockFetch((url) =>
      url.includes('/pulses/')
        ? jsonResponse({ results: indicators, next: null })
        : url.includes('/indicators/domain/')
          ? jsonResponse({ pulse_info: { count: 0, pulses: [] } })
          : jsonResponse({ pulse_info: { count: pulses.length, pulses } }),
    )
  }

  it('OTX memperlakukan penyebutan pulse ber-tag tanpa indikator terbukti sebagai intelijen komunitas', async () => {
    const fetchMock = mockFetch((url) => {
      if (url.includes('/pulses/')) {
        // Daftar indikator terbaca tetapi tidak memuat alamat yang diperiksa.
        return jsonResponse({ results: [{ indicator: 'https://lain.example/login', type: 'url' }], next: null })
      }
      return jsonResponse({
        pulse_info: {
          count: 2,
          pulses: [
            {
              id: 'p-1',
              name: 'Kampanye phishing',
              tags: ['phishing'],
              malware_families: [],
              indicator_count: 12,
            },
          ],
        },
      })
    })

    const check = await otxAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(String(fetchMock.mock.calls[1]?.[0])).toBe(
      'https://otx.alienvault.com/api/v1/pulses/p-1/indicators?limit=100',
    )
    expect(check.status).toBe('success')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.signals.every((signal) => signal.severity === 'info')).toBe(true)
    expect(check.summary).toContain('2 laporan komunitas')
    expect(check.signals.some((signal) => signal.detail.includes('2 pulse'))).toBe(true)
    expect(check.reason).toContain('bukan konfirmasi ancaman')
    expect(JSON.stringify(check)).not.toContain('otx-key')
  })

  it('OTX menaikkan suspicious 45 ketika URL persis terbukti menjadi indikator pulse ber-konteks phishing', async () => {
    const fetchMock = otxFetch(
      [{ id: 'p-1', name: 'Kampanye phishing', tags: ['phishing'], malware_families: [], indicator_count: 12 }],
      [{ indicator: 'https://contoh.com/path', type: 'url' }],
    )

    const check = await otxAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.verdict).toBe('suspicious')
    expect(check.score).toBe(45)
    expect(check.summary).toContain('bukan konfirmasi ancaman')
    expect(check.signals.some((signal) => signal.label === 'Indikator terverifikasi')).toBe(true)
  })

  it('OTX hanya menyebut malicious ketika URL persis terbukti sebagai indikator pulse berkeluarga malware', async () => {
    const fetchMock = mockFetch((url) => {
      if (url.includes('/pulses/')) {
        return jsonResponse({ results: [{ indicator: 'https://contoh.com/path', type: 'url' }], next: null })
      }
      return jsonResponse({
        pulse_info: {
          count: 3,
          pulses: [
            { id: 'p-2', name: 'Botnet report', tags: ['botnet'], malware_families: ['AsyncRAT'], indicator_count: 8 },
          ],
        },
      })
    })

    const check = await otxAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.verdict).toBe('malicious')
    expect(check.score).toBe(70)
    expect(check.summary).toContain('AsyncRAT')
  })

  it('OTX tidak menaikkan vonis ketika indikator pulse tidak memuat alamat yang diperiksa', async () => {
    // Keluarga malware pada pulse tidak cukup: tanpa kecocokan indikator, ini penyebutan komunitas.
    const fetchMock = mockFetch((url) => {
      if (url.includes('/pulses/')) {
        return jsonResponse({
          results: [
            { indicator: 'https://lain.example/login', type: 'url' },
            { indicator: 'other.example', type: 'domain' },
            { indicator: '4f1c6e9d0a7b', type: 'hash' },
          ],
          next: null,
        })
      }
      return jsonResponse({
        pulse_info: {
          count: 1,
          pulses: [{ id: 'p-3', name: 'Botnet report', tags: [], malware_families: ['AsyncRAT'], indicator_count: 4 }],
        },
      })
    })

    const check = await otxAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.reason).toContain('bukan konfirmasi ancaman')
  })

  it('OTX membatasi permintaan konfirmasi indikator pada tiga pulse', async () => {
    const candidates = Array.from({ length: 6 }, (_unused, index) => ({
      id: `p-${index}`,
      name: `Pulse ${index}`,
      tags: [],
      malware_families: ['AsyncRAT'],
      indicator_count: 5,
    }))
    const fetchMock = mockFetch((url) => {
      if (url.includes('/pulses/')) return jsonResponse({ results: [], next: null })
      return jsonResponse({ pulse_info: { count: candidates.length, pulses: candidates } })
    })

    const check = await otxAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    // Satu permintaan indikator URL + tiga konfirmasi; tiga pulse lainnya tidak diminta.
    expect(fetchMock).toHaveBeenCalledTimes(4)
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(
      check.signals.some((signal) => signal.detail.includes('batas permintaan konfirmasi tercapai')),
    ).toBe(true)
  })

  it('OTX tidak mengambil vonis dari pulse daftar indikator massal tanpa permintaan tambahan', async () => {
    const fetchMock = mockFetch((url) => {
      if (url.includes('/pulses/')) {
        return jsonResponse({ results: [{ indicator: 'https://contoh.com/path', type: 'url' }], next: null })
      }
      return jsonResponse({
        pulse_info: {
          count: 1,
          pulses: [
            {
              id: 'p-blocklist',
              name: 'Daftar blokir gabungan',
              tags: ['phishing'],
              malware_families: ['AsyncRAT'],
              indicator_count: 4800,
            },
          ],
        },
      })
    })

    const check = await otxAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    // Pulse massal tidak dikirimi permintaan: kehadirannya di dalam daftar besar bukan bukti
    // yang khusus untuk alamat ini.
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.signals.some((signal) => signal.detail.includes('lebih dari 50 indikator'))).toBe(true)
  })

  it('OTX melaporkan kegagalan konfirmasi indikator sebagai tanpa bukti, bukan sebagai aman', async () => {
    const fetchMock = mockFetch((url) => {
      if (url.includes('/pulses/')) return jsonResponse({ detail: 'server error' }, 500)
      return jsonResponse({
        pulse_info: {
          count: 1,
          pulses: [{ id: 'p-4', name: 'Botnet report', tags: [], malware_families: ['AsyncRAT'], indicator_count: 3 }],
        },
      })
    })

    const check = await otxAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.signals.some((signal) => signal.detail.includes('tidak dapat diperiksa'))).toBe(true)
  })

  it('OTX menelusuri indikator domain ketika URL persis tanpa pulse tanpa menaikkan vonis', async () => {
    const urls: string[] = []
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      urls.push(url)
      if (url.includes('/pulses/')) {
        return jsonResponse({ results: [{ indicator: 'contoh.com', type: 'domain' }], next: null })
      }
      if (url.includes('/indicators/domain/')) {
        return jsonResponse({
          pulse_info: {
            count: 4,
            pulses: [
              {
                id: 'p-5',
                name: 'Infra AsyncRAT',
                malware_families: ['AsyncRAT'],
                tags: ['botnet'],
                indicator_count: 9,
              },
            ],
          },
        })
      }
      return jsonResponse({ pulse_info: { count: 0, pulses: [] } })
    })

    const check = await otxAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(urls).toHaveLength(3)
    expect(urls[0]).toBe(
      'https://otx.alienvault.com/api/v1/indicators/url/https%3A%2F%2Fcontoh.com%2Fpath/general',
    )
    expect(urls[1]).toBe('https://otx.alienvault.com/api/v1/indicators/domain/contoh.com/general')
    expect(urls[2]).toBe('https://otx.alienvault.com/api/v1/pulses/p-5/indicators?limit=100')
    // Bukti domain tidak pernah dibaca sebagai malicious untuk URL yang diperiksa.
    expect(check.verdict).toBe('suspicious')
    expect(check.status).toBe('success')
    expect(check.score).toBe(55)
    expect(check.reason).toContain('bukan URL persis')
    expect(check.signals.some((signal) => signal.detail.includes('domain contoh.com'))).toBe(true)
  })

  it('OTX menurunkan penyebutan domain menjadi intelijen komunitas ketika indikator pulse tidak cocok', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      if (url.includes('/pulses/')) {
        return jsonResponse({ results: [{ indicator: 'lain.example', type: 'domain' }], next: null })
      }
      if (url.includes('/indicators/domain/')) {
        return jsonResponse({
          pulse_info: {
            count: 4,
            pulses: [
              {
                id: 'p-6',
                name: 'Infra AsyncRAT',
                malware_families: ['AsyncRAT'],
                tags: ['botnet'],
                indicator_count: 9,
              },
            ],
          },
        })
      }
      return jsonResponse({ pulse_info: { count: 0, pulses: [] } })
    })

    const check = await otxAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.signals.every((signal) => signal.severity === 'info')).toBe(true)
    expect(check.reason).toContain('bukan konfirmasi ancaman maupun bukti bersih')
  })

  it('OTX menolak kecocokan indikator domain pada public suffix dan lookalike', async () => {
    // Pulse domain menyebut `co.id` (bukan bca.co.id) dan lookalike `bca.co.id.verify-secure.top`.
    // Keduanya bukan cakupan host yang diperiksa, jadi tidak boleh menaikkan vonis.
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      if (url.includes('/pulses/')) {
        return jsonResponse({
          results: [
            { indicator: 'co.id', type: 'domain' },
            { indicator: 'bca.co.id.verify-secure.top', type: 'domain' },
          ],
          next: null,
        })
      }
      if (url.includes('/indicators/domain/')) {
        return jsonResponse({
          pulse_info: {
            count: 2,
            pulses: [
              {
                id: 'p-7',
                name: 'Infra AsyncRAT',
                malware_families: ['AsyncRAT'],
                tags: ['botnet'],
                indicator_count: 4,
              },
            ],
          },
        })
      }
      return jsonResponse({ pulse_info: { count: 0, pulses: [] } })
    })

    const check = await otxAdapter.check(
      { ...context(fetchMock as unknown as typeof fetch), url: 'https://www.bca.co.id/', hostname: 'www.bca.co.id' },
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
  })

  it('OTX menghentikan penelusuran pada indikator IP dan menyebut cakupan', async () => {
    const fetchMock = mockFetch(() => jsonResponse({ pulse_info: { count: 0, pulses: [] } }))
    const check = await otxAdapter.check(
      { ...context(fetchMock as unknown as typeof fetch), hostname: '104.16.1.2' },
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(check.status).toBe('not_found')
    expect(check.verdict).toBe('inconclusive')
    expect(check.reason).toContain('alamat IP')
  })

  it('OTX memperlakukan HTTP 404 rute indikator sebagai kegagalan teknis', async () => {
    const urlRoute = await otxAdapter.check(
      context(mockFetch(() => jsonResponse({ detail: 'endpoint not found' }, 404)) as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(urlRoute.status).toBe('error')
    expect(urlRoute.reason).toContain('Rute indikator URL')
    expect(urlRoute.verdict).toBe('inconclusive')

    // Domain: indikator URL kosong lalu rute domain menjawab 404.
    const domainRoute = await otxAdapter.check(
      context(
        mockFetch((url) =>
          url.includes('/indicators/domain/')
            ? jsonResponse({ detail: 'endpoint not found' }, 404)
            : jsonResponse({ pulse_info: { count: 0, pulses: [] } }),
        ) as unknown as typeof fetch,
      ),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(domainRoute.status).toBe('error')
    expect(domainRoute.reason).toContain('Rute indikator domain')
  })

  it('OTX memisahkan kegagalan indikator domain dari ketiadaan laporan', async () => {
    const emptyUrl = () => jsonResponse({ pulse_info: { count: 0, pulses: [] } })

    const invalidDomain = await otxAdapter.check(
      context(
        mockFetch((url) =>
          url.includes('/indicators/domain/') ? jsonResponse({ detail: 'Invalid domain' }, 400) : emptyUrl(),
        ) as unknown as typeof fetch,
      ),
      makeConfig({ otxApiKey: 'otx-key' }),
    )
    // 400 berarti domain tidak dikenal di OTX: memang tidak ada laporan, bukan galat teknis.
    expect(invalidDomain.status).toBe('not_found')
    expect(invalidDomain.reason).toContain('bukti situs aman')

    const limited = await otxAdapter.check(
      context(
        mockFetch((url) =>
          url.includes('/indicators/domain/') ? jsonResponse({ detail: 'Too many requests' }, 429) : emptyUrl(),
        ) as unknown as typeof fetch,
      ),
      makeConfig({ otxApiKey: 'otx-key' }),
    )
    expect(limited.status).toBe('rate_limited')
    expect(limited.reason).toContain('penelusuran domain contoh.com gagal')

    const blocked = await otxAdapter.check(
      context(
        mockFetch((url) =>
          url.includes('/indicators/domain/') ? jsonResponse({ detail: 'forbidden' }, 403) : emptyUrl(),
        ) as unknown as typeof fetch,
      ),
      makeConfig({ otxApiKey: 'otx-key' }),
    )
    expect(blocked.status).toBe('auth_failed')

    const offline = await otxAdapter.check(
      context(
        mockFetch((url) =>
          url.includes('/indicators/domain/') ? jsonResponse({ detail: 'server error' }, 500) : emptyUrl(),
        ) as unknown as typeof fetch,
      ),
      makeConfig({ otxApiKey: 'otx-key' }),
    )
    expect(offline.status).toBe('unavailable')
    // Kegagalan teknis tidak pernah diubah menjadi vonis aman.
    for (const check of [limited, blocked, offline]) {
      expect(check.verdict).toBe('inconclusive')
      expect(check.score).toBeNull()
    }
  })

  it('OTX tidak menyebut malicious ketika URL dan domain sama-sama kosong', async () => {
    const fetchMock = mockFetch(() => jsonResponse({ pulse_info: { count: 0, pulses: [] } }))

    const check = await otxAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(check.status).toBe('not_found')
    expect(check.summary).toBe('AlienVault OTX tidak memiliki laporan komunitas untuk URL ini.')
    expect(check.signals[0]?.label).toBe('Cakupan penelusuran')
    expect(check.reason).toContain('ketiadaan laporan komunitas bukan bukti situs aman')
  })
})

describe('agen eksternal: adapter Google Safe Browsing, registry, dan Hybrid Analysis', () => {
  const GSB_ENDPOINT = 'https://safebrowsing.googleapis.com/v5/urls:search'

  function gsbFetch(responder: (url: string) => Response) {
    return vi.fn(async (input: string | URL | Request) => responder(String(input)))
  }

  function withKey(overrides: Partial<ScannerConfig> = {}) {
    return makeConfig({ googleSafeBrowsingApiKey: 'gsb-key', ...overrides })
  }

  // Kontrak resmi Google Safe Browsing v5 `urls.search`
  // (developers.google.com/safe-browsing/v5/reference/rest/v5/urls/search serta
  //  developers.google.com/safe-browsing/v5/migrate dari v4, terverifikasi 2026-10-28):
  //   GET /v5/urls:search?key=API_KEY&urls=<URL>
  //   Tanpa request body; `urls` berulang hingga 50 URL, VERIGUARD mengirim 1 URL.
  //   Respons: { threats: [ { url, threatTypes: [ThreatType] } ], cacheDuration }
  //   No-match: HTTP 200 dengan `threats` array kosong (BUKAN `{}` maupun 404).
  it('memakai endpoint resmi v5 dan mengirim kunci lewat query parameter (bukan header)', async () => {
    const fetchMock = gsbFetch(() => jsonResponse({ threats: [] }))
    const check = await googleSafeBrowsingAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      withKey(),
    )

    const [url, init] = fetchMock.mock.calls[0] ?? []
    const urlStr = String(url)
    // Bentuk resmi v5: kunci pada query parameter, URL target di-encode pada `urls=`.
    // URL request memuat kunci, jadi describeError() wajib menyanitasi URL sebelum galat
    // muncul ke UI (dijaga pada uji transport di bawah).
    expect(urlStr.startsWith(`${GSB_ENDPOINT}?key=gsb-key&urls=`)).toBe(true)
    expect(urlStr).toContain('gsb-key')
    expect(urlStr).toContain(encodeURIComponent('https://contoh.com/path'))
    expect(init?.method).toBe('GET')
    // v5 `urls.search` adalah GET tanpa body dan tanpa `Content-Type: application/json`.
    expect(init?.body).toBeUndefined()
    expect((init?.headers ?? {})).not.toHaveProperty('Content-Type')

    // Teks UI (summary/signals/reason) HARAM memuat kunci.
    expect(JSON.stringify(check)).not.toContain('gsb-key')

    // threats:[] = laporan provider = ketiadaan entri (not_found), BUKAN clean.
    expect(check.status).toBe('not_found')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
  })

  it('tanpa kunci agen tidak memanggil jaringan dan menyebut nama env-nya', async () => {
    const fetchMock = gsbFetch(() => jsonResponse({ threats: [] }))
    const check = await googleSafeBrowsingAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig(),
    )
    expect(check.status).toBe('not_configured')
    expect(check.reason).toContain('GOOGLE_SAFE_BROWSING_API_KEY')
    expect(check.verdict).toBe('inconclusive')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('MALWARE -> malicious dengan skor 85 dan bukti new_scan', async () => {
    const check = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(() =>
          jsonResponse({
            threats: [
              {
                url: 'https://contoh.com/path',
                threatTypes: ['MALWARE'],
              },
            ],
            cacheDuration: '300.000s',
          }),
        ) as unknown as typeof fetch,
      ),
      withKey(),
    )
    expect(check.status).toBe('success')
    expect(check.verdict).toBe('malicious')
    expect(check.score).toBe(85)
    expect(check.summary).toContain('MALWARE')
    expect(check.evidence?.source).toBe('new_scan')
    expect(check.evidence?.ageMs).toBe(0)
    expect(JSON.stringify(check)).not.toContain('gsb-key')
  })

  it('SOCIAL_ENGINEERING -> malicious; UNWANTED_SOFTWARE -> suspicious; threatType tak dikenal -> suspicious (bukan clean)', async () => {
    const phishing = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(() =>
          jsonResponse({
            threats: [
              { url: 'https://contoh.com/path', threatTypes: ['SOCIAL_ENGINEERING'] },
            ],
          }),
        ) as unknown as typeof fetch,
      ),
      withKey(),
    )
    expect(phishing.verdict).toBe('malicious')
    expect(phishing.score).toBe(85)

    const unwanted = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(() =>
          jsonResponse({
            threats: [
              { url: 'https://contoh.com/path', threatTypes: ['UNWANTED_SOFTWARE'] },
            ],
          }),
        ) as unknown as typeof fetch,
      ),
      withKey(),
    )
    expect(unwanted.verdict).toBe('suspicious')
    expect(unwanted.score).toBe(55)

    const unknown = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(() =>
          jsonResponse({
            threats: [
              { url: 'https://contoh.com/path', threatTypes: ['THREAT_TYPE_BARU'] },
            ],
          }),
        ) as unknown as typeof fetch,
      ),
      withKey(),
    )
    // Type tak dikenal TETAP menjadi sinyal ancaman; tidak pernah dibaca sebagai bukti aman.
    expect(unknown.status).toBe('success')
    expect(unknown.verdict).toBe('suspicious')
    expect(unknown.score).toBe(55)
    expect(JSON.stringify(unknown)).not.toContain('gsb-key')
  })

  it('entri ancaman tanpa threatTypes (mis. enum baru atau THREAT_TYPE_UNSPECIFIED) -> suspicious', async () => {
    // Halaman v5 mewajibkan klien toleran terhadap nilai enum baru. Entri yang di-return
    // Google pada URL kita TETAP merupakan sinyal ancaman walaupun `threatTypes` kosong.
    const emptyTypes = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(() =>
          jsonResponse({
            threats: [{ url: 'https://contoh.com/path' }],
          }),
        ) as unknown as typeof fetch,
      ),
      withKey(),
    )
    expect(emptyTypes.status).toBe('success')
    expect(emptyTypes.verdict).toBe('suspicious')
    expect(emptyTypes.score).toBe(55)
  })

  it('respons `{threats:[]}` (no-match) TIDAK pernah dibaca sebagai bukti aman', async () => {
    const check = await googleSafeBrowsingAdapter.check(
      context(gsbFetch(() => jsonResponse({ threats: [] })) as unknown as typeof fetch),
      withKey(),
    )
    expect(check.status).toBe('not_found')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.reason).toContain('BUKAN konfirmasi')
    expect(check.reason).toContain('aman')
  })

  it('respons bentuk tak terduga (array/string/number/JSON cacat/threats non-array) -> error/inconclusive', async () => {
    const arrayResponse = await googleSafeBrowsingAdapter.check(
      context(gsbFetch(() => jsonResponse([])) as unknown as typeof fetch),
      withKey(),
    )
    expect(arrayResponse.status).toBe('error')
    expect(arrayResponse.verdict).toBe('inconclusive')

    const stringRoot = await googleSafeBrowsingAdapter.check(
      context(gsbFetch(() => jsonResponse('ok')) as unknown as typeof fetch),
      withKey(),
    )
    expect(stringRoot.status).toBe('error')

    const malformed = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(() => new Response('bukan json', { status: 200 })) as unknown as typeof fetch,
      ),
      withKey(),
    )
    expect(malformed.status).toBe('error')
    expect(malformed.verdict).toBe('inconclusive')

    // `threats` yang bukan array juga tidak boleh dibaca sebagai no-match.
    const badThreats = await googleSafeBrowsingAdapter.check(
      context(gsbFetch(() => jsonResponse({ threats: 'oops' })) as unknown as typeof fetch),
      withKey(),
    )
    expect(badThreats.status).toBe('error')
  })

  it('HTTP 200 dengan body kosong diperlakukan sebagai no-match, BUKAN parsing error', async () => {
    // Regresi Issue 1: beberapa klien Google mengirim HTTP 200 dengan body kosong untuk
    // no-match (proto3 elision). Dulu `fetchJson` mencoba `response.json()` dan gagal,
    // menampilkan "Respons agen tidak dapat dibaca. (HTTP 200)". Sekarang body dibaca
    // sebagai text; string kosong = no-match sah dengan status not_found/inconclusive.
    const check = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(
          () => new Response('', { status: 200, headers: { 'Content-Type': 'application/json' } }),
        ) as unknown as typeof fetch,
      ),
      withKey(),
    )
    expect(check.status).toBe('not_found')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.summary).toContain('tidak memiliki entri ancaman')
    expect(check.reason).toContain('BUKAN konfirmasi')
  })

  it('HTTP 200 dengan body whitespace atau hanya newline tetap no-match', async () => {
    const check = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(() => new Response('  \n  ', { status: 200 })) as unknown as typeof fetch,
      ),
      withKey(),
    )
    expect(check.status).toBe('not_found')
    expect(check.verdict).toBe('inconclusive')
  })

  it('HTTP 200 dengan HTML/non-JSON -> error terkendali tanpa membocorkan body atau kunci', async () => {
    // Regresi: kalau Google (atau proxy di tengah) membalas HTTP 200 dengan HTML login
    // atau teks bebas, VERIGUARD melaporkan `error` dengan pesan singkat yang sudah
    // disanitasi, BUKAN body mentah dan BUKAN vonis bersih.
    const body = `<html><head><title>Sign in — key=AIzaSecretLongApiKey0123456789abcdefghij</title></head><body>…</body></html>`
    const check = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(
          () => new Response(body, { status: 200, headers: { 'Content-Type': 'text/html' } }),
        ) as unknown as typeof fetch,
      ),
      makeConfig({ googleSafeBrowsingApiKey: 'AIzaSecretLongApiKey0123456789abcdefghij' }),
    )
    expect(check.status).toBe('error')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    const rendered = JSON.stringify(check)
    // Kunci API HARAM muncul di summary/signals/reason yang dikirim ke frontend.
    expect(rendered).not.toContain('AIzaSecretLongApiKey0123456789abcdefghij')
    // Body mentah HARAM ikut direfleksikan.
    expect(rendered).not.toContain('Sign in')
    expect(rendered).not.toContain('<html>')
  })

  it('HTTP 200 dengan JSON valid yang bentuknya tidak dikenali -> error terkendali', async () => {
    // Bentuk sah tapi skema v5 tidak cocok (mis. `{}` legacy v4 atau objek lain tanpa field
    // `threats` yang array) TIDAK boleh dibaca no-match kalau strukturnya jelas-jelas lain.
    // Catatan: `{}` tanpa field `threats` adalah no-match sah di v5 (`extractThreats`
    // mengembalikan []). Yang di sini diuji adalah objek dengan field lain yang membingungkan.
    const check = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(() => jsonResponse({ threats: 'unexpected string' })) as unknown as typeof fetch,
      ),
      withKey(),
    )
    expect(check.status).toBe('error')
    expect(check.verdict).toBe('inconclusive')

    const arrayBody = await googleSafeBrowsingAdapter.check(
      context(gsbFetch(() => jsonResponse([])) as unknown as typeof fetch),
      withKey(),
    )
    expect(arrayBody.status).toBe('error')
  })

  it('memisahkan kegagalan transport, penolakan autentikasi, kuota, dan gangguan layanan', async () => {
    const denied = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(() => jsonResponse({ error: { message: 'bad key' } }, 401)) as unknown as typeof fetch,
      ),
      withKey(),
    )
    expect(denied.status).toBe('auth_failed')
    expect(denied.verdict).toBe('inconclusive')

    const limited = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(() => jsonResponse({ error: { message: 'quota' } }, 429)) as unknown as typeof fetch,
      ),
      withKey(),
    )
    expect(limited.status).toBe('rate_limited')
    expect(limited.verdict).toBe('inconclusive')

    const offline = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(() => jsonResponse({ error: { message: 'boom' } }, 503)) as unknown as typeof fetch,
      ),
      withKey(),
    )
    expect(offline.status).toBe('unavailable')
    expect(offline.verdict).toBe('inconclusive')

    // Kegagalan TRANSPORT: undici membungkus sebagai `TypeError: fetch failed` dengan cause
    // ENOTFOUND. Karena request URL memuat `?key=...`, kunci HARAM muncul di UI — sanitizer
    // describeError() ([url]-redaction + long-token redaction) wajib menangkap keduanya.
    const cause = Object.assign(
      new Error('getaddrinfo ENOTFOUND safebrowsing.googleapis.com'),
      { code: 'ENOTFOUND' },
    )
    const netFail = await googleSafeBrowsingAdapter.check(
      context(
        vi.fn(async () => {
          throw new TypeError('fetch failed', { cause })
        }) as unknown as typeof fetch,
      ),
      makeConfig({ googleSafeBrowsingApiKey: 'AIzaSecretLongApiKey0123456789abcdefghij' }),
    )
    expect(netFail.status).toBe('unavailable')
    expect(netFail.verdict).toBe('inconclusive')
    expect(netFail.score).toBeNull()
    // URL request (yang mengandung kunci) tidak pernah bocor ke UI; kunci juga tidak.
    const rendered = JSON.stringify(netFail)
    expect(rendered).not.toContain('AIzaSecretLongApiKey0123456789abcdefghij')
    expect(rendered).not.toContain('safebrowsing.googleapis.com/v5/urls:search?key=')
    expect(rendered).not.toContain('https://')
  })

  // ---------- Helper protobuf ----------
  // Encoder varint protobuf standar (uint64 kecil; cukup untuk field number, enum, length).
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

  // Bangun bytes SearchUrlsResponse dari satu atau lebih ThreatUrl + cacheDuration.
  function buildProtobufSearchUrlsResponse(
    threats: Array<{ url: string; threatTypeNumbers: number[] }>,
    cacheSeconds = 300,
  ): Uint8Array {
    const parts: number[] = []
    for (const t of threats) {
      const urlBytes = Array.from(new TextEncoder().encode(t.url))
      const threatUrlInner: number[] = [
        0x0a,
        urlBytes.length,
        ...urlBytes,
      ]
      for (const tn of t.threatTypeNumbers) {
        threatUrlInner.push(0x10, ...encodeVarint(tn))
      }
      parts.push(0x0a, threatUrlInner.length, ...threatUrlInner)
    }
    const durBytes = [0x08, ...encodeVarint(cacheSeconds)]
    parts.push(0x12, durBytes.length, ...durBytes)
    return new Uint8Array(parts)
  }

  // Bytes no-match yang diamati langsung dari live probe Google 2026-10-28:
  // hanya cache_duration=300s; threats elided (proto3 default/kosong).
  const LIVE_NO_MATCH_BYTES = new Uint8Array([0x12, 0x03, 0x08, 0xac, 0x02])

  function protobufResponse(bytes: Uint8Array, status = 200): Response {
    return new Response(bytes, {
      status,
      headers: { 'Content-Type': 'application/x-protobuf' },
    })
  }

  // ---------- Test regresi protobuf + pesan HTTP ganda ----------

  // 1. Valid no-match protobuf (bytes yang diamati langsung dari live API).
  it('protobuf no-match (live bytes, hanya cache_duration) -> not_found/inconclusive', async () => {
    const check = await googleSafeBrowsingAdapter.check(
      context(gsbFetch(() => protobufResponse(LIVE_NO_MATCH_BYTES)) as unknown as typeof fetch),
      withKey(),
    )
    expect(check.status).toBe('not_found')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.summary).toContain('tidak memiliki entri ancaman')
    expect(check.reason).toContain('BUKAN konfirmasi')
    expect(JSON.stringify(check)).not.toContain('gsb-key')
  })

  // 2. Valid match protobuf (satu ancaman MALWARE).
  it('protobuf match MALWARE -> malicious/85', async () => {
    const bytes = buildProtobufSearchUrlsResponse([
      { url: 'https://contoh.com/path', threatTypeNumbers: [1] },
    ])
    const check = await googleSafeBrowsingAdapter.check(
      context(gsbFetch(() => protobufResponse(bytes)) as unknown as typeof fetch),
      withKey(),
    )
    expect(check.status).toBe('success')
    expect(check.verdict).toBe('malicious')
    expect(check.score).toBe(85)
    expect(check.summary).toContain('MALWARE')
  })

  // 3. Body protobuf kosong (0 byte) = no-match sah (proto3 elision semua field default).
  it('protobuf body kosong (0 byte) -> not_found/inconclusive, bukan parsing error', async () => {
    const check = await googleSafeBrowsingAdapter.check(
      context(gsbFetch(() => protobufResponse(new Uint8Array(0))) as unknown as typeof fetch),
      withKey(),
    )
    expect(check.status).toBe('not_found')
    expect(check.verdict).toBe('inconclusive')
  })

  // 4. Protobuf cacat (teruncated length-delimited field) -> error, bukan clean.
  it('protobuf cacat (teruncated) -> error/inconclusive, tidak pernah clean', async () => {
    // Field 1 (threats) dimulai tapi length-delimited payload tidak lengkap.
    const truncated = new Uint8Array([0x0a, 0xff, 0x01])
    const check = await googleSafeBrowsingAdapter.check(
      context(gsbFetch(() => protobufResponse(truncated)) as unknown as typeof fetch),
      withKey(),
    )
    expect(check.status).toBe('error')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
  })

  // 5. Protobuf dengan beberapa threatType (packed unpacked) dan type tak dikenal.
  it('protobuf multiple threatTypes termasuk type tak dikenal -> malicious, semua muncul di summary', async () => {
    // threatTypes = [1=MALWARE, 2=SOCIAL_ENGINEERING, 99=tak dikenal]
    const bytes = buildProtobufSearchUrlsResponse([
      { url: 'https://contoh.com/path', threatTypeNumbers: [1, 2, 99] },
    ])
    const check = await googleSafeBrowsingAdapter.check(
      context(gsbFetch(() => protobufResponse(bytes)) as unknown as typeof fetch),
      withKey(),
    )
    expect(check.status).toBe('success')
    expect(check.verdict).toBe('malicious')
    expect(check.summary).toContain('MALWARE')
    expect(check.summary).toContain('UNKNOWN_99')
  })

  // 6. Protobuf entri tanpa threatTypes (hanya url) -> suspicious (sinyal ancaman, bukan bersih).
  it('protobuf entri tanpa threatTypes -> suspicious, bukan clean', async () => {
    const urlBytes = Array.from(new TextEncoder().encode('https://contoh.com/path'))
    const threatUrl = new Uint8Array([0x0a, urlBytes.length, ...urlBytes])
    const resp = new Uint8Array([0x0a, threatUrl.length, ...threatUrl, 0x12, 0x03, 0x08, 0xac, 0x02])
    const check = await googleSafeBrowsingAdapter.check(
      context(gsbFetch(() => protobufResponse(resp)) as unknown as typeof fetch),
      withKey(),
    )
    expect(check.status).toBe('success')
    expect(check.verdict).toBe('suspicious')
    expect(check.score).toBe(55)
  })

  // 7. Respons 400 Google (Unsupported Output Format) dengan content-type JSON:
  // tetap dipetakan fetchJson ke `invalid_request`, bukan no-match maupun vonis.
  it('HTTP 400 dengan body JSON error -> invalid_request, bukan not_found', async () => {
    const check = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(
          () =>
            new Response(
              JSON.stringify({ error: { code: 400, message: 'Unsupported Output Format' } }),
              { status: 400, headers: { 'Content-Type': 'application/json' } },
            ),
        ) as unknown as typeof fetch,
      ),
      withKey(),
    )
    expect(check.status).toBe('invalid_request')
    expect(check.verdict).toBe('inconclusive')
  })

  // 8. Kunci API tidak pernah muncul di body protobuf yang di-parse atau error yang ditampilkan.
  it('kunci API tidak bocor ke UI bahkan saat protobuf cacat', async () => {
    const secretKey = 'AIzaSecretLongApiKey0123456789abcdefghij'
    // Field 1 (threats) dimulai dengan continuation varint, tetapi body terputus di tengah
    // varint panjang: decodeVarint akan melewati byte terakhir dan mengembalikan null.
    const badProto = new Uint8Array([0x0a, 0x80])
    const check = await googleSafeBrowsingAdapter.check(
      context(gsbFetch(() => protobufResponse(badProto)) as unknown as typeof fetch),
      makeConfig({ googleSafeBrowsingApiKey: secretKey }),
    )
    expect(check.status).toBe('error')
    expect(JSON.stringify(check)).not.toContain(secretKey)
  })

  // 9. Regresi pesan HTTP ganda: kegagalan pada HTTP 200 (mis. protobuf cacat) HANYA
  // menghasilkan satu `(HTTP 200)` pada reason — bukan `(HTTP 200) (HTTP 200)`.
  // Bug lama: failureNote() pre-append "(HTTP 200)" lalu failureCheck() append lagi via withHttpStatus().
  it('galat HTTP 200 hanya memuat satu (HTTP 200), bukan dua kali', async () => {
    // Pakai HTTP 500 yang memang memicu jalur failureCheck dengan status 500.
    const check = await googleSafeBrowsingAdapter.check(
      context(
        gsbFetch(
          () =>
            new Response('server error', {
              status: 500,
              headers: { 'Content-Type': 'text/plain' },
            }),
        ) as unknown as typeof fetch,
      ),
      withKey(),
    )
    expect(check.status).toBe('unavailable')
    expect(check.reason).toBe('Layanan provider sedang tidak tersedia. (HTTP 500)')
    const httpCount = (check.reason?.match(/\(HTTP \d+\)/g) ?? []).length
    expect(httpCount).toBe(1)
  })
})


describe('agen eksternal: adapter Hybrid Analysis (Agen 7)', () => {

  it('mendaftarkan agen ketujuh dan kedelapan setelah enam agen yang sudah ada', () => {
    expect(PROVIDER_ADAPTERS.map((adapter) => adapter.id)).toEqual([
      'urlscan',
      'virustotal',
      'openphish',
      'threatfox',
      'radar',
      'otx',
      'hybrid',
      'safebrowsing',
    ])
    expect(googleSafeBrowsingAdapter.timeoutMs).toBe(20_000)
    expect(googleSafeBrowsingAdapter.requiredEnv).toEqual(['GOOGLE_SAFE_BROWSING_API_KEY'])
  })

  // Nomor agen dihitung dari indeks registrasi, jadi registry backend dan daftar id
  // frontend harus tetap satu urutan. Sumber frontend dibaca sebagai teks supaya urutan
  // tampilan diuji terhadap registry tanpa menarik kode React ke runtime node.
  it('urutan registry identik dengan urutan id yang dikenali frontend', () => {
    const registry = PROVIDER_ADAPTERS.map((adapter) => adapter.id)

    expect(readFrontendIdList('types.ts', 'EXTERNAL_PROVIDER_IDS')).toEqual(registry)
    expect(readFrontendIdList('report.ts', 'EXTERNAL_PROVIDERS')).toEqual(registry)

    // Tabel nama di agentLabels dipakai untuk mencocokkan teks provider, jadi urutannya
    // sengaja tidak sama; yang wajib sama adalah himpunan id-nya, dan nomor agen di file
    // itu diturunkan dari EXTERNAL_PROVIDER_IDS (bukan dari tabel nama).
    const nameTable = readFrontendIdList('agentLabels.ts', 'PROVIDER_NAMES_BY_AGENT')
    expect([...nameTable].sort()).toEqual([...registry].sort())
    const labelsSource = readFileSync(
      fileURLToPath(new URL('agentLabels.ts', WEB_SCANNERS_DIR)),
      'utf8',
    )
    expect(labelsSource).toContain('EXTERNAL_PROVIDER_IDS.map((id, index) => [id, index + 1])')
  })

  it('Hybrid Analysis terdaftar sebagai Agen 7 read-only dan memakai kontrak yang terverifikasi', async () => {
    // Kontrak diverifikasi dari konektor resmi penerbit (hybrid-analysis/VxAPI, api_caller.py)
    // dan pemeriksaan langsung 2026-10-28: basis CANONICAL https://hybrid-analysis.com/api/v2
    // (host `www.` menjawab HTTP 301 normalisasi yang memicu galat "redirect not allowed"),
    // POST /search/terms dengan body form-urlencoded dan kunci pada header `api-key`. Agen ini
    // HANYA menelusuri laporan yang sudah ada; tidak pernah mengirim URL untuk analisis sandbox.
    const HYBRID_ENDPOINT = 'https://hybrid-analysis.com/api/v2/search/terms'

    // Mock yang menyalakan respons sesuai field yang dicari (url= vs domain=), keduanya ke
    // endpoint yang sama. Payload array otomatis dibungkus ke bentuk terdokumentasi
    // `{ count, result: [...] }`; payload non-array diteruskan apa adanya (untuk menguji
    // bentuk tak terduga).
    function hybridFetch(responses: { url?: unknown; domain?: unknown; status?: number }) {
      return vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
        const body = String(init?.body ?? '')
        const raw = body.startsWith('domain=') ? (responses.domain ?? []) : (responses.url ?? [])
        const payload = Array.isArray(raw) ? { count: raw.length, result: raw } : raw
        return jsonResponse(payload, responses.status ?? 200)
      })
    }

    expect(PROVIDER_ADAPTERS[6]?.id).toBe('hybrid')
    expect(hybridAnalysisAdapter.id).toBe('hybrid')
    expect(hybridAnalysisAdapter.label).toBe('Hybrid Analysis')
    expect(hybridAnalysisAdapter.timeoutMs).toBe(20_000)
    expect(hybridAnalysisAdapter.requiredEnv).toEqual(['HYBRID_ANALYSIS_API_KEY'])

    // Tanpa kunci: tidak menyentuh jaringan dan menyebut nama env-nya.
    const unconfigured = hybridFetch({})
    const missingKey = await hybridAnalysisAdapter.check(
      context(unconfigured as unknown as typeof fetch),
      makeConfig(),
    )
    expect(missingKey.status).toBe('not_configured')
    expect(missingKey.verdict).toBe('inconclusive')
    expect(missingKey.reason).toContain('HYBRID_ANALYSIS_API_KEY')
    expect(unconfigured).not.toHaveBeenCalled()

    // Cocok persis pada URL dengan verdict "malicious" -> malicious, ditandai laporan yang
    // sudah ada.
    const maliciousDocs = [
      {
        verdict: 'malicious',
        threat_score: 100,
        av_detect: 42,
        vx_family: ['Zeus'],
        tags: ['banking-trojan'],
        url: [{ url: 'https://contoh.com/path' }],
        analysis_start_time: new Date(1_700_000_000_000 - 3_600_000).toISOString(),
      },
    ]
    const fetchMock = hybridFetch({ url: maliciousDocs })
    const matched = await hybridAnalysisAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )
    const [urlArg, init] = fetchMock.mock.calls[0] ?? []
    expect(String(urlArg)).toBe(HYBRID_ENDPOINT)
    expect(init?.method).toBe('POST')
    expect(init?.headers).toMatchObject({
      'api-key': 'ha-key',
      'Content-Type': 'application/x-www-form-urlencoded',
    })
    expect(String(init?.body)).toBe('url=https%3A%2F%2Fcontoh.com%2Fpath')
    // Hanya satu panggilan (URL): tidak ada pengiriman sandbox, tidak ada pencarian domain sia-sia.
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(matched.status).toBe('success')
    expect(matched.verdict).toBe('malicious')
    expect(matched.score).toBe(85)
    expect(matched.evidence?.source).toBe('existing_report')
    expect(JSON.stringify(matched)).not.toContain('ha-key')

    // Ketiadaan laporan -> not_found, BUKAN bukti aman.
    const empty = await hybridAnalysisAdapter.check(
      context(hybridFetch({ url: [], domain: [] }) as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )
    expect(empty.status).toBe('not_found')
    expect(empty.verdict).toBe('inconclusive')
    expect(empty.score).toBeNull()
    expect(empty.reason).toContain('bukan bukti situs aman')

    // Kategori C: laporan tanpa identitas subjek tidak dapat dikaitkan dengan URL ini, jadi
    // vonisnya (di sini "no specific threat") tidak dibaca sebagai aman maupun ancaman. Status
    // `success` karena provider menjawab dan datanya terurai; yang kosong adalah BUKTINYA.
    const noVerdict = await hybridAnalysisAdapter.check(
      context(hybridFetch({ url: [{ verdict: 'no specific threat' }] }) as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )
    expect(noVerdict.status).toBe('success')
    expect(noVerdict.verdict).toBe('inconclusive')
    expect(noVerdict.score).toBeNull()
    expect(noVerdict.signals.some((signal) => signal.detail.includes('tanpa identitas'))).toBe(true)
    expect(noVerdict.signals.every((signal) => signal.severity === 'info')).toBe(true)
    expect(noVerdict.reason).toContain('bukan bukti situs aman')

    // Dokumen domain tanpa identitas subjek: Kategori C, bukan vonis tingkat domain (VGL-30K-R4).
    const domainOnly = await hybridAnalysisAdapter.check(
      context(
        hybridFetch({
          url: [],
          domain: [
            {
              verdict: 'malicious',
              analysis_start_time: new Date(1_700_000_000_000 - 86_400_000).toISOString(),
            },
          ],
        }) as unknown as typeof fetch,
      ),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )
    expect(domainOnly.status).toBe('success')
    expect(domainOnly.verdict).toBe('inconclusive')
    expect(domainOnly.score).toBeNull()
    expect(domainOnly.reason).toContain('subjek analisisnya')

    // Bukti pada subjek persis yang TERAMAT di laporan domain:vonis penuh tetap dipakai.
    const exactOnDomain = await hybridAnalysisAdapter.check(
      context(
        hybridFetch({
          url: [],
          domain: [
            {
              verdict: 'malicious',
              host: 'contoh.com',
              url: [{ url: 'https://contoh.com/path' }],
              analysis_start_time: new Date(1_700_000_000_000 - 86_400_000).toISOString(),
            },
          ],
        }) as unknown as typeof fetch,
      ),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )
    expect(exactOnDomain.verdict).toBe('malicious')
    expect(exactOnDomain.score).toBe(85)
    expect(exactOnDomain.evidence?.source).toBe('existing_report')

    // Laporan URL LAIN pada host yang sama: intelijen berkaitan, tanpa skor dan tanpa vonis.
    const otherUrlSameHost = await hybridAnalysisAdapter.check(
      context(
        hybridFetch({
          url: [],
          domain: [
            {
              verdict: 'malicious',
              host: 'contoh.com',
              url: [{ url: 'https://contoh.com/berbeda' }],
              analysis_start_time: new Date(1_700_000_000_000 - 86_400_000).toISOString(),
            },
          ],
        }) as unknown as typeof fetch,
      ),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )
    expect(otherUrlSameHost.verdict).toBe('inconclusive')
    expect(otherUrlSameHost.score).toBeNull()
    expect(
      otherUrlSameHost.signals.some((signal) => signal.detail.includes('bukan URL persis yang diperiksa')),
    ).toBe(true)

    // Kunci ditolak (401) -> auth_failed; kuota (429) -> rate_limited. Keduanya tanpa vonis.
    const rejected = await hybridAnalysisAdapter.check(
      context(
        vi.fn(async () => jsonResponse({ error: 'unauthorized' }, 401)) as unknown as typeof fetch,
      ),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )
    expect(rejected.status).toBe('auth_failed')
    expect(rejected.verdict).toBe('inconclusive')

    const throttled = await hybridAnalysisAdapter.check(
      context(vi.fn(async () => jsonResponse({}, 429)) as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )
    expect(throttled.status).toBe('rate_limited')
    expect(throttled.verdict).toBe('inconclusive')
  })

  it('Hybrid Analysis melaporkan kegagalan (bukan vonis aman) untuk JSON cacat, bentuk tak terduga, dan HTTP 403', async () => {
    // (a) JSON cacat: HTTP 200 tetapi body bukan JSON valid -> fetchJson gagal membaca ->
    //     status `error`, verdict `inconclusive`, TIDAK diubah menjadi clean.
    const malformed = await hybridAnalysisAdapter.check(
      context(
        vi.fn(
          async () =>
            new Response('bukan json {', {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            }),
        ) as unknown as typeof fetch,
      ),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )
    expect(malformed.status).toBe('error')
    expect(malformed.verdict).toBe('inconclusive')
    expect(malformed.score).toBeNull()
    expect(JSON.stringify(malformed)).not.toContain('ha-key')

    // (b) Bentuk tak terduga: objek tanpa daftar hasil yang dikenali -> diagnostik `error` yang
    //     menyebut status HTTP + tipe/kunci level-teratas SAJA (tanpa nilai/isi mentah), bukan clean.
    const unexpectedFetch = vi.fn(async () =>
      jsonResponse({ message: 'gateway tidak terduga', detail: 'rahasia-pendek' }, 200),
    )
    const unexpected = await hybridAnalysisAdapter.check(
      context(unexpectedFetch as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )
    expect(unexpected.status).toBe('error')
    expect(unexpected.verdict).toBe('inconclusive')
    expect(unexpected.score).toBeNull()
    // Diagnostik memuat HTTP 200 dan nama kunci level-teratas, tetapi BUKAN nilainya dan BUKAN kunci API.
    expect(unexpected.reason).toContain('HTTP 200')
    expect(unexpected.reason).toContain('message')
    expect(unexpected.reason).not.toContain('gateway tidak terduga')
    expect(unexpected.reason).not.toContain('rahasia-pendek')
    expect(JSON.stringify(unexpected)).not.toContain('ha-key')

    // (c) HTTP 403: kredensial/akses ditolak -> auth_failed, verdict `inconclusive`, bukan clean.
    const forbidden = await hybridAnalysisAdapter.check(
      context(vi.fn(async () => jsonResponse({ message: 'forbidden' }, 403)) as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )
    expect(forbidden.status).toBe('auth_failed')
    expect(forbidden.verdict).toBe('inconclusive')
    expect(forbidden.score).toBeNull()
    expect(JSON.stringify(forbidden)).not.toContain('ha-key')
  })

  it('Hybrid Analysis tidak mengikuti redirect dan tidak mengarang vonis saat API menjawab 3xx', async () => {
    // Akar masalah yang diperbaiki: host `www.` menjawab HTTP 301 normalisasi ke apex. Dengan
    // semantik `redirect: 'error'` galat ini surfaced sebagai kegagalan, BUKAN diikuti buta.
    // Agen diarahkan ke host canonical tanpa redirect; tes ini menjaga agar KEDUA jalur redirect
    // (respons 3xx dan lemparan shim Worker) tetap dilaporkan sebagai kegagalan read-only.

    // (a) Mock mengembalikan respons 301 + Location ke host lain: harus menjadi kegagalan,
    //     tanpa vonis, TANPA permintaan kedua ke tujuan redirect (kunci tidak diteruskan).
    const redirectMock = vi.fn(async () =>
      new Response('', { status: 301, headers: { Location: 'https://penyedia-asing.example/x' } }),
    )
    const redirected = await hybridAnalysisAdapter.check(
      context(redirectMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key-rahasia' }),
    )
    expect(redirected.status).toBe('error')
    expect(redirected.verdict).toBe('inconclusive')
    expect(redirected.score).toBeNull()
    // Hanya satu panggilan (ke host canonical); redirect TIDAK diikuti, jadi kredensial tidak
    // pernah dikirim ke tujuan asing.
    expect(redirectMock).toHaveBeenCalledTimes(1)
    expect(String(redirectMock.mock.calls[0]?.[0])).toBe(
      'https://hybrid-analysis.com/api/v2/search/terms',
    )
    // Nilai kunci tidak pernah muncul pada teks yang dikirim ke antarmuka.
    expect(JSON.stringify(redirected)).not.toContain('ha-key-rahasia')

    // (b) Shim Worker melempar TypeError('fetch failed: redirect not allowed') saat 3xx:
    //     tetap dilaporkan `unavailable`, bukan aman/malicious.
    const throwing = vi.fn(async () => {
      throw new TypeError('fetch failed: redirect not allowed')
    })
    const unavailable = await hybridAnalysisAdapter.check(
      context(throwing as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key-rahasia' }),
    )
    expect(unavailable.status).toBe('unavailable')
    expect(unavailable.verdict).toBe('inconclusive')
    expect(JSON.stringify(unavailable)).not.toContain('ha-key-rahasia')
  })
})

describe('penerusan sinyal abort pada fetchJson', () => {
  it('meneruskan sinyal abort eksternal ke fetch dan membatalkan permintaan', async () => {
    const controller = new AbortController()
    let fetchSignal: AbortSignal | null = null
    const fetchMock = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      fetchSignal = init?.signal ?? null
      return await new Promise<Response>((resolve, reject) => {
        init?.signal?.addEventListener(
          'abort',
          () => reject(new DOMException('The operation was aborted.', 'AbortError')),
          { once: true },
        )
        setTimeout(() => resolve(jsonResponse({})), 100)
      })
    })

    const pending = fetchJson(fetchMock as unknown as typeof fetch, 'https://contoh.com', {
      signal: controller.signal,
    })
    controller.abort()
    const result = await pending

    expect(result).toMatchObject({ ok: false, kind: 'skipped' })
    expect(fetchSignal?.aborted).toBe(true)
  })

  it('mengembalikan skipped saat sinyal pemanggil sudah dibatalkan sebelum fetch', async () => {
    const controller = new AbortController()
    controller.abort()
    const fetchMock = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      if (init?.signal?.aborted) {
        throw new DOMException('The operation was aborted.', 'AbortError')
      }
      return jsonResponse({})
    })

    const result = await fetchJson(fetchMock as unknown as typeof fetch, 'https://contoh.com', {
      signal: controller.signal,
    })

    expect(result).toMatchObject({
      ok: false,
      kind: 'skipped',
      reason: 'Permintaan ke provider dibatalkan saat proses scan berjalan.',
    })
    expect(fetchMock.mock.calls[0]?.[1]?.signal?.aborted).toBe(true)
  })

  it('tetap membatalkan fetch saat timeout internal tercapai', async () => {
    vi.useFakeTimers()
    try {
      const fetchMock = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
        return await new Promise<Response>((resolve, reject) => {
          init?.signal?.addEventListener(
            'abort',
            () => reject(new DOMException('The operation was aborted.', 'AbortError')),
            { once: true },
          )
        })
      })

      let settled: Awaited<ReturnType<typeof fetchJson>> | undefined
      const pending = fetchJson(
        fetchMock as unknown as typeof fetch,
        'https://contoh.com',
        {},
        1_000,
      ).then((resolved) => {
        settled = resolved
        return resolved
      })

      await vi.advanceTimersByTimeAsync(2_000)
      await pending

      expect(settled).toMatchObject({
        ok: false,
        kind: 'timeout',
        reason: 'Permintaan ke provider melebihi batas waktu.',
      })
    } finally {
      vi.useRealTimers()
    }
  })

  it('failureCheck memetakan kind skipped ke status skipped', () => {
    const check = failureCheck({
      ok: false,
      status: null,
      kind: 'skipped',
      reason: 'Permintaan ke provider dibatalkan saat proses scan berjalan.',
    })

    expect(check.status).toBe('skipped')
    expect(check.summary).toBe('Provider tidak dijalankan.')
    expect(check.reason).toBe('Permintaan ke provider dibatalkan saat proses scan berjalan.')
  })
})

describe('diagnostik penyebab galat fetch pada fetchJson (describeError)', () => {
  // Kegagalan koneksi dibungkus undici sebagai `TypeError: fetch failed` dengan penyebab asli
  // di `error.cause`. describeError kini menampilkan HANYA kode penyebab yang dikenali dan tetap
  // memetakan kegagalan jaringan ke `unavailable`/`inconclusive`, tanpa membocorkan URL/kunci/header.
  async function unavailableReason(error: unknown): Promise<string> {
    const fetchMock = vi.fn(async () => {
      throw error
    })
    const result = await fetchJson(fetchMock as unknown as typeof fetch, 'https://provider.example/api', {})
    expect(result.ok).toBe(false)
    if (result.ok) throw new Error('expected failure')
    expect(result.kind).toBe('unavailable')
    expect(result.status).toBeNull()
    return result.reason
  }

  it('mengekspor kode dari cause bersarang tanpa hostname/URL mentah dan tetap unavailable', async () => {
    const cause = Object.assign(
      new Error('getaddrinfo ENOTFOUND hybrid-analysis.com secret.host https://private.example/path'),
      { code: 'ENOTFOUND', hostname: 'hybrid-analysis.com' },
    )
    const reason = await unavailableReason(new TypeError('fetch failed', { cause }))

    expect(reason).toContain('TypeError: fetch failed')
    expect(reason).toContain('[ENOTFOUND]')
    // Penyebab asli TIDAK dibaca mentah: hostname, URL, dan token rahasia tidak pernah muncul.
    expect(reason).not.toContain('hybrid-analysis.com')
    expect(reason).not.toContain('private.example')
    expect(reason).not.toContain('secret.host')
    expect(reason).not.toContain('getaddrinfo')
    expect(reason).not.toContain('https://')
  })

  it('menelusuri cause hingga dua level untuk kode TLS yang dikenali', async () => {
    const inner = Object.assign(new Error('tls handshake altname mismatch'), {
      code: 'ERR_TLS_CERT_ALTNAME_INVALID',
    })
    const middle = new Error('socket error', { cause: inner })
    const reason = await unavailableReason(new TypeError('fetch failed', { cause: middle }))

    expect(reason).toContain('[ERR_TLS_CERT_ALTNAME_INVALID]')
    expect(reason).not.toContain('tls handshake')
    expect(reason).not.toContain('socket error')
  })

  it('mengabaikan cause yang tidak dikenali/bentuk aneh dan tanpa kurung kode', async () => {
    // Cause berupa string, angka, atau objek tanpa `code` aman tidak boleh memunculkan kode palsu.
    const stringCause = Object.assign(new Error('fetch failed'), { cause: 'rahasia-host.example.com' })
    const reasonString = await unavailableReason(stringCause)
    expect(reasonString).not.toContain('[')
    expect(reasonString).not.toContain('rahasia-host.example.com')

    const oddCause = Object.assign(new Error('fetch failed'), {
      cause: { message: 'boom', code: 'lowercase-not-a-code', url: 'https://x.example' },
    })
    const reasonOdd = await unavailableReason(oddCause)
    expect(reasonOdd).not.toContain('lowercase-not-a-code')
    expect(reasonOdd).not.toContain('x.example')

    // Tanpa cause sama sekali: hanya `Name: message`, tanpa kurung kode.
    const plain = new TypeError('boom failed')
    const reasonPlain = await unavailableReason(plain)
    expect(reasonPlain).toBe('Provider tidak dapat dihubungi. (TypeError: boom failed)')
  })

  it('meredaksi URL, token panjang (kunci/header), dan memuat kode pada error level-teratas', async () => {
    // Message level-teratas memuat URL + token rahasia 26 karakter: keduanya harus disanitasi.
    const leaking = new TypeError(
      'Failed to parse URL from https://private.example.com/secret abcdefghijklmnopqrstuvwxyz0123',
    )
    const reasonLeak = await unavailableReason(leaking)
    expect(reasonLeak).toContain('[url]')
    expect(reasonLeak).not.toContain('private.example.com')
    expect(reasonLeak).not.toContain('abcdefghijklmnopqrstuvwxyz0123')

    // Error dengan `code` di level-teratas (mis. ECONNRESET) tetap terbaca.
    const top = Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' })
    const reasonTop = await unavailableReason(top)
    expect(reasonTop).toContain('[ECONNRESET]')
  })
})

describe('pemetaan kuota dan Retry-After di lapisan HTTP', () => {
  function limitedFetch(headers: Record<string, string>, status = 429) {
    return mockFetch(
      () => new Response(JSON.stringify({ message: 'slow down' }), { status, headers }),
    )
  }

  it('menyertakan jeda yang diminta provider ketika Retry-After tersedia', async () => {
    const result = await fetchJson(
      limitedFetch({ 'Retry-After': '30' }) as unknown as typeof fetch,
      'https://example.test/limited',
    )

    expect(result).toMatchObject({
      ok: false,
      status: 429,
      kind: 'rate_limited',
      retryAfterMs: 30_000,
    })
    if (!result.ok) {
      expect(result.reason).toContain('30 detik')
      expect(failureCheck(result).reason).toContain('HTTP 429')
    }
  })

  it('memakai nilai Retry-After tanggal dan mengabaikan nilai yang tidak masuk akal', async () => {
    const future = new Date(Date.now() + 12_000).toUTCString()
    const dated = await fetchJson(
      limitedFetch({ 'Retry-After': future }) as unknown as typeof fetch,
      'https://example.test/dated',
    )
    const garbage = await fetchJson(
      limitedFetch({ 'Retry-After': 'sebentar-lagi' }) as unknown as typeof fetch,
      'https://example.test/garbage',
    )
    const huge = await fetchJson(
      limitedFetch({ 'Retry-After': '999999' }) as unknown as typeof fetch,
      'https://example.test/huge',
    )

    if (!dated.ok) expect(dated.retryAfterMs).toBeGreaterThanOrEqual(9_000)
    expect(garbage.ok ? null : garbage.retryAfterMs ?? null).toBeNull()
    if (!huge.ok) expect(huge.retryAfterMs).toBeLessThanOrEqual(10 * 60_000)
  })

  it('menggambarkan 429 tanpa Retry-After sebagai kuota tanpa jeda kosong', async () => {
    const result = await fetchJson(
      limitedFetch({}) as unknown as typeof fetch,
      'https://example.test/quiet',
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('rate_limited')
      expect(result.retryAfterMs).toBeNull()
      expect(result.reason).toBe('Kuota permintaan provider tercapai.')
    }
  })

  it('memakai header kuota X-Rate-Limit ketika Retry-After tidak dikirim', async () => {
    const result = await fetchJson(
      limitedFetch({
        'x-rate-limit-scope': 'user',
        'x-rate-limit-action': 'private',
        'x-rate-limit-window': 'day',
        'x-rate-limit-limit': '50',
        'x-rate-limit-remaining': '0',
        'x-rate-limit-reset': new Date(Date.now() + 3_600_000).toISOString(),
        'x-rate-limit-reset-after': '240',
      }) as unknown as typeof fetch,
      'https://example.test/quota',
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('rate_limited')
      expect(result.retryAfterMs).toBe(240_000)
      expect(result.rateLimit).toMatchObject({
        scope: 'user',
        action: 'private',
        window: 'day',
        limit: 50,
        remaining: 0,
      })
      expect(result.reason).toContain('sisa 0 dari 50')
      expect(result.reason).toContain('operasi private')
      expect(result.reason).toContain('lingkup user')
      expect(result.reason).toContain('jendela kuota berikutnya')
    }
  })

  it('menghitung ulang jeda dari header reset saat reset-after absen', async () => {
    const result = await fetchJson(
      limitedFetch({
        'x-rate-limit-window': 'minute',
        'x-rate-limit-reset': new Date(Date.now() + 45_000).toISOString(),
      }) as unknown as typeof fetch,
      'https://example.test/reset',
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.retryAfterMs).not.toBeNull()
      expect(result.retryAfterMs! + 5_000).toBeGreaterThanOrEqual(40_000)
      expect(result.rateLimit?.resetAfterMs).not.toBeNull()
    }
  })

  it('mengabaikan nilai header kuota yang tidak valid tanpa mengarang angka', async () => {
    const result = await fetchJson(
      limitedFetch({
        'x-rate-limit-remaining': 'banyak',
        'x-rate-limit-limit': '-3',
        'x-rate-limit-reset': 'besok-saja',
      }) as unknown as typeof fetch,
      'https://example.test/bogus',
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.retryAfterMs).toBeNull()
      expect(result.rateLimit).toMatchObject({ remaining: null, limit: null, resetAfterMs: null })
      expect(result.reason).toBe('Kuota permintaan provider tercapai.')
    }
  })

  it('memperlakukan kegagalan jaringan sebagai layanan tidak tersedia, bukan tidak ada data', async () => {
    const throwing = vi.fn(async () => {
      throw new Error('ECONNREFUSED')
    })
    const result = await fetchJson(
      throwing as unknown as typeof fetch,
      'https://example.test/network',
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('unavailable')
      expect(result.status).toBeNull()
      const check = failureCheck(result)
      expect(check.status).toBe('unavailable')
      expect(check.verdict).toBe('inconclusive')
      expect(check.summary).toBe('Provider sedang tidak tersedia.')
    }
  })

  it('memisahkan galat server, penolakan, dan respons tidak terbaca dari kuota', async () => {
    const server = await fetchJson(
      mockFetch(() => jsonResponse({}, 503)) as unknown as typeof fetch,
      'https://example.test/down',
    )
    const refused = await fetchJson(
      mockFetch(() => jsonResponse({}, 400)) as unknown as typeof fetch,
      'https://example.test/refused',
    )
    const unreadable = await fetchJson(
      mockFetch(() => new Response('bukan json', { status: 200 })) as unknown as typeof fetch,
      'https://example.test/broken',
    )

    expect(server.ok ? null : server.kind).toBe('unavailable')
    expect(refused.ok ? null : refused.kind).toBe('invalid_request')
    expect(unreadable.ok ? null : unreadable.kind).toBe('error')
    if (!unreadable.ok) expect(unreadable.reason).toBe('Respons provider tidak dapat dibaca.')
  })

  it('tidak menyertakan nilai kredensial atau token panjang dalam alasan kegagalan', async () => {
    const secret = 'sk_test_REDACTED_FOR_PUBLIC_REPO'
    const throwing = vi.fn(async () => {
      throw new Error(`invalid api key ${secret} Authorization: Bearer ${secret}`)
    })
    const result = await fetchJson(throwing as unknown as typeof fetch, 'https://example.test/leak')

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).not.toContain(secret)
      expect(failureCheck(result).reason).not.toContain(secret)
    }
  })
})

describe('VGM-04: pemetaan vonis Cloudflare Radar (kategori berjenjang tidak menjadi clean)', () => {
  function radarBody(overall: Record<string, unknown>): Response {
    return jsonResponse({
      task: { status: 'finished', success: true, reportURL: 'https://radar.cloudflare.com/scan/ab12cd34' },
      verdicts: { overall },
    })
  }

  function radarWith(overall: Record<string, unknown>) {
    const fetchMock = mockFetch((url) => {
      if (url.includes('/urlscanner/v2/search')) return jsonResponse({ results: [] })
      if (url.endsWith('/urlscanner/v2/scan')) {
        return jsonResponse({ success: true, result: { uuid: 'ab12cd34-1111-4aaa-8bbb-222233334444' } })
      }
      return radarBody(overall)
    })
    return radarAdapter.check(
      context(fetchMock as unknown as typeof fetch),
      makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' }),
    )
  }

  it('kategori keamanan berjenjang menjadi suspicious, bukan clean', async () => {
    const check = await radarWith({
      malicious: false,
      hasVerdicts: true,
      categories: ['phishing'],
      tags: [],
    })

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('suspicious')
    expect(check.score).toBe(60)
    expect(check.signals?.some((signal) => /phishing/i.test(signal.detail))).toBe(true)
  })

  it('tag keamanan berjenjang juga menahan vonis tetap suspicious', async () => {
    const check = await radarWith({
      malicious: false,
      hasVerdicts: true,
      categories: [],
      tags: ['scams'],
    })

    expect(check.verdict).toBe('suspicious')
  })

  it('malicious tetap menang atas kategori lain', async () => {
    const check = await radarWith({
      malicious: true,
      hasVerdicts: true,
      categories: ['phishing', 'advertisements'],
      tags: [],
    })

    expect(check.verdict).toBe('malicious')
    expect(check.score).toBe(85)
  })

  it('hanya kategori taksonomi konten yang boleh menjadi clean', async () => {
    const check = await radarWith({
      malicious: false,
      hasVerdicts: true,
      categories: ['advertisements', 'analytics'],
      tags: [],
    })

    expect(check.verdict).toBe('clean')
    expect(check.score).toBe(0)
  })

  it('kategori yang tidak dikenal taksonomi menjadi inconclusive', async () => {
    const check = await radarWith({
      malicious: false,
      hasVerdicts: true,
      categories: ['sesuatu-yang-baru'],
      tags: [],
    })

    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
  })

  it('tanpa vonis tetap inconclusive dan tidak pernah clean', async () => {
    const check = await radarWith({
      malicious: false,
      hasVerdicts: false,
      categories: [],
      tags: [],
    })

    expect(check.verdict).toBe('inconclusive')
  })
})

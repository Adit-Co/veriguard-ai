import { describe, expect, it, vi } from 'vitest'
import { radarAdapter } from '../src/scanners/providers/radar.js'
import { urlScanAdapter } from '../src/scanners/providers/urlscan.js'
import { forbiddenNarrativeHits, providerCheckText } from './helpers/narrative.js'
import { normalizeScanUrl } from '../src/scanners/url.js'
import type { ProviderCheck, ProviderContext, ScannerConfig } from '../src/scanners/types.js'

// VGL-30K-R1 Test C: kegagalan provider harus tetap terbaca sebagai kegagalan. Dua gejala yang
// dilaporkan pemilik — Agen 1 menjawab HTTP 400 dan Agen 5 gagal (dugaan DNS) — diuji sampai ke
// bentuk ProviderCheck: tidak pernah menjadi clean, tidak pernah menjadi ancaman, dan tidak
// pernah dihitung sebagai agen yang berhasil.

const NOW_MS = 1_700_000_000_000
const LOOKALIKE_URL = 'https://www.bca.co.id.verify-secure.top'
const REPORT_UUID = 'aaaa1111-2222-4333-8444-555566667777'

const URLSCAN_CLEAN_BODY = {
  verdicts: {
    overall: { score: 0, malicious: false, categories: ['business'] },
    engines: { malicious: false, maliciousTotal: 0 },
  },
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
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

function contextFor(url: string, fetchImpl: typeof fetch, signal?: AbortSignal): ProviderContext {
  return {
    url,
    hostname: new URL(url).hostname,
    fetchImpl,
    now: () => NOW_MS,
    sleep: async () => undefined,
    ...(signal ? { signal } : {}),
  }
}

function radarConfig(): ScannerConfig {
  return makeConfig({ cloudflareApiToken: 'cf-token', cloudflareAccountId: 'cf-account' })
}

function dnsFetch(hostname: string) {
  return vi.fn(async () => {
    const cause = Object.assign(new Error(`queryA ENOTFOUND ${hostname}`), { code: 'ENOTFOUND' })
    throw new TypeError('fetch failed', { cause })
  })
}

type StoredScan = { taskUrl: string; pageUrl: string; ageMs: number }

/**
 * Peniru perilaku urlscan.io sesuai referensi resmi pencarian (https://urlscan.io/docs/search/):
 * `task.url` adalah URL yang dikirim, `page.url` adalah halaman akhir SETELAH redirect, dan
 * sebuah kueri hanya mengembalikan dokumen yang field yang ditanyakan cocok dengan frasanya.
 * Endpoint pengiriman menolak HTTP 400 untuk URL yang sudah dimiliki akun — persis rantai yang
 * menimbulkan gejala pemilik.
 */
function urlscanEmulator(scans: StoredScan[]) {
  const calls: Array<'lookup' | 'submit' | 'result'> = []
  const queries: string[] = []

  const fetchImpl = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input))

    if (url.pathname.includes('/api/v1/search/')) {
      calls.push('lookup')
      const query = decodeURIComponent(url.searchParams.get('q') ?? '')
      queries.push(query)

      const clause = /([A-Za-z][\w.]*)\s*:\s*"([^"]*)"/.exec(query)
      const field = clause?.[1]
      const phrase = (clause?.[2] ?? '').toLowerCase()
      const hits = scans.filter((scan) => {
        if (field === 'task.url') return scan.taskUrl.toLowerCase() === phrase
        if (field === 'page.url') return scan.pageUrl.toLowerCase() === phrase
        return false
      })

      return jsonResponse({
        results: hits.map((scan) => ({
          page: { url: scan.pageUrl },
          task: {
            uuid: REPORT_UUID,
            url: scan.taskUrl,
            time: new Date(NOW_MS - scan.ageMs).toISOString(),
          },
        })),
      })
    }

    if (url.pathname.includes('/api/v1/scan/')) {
      calls.push('submit')
      const submitted = String(JSON.parse(String(init?.body ?? '{}')).url ?? '')
      const owned = scans.some((scan) => scan.taskUrl.toLowerCase() === submitted.toLowerCase())

      return owned
        ? jsonResponse({ code: 400, message: 'this URL has already been scanned by your key' }, 400)
        : jsonResponse({ uuid: REPORT_UUID, message: 'Job submitted' }, 201)
    }

    calls.push('result')
    return jsonResponse(URLSCAN_CLEAN_BODY)
  })

  return { fetchImpl, calls, queries }
}

function dnsErrorFetch(code: string) {
  return vi.fn(async () => {
    const cause = Object.assign(new Error(`connect ${code} api.cloudflare.com:443`), { code })
    throw new TypeError('fetch failed', { cause })
  })
}

describe('VGL-30K-R1 Test C Agen 1 urlscan: identitas laporan dan penolakan permintaan', () => {
  it('mencari dengan field identitas URL yang dikirim, bukan halaman hasil redirect', async () => {
    // Akar masalah HTTP 400 pemilik: laporan untuk URL yang dikirim sudah ada, tetapi kueri
    // menanyakan page.url (halaman akhir setelah redirect) sehingga tidak menemukan apa pun,
    // lalu pengiriman ulang ditolak provider dengan HTTP 400.
    // Service menormalkan URL sebelum memanggil adapter, jadi identitas yang dicari dan yang
    // tersimpan di laporan memakai bentuk yang sama.
    const target = normalizeScanUrl(LOOKALIKE_URL)
    const { fetchImpl, calls, queries } = urlscanEmulator([
      { taskUrl: target, pageUrl: 'https://situs-resmi.example/', ageMs: 3_600_000 },
    ])

    const check = await urlScanAdapter.check(
      contextFor(target, fetchImpl as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(queries[0]).toContain('task.url:')
    expect(queries[0]).not.toContain('page.url:')
    // Bukti bahwa 400 tidak terjadi lagi: laporan yang ada dipakai ulang tanpa pengiriman ulang.
    expect(calls).toEqual(['lookup', 'result'])
    expect(check.status).toBe('success')
    expect(check.verdict).toBe('clean')
    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence?.ageMs).toBe(3_600_000)
  })

  it('HTTP 400 yang sesungguhnya tetap menjadi permintaan ditolak, bukan clean atau ancaman', async () => {
    // Tidak ada laporan yang cocok sama sekali, dan provider tetap menolak pengirimannya:
    // status penolakan dipertahankan apa adanya.
    const rejected = vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      if (url.includes('/api/v1/search/')) return jsonResponse({ results: [] })
      if (url.includes('/api/v1/scan/')) {
        return jsonResponse({ code: 400, message: 'parameter url is not acceptable' }, 400)
      }
      return jsonResponse(URLSCAN_CLEAN_BODY)
    })

    const check = await urlScanAdapter.check(
      contextFor(LOOKALIKE_URL, rejected as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(check.status).toBe('invalid_request')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.signals).toHaveLength(0)
    expect(check.summary).toBe('Permintaan pemeriksaan ditolak provider.')
    expect(check.reason).toContain('400')
    // Body respons provider tidak pernah dibaca, jadi isinya tidak mungkin ikut terbaca.
    expect(check.reason).not.toContain('not acceptable')
    expect(forbiddenNarrativeHits(providerCheckText(check))).toHaveLength(0)
  })

  it('galat jaringan urlscan menjadi penyedia tidak tersedia dengan kode aman', async () => {
    const dns = dnsErrorFetch('ENOTFOUND')

    const check = await urlScanAdapter.check(
      contextFor(LOOKALIKE_URL, dns as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(check.status).toBe('unavailable')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.summary).toBe('Provider sedang tidak tersedia.')
    expect(check.reason).toContain('ENOTFOUND')
    expect(check.reason).not.toContain('api.cloudflare.com')
  })
})

describe('VGL-30K-R1 Test C Agen 5 Radar: kegagalan jaringan dan penolakan dipisah', () => {
  it('kegagalan DNS dilaporkan sebagai penyedia tidak tersedia, bukan tidak dijalankan', async () => {
    // Gejala pemilik: Agen 5 gagal karena DNS, tetapi antarmuka membaca "Tidak dijalankan"
    // karena galat jaringan non-timeout dipetakan sebagai pembatalan proses scan.
    const dns = dnsErrorFetch('ENOTFOUND')

    const check = await radarAdapter.check(
      contextFor(LOOKALIKE_URL, dns as unknown as typeof fetch),
      radarConfig(),
    )

    expect(check.status).toBe('unavailable')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.signals).toHaveLength(0)
    expect(check.summary).toBe('Provider sedang tidak tersedia.')
    expect(check.reason).toContain('ENOTFOUND')
    expect(check.reason).not.toContain('dibatalkan')
    expect(check.reason).not.toContain('api.cloudflare.com')
    expect(forbiddenNarrativeHits(providerCheckText(check))).toHaveLength(0)
  })

  it('kode kegagalan jaringan yang berbeda tetap tampil berbeda', async () => {
    const reset = await radarAdapter.check(
      contextFor(LOOKALIKE_URL, dnsErrorFetch('ECONNRESET') as unknown as typeof fetch),
      radarConfig(),
    )
    const refused = await radarAdapter.check(
      contextFor(LOOKALIKE_URL, dnsErrorFetch('ECONNREFUSED') as unknown as typeof fetch),
      radarConfig(),
    )

    expect(reset.status).toBe('unavailable')
    expect(refused.status).toBe('unavailable')
    expect(reset.reason).toContain('ECONNRESET')
    expect(refused.reason).toContain('ECONNREFUSED')
    expect(reset.reason).not.toBe(refused.reason)
  })

  it('HTTP 400 pada pencarian tidak berubah menjadi hasil dan tidak mengumpan body provider', async () => {
    const rejected = vi.fn(async () => {
      const leaked = 'invalid parameter for https://rahasia-klien.example/top-secret-path'
      return jsonResponse({ success: false, errors: [{ message: leaked }] }, 400)
    })

    const check = await radarAdapter.check(
      contextFor(LOOKALIKE_URL, rejected as unknown as typeof fetch),
      radarConfig(),
    )

    expect(check.status).toBe('invalid_request')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.summary).toBe('Permintaan pemeriksaan ditolak provider.')
    expect(check.reason).toContain('400')
    expect(check.reason).not.toContain('invalid parameter')
    expect(check.reason).not.toContain('rahasia-klien')
  })

  it('HTTP 400 pada pengiriman scan juga tetap menjadi permintaan ditolak', async () => {
    const rejected = vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      if (url.includes('/urlscanner/v2/search')) return jsonResponse({ results: [] })
      if (url.endsWith('/urlscanner/v2/scan')) {
        return jsonResponse({ success: false, errors: [{ message: 'url not acceptable' }] }, 400)
      }
      return jsonResponse({ task: { status: 'finished' }, verdicts: {} })
    })

    const check = await radarAdapter.check(
      contextFor(LOOKALIKE_URL, rejected as unknown as typeof fetch),
      radarConfig(),
    )

    expect(check.status).toBe('invalid_request')
    expect(check.verdict).toBe('inconclusive')
    expect(check.summary).toBe('Permintaan pemeriksaan ditolak provider.')
  })

  it('pembatalan eksternal yang sesungguhnya tetap ditandai tidak dijalankan', async () => {
    // Guard: perbaikan klasifikasi tidak boleh mengubah pembatalan proses scan menjadi
    // "provider tidak tersedia".
    const controller = new AbortController()
    controller.abort()

    const aborted = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      throw (init?.signal as AbortSignal | undefined)?.reason ?? new DOMException('aborted', 'AbortError')
    })

    const check = await radarAdapter.check(
      contextFor(LOOKALIKE_URL, aborted as unknown as typeof fetch, controller.signal),
      radarConfig(),
    )

    expect(check.status).toBe('skipped')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
  })

  it('galat server 5xx tetap tidak tersedia dan tidak mengumpan pesan provider', async () => {
    const broken = vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      if (url.includes('/urlscanner/v2/search')) {
        return jsonResponse({ success: false, errors: [{ message: 'unexpected server condition' }] }, 500)
      }
      return jsonResponse({ success: false, errors: [{ message: 'unexpected server condition' }] }, 500)
    })

    const check = await radarAdapter.check(
      contextFor(LOOKALIKE_URL, broken as unknown as typeof fetch),
      radarConfig(),
    )

    expect(check.status).toBe('unavailable')
    expect(check.summary).toBe('Provider sedang tidak tersedia.')
    expect(check.reason).toContain('500')
    expect(check.reason).not.toContain('unexpected server condition')
  })
})

describe('VGL-30K-R1 Test C kegagalan selalu fail-closed', () => {
  it('galat jaringan kedua agen tidak menghasilkan vonis maupun skor', async () => {
    const throwing = () =>
      vi.fn(async () => {
        throw new TypeError('fetch failed')
      }) as unknown as typeof fetch

    const checks: ProviderCheck[] = await Promise.all([
      urlScanAdapter.check(contextFor(LOOKALIKE_URL, throwing()), makeConfig({ urlscanApiKey: 'k' })),
      radarAdapter.check(contextFor(LOOKALIKE_URL, throwing()), radarConfig()),
    ])

    for (const check of checks) {
      expect(check.verdict).toBe('inconclusive')
      expect(check.score).toBeNull()
      expect(check.signals).toHaveLength(0)
      expect(check.status).not.toBe('success')
    }
  })
})

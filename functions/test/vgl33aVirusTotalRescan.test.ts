import { describe, expect, it } from 'vitest'
import { virusTotalAdapter } from '../src/scanners/providers/virustotal.js'
import type { ProviderContext, ScannerConfig } from '../src/scanners/types.js'

// VGL-33A — pemulihan laporan VirusTotal yang kedaluwarsa.
//
// VGL-32C membuktikan celahnya secara live: translate.google.co.id mentok "Perlu Perhatian"
// karena satu-satunya bukti bersih VT berasal dari laporan berumur 16,2 hari — engine mem-valid
// kebugaran bukti (TTL 168 jam), jadi laporan lama tidak dihitung meski vonisnya 0 deteksi.
// Dokumentasi VT v3 menyediakan mekanisme analisis baru yang resmi: POST /urls (submit) lalu
// GET /analyses/{id} (pantau) lalu GET /urls/{id} (laporan terbaru). Adapter ini memakainya
// TERBATAS: satu submit per pemeriksaan, hanya untuk laporan stale yang 0 berbahaya +
// 0 mencurigakan + >= 20 engine melapor, dengan anggaran polling di bawah tenggat provider.
// Setiap kegagalan (429, 400, polling belum selesai, baca ulang gagal) mengembalikan laporan
// lama APA ADANYA — stale, timestamp asli, tanpa retry submission yang ditolak.

const NOW_MS = 1_700_000_000_000
const TARGET_URL = 'https://translate.google.co.id/'
const HOUR_MS = 3_600_000

type Call = { url: string; method: string }

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function makeConfig(overrides: Partial<ScannerConfig> = {}): ScannerConfig {
  return {
    urlscanApiKey: 'urlscan-key',
    virusTotalApiKey: 'vt-key',
    openPhishApiKey: null,
    threatFoxApiKey: 'tf-key',
    cloudflareApiToken: 'cf-token',
    cloudflareAccountId: 'cf-account',
    otxApiKey: 'otx-key',
    googleSafeBrowsingApiKey: 'sb-key',
    hybridAnalysisApiKey: 'ha-key',
    ...overrides,
  }
}

function vtReport(stats: Record<string, number>, ageSec: number) {
  return {
    data: {
      attributes: {
        last_analysis_date: Math.floor(NOW_MS / 1000) - ageSec,
        last_analysis_stats: {
          malicious: 0,
          suspicious: 0,
          harmless: 2,
          undetected: 91,
          ...stats,
        },
      },
    },
  }
}

const STALE_AGE_SEC = Math.floor((200 * HOUR_MS) / 1000) // ±8,3 hari > TTL 168 jam
const FRESH_AGE_SEC = 60

function makeContext(
  handler: (url: string, init: RequestInit | undefined) => Response,
): { context: ProviderContext; calls: Call[] } {
  const calls: Call[] = []
  const fetchImpl = (async (input: unknown, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    calls.push({ url, method })
    return handler(url, init)
  }) as unknown as typeof fetch
  const context: ProviderContext = {
    url: TARGET_URL,
    hostname: new URL(TARGET_URL).hostname,
    fetchImpl,
    now: () => NOW_MS,
    sleep: async () => undefined,
  }
  return { context, calls }
}

function countPosts(calls: Call[]): number {
  return calls.filter(
    (call) => call.method === 'POST' && call.url === 'https://www.virustotal.com/api/v3/urls',
  ).length
}

const SUBMIT_OK = { data: { id: 'analysis-1' } }
const ANALYSIS_COMPLETED = { data: { id: 'analysis-1', attributes: { status: 'completed' } } }
const ANALYSIS_QUEUED = { data: { id: 'analysis-1', attributes: { status: 'queued' } } }

describe('VGL-33A — rescan VirusTotal untuk laporan stale yang bersih', () => {
  it('laporan stale 0 deteksi -> submit sekali, pantau, baca ulang -> bukti fresh dari new_scan', async () => {
    const { context, calls } = makeContext((url, init) => {
      const method = init?.method ?? 'GET'
      if (method === 'POST' && url.endsWith('/api/v3/urls')) return jsonResponse(SUBMIT_OK)
      if (url.includes('/api/v3/analyses/')) return jsonResponse(ANALYSIS_COMPLETED)
      if (url.includes('/api/v3/urls/')) {
        // Baca ulang setelah analisis selesai: laporan baru berumur beberapa menit.
        return jsonResponse(
          calls.some((call) => call.method === 'POST') &&
            calls.filter((call) => call.url.includes('/api/v3/analyses/')).length > 0 &&
            calls.filter((call) => call.method === 'GET' && call.url.includes('/api/v3/urls/')).length > 1
            ? vtReport({}, FRESH_AGE_SEC)
            : vtReport({}, STALE_AGE_SEC),
        )
      }
      throw new Error(`Fixture tidak menyiapkan rute: ${method} ${url}`)
    })

    const check = await virusTotalAdapter.check(context, makeConfig())

    expect(check.verdict).toBe('clean')
    expect(check.negative?.strength).toBe('explicit')
    expect(check.evidence?.source).toBe('new_scan')
    expect(check.evidence?.ageMs).toBe(FRESH_AGE_SEC * 1000)
    expect(check.evidence?.observedAt).toBe(
      new Date((Math.floor(NOW_MS / 1000) - FRESH_AGE_SEC) * 1000).toISOString(),
    )
    expect(countPosts(calls)).toBe(1)
  })

  it('laporan fresh -> tidak ada submission sama sekali', async () => {
    const { context, calls } = makeContext((url) => {
      if (url.includes('/api/v3/urls/')) return jsonResponse(vtReport({}, FRESH_AGE_SEC))
      throw new Error(`Fixture tidak menyiapkan rute: ${url}`)
    })

    const check = await virusTotalAdapter.check(context, makeConfig())

    expect(check.verdict).toBe('clean')
    expect(check.negative?.strength).toBe('explicit')
    expect(countPosts(calls)).toBe(0)
  })

  it('laporan stale dengan deteksi berbahaya -> tidak ada submission (vonis tidak dikejar ulang)', async () => {
    const { context, calls } = makeContext((url) => {
      if (url.includes('/api/v3/urls/')) {
        return jsonResponse(vtReport({ malicious: 3 }, STALE_AGE_SEC))
      }
      throw new Error(`Fixture tidak menyiapkan rute: ${url}`)
    })

    const check = await virusTotalAdapter.check(context, makeConfig())

    expect(check.verdict).toBe('malicious')
    expect(countPosts(calls)).toBe(0)
  })

  it('HTTP 429 saat submit -> hanya satu percobaan, laporan stale dikembalikan utuh', async () => {
    const { context, calls } = makeContext((url, init) => {
      const method = init?.method ?? 'GET'
      if (method === 'POST') {
        return jsonResponse({ error: { code: 'QuotaExceeded' } }, 429)
      }
      if (url.includes('/api/v3/urls/')) return jsonResponse(vtReport({}, STALE_AGE_SEC))
      throw new Error(`Fixture tidak menyiapkan rute: ${method} ${url}`)
    })

    const check = await virusTotalAdapter.check(context, makeConfig())

    expect(countPosts(calls)).toBe(1)
    expect(check.verdict).toBe('clean')
    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence?.ageMs).toBe(STALE_AGE_SEC * 1000)
    // Umur laporan lama tetap terbaca jujur di provenance.
    expect(
      check.signals.some((signal) => signal.detail.includes('melewati batas umur laporan 168 jam')),
    ).toBe(true)
  })

  it('HTTP 400 saat submit -> submission yang ditolak tidak pernah diulang', async () => {
    const { context, calls } = makeContext((url, init) => {
      const method = init?.method ?? 'GET'
      if (method === 'POST') {
        return jsonResponse({ error: { code: 'BadRequest' } }, 400)
      }
      if (url.includes('/api/v3/urls/')) return jsonResponse(vtReport({}, STALE_AGE_SEC))
      throw new Error(`Fixture tidak menyiapkan rute: ${method} ${url}`)
    })

    const check = await virusTotalAdapter.check(context, makeConfig())

    expect(countPosts(calls)).toBe(1)
    expect(check.verdict).toBe('clean')
    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence?.ageMs).toBe(STALE_AGE_SEC * 1000)
  })

  it('polling belum selesai -> laporan stale tetap dipakai, submit tidak diulang', async () => {
    const { context, calls } = makeContext((url, init) => {
      const method = init?.method ?? 'GET'
      if (method === 'POST') return jsonResponse(SUBMIT_OK)
      if (url.includes('/api/v3/analyses/')) return jsonResponse(ANALYSIS_QUEUED)
      if (url.includes('/api/v3/urls/')) return jsonResponse(vtReport({}, STALE_AGE_SEC))
      throw new Error(`Fixture tidak menyiapkan rute: ${method} ${url}`)
    })

    const check = await virusTotalAdapter.check(context, makeConfig())

    expect(countPosts(calls)).toBe(1)
    expect(check.verdict).toBe('clean')
    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence?.ageMs).toBe(STALE_AGE_SEC * 1000)
  })

  it('rescan sukses tetapi baca ulang gagal -> laporan lama apa adanya, tanpa timestamp palsu', async () => {
    let reads = 0
    const { context } = makeContext((url, init) => {
      const method = init?.method ?? 'GET'
      if (method === 'POST') return jsonResponse(SUBMIT_OK)
      if (url.includes('/api/v3/analyses/')) return jsonResponse(ANALYSIS_COMPLETED)
      if (url.includes('/api/v3/urls/')) {
        reads += 1
        if (reads === 1) return jsonResponse(vtReport({}, STALE_AGE_SEC))
        return jsonResponse({ error: { code: 'APIError' } }, 500)
      }
      throw new Error(`Fixture tidak menyiapkan rute: ${method} ${url}`)
    })

    const check = await virusTotalAdapter.check(context, makeConfig())

    expect(check.verdict).toBe('clean')
    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence?.ageMs).toBe(STALE_AGE_SEC * 1000)
    expect(check.evidence?.observedAt).toBe(
      new Date((Math.floor(NOW_MS / 1000) - STALE_AGE_SEC) * 1000).toISOString(),
    )
  })

  it('status analisis "in-progress" (varian hyphen live) -> tetap dipantau sampai completed', async () => {
    let polls = 0
    const { context, calls } = makeContext((url, init) => {
      const method = init?.method ?? 'GET'
      if (method === 'POST') return jsonResponse(SUBMIT_OK)
      if (url.includes('/api/v3/analyses/')) {
        polls += 1
        return jsonResponse(
          polls < 3
            ? { data: { id: 'analysis-1', attributes: { status: 'in-progress' } } }
            : ANALYSIS_COMPLETED,
        )
      }
      if (url.includes('/api/v3/urls/')) {
        return jsonResponse(
          polls >= 3 ? vtReport({}, FRESH_AGE_SEC) : vtReport({}, STALE_AGE_SEC),
        )
      }
      throw new Error(`Fixture tidak menyiapkan rute: ${method} ${url}`)
    })

    const check = await virusTotalAdapter.check(context, makeConfig())

    expect(check.evidence?.source).toBe('new_scan')
    expect(check.verdict).toBe('clean')
    expect(countPosts(calls)).toBe(1)
  })

  it('kasus live translate: stale 16,2 hari + submit 429 -> tetap existing_report, vonis tidak berubah', async () => {
    const { context, calls } = makeContext((url, init) => {
      const method = init?.method ?? 'GET'
      if (method === 'POST') {
        return jsonResponse({ error: { code: 'QuotaExceeded', message: 'health' } }, 429)
      }
      if (url.includes('/api/v3/urls/')) {
        return jsonResponse(vtReport({}, Math.floor((16.2 * 24 * 3600 * 1000) / 1000)))
      }
      throw new Error(`Fixture tidak menyiapkan rute: ${method} ${url}`)
    })

    const check = await virusTotalAdapter.check(context, makeConfig())

    expect(countPosts(calls)).toBe(1)
    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence!.ageMs!).toBeGreaterThan(168 * HOUR_MS)
  })
})

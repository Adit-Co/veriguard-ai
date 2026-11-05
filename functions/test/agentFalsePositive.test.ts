import { describe, expect, it, vi } from 'vitest'
import { fetchJson, type FetchJsonResult } from '../src/scanners/http.js'
import { failureCheck } from '../src/scanners/result.js'
import { hybridAnalysisAdapter } from '../src/scanners/providers/hybrid.js'
import { otxAdapter } from '../src/scanners/providers/otx.js'
import { urlScanAdapter } from '../src/scanners/providers/urlscan.js'
import { forbiddenNarrativeHits, providerCheckText } from './helpers/narrative.js'
import type { ProviderCheck, ProviderContext, ScannerConfig } from '../src/scanners/types.js'

// VGL-30J: regressi khusus untuk dua mekanik false positive pada situs resmi yang
// dilaporkan pengguna (youtube/instagram/discord/gmail/steam/spotify) dan untuk HTTP 400
// yang dikirim Agen 1. Semua fixture memakai fetchImpl tiruan; tidak ada permintaan nyata
// ke provider dan tidak ada kredensial yang dipakai.

const NOW_MS = 1_700_000_000_000
const SUBMIT_UUID = '11111111-1111-1111-1111-111111111111'
const PHISH_REPORT_UUID = '22222222-2222-2222-2222-222222222222'

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

function contextFor(url: string, fetchImpl: typeof fetch): ProviderContext {
  return {
    url,
    hostname: new URL(url).hostname,
    fetchImpl,
    now: () => NOW_MS,
    sleep: async () => undefined,
  }
}

function notCacheNarrative(check: ProviderCheck): boolean {
  return forbiddenNarrativeHits(providerCheckText(check)).length === 0
}

const OFFICIAL_TARGET = 'https://www.instagram.com/'

const CLEAN_BODY = {
  verdicts: {
    overall: { score: 0, malicious: false, categories: ['business'] },
    engines: { malicious: false, maliciousTotal: 0 },
  },
  task: { uuid: SUBMIT_UUID, url: OFFICIAL_TARGET },
}

const MALICIOUS_BODY = {
  verdicts: {
    overall: {
      score: 90,
      malicious: true,
      categories: [' phishing'],
      tags: [],
      brands: [],
    },
    engines: { malicious: true, maliciousTotal: 3 },
  },
  task: { uuid: PHISH_REPORT_UUID, url: 'https://insta-secure-login.xyz/verify' },
}

type UrlscanKind = 'search' | 'submit' | 'result'

function urlscanFetch(
  handlers: Partial<Record<UrlscanKind, (url: string) => Response>>,
  onCall?: (kind: UrlscanKind, url: string) => void,
) {
  return vi.fn(async (input: string | URL | Request) => {
    const url = String(input)
    if (url.includes('/api/v1/search/')) {
      onCall?.('search', url)
      return handlers.search?.(url) ?? jsonResponse({ results: [] })
    }
    if (url.includes('/api/v1/scan/')) {
      onCall?.('submit', url)
      return handlers.submit?.(url) ?? jsonResponse({ uuid: SUBMIT_UUID, message: 'Successful' })
    }
    onCall?.('result', url)
    // Vonis pengirim phishing hanya tersedia untuk uuid laporan itu; pemindaian baru untuk
    // URL resmi selalu menjawab bersih, sehingga tes membuktikan DARI mana bukti diambil.
    if (url.includes(PHISH_REPORT_UUID)) return jsonResponse(MALICIOUS_BODY)
    return handlers.result?.(url) ?? jsonResponse(CLEAN_BODY)
  })
}

function searchRecord(input: {
  taskUrl: string
  pageUrl: string
  ageMs: number
  uuid?: string
}) {
  return {
    results: [
      {
        task: {
          uuid: input.uuid ?? PHISH_REPORT_UUID,
          url: input.taskUrl,
          time: new Date(NOW_MS - input.ageMs).toISOString(),
        },
        page: { url: input.pageUrl },
      },
    ],
  }
}

describe('VGL-30J Agen 1: identitas laporan yang dipakai ulang', () => {
  it('tidak memakai laporan yang dikirim untuk URL lain walau halaman akhirnya sama', async () => {
    // Mekanik kegagalan nyata: tautan phishing di-indeks URLScan karena MENGALIHKAN
    // korban ke situs resmi. Field `page.url` laporan itu memang URL resmi, sedangkan
    // vonis provider (`verdicts.overall`) bercerita tentang URL yang DIKIRIM. Laporan
    // semacam itu bukan bukti tentang situs resmi.
    const calls: UrlscanKind[] = []
    const resultUrls: string[] = []
    const fetchMock = urlscanFetch(
      {
        search: () =>
          jsonResponse(
            searchRecord({
              taskUrl: 'https://insta-secure-login.xyz/verify',
              pageUrl: OFFICIAL_TARGET,
              ageMs: 60_000,
            }),
          ),
      },
      (kind, url) => {
        calls.push(kind)
        if (kind === 'result') resultUrls.push(url)
      },
    )

    const check = await urlScanAdapter.check(
      contextFor(OFFICIAL_TARGET, fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    // Laporan phishing tidak pernah dibaca sebagai vonis untuk URL resmi.
    expect(resultUrls.some((url) => url.includes(PHISH_REPORT_UUID))).toBe(false)
    expect(calls).toEqual(['search', 'submit', 'result'])
    expect(check.verdict).toBe('clean')
    expect(check.evidence?.source).toBe('new_scan')
    expect(notCacheNarrative(check)).toBe(true)
  })

  it('tetap memakai laporan yang memang dikirim untuk URL resmi walau halaman akhirnya berpindah', async () => {
    // Kontrol: jalur hemat kuota tidak boleh dirusak. Laporan dikirim pada URL persis yang
    // diperiksa; redirect internal situs (halaman akhir berbeda) adalah properti URL itu.
    const calls: UrlscanKind[] = []
    const fetchMock = urlscanFetch(
      {
        search: () =>
          jsonResponse(
            searchRecord({
              taskUrl: OFFICIAL_TARGET,
              pageUrl: 'https://www.instagram.com/accounts/login/',
              ageMs: 3_600_000,
              uuid: SUBMIT_UUID,
            }),
          ),
        result: () => jsonResponse({ ...CLEAN_BODY, task: { uuid: SUBMIT_UUID, url: OFFICIAL_TARGET } }),
      },
      (kind) => calls.push(kind),
    )

    const check = await urlScanAdapter.check(
      contextFor(OFFICIAL_TARGET, fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(calls).toEqual(['search', 'result'])
    expect(check.status).toBe('success')
    expect(check.verdict).toBe('clean')
    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence?.ageMs).toBe(3_600_000)
  })

  it('tidak memakai laporan tanpa URL kiriman (kecocokan tidak dapat dipastikan)', async () => {
    const calls: UrlscanKind[] = []
    const fetchMock = urlscanFetch(
      {
        search: () =>
          jsonResponse({
            results: [
              {
                task: {
                  uuid: PHISH_REPORT_UUID,
                  time: new Date(NOW_MS - 60_000).toISOString(),
                },
                page: { url: OFFICIAL_TARGET },
              },
            ],
          }),
      },
      (kind) => calls.push(kind),
    )

    const check = await urlScanAdapter.check(
      contextFor(OFFICIAL_TARGET, fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(calls).toEqual(['search', 'submit', 'result'])
    expect(check.verdict).toBe('clean')
  })
})

describe('VGL-30J Agen 1: permintaan ditolak (HTTP 400)', () => {
  it('memakai laporan lama yang sudah ada ketika submit ditolak provider', async () => {
    // Bukti pencarian sudah tersedia: ada laporan untuk URL persis ini, hanya lebih tua
    // dari kebijakan kesegaran. Submit ditolak (HTTP 400) BUKAN alasan untuk membuang
    // bukti itu dan melaporkan "tidak dapat dinilai".
    const calls: UrlscanKind[] = []
    const fetchMock = urlscanFetch(
      {
        search: () =>
          jsonResponse(
            searchRecord({
              taskUrl: OFFICIAL_TARGET,
              pageUrl: OFFICIAL_TARGET,
              ageMs: 48 * 60 * 60_000,
              uuid: SUBMIT_UUID,
            }),
          ),
        submit: () => jsonResponse({ message: 'Duplicate scan', success: false, status: 400 }, 400),
        result: () =>
          jsonResponse({ ...CLEAN_BODY, task: { uuid: SUBMIT_UUID, url: OFFICIAL_TARGET } }),
      },
      (kind) => calls.push(kind),
    )

    const check = await urlScanAdapter.check(
      contextFor(OFFICIAL_TARGET, fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('clean')
    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence?.ageMs).toBe(48 * 60 * 60_000)
    expect(calls.filter((kind) => kind === 'submit')).toHaveLength(1)
    expect(notCacheNarrative(check)).toBe(true)
  })

  it('melaporkan permintaan tidak valid tanpa mengarang vonis saat tidak ada laporan', async () => {
    const fetchMock = urlscanFetch({
      submit: () => jsonResponse({ message: 'Invalid URL format', success: false, status: 400 }, 400),
    })

    const check = await urlScanAdapter.check(
      contextFor(OFFICIAL_TARGET, fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(check.status).toBe('invalid_request')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.reason).toContain('HTTP 400')
    // Penolakan permintaan bukan bukti aman maupun ancaman.
    expect(check.signals).toHaveLength(0)
    expect(notCacheNarrative(check)).toBe(true)
  })

  it('deteksi tautan phishing tetap berjalan saat URL yang diperiksa adalah pengirimnya', async () => {
    // Sisi penting dari perbaikan: identitas diambil dari URL kiriman, jadi pemeriksaan
    // terhadap tautan phishing itu sendiri tetap memakai laporan provider dan tetap
    // divonis berbahaya. Perbaikan false positive tidak mengurangi deteksi.
    const phishingUrl = 'https://insta-secure-login.xyz/verify'
    const calls: UrlscanKind[] = []
    const fetchMock = urlscanFetch(
      {
        search: () =>
          jsonResponse(
            searchRecord({
              taskUrl: phishingUrl,
              pageUrl: OFFICIAL_TARGET,
              ageMs: 60_000,
            }),
          ),
      },
      (kind) => calls.push(kind),
    )

    const check = await urlScanAdapter.check(
      contextFor(phishingUrl, fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(calls).toEqual(['search', 'result'])
    expect(check.verdict).toBe('malicious')
    expect(check.score).toBe(90)
    expect(check.evidence?.source).toBe('existing_report')
  })

  it('permintaan lookup yang ditolak tidak menghentikan pemindaian baru', async () => {
    const calls: UrlscanKind[] = []
    const fetchMock = urlscanFetch(
      {
        search: () => jsonResponse({ message: 'invalid query', success: false }, 400),
      },
      (kind) => calls.push(kind),
    )

    const check = await urlScanAdapter.check(
      contextFor(OFFICIAL_TARGET, fetchMock as unknown as typeof fetch),
      makeConfig({ urlscanApiKey: 'urlscan-key' }),
    )

    expect(calls).toEqual(['search', 'submit', 'result'])
    expect(check.status).toBe('success')
  })
})

describe('VGL-30J: klasifikasi status kegagalan provider', () => {
  async function kindFor(status: number): Promise<FetchJsonResult> {
    return fetchJson(
      (async () =>
        new Response(JSON.stringify({ message: 'rejected' }), {
          status,
          headers: { 'Content-Type': 'application/json' },
        })) as unknown as typeof fetch,
      'https://provider.example/api',
      {},
      5_000,
    )
  }

  it('memisahkan permintaan yang ditolak (400/422) dari kegagalan provider umum', async () => {
    expect((await kindFor(400)).kind).toBe('invalid_request')
    expect((await kindFor(422)).kind).toBe('invalid_request')
  })

  it('status kegagalan lain tidak berubah', async () => {
    expect((await kindFor(401)).kind).toBe('auth_failed')
    expect((await kindFor(403)).kind).toBe('auth_failed')
    expect((await kindFor(404)).kind).toBe('not_found')
    expect((await kindFor(429)).kind).toBe('rate_limited')
    expect((await kindFor(503)).kind).toBe('unavailable')
    expect((await kindFor(418)).kind).toBe('error')
  })

  it('alasan 400 tidak pernah membawa isi atau kredensial respons provider', async () => {
    const result = await fetchJson(
      (async () =>
        new Response(
          JSON.stringify({
            message: 'bad request',
            api_key: 'supersecretvalue1234567890abcdef',
            url: 'https://user:pass@internal.example/path',
          }),
          { status: 400, headers: { 'Content-Type': 'application/json' } },
        )) as unknown as typeof fetch,
      'https://provider.example/api',
      {},
      5_000,
    )

    const rendered = JSON.stringify(result)
    expect(result.kind).toBe('invalid_request')
    expect(rendered).not.toContain('supersecretvalue1234567890abcdef')
    expect(rendered).not.toContain('internal.example')
    expect(rendered).not.toContain('bad request')
  })

  it('failureCheck memetakan permintaan ditolak ke inconclusive tanpa skor', () => {
    const failed: Extract<FetchJsonResult, { ok: false }> = {
      ok: false,
      status: 400,
      kind: 'invalid_request',
      reason: 'Permintaan ditolak provider (HTTP 400).',
    }
    const check = failureCheck(failed)
    expect(check.status).toBe('invalid_request')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.reason).toBe('Permintaan ditolak provider (HTTP 400).')
  })
})

describe('VGL-30J Hybrid Analysis: konsistensi skor pada bukti tingkat domain', () => {
  function hybridFetch(domainDocs: Record<string, unknown>[]) {
    return vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      const body = String(init?.body ?? '')
      // Pencarian URL persis: tanpa dokumen → adapter turun ke pencarian domain.
      if (!body.startsWith('domain=')) return jsonResponse({ result: [] })
      return jsonResponse({ result: domainDocs })
    })
  }

  // VGL-30J melarang vonis tingkat domain membawa skor band malicious. VGL-30K-R4 memperketat
  // aturan yang sama ke nol: dokumen yang subjeknya bukan alamat ini tidak menyumbang skor sama
  // sekali, jadi invariant "tidak ada 85 pada bukti domain" tetap dijaga.
  it('vonis pada laporan tanpa identitas subjek tidak membawa skor sama sekali', async () => {
    const fetchMock = hybridFetch([
      {
        verdict: 'malicious',
        threat_score: 100,
        av_detect: 40,
        analysis_start_time: new Date(NOW_MS - 2 * 60 * 60_000).toISOString(),
        vx_family: ['Phishing'],
      },
    ])

    const check = await hybridAnalysisAdapter.check(
      contextFor('https://www.youtube.com/', fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'hybrid-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.signals.every((signal) => signal.severity === 'info')).toBe(true)
    expect(check.reason).toContain('subjek analisisnya')
  })

  it('vonis malicious pada subjek lain di domain yang sama tetap tanpa skor', async () => {
    const fetchMock = hybridFetch([
      {
        verdict: 'malicious',
        threat_score: 100,
        host: 'www.youtube.com',
        url: [{ url: 'https://www.youtube.com/watch?v=x' }],
        analysis_start_time: new Date(NOW_MS - 2 * 60 * 60_000).toISOString(),
        vx_family: ['Phishing'],
      },
    ])

    const check = await hybridAnalysisAdapter.check(
      contextFor('https://www.youtube.com/', fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'hybrid-key' }),
    )

    // Laporan menganalisis URL lain: vonisnya bukan tentang alamat ini.
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
  })
})

describe('VGL-30J OTX: 400 domain tidak dikenal tetap tanpa bukti', () => {
  it('memperlakukan indikator domain yang ditolak sebagai no-match, bukan galat teknis', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      if (url.includes('/indicators/domain/')) {
        return jsonResponse({ detail: 'Invalid domain' }, 400)
      }
      return jsonResponse({ pulse_info: { count: 0, pulses: [] } })
    })

    const check = await otxAdapter.check(
      contextFor('https://www.spotify.com/', fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.status).toBe('not_found')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
  })
})

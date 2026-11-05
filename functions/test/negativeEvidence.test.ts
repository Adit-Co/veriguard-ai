import { describe, expect, it } from 'vitest'
import { PROVIDER_ADAPTERS } from '../src/scanners/providers/index.js'
import { googleSafeBrowsingAdapter } from '../src/scanners/providers/safebrowsing.js'
import { radarAdapter } from '../src/scanners/providers/radar.js'
import { urlScanAdapter } from '../src/scanners/providers/urlscan.js'
import { virusTotalAdapter } from '../src/scanners/providers/virustotal.js'
import { runMultiSourceScan } from '../src/scanners/service.js'
import type { ProviderCheck, ProviderContext, ScannerConfig } from '../src/scanners/types.js'

// VGL-31 TAHAP 2/5 — aturan kredibilitas bukti negatif per provider.
//
// Uji ini mengikat perilaku NYATA adapter ke keputusan pemilik:
//   1. VirusTotal: negatif EKSPLISIT bila >=20 mesin memberi hasil, 0 malicious, 0 suspicious,
//      tanpa mesin yang gagal (VGL-32B: laporan lengkap = pernyataan agregat provider;
//      pembedaan harmless/undetected tidak lagi menurunkan kekuatan bukti).
//   2. Google Safe Browsing: negatif terbatas bila lookup berhasil dan daftar ancaman kosong.
//   3. URLScan: skor 0 / tanpa klasifikasi TIDAK otomatis confirmed_clean; provider harus
//      benar-benar menyatakan skor dan klasifikasinya.
//   4. Cloudflare Radar: ketiadaan kategori ancaman bukan confirmed_clean; perlu vonis negatif
//      eksplisit dengan cakupan yang jelas.
//   5. OpenPhish dan ThreatFox: no_match tetap no_match (keduanya feed indikator).
//   6. AlienVault OTX dan Hybrid: penyebutan komunitas/pulse/tanpa laporan bukan bukti negatif.
//   7. timeout, gagal, invalid_request, rate_limited, unavailable tidak pernah negatif.
// Semua fixture memakai fetchImpl tiruan: tidak ada permintaan nyata, tidak ada kunci API nyata.

const NOW_MS = 1_700_000_000_000
const TARGET_URL = 'https://translate.google.co.id/'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function textResponse(body: string, status = 200): Response {
  return new Response(body, { status, headers: { 'Content-Type': 'text/plain' } })
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

function contextFor(url: string, fetchImpl: typeof fetch): ProviderContext {
  return {
    url,
    hostname: new URL(url).hostname,
    fetchImpl,
    now: () => NOW_MS,
    sleep: async () => undefined,
  }
}

function fetchFor(routes: (url: string) => Response | null) {
  return (async (input: unknown, init?: RequestInit) => {
    const url = String(input)
    const response = routes(url, init)
    if (response) return response
    throw new Error(`Fixture tidak menyiapkan rute: ${url}`)
  }) as unknown as typeof fetch
}

const URLSCAN_CLEAN = {
  verdicts: {
    overall: { score: 0, malicious: false, categories: [], tags: [] },
    engines: { malicious: false, maliciousTotal: 0 },
  },
}

const RADAR_CLEAN = {
  task: { status: 'finished' },
  verdicts: {
    overall: { malicious: false, hasVerdicts: true, categories: ['search-engine'], tags: [] },
  },
}

function vtStats(overrides: Record<string, number> = {}) {
  return {
    data: {
      attributes: {
        last_analysis_date: Math.floor(NOW_MS / 1000) - 60,
        last_analysis_stats: {
          malicious: 0,
          suspicious: 0,
          harmless: 20,
          undetected: 0,
          ...overrides,
        },
      },
    },
  }
}

async function checkWith(
  adapterId: string,
  routes: (url: string) => Response | null,
  url = TARGET_URL,
): Promise<ProviderCheck> {
  const adapter = PROVIDER_ADAPTERS.find((row) => row.id === adapterId)
  if (!adapter) throw new Error(`Adapter ${adapterId} tidak ditemukan`)
  return adapter.check(contextFor(url, fetchFor(routes)), makeConfig())
}

describe('VGL-31 aturan 3 — URLScan hanya mengeksplisitkan bukti bila provider menyatakannya', () => {
  const scanRoutes = (result: unknown) =>
    fetchFor((url) => {
      if (url.includes('urlscan.io/api/v1/search')) return jsonResponse({ results: [] })
      if (url.includes('urlscan.io/api/v1/scan')) {
        return jsonResponse({ uuid: '11111111-1111-1111-1111-111111111111' })
      }
      if (url.includes('urlscan.io/api/v1/result')) return jsonResponse(result)
      return null
    })

  it('vonis selesai dengan skor dan klasifikasi eksplisit -> bukti negatif eksplisit', async () => {
    const check = await urlScanAdapter.check(
      contextFor(TARGET_URL, scanRoutes(URLSCAN_CLEAN)),
      makeConfig(),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('clean')
    expect(check.negative).toMatchObject({ strength: 'explicit', scope: 'url', evidenceClass: 'scan_verdict' })
  })

  it('respons tanpa field skor tidak boleh dinaikan menjadi bersih', async () => {
    const check = await urlScanAdapter.check(
      contextFor(
        TARGET_URL,
        scanRoutes({ verdicts: { overall: { malicious: false, categories: [] }, engines: {} } }),
      ),
      makeConfig(),
    )

    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.negative).toBeUndefined()
  })

  it('respons tanpa daftar klasifikasi tidak boleh dibaca "tidak ada kategori = aman"', async () => {
    const check = await urlScanAdapter.check(
      contextFor(TARGET_URL, scanRoutes({ verdicts: { overall: { score: 0, malicious: false } } })),
      makeConfig(),
    )

    expect(check.verdict).toBe('inconclusive')
    expect(check.negative).toBeUndefined()
  })

  it('bendera malicious tidak pernah membawa bukti negatif', async () => {
    const check = await urlScanAdapter.check(
      contextFor(
        TARGET_URL,
        scanRoutes({
          verdicts: { overall: { score: 100, malicious: true, categories: ['phishing'] }, engines: {} },
        }),
      ),
      makeConfig(),
    )

    expect(check.verdict).toBe('malicious')
    expect(check.negative).toBeUndefined()
  })
})

describe('VGL-31 aturan 1 + VGL-32B — laporan lengkap VirusTotal adalah vonis agregat provider', () => {
  const vtRoutes = (body: unknown) =>
    fetchFor((url) => (url.includes('virustotal.com') ? jsonResponse(body) : null))

  it('20 mesin melapor, 0 ditandai, semuanya memilih harmless -> eksplisit', async () => {
    const check = await virusTotalAdapter.check(contextFor(TARGET_URL, vtRoutes(vtStats())), makeConfig())

    expect(check.verdict).toBe('clean')
    expect(check.negative?.strength).toBe('explicit')
    expect(check.negative?.evidenceClass).toBe('engine_verdicts')
  })

  it('20 mesin hanya tidak menandai (undetected) -> tetap eksplisit: laporan lengkap tanpa kegagalan', async () => {
    const check = await virusTotalAdapter.check(
      contextFor(TARGET_URL, vtRoutes(vtStats({ harmless: 0, undetected: 25 }))),
      makeConfig(),
    )

    expect(check.verdict).toBe('clean')
    expect(check.negative?.strength).toBe('explicit')
    expect(check.negative?.basis).toContain('tidak menemukan tanda')
  })

  // Mesin yang gagal tidak dihitung sebagai engine yang "melaporkan hasil", jadi fixture ini
  // memakai 20 harmless + 4 failure: ambang 20 mesin terpenuhi, tetapi ada mesin yang bisu.
  it('ada mesin yang gagal -> rasio 0 tidak diberi bukti negatif sama sekali', async () => {
    const check = await virusTotalAdapter.check(
      contextFor(TARGET_URL, vtRoutes(vtStats({ failure: 4 }))),
      makeConfig(),
    )

    expect(check.verdict).toBe('clean')
    expect(check.negative).toBeUndefined()
    expect(check.reason).toContain('tidak memberikan hasil')
  })

  it('ada mesin yang timeout -> sama sekali tidak ada bukti negatif', async () => {
    const check = await virusTotalAdapter.check(
      contextFor(TARGET_URL, vtRoutes(vtStats({ timeout: 2 }))),
      makeConfig(),
    )

    expect(check.negative).toBeUndefined()
    expect(check.reason).toContain('tidak memberikan hasil')
  })

  it('laporan baru 3 mesin tetap inconclusive dan tanpa bukti', async () => {
    const check = await virusTotalAdapter.check(
      contextFor(TARGET_URL, vtRoutes(vtStats({ harmless: 1, undetected: 2 }))),
      makeConfig(),
    )

    expect(check.verdict).toBe('inconclusive')
    expect(check.negative).toBeUndefined()
  })
})

describe('VGL-31 aturan 4 — Radar butuh vonis negatif dengan cakupan yang jelas', () => {
  const radarRoutes = (body: unknown) =>
    fetchFor((url) => {
      if (!url.includes('api.cloudflare.com')) return null
      if (url.includes('/urlscanner/v2/search')) return jsonResponse({ results: [] })
      if (url.endsWith('/urlscanner/v2/scan')) {
        return jsonResponse({ success: true, result: { uuid: '11111111-1111-4111-8111-111111111111' } })
      }
      return jsonResponse(body)
    })

  it('vonis dengan kategori konten yang dikenali -> eksplisit', async () => {
    const check = await radarAdapter.check(contextFor(TARGET_URL, radarRoutes(RADAR_CLEAN)), makeConfig())

    expect(check.verdict).toBe('clean')
    expect(check.negative?.strength).toBe('explicit')
    expect(check.negative?.evidenceClass).toBe('scanner_verdict')
  })

  it('hasVerdicts tanpa satu kategori pun -> hanya bukti terbatas', async () => {
    const check = await radarAdapter.check(
      contextFor(
        TARGET_URL,
        radarRoutes({
          task: { status: 'finished' },
          verdicts: { overall: { malicious: false, hasVerdicts: true, categories: [], tags: [] } },
        }),
      ),
      makeConfig(),
    )

    expect(check.verdict).toBe('clean')
    expect(check.negative?.strength).toBe('limited')
  })

  it('pemindaian selesai tanpa vonis -> tidak ada bukti negatif', async () => {
    const check = await radarAdapter.check(
      contextFor(
        TARGET_URL,
        radarRoutes({
          task: { status: 'finished' },
          verdicts: { overall: { malicious: false, hasVerdicts: false, categories: [], tags: [] } },
        }),
      ),
      makeConfig(),
    )

    expect(check.verdict).toBe('inconclusive')
    expect(check.negative).toBeUndefined()
  })
})

describe('VGL-31 aturan 2 — Safe Browsing: daftar kosong adalah jawaban, bukan vonis', () => {
  it('threats kosong -> tetap not_found dengan bukti negatif terbatas', async () => {
    const check = await googleSafeBrowsingAdapter.check(
      contextFor(TARGET_URL, fetchFor((url) => (url.includes('safebrowsing.googleapis.com') ? jsonResponse({ threats: [] }) : null))),
      makeConfig(),
    )

    expect(check.status).toBe('not_found')
    expect(check.verdict).toBe('inconclusive')
    expect(check.negative).toMatchObject({
      strength: 'limited',
      scope: 'url',
      evidenceClass: 'threat_list',
    })
    // `no_match` tidak pernah berubah menjadi confirmed_clean: status dan vonis tetap seperti
    // adanya, hanya penanda cakupannya yang bertambah.
    expect(check.reason).toContain('BUKAN konfirmasi')
  })

  it('ancaman yang benar-benar cocok -> tanpa bukti negatif', async () => {
    const check = await googleSafeBrowsingAdapter.check(
      contextFor(
        TARGET_URL,
        fetchFor((url) =>
          url.includes('safebrowsing.googleapis.com')
            ? jsonResponse({ threats: [{ threatTypes: ['MALWARE'] }] })
            : null,
        ),
      ),
      makeConfig(),
    )

    expect(check.verdict).toBe('malicious')
    expect(check.negative).toBeUndefined()
  })
})

describe('VGL-31 aturan 5-7 — feed, komunitas, dan kegagalan tidak pernah membawa bukti', () => {
  it('roster penuh: hanya agen yang dizinkan yang mengirim penanda', async () => {
    const result = await runMultiSourceScan({
      uid: 'user-vgl31',
      url: TARGET_URL,
      config: makeConfig(),
      fetchImpl: fetchFor((url) => {
        if (url.includes('urlscan.io/api/v1/search')) return jsonResponse({ results: [] })
        if (url.includes('urlscan.io/api/v1/scan')) {
          return jsonResponse({ uuid: '11111111-1111-1111-1111-111111111111' })
        }
        if (url.includes('urlscan.io/api/v1/result')) return jsonResponse(URLSCAN_CLEAN)
        if (url.includes('virustotal.com')) return jsonResponse(vtStats())
        if (url.includes('safebrowsing.googleapis.com')) return jsonResponse({ threats: [] })
        if (url.includes('threatfox-api')) return jsonResponse({ query_status: 'no_result' })
        if (url.includes('otx.alienvault.com')) return jsonResponse({ pulse_info: { count: 0, pulses: [] } })
        if (url.includes('urlscan.io')) return jsonResponse({})
        if (url.includes('analysis0.totalgrid.com') || url.includes('hybrid-analysis')) {
          return jsonResponse({ data: [] })
        }
        if (url.startsWith('https://openphish.eu') || url.includes('openphish')) {
          return url.includes('feed') ? textResponse('') : jsonResponse({ results: [] })
        }
        if (url.includes('api.cloudflare.com')) {
          if (url.includes('/urlscanner/v2/search')) return jsonResponse({ results: [] })
          if (url.endsWith('/urlscanner/v2/scan')) {
            return jsonResponse({ success: true, result: { uuid: '11111111-1111-4111-8111-111111111111' } })
          }
          return jsonResponse(RADAR_CLEAN)
        }
        return null
      }),
      now: () => NOW_MS,
      sleep: async () => undefined,
    })

    const byId = new Map(result.providers.map((provider) => [provider.id, provider]))

    expect(byId.get('urlscan')?.negative?.strength).toBe('explicit')
    expect(byId.get('radar')?.negative?.strength).toBe('explicit')
    expect(byId.get('virustotal')?.negative?.strength).toBe('explicit')
    expect(byId.get('safebrowsing')?.negative?.strength).toBe('limited')
    expect(byId.get('safebrowsing')?.status).toBe('not_found')

    for (const id of ['openphish', 'threatfox', 'otx', 'hybrid']) {
      expect(byId.get(id as 'openphish')?.negative, `${id} tidak boleh membawa bukti negatif`).toBeUndefined()
    }
  })

  it('setiap status kegagalan tetap tanpa bukti negatif', async () => {
    const failures: Array<{ label: string; response: () => Response }> = [
      { label: 'auth_failed', response: () => jsonResponse({ error: 'key' }, 403) },
      { label: 'rate_limited', response: () => jsonResponse({ error: 'limit' }, 429) },
      { label: 'unavailable', response: () => jsonResponse({ error: 'down' }, 503) },
      { label: 'invalid_request', response: () => jsonResponse({ error: 'bad' }, 400) },
    ]

    for (const failure of failures) {
      const check = await checkWith('virustotal', () => failure.response())
      expect(check.status, failure.label).toBe(failure.label)
      expect(check.negative, failure.label).toBeUndefined()
    }

    const thrown = await checkWith('virustotal', () => null)
    expect(thrown.negative).toBeUndefined()
  })
})

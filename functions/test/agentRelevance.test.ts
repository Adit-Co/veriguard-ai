import { beforeEach, describe, expect, it, vi } from 'vitest'
import { hybridAnalysisAdapter } from '../src/scanners/providers/hybrid.js'
import { otxAdapter } from '../src/scanners/providers/otx.js'
import { PROVIDER_ADAPTERS } from '../src/scanners/providers/index.js'
import { runMultiSourceScan } from '../src/scanners/service.js'
import { resetScanState } from './helpers/scanState.js'
import { forbiddenNarrativeHits, providerCheckText } from './helpers/narrative.js'
import type { ProviderCheck, ProviderContext, ScannerConfig } from '../src/scanners/types.js'

// VGL-30K: regressi untuk dua mekanik false positive yang terbukti pada sumber kode dan dilaporkan
// pengguna (instagram ~40% risiko, website resmi mendapat indikasi malware dari Agen 7). Semua
// fixture memakai fetchImpl tiruan: tidak ada permintaan nyata ke provider dan tidak ada kunci API
// yang dipakai.

const NOW_MS = 1_700_000_000_000

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

function narrativeClean(check: ProviderCheck): boolean {
  return forbiddenNarrativeHits(providerCheckText(check)).length === 0
}

const INSTAGRAM_URL = 'https://www.instagram.com/'
const BCA_URL = 'https://www.bca.co.id/'

// 31 pulse komunitas dengan tag/nama yang tidak relevan dengan target; tidak ada satu pun
// keluarga malware. Bentuknya menandai gejala yang dilaporkan: Agen 6 menyebut puluhan pulse.
function irrelevantPulses(count: number) {
  const tags = ['phishing', 'malware', 'botnet', 'ransomware', 'spam', 'ddos']
  return Array.from({ length: count }, (_unused, index) => ({
    name: ` Laporan komunitas ${index + 1}`,
    tags: [tags[index % tags.length]],
    malware_families: [],
  }))
}

function otxFetch(handlers: { url?: unknown; domain?: unknown; indicators?: unknown }) {
  return vi.fn(async (input: string | URL | Request) => {
    const url = String(input)
    if (url.includes('/pulses/')) {
      return jsonResponse(handlers.indicators ?? { results: [], next: null })
    }
    if (url.includes('/indicators/domain/')) {
      return jsonResponse(handlers.domain ?? { pulse_info: { count: 0, pulses: [] } })
    }
    return jsonResponse(handlers.url ?? { pulse_info: { count: 0, pulses: [] } })
  })
}

describe('VGL-30K P5: penyebutan domain OTX bukan risiko pada tingkat URL', () => {
  it('hanya menyebut domain tanpa keluarga malware menjadi inconclusive tanpa skor', async () => {
    const fetchMock = otxFetch({
      url: { pulse_info: { count: 0, pulses: [] } },
      domain: { pulse_info: { count: 31, pulses: irrelevantPulses(31) } },
    })

    const check = await otxAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    // Bukti tetap ditampilkan, hanya tidak lagi dinilai sebagai risiko.
    expect(check.summary).toContain('31 pulse komunitas')
    expect(check.signals.some((signal) => signal.detail.includes('31 pulse'))).toBe(true)
    expect(check.signals.some((signal) => signal.label === 'Tag pulse')).toBe(true)
    expect(check.signals.every((signal) => signal.severity === 'info')).toBe(true)
    expect(check.reason).toContain('bukan konfirmasi ancaman')
    expect(narrativeClean(check)).toBe(true)
    expect(JSON.stringify(check)).not.toContain('otx-key')
  })

  it('domain dengan indikator terbukti pada pulse berkeluarga malware tetap suspicious 55', async () => {
    const fetchMock = otxFetch({
      url: { pulse_info: { count: 0, pulses: [] } },
      domain: {
        pulse_info: {
          count: 4,
          pulses: [
            {
              id: 'pulse-asyncrat',
              name: 'Infra AsyncRAT',
              tags: ['botnet'],
              malware_families: ['AsyncRAT'],
              indicator_count: 7,
            },
          ],
        },
      },
      indicators: { results: [{ indicator: 'www.bca.co.id', type: 'domain' }], next: null },
    })

    const check = await otxAdapter.check(
      contextFor(BCA_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    // Permintaan keempat adalah konfirmasi indikator pulse, bukan asumsi dari rute /general.
    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(check.verdict).toBe('suspicious')
    expect(check.score).toBe(55)
    expect(check.reason).toContain('bukan URL persis')
    // Bukti tingkat domain bukan konfirmasi ancaman: severity tidak boleh naik ke danger.
    expect(check.signals.every((signal) => signal.severity !== 'danger')).toBe(true)
    expect(narrativeClean(check)).toBe(true)
  })

  it('kontrol: penyebutan URL persis tanpa indikator terbukti menjadi intelijen komunitas', async () => {
    // Bentuk yang sebelumnya menaikkan vonis hanya karena pulse menyebut URL; target tidak ada
    // di daftar indikator pulse sehingga tidak ada dasar ancaman.
    const fetchMock = otxFetch({
      url: {
        pulse_info: {
          count: 2,
          pulses: [
            {
              id: 'pulse-phish',
              name: 'Kampanye phishing',
              tags: ['phishing'],
              malware_families: [],
              indicator_count: 12,
            },
          ],
        },
      },
      indicators: { results: [{ indicator: 'https://target-lain.example/accounts/login', type: 'url' }], next: null },
    })

    const check = await otxAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.signals.every((signal) => signal.severity === 'info')).toBe(true)
    expect(narrativeClean(check)).toBe(true)
  })

  it('kontrol: penyebutan URL persis tetap suspicious 45 ketika indikator pulse memuat URL ini', async () => {
    const fetchMock = otxFetch({
      url: {
        pulse_info: {
          count: 2,
          pulses: [
            {
              id: 'pulse-phish',
              name: 'Kampanye phishing',
              tags: ['phishing'],
              malware_families: [],
              indicator_count: 12,
            },
          ],
        },
      },
      indicators: { results: [{ indicator: 'https://www.instagram.com/', type: 'url' }], next: null },
    })

    const check = await otxAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    // Cocok pada indikator URL persis: tetap diperlakukan mencurigakan, tidak dilonggarkan.
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(check.verdict).toBe('suspicious')
    expect(check.score).toBe(45)
    expect(check.summary).toContain('bukan konfirmasi ancaman')
  })

  it('kontrol: keluarga malware pada indikator URL persis tetap malicious 70', async () => {
    const fetchMock = otxFetch({
      url: {
        pulse_info: {
          count: 1,
          pulses: [
            {
              id: 'pulse-asyncrat-url',
              name: 'Phishing AsyncRAT',
              tags: [],
              malware_families: ['AsyncRAT'],
              indicator_count: 5,
            },
          ],
        },
      },
      indicators: { results: [{ indicator: 'https://www.instagram.com/', type: 'url' }], next: null },
    })

    const check = await otxAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.verdict).toBe('malicious')
    expect(check.score).toBe(70)
  })

  it('pulse daftar indikator massal tidak menaikkan vonis dan tidak dikirimi permintaan', async () => {
    const fetchMock = otxFetch({
      url: {
        pulse_info: {
          count: 1,
          pulses: [
            {
              id: 'pulse-blocklist',
              name: 'Blocklist gabungan',
              tags: ['phishing'],
              malware_families: ['AsyncRAT'],
              indicator_count: 25_000,
            },
          ],
        },
      },
      indicators: { results: [{ indicator: 'https://www.instagram.com/', type: 'url' }], next: null },
    })

    const check = await otxAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(narrativeClean(check)).toBe(true)
  })
})

// Router Hybrid Analysis: kedua pencarian memakai endpoint yang sama dan dibedakan dari body.
function hybridFetch(responses: { url?: unknown; domain?: unknown }) {
  return vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
    const body = String(init?.body ?? '')
    const raw = body.startsWith('domain=') ? (responses.domain ?? []) : (responses.url ?? [])
    const payload = Array.isArray(raw) ? { count: raw.length, result: raw } : raw
    return jsonResponse(payload)
  })
}

function hybridDoc(input: {
  verdict: string
  hosts: string[]
  family?: string
  // `subject` = host yang tercatat sebagai subjek analisis (field `host`/`domain` pada laporan),
  // `exactUrl` = URL yang TERAMAT di dalam laporan persis alamat yang diperiksa.
  subject?: string
  exactUrl?: string
}) {
  const urls = input.hosts.map((host) => ({ url: `https://${host}/login` }))
  if (input.exactUrl) urls.push({ url: input.exactUrl })
  return {
    verdict: input.verdict,
    threat_score: input.verdict === 'malicious' ? 100 : 10,
    av_detect: 40,
    vx_family: input.family ? [input.family] : [],
    ...(input.subject ? { host: input.subject, domain: input.subject } : {}),
    url: urls,
    analysis_start_time: new Date(NOW_MS - 86_400_000).toISOString(),
  }
}

describe('VGL-30K P6: identitas host dokumen Hybrid Analysis pada tingkat domain', () => {
  it('laporan domain yang menunjuk host lain tidak menghasilkan vonis untuk URL ini', async () => {
    // Host terdaftar menumpang di bawah domain lain: lookalike, bukan bagian dari www.bca.co.id.
    const fetchMock = hybridFetch({
      url: [],
      domain: [hybridDoc({ verdict: 'malicious', hosts: ['www.bca.co.id.verify-secure.top'], family: 'Emotet' })],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(BCA_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.verdict).not.toBe('malicious')
    expect(check.verdict).not.toBe('suspicious')
    // Provider menjawab dengan data yang terurai, hanya datanya bukan bukti untuk alamat ini.
    expect(check.status).toBe('success')
    expect(check.score).toBeNull()
    // Bukti tidak dihapus: laporan host lain tetap muncul sebagai info.
    expect(check.signals.some((signal) => signal.detail.includes('verify-secure.top'))).toBe(true)
    expect(narrativeClean(check)).toBe(true)
    expect(JSON.stringify(check)).not.toContain('ha-key')
  })

  // VGL-30K-R4: Vonis sandbox hanya dipakai bila SUBJEK analisisnya alamat yang diperiksa. Laporan
  // pada host yang sama tetapi URL lain, laporan domain induk, dan laporan tanpa identitas adalah
  // intelijen berkaitan (Kategori B/C): ditampilkan, tanpa skor, tanpa kenaikan vonis.
  it('laporan URL lain pada host yang sama menjadi intelijen komunitas tanpa skor', async () => {
    const fetchMock = hybridFetch({
      url: [],
      domain: [hybridDoc({ verdict: 'malicious', hosts: ['www.bca.co.id'], family: 'Emotet' })],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(BCA_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.summary).toContain('tidak memiliki bukti')
    expect(check.signals.some((signal) => signal.label === 'Laporan terkait pada host ini')).toBe(true)
    expect(check.signals.every((signal) => signal.severity === 'info')).toBe(true)
    expect(narrativeClean(check)).toBe(true)
  })

  it('laporan pada domain induk tidak diwariskan sebagai vonis untuk host ini', async () => {
    const fetchMock = hybridFetch({
      url: [],
      domain: [hybridDoc({ verdict: 'malicious', hosts: ['bca.co.id'], family: 'Emotet' })],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(BCA_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    // bca.co.id adalah induk dari www.bca.co.id, namun laporan itu menganalisis URL di host
    // lain sehingga vonisnya tidak diwariskan ke alamat ini.
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(narrativeClean(check)).toBe(true)
  })

  it('vonis hanya dihitung dari dokumen yang subjeknya cocok', async () => {
    const fetchMock = hybridFetch({
      url: [],
      domain: [
        hybridDoc({ verdict: 'malicious', hosts: ['www.bca.co.id.verify-secure.top'], family: 'Emotet' }),
        hybridDoc({ verdict: 'suspicious', hosts: ['www.bca.co.id'], family: 'Phorpiex' }),
        hybridDoc({
          verdict: 'suspicious',
          hosts: [],
          family: 'Phorpiex',
          subject: 'www.bca.co.id',
          exactUrl: BCA_URL,
        }),
      ],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(BCA_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    // Dokumen lookalike dan dokumen URL lain tidak menyumbang band; hanya subjek persis yang
    // dibaca, dan band malicious dari dokumen asing tidak ikut naik.
    expect(check.verdict).toBe('suspicious')
    expect(check.score).toBe(55)
    expect(check.summary).toContain('verdict suspicious')
    expect(check.summary).not.toContain('verdict malicious')
    expect(check.evidence?.source).toBe('existing_report')
    // Laporan berkaitan tetap ikut ditampilkan pada vonis yang sama.
    expect(check.signals.some((signal) => signal.label === 'Laporan pada host lain')).toBe(true)
  })

  it('kontrol: vonis malicious pada URL persis tetap 85', async () => {
    const fetchMock = hybridFetch({
      url: [hybridDoc({ verdict: 'malicious', hosts: ['www.bca.co.id'], family: 'Emotet' })],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(BCA_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(check.verdict).toBe('malicious')
    expect(check.score).toBe(85)
  })

  it('kontrol: malware yang benar-benar dianalisis pada URL ini tetap detected walau laporan lain asing', async () => {
    const fetchMock = hybridFetch({
      url: [
        hybridDoc({
          verdict: 'malicious',
          hosts: [],
          family: 'Emotet',
          subject: 'www.bca.co.id',
          exactUrl: BCA_URL,
        }),
      ],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(BCA_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.verdict).toBe('malicious')
    expect(check.score).toBe(85)
  })

  it('kontrol: dokumen tanpa data identitas menjadi Kategori C, bukan vonis maupun bukti aman', async () => {
    const fetchMock = hybridFetch({
      url: [],
      domain: [{ verdict: 'malicious', analysis_start_time: new Date(NOW_MS - 86_400_000).toISOString() }],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(BCA_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.signals.some((signal) => signal.label === 'Identitas laporan')).toBe(true)
    expect(check.reason).toContain('bukan bukti situs aman')
  })

  it('kontrol: dokumen clean pada host yang sama tidak dinyatakan sebagai vonis bersih untuk URL ini', async () => {
    // Cermin dari false positive yang diperbaiki: laporan "whitelisted" pada URL lain juga bukan
    // bukti aman untuk alamat yang diperiksa, jadi tidak pernah menurunkan laporan menjadi clean.
    const fetchMock = hybridFetch({
      url: [],
      domain: [hybridDoc({ verdict: 'whitelisted', hosts: ['www.bca.co.id'] })],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(BCA_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
  })

  it('kontrol: dokumen clean pada URL persis tetap clean', async () => {
    const fetchMock = hybridFetch({
      url: [hybridDoc({ verdict: 'whitelisted', hosts: ['www.bca.co.id'], exactUrl: BCA_URL })],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(BCA_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.status).toBe('success')
    expect(check.verdict).toBe('clean')
    expect(check.score).toBe(10)
  })
})

// Cakupan (TAHAP 5): perbaikan klasifikasi bukti tidak boleh membuat satu agen pun berhenti
// dipanggil, dan kegagalan provider tidak boleh terbaca sebagai situs aman.
describe('VGL-30K cakupan: delapan agen tetap berjalan dan galat tidak menjadi clean', () => {
  const FULL_CONFIG = makeConfig({
    urlscanApiKey: 'urlscan-key',
    virusTotalApiKey: 'vt-key',
    openPhishApiKey: 'openphish-key',
    threatFoxApiKey: 'threatfox-key',
    cloudflareApiToken: 'cf-token',
    cloudflareAccountId: 'cf-account',
    otxApiKey: 'otx-key',
    googleSafeBrowsingApiKey: 'gsb-key',
    hybridAnalysisApiKey: 'ha-key',
  })

  it('registry tetap berisi delapan agen dengan urutan penomoran yang sama', () => {
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
  })

  it('setiap agen tetap menyentuh provider dan memfail-closed saat HTTP 500', async () => {
    for (const adapter of PROVIDER_ADAPTERS) {
      const fetchMock = vi.fn(async () => jsonResponse({ error: 'server error' }, 500))
      const check = await adapter.check(
        contextFor(BCA_URL, fetchMock as unknown as typeof fetch),
        FULL_CONFIG,
      )

      expect(fetchMock.mock.calls.length, `${adapter.id}: permintaan`).toBeGreaterThan(0)
      expect(check.verdict, `${adapter.id}: vonis`).toBe('inconclusive')
      expect(check.score, `${adapter.id}: skor`).toBeNull()
      expect(check.status, `${adapter.id}: status`).not.toBe('success')
      expect(check.status, `${adapter.id}: status`).not.toBe('not_configured')
      expect(check.status, `${adapter.id}: status`).not.toBe('clean')
      expect(JSON.stringify(check), `${adapter.id}: kunci`).not.toContain('ha-key')
    }
  })

  it('setiap agen memfail-closed ketika permintaan lempar galat jaringan', async () => {
    for (const adapter of PROVIDER_ADAPTERS) {
      const fetchMock = vi.fn(async () => {
        throw new TypeError('fetch failed')
      })
      const check = await adapter.check(
        contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
        FULL_CONFIG,
      )

      expect(check.verdict, `${adapter.id}: vonis`).toBe('inconclusive')
      expect(check.score, `${adapter.id}: skor`).toBeNull()
      expect(check.signals, `${adapter.id}: sinyal`).toHaveLength(0)
    }
  })
})

// Reproduksi end-to-end gejala pengguna pada roster nyata (PROVIDER_ADAPTERS + service), bukan
// hanya pada satu adapter: permintaan yang sama dengan jawaban provider yang dilaporkan.
describe('VGL-30K reproduksi end-to-end: instagram dan bca pada roster nyata', () => {
  beforeEach(() => {
    resetScanState()
  })

  function officialSiteFetch(onCall: (url: string, body: string) => void) {
    return vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input)
      const body = String(init?.body ?? '')
      onCall(url, body)

      if (url.includes('raw.githubusercontent.com')) return textResponse('https://phish.example/login\n')
      if (url.includes('/indicators/url/')) return jsonResponse({ pulse_info: { count: 0, pulses: [] } })
      if (url.includes('/indicators/domain/')) {
        return jsonResponse({ pulse_info: { count: 31, pulses: irrelevantPulses(31) } })
      }
      if (url.includes('/api/v2/search/terms')) {
        // Pencarian URL persis kosong; pencarian domain mengembalikan laporan lookalike.
        if (body.startsWith('domain=')) {
          return jsonResponse({
            count: 1,
            result: [hybridDoc({ verdict: 'malicious', hosts: ['www.bca.co.id.verify-secure.top'], family: 'Emotet' })],
          })
        }
        return jsonResponse({ count: 0, result: [] })
      }
      throw new Error(`Permintaan keluar tak terduga: ${url}`)
    })
  }

  async function runOfficial(url: string) {
    const calls: Array<{ url: string; body: string }> = []
    const response = await runMultiSourceScan({
      uid: 'vgl-30k',
      url,
      config: makeConfig({ otxApiKey: 'otx-key', hybridAnalysisApiKey: 'ha-key' }),
      adapters: PROVIDER_ADAPTERS,
      fetchImpl: officialSiteFetch((called, body) => calls.push({ url: called, body })) as unknown as typeof fetch,
      now: () => NOW_MS,
    })
    return { response, calls }
  }

  it('penyebutan komunitas OTX tidak lagi menjadi risiko pada pemeriksaan instagram', async () => {
    const { response, calls } = await runOfficial(INSTAGRAM_URL)
    const byId = new Map(response.providers.map((provider) => [provider.id, provider]))

    // Delapan agen tetap ada pada hasil dan agen yang terpasang benar-benar dipanggil.
    expect(response.providers.map((provider) => provider.id)).toEqual([
      'urlscan',
      'virustotal',
      'openphish',
      'threatfox',
      'radar',
      'otx',
      'hybrid',
      'safebrowsing',
    ])
    expect(calls.some((call) => call.url.includes('/indicators/domain/www.instagram.com'))).toBe(true)

    const otx = byId.get('otx')
    expect(otx?.status).toBe('success')
    expect(otx?.verdict).toBe('inconclusive')
    expect(otx?.score).toBeNull()
    expect(otx?.signals.some((signal) => signal.detail.includes('31 pulse'))).toBe(true)

    // Tidak satu pun agen menaikkan risiko; maksimum skor agen adalah kosong.
    expect(response.providers.every((provider) => provider.verdict !== 'suspicious')).toBe(true)
    expect(response.providers.every((provider) => provider.verdict !== 'malicious')).toBe(true)
    expect(response.providers.every((provider) => provider.score === null || provider.score === 0)).toBe(true)
  })

  it('laporan host lain pada domain tidak lagi menjadi risiko pada pemeriksaan bca', async () => {
    const { response, calls } = await runOfficial(BCA_URL)
    const byId = new Map(response.providers.map((provider) => [provider.id, provider]))

    expect(calls.some((call) => call.body.startsWith('domain=www.bca.co.id'))).toBe(true)

    const hybrid = byId.get('hybrid')
    expect(hybrid?.status).toBe('success')
    expect(hybrid?.verdict).toBe('inconclusive')
    expect(hybrid?.score).toBeNull()
    expect(hybrid?.signals.some((signal) => signal.detail.includes('verify-secure.top'))).toBe(true)

    const otx = byId.get('otx')
    expect(otx?.verdict).toBe('inconclusive')
    expect(otx?.score).toBeNull()

    expect(response.providers.every((provider) => provider.verdict !== 'suspicious')).toBe(true)
    expect(response.providers.every((provider) => provider.verdict !== 'malicious')).toBe(true)
  })

  it('kontrol cakupan: feed OpenPhish dan indikator OTX tetap diminta walau hasilnya nol', async () => {
    const { response, calls } = await runOfficial(INSTAGRAM_URL)
    const byId = new Map(response.providers.map((provider) => [provider.id, provider]))

    expect(calls.some((call) => call.url.includes('raw.githubusercontent.com'))).toBe(true)
    expect(byId.get('openphish')?.status).toBe('not_found')
    expect(byId.get('openphish')?.verdict).toBe('inconclusive')
    // Agen tanpa kunci tetap berjalan penuh sebagai not_configured, bukan hilang dari hasil.
    expect(byId.get('threatfox')?.status).toBe('not_configured')
  })
})

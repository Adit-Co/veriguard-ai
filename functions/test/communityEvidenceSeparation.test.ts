import { beforeEach, describe, expect, it, vi } from 'vitest'
import { hybridAnalysisAdapter } from '../src/scanners/providers/hybrid.js'
import { otxAdapter } from '../src/scanners/providers/otx.js'
import { PROVIDER_ADAPTERS } from '../src/scanners/providers/index.js'
import { runMultiSourceScan } from '../src/scanners/service.js'
import { resetScanState } from './helpers/scanState.js'
import { forbiddenNarrativeHits, providerCheckText } from './helpers/narrative.js'
import type { ProviderCheck, ProviderContext, ScannerConfig } from '../src/scanners/types.js'

// VGL-30K-R4: pemisahan bukti komunitas (Agen 6 AlienVault OTX, Agen 7 Hybrid Analysis) dari
// vonis. Kelas bukti yang dipakai:
//   A = target yang diperiksa terbukti menjadi subjek bukti + konteks ancaman valid  -> boleh menilai
//   B = intelijen komunitas (penyebutan pulse / laporan URL lain pada host ini)       -> tanpa skor
//   C = bukti tanpa identitas target                                                  -> inconclusive, bukan aman
// Semua fixture memakai fetchImpl tiruan: tidak ada permintaan nyata ke provider, tidak ada kunci
// API yang dipakai, dan tidak ada laporan produksi yang dibaca.

const NOW_MS = 1_700_000_000_000
const GOOGLE_URL = 'https://accounts.google.com/'
const GOOGLE_HOST = 'accounts.google.com'
const INSTAGRAM_URL = 'https://www.instagram.com/'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function textResponse(body: string, status = 200): Response {
  return new Response(body, { status, headers: { 'Content-Type': 'text/plain' } })
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

function contextFor(url: string, fetchImpl: typeof fetch, hostname = new URL(url).hostname): ProviderContext {
  return { url, hostname, fetchImpl, now: () => NOW_MS, sleep: async () => undefined }
}

function narrativeClean(check: ProviderCheck): boolean {
  return forbiddenNarrativeHits(providerCheckText(check)).length === 0
}

// Kategori B WAJIB dinyatakan sebagai nol kontribusi: verdict `inconclusive` DAN `score` null.
// Satu-satunya jalur teks sinyal (severity) tidak punya jalan ke skor, jadi bentuk inilah yang
// dijaga; helper ini dipakai di semua kasus B agar buktinya eksplisit, bukan implisit.
function expectZeroContribution(check: ProviderCheck): void {
  expect(check.verdict).toBe('inconclusive')
  expect(check.score).toBeNull()
  expect(check.signals.every((signal) => signal.severity === 'info')).toBe(true)
  expect(narrativeClean(check)).toBe(true)
}

type OtxPulse = {
  id?: string
  name?: string
  tags?: string[]
  malware_families?: string[]
  indicator_count?: number
}

// Agen 6: rute indikator (URL/domain) dan rute konfirmasi indikator pulse dipisah supaya fixture
// bisa menyatakan "pulse menyebut target" TANPA menyatakan "target ada di daftar indikator pulse".
function otxFetch(input: {
  urlPulses?: OtxPulse[]
  domainPulses?: OtxPulse[]
  indicators?: Array<{ indicator: string; type: string }> | null
  pulseStatus?: number
}) {
  const pulses = (list: OtxPulse[]) => ({ pulse_info: { count: list.length, pulses: list } })
  return vi.fn(async (request: string | URL | Request) => {
    const url = String(request)
    if (url.includes('/pulses/')) {
      if (input.pulseStatus && input.pulseStatus !== 200) {
        return jsonResponse({ detail: 'permintaan gagal' }, input.pulseStatus)
      }
      return jsonResponse({ results: input.indicators ?? [], next: null })
    }
    if (url.includes('/indicators/domain/')) {
      return jsonResponse(pulses(input.domainPulses ?? []))
    }
    return jsonResponse(pulses(input.urlPulses ?? []))
  })
}

function hybridFetch(routes: { url?: unknown[]; domain?: unknown[]; status?: number }) {
  return vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
    if (routes.status && routes.status !== 200) return jsonResponse({ detail: 'gagal' }, routes.status)
    const body = String(init?.body ?? '')
    const docs = body.startsWith('domain=') ? (routes.domain ?? []) : (routes.url ?? [])
    return jsonResponse({ count: docs.length, result: docs })
  })
}

function hybridReport(input: {
  verdict: string
  subject?: string
  observedUrls?: string[]
  family?: string
}) {
  return {
    verdict: input.verdict,
    threat_score: input.verdict === 'malicious' ? 100 : 10,
    av_detect: 40,
    vx_family: input.family ? [input.family] : [],
    ...(input.subject ? { host: input.subject, domain: input.subject } : {}),
    url: (input.observedUrls ?? []).map((url) => ({ url })),
    analysis_start_time: new Date(NOW_MS - 86_400_000).toISOString(),
  }
}

describe('VGL-30K-R4 Kategori B: intelijen komunitas tidak menyumbang skor (Agen 6)', () => {
  it('situs resmi dengan puluhan pulse komunitas tetap tanpa vonis dan tanpa skor', async () => {
    const pulses: OtxPulse[] = Array.from({ length: 40 }, (_unused, index) => ({
      id: `pulse-${index}`,
      name: `Pulse komunitas ${index}`,
      tags: ['phishing', 'botnet'],
      malware_families: [],
      indicator_count: 10,
    }))
    const fetchMock = otxFetch({ urlPulses: [], domainPulses: pulses })

    const check = await otxAdapter.check(
      contextFor(GOOGLE_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.status).toBe('success')
    expectZeroContribution(check)
    expect(check.reason).toContain('bukan konfirmasi ancaman')
    // Data tetap ditampilkan: jumlah pulse, tag, dan nama pulse tidak dihapus.
    expect(check.signals.some((signal) => signal.detail.includes('40 pulse'))).toBe(true)
    expect(check.signals.some((signal) => signal.label === 'Tag pulse')).toBe(true)
    expect(check.signals.some((signal) => signal.label === 'Nama pulse')).toBe(true)
    expect(JSON.stringify(check)).not.toContain('otx-key')
  })

  it('pulse besar (daftar blokir / multi-brand) tidak menaikkan vonis dan tidak diminta', async () => {
    const pulses: OtxPulse[] = Array.from({ length: 6 }, (_unused, index) => ({
      id: `blocklist-${index}`,
      name: 'Daftar blokir gabungan lintas merek',
      tags: ['phishing'],
      malware_families: ['AsyncRAT'],
      indicator_count: 250_000,
    }))
    const fetchMock = otxFetch({
      urlPulses: pulses,
      // Seandainya permintaan konfirmasi tetap dikirim, target akan "cocok". Fixture ini
      // membuktikan bahwa kecocokan di dalam daftar massal tidak pernah diminta maupun dipercaya.
      indicators: [{ indicator: GOOGLE_URL, type: 'url' }],
    })

    const check = await otxAdapter.check(
      contextFor(GOOGLE_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(
      check.signals.some((signal) => signal.detail.includes('lebih dari 50 indikator')),
    ).toBe(true)
  })

  it('nama pulse, tag, dan jumlah penyebutan tidak menaikkan vonis tanpa indikator terbukti', async () => {
    // Bentuk yang dulu menaikkan vonis: pulse ber-tag malware menyebut hostname, tetapi daftar
    // indikatornya tidak memuat alamat yang diperiksa.
    const fetchMock = otxFetch({
      urlPulses: [],
      domainPulses: [
        {
          id: 'pulse-1',
          name: 'Kampanye phishing kredensial bank',
          tags: ['phishing', 'malware'],
          malware_families: ['Emotet'],
          indicator_count: 9,
        },
      ],
      indicators: [
        { indicator: 'https://situs-palsu.example/login', type: 'url' },
        { indicator: 'infra-jahat.example', type: 'domain' },
        { indicator: '44d88612fea8a8f36de06e7bbbfd9c9d', type: 'hash' },
        { indicator: '198.51.100.7', type: 'ip' },
      ],
    })

    const check = await otxAdapter.check(
      contextFor(GOOGLE_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(check.status).toBe('success')
    expectZeroContribution(check)
    expect(
      check.signals.some((signal) => signal.detail.includes('tidak memuat alamat ini')),
    ).toBe(true)
  })

  it('indikator domain lookalike tidak diwariskan ke host yang diperiksa', async () => {
    const fetchMock = otxFetch({
      urlPulses: [],
      domainPulses: [
        {
          id: 'pulse-2',
          name: 'Infra AsyncRAT',
          tags: ['botnet'],
          malware_families: ['AsyncRAT'],
          indicator_count: 12,
        },
      ],
      indicators: [
        { indicator: 'accounts.google.com.phishing-check.top', type: 'domain' },
        { indicator: 'google.com', type: 'domain' },
        { indicator: 'co.id', type: 'domain' },
      ],
    })

    const check = await otxAdapter.check(
      contextFor(GOOGLE_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    // `google.com` adalah induk dari accounts.google.com: ini kecocokan tingkat domain yang sah,
    // jadi vonis `suspicious` dengan skor domain (bukan malicious) memang dipakai. Yang diuji di
    // sini: lookalike dan public suffix tidak menambah apa pun, dan tidak pernah malicious.
    expect(check.verdict).toBe('suspicious')
    expect(check.score).toBe(55)
    expect(check.reason).toContain('bukan URL persis')
    expect(check.signals.some((signal) => signal.severity === 'danger')).toBe(false)
  })

  it('public suffix saja tidak membuat host yang diperiksa cocok dengan indikator', async () => {
    // Target `www.bca.co.id`; indikator hanya `co.id` (public suffix) dan `id` -> tidak covers.
    const fetchMock = otxFetch({
      urlPulses: [],
      domainPulses: [
        {
          id: 'pulse-3',
          name: 'Pulse infrastruktur',
          tags: [],
          malware_families: ['AsyncRAT'],
          indicator_count: 5,
        },
      ],
      indicators: [
        { indicator: 'co.id', type: 'domain' },
        { indicator: 'id', type: 'domain' },
      ],
    })

    const check = await otxAdapter.check(
      contextFor(
        'https://www.bca.co.id/',
        fetchMock as unknown as typeof fetch,
        'www.bca.co.id',
      ),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expectZeroContribution(check)
  })

  it('kecocokan sebagian label (notcontoh.com vs contoh.com) bukan indikator target', async () => {
    const fetchMock = otxFetch({
      urlPulses: [],
      domainPulses: [
        {
          id: 'pulse-4',
          name: 'Pulse infrastruktur',
          tags: [],
          malware_families: ['AsyncRAT'],
          indicator_count: 5,
        },
      ],
      indicators: [{ indicator: 'notcontoh.com', type: 'domain' }],
    })

    const check = await otxAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch, 'contoh.com'),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expectZeroContribution(check)
  })

  it('tanpa id pulse: tidak ada konfirmasi, hasil tetap intelijen komunitas (bukan bukti aman)', async () => {
    const fetchMock = otxFetch({
      urlPulses: [
        { name: 'Pulse tanpa id', tags: ['phishing'], malware_families: ['AsyncRAT'], indicator_count: 3 },
      ],
    })

    const check = await otxAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(check.status).toBe('success')
    expectZeroContribution(check)
    // Kegagalan mengonfirmasi TIDAK pernah dibaca sebagai "bersih".
    expect(check.verdict).not.toBe('clean')
    expect(check.reason).toContain('bukan konfirmasi ancaman maupun bukti bersih')
  })

  it('anggaran konfirmasi dibatasi tiga pulse per pemeriksaan', async () => {
    const pulses: OtxPulse[] = Array.from({ length: 7 }, (_unused, index) => ({
      id: `pulse-${index}`,
      name: `Pulse ${index}`,
      tags: [],
      malware_families: ['AsyncRAT'],
      indicator_count: 4,
    }))
    const fetchMock = otxFetch({ urlPulses: pulses, indicators: [] })

    const check = await otxAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    // Satu permintaan indikator URL + paling banyak tiga permintaan konfirmasi pulse.
    expect(fetchMock).toHaveBeenCalledTimes(4)
    expectZeroContribution(check)
    expect(check.signals.some((signal) => signal.detail.includes('batas permintaan konfirmasi tercapai'))).toBe(
      true,
    )
  })
})

describe('VGL-30K-R4 Kategori B/C: identitas subjek pada Hybrid Analysis (Agen 7)', () => {
  it('laporan sandbox URL lain pada host yang sama tidak menyumbang skor', async () => {
    const fetchMock = hybridFetch({
      url: [],
      domain: [
        hybridReport({
          verdict: 'malicious',
          subject: 'www.instagram.com',
          observedUrls: ['https://www.instagram.com/accounts/login'],
          family: 'Emotet',
        }),
      ],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.status).toBe('success')
    expectZeroContribution(check)
    expect(check.signals.some((signal) => signal.label === 'Laporan terkait pada host ini')).toBe(true)
    expect(JSON.stringify(check)).not.toContain('ha-key')
  })

  it('laporan subjek host lain (mis. tujuan redirect) tidak diwariskan ke alamat ini', async () => {
    // URL yang diperiksa mengalihkan ke `login-external.example`; laporan sandbox ada di
    // tujuan itu, bukan pada alamat yang diperiksa.
    const fetchMock = hybridFetch({
      url: [
        hybridReport({
          verdict: 'malicious',
          subject: 'login-external.example',
          observedUrls: ['https://login-external.example/sso'],
          family: 'Zeus',
        }),
      ],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.signals.some((signal) => signal.detail.includes('login-external.example'))).toBe(true)
  })

  it('dokumen tanpa identitas subjek menjadi Kategori C, bukan aman dan bukan ancaman', async () => {
    const fetchMock = hybridFetch({
      url: [{ verdict: 'malicious', analysis_start_time: new Date(NOW_MS - 3_600_000).toISOString() }],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(GOOGLE_URL, fetchMock as unknown as typeof fetch, GOOGLE_HOST),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.status).toBe('success')
    expectZeroContribution(check)
    expect(check.verdict).not.toBe('clean')
    expect(check.signals.some((signal) => signal.label === 'Identitas laporan')).toBe(true)
  })

  it('vonis clean pada laporan host lain tidak menurunkan laporan menjadi aman', async () => {
    const fetchMock = hybridFetch({
      url: [],
      domain: [
        hybridReport({
          verdict: 'whitelisted',
          subject: 'instagram.com',
          observedUrls: ['https://www.instagram.com/explore/tags/x'],
        }),
      ],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
  })
})

describe('VGL-30K-R4 Kategori A: ancaman pada target tetap terdeteksi', () => {
  it('OTX: URL persis terbukti menjadi indikator pulse berkeluarga malware -> malicious 70', async () => {
    const fetchMock = otxFetch({
      urlPulses: [
        {
          id: 'pulse-tp-1',
          name: 'Phishing AsyncRAT pada URL spesifik',
          tags: [],
          malware_families: ['AsyncRAT'],
          indicator_count: 6,
        },
      ],
      indicators: [{ indicator: INSTAGRAM_URL, type: 'url' }],
    })

    const check = await otxAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(check.status).toBe('success')
    expect(check.verdict).toBe('malicious')
    expect(check.score).toBe(70)
    expect(check.signals.some((signal) => signal.label === 'Indikator terverifikasi')).toBe(true)
  })

  it('OTX: URL persis terbukti pada pulse ber-tag phishing -> suspicious 45', async () => {
    const fetchMock = otxFetch({
      urlPulses: [
        {
          id: 'pulse-tp-2',
          name: 'Kampanye harvest kredensial',
          tags: ['phishing'],
          malware_families: [],
          indicator_count: 20,
        },
      ],
      indicators: [{ indicator: INSTAGRAM_URL, type: 'url' }],
    })

    const check = await otxAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.verdict).toBe('suspicious')
    expect(check.score).toBe(45)
  })

  it('OTX: indikator domain terbukti pada pulse malware -> suspicious 55, tidak pernah malicious', async () => {
    const fetchMock = otxFetch({
      urlPulses: [],
      domainPulses: [
        {
          id: 'pulse-tp-3',
          name: 'Infra AsyncRAT',
          tags: ['botnet'],
          malware_families: ['AsyncRAT'],
          indicator_count: 9,
        },
      ],
      indicators: [{ indicator: 'instagram.com', type: 'domain' }],
    })

    const check = await otxAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.verdict).toBe('suspicious')
    expect(check.score).toBe(55)
    expect(check.reason).toContain('bukan URL persis')
  })

  it('Hybrid: laporan yang menganalisis URL persis tetap malicious 85', async () => {
    const fetchMock = hybridFetch({
      url: [
        hybridReport({
          verdict: 'malicious',
          subject: 'www.instagram.com',
          observedUrls: [INSTAGRAM_URL],
          family: 'Emotet',
        }),
      ],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(check.verdict).toBe('malicious')
    expect(check.score).toBe(85)
    expect(check.evidence?.source).toBe('existing_report')
  })

  it('Hybrid: vonis suspicious pada subjek URL persis tetap 55 dan tidak diturunkan', async () => {
    const fetchMock = hybridFetch({
      url: [hybridReport({ verdict: 'suspicious', subject: 'www.instagram.com', family: 'AgentTesla' })],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.verdict).toBe('suspicious')
    expect(check.score).toBe(55)
  })

  it('Hybrid: laporan host berkaitan tidak menghapus vonis target yang sah', async () => {
    const fetchMock = hybridFetch({
      url: [
        hybridReport({ verdict: 'malicious', subject: 'www.instagram.com', observedUrls: [INSTAGRAM_URL], family: 'Emotet' }),
      ],
      domain: [
        hybridReport({
          verdict: 'suspicious',
          subject: 'www.instagram.com',
          observedUrls: ['https://www.instagram.com/other'],
          family: 'Phorpiex',
        }),
        hybridReport({
          verdict: 'malicious',
          subject: 'www.instagram.com.phishing-check.top',
          observedUrls: ['https://www.instagram.com.phishing-check.top/x'],
          family: 'Zeus',
        }),
      ],
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.verdict).toBe('malicious')
    expect(check.score).toBe(85)
    expect(check.summary).not.toContain('verdict suspicious')
  })
})

describe('VGL-30K-R4 kegagalan provider tetap tanpa vonis (bukan clean, bukan malicious)', () => {
  it.each([
    [400, 'invalid_request'],
    [422, 'invalid_request'],
  ])('Agen 6: HTTP %i pada indikator URL -> %s dan tanpa vonis', async (status, expected) => {
    const fetchMock = vi.fn(async () => jsonResponse({ detail: 'permintaan ditolak' }, status))
    const check = await otxAdapter.check(
      contextFor(GOOGLE_URL, fetchMock as unknown as typeof fetch, GOOGLE_HOST),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.status).toBe(expected)
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
  })

  it('Agen 6: HTTP 429 pada indikator URL -> rate_limited, bukan bukti aman', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ detail: 'Too many requests' }, 429))
    const check = await otxAdapter.check(
      contextFor(GOOGLE_URL, fetchMock as unknown as typeof fetch, GOOGLE_HOST),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.status).toBe('rate_limited')
    expect(check.verdict).toBe('inconclusive')
    expect(check.verdict).not.toBe('clean')
    expect(check.score).toBeNull()
  })

  it('Agen 6: galat DNS pada indikator URL dilaporkan sebagai kegagalan', async () => {
    const fetchMock = vi.fn(async () => {
      throw new TypeError('fetch failed')
    })
    const check = await otxAdapter.check(
      contextFor(GOOGLE_URL, fetchMock as unknown as typeof fetch, GOOGLE_HOST),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.status).toBe('unavailable')
    expect(check.verdict).toBe('inconclusive')
    expect(check.signals).toHaveLength(0)
  })

  it.each([
    [500, 'unavailable'],
    [429, 'rate_limited'],
    [401, 'auth_failed'],
  ])('Agen 6: kegagalan rute domain (%i) -> %s walau indikator URL kosong', async (status, expected) => {
    const fetchMock = vi.fn(async (request: string | URL | Request) => {
      if (String(request).includes('/indicators/domain/')) return jsonResponse({ detail: 'gagal' }, status)
      return jsonResponse({ pulse_info: { count: 0, pulses: [] } })
    })

    const check = await otxAdapter.check(
      contextFor(GOOGLE_URL, fetchMock as unknown as typeof fetch, GOOGLE_HOST),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.status).toBe(expected)
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(check.reason).toContain('penelusuran domain accounts.google.com gagal')
  })

  it('Agen 6: kegagalan konfirmasi indikator TIDAK dianggap tidak ada ancaman', async () => {
    const fetchMock = otxFetch({
      urlPulses: [
        {
          id: 'pulse-x',
          name: 'Infra AsyncRAT',
          tags: [],
          malware_families: ['AsyncRAT'],
          indicator_count: 5,
        },
      ],
      pulseStatus: 500,
    })

    const check = await otxAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ otxApiKey: 'otx-key' }),
    )

    expect(check.status).toBe('success')
    expectZeroContribution(check)
    expect(check.signals.some((signal) => signal.detail.includes('tidak dapat diperiksa'))).toBe(true)
    // Bukan "bersih": ketiadaan konfirmasi bukan bukti aman.
    expect(check.verdict).not.toBe('clean')
  })

  it.each([
    [400, 'invalid_request'],
    [422, 'invalid_request'],
    [500, 'unavailable'],
    [429, 'rate_limited'],
  ])('Agen 7: HTTP %i -> %s, tanpa vonis', async (status, expected) => {
    const fetchMock = vi.fn(async () => jsonResponse({ detail: 'gagal' }, status))
    const check = await hybridAnalysisAdapter.check(
      contextFor(GOOGLE_URL, fetchMock as unknown as typeof fetch, GOOGLE_HOST),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.status).toBe(expected)
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
    expect(JSON.stringify(check)).not.toContain('ha-key')
  })

  it('Agen 7: pencarian domain gagal setelah URL tanpa vonis dilaporkan sebagai kegagalan', async () => {
    const fetchMock = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      if (String(init?.body ?? '').startsWith('domain=')) return jsonResponse({ detail: 'server error' }, 500)
      return jsonResponse({ count: 0, result: [] })
    })

    const check = await hybridAnalysisAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.status).toBe('unavailable')
    expect(check.verdict).toBe('inconclusive')
    expect(check.reason).toContain('penelusuran domain www.instagram.com gagal')
  })

  it('Agen 7: JSON cacat pada rute indikator tidak pernah diubah menjadi vonis', async () => {
    const fetchMock = vi.fn(
      async () => new Response('bukan json {', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    const check = await hybridAnalysisAdapter.check(
      contextFor(INSTAGRAM_URL, fetchMock as unknown as typeof fetch),
      makeConfig({ hybridAnalysisApiKey: 'ha-key' }),
    )

    expect(check.status).toBe('error')
    expect(check.verdict).toBe('inconclusive')
    expect(check.score).toBeNull()
  })
})

describe('VGL-30K-R4 nol kontribusi lewat agregasi delapan agen', () => {
  beforeEach(() => {
    resetScanState()
  })

  function communityNoiseFetch(onCall: (url: string, body: string) => void) {
    return vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input)
      const body = String(init?.body ?? '')
      onCall(url, body)

      if (url.includes('raw.githubusercontent.com')) return textResponse('https://phish.example/login\n')
      if (url.includes('/pulses/')) return jsonResponse({ results: [], next: null })
      if (url.includes('/indicators/url/')) {
        return jsonResponse({ pulse_info: { count: 0, pulses: [] } })
      }
      if (url.includes('/indicators/domain/')) {
        // 55 pulse komunitas menyebut hostname situs resmi; masing-masing adalah daftar indikator
        // besar (blocklist/kampanye multi-merek) sehingga kecocokan di dalamnya tidak khusus
        // untuk alamat ini dan tidak dikirimi permintaan konfirmasi.
        return jsonResponse({
          pulse_info: {
            count: 55,
            pulses: Array.from({ length: 12 }, (_unused, index) => ({
              id: `pulse-domain-${index}`,
              name: `Pulse komunitas ${index}`,
              tags: ['botnet'],
              malware_families: ['Emotet'],
              indicator_count: 400_000,
            })),
          },
        })
      }
      if (url.includes('/api/v2/search/terms')) {
        if (body.startsWith('domain=')) {
          return jsonResponse({
            count: 1,
            result: [
              hybridReport({
                verdict: 'malicious',
                subject: new URL(GOOGLE_URL).hostname,
                observedUrls: ['https://accounts.google.com/ServiceLogin?x=1'],
                family: 'Emotet',
              }),
            ],
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
      uid: 'vgl-30k-r4',
      url,
      config: makeConfig({ otxApiKey: 'otx-key', hybridAnalysisApiKey: 'ha-key' }),
      adapters: PROVIDER_ADAPTERS,
      fetchImpl: communityNoiseFetch((called, body) => calls.push({ url: called, body })) as unknown as typeof fetch,
      now: () => NOW_MS,
    })
    return { response, calls }
  }

  it('hanya noise komunitas: tidak ada agen yang membawa skor atau menaikkan vonis', async () => {
    const { response, calls } = await runOfficial(GOOGLE_URL)

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

    const otx = response.providers.find((provider) => provider.id === 'otx')
    expect(otx?.status).toBe('success')
    expect(otx?.verdict).toBe('inconclusive')
    expect(otx?.score).toBeNull()

    const hybrid = response.providers.find((provider) => provider.id === 'hybrid')
    expect(hybrid?.status).toBe('success')
    expect(hybrid?.verdict).toBe('inconclusive')
    expect(hybrid?.score).toBeNull()

    // Nol kontribusi struktural: tidak ada angka dari agen 6/7 yang bisa diambil agregator
    // (`Math.max` atas skor non-null), jadi skor gabungan tetap 0.
    for (const provider of [otx, hybrid]) {
      expect(provider?.signals.every((signal) => signal.severity === 'info')).toBe(true)
    }
    expect(response.providers.every((provider) => provider.score === null || provider.score === 0)).toBe(true)
    expect(response.providers.every((provider) => provider.verdict !== 'malicious')).toBe(true)
    expect(response.providers.every((provider) => provider.verdict !== 'suspicious')).toBe(true)

    // Data komunitas TETAP dikirim ke antarmuka (jumlah + konteks), bukan disembunyikan.
    expect(otx?.signals.some((signal) => signal.detail.includes('55 pulse'))).toBe(true)
    expect(hybrid?.signals.some((signal) => signal.label === 'Laporan terkait pada host ini')).toBe(true)

    // Harga permintaan tetap terprediksi: daftar indikator massal tidak dikirimi permintaan
    // konfirmasi sama sekali (batas keras 3 dijaga pada uji unit), dan agen 7 hanya melakukan dua
    // penelusuran laporan (URL + domain).
    const confirmations = calls.filter((call) => call.url.includes('/pulses/')).length
    expect(confirmations).toBe(0)
    const hybridCalls = calls.filter((call) => call.url.includes('/api/v2/search/terms')).length
    expect(hybridCalls).toBe(2)
  })
})

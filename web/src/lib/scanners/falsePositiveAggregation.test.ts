import { describe, expect, it } from 'vitest'
import type { ScanResult } from '../analysis/types'
import { buildMultiSourceReport } from './report'
import { EXTERNAL_PROVIDER_IDS, type ExternalProviderId, type ProviderResult } from './types'

// VGL-30K: kontrak agregasi untuk gejala yang dilaporkan pengguna — instagram.com sempat tampil
// sebagai risiko menengah karena satu agen menyebut domain pada pulse komunitas, dan website
// resmi sempat membawa indikasi malware dari bukti tingkat domain. Fixture memakai payload agen
// hasil patch backend (P5/P6); tidak ada panggilan jaringan di tes ini.

const INSTAGRAM_URL = 'https://www.instagram.com/'
const BCA_URL = 'https://www.bca.co.id/'

function makeScan(input: string, overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    id: 'scan-30k',
    createdAt: '2026-01-01T00:00:00.000Z',
    mode: 'link',
    input,
    displayTarget: new URL(input).hostname,
    riskScore: 0,
    riskLevel: 'low',
    headline: 'Indikasi risiko rendah',
    summary: 'Tidak banyak indikator risiko ditemukan.',
    reasons: [],
    patterns: [],
    recommendations: ['Verifikasi melalui kanal resmi.'],
    technical: [],
    meta: { engineVersion: 'test', signalCount: 0, inputLength: input.length, aiStatus: 'not_used' },
    ...overrides,
  }
}

function makeProvider(
  id: ExternalProviderId,
  overrides: Partial<ProviderResult> = {},
): ProviderResult {
  return {
    id,
    label: id,
    status: 'success',
    verdict: 'clean',
    score: 0,
    summary: 'Tidak ditemukan indikasi.',
    signals: [],
    reason: null,
    durationMs: 120,
    ...overrides,
  }
}

function allClean(except: Partial<Record<ExternalProviderId, Partial<ProviderResult>>> = {}) {
  return EXTERNAL_PROVIDER_IDS.map((id) => makeProvider(id, except[id] ?? {}))
}

function reportFor(input: string, providers: ProviderResult[]) {
  return buildMultiSourceReport({
    scan: makeScan(input),
    externalProviders: providers,
    externalRequested: true,
    generatedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 1_200,
  })
}

describe('VGL-30K agregasi: penyebutan komunitas dan bukti domain bukan risiko URL', () => {
  it('penyebutan domain oleh pulse komunitas tidak lagi mendorong laporan ke risiko menengah', () => {
    // Payload Agen 6 setelah P5: success dengan vonis inconclusive dan TANPA skor, bukti tetap
    // tampil sebagai sinyal info.
    const providers = allClean({
      otx: {
        verdict: 'inconclusive',
        score: null,
        summary:
          'AlienVault OTX tidak menyebut URL ini; domain www.instagram.com hanya muncul pada 31 pulse komunitas tanpa keluarga malware.',
        reason: 'Penyebutan domain oleh komunitas tanpa indikator malware konkret.',
        signals: [
          { label: 'Pulse komunitas', detail: '31 pulse OTX menyebut domain www.instagram.com.', severity: 'info' },
          { label: 'Tag pulse', detail: 'phishing, malware, botnet', severity: 'info' },
        ],
      },
    })

    const report = reportFor(INSTAGRAM_URL, providers)

    // Vonis bersih agen lain tetap tidak boleh dibaca sebagai "dijamin aman": ada satu agen
    // yang hasilnya tidak konklusif. Yang hilang adalah risiko menegah ~40% dari penyebutan.
    expect(report.verdict).toBe('inconclusive')
    expect(report.score).toBeLessThanOrEqual(34)
    // Bukti komunitas tetap terlihat, hanya tidak dinilai sebagai risiko.
    const otx = report.providers.find((provider) => provider.id === 'otx')
    expect(otx?.signals.some((signal) => signal.detail.includes('31 pulse'))).toBe(true)
    expect(report.providers.some((provider) => provider.verdict === 'suspicious')).toBe(false)
  })

  it('bukti domain host lain dari Agen 7 tidak menghasilkan laporan mencurigakan', () => {
    // Payload Agen 7 setelah P6: dokumen lookalike dikeluarkan dari vonis, status not_found.
    const providers = allClean({
      hybrid: {
        status: 'not_found',
        verdict: 'inconclusive',
        score: null,
        summary: 'Hybrid Analysis tidak memiliki laporan dengan vonis untuk URL ini.',
        reason: 'Laporan pada domain www.bca.co.id menunjuk host lain.',
        signals: [
          { label: 'Cakupan penelusuran', detail: 'URL persis dan domain tanpa vonis terbaca.', severity: 'info' },
          {
            label: 'Laporan pada host lain',
            detail: '1 laporan ikut terkembalikan menunjuk host di luar www.bca.co.id (www.bca.co.id.verify-secure.top).',
            severity: 'info',
          },
        ],
      },
    })

    const report = reportFor(BCA_URL, providers)

    // Tidak ada agen yang memberi vonis positif, tetapi satu agen tanpa laporan membuat
    // hasilnya tidak bisa disebut bersih: inconclusive dengan risiko efektif nol.
    expect(report.verdict).toBe('inconclusive')
    expect(report.score).toBeLessThanOrEqual(34)
    expect(report.completeness.notFound).toBe(1)
    expect(report.completeness.checked).toBe(EXTERNAL_PROVIDER_IDS.length)
    expect(report.providers.some((provider) => provider.verdict === 'suspicious')).toBe(false)
  })

  it('karakterisasi gejala: payload lama (suspicious 40) memang tampil risiko menengah', () => {
    // Bukan ekspektasi yang diinginkan, melainkan bukti mekanismenya: sebelum P5, Agen 6
    // memberi vonis suspicious dengan skor 40 hanya dari penyebutan domain. Pita skor
    // suspicious mulai dari 35, jadi satu temuan lemah itu sendiri yang menghasilkan angka
    // ~40% pada laporan. Karena pita dan struktur hasil tidak boleh diubah, perbaikannya ada
    // di lapisan penyedia (P5) dan tes ini menjaga hubungan itu tetap terbaca.
    const providers = allClean({
      otx: { verdict: 'suspicious', score: 40, summary: 'domain muncul pada 31 pulse komunitas.' },
    })

    const report = reportFor(INSTAGRAM_URL, providers)

    expect(report.verdict).toBe('suspicious')
    expect(report.score).toBe(40)
  })

  it('kontrol sensitivitas: keluarga malware pada domain tetap naik menjadi mencurigakan', () => {
    const providers = allClean({
      otx: {
        verdict: 'suspicious',
        score: 55,
        summary: 'AlienVault OTX tidak menyebut URL ini, tetapi domain contoh.com dikaitkan dengan AsyncRAT pada 4 pulse.',
        reason: 'Bukti berasal dari indikator domain, bukan URL persis yang diperiksa.',
      },
    })

    const report = reportFor(INSTAGRAM_URL, providers)

    expect(report.verdict).toBe('suspicious')
    expect(report.score).toBeGreaterThanOrEqual(55)
  })

  it('kontrol sensitivitas: kecocokan IOC persis tetap diangkat sebagai ancaman', () => {
    const report = reportFor(
      'https://instagram-verify.example/login',
      allClean({
        threatfox: {
          verdict: 'malicious',
          score: 85,
          summary: 'ThreatFox menemukan 1 IOC yang cocok dengan URL ini.',
        },
      }),
    )

    expect(report.verdict).toBe('malicious')
    expect(report.score).toBeGreaterThanOrEqual(80)
  })
})

// VGL-30K-R4: Kategori B (intelijen komunitas) dan Kategori C (bukti tanpa identitas target)
// harus nol kontribusi pada TATA letak agregasi, bukan hanya pada adapter. Agregator hanya
// membaca `verdict` dan `score`, jadi dua field itulah yang dijaga di sini: jalur tidak langsung
// (`Math.max` atas skor, korroborasi +5, vonis gabungan, dan pita skor) ikut diuji.
describe('VGL-30K-R4 agregasi: Kategori B nol kontribusi lewat seluruh jalur', () => {
  const communityB = (id: ExternalProviderId, detail: string): Partial<ProviderResult> => ({
    verdict: 'inconclusive',
    score: null,
    summary: `${id}: data komunitas tersedia tetapi bukan bukti untuk URL ini.`,
    reason: 'Bukti berasal dari laporan yang subjeknya bukan alamat yang diperiksa.',
    signals: [{ label: 'Intelijen komunitas', detail, severity: 'info' }],
  })

  it('dua agen komunitas sekaligus tidak menyumbang angka, korroborasi, maupun vonis', () => {
    const providers = allClean({
      otx: communityB('otx', '55 laporan komunitas menyebut domain; kecocokan indikator tidak terbukti.'),
      hybrid: communityB('hybrid', '1 laporan menganalisis URL lain pada host ini.'),
    })

    const report = reportFor(INSTAGRAM_URL, providers)

    // Tidak ada skor dari agen 6/7 yang bisa diambil `Math.max`: basis agregasi tetap 0.
    expect(report.score).toBe(0)
    // Vonis tidak boleh naik; dan "clean" juga tidak boleh dijanjikan selama ada agen tanpa
    // bukti konklusif.
    expect(report.verdict).toBe('inconclusive')
    expect(report.providers.some((provider) => provider.verdict === 'suspicious')).toBe(false)
    expect(report.providers.some((provider) => provider.verdict === 'malicious')).toBe(false)
    // Data tetap ditampilkan.
    const otx = report.providers.find((provider) => provider.id === 'otx')
    expect(otx?.signals.some((signal) => signal.detail.includes('55 laporan komunitas'))).toBe(true)
  })

  it('Kategori B tidak menambah korroborasi pada vonis suspicious dari Kategori A', () => {
    // Satu agen memberi bukti target-spesifik (A, 55) + dua agen komunitas. Korroborasi +5 hanya
    // berlaku bila ada LEBIH DARI SATU agen `suspicious`; bila B ikut terhitung, skor menjadi 60.
    const providers = allClean({
      otx: {
        verdict: 'suspicious',
        score: 55,
        summary: 'URL ini terbukti menjadi indikator laporan komunitas berkeluarga malware.',
      },
      hybrid: communityB('hybrid', '1 laporan pada host ini menganalisis URL lain.'),
      safebrowsing: communityB('safebrowsing', 'Cakupan penelusuran tanpa vonis terbaca.'),
    })

    const report = reportFor(BCA_URL, providers)

    expect(report.verdict).toBe('suspicious')
    expect(report.score).toBe(55)
    expect(report.providers.filter((provider) => provider.verdict === 'suspicious')).toHaveLength(1)
  })

  it('Kategori C tidak pernah dibaca sebagai bersih', () => {
    const providers = allClean({
      hybrid: {
        verdict: 'inconclusive',
        score: null,
        status: 'success',
        summary: 'Laporan dikembalikan tanpa identitas subjek.',
        reason: 'Ketiadaan laporan bukan bukti situs aman.',
        signals: [{ label: 'Identitas laporan', detail: '1 laporan tanpa subjek terbaca.', severity: 'info' }],
      },
    })

    const report = reportFor(INSTAGRAM_URL, providers)

    expect(report.verdict).not.toBe('clean')
    expect(report.verdict).toBe('inconclusive')
    expect(report.score).toBe(0)
  })

  it('kontrol bentuk: penyebutan yang membawa angka tetap terhitung agregator (regresi larangan)', () => {
    // Bentuk B yang benar adalah TANPA angka. Bila seseorang menempel angka pada hasil
    // inconclusive, `Math.max` agregasi langsung memakainya: di pita inconclusive angkanya
    // dipotong ke 34, dan pada vonis suspicious ia tampil ~40 seperti gejala yang dilaporkan
    // pengguna. Jadi larangannya ada di bentuk hasil agen, bukan di pemotongan tampilan.
    const withNumber = allClean({
      otx: { verdict: 'inconclusive', score: 40, summary: 'bentuk lama: skor ditempel pada penyebutan' },
    })
    expect(reportFor(INSTAGRAM_URL, withNumber).score).toBe(34)

    const asSuspicious = allClean({ otx: { verdict: 'suspicious', score: 40, summary: 'bentuk lama' } })
    expect(reportFor(INSTAGRAM_URL, asSuspicious).score).toBe(40)

    const asShipped = allClean({ otx: communityB('otx', 'hanya penyebutan komunitas.') })
    expect(reportFor(INSTAGRAM_URL, asShipped).score).toBe(0)
  })
})

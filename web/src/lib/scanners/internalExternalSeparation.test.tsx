import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { MultiSourceReportPanel } from '../../components/result/MultiSourceReportPanel'
import { analyze } from '../analysis'
import type { ScanResult } from '../analysis/types'
import { buildMultiSourceReport } from './report'
import {
  EXTERNAL_PROVIDER_IDS,
  type ExternalProviderId,
  type MultiSourceReport,
  type ProviderResult,
} from './types'
import { isMultiSourceReport } from './validate'

// VGL-30K-R1: pemisahan bukti internal vs bukti eksternal. Gejala yang dilaporkan pemilik:
// heuristik leksikal ikut tampil dan ikut menghitung "Laporan Multi-Sumber", sehingga satu
// URL lookalike BCA memperoleh skor gabungan 76/100 tanpa satu pun bukti agen. Uji di bawah
// menjaga dua hal: (1) hasil internal hanya hidup pada bagian "Indikasi internal · heuristik
// leksikal" (dijaga ResultPage.test.tsx), dan (2) skor, vonis, jumlah agen, serta cakupan
// laporan multi-sumber dihitung dari kedelapan agen eksternal saja.

const LOOKALIKE_URL = 'https://www.bca.co.id.verify-secure.top'
const GENERATED_AT = '2026-01-01T00:00:00.000Z'

// Angka heuristik dibaca dari mesin yang sebenarnya lewat analyze(), bukan ditulis tangan,
// supaya tidak ada angka yang dikarang di dalam pengujian ini.
function lexicalScan(input = LOOKALIKE_URL): ScanResult {
  const draft = analyze({ mode: 'link', value: input })
  return { ...draft, id: 'scan-r1', createdAt: GENERATED_AT }
}

function noRiskScan(input = LOOKALIKE_URL): ScanResult {
  return { ...lexicalScan(input), riskScore: 0, riskLevel: 'low', reasons: [], patterns: [] }
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

function reportFor(scan: ScanResult, providers: ProviderResult[]): MultiSourceReport {
  return buildMultiSourceReport({
    scan,
    externalProviders: providers,
    sharedWithProviders: [...EXTERNAL_PROVIDER_IDS],
    externalRequested: true,
    generatedAt: GENERATED_AT,
    durationMs: 1_200,
  })
}

describe('VGL-30K-R1 §1A heuristik internal berdiri sendiri', () => {
  it('skor leksikal lookalike BCA adalah hasil kalkulasi aktual', () => {
    const scan = lexicalScan()
    const totalWeight = scan.reasons.reduce((sum, reason) => sum + reason.weight, 0)

    // Diukur dari mesin: 26 + 20 + 12 + 10 + 8 = 76. Dua assert dipakai bersama supaya angka
    // 76 tetap terbukti sebagai jumlah bobot, bukan nilai yang diketik sesuai keinginan.
    expect(scan.riskScore).toBe(Math.min(100, totalWeight))
    expect(scan.riskScore).toBe(76)
    expect(scan.riskLevel).toBe('high')
    expect(scan.reasons.map((reason) => reason.id)).toEqual(
      expect.arrayContaining([
        'brand_domain_prefix',
        'brand_credential_combo',
        'suspicious_tld',
        'deep_subdomain',
        'credential_keywords',
      ]),
    )
    expect(scan.patterns.map((pattern) => pattern.id)).toEqual(
      expect.arrayContaining(['impersonation', 'phishing', 'fake_login']),
    )
  })
})

describe('VGL-30K-R1 Test A pemisahan data internal vs laporan multi-sumber', () => {
  it('heuristik internal tidak menjadi baris agen di laporan', () => {
    const report = reportFor(lexicalScan(), allClean())

    expect(report.providers.some((provider) => provider.id === 'internal')).toBe(false)
    expect(report.providers).toHaveLength(EXTERNAL_PROVIDER_IDS.length)
    expect(report.providers.map((provider) => provider.id)).toEqual([...EXTERNAL_PROVIDER_IDS])
  })

  it('skor internal tidak menaikkan maupun menurunkan skor gabungan agen', () => {
    const providers = allClean()
    const risky = reportFor(lexicalScan(), providers)
    const plain = reportFor(noRiskScan(), providers)

    // Tanpa bukti apa pun dari agen, laporan tidak boleh mewarisi angka 76 dari heuristik.
    expect(risky.score).toBe(0)
    expect(risky.score).toBeLessThanOrEqual(34)
    expect(risky.score).toBe(plain.score)
    expect(risky.providers.some((provider) => provider.score === 76)).toBe(false)
    expect(risky.verdict).not.toBe('suspicious')
    expect(risky.verdict).not.toBe('malicious')
  })

  it('vonis eksternal tetap diangkat sesuai bukti eksternal', () => {
    const flagged = reportFor(lexicalScan(), allClean({ urlscan: { verdict: 'malicious', score: 90 } }))
    const suspicious = reportFor(
      lexicalScan(),
      allClean({ threatfox: { verdict: 'suspicious', score: 55 } }),
    )

    expect(flagged.verdict).toBe('malicious')
    expect(flagged.score).toBeGreaterThanOrEqual(80)
    expect(suspicious.verdict).toBe('suspicious')
    expect(suspicious.score).toBe(55)
  })

  it('risiko internal tidak mengubah jumlah agen berhasil maupun cakupan', () => {
    const providers = allClean({
      radar: { status: 'timeout', verdict: 'inconclusive', score: null },
    })
    const risky = reportFor(lexicalScan(), providers)
    const plain = reportFor(noRiskScan(), providers)

    expect(risky.completeness).toEqual(plain.completeness)
    expect(risky.completeness.total).toBe(EXTERNAL_PROVIDER_IDS.length)
    expect(risky.completeness.success).toBe(7)
    expect(risky.completeness.timeout).toBe(1)
    expect(risky.completeness.checked).toBe(7)
  })

  it('ketidaksesuaian internal vs eksternal tetap terbaca sebagai catatan, bukan sebagai agen', () => {
    const report = reportFor(lexicalScan(), allClean())

    expect(report.conflicts.some((conflict) => conflict.includes('Aturan internal'))).toBe(true)
    expect(report.providers.every((provider) => provider.id !== 'internal')).toBe(true)
  })

  it('kartu agen internal hilang dari panel sedangkan agen eksternal tetap delapan', () => {
    const markup = renderToStaticMarkup(
      <MultiSourceReportPanel report={reportFor(lexicalScan(), allClean())} />,
    )

    expect(markup).not.toContain('Analisis internal')
    expect(markup).toContain(`${EXTERNAL_PROVIDER_IDS.length} agen pemeriksaan dalam laporan`)
  })

  it('riwayat lama yang masih memuat baris internal tetap sah dan tidak dirender sebagai agen', () => {
    const report = reportFor(lexicalScan(), allClean())
    const legacy: MultiSourceReport = {
      ...report,
      providers: [
        {
          id: 'internal',
          label: 'Analisis internal',
          status: 'success',
          verdict: 'suspicious',
          score: 76,
          summary: 'Aturan internal menemukan indikasi risiko tinggi.',
          signals: [],
          reason: null,
          durationMs: 0,
        },
        ...report.providers,
      ],
    }

    expect(isMultiSourceReport(report)).toBe(true)
    // Riwayat pengguna tidak boleh dibuang hanya karena pernah dibentuk roster versi lama.
    expect(isMultiSourceReport(legacy)).toBe(true)

    const markup = renderToStaticMarkup(<MultiSourceReportPanel report={legacy} />)
    expect(markup).not.toContain('Analisis internal')
    expect(markup).toContain(`${EXTERNAL_PROVIDER_IDS.length} agen pemeriksaan dalam laporan`)
  })
})

describe('VGL-30K-R1 Test B lookalike BCA pada lapisan agregasi', () => {
  const hostBuktiInfo = {
    status: 'not_found' as const,
    verdict: 'inconclusive' as const,
    score: null,
    summary: 'Hybrid Analysis tidak memiliki laporan dengan vonis untuk URL ini.',
    reason: 'Laporan pada domain ikut terkembalikan menunjuk host lain.',
    signals: [
      {
        label: 'Laporan pada host lain',
        detail: '1 laporan ikut terkembalikan menunjuk host di luar host URL yang diperiksa.',
        severity: 'info' as const,
      },
    ],
  }

  it('heuristik menangkap lookalike sementara laporan agen tetap tanpa bukti', () => {
    const report = reportFor(lexicalScan(), allClean({ hybrid: hostBuktiInfo }))

    expect(lexicalScan().riskLevel).toBe('high')
    expect(report.providers.find((provider) => provider.id === 'hybrid')?.score).toBeNull()
    expect(report.score).toBe(0)
    expect(report.verdict).toBe('inconclusive')
    expect(
      report.providers
        .find((provider) => provider.id === 'hybrid')
        ?.signals.some((signal) => signal.severity === 'info'),
    ).toBe(true)
    expect(report.completeness.notFound).toBe(1)
    expect(report.completeness.checked).toBe(8)
  })

  it('skor laporan agen tidak pernah identik dengan skor heuristik leksikal', () => {
    const scan = lexicalScan()
    const report = reportFor(scan, allClean({ otx: hostBuktiInfo }))

    expect(report.score).not.toBe(scan.riskScore)
    expect(report.providers.some((provider) => provider.score === scan.riskScore)).toBe(false)
  })

  it('situs resmi dengan bukti negatif agen tetap dibaca sesuai bukti agen', () => {
    const report = reportFor(
      noRiskScan('https://www.bca.co.id/'),
      allClean({
        urlscan: { verdict: 'malicious', score: 88, summary: 'URLScan menilai URL ini berbahaya.' },
      }),
    )

    // Vonis agen diangkat apa adanya; tidak dinetralkan maupun dinaikkan oleh heuristik.
    expect(report.verdict).toBe('malicious')
    expect(report.score).toBeGreaterThanOrEqual(80)
  })
})

describe('VGL-30K-R1 Test D cakupan berasal dari hasil aktual', () => {
  function mixedRoster(): ProviderResult[] {
    const overrides: Record<ExternalProviderId, Partial<ProviderResult>> = {
      urlscan: { status: 'invalid_request', verdict: 'inconclusive', score: null },
      virustotal: { verdict: 'clean', score: 0 },
      openphish: { status: 'not_found', verdict: 'inconclusive', score: null },
      threatfox: { verdict: 'malicious', score: 85 },
      radar: { status: 'unavailable', verdict: 'inconclusive', score: null },
      otx: { status: 'not_configured', verdict: 'inconclusive', score: null },
      hybrid: { status: 'timeout', verdict: 'inconclusive', score: null },
      safebrowsing: { status: 'auth_failed', verdict: 'inconclusive', score: null },
    }
    return EXTERNAL_PROVIDER_IDS.map((id) => makeProvider(id, overrides[id]))
  }

  it('delapan agen tetap terdaftar dan yang dihitung selesai hanya yang memberi hasil', () => {
    const report = reportFor(lexicalScan(), mixedRoster())

    expect(EXTERNAL_PROVIDER_IDS).toHaveLength(8)
    expect(report.providers).toHaveLength(8)
    expect(report.completeness.total).toBe(8)
    expect(report.completeness.success).toBe(2)
    expect(report.completeness.notFound).toBe(1)
    expect(report.completeness.checked).toBe(3)
    expect(report.completeness.percent).toBe(38)
    expect(report.completeness.timeout).toBe(1)
    expect(report.completeness.notConfigured).toBe(1)
    expect(report.completeness.authFailed).toBe(1)
    expect(report.completeness.error).toBe(1)
    expect(report.completeness.unavailable).toBe(1)
  })

  it('permintaan ditolak, timeout, belum dikonfigurasi, dan gagal tidak dibaca sebagai aman', () => {
    const report = reportFor(lexicalScan(), mixedRoster())
    const byId = new Map(report.providers.map((provider) => [provider.id, provider]))

    for (const id of ['urlscan', 'hybrid', 'otx', 'safebrowsing', 'radar'] as ExternalProviderId[]) {
      expect(byId.get(id)?.verdict).toBe('inconclusive')
      expect(byId.get(id)?.score).toBeNull()
    }
    expect(report.verdict).toBe('malicious')
    expect(report.score).toBe(85)
  })

  it('rincian agen menampilkan penolakan permintaan sebagai status sendiri, bukan aman', () => {
    const markup = renderToStaticMarkup(
      <MultiSourceReportPanel report={reportFor(lexicalScan(), mixedRoster())} />,
    )

    // Label per status (VGL-30K-R1 §5): penolakan, tidak tersedia, belum dikonfigurasi, gagal
    // autentikasi, dan batas waktu tampil apa adanya; tak satu pun dibaca aman.
    expect(markup).toContain('Permintaan ditolak')
    expect(markup).toContain('Tidak tersedia')
    expect(markup).toContain('Belum dikonfigurasi')
    expect(markup).toContain('Gagal autentikasi')
    expect(markup).toContain('Melebihi batas waktu')
    expect(markup).toContain('Tidak ada kecocokan data')
    // Bilangan cakupan memisahkan permintaan yang ditolak, dihitung dari baris agen aktual.
    expect(markup).toContain('1 permintaan ditolak')
    expect(markup).toContain(`${EXTERNAL_PROVIDER_IDS.length} agen pemeriksaan dalam laporan`)
    expect(markup.split('Risiko: Tidak dapat dinilai').length - 1).toBe(5)
    expect(markup).not.toContain('Analisis internal')
  })

  it('laporan tanpa permintaan eksternal tidak mengklaim cakupan maupun skor palsu', () => {
    const report = buildMultiSourceReport({
      scan: lexicalScan(),
      externalRequested: false,
      generatedAt: GENERATED_AT,
    })

    expect(report.providers).toHaveLength(8)
    expect(report.providers.every((provider) => provider.status === 'skipped')).toBe(true)
    expect(report.completeness.checked).toBe(0)
    expect(report.completeness.success).toBe(0)
    expect(report.score).toBeLessThanOrEqual(34)
    expect(report.verdict).toBe('inconclusive')
  })
})

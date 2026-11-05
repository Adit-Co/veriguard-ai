import { describe, expect, it } from 'vitest'
import type { ScanResult } from '../analysis/types'
import { buildMultiSourceReport } from './report'
import { EXTERNAL_PROVIDER_IDS, type ExternalProviderId, type ProviderResult } from './types'
import { negativeEvidenceFor } from './providerEvidenceFixtures'

// VGL-30J: kontrak agregasi untuk situs resmi yang dilaporkan terkena false positive dan
// untuk status kegagalan baru (permintaan ditolak provider). Semua fixture adalah hasil
// agen yang sudah ternormalisasi; tidak ada panggilan jaringan di tes ini.

const OFFICIAL_BENCHMARK_URLS = [
  'https://www.youtube.com/',
  'https://www.instagram.com/',
  'https://discord.com/',
  'https://mail.google.com/',
  'https://store.steampowered.com/',
  'https://www.spotify.com/',
]

function makeScan(input: string, overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    id: 'scan-resmi',
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
  const base: ProviderResult = {
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

  // Fixture meniru penanda bukti negatif yang dikirim adapter nyata (lihat
  // `providerEvidenceFixtures`), karena sejak VGL-31 vonis Risiko Rendah bersandar pada
  // penanda itu, bukan pada warna status belaka.
  const negative = overrides.negative ?? negativeEvidenceFor(id, base)
  return negative ? { ...base, negative } : base
}

// Semua agen menjawab bersih untuk URL persis yang diperiksa.
function allClean(except: Partial<Record<ExternalProviderId, Partial<ProviderResult>>> = {}) {
  return EXTERNAL_PROVIDER_IDS.map((id) => makeProvider(id, except[id] ?? {}))
}

function reportFor(input: string, providers: ProviderResult[], scanOverrides: Partial<ScanResult> = {}) {
  return buildMultiSourceReport({
    scan: makeScan(input, scanOverrides),
    externalProviders: providers,
    externalRequested: true,
    generatedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 1_200,
  })
}

describe('regresi situs resmi: agregasi tidak menaikkan risiko tanpa dasar', () => {
  for (const url of OFFICIAL_BENCHMARK_URLS) {
    it(`${url}: semua agen bersih tidak pernah dibaca berbahaya atau mencurigakan`, () => {
      const report = reportFor(url, allClean())

      expect(report.verdict).toBe('clean')
      expect(report.score).toBeLessThanOrEqual(35)
      expect(report.completeness.checked).toBe(EXTERNAL_PROVIDER_IDS.length)
    })

    it(`${url}: ketiadaan data di semua agen tidak pernah dibaca berbahaya`, () => {
      const providers = EXTERNAL_PROVIDER_IDS.map((id) =>
        makeProvider(id, {
          status: 'not_found',
          verdict: 'inconclusive',
          score: null,
          summary: 'Tidak ada kecocokan data.',
        }),
      )

      const report = reportFor(url, providers)

      expect(report.verdict).toBe('inconclusive')
      expect(report.score).toBeLessThanOrEqual(34)
      expect(report.completeness.notFound).toBe(EXTERNAL_PROVIDER_IDS.length)
    })

    it(`${url}: provider yang gagal atau menolak permintaan tidak menjadi bukti ancaman`, () => {
      const providers = allClean({
        urlscan: {
          status: 'invalid_request',
          verdict: 'inconclusive',
          score: null,
          summary: 'Permintaan pemeriksaan ditolak provider.',
          reason: 'Permintaan pemeriksaan ditolak provider. (HTTP 400)',
        },
        hybrid: {
          status: 'error',
          verdict: 'inconclusive',
          score: null,
          summary: 'Pemeriksaan provider gagal.',
          reason: 'Provider menolak permintaan (HTTP 500).',
        },
        otx: {
          status: 'timeout',
          verdict: 'inconclusive',
          score: null,
          summary: 'Provider melebihi batas waktu.',
        },
      })

      const report = reportFor(url, providers)

      expect(report.verdict).toBe('inconclusive')
      // Agen yang gagal tidak dihitung sebagai "terperiksa" maupun sebagai unavailable palsu.
      expect(report.completeness.checked).toBe(EXTERNAL_PROVIDER_IDS.length - 3)
      expect(report.completeness.unavailable).toBe(0)
      expect(report.completeness.error).toBe(2)
      expect(report.completeness.timeout).toBe(1)
      expect(report.providers.some((provider) => provider.verdict === 'malicious')).toBe(false)
    })
  }

  it('bukti tingkat domain tidak membawa skor band malicious ke laporan gabungan', () => {
    // Hybrid menurunkan vonis ke "suspicious" karena cocok di tingkat domain; angkanya harus
    // ikut turun. Sebelum perbaikan, 85 (band malicious) bertahan dan maksimum antar agen
    // membuat laporan situs resmi tampil sebagai risiko tinggi-menengah tanpa dasar URL.
    const report = reportFor('https://www.youtube.com/', allClean({
      hybrid: {
        verdict: 'suspicious',
        score: 55,
        summary: 'Bukti berasal dari domain youtube.com, bukan URL persis.',
        reason: 'Cocok pada tingkat domain, bukan URL persis yang diperiksa.',
      },
    }))

    expect(report.verdict).toBe('suspicious')
    expect(report.score).toBeLessThanOrEqual(60)
  })

  it('kecocokan tingkat URL persis tetap diangkat sebagai ancaman', () => {
    // Perbaikan false positive tidak boleh menghapus sinyal ancaman yang sah.
    const report = reportFor('https://insta-secure-login.xyz/verify', allClean({
      urlscan: {
        verdict: 'malicious',
        score: 90,
        summary: 'URLScan menilai URL ini berbahaya (skor 90/100).',
      },
    }))

    expect(report.verdict).toBe('malicious')
    expect(report.score).toBeGreaterThanOrEqual(80)
  })

  it('indikasi internal tidak mengangkat vonis saat provider tidak memberi hasil', () => {
    // VGL-30K-R1 §1 Track B: delapan agen menolak permintaan => tidak ada bukti eksternal.
    // Vonis gabungan harus tetap inconclusive (bukan clean, bukan suspicious) dan skor tidak
    // boleh meminjam riskScore leksikal. Heuristik tetap tampil pada kartu indikasi internal.
    const report = reportFor(
      'https://situs-asing.example/login',
      EXTERNAL_PROVIDER_IDS.map((id) =>
        makeProvider(id, {
          status: 'invalid_request',
          verdict: 'inconclusive',
          score: null,
          summary: 'Permintaan pemeriksaan ditolak provider.',
        }),
      ),
      { riskLevel: 'high', riskScore: 72 },
    )

    expect(report.verdict).toBe('inconclusive')
    expect(report.score).toBeLessThanOrEqual(34)
    expect(report.completeness.checked).toBe(0)
    expect(report.providers.some((provider) => provider.id === 'internal')).toBe(false)
  })
})

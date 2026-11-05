import { describe, expect, it } from 'vitest'
import type { ScanResult } from '../analysis/types'
import { buildLocalReport, buildMultiSourceReport, reportDimensions } from './report'
import {
  EXTERNAL_PROVIDER_IDS,
  type ExternalProviderId,
  type NegativeEvidence,
  type ProviderResult,
} from './types'
import { negativeEvidenceFor } from './providerEvidenceFixtures'

// VGL-31 TAHAP 5 — regression & benchmark untuk klasifikasi risiko berbasis bukti.
//
// Semua fixture adalah hasil agen yang sudah ternormalisasi; tidak ada panggilan jaringan.
// Sumbu yang diuji sengaja dipisah seperti tuntutan PATCH: skor risiko (A), kecukupan bukti
// (B), cakupan agen (C), dan keyakinan vonis (D). Tidak ada uji yang boleh meloloskan vonis
// Risiko Rendah karena jumlah agen yang menjawab, popularitas domain, atau HTTP 200.

const BENCHMARK_URL = 'https://translate.google.co.id/'

function makeScan(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    id: 'scan-vgl31',
    createdAt: '2026-01-01T00:00:00.000Z',
    mode: 'link',
    input: BENCHMARK_URL,
    displayTarget: 'translate.google.co.id',
    riskScore: 14,
    riskLevel: 'low',
    headline: 'Indikasi risiko rendah',
    summary: 'Tidak banyak indikator risiko ditemukan.',
    reasons: [],
    patterns: [],
    recommendations: ['Verifikasi melalui kanal resmi.'],
    technical: [],
    meta: {
      engineVersion: 'test',
      signalCount: 1,
      inputLength: BENCHMARK_URL.length,
      aiStatus: 'not_used',
    },
    ...overrides,
  }
}

// `negative: null` dipakai uji untuk memaksa bentuk hasil yang TIDAK pernah dikirim adapter
// (vonis bersih tanpa penanda bukti), supaya paths itu tetap terverifikasi.
type ProviderOverrides = Partial<Omit<ProviderResult, 'negative'>> & { negative?: NegativeEvidence | null }

function provider(id: ExternalProviderId, overrides: ProviderOverrides = {}): ProviderResult {
  const { negative: forced, ...rest } = overrides
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
    ...rest,
  }

  if (forced !== undefined) {
    return forced === null ? { ...base, negative: undefined } : { ...base, negative: forced }
  }

  const negative = negativeEvidenceFor(id, base)
  return negative ? { ...base, negative } : base
}

function noMatch(id: ExternalProviderId): ProviderResult {
  return provider(id, {
    status: 'not_found',
    verdict: 'inconclusive',
    score: null,
    summary: 'Tidak ada kecocokan data.',
  })
}

// Keadaan nyata benchmark: urlscan dan radar memindai URL apa adanya dan keduanya mengirim
// vonis negatif; enam agen lain tidak punya data untuk URL ini. Ini persis bentuk hasil yang
// sebelumnya mentok di "Belum Konklusif" karena aturannya menuntut semua agen `success`.
function scannedCleanRoster(): ProviderResult[] {
  return EXTERNAL_PROVIDER_IDS.map((id) => (id === 'urlscan' || id === 'radar' ? provider(id) : noMatch(id)))
}

function reportFor(providers: ProviderResult[], scanOverrides: Partial<ScanResult> = {}) {
  return buildMultiSourceReport({
    scan: makeScan(scanOverrides),
    externalProviders: providers,
    sharedWithProviders: EXTERNAL_PROVIDER_IDS.filter((id) =>
      providers.some((provider) => provider.id === id),
    ),
    externalRequested: true,
    generatedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 1_500,
  })
}

describe('VGL-31 benchmark translate.google.co.id', () => {
  it('vonis Risiko Rendah lahir dari dua agen independen yang menyatakan bersih, bukan dari jumlah agen', () => {
    const report = reportFor(scannedCleanRoster())

    expect(report.version).toBe(2)
    expect(report.verdict).toBe('clean')
    expect(report.score).toBeLessThanOrEqual(35)
    expect(report.evidenceSufficiency).toMatchObject({
      level: 'sufficient',
      confirmedClean: 2,
      confirmedCleanClasses: ['scan_verdict', 'scanner_verdict'],
      requiredConfirmedClean: 2,
    })
    expect(report.providerCoverage).toMatchObject({
      answered: 8,
      total: 8,
      noMatch: 6,
      unresolved: 0,
      positiveFindings: 0,
    })
    expect(report.verdictConfidence).toBe('high')
    expect(report.notes.join('\n')).toContain('bukan jaminan URL ini aman')
  })

  it('skor risiko tidak pernah diambil dari heuristik internal maupun dari jumlah agen', () => {
    const report = reportFor(scannedCleanRoster())

    // Heuristik internal benchmark berbobot 14; angka itu tidak boleh muncul di laporan eksternal.
    expect(report.score).not.toBe(14)
    expect(report.score).toBeLessThanOrEqual(10)
    // Delapan agen menjawab, tetapi vonis bersih tidak dihitung dari delapan: hanya tiga hasil
    // yang benar-benar membawa bukti negatif (dua eksplisit + satu terbatas).
    expect(report.providerCoverage?.usableNegativeEvidence).toBe(3)
  })
})

describe('VGL-31 pemisahan status bukti (TAHAP 2)', () => {
  it('no_match di semua agen tidak pernah menjadi confirmed_clean maupun bersih', () => {
    const report = reportFor(EXTERNAL_PROVIDER_IDS.map(noMatch))

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(0)
    // Safe Browsing memang mengirim bukti negatif terbatas saat daftarnya menjawab kosong.
    expect(report.evidenceSufficiency?.limitedNegatives).toBe(1)
    expect(report.verdictConfidence).toBe('low')
  })

  it('bukti negatif terbatas tidak pernah berdiri sendiri sebagai vonis bersih', () => {
    const providers = EXTERNAL_PROVIDER_IDS.map((id) => {
      if (id === 'urlscan' || id === 'radar') {
        // Vonis bersih provider TANPA penanda eksplisit: tetap `clean` di lapisannya sendiri,
        // tapi tidak memberi kewenangan Risiko Rendah.
        return provider(id, { negative: null })
      }
      return noMatch(id)
    })

    const report = reportFor(providers)

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.level).toBe('limited')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(0)
  })

  it('dua agen yang menyalin laporan identik (kelas dan basis sama) dihitung satu agen independen', () => {
    const sameClass: NegativeEvidence = {
      strength: 'explicit',
      scope: 'url',
      evidenceClass: 'scan_verdict',
      basis: 'Dua agen menyalin kebiasaan pemindaian yang sama.',
    }

    const report = reportFor(
      EXTERNAL_PROVIDER_IDS.map((id) =>
        id === 'urlscan' || id === 'radar' ? provider(id, { negative: sameClass }) : noMatch(id),
      ),
    )

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(2)
    expect(report.evidenceSufficiency?.confirmedCleanClasses).toHaveLength(1)
  })

  it('bukti selebar domain bukan bukti untuk URL ini', () => {
    const domainScoped: NegativeEvidence = {
      strength: 'explicit',
      scope: 'domain',
      evidenceClass: 'scan_verdict',
      basis: 'Cakupan provider hanya selebar domain, bukan alamat yang diperiksa.',
    }

    const report = reportFor(
      EXTERNAL_PROVIDER_IDS.map((id) =>
        id === 'urlscan' || id === 'radar' ? provider(id, { negative: domainScoped }) : noMatch(id),
      ),
    )

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(0)
  })
})

describe('VGL-31 kegagalan provider tidak pernah menjadi bukti negatif (TAHAP 3–4)', () => {
  const failing: Array<ProviderResult['status']> = [
    'timeout',
    'error',
    'unavailable',
    'rate_limited',
    'auth_failed',
    'invalid_request',
    'not_configured',
    'skipped',
  ]

  for (const status of failing) {
    it(`satu agen ${status} membatalkan Risiko Rendah dan tidak menambah bukti`, () => {
      const providers = scannedCleanRoster().map((row) =>
        row.id === 'otx'
          ? provider('otx', { status, verdict: 'inconclusive', score: null, summary: 'Agen tidak memberi hasil.' })
          : row,
      )

      const report = reportFor(providers)

      expect(report.verdict).toBe('inconclusive')
      expect(report.providerCoverage?.unresolved).toBe(1)
      expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toContain('bukti aman')
    })
  }

  it('kegagalan yang disertai penanda bukti tetap tidak boleh menurunkan vonis risiko', () => {
    // Bentuk ini tidak pernah dihasilkan adapter (semua helper kegagalan tidak mengisi
    // `negative`); uji menjaga agar agregator tidak pernah mempercayainya.
    const poisoned = scannedCleanRoster().map((row) =>
      row.id === 'hybrid'
        ? provider('hybrid', {
            status: 'timeout',
            verdict: 'clean',
            negative: {
              strength: 'explicit',
              scope: 'url',
              evidenceClass: 'scan_verdict',
              basis: 'Penanda tidak sah pada agen yang gagal.',
            },
          })
        : row,
    )

    const report = reportFor(poisoned)

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(2)
  })
})

describe('VGL-31 bukti ancaman tetap menang (TAHAP 4)', () => {
  it('satu temuan suspicious menahan vonis meskipun bukti negatif cukup lengkap', () => {
    const report = reportFor(
      scannedCleanRoster().map((row) =>
        row.id === 'threatfox'
          ? provider('threatfox', { verdict: 'suspicious', score: 45 })
          : row,
      ),
    )

    expect(report.verdict).toBe('suspicious')
    expect(report.score).toBeGreaterThanOrEqual(35)
  })

  it('temuan malicious tidak pernah diturunkan oleh provider yang bersih', () => {
    const report = reportFor(
      scannedCleanRoster().map((row) =>
        row.id === 'openphish'
          ? provider('openphish', { verdict: 'malicious', score: 80 })
          : row,
      ),
    )

    expect(report.verdict).toBe('malicious')
    expect(report.score).toBeGreaterThanOrEqual(80)
  })

  it('heuristik internal medium masih menahan vonis Risiko Rendah', () => {
    const report = reportFor(scannedCleanRoster(), { riskLevel: 'medium', riskScore: 45 })

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toContain('Heuristik internal')
  })

  it('bukti yang melewati batas segar tidak menaikkan kepercayaan', () => {
    const staleDay = 24 * 60 * 60_000
    const report = reportFor(
      scannedCleanRoster().map((row) =>
        row.id === 'radar'
          ? provider('radar', {
              evidence: {
                source: 'existing_report',
                observedAt: '2025-12-20T00:00:00.000Z',
                ageMs: 3 * staleDay,
              },
            })
          : row,
      ),
    )

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toContain('kesegarannya')
  })
})

describe('VGL-31 kategori komunitas tetap nol skor (TAHAP 3)', () => {
  it('intelijen komunitas yang menjawab tidak mengubah skor maupun kecukupan', () => {
    const communityOnly = EXTERNAL_PROVIDER_IDS.map((id) => {
      if (id === 'urlscan' || id === 'radar') return provider(id)
      if (id === 'otx' || id === 'hybrid') {
        return provider(id, {
          status: 'success',
          verdict: 'inconclusive',
          score: null,
          summary: 'Laporan komunitas menyebut host ini.',
          signals: [{ label: 'Penyebutan komunitas', detail: '12 laporan.', severity: 'info' }],
          negative: null,
        })
      }
      return noMatch(id)
    })

    const baseline = reportFor(scannedCleanRoster())
    const withCommunity = reportFor(communityOnly)

    expect(withCommunity.verdict).toBe('clean')
    expect(withCommunity.score).toBe(baseline.score)
    expect(withCommunity.evidenceSufficiency?.confirmedClean).toBe(2)
    expect(withCommunity.providerCoverage?.usableNegativeEvidence).toBe(3)
  })

  it('tanpa permintaan eksternal tidak ada dimensi yang mengklaim kebersihan', () => {
    const report = buildLocalReport(makeScan())

    expect(report.verdict).toBe('inconclusive')
    expect(report.providerCoverage?.answered).toBe(0)
    expect(report.providerCoverage?.unresolved).toBe(EXTERNAL_PROVIDER_IDS.length)
    expect(report.verdictConfidence).toBe('low')
  })
})

describe('VGL-31 skenario wajib TAHAP 5 (sisa)', () => {
  it('skenario 3 — beberapa provider inconclusive tidak menambah bukti kebersihan', () => {
    const dodging = (id: ExternalProviderId): ProviderResult =>
      provider(id, {
        verdict: 'inconclusive',
        score: null,
        summary: 'Provider menjawab tanpa menyatakan vonis.',
        negative: null,
      })

    const providers = EXTERNAL_PROVIDER_IDS.map((id) => {
      if (id === 'urlscan') return provider(id)
      if (id === 'otx' || id === 'hybrid' || id === 'safebrowsing') return dodging(id)
      return noMatch(id)
    })

    const report = reportFor(providers)

    expect(report.verdict).toBe('inconclusive')
    // Delapan agen menjawab, tetapi hanya satu yang benar-benar membawa bukti negatif.
    expect(report.providerCoverage?.answered).toBe(8)
    expect(report.providerCoverage?.unresolved).toBe(0)
    expect(report.providerCoverage?.usableNegativeEvidence).toBe(1)
    expect(report.evidenceSufficiency?.confirmedClean).toBe(1)
    expect(report.evidenceSufficiency?.confirmedCleanClasses).toEqual(['scan_verdict'])
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toContain('agen berbeda')
  })

  it('skenario 4 — seluruh provider timeout sama sekali tidak menghasilkan bersih', () => {
    const report = reportFor(
      EXTERNAL_PROVIDER_IDS.map((id) =>
        provider(id, {
          status: 'timeout',
          verdict: 'inconclusive',
          score: null,
          summary: 'Provider tidak menjawab tepat waktu.',
          negative: null,
        }),
      ),
    )

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.level).toBe('insufficient')
    expect(report.providerCoverage).toMatchObject({ answered: 0, unresolved: 8, percent: 0 })
    expect(report.verdictConfidence).toBe('low')
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toContain('bukti aman')
  })

  it('skenario 5 — roster dengan API error campur timeout juga tidak menghasilkan bersih', () => {
    const report = reportFor(
      EXTERNAL_PROVIDER_IDS.map((id) =>
        provider(id, {
          status: id === 'radar' || id === 'hybrid' ? 'error' : 'timeout',
          verdict: 'inconclusive',
          score: null,
          summary: 'Provider gagal.',
          negative: null,
        }),
      ),
    )

    expect(report.verdict).toBe('inconclusive')
    expect(report.providerCoverage?.unresolved).toBe(8)
    expect(report.evidenceSufficiency?.confirmedClean).toBe(0)
  })

  it('skenario 8 — campuran clean, no_match, dan malicious: temuan malicious tetap menang', () => {
    const providers = EXTERNAL_PROVIDER_IDS.map((id) => {
      if (id === 'urlscan' || id === 'radar') return provider(id)
      if (id === 'openphish') {
        return provider(id, {
          status: 'success',
          verdict: 'malicious',
          score: 90,
          summary: 'URL ini ada dalam daftar phishing.',
          negative: null,
        })
      }
      return noMatch(id)
    })

    const report = reportFor(providers)

    expect(report.verdict).toBe('malicious')
    expect(report.score).toBeGreaterThanOrEqual(80)
    expect(report.evidenceSufficiency?.confirmedClean).toBe(2)
    // Dua kelas bukti eksplisit ADA, tetapi temuan positif menahan vonis bersih.
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toContain('bukti ancaman positif')
    expect(report.providerCoverage?.positiveFindings).toBe(1)
  })

  it('skenario 9 — domain lookalike tanpa data provider tidak pernah dapat Risiko Rendah', () => {
    const report = reportFor(EXTERNAL_PROVIDER_IDS.map(noMatch), {
      input: 'https://g00gle-translate-verify.co.id/',
      displayTarget: 'g00gle-translate-verify.co.id',
    })

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(0)
  })

  it('skenario 9b — lookalike yang heuristik internalnya medium tetap tertahan', () => {
    const report = reportFor(scannedCleanRoster(), {
      input: 'https://g00gle-translate-verify.co.id/',
      displayTarget: 'g00gle-translate-verify.co.id',
      riskLevel: 'medium',
      riskScore: 52,
    })

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toContain('Heuristik internal')
  })

  it('skenario 10 — alamat pengalihan ke situs resmi tidak mewarisi reputasi tujuannya', () => {
    const domainOnly: NegativeEvidence = {
      strength: 'explicit',
      scope: 'domain',
      evidenceClass: 'scan_verdict',
      basis: 'Provider menilai alamat lain di domain yang sama, bukan alamat pengalihan ini.',
    }

    const providers = EXTERNAL_PROVIDER_IDS.map((id) => {
      if (id === 'urlscan' || id === 'radar') return provider(id, { negative: domainOnly })
      return noMatch(id)
    })

    const report = reportFor(providers, {
      input: 'https://link-singkat.example/go-bca',
      displayTarget: 'link-singkat.example/go-bca',
    })

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(0)
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toContain('secara eksplisit')
  })

  it('skenario 11 — benchmark lama tetap: dua kelas eksplisit cukup, tanpa skor warisan 14', () => {
    const report = reportFor(scannedCleanRoster())

    expect(report.verdict).toBe('clean')
    expect(report.score).not.toBe(14)
    expect(report.evidenceSufficiency?.confirmedCleanClasses).toHaveLength(2)
  })
})

describe('VGL-31 riwayat laporan versi 1 tetap terbaca (TAHAP 3)', () => {
  it('dimensi diturunkan ulang tanpa mengubah vonis dan skor yang tersimpan', () => {
    const stored = reportFor(scannedCleanRoster())
    const legacy = {
      ...stored,
      version: 1 as const,
      evidenceSufficiency: undefined,
      providerCoverage: undefined,
      verdictConfidence: undefined,
    }

    const dimensions = reportDimensions(legacy)

    expect(legacy.verdict).toBe('clean')
    expect(dimensions.coverage.answered).toBe(8)
    expect(dimensions.sufficiency.confirmedClean).toBe(2)
    // Laporan lama yang sudah membawa penanda tetap memperoleh alasan historis agar riwayat
    // tidak mengaku-aku telah diverifikasi dengan aturan baru.
    expect(dimensions.sufficiency.blockingReasons.join(' ')).toContain('sebelum VERIGUARD mencatat')
    expect(dimensions.confidence).toBe('high')
  })
})

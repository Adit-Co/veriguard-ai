import { describe, expect, it } from 'vitest'
import type { ScanResult } from '../analysis/types'
import { buildMultiSourceReport } from './report'
import {
  EXTERNAL_PROVIDER_IDS,
  type ExternalProviderId,
  type NegativeEvidence,
  type ProviderResult,
} from './types'
import { negativeEvidenceFor } from './providerEvidenceFixtures'

// VGL-32B — kebijakan vonis dua agen: MINIMAL DUA AGEN BERBEDA MENYATAKAN BERSIH SECARA
// VALID = INDIKASI RISIKO RENDAH. Dua kelas bukti tidak lagi syarat mutlak; yang wajib
// adalah dua provider berbeda dengan bukti bersih valid, relevan, dan masih berlaku.
// Korelasi sumber NYATA (kelas bukti dan dasar laporan yang identik — dua adapter yang
// hanya meneruskan laporan yang sama) tetap dihitung satu agen.

const BENCHMARK_URL = 'https://mail.google.com/'

function makeScan(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    id: 'scan-vgl32b',
    createdAt: '2026-01-01T00:00:00.000Z',
    mode: 'link',
    input: BENCHMARK_URL,
    displayTarget: 'mail.google.com',
    riskScore: 12,
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

type ProviderOverrides = Partial<Omit<ProviderResult, 'negative'>> & {
  negative?: NegativeEvidence | null
}

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

function noMatch(id: ExternalProviderId, overrides: ProviderOverrides = {}): ProviderResult {
  return provider(id, {
    status: 'not_found',
    verdict: 'inconclusive',
    score: null,
    summary: 'Tidak ada kecocokan data.',
    ...overrides,
  })
}

function roster(
  cleanIds: ExternalProviderId[],
  overrides: Partial<Record<ExternalProviderId, ProviderResult>> = {},
): ProviderResult[] {
  return EXTERNAL_PROVIDER_IDS.map((id) => {
    const row = cleanIds.includes(id) ? provider(id) : noMatch(id)
    return overrides[id] ?? row
  })
}

function reportFor(providers: ProviderResult[], scanOverrides: Partial<ScanResult> = {}) {
  return buildMultiSourceReport({
    scan: makeScan(scanOverrides),
    externalProviders: providers,
    sharedWithProviders: [...EXTERNAL_PROVIDER_IDS],
    externalRequested: true,
    generatedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 1_500,
  })
}

const HOUR_MS = 60 * 60_000

describe('VGL-32B kasus A — URLScan + VirusTotal bersih valid, enam no_match', () => {
  const report = reportFor(roster(['virustotal', 'urlscan']))

  it('dua agen berbeda yang menyatakan bersih = Indikasi Risiko Rendah', () => {
    expect(report.verdict).toBe('clean')
    expect(report.score).toBe(0)
    expect(report.evidenceSufficiency?.level).toBe('sufficient')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(2)
    expect(report.providerCoverage).toMatchObject({
      answered: 8,
      total: 8,
      noMatch: 6,
      unresolved: 0,
      positiveFindings: 0,
    })
  })
})

describe('VGL-32B kasus B — dua agen bersih + sisa no_match atau bukti negatif terbatas', () => {
  it('bukti negatif tambahan (safebrowsing limited) tidak mengubah kesimpulan', () => {
    const providers = roster(['virustotal', 'urlscan']).map((row) =>
      row.id === 'safebrowsing'
        ? provider('safebrowsing')
        : row,
    )

    expect(reportFor(providers).verdict).toBe('clean')
  })
})

describe('VGL-32B kasus C — bukti bersih kedua kedaluwarsa', () => {
  it('VT aged 30 hari (> batas reuse 168 jam) tidak dihitung: satu agen valid = Perlu Perhatian', () => {
    const report = reportFor(
      roster(['virustotal', 'urlscan'], {
        virustotal: provider('virustotal', {
          evidence: {
            source: 'existing_report',
            observedAt: '2025-12-02T00:00:00.000Z',
            ageMs: 30 * 24 * HOUR_MS,
          },
        }),
      }),
    )

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(1)
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toMatch(/kedaluwarsa|kesegar/)
  })
})

describe('VGL-32B kasus D — dua agen bersih + satu temuan ancaman terverifikasi', () => {
  it('temuan malicious tetap Berbahaya, jumlah agen bersih tidak menurunkan vonis', () => {
    const report = reportFor(
      roster(['virustotal', 'urlscan'], {
        openphish: provider('openphish', {
          verdict: 'malicious',
          score: 90,
          summary: 'URL ini tercatat dalam daftar phishing aktif.',
          negative: null,
        }),
      }),
    )

    expect(report.verdict).toBe('malicious')
    expect(report.score).toBeGreaterThanOrEqual(80)
  })
})

describe('VGL-32B kasus E — hanya satu agen confirmed_clean', () => {
  it('satu agen bersih + tujuh no_match = Perlu Perhatian', () => {
    const report = reportFor(roster(['urlscan']))

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(1)
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toMatch(/agen/)
  })

  it('agen kedua yang hanya verdict clean TANPA penanda bukti tidak dihitung', () => {
    const report = reportFor(
      roster(['urlscan'], {
        hybrid: provider('hybrid', { negative: null, summary: 'Sandbox selesai tanpa vonis bersih eksplisit.' }),
      }),
    )

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(1)
  })
})

describe('VGL-32B kasus F — dua agen bersih + agen gagal', () => {
  it('timeout tetap memblokir dan tidak disamakan dengan no_match atau clean', () => {
    const report = reportFor(
      roster(['virustotal', 'urlscan'], {
        radar: provider('radar', {
          status: 'timeout',
          verdict: 'inconclusive',
          score: null,
          summary: 'Provider tidak menjawab tepat waktu.',
          negative: null,
        }),
      }),
    )

    expect(report.verdict).toBe('inconclusive')
    expect(report.providerCoverage?.unresolved).toBe(1)
    expect(report.evidenceSufficiency?.confirmedClean).toBe(2)
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toContain('tidak memberi hasil')
  })
})

describe('VGL-32B dua agen berbeda adalah syaratnya, bukan dua kelas bukti', () => {
  it('dua agen dengan kelas bukti SAMA tetapi laporan berbeda tetap dua agen independen', () => {
    const classA: NegativeEvidence = {
      strength: 'explicit',
      scope: 'url',
      evidenceClass: 'scan_verdict',
      basis: 'Pemindaian A: skor 0 dan klasifikasi kosong dinyatakan provider untuk URL ini.',
    }
    const classB: NegativeEvidence = {
      strength: 'explicit',
      scope: 'url',
      evidenceClass: 'scan_verdict',
      basis: 'Pemindaian B: provider kedua menilai URL ini bersih dari sumber yang berbeda.',
    }

    const report = reportFor(
      roster([], {
        urlscan: provider('urlscan', { negative: classA }),
        radar: provider('radar', { negative: classB }),
      }),
    )

    expect(report.verdict).toBe('clean')
  })

  it('korelasi sumber nyata (kelas dan dasar laporan identik) tetap dihitung SATU agen', () => {
    const copied: NegativeEvidence = {
      strength: 'explicit',
      scope: 'url',
      evidenceClass: 'scan_verdict',
      basis: 'Dua agen meneruskan laporan yang sama persis.',
    }

    const report = reportFor(
      roster([], {
        urlscan: provider('urlscan', { negative: copied }),
        radar: provider('radar', { negative: copied }),
      }),
    )

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toMatch(/agen/)
  })
})

describe('VGL-32B kesegaran VirusTotal selaras kontrak adapter (reuse maks 168 jam)', () => {
  it('laporan VT berusia 48 jam dari analisis provider tetap bukti bersih yang berlaku', () => {
    // Adapter VirusTotal sengaja menerima laporan hingga 168 jam (kontrak provider:
    // endpoint adalah lookup laporan, bukan pemindaian baru). Batas engine 24 jam
    // sebelumnya membuang bukti yang kontrak adapternya sendiri nyatakan sah.
    const report = reportFor(
      roster(['virustotal', 'urlscan'], {
        virustotal: provider('virustotal', {
          evidence: {
            source: 'existing_report',
            observedAt: '2025-12-30T00:00:00.000Z',
            ageMs: 48 * HOUR_MS,
          },
        }),
      }),
    )

    expect(report.evidenceSufficiency?.confirmedClean).toBe(2)
    expect(report.verdict).toBe('clean')
  })

  it('laporan VT berusia 200 jam (lewat 168 jam) tetap diperlakukan kedaluwarsa', () => {
    const report = reportFor(
      roster(['virustotal', 'urlscan'], {
        virustotal: provider('virustotal', {
          evidence: {
            source: 'existing_report',
            observedAt: '2025-12-02T00:00:00.000Z',
            ageMs: 200 * HOUR_MS,
          },
        }),
      }),
    )

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(1)
  })
})

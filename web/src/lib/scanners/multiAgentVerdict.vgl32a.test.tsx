import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import type { ScanResult } from '../analysis/types'
import { MultiSourceReportPanel } from '../../components/result/MultiSourceReportPanel'
import { buildMultiSourceReport } from './report'
import {
  EXTERNAL_PROVIDER_IDS,
  type ExternalProviderId,
  type NegativeEvidence,
  type ProviderResult,
} from './types'
import { negativeEvidenceFor } from './providerEvidenceFixtures'
import { parseMultiSourceResponse } from './validate'

// VGL-32A — aturan klasifikasi multi-agen yang direvisi.
//
// Uji ini mengunci perbedaan perilaku yang dituntut PATCH:
//   - dua bukti bersih valid + sisanya no_match  -> Risiko Rendah (bukan Belum Konklusif);
//   - no_match dihitung sebagai pemeriksaan BERHASIL, tetapi tidak pernah sebagai bukti bersih;
//   - bukti bersih kedaluwarsa tidak memenuhi syarat minimal dua;
//   - baris no_match yang tua (cache feed) TIDAK boleh memvonis laporan mentok perhatian;
//   - skor risiko Risiko Rendah = 0 ketika tidak ada sinyal ancaman positif;
//   - vonis tampilan memakai tiga tingkat: 'Indikasi Risiko Rendah', 'Perlu Perhatian',
//     'Berbahaya';
//   - daftar "Bukti penilaian" harus berisi bukti yang SAMA dengan yang dipakai engine.

const BENCHMARK_URL = 'https://translate.google.co.id/'
const HOUR_MS = 60 * 60_000

function makeScan(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    id: 'scan-vgl32a',
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

// Roster hidup benchmark: dua agen pemindai menyatakan bersih secara eksplisit
// (sumber bukti independen — VGL-32B), enam agen lain hanya "tidak ada kecocokan data".
function caseARoster(
  cleanIds: ExternalProviderId[] = ['virustotal', 'urlscan'],
  overrides: Partial<Record<ExternalProviderId, ProviderResult>> = {},
): ProviderResult[] {
  return EXTERNAL_PROVIDER_IDS.map((id) => {
    const row = cleanIds.includes(id) ? provider(id) : noMatch(id)
    return overrides[id] ?? row
  })
}

function reportFor(
  providers: ProviderResult[],
  scanOverrides: Partial<ScanResult> = {},
) {
  return buildMultiSourceReport({
    scan: makeScan(scanOverrides),
    externalProviders: providers,
    sharedWithProviders: [...EXTERNAL_PROVIDER_IDS],
    externalRequested: true,
    generatedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 1_500,
  })
}

describe('VGL-32A kasus A — dua bukti bersih + enam no_match = Indikasi Risiko Rendah', () => {
  const report = reportFor(caseARoster())

  it('vonis bersih lahir dari dua confirmed_clean valid tanpa memaksa verdict bersih dari no_match', () => {
    expect(report.verdict).toBe('clean')
  })

  it('skor risiko 0 karena tidak ada sinyal ancaman positif', () => {
    expect(report.score).toBe(0)
  })

  it('kecukupan bukti memadai dan hanya dua agen dihitung sebagai bersih', () => {
    expect(report.evidenceSufficiency?.level).toBe('sufficient')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(2)
    expect(report.evidenceSufficiency?.blockingReasons).toEqual([])
  })

  it('no_match dihitung pemeriksaan berhasil: coverage 8/8, unresolved 0', () => {
    expect(report.providerCoverage).toMatchObject({
      answered: 8,
      total: 8,
      noMatch: 6,
      unresolved: 0,
      positiveFindings: 0,
    })
  })

  it('heuristik internal tetap terpisah dan tidak menambah skor eksternal', () => {
    expect(report.score).not.toBe(14)
  })

  it('panel menampilkan label tiga tingkat dan no_match tetap "Tidak ada kecocokan data"', () => {
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={report} />)
    expect(html).toContain('Indikasi Risiko Rendah')
    expect(html).not.toContain('Belum konklusif</h2>')
    // Enam agen no_match tetap tampil sebagai "Tidak ada kecocokan data".
    const noMatchLabelCount = html.split('Tidak ada kecocokan data').length - 1
    expect(noMatchLabelCount).toBeGreaterThanOrEqual(6)
  })
})

describe('VGL-32A — kesegaran bukti hanya menggugurkan bukti bersih, bukan no_match', () => {
  it('kasus C — bukti bersih kedua kedaluwarsa: hanya satu yang berlaku, jadi Perlu Perhatian', () => {
    const report = reportFor(
      caseARoster(['virustotal', 'urlscan'], {
        virustotal: provider('virustotal', {
          evidence: {
            source: 'existing_report',
            observedAt: '2025-12-31T00:00:00.000Z',
            // VGL-32B: TTL VirusTotal 168 jam (sejajar plafon pemakaian ulang laporan adapter),
            // jadi bukti basi harus lewat ambang itu.
            ageMs: 170 * HOUR_MS,
          },
        }),
      }),
    )

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(1)
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toMatch(/kedaluwarsa|kesegar/)
  })

  it('baris no_match berumur lewat batas cache TIDAK membatalkan Risiko Rendah', () => {
    // OpenPhish/ThreatFox punya batas segar 12 jam; hasil "tidak ada kecocokan" dari cache
    // berumur 13 jam adalah pemeriksaan yang berhasil, bukan bukti bersih basi.
    const report = reportFor(
      caseARoster(['virustotal', 'urlscan'], {
        openphish: noMatch('openphish', {
          evidence: {
            source: 'existing_report',
            observedAt: '2025-12-31T00:00:00.000Z',
            ageMs: 13 * HOUR_MS,
          },
        }),
        threatfox: noMatch('threatfox', {
          evidence: {
            source: 'existing_report',
            observedAt: '2025-12-31T00:00:00.000Z',
            ageMs: 13 * HOUR_MS,
          },
        }),
      }),
    )

    expect(report.verdict).toBe('clean')
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).not.toMatch(/kedaluwarsa|kesegar/)
  })

  it('bukti bersih kedaluwarsa tidak dihitung, tetapi tetap ditampilkan sebagai informasi historis', () => {
    const report = reportFor(
      caseARoster(['virustotal', 'urlscan'], {
        virustotal: provider('virustotal', {
          evidence: {
            source: 'existing_report',
            observedAt: '2025-12-31T00:00:00.000Z',
            // VGL-32B: TTL VirusTotal 168 jam (sejajar plafon pemakaian ulang laporan adapter),
            // jadi bukti basi harus lewat ambang itu.
            ageMs: 170 * HOUR_MS,
          },
        }),
      }),
    )

    expect(report.notes.join(' ')).toContain('informasi historis')
  })
})

describe('VGL-32A kasus B — satu bukti bersih saja tidak cukup', () => {
  it('satu confirmed_clean + tujuh no_match = Perlu Perhatian (inconclusive)', () => {
    const report = reportFor(caseARoster(['urlscan']))

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(1)
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toContain('agen berbeda')
  })

  it('panel menampilkan vonis kurang bukti sebagai "Perlu Perhatian"', () => {
    const html = renderToStaticMarkup(
      <MultiSourceReportPanel report={reportFor(caseARoster(['urlscan']))} />,
    )
    expect(html).toContain('Perlu Perhatian')
  })
})

describe('VGL-32A kasus D — satu agen gagal tidak otomatis risiko rendah', () => {
  const report = reportFor(
    caseARoster(['virustotal', 'urlscan'], {
      radar: provider('radar', {
        status: 'timeout',
        verdict: 'inconclusive',
        score: null,
        summary: 'Provider tidak menjawab tepat waktu.',
        negative: null,
      }),
    }),
  )

  it('kegagalan tetap memblokir Risiko Rendah dan dilaporkan transparan', () => {
    expect(report.verdict).toBe('inconclusive')
    expect(report.providerCoverage?.unresolved).toBe(1)
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toContain('tidak memberi hasil')
  })

  it('status kegagalan agen tetap tampil di panel', () => {
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={report} />)
    expect(html).toContain('Melebihi batas waktu')
  })
})

describe('VGL-32A kasus E — temuan ancaman terverifikasi = Berbahaya', () => {
  const report = reportFor(
    caseARoster(['virustotal', 'urlscan'], {
      radar: provider('radar', {
        verdict: 'malicious',
        score: 85,
        summary: 'Cloudflare URL Scanner menilai URL ini berbahaya.',
        negative: null,
      }),
    }),
  )

  it('temuan malicious menahan vonis bersih', () => {
    expect(report.verdict).toBe('malicious')
    expect(report.score).toBeGreaterThanOrEqual(80)
  })

  it('panel menampilkan label "Berbahaya"', () => {
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={report} />)
    expect(html).toContain('Berbahaya')
  })
})

describe('VGL-32A independensi bukti dan pemisahan heuristik (aturan independensi direvisi VGL-32B)', () => {
  it('dua agen yang meneruskan laporan identik (kelas dan basis sama) dihitung satu sumber', () => {
    // VGL-32B tidak lagi memakai kesamaan kelas sebagai pembatal; yang dibatalkan adalah
    // korelasi sumber NYATA: dua adapter yang hanya meneruskan laporan yang sama persis.
    const sameSource: NegativeEvidence = {
      strength: 'explicit',
      scope: 'url',
      evidenceClass: 'scan_verdict',
      basis: 'Kedua agen membaca sumber laporan yang sama.',
    }

    const report = reportFor(
      caseARoster(['virustotal', 'urlscan'], {
        virustotal: provider('virustotal', { negative: sameSource }),
        urlscan: provider('urlscan', { negative: sameSource }),
      }),
    )

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.confirmedCleanClasses).toHaveLength(1)
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toContain('agen berbeda')
  })

  it('heuristik internal medium menahan Risiko Rendah tetapi tidak menambah skor eksternal', () => {
    const report = reportFor(caseARoster(), { riskLevel: 'medium', riskScore: 45 })

    expect(report.verdict).toBe('inconclusive')
    expect(report.evidenceSufficiency?.blockingReasons.join(' ')).toContain('Heuristik internal')
    expect(report.score).toBeLessThanOrEqual(34)
  })

  it('heuristik internal rendah: vonis eksternal tetap Risiko Rendah dan kartu internal tetap tampil', () => {
    const report = reportFor(caseARoster(), {
      riskLevel: 'low',
      riskScore: 14,
      headline: 'Indikasi risiko rendah',
    })

    expect(report.verdict).toBe('clean')
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={report} />)
    // Skor heuristik (14) tidak pernah bocor ke skor gabungan eksternal (0).
    expect(html).toContain('Skor gabungan 0/100')
  })
})

describe('VGL-32A konsistensi tampilan vs mesin bukti', () => {  it('daftar "Bukti penilaian" hanya memuat agen yang dihitung engine sebagai bukti bersih', () => {
    // urlscan + virustotal confirmed_clean; hybrid "clean" TANPA penanda bukti (bentuk
    // lama) tidak dihitung engine, jadi tidak boleh tampil sebagai bukti penilaian.
    const report = reportFor(
      caseARoster(['virustotal', 'urlscan'], {
        hybrid: provider('hybrid', {
          negative: null,
          summary: 'Sandbox selesai tanpa menandai URL.',
        }),
      }),
    )

    expect(report.verdict).toBe('clean')
    expect(report.evidenceSufficiency?.confirmedClean).toBe(2)

    const html = renderToStaticMarkup(<MultiSourceReportPanel report={report} />)
    expect(html).toContain('menyatakan hasil bersih untuk URL ini')
    expect(html).not.toContain('selesai diperiksa dan tidak menemukan indikasi ancaman')
  })
})

describe('VGL-32A integrasi lintas lapisan — payload provider sampai vonis', () => {
  it('roster hidup benchmark lolos validasi respons dan menghasilkan Indikasi Risiko Rendah', () => {
    const response = parseMultiSourceResponse({
      providers: caseARoster(),
      sharedWithProviders: [...EXTERNAL_PROVIDER_IDS],
      sensitiveUrl: false,
      privacyReasons: [],
      generatedAt: '2026-01-01T00:00:00.000Z',
      durationMs: 1_500,
    })

    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: response.providers,
      sharedWithProviders: response.sharedWithProviders,
      externalRequested: true,
      generatedAt: response.generatedAt,
      durationMs: response.durationMs,
    })

    expect(report.verdict).toBe('clean')
    expect(report.score).toBe(0)
    expect(report.providerCoverage?.noMatch).toBe(6)
  })
})

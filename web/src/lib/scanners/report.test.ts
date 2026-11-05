import { describe, expect, it } from 'vitest'
import type { ScanResult } from '../analysis/types'
import { buildLocalReport, buildMultiSourceReport, isStaleEvidence } from './report'
import {
  EXTERNAL_PROVIDER_IDS,
  type ExternalProviderId,
  type ProviderResult,
  type ScanCacheMeta,
} from './types'
import { negativeEvidenceFor } from './providerEvidenceFixtures'

function makeScan(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    id: 'scan-1',
    createdAt: '2026-01-01T00:00:00.000Z',
    mode: 'link',
    input: 'https://contoh.com/path',
    displayTarget: 'contoh.com/path',
    riskScore: 0,
    riskLevel: 'low',
    headline: 'Indikasi risiko rendah',
    summary: 'Tidak banyak indikator risiko ditemukan.',
    reasons: [],
    patterns: [],
    recommendations: ['Verifikasi melalui kanal resmi.'],
    technical: [],
    meta: {
      engineVersion: 'test',
      signalCount: 0,
      inputLength: 25,
      aiStatus: 'not_used',
    },
    ...overrides,
  }
}

function makeProvider(
  id: ExternalProviderId,
  overrides: Partial<ProviderResult> = {},
): ProviderResult {
  const base: ProviderResult = {
    id,
    label: id === 'virustotal' ? 'VirusTotal' : id,
    status: 'success',
    verdict: 'clean',
    score: 0,
    summary: 'Tidak ditemukan indikasi.',
    signals: [],
    reason: null,
    durationMs: 120,
    ...overrides,
  }

  // VGL-31: fixture membawa penanda bukti negatif seperti adapter nyatanya, supaya jalur
  // "vonis bersih dinyatakan provider" teruji dan bukan hanya jalur warna status.
  const negative = overrides.negative ?? negativeEvidenceFor(id, base)
  return negative ? { ...base, negative } : base
}

describe('laporan multi-sumber', () => {
  it('memisahkan indikasi internal saat eksternal tidak diminta', () => {
    // VGL-30K-R1 §1 Track B: laporan multi-sumber hanya berisi agen eksternal. Heuristik
    // leksikal (riskScore 72, high) tetap hidup di lapisannya sendiri dan tidak lagi
    // menyamar sebagai baris agen, mengangkat vonis, atau menyumbang skor gabungan.
    const report = buildMultiSourceReport({
      scan: makeScan({ riskLevel: 'high', riskScore: 72 }),
      externalRequested: false,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.verdict).toBe('inconclusive')
    expect(report.score).toBeLessThanOrEqual(34)
    expect(report.completeness.checked).toBe(0)
    expect(report.providers).toHaveLength(EXTERNAL_PROVIDER_IDS.length)
    expect(report.providers.some((provider) => provider.id === 'internal')).toBe(false)
    expect(report.externalShared).toBe(false)
    expect(report.providers.every((provider) => provider.status === 'skipped')).toBe(true)
  })

  it('melaporkan agen yang tidak dikirim backend roster lama sebagai skipped, bukan aman', () => {
    // Backend yang masih memakai registry 6 agen tidak boleh membuat laporan
    // dibuang; dua agen yang absen tetap muncul dan tidak diangkat menjadi clean.
    const legacyIds: ExternalProviderId[] = [
      'urlscan',
      'virustotal',
      'openphish',
      'threatfox',
      'radar',
      'otx',
    ]
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: legacyIds.map((id) => makeProvider(id)),
      sharedWithProviders: legacyIds,
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    const byId = new Map(report.providers.map((provider) => [provider.id, provider]))
    expect(byId.get('hybrid')?.status).toBe('skipped')
    expect(byId.get('safebrowsing')?.status).toBe('skipped')
    expect(byId.get('virustotal')?.status).toBe('success')
    expect(report.completeness.total).toBe(EXTERNAL_PROVIDER_IDS.length)
    expect(report.completeness.checked).toBe(6)
    expect(report.verdict).not.toBe('clean')
  })

  it('mengangkat provider eksternal yang menandai ancaman', () => {
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: [
        makeProvider('virustotal', { verdict: 'malicious', score: 60 }),
      ],
      sharedWithProviders: ['virustotal'],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.verdict).toBe('malicious')
    expect(report.score).toBeGreaterThanOrEqual(80)
    expect(report.completeness.success).toBe(1)
    expect(report.externalShared).toBe(true)
    expect(report.notes.some((note) => note.includes('tidak dikirim'))).toBe(false)
  })

  it('menyatakan clean hanya saat semua provider eksternal memberi hasil', () => {
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: EXTERNAL_PROVIDER_IDS.map((id) =>
        makeProvider(id, { verdict: 'clean' }),
      ),
      sharedWithProviders: [...EXTERNAL_PROVIDER_IDS],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.verdict).toBe('clean')
    expect(report.score).toBeLessThanOrEqual(35)
    expect(report.conflicts).toHaveLength(0)
  })

  // VGL-31 mengubah kontrak vonis bersih: dulu syaratnya "SEMUA agen status success", sehingga
  // `no_match` di satu agen saja sudah memaksa Belum Konklusif untuk setiap situs resmi.
  // Sekarang kewenangannya ada pada bukti negatif eksplisit. Dua uji di bawah memisahkan kedua
  // sisi aturan: ketiadaan data tidak pernah menjadi kebersihan, dan `no_match` tidak lagi
  // menghalangi Risiko Rendah selama bukti negatif yang relevan cukup.
  it('tidak menyatakan clean saat semua provider hanya tidak menemukan data', () => {
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: EXTERNAL_PROVIDER_IDS.map((id) =>
        makeProvider(id, {
          status: 'not_found',
          verdict: 'inconclusive',
          score: null,
          summary: 'Tidak ada kecocokan data.',
        }),
      ),
      sharedWithProviders: [...EXTERNAL_PROVIDER_IDS],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.verdict).toBe('inconclusive')
    expect(report.completeness.notFound).toBe(EXTERNAL_PROVIDER_IDS.length)
    expect(report.evidenceSufficiency?.confirmedClean).toBe(0)
  })

  it('no_match tunggal tidak menghalangi Risiko Rendah bila dua kelas bukti negatif eksplisit ada', () => {
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: EXTERNAL_PROVIDER_IDS.map((id) =>
        makeProvider(id, {
          status: id === 'virustotal' ? 'not_found' : 'success',
          verdict: id === 'virustotal' ? 'inconclusive' : 'clean',
          score: id === 'virustotal' ? null : 0,
        }),
      ),
      sharedWithProviders: [...EXTERNAL_PROVIDER_IDS],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.verdict).toBe('clean')
    expect(report.completeness.notFound).toBe(1)
    // Kelas yang tersisa untuk uji ini: urlscan (scan_verdict) dan radar (scanner_verdict).
    expect(report.evidenceSufficiency?.confirmedCleanClasses).toEqual(
      expect.arrayContaining(['scan_verdict', 'scanner_verdict']),
    )
    expect(report.verdictConfidence).toBe('high')
  })

  it('tidak menyatakan clean saat masih ada provider gagal atau belum dikonfigurasi', () => {
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: EXTERNAL_PROVIDER_IDS.map((id) =>
        makeProvider(id, {
          status: id === 'radar' ? 'not_configured' : 'success',
          verdict: id === 'radar' ? 'inconclusive' : 'clean',
          score: id === 'radar' ? null : 0,
        }),
      ),
      sharedWithProviders: ['urlscan', 'virustotal', 'openphish', 'threatfox', 'otx'],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.verdict).toBe('inconclusive')
    expect(report.completeness.notConfigured).toBe(1)
    expect(report.notes.some((note) => note.includes('belum penuh'))).toBe(true)
  })

  it('mencatat konflik ketika sumber internal dan eksternal berbeda', () => {
    // Perbedaan lapisan tetap dinyatakan (transparansi), tapi tidak lagi mengangkat vonis
    // gabungan: internal high + satu agen clean bukan bukti risiko dari agen. Rem satu arah
    // dipertahankan — vonis tidak pernah clean selama heuristik menandai risiko.
    const report = buildMultiSourceReport({
      scan: makeScan({
        riskLevel: 'high',
        riskScore: 70,
        reasons: [
          {
            id: 'brand_impersonation',
            label: 'Nama merek tidak resmi',
            detail: 'Domain meniru merek.',
            severity: 'danger',
            weight: 30,
            category: 'impersonation',
          },
        ],
      }),
      externalProviders: [makeProvider('virustotal', { verdict: 'clean' })],
      sharedWithProviders: ['virustotal'],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.verdict).toBe('inconclusive')
    expect(report.score).toBeLessThanOrEqual(34)
    expect(report.providers.some((provider) => provider.id === 'internal')).toBe(false)
    expect(report.conflicts.some((conflict) => conflict.includes('Aturan internal'))).toBe(true)
  })

  it('menghitung provider yang gagal tanpa menurunkan bukti risiko', () => {
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: [
        makeProvider('virustotal', { verdict: 'malicious', score: 60 }),
        makeProvider('radar', {
          status: 'rate_limited',
          verdict: 'inconclusive',
          score: null,
          summary: 'Kuota tercapai.',
          reason: 'Kuota provider tercapai.',
        }),
        makeProvider('otx', {
          status: 'error',
          verdict: 'inconclusive',
          score: null,
          summary: 'Gagal.',
          reason: 'Provider gagal.',
        }),
        makeProvider('urlscan', {
          status: 'auth_failed',
          verdict: 'inconclusive',
          score: null,
          summary: 'Autentikasi gagal.',
          reason: 'Kredensial ditolak.',
        }),
        makeProvider('openphish', {
          status: 'not_configured',
          verdict: 'inconclusive',
          score: null,
          summary: 'Belum dikonfigurasi.',
          reason: 'API key belum diisi.',
        }),
      ],
      sharedWithProviders: ['virustotal', 'radar', 'otx', 'urlscan', 'openphish'],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.verdict).toBe('malicious')
    expect(report.completeness.rateLimited).toBe(1)
    expect(report.completeness.error).toBe(1)
    expect(report.completeness.authFailed).toBe(1)
    expect(report.completeness.notConfigured).toBe(1)
    expect(report.completeness.checked).toBe(1)
    expect(report.completeness.percent).toBe(13)
  })

  it('menghitung timeout dan tidak menyimpulkan clean', () => {
    const providers = EXTERNAL_PROVIDER_IDS.map((id) =>
      makeProvider(id, {
        status: id === 'urlscan' ? 'timeout' : 'success',
        verdict: id === 'urlscan' ? 'inconclusive' : 'clean',
        score: id === 'urlscan' ? null : 0,
        summary: id === 'urlscan' ? 'Melewati batas waktu.' : 'Tidak ditemukan indikasi.',
      }),
    )
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: providers,
      sharedWithProviders: [...EXTERNAL_PROVIDER_IDS],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.verdict).toBe('inconclusive')
    expect(report.completeness.timeout).toBe(1)
    expect(report.completeness.checked).toBe(7)
  })

  it('menjelaskan batas pemeriksaan saat semua provider dibatasi', () => {
    const providers = EXTERNAL_PROVIDER_IDS.map((id) =>
      makeProvider(id, {
        status: 'rate_limited',
        verdict: 'inconclusive',
        score: null,
        summary: 'Kuota provider tercapai.',
        reason: 'Batas pemeriksaan milik VERIGUARD tercapai, bukan kuota agen. Coba lagi dalam ±600 detik.',
      }),
    )
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: providers,
      sharedWithProviders: [],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.completeness.rateLimited).toBe(8)
    expect(report.externalShared).toBe(false)
    expect(report.notes.some((note) => note.includes('Batas pemeriksaan eksternal'))).toBe(true)
  })

  it('tidak menyatakan tidak diminta saat request tertahan oleh autentikasi', () => {
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalRequested: false,
      externalError: 'Masuk ke akun Firebase agar pemeriksaan eksternal dapat dijalankan.',
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    const external = report.providers.filter((provider) => provider.id !== 'internal')
    expect(report.notes.some((note) => note.includes('tidak diminta'))).toBe(false)
    expect(
      external.every((provider) => !provider.reason?.includes('tidak diminta')),
    ).toBe(true)
    expect(report.notes.some((note) => note.includes('Masuk ke akun Firebase'))).toBe(true)
  })

  it('tidak menandai URL dibagikan saat request eksternal gagal', () => {
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalRequested: true,
      externalError: 'Layanan pemeriksaan eksternal tidak dapat dihubungi.',
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.externalRequested).toBe(true)
    expect(report.externalShared).toBe(false)
    expect(report.notes.some((note) => note.includes('tidak dapat dihubungi'))).toBe(true)
  })

  it('menjelaskan saat tidak ada provider eksternal yang dikonfigurasi', () => {
    const providers = EXTERNAL_PROVIDER_IDS.map((id) =>
      makeProvider(id, {
        status: 'not_configured',
        verdict: 'inconclusive',
        score: null,
        summary: 'Belum dikonfigurasi.',
        reason: 'API key belum diisi.',
      }),
    )
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: providers,
      sharedWithProviders: [],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.externalShared).toBe(false)
    expect(
      report.notes.some((note) => note.includes('Tidak ada agen eksternal')),
    ).toBe(true)
  })

  it('tidak menulis cara pengambilan hasil ke catatan laporan walau agen memakai laporan lama', () => {
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: EXTERNAL_PROVIDER_IDS.map((id) =>
        makeProvider(id, {
          ...(id === 'urlscan' ? { label: 'URLScan.io' } : {}),
          evidence:
            id === 'urlscan' || id === 'virustotal'
              ? {
                  source: 'existing_report',
                  observedAt: '2025-12-31T23:00:00.000Z',
                  ageMs: 3_600_000,
                }
              : { source: 'new_scan', observedAt: null, ageMs: 0 },
        }),
      ),
      sharedWithProviders: [...EXTERNAL_PROVIDER_IDS],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    // Catatan hanya berisi hasil pemeriksaan, tidak pernah mekanisme cache atau laporan ulang.
    expect(report.notes.some((note) => /laporan yang sudah ada|bukan pemindaian/i.test(note))).toBe(
      false,
    )
    // Asal bukti tetap tersimpan sebagai metadata terstruktur untuk tampilan waktu laporan.
    const reused = report.providers.filter(
      (provider) => provider.evidence?.source === 'existing_report',
    )
    expect(reused.map((provider) => provider.id).sort()).toEqual(['urlscan', 'virustotal'])
    expect(report.verdict).toBe('clean')
  })

  it('tidak memberi catatan pakai ulang saat agen benar-benar memindai atau gagal teknis', () => {
    const scanned = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: EXTERNAL_PROVIDER_IDS.map((id) =>
        makeProvider(id, { evidence: { source: 'new_scan', observedAt: null, ageMs: 0 } }),
      ),
      sharedWithProviders: [...EXTERNAL_PROVIDER_IDS],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })
    expect(scanned.notes.some((note) => note.includes('laporan yang sudah ada'))).toBe(false)

    const staleFailure = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: EXTERNAL_PROVIDER_IDS.map((id) =>
        makeProvider(id, {
          status: id === 'radar' ? 'rate_limited' : 'success',
          verdict: id === 'radar' ? 'inconclusive' : 'clean',
          score: id === 'radar' ? null : 0,
          evidence:
            id === 'radar'
              ? { source: 'existing_report', observedAt: null, ageMs: 0 }
              : undefined,
        }),
      ),
      sharedWithProviders: [...EXTERNAL_PROVIDER_IDS],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })
    expect(staleFailure.notes.some((note) => note.includes('laporan yang sudah ada'))).toBe(false)
    expect(staleFailure.verdict).toBe('inconclusive')
  })

  it('membuat laporan fallback tanpa mengklaim pemeriksaan eksternal', () => {
    const report = buildLocalReport(makeScan())

    expect(report.externalRequested).toBe(false)
    expect(report.externalShared).toBe(false)
    expect(report.generatedAt).toBe('2026-01-01T00:00:00.000Z')
    expect(report.notes.some((note) => note.includes('direkonstruksi'))).toBe(true)
    expect(report.notes.some((note) => note.includes('tidak dikirim'))).toBe(false)
  })
})

function cacheMeta(overrides: Partial<ScanCacheMeta> = {}): ScanCacheMeta {
  return {
    status: 'partial',
    hit: false,
    observedAt: '2026-01-01T00:00:00.000Z',
    ageMs: 3_600_000,
    reusedProviders: ['urlscan'],
    refreshedProviders: ['virustotal'],
    requestsAvoided: 1,
    ...overrides,
  }
}

describe('laporan multi-sumber dengan hasil cache', () => {
  const build = (scanCache?: ScanCacheMeta | null) =>
    buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: [
        makeProvider('urlscan', {
          cache: { hit: true, observedAt: '2026-01-01T00:00:00.000Z', ageMs: 3_600_000, stale: false },
        }),
        makeProvider('virustotal'),
      ],
      sharedWithProviders: ['urlscan', 'virustotal'],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
      ...(scanCache === undefined ? {} : { scanCache }),
    })

  it('tidak menambah field cache saat backend lama tidak mengirimnya', () => {
    const report = build()

    expect(report.cache).toBeUndefined()
    expect(report.notes.some((note) => note.includes('hasil pemeriksaan'))).toBe(false)
  })

  it('vonis dan skor tidak berubah hanya karena sebuah hasil datang dari cache', () => {
    const withCache = build(cacheMeta())
    const withoutCache = build(null)

    expect(withCache.verdict).toBe(withoutCache.verdict)
    expect(withCache.score).toBe(withoutCache.score)
    expect(
      withCache.providers.map((provider) => [provider.status, provider.verdict, provider.score]),
    ).toEqual(
      withoutCache.providers.map((provider) => [provider.status, provider.verdict, provider.score]),
    )
  })

  it('tidak pernah menulis metadata cache ke catatan yang dibaca pengguna', () => {
    const report = build(cacheMeta())

    // Metadata tetap ada untuk observability internal, tetapi tidak pernah jadi teks UI.
    expect(report.cache).toEqual(cacheMeta())

    const notes = report.notes.join('\n')
    for (const hidden of [
      'memakai hasil pemeriksaan',
      'tidak ada permintaan keluar',
      'berbagi hasil dengan pemeriksaan lain',
      'lebih tua dari batas segarnya',
      'hasil tersimpan',
      'URLScan.io',
    ]) {
      expect(notes).not.toContain(hidden)
    }
  })

  it('hit penuh, deduplikasi, dan bukti hulu basi tidak menambah catatan cache', () => {
    const fullHit = build(
      cacheMeta({
        status: 'hit',
        hit: true,
        reusedProviders: [...EXTERNAL_PROVIDER_IDS],
        refreshedProviders: [],
        requestsAvoided: EXTERNAL_PROVIDER_IDS.length,
      }),
    )
    const deduplicated = build(cacheMeta({ deduplicated: true }))
    const stale = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: [
        makeProvider('urlscan', {
          cache: { hit: true, observedAt: '2026-01-01T00:00:00.000Z', ageMs: 60_000, stale: true },
        }),
      ],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
      scanCache: cacheMeta({ reusedProviders: ['urlscan'], refreshedProviders: [] }),
    })

    for (const report of [fullHit, deduplicated, stale]) {
      expect(report.notes.join('\n')).not.toMatch(
        /permintaan keluar|pekerjaan ganda|batas segarnya|hasil tersimpan|memakai hasil/,
      )
    }
    // Tidak ada perubahan vonis hanya karena cache.
    expect(fullHit.verdict).toBe(build(null).verdict)
    expect(fullHit.score).toBe(build(null).score)
    expect(stale.verdict).toBe(build(null).verdict)
  })

  it('hasil cache tanpa kecocokan tetap inconclusive, bukan aman', () => {
    const report = buildMultiSourceReport({
      scan: makeScan({ riskLevel: 'low', riskScore: 5 }),
      externalProviders: [
        makeProvider('urlscan', {
          status: 'not_found',
          verdict: 'inconclusive',
          score: null,
          summary: 'Tidak ada kecocokan.',
          cache: { hit: true, observedAt: '2026-01-01T00:00:00.000Z', ageMs: 60_000, stale: false },
        }),
      ],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
      scanCache: cacheMeta({ reusedProviders: ['urlscan'], refreshedProviders: [], status: 'hit', hit: true }),
    })

    expect(report.verdict).toBe('inconclusive')
  })
})

describe('VGM-05: kesegaran bukti dalam vonis gabungan', () => {
  const DAY_MS = 24 * 60 * 60_000

  function allClean(overrides: Partial<Record<ExternalProviderId, Partial<ProviderResult>>> = {}) {
    return EXTERNAL_PROVIDER_IDS.map((id) =>
      makeProvider(id, {
        evidence: { source: 'new_scan', observedAt: null, ageMs: 0 },
        ...overrides[id],
      }),
    )
  }

  it('vonis clean utuh ketika semua bukti masih segar', () => {
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: allClean(),
      sharedWithProviders: [...EXTERNAL_PROVIDER_IDS],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.verdict).toBe('clean')
    expect(report.notes.join('\n')).not.toMatch('informasi historis')
  })

  // VGL-32A merevisi cara bukti kedaluwarsa memperlakukan vonis: bukti bersih yang lewat
  // batas umur TIDAK dihitung memenuhi syarat minimal dua (diagnosis tetap muncul lewat
  // catatan historis dan penurunan keyakinan), tetapi ia juga tidak lagi membatalkan vonis
  // Risiko Rendah yang memang lahir dari dua bukti segar yang independen.
  it('bukti clean yang melewati batas usia tidak boleh menaikkan kepercayaan', () => {
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: allClean({
        virustotal: {
          evidence: { source: 'existing_report', observedAt: '2026-01-01T00:00:00.000Z', ageMs: 169 * 60 * 60_000 },
        },
      }),
      sharedWithProviders: [...EXTERNAL_PROVIDER_IDS],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.verdict).toBe('clean')
    // Bukti VirusTotal yang basi tidak dihitung sebagai bukti bersih...
    expect(report.evidenceSufficiency?.confirmedClean).toBe(2)
    expect(report.evidenceSufficiency?.confirmedCleanClasses).not.toContain('engine_verdicts')
    // ...dan kepercayaan turun karena ada bukti bersih yang kedaluwarsa.
    expect(report.verdictConfidence).toBe('medium')
    expect(report.score).toBe(0)
    expect(report.notes.join(' ')).toContain('informasi historis')
  })

  it('malicious tetap menang walaupun buktinya tua (keamanan pengguna didahulukan)', () => {
    const report = buildMultiSourceReport({
      scan: makeScan(),
      externalProviders: allClean({
        openphish: {
          verdict: 'malicious',
          score: 90,
          status: 'success',
          evidence: { source: 'existing_report', observedAt: '2026-01-01T00:00:00.000Z', ageMs: 30 * DAY_MS },
        },
      }),
      sharedWithProviders: [...EXTERNAL_PROVIDER_IDS],
      externalRequested: true,
      generatedAt: '2026-01-01T00:00:00.000Z',
    })

    expect(report.verdict).toBe('malicious')
    // Bukti tua tidak dibuang dari laporan; ia ditandai sebagai historis untuk transparansi.
    expect(report.notes.join(' ')).toContain('informasi historis')
  })

  it('hasil pemindaian langsung tidak pernah dianggap basi', () => {
    const provider = makeProvider('safebrowsing', {
      evidence: { source: 'new_scan', observedAt: '2026-01-01T00:00:00.000Z', ageMs: 400 * DAY_MS },
    })

    expect(isStaleEvidence(provider)).toBe(false)
  })

  it('batas usia per provider dipakai, bukan satu angka global', () => {
    const threeDays = 3 * DAY_MS
    expect(
      isStaleEvidence(
        makeProvider('safebrowsing', {
          evidence: { source: 'existing_report', observedAt: null, ageMs: threeDays },
        }),
      ),
    ).toBe(true)
    expect(
      isStaleEvidence(
        makeProvider('urlscan', {
          evidence: { source: 'existing_report', observedAt: null, ageMs: threeDays },
        }),
      ),
    ).toBe(false)
  })
})

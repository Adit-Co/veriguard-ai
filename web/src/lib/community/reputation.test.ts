import { describe, expect, it } from 'vitest'
import {
  computeCommunityReputation,
  reputationLabel,
  type CommunityReputation,
} from './reputation'
import type { CommunityReportEntry, CommunitySummary } from './types'

const NOW = Date.parse('2026-10-20T04:00:00.000Z')

function entry(overrides: Partial<CommunityReportEntry> = {}): CommunityReportEntry {
  return {
    id: 'a'.repeat(32),
    userName: 'Perlapsi Satu',
    reportText: 'Halaman meminta kata sandi lewat formulir palsu.',
    category: 'phishing',
    hostname: 'contoh-situs.id',
    createdAt: new Date(NOW - 86_400_000).toISOString(),
    updatedAt: new Date(NOW - 86_400_000).toISOString(),
    ...overrides,
  }
}

function summary(overrides: Partial<CommunitySummary> = {}): CommunitySummary {
  const reportCount = overrides.reportCount ?? 1
  return {
    hostname: 'contoh-situs.id',
    reportCount,
    reporterCount: overrides.reporterCount ?? reportCount,
    categoryCounts: { phishing: 1 },
    firstReportedAt: new Date(NOW - 86_400_000).toISOString(),
    lastReportedAt: new Date(NOW - 86_400_000).toISOString(),
    lastActivityAt: new Date(NOW - 86_400_000).toISOString(),
    moderationStatus: 'community_reported',
    reviewRequired: false,
    reviewReason: null,
    verificationSource: null,
    verifiedAt: null,
    aggregatesComplete: true,
    ...overrides,
  }
}

function score(reports: CommunityReportEntry[], base?: Partial<CommunitySummary>): number | null {
  return computeCommunityReputation(reports, summary(base), NOW)?.score ?? null
}

describe('Skor Reputasi komunitas', () => {
  it('tidak mengarang skor ketika tidak ada laporan yang cocok', () => {
    expect(computeCommunityReputation([], null, NOW)).toBeNull()
    expect(computeCommunityReputation([], summary({ reportCount: 0 }), NOW)).toBeNull()
  })

  it('deterministik dan tidak bergantung urutan laporan', () => {
    const reports = [entry({ userName: 'A' }), entry({ userName: 'B', category: 'other' })]
    const first = computeCommunityReputation(reports, summary({ reportCount: 2 }), NOW)
    const second = computeCommunityReputation([...reports].reverse(), summary({ reportCount: 2 }), NOW)

    expect(first).toEqual(second)
    expect(first).not.toBeNull()
    expect(computeCommunityReputation(reports, summary({ reportCount: 2 }), NOW)).toEqual(first)
  })

  it('satu laporan komunitas belum menjadikan situs disebut berbahaya', () => {
    const result = computeCommunityReputation([entry()], summary({ reportCount: 1 }), NOW)

    expect(result?.score).toBe(22)
    expect(result?.label).toBe('Indikasi rendah')
    expect(result?.label).not.toMatch(/berbahaya/i)
  })

  it('hanya menghitung pseudonim unik, bukan jumlah laporan', () => {
    const sameAccount = Array.from({ length: 5 }, (_unused, index) =>
      entry({ userName: 'Akun Sama', createdAt: new Date(NOW - (index + 1) * 86_400_000).toISOString() }),
    )
    const result = computeCommunityReputation(
      sameAccount,
      summary({ reportCount: 5, reporterCount: 1 }),
      NOW,
    )

    expect(result?.reporters).toBe(1)
    expect(result?.score).toBe(22)

    const manyAccounts = computeCommunityReputation(
      sameAccount,
      summary({ reportCount: 5, reporterCount: 5 }),
      NOW,
    )
    expect(manyAccounts?.score).toBe(54)
  })

  it('tidak menghitung skor bila ringkasan tidak punya pseudonim pelapor yang sah', () => {
    const reports = [entry()]
    expect(computeCommunityReputation(reports, summary({ reportCount: 1, reporterCount: 0 }), NOW)).toBeNull()
    expect(computeCommunityReputation(reports, summary({ reportCount: 0, reporterCount: 0 }), NOW)).toBeNull()
  })

  it('tidak menghitung skor dari agregat yang tidak lengkap', () => {
    const reports = [entry()]
    const incomplete = summary({
      reportCount: 400,
      reporterCount: 0,
      categoryCounts: {},
      aggregatesComplete: false,
    })

    expect(computeCommunityReputation(reports, incomplete, NOW)).toBeNull()
  })

  it('menaikkan nilai menurut jumlah pseudonim pelapor dan berhenti naik setelah lima', () => {
    const reporters = (count: number): CommunityReputation | null =>
      computeCommunityReputation(
        Array.from({ length: count }, (_unused, index) =>
          entry({ userName: `Pelapor ${index}` }),
        ),
        summary({ reportCount: count }),
        NOW,
      )

    expect(reporters(1)?.score).toBe(22)
    expect(reporters(2)?.score).toBe(30)
    expect(reporters(5)?.score).toBe(54)
    expect(reporters(9)?.score).toBe(54)
  })

  it('jumlah pengaduan saja tidak dapat mencapai label tertinggi', () => {
    // Pseudonim per URL dibuat sekali per akun, tetapi klien dapat menyalin nilai yang
    // terlihat. Meski begitu, bobot pengguna berhenti di 40 sehingga tanpa verifikasi
    // admin skornya tidak menyentuh "sangat tinggi".
    const many = Array.from({ length: 12 }, (_unused, index) =>
      entry({ userName: `Pelapor ${index}` }),
    )
    const result = computeCommunityReputation(many, summary({ reportCount: 12 }), NOW)

    expect(result?.reporters).toBe(12)
    expect(result?.score).toBe(54)
    expect(result?.label).toBe('Indikasi sedang')
    expect(result?.label).not.toMatch(/sangat tinggi|berbahaya/i)
  })

  it('memberi bobot lebih pada laporan yang masih baru', () => {
    const recent = entry({ createdAt: new Date(NOW - 2 * 86_400_000).toISOString() })
    const month = entry({ createdAt: new Date(NOW - 45 * 86_400_000).toISOString() })
    const old = entry({ createdAt: new Date(NOW - 200 * 86_400_000).toISOString() })

    expect(score([recent])).toBe(22)
    expect(score([month])).toBe(18)
    expect(score([old])).toBe(14)
  })

  it('hanya kategori berdampak tinggi yang menambah bobot tuduhan', () => {
    expect(score([entry({ category: 'malware' })], { categoryCounts: { malware: 1 } })).toBe(22)
    expect(score([entry({ category: 'giveaway' })], { categoryCounts: { giveaway: 1 } })).toBe(18)
  })

  it('memakai status moderasi nyata, termasuk penurunan untuk situs yang dibersihkan', () => {
    const reports = [entry()]

    expect(score(reports, { moderationStatus: 'verified_malicious' })).toBe(57)
    expect(score(reports, { moderationStatus: 'under_review' })).toBe(32)
    expect(score(reports, { moderationStatus: 'community_reported' })).toBe(22)
    expect(score(reports, { moderationStatus: 'cleared' })).toBe(2)
  })

  it('memakai agregat backend ketika daftar laporan tidak dikirim lengkap', () => {
    const result = computeCommunityReputation([entry()], summary({ reportCount: 4 }), NOW)

    expect(result?.reporters).toBe(4)
    expect(result?.score).toBe(46)
  })

  it('selalu berada di rentang 0-100 dan memberi label yang sesuai ambang', () => {
    const many = Array.from({ length: 5 }, (_unused, index) => entry({ userName: `P${index}` }))
    const max = computeCommunityReputation(many, summary({ reportCount: 5, moderationStatus: 'verified_malicious' }), NOW)

    expect(max?.score).toBe(89)
    expect(max?.score).toBeLessThanOrEqual(100)
    expect(max?.label).toBe('Indikasi sangat tinggi')
    expect(reputationLabel(80)).toBe('Indikasi sangat tinggi')
    expect(reputationLabel(55)).toBe('Indikasi tinggi')
    expect(reputationLabel(25)).toBe('Indikasi sedang')
    expect(reputationLabel(24)).toBe('Indikasi rendah')
  })

  it('waktu laporan terbaru ikut dikembalikan untuk tampilan', () => {
    const result = computeCommunityReputation(
      [
        entry({ createdAt: new Date(NOW - 10 * 86_400_000).toISOString() }),
        entry({ userName: 'Dua', createdAt: new Date(NOW - 3 * 86_400_000).toISOString() }),
      ],
      summary({ reportCount: 2 }),
      NOW,
    )

    expect(result?.latestReportAt).toBe(new Date(NOW - 3 * 86_400_000).toISOString())
  })
})

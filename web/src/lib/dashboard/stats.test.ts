import { describe, expect, it } from 'vitest'
import type { ScanResult } from '../analysis'
import { buildDashboardStats, riskPercentage } from './stats'

function makeScan(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    id: `scan-${Math.random().toString(36).slice(2)}`,
    createdAt: '2026-10-21T06:00:00.000Z',
    mode: 'link',
    input: 'https://contoh.com',
    displayTarget: 'contoh.com',
    riskScore: 40,
    riskLevel: 'medium',
    headline: 'Indikasi risiko sedang',
    summary: 'Ringkasan pemeriksaan.',
    reasons: [],
    patterns: [],
    recommendations: [],
    technical: [],
    meta: {
      engineVersion: 'test',
      signalCount: 0,
      inputLength: 18,
      aiStatus: 'not_used',
      inputStored: 'full',
    },
    ...overrides,
  }
}

describe('statistik dashboard', () => {
  it('menghitung total, distribusi risiko, dan rata-rata skor', () => {
    const stats = buildDashboardStats([
      makeScan({ riskLevel: 'low', riskScore: 10 }),
      makeScan({ riskLevel: 'high', riskScore: 80 }),
      makeScan({ riskLevel: 'high', riskScore: 70 }),
    ])

    expect(stats.total).toBe(3)
    expect(stats.byRisk).toEqual({ low: 1, medium: 0, high: 2 })
    expect(stats.averageScore).toBe(53)
  })

  it('mengurutkan pola terbanyak lalu label', () => {
    const stats = buildDashboardStats([
      makeScan({
        patterns: [
          { id: 'phishing', label: 'Phishing', description: '', confidence: 'high' },
          { id: 'urgency', label: 'Urgensi palsu', description: '', confidence: 'medium' },
        ],
      }),
      makeScan({
        patterns: [
          { id: 'phishing', label: 'Phishing', description: '', confidence: 'high' },
        ],
      }),
    ])

    expect(stats.topPatterns[0]).toMatchObject({ id: 'phishing', count: 2 })
    expect(stats.topPatterns[1]).toMatchObject({ id: 'urgency', count: 1 })
  })

  it('membatasi riwayat terbaru dan mengurutkannya', () => {
    const stats = buildDashboardStats(
      [
        makeScan({ id: 'lama', createdAt: '2026-10-20T06:00:00.000Z' }),
        makeScan({ id: 'baru', createdAt: '2026-10-22T06:00:00.000Z' }),
        makeScan({ id: 'tengah', createdAt: '2026-10-21T06:00:00.000Z' }),
      ],
      2,
    )

    expect(stats.latest.map((scan) => scan.id)).toEqual(['baru', 'tengah'])
  })

  it('menangani riwayat kosong', () => {
    expect(buildDashboardStats([])).toEqual({
      total: 0,
      byRisk: { low: 0, medium: 0, high: 0 },
      averageScore: 0,
      topPatterns: [],
      latest: [],
    })
    expect(riskPercentage(0, 0)).toBe(0)
    expect(riskPercentage(2, 3)).toBe(67)
  })
})

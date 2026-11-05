import { describe, expect, it } from 'vitest'
import { buildModerationMetrics, buildModerationTrend } from './stats'
import type { AdminModerationReport, ModerationStatus } from './types'

function report(
  id: string,
  status: ModerationStatus | null,
  createdAt: string | null = '2026-10-25T01:00:00.000Z',
): AdminModerationReport {
  return {
    id,
    urlHash: `hash-${id}`,
    userName: 'Pengguna Uji',
    reportText: 'Laporan uji',
    category: 'phishing',
    reportedUrl: 'https://contoh.test/',
    hostname: 'contoh.test',
    createdAt,
    moderation: status
      ? {
          status,
          note: '',
          updatedAt: '2026-10-25T02:00:00.000Z',
          updatedBy: 'admin-uji',
        }
      : null,
  }
}

describe('metrik moderasi', () => {
  it('menghitung setiap status dan memisahkan yang belum diputuskan', () => {
    const metrics = buildModerationMetrics([
      report('1', null),
      report('2', 'pending'),
      report('3', 'review'),
      report('4', 'confirmed_malicious'),
      report('5', 'inconclusive'),
      report('6', 'rejected'),
    ])

    expect(metrics).toEqual({
      total: 6,
      unmoderated: 1,
      pending: 1,
      review: 1,
      confirmed: 1,
      inconclusive: 1,
      rejected: 1,
      awaiting: 3,
      decided: 3,
    })
  })

  it('mengembalikan nol untuk antrean kosong', () => {
    expect(buildModerationMetrics([])).toEqual({
      total: 0,
      unmoderated: 0,
      pending: 0,
      review: 0,
      confirmed: 0,
      inconclusive: 0,
      rejected: 0,
      awaiting: 0,
      decided: 0,
    })
  })
})

describe('tren moderasi tujuh hari WITA', () => {
  const now = Date.parse('2026-10-25T10:00:00+08:00')

  it('membuat tujuh ember berurutan meski tidak ada laporan', () => {
    const trend = buildModerationTrend([], now)

    expect(trend.map((bucket) => bucket.dayKey)).toEqual([
      '2026-10-19',
      '2026-10-20',
      '2026-10-21',
      '2026-10-22',
      '2026-10-23',
      '2026-10-24',
      '2026-10-25',
    ])
    expect(trend.every((bucket) => bucket.total === 0)).toBe(true)
  })

  it('mengelompokkan laporan menurut hari WITA dan status saat ini', () => {
    const trend = buildModerationTrend(
      [
        report('today', 'pending', '2026-10-24T16:00:00.000Z'),
        report('yesterday', 'review', '2026-10-24T15:59:00.000Z'),
        report('confirmed', 'confirmed_malicious', '2026-10-20T03:00:00.000Z'),
        report('rejected', 'rejected', '2026-10-18T16:00:00.000Z'),
        report('outside', 'pending', '2026-10-18T15:59:00.000Z'),
        report('invalid', 'pending', 'bukan-waktu'),
        report('missing', 'pending', null),
      ],
      now,
    )

    const byDay = new Map(trend.map((bucket) => [bucket.dayKey, bucket]))
    expect(byDay.get('2026-10-19')?.concluded).toBe(1)
    expect(byDay.get('2026-10-20')?.confirmed).toBe(1)
    expect(byDay.get('2026-10-24')?.awaiting).toBe(1)
    expect(byDay.get('2026-10-25')?.awaiting).toBe(1)
    expect(trend.reduce((sum, bucket) => sum + bucket.total, 0)).toBe(4)
  })

  it('membedakan status akhir yang dikonfirmasi dari yang selesai tanpa konfirmasi', () => {
    const trend = buildModerationTrend(
      [
        report('confirmed', 'confirmed_malicious', '2026-10-23T02:00:00.000Z'),
        report('inconclusive', 'inconclusive', '2026-10-23T03:00:00.000Z'),
        report('rejected', 'rejected', '2026-10-23T04:00:00.000Z'),
        report('pending', null, '2026-10-23T05:00:00.000Z'),
      ],
      now,
    )

    const bucket = trend.find((item) => item.dayKey === '2026-10-23')
    expect(bucket).toMatchObject({
      awaiting: 1,
      confirmed: 1,
      concluded: 2,
      total: 4,
    })
  })
})

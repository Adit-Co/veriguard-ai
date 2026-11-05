import type { AdminModerationReport, ModerationStatus } from './types'

const WITA_OFFSET_MS = 8 * 60 * 60 * 1000
const DAY_MS = 24 * 60 * 60 * 1000
const TREND_DAYS = 7

const dayLabelFormatter = new Intl.DateTimeFormat('id-ID', {
  day: 'numeric',
  month: 'short',
  timeZone: 'Asia/Makassar',
})

export type ModerationMetrics = {
  total: number
  unmoderated: number
  pending: number
  review: number
  confirmed: number
  inconclusive: number
  rejected: number
  awaiting: number
  decided: number
}

export function buildModerationMetrics(
  reports: AdminModerationReport[],
): ModerationMetrics {
  const metrics: ModerationMetrics = {
    total: reports.length,
    unmoderated: 0,
    pending: 0,
    review: 0,
    confirmed: 0,
    inconclusive: 0,
    rejected: 0,
    awaiting: 0,
    decided: 0,
  }

  for (const report of reports) {
    const status = report.moderation?.status
    if (status === undefined) {
      metrics.unmoderated += 1
      continue
    }
    if (status === 'pending') metrics.pending += 1
    else if (status === 'review') metrics.review += 1
    else if (status === 'confirmed_malicious') metrics.confirmed += 1
    else if (status === 'inconclusive') metrics.inconclusive += 1
    else if (status === 'rejected') metrics.rejected += 1
  }

  metrics.awaiting = metrics.unmoderated + metrics.pending + metrics.review
  metrics.decided = metrics.confirmed + metrics.inconclusive + metrics.rejected
  return metrics
}

export type ModerationTrendBucket = {
  dayKey: string
  label: string
  dateLabel: string
  awaiting: number
  confirmed: number
  concluded: number
  total: number
}

function witaDayKey(ms: number): string {
  return new Date(ms + WITA_OFFSET_MS).toISOString().slice(0, 10)
}

function bucketOf(status: ModerationStatus | undefined): 'awaiting' | 'confirmed' | 'concluded' {
  if (status === 'confirmed_malicious') return 'confirmed'
  if (status === 'inconclusive' || status === 'rejected') return 'concluded'
  return 'awaiting'
}

/**
 * Tujuh hari WITA terakhir, dihitung dari waktu kirim laporan. Warna batang memakai
 * status moderasi saat ini, sehingga laporan lama yang baru diputuskan tetap terlihat
 * pada hari laporannya masuk. Tidak ada data contoh saat antrean kosong.
 */
export function buildModerationTrend(
  reports: AdminModerationReport[],
  nowMs: number = Date.now(),
): ModerationTrendBucket[] {
  const currentDayStart = Math.floor((nowMs + WITA_OFFSET_MS) / DAY_MS) * DAY_MS
  const buckets: ModerationTrendBucket[] = []
  const byKey = new Map<string, ModerationTrendBucket>()

  for (let offset = TREND_DAYS - 1; offset >= 0; offset -= 1) {
    const shiftedDayStart = currentDayStart - offset * DAY_MS
    const dayKey = witaDayKey(shiftedDayStart)
    const date = new Date(`${dayKey}T00:00:00+08:00`)
    const bucket: ModerationTrendBucket = {
      dayKey,
      label: dayLabelFormatter.format(date),
      dateLabel: new Intl.DateTimeFormat('id-ID', {
        weekday: 'short',
        day: 'numeric',
        month: 'short',
        timeZone: 'Asia/Makassar',
      }).format(date),
      awaiting: 0,
      confirmed: 0,
      concluded: 0,
      total: 0,
    }
    buckets.push(bucket)
    byKey.set(dayKey, bucket)
  }

  for (const report of reports) {
    if (!report.createdAt) continue
    const time = Date.parse(report.createdAt)
    if (Number.isNaN(time)) continue
    const bucket = byKey.get(witaDayKey(time))
    if (!bucket) continue
    const group = bucketOf(report.moderation?.status)
    bucket[group] += 1
    bucket.total += 1
  }

  return buckets
}

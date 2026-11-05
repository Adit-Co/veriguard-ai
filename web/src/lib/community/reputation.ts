import type { CommunityReportEntry, CommunitySummary } from './types'

/**
 * Rumus Skor Reputasi (deterministik, 0-100, hanya dari laporan komunitas nyata):
 *
 *   reports          = ringkasan.reportCount (laporan aktif untuk URL ini)
 *   reporters        = min(ringkasan.reporterCount, reports)  -> pseudonim unik, bukan jumlah kiriman
 *   userWeight       = min(reporters, 5) * 8                  -> 0..40
 *   recencyWeight    = 10 (<=30 hari) | 6 (<=90 hari) | 2     -> 2..10
 *   allegationWeight = 4 bila ringkasan memuat kategori berdampak tinggi -> 0 | 4
 *   moderationWeight = verified_malicious +35 | under_review +10
 *                      | community_reported 0 | cleared -20  -> -20..35
 *   score            = clamp(0, 100, userWeight + recencyWeight
 *                            + allegationWeight + moderationWeight)
 *
 * reportCount tidak pernah menambah skor secara langsung: akun yang sama dapat mengirim
 * satu laporan per hari, sedangkan bobot pengguna hanya bertambah lewat pseudonim berbeda.
 * Pseudonim dibuat oleh klien dan dapat disalin, jadi bobot ini adalah heuristik, bukan
 * bukti jumlah akun unik. Tanpa laporan aktif, hasilnya null (bukan 0) supaya keadaan kosong tidak dibaca sebagai
 * "reputasi nol", dan kegagalan pengambilan data ditangani terpisah oleh pemanggil.
 */

const HIGH_IMPACT_CATEGORIES = new Set<string>([
  'phishing',
  'malware',
  'impersonation',
  'investment_job',
])

const MODERATION_WEIGHT: Record<string, number> = {
  verified_malicious: 35,
  under_review: 10,
  community_reported: 0,
  cleared: -20,
}

export type CommunityReputation = {
  score: number
  reporters: number
  label: string
  latestReportAt: string | null
}

export function reputationLabel(score: number): string {
  if (score >= 80) return 'Indikasi sangat tinggi'
  if (score >= 55) return 'Indikasi tinggi'
  if (score >= 25) return 'Indikasi sedang'
  return 'Indikasi rendah'
}

function timestampOf(value: string | null | undefined): number | null {
  if (!value) return null
  const parsed = Date.parse(value)
  return Number.isNaN(parsed) ? null : parsed
}

function newestReportTime(
  reports: CommunityReportEntry[],
  summary: CommunitySummary,
): number | null {
  let newest: number | null = null
  for (const report of reports) {
    const value = timestampOf(report.createdAt)
    if (value === null) continue
    if (newest === null || value > newest) newest = value
  }
  // Daftar konteks dibatasi jumlahnya; bila kosong, waktu agregat backend tetap data nyata.
  return newest ?? timestampOf(summary.lastReportedAt)
}

export function computeCommunityReputation(
  reports: CommunityReportEntry[],
  summary: CommunitySummary | null,
  now: number = Date.now(),
): CommunityReputation | null {
  const reportCount = summary?.reportCount ?? 0
  const reporters = Math.min(summary?.reporterCount ?? 0, reportCount)
  if (!summary || !summary.aggregatesComplete || reportCount <= 0 || reporters <= 0) return null

  const userWeight = Math.min(reporters, 5) * 8

  const latest = newestReportTime(reports, summary)
  let recencyWeight = 2
  if (latest !== null) {
    const ageDays = Math.max(0, (now - latest) / 86_400_000)
    recencyWeight = ageDays <= 30 ? 10 : ageDays <= 90 ? 6 : 2
  }

  const highImpact =
    Object.entries(summary.categoryCounts).some(
      ([category, count]) => typeof count === 'number' && count > 0 && HIGH_IMPACT_CATEGORIES.has(category),
    ) || reports.some((report) => HIGH_IMPACT_CATEGORIES.has(report.category))
  const allegationWeight = highImpact ? 4 : 0

  const moderationWeight = MODERATION_WEIGHT[summary.moderationStatus] ?? 0

  const score = Math.max(
    0,
    Math.min(100, userWeight + recencyWeight + allegationWeight + moderationWeight),
  )

  return {
    score,
    reporters,
    label: reputationLabel(score),
    latestReportAt:
      latest === null
        ? (summary.lastReportedAt ?? summary.lastActivityAt)
        : new Date(latest).toISOString(),
  }
}

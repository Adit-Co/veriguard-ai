import type { RiskLevel, ScanResult } from '../analysis'

export type PatternSummary = {
  id: string
  label: string
  count: number
}

export type DashboardStats = {
  total: number
  byRisk: Record<RiskLevel, number>
  averageScore: number
  topPatterns: PatternSummary[]
  latest: ScanResult[]
}

function timeValue(value: string): number {
  const time = Date.parse(value)
  return Number.isNaN(time) ? 0 : time
}

export function buildDashboardStats(scans: ScanResult[], latestLimit = 5): DashboardStats {
  const byRisk: Record<RiskLevel, number> = { low: 0, medium: 0, high: 0 }
  const patterns = new Map<string, PatternSummary>()
  let scoreTotal = 0

  for (const scan of scans) {
    byRisk[scan.riskLevel] += 1
    scoreTotal += scan.riskScore

    for (const pattern of scan.patterns) {
      const existing = patterns.get(pattern.id)
      if (existing) {
        existing.count += 1
      } else {
        patterns.set(pattern.id, {
          id: pattern.id,
          label: pattern.label,
          count: 1,
        })
      }
    }
  }

  const latest = [...scans]
    .sort((a, b) => timeValue(b.createdAt) - timeValue(a.createdAt))
    .slice(0, latestLimit)

  const topPatterns = [...patterns.values()].sort(
    (a, b) => b.count - a.count || a.label.localeCompare(b.label, 'id'),
  )

  return {
    total: scans.length,
    byRisk,
    averageScore: scans.length === 0 ? 0 : Math.round(scoreTotal / scans.length),
    topPatterns,
    latest,
  }
}

export function riskPercentage(count: number, total: number): number {
  if (total <= 0) return 0
  return Math.round((count / total) * 100)
}

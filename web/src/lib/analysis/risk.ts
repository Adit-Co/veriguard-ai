import type { RiskLevel } from './types'

export type RiskVisual = {
  label: string
  shortLabel: string
  description: string
  badgeTone: 'low' | 'medium' | 'high'
  panelClass: string
  iconClass: string
  scoreClass: string
  barClass: string
}

export const RISK_VISUALS: Record<RiskLevel, RiskVisual> = {
  low: {
    label: 'Risiko rendah',
    shortLabel: 'Rendah',
    description:
      'Tidak banyak indikator risiko ditemukan. Ini bukan jaminan bahwa tautan atau pesan tersebut aman.',
    badgeTone: 'low',
    panelClass: 'border-risk-low-line bg-risk-low-bg',
    iconClass: 'border-risk-low-line bg-white text-risk-low',
    scoreClass: 'text-risk-low',
    barClass: 'bg-risk-low',
  },
  medium: {
    label: 'Risiko sedang',
    shortLabel: 'Sedang',
    description:
      'Ada beberapa indikator yang perlu diverifikasi. Jangan bertindak sebelum memastikan melalui kanal resmi.',
    badgeTone: 'medium',
    panelClass: 'border-risk-medium-line bg-risk-medium-bg',
    iconClass: 'border-risk-medium-line bg-white text-risk-medium',
    scoreClass: 'text-risk-medium',
    barClass: 'bg-risk-medium',
  },
  high: {
    label: 'Risiko tinggi',
    shortLabel: 'Tinggi',
    description:
      'Beberapa indikator yang saling menguatkan mengarah pada upaya penipuan. Hentikan interaksi dan verifikasi melalui kanal resmi.',
    badgeTone: 'high',
    panelClass: 'border-risk-high-line bg-risk-high-bg',
    iconClass: 'border-risk-high-line bg-white text-risk-high',
    scoreClass: 'text-risk-high',
    barClass: 'bg-risk-high',
  },
}

export function riskLabel(level: RiskLevel): string {
  return RISK_VISUALS[level].label
}

export function riskScoreText(score: number): string {
  return `${score}/100`
}

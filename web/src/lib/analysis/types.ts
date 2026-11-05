export type ScanMode = 'link' | 'message'

export type RiskLevel = 'low' | 'medium' | 'high'

export type ReasonSeverity = 'info' | 'warning' | 'danger'

export type ReasonCategory =
  | 'url-structure'
  | 'domain'
  | 'obfuscation'
  | 'request'
  | 'urgency'
  | 'impersonation'
  | 'transaction'
  | 'language'

export type AnalysisReason = {
  id: string
  label: string
  detail: string
  severity: ReasonSeverity
  weight: number
  category: ReasonCategory
}

export type PatternId =
  | 'phishing'
  | 'fake_login'
  | 'giveaway'
  | 'marketplace'
  | 'impersonation'
  | 'urgency'
  | 'investment'
  | 'job_scam'
  | 'otp_theft'

export type PatternConfidence = 'low' | 'medium' | 'high'

export type DetectedPattern = {
  id: PatternId
  label: string
  description: string
  confidence: PatternConfidence
}

export type TechnicalTone = 'neutral' | 'warning' | 'danger'

export type TechnicalItem = {
  label: string
  value: string
  tone?: TechnicalTone
}

export type AnalysisMeta = {
  engineVersion: string
  signalCount: number
  inputLength: number
  aiStatus: 'not_used'
  inputStored?: 'full' | 'redacted'
}

export type ScanDraft = {
  mode: ScanMode
  input: string
  displayTarget: string
  riskScore: number
  riskLevel: RiskLevel
  headline: string
  summary: string
  reasons: AnalysisReason[]
  patterns: DetectedPattern[]
  recommendations: string[]
  technical: TechnicalItem[]
  meta: AnalysisMeta
}

export type ScanResult = ScanDraft & {
  id: string
  createdAt: string
}

export type AnalysisInput = {
  mode: ScanMode
  value: string
}

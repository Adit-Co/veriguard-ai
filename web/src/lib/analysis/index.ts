import { analyzeLink } from './link'
import { analyzeMessage } from './message'
import type { AnalysisInput, ScanDraft } from './types'

export type {
  AnalysisInput,
  AnalysisMeta,
  AnalysisReason,
  DetectedPattern,
  PatternConfidence,
  PatternId,
  ReasonCategory,
  ReasonSeverity,
  RiskLevel,
  ScanDraft,
  ScanMode,
  ScanResult,
  TechnicalItem,
  TechnicalTone,
} from './types'

export { analyzeLink, detectBrand, getRegistrableDomain } from './link'
export { analyzeMessage } from './message'
export { RISK_THRESHOLDS, riskLevelFromScore } from './result'
export { RISK_VISUALS, riskLabel, riskScoreText } from './risk'
export {
  AnalysisError,
  MAX_LINK_LENGTH,
  MAX_MESSAGE_LENGTH,
  MIN_MESSAGE_LENGTH,
  validateInput,
  validateLinkInput,
  validateMessageInput,
} from './validate'
export type { ValidationResult } from './validate'

export function analyze(input: AnalysisInput): ScanDraft {
  return input.mode === 'link' ? analyzeLink(input.value) : analyzeMessage(input.value)
}

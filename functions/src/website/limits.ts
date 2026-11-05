import { STATE_MAX_KEYS, createSlidingWindowLimiter } from '../state/stores.js'
import type { RateLimitDecision } from '../state/stores.js'

export const SITE_ANALYSIS_RATE_LIMIT = {
  windowMs: 10 * 60 * 1_000,
  maxAnalyses: 4,
} as const

export const SITE_ANALYSIS_MAX_TRACKED_KEYS = STATE_MAX_KEYS

const usage = createSlidingWindowLimiter(SITE_ANALYSIS_MAX_TRACKED_KEYS)

export function consumeSiteAnalysisRateLimit(
  key: string,
  now: number = Date.now(),
  limit: number = SITE_ANALYSIS_RATE_LIMIT.maxAnalyses,
  windowMs: number = SITE_ANALYSIS_RATE_LIMIT.windowMs,
): RateLimitDecision {
  return usage.consume(key, now, limit, windowMs)
}

export function resetSiteAnalysisRateLimit(): void {
  usage.reset()
}

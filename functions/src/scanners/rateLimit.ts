import { STATE_MAX_KEYS, createSlidingWindowLimiter } from '../state/stores.js'
import type { RateLimitDecision } from '../state/stores.js'

export const SCAN_RATE_LIMIT = {
  windowMs: 10 * 60 * 1_000,
  maxScans: 6,
} as const

export const SCAN_RATE_LIMIT_MAX_BUCKETS = STATE_MAX_KEYS

const usage = createSlidingWindowLimiter(SCAN_RATE_LIMIT_MAX_BUCKETS)

export function consumeScanRateLimit(
  uid: string,
  now = Date.now(),
): RateLimitDecision {
  return usage.consume(uid, now, SCAN_RATE_LIMIT.maxScans, SCAN_RATE_LIMIT.windowMs)
}

export function resetScanRateLimit(): void {
  usage.reset()
}

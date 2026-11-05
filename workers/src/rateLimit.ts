import {
  STATE_MAX_KEYS,
  createFixedWindowCounter,
  type RateLimitDecision,
} from '../../functions/src/state/stores.js'

// Batas tepi (per-IP / per-uid). Nilai default dan jendela waktunya ditentukan pemanggil;
// berkas ini hanya menyediakan penyimpanan hitungannya.
export const EDGE_RATE_LIMIT_MAX_BUCKETS = STATE_MAX_KEYS

const counters = createFixedWindowCounter(EDGE_RATE_LIMIT_MAX_BUCKETS)

export function consumeEdgeRateLimit(
  key: string,
  limit: number,
  windowMs: number,
  now = Date.now(),
): RateLimitDecision {
  return counters.consume(key, limit, windowMs, now)
}

export function resetEdgeRateLimit(): void {
  counters.reset()
}

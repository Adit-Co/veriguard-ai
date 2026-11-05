import type { RateLimitDecision } from '../../../functions/src/state/stores.js'
import type { ScanStateStore } from '../../src/state/store.js'

/**
 * Helper tes untuk P1-3: StoreDependency Worker kini berupa satu objek ScanStateStore.
 * Spy ini merekam setiap panggilan dan mengembalikan keputusan yang ditentukan kasus uji,
 * tanpa menyentuh penyimpanan memori modul maupun Durable Object.
 */
export type CounterCall = { key: string; limit: number; windowMs: number; now: number }
export type SiteWindowCall = { key: string; now: number }

export type StateStoreSpy = {
  store: ScanStateStore
  counters: CounterCall[]
  siteWindows: SiteWindowCall[]
  clearanceChecks: string[]
  clearanceIssues: string[]
}

export function createStateStoreSpy(options: {
  allow?: boolean
  used?: number
  retryAfterSeconds?: number
  counter?: (call: CounterCall) => RateLimitDecision
  siteWindow?: (call: SiteWindowCall) => RateLimitDecision
  clearanceActive?: boolean
} = {}): StateStoreSpy {
  const counters: CounterCall[] = []
  const siteWindows: SiteWindowCall[] = []
  const clearanceChecks: string[] = []
  const clearanceIssues: string[] = []
  // Izin yang diterbitkan spy tetap hidup untuk permintaan berikutnya, sama seperti
  // penyimpanan asli: tanpa ini tes "tidak menantang ulang" tidak bisa diekspresikan.
  const issued = new Set<string>()

  const decide = (): RateLimitDecision => ({
    allowed: options.allow !== false,
    retryAfterSeconds: options.retryAfterSeconds ?? 0,
    ...(options.used === undefined ? {} : { used: options.used }),
  })

  const store: ScanStateStore = {
    async consumeCounter(key, limit, windowMs, now) {
      const call = { key, limit, windowMs, now }
      counters.push(call)
      if (options.counter) return options.counter(call)
      return decide()
    },
    async consumeSiteWindow(key, now) {
      const call = { key, now }
      siteWindows.push(call)
      if (options.siteWindow) return options.siteWindow(call)
      return decide()
    },
    async hasClearance(key) {
      clearanceChecks.push(key)
      return options.clearanceActive === true || issued.has(key)
    },
    async issueClearance(key) {
      clearanceIssues.push(key)
      issued.add(key)
    },
  }

  return { store, counters, siteWindows, clearanceChecks, clearanceIssues }
}

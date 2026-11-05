import { beforeEach, describe, expect, it } from 'vitest'
import {
  SCAN_RATE_LIMIT,
  SCAN_RATE_LIMIT_MAX_BUCKETS,
  consumeScanRateLimit,
  resetScanRateLimit,
} from '../src/scanners/rateLimit.js'

describe('batas laju scan', () => {
  beforeEach(() => {
    resetScanRateLimit()
  })

  it('menolak scan berlebih dalam jendela waktu dan memulihkan setelah jendela lewat', () => {
    const now = 1_700_000_000_000

    for (let index = 0; index < SCAN_RATE_LIMIT.maxScans; index += 1) {
      expect(consumeScanRateLimit('pengguna', now).allowed).toBe(true)
    }

    const blocked = consumeScanRateLimit('pengguna', now)
    expect(blocked.allowed).toBe(false)
    expect(blocked.retryAfterSeconds).toBe(Math.ceil(SCAN_RATE_LIMIT.windowMs / 1_000))
    expect(consumeScanRateLimit('pengguna', now + SCAN_RATE_LIMIT.windowMs + 1).allowed).toBe(true)
  })

  it('menjaga tabel tetap terbatas dan menolak uid baru saat tabel penuh', () => {
    const now = 1_700_000_000_000

    for (let index = 0; index < SCAN_RATE_LIMIT_MAX_BUCKETS; index += 1) {
      expect(consumeScanRateLimit(`pengguna-${index}`, now).allowed).toBe(true)
    }

    const rejected = consumeScanRateLimit('pengguna-baru', now)
    expect(rejected.allowed).toBe(false)
    expect(rejected.retryAfterSeconds).toBeGreaterThan(0)
    expect(consumeScanRateLimit('pengguna-0', now).allowed).toBe(true)
    expect(
      consumeScanRateLimit('pengguna-baru', now + SCAN_RATE_LIMIT.windowMs + 1).allowed,
    ).toBe(true)
  })
})

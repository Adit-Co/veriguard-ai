import { beforeEach, describe, expect, it } from 'vitest'
import {
  EDGE_RATE_LIMIT_MAX_BUCKETS,
  consumeEdgeRateLimit,
  resetEdgeRateLimit,
} from '../src/rateLimit.js'

const NOW = 1_700_000_000_000

beforeEach(() => {
  resetEdgeRateLimit()
})

describe('rate limit edge', () => {
  it('membatasi jumlah bucket dan menolak kunci baru saat tabel penuh', () => {
    for (let index = 0; index < EDGE_RATE_LIMIT_MAX_BUCKETS; index += 1) {
      expect(consumeEdgeRateLimit(`ip:${index}`, 1, 60_000, NOW).allowed).toBe(true)
    }

    expect(consumeEdgeRateLimit('ip:baru', 1, 60_000, NOW)).toEqual({
      allowed: false,
      retryAfterSeconds: 60,
    })
    // Bucket yang sudah tercatat tidak dikorbankan demi kunci baru.
    expect(consumeEdgeRateLimit('ip:0', 1, 60_000, NOW)).toEqual({
      allowed: false,
      retryAfterSeconds: 60,
      used: 1,
    })
  })

  it('menerima kunci baru lagi setelah bucket lama kedaluwarsa', () => {
    for (let index = 0; index < EDGE_RATE_LIMIT_MAX_BUCKETS; index += 1) {
      consumeEdgeRateLimit(`ip:${index}`, 1, 60_000, NOW)
    }
    expect(consumeEdgeRateLimit('ip:baru', 1, 60_000, NOW).allowed).toBe(false)

    const afterWindow = NOW + 60_001
    expect(consumeEdgeRateLimit('ip:baru', 1, 60_000, afterWindow).allowed).toBe(true)
  })

  it('menghitung permintaan berulang pada jendela yang sama', () => {
    // `used` adalah jumlah permintaan tercatat setelah permintaan ini; gerbang CAPTCHA adaptif
    // membacanya untuk menaikkan tingkat verifikasi sebelum batas keras 429.
    expect(consumeEdgeRateLimit('ip:sama', 2, 60_000, NOW)).toEqual({
      allowed: true,
      retryAfterSeconds: 0,
      used: 1,
    })
    expect(consumeEdgeRateLimit('ip:sama', 2, 60_000, NOW).allowed).toBe(true)
    expect(consumeEdgeRateLimit('ip:sama', 2, 60_000, NOW)).toEqual({
      allowed: false,
      retryAfterSeconds: 60,
      used: 2,
    })
  })
})

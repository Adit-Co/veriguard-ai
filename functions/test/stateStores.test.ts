import { describe, expect, it } from 'vitest'
import {
  createExpiryRegistry,
  createFixedWindowCounter,
  createSlidingWindowLimiter,
} from '../src/state/stores.js'

const NOW = 1_700_000_000_000
const WINDOW_MS = 60_000

describe('P1-3: primitif state atomik', () => {
  describe('pencacah jendela tetap', () => {
    it('menutup gerbang ketika batas nol atau negatif, bukan membukanya', () => {
      const counters = createFixedWindowCounter()

      // Ini inti perbaikan VGM: dulu `limit <= 0` berarti "tanpa batas".
      expect(counters.consume('ip:a', 0, WINDOW_MS, NOW).allowed).toBe(false)
      expect(counters.consume('ip:a', -1, WINDOW_MS, NOW).allowed).toBe(false)
      expect(counters.consume('ip:a', 5, 0, NOW).allowed).toBe(false)
      expect(counters.consume('ip:a', 5, -1, NOW).allowed).toBe(false)
    })

    it('menghitung dalam satu jendela dan memulai jendela baru setelahnya', () => {
      const counters = createFixedWindowCounter()

      expect(counters.consume('ip:a', 2, WINDOW_MS, NOW)).toEqual({
        allowed: true,
        retryAfterSeconds: 0,
        used: 1,
      })
      expect(counters.consume('ip:a', 2, WINDOW_MS, NOW).used).toBe(2)
      expect(counters.consume('ip:a', 2, WINDOW_MS, NOW).allowed).toBe(false)

      // Jendela tetap: setelah resetAt terlewati, pencacah mulai dari satu lagi.
      expect(counters.consume('ip:a', 2, WINDOW_MS, NOW + WINDOW_MS).used).toBe(1)
    })

    it('menolak kunci baru saat tabel penuh tanpa mengorbankan kunci yang tercatat', () => {
      const counters = createFixedWindowCounter(3)

      for (const key of ['ip:1', 'ip:2', 'ip:3']) {
        expect(counters.consume(key, 1, WINDOW_MS, NOW).allowed).toBe(true)
      }

      expect(counters.consume('ip:4', 1, WINDOW_MS, NOW)).toEqual({
        allowed: false,
        retryAfterSeconds: WINDOW_MS / 1_000,
      })
      // Kunci yang sudah punya kuota habis tetap ditolak karena batasnya, bukan karena tabel.
      expect(counters.consume('ip:1', 1, WINDOW_MS, NOW)).toMatchObject({ allowed: false, used: 1 })

      // Setelah jendela kunci lama lewat, kunci baru diterima lagi.
      expect(counters.consume('ip:4', 1, WINDOW_MS, NOW + WINDOW_MS + 1).allowed).toBe(true)
    })

    it('membatasi nilai Retry-After agar header tetap masuk akal', () => {
      const counters = createFixedWindowCounter()
      const decision = counters.consume('ip:a', 1, 7 * 24 * 60 * 60 * 1_000, NOW)
      expect(decision.allowed).toBe(true)

      const blocked = counters.consume('ip:a', 1, 7 * 24 * 60 * 60 * 1_000, NOW)
      expect(blocked.retryAfterSeconds).toBe(3_600)
    })
  })

  describe('batas jendela geser', () => {
    it('menolak setelah kuota jendela habis dan pulih per cap waktu', () => {
      const window = createSlidingWindowLimiter()
      const timestamps = [NOW, NOW + 1_000, NOW + 2_000, NOW + 3_000]

      for (const timestamp of timestamps) {
        expect(window.consume('site:a', timestamp, 4, 600_000).allowed).toBe(true)
      }
      const blocked = window.consume('site:a', NOW + 4_000, 4, 600_000)
      expect(blocked.allowed).toBe(false)
      expect(blocked.used).toBe(4)
      expect(blocked.retryAfterSeconds).toBe(596)

      // Sebagian cap waktu sudah keluar jendela: slot yang tersisa dihitung ulang.
      const partial = window.consume('site:a', NOW + 600_001, 4, 600_000)
      expect(partial.allowed).toBe(true)
      expect(partial.used).toBe(4)

      // Setelah seluruh cap waktu lama terlewat, yang tersisa hanya slot dari langkah
      // sebelumnya, jadi kuota kembali panjang.
      const fresh = window.consume('site:a', NOW + 605_001, 4, 600_000)
      expect(fresh.allowed).toBe(true)
      expect(fresh.used).toBe(2)
    })

    it('menutup gerbang untuk batas nol dan menolak kunci baru saat tabel penuh', () => {
      const window = createSlidingWindowLimiter(2)

      expect(window.consume('site:a', NOW, 0, 600_000).allowed).toBe(false)
      expect(window.consume('site:a', NOW, 1, 600_000).allowed).toBe(true)
      expect(window.consume('site:b', NOW, 1, 600_000).allowed).toBe(true)
      expect(window.consume('site:c', NOW, 1, 600_000)).toEqual({
        allowed: false,
        retryAfterSeconds: 600,
      })
    })
  })

  describe('registry batas waktu', () => {
    it('issue memperbarui izin dan has menolak setelah kedaluwarsa', () => {
      const registry = createExpiryRegistry()

      expect(registry.has('k', NOW)).toBe(false)
      expect(registry.issue('k', NOW, 1_000)).toBe(true)
      expect(registry.has('k', NOW + 999)).toBe(true)
      expect(registry.has('k', NOW + 1_000)).toBe(false)

      // Izin yang sama dapat diperpanjang selama belum kedaluwarsa.
      registry.issue('k', NOW, 1_000)
      registry.issue('k', NOW + 500, 1_000)
      expect(registry.has('k', NOW + 1_200)).toBe(true)
    })

    it('claim hanya sekali untuk kunci yang sama dan mengembalikan false saat tabel penuh', () => {
      const registry = createExpiryRegistry(2)

      expect(registry.claim('t1', NOW, 1_000)).toBe(true)
      expect(registry.claim('t1', NOW, 1_000)).toBe(false)
      expect(registry.claim('t2', NOW, 1_000)).toBe(true)
      expect(registry.claim('t3', NOW, 1_000)).toBe(false)

      // Setelah kedaluwarsa, kunci lama memberi tempat dan boleh diklaim lagi.
      expect(registry.claim('t1', NOW + 1_000, 1_000)).toBe(true)
    })
  })
})

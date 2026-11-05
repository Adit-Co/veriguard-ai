export type RateLimitDecision = {
  allowed: boolean
  retryAfterSeconds: number
  // Jumlah permintaan yang tercatat di jendela berjalan SETELAH permintaan ini. Dipakai
  // gerbang CAPTCHA adaptif untuk menaikkan tingkat verifikasi sebelum batas keras.
  used?: number
}

// Batas jumlah kunci per tabel. Semua struktur di berkas ini hanya menyimpan keadaan
// sementara (hitungan/izin) sehingga tabel yang penuh harus menolak kunci BARU, bukan
// mengusir entri yang masih hidup: mengusir entri hidup membuka jalur bypass batas.
export const STATE_MAX_KEYS = 5_000

const MAX_RETRY_AFTER_SECONDS = 3_600

function retryAfter(ms: number): number {
  if (!Number.isFinite(ms) || ms <= 0) return 1
  return Math.min(MAX_RETRY_AFTER_SECONDS, Math.max(1, Math.ceil(ms / 1_000)))
}

export type FixedWindowCounter = {
  consume(key: string, limit: number, windowMs: number, now: number): RateLimitDecision
  size(): number
  reset(): void
}

/**
 * Pencacah jendela tetap. Satu operasi read-modify-write sinkron, jadi pemanggil yang
 * menjalankannya di dalam satu thread (isolates Worker, Durable Object, atau Node host)
 * tidak pernah kehilangan increment di sela await.
 */
export function createFixedWindowCounter(
  maxKeys: number = STATE_MAX_KEYS,
): FixedWindowCounter {
  const buckets = new Map<string, { count: number; resetAt: number }>()

  const cleanup = (now: number): void => {
    if (buckets.size < maxKeys) return
    for (const [key, bucket] of buckets) {
      if (bucket.resetAt <= now) buckets.delete(key)
    }
  }

  return {
    consume(key, limit, windowMs, now) {
      // P1-3: limit <= 0 berarti TIDAK ADA kuota, bukan kuota tak terbatas. Sebelum ini
      // nilai 0 (misalnya karena variabel env salah set) membuka gerbang sepenuhnya.
      if (limit <= 0 || windowMs <= 0) {
        return { allowed: false, retryAfterSeconds: retryAfter(windowMs) }
      }

      cleanup(now)

      const current = buckets.get(key)
      if (!current || current.resetAt <= now) {
        if (!current && buckets.size >= maxKeys) {
          return { allowed: false, retryAfterSeconds: retryAfter(windowMs) }
        }
        buckets.set(key, { count: 1, resetAt: now + windowMs })
        return { allowed: true, retryAfterSeconds: 0, used: 1 }
      }

      if (current.count >= limit) {
        return {
          allowed: false,
          retryAfterSeconds: retryAfter(current.resetAt - now),
          used: current.count,
        }
      }

      current.count += 1
      return { allowed: true, retryAfterSeconds: 0, used: current.count }
    },
    size() {
      return buckets.size
    },
    reset() {
      buckets.clear()
    },
  }
}

export type SlidingWindowLimiter = {
  consume(key: string, now: number, limit: number, windowMs: number): RateLimitDecision
  size(): number
  reset(): void
}

/**
 * Batas jendela geser (daftar cap waktu per kunci). Dipakai untuk batas analisis situs dan
 * batas scan per-uid di mesin, tempat "berapa banyak dalam N menit terakhir" lebih tepat
 * daripada jendela tetap yang bisa meloloskan dua kali lipat di perbatasan jendela.
 */
export function createSlidingWindowLimiter(
  maxKeys: number = STATE_MAX_KEYS,
): SlidingWindowLimiter {
  const usage = new Map<string, number[]>()

  const prune = (timestamps: readonly number[], cutoff: number): number[] =>
    timestamps.filter((timestamp) => timestamp > cutoff)

  const cleanup = (now: number, windowMs: number): void => {
    if (usage.size < maxKeys) return
    const cutoff = now - windowMs
    for (const [key, timestamps] of usage) {
      if (timestamps.every((timestamp) => timestamp <= cutoff)) usage.delete(key)
    }
  }

  return {
    consume(key, now, limit, windowMs) {
      if (limit <= 0 || windowMs <= 0) {
        return { allowed: false, retryAfterSeconds: retryAfter(windowMs) }
      }

      cleanup(now, windowMs)

      const cutoff = now - windowMs
      const recent = prune(usage.get(key) ?? [], cutoff)

      if (recent.length >= limit) {
        usage.set(key, recent)
        const oldest = recent[0] ?? now
        return {
          allowed: false,
          retryAfterSeconds: retryAfter(oldest + windowMs - now),
          used: recent.length,
        }
      }

      if (!usage.has(key) && usage.size >= maxKeys) {
        return { allowed: false, retryAfterSeconds: retryAfter(windowMs) }
      }

      recent.push(now)
      usage.set(key, recent)
      return { allowed: true, retryAfterSeconds: 0, used: recent.length }
    },
    size() {
      return usage.size
    },
    reset() {
      usage.clear()
    },
  }
}

export type ExpiryRegistry = {
  has(key: string, now: number): boolean
  issue(key: string, now: number, ttlMs: number): boolean
  claim(key: string, now: number, ttlMs: number): boolean
  size(): number
  reset(): void
}

/**
 * Kuncinya masih hidup sampai expiresAt. Dua semantik tulis:
 *  - issue(): perpanjangan/izin ulang (izin CAPTCHA). Mengembalikan false bila tabel penuh
 *    dan kunci belum tercatat; arah gagalnya "tantang CAPTCHA lagi", yang aman.
 *  - claim(): catat baru HANYA bila belum ada. Memakai return false untuk kunci yang sudah
 *    ada, sehingga cocok sebagai anti-replay token CAPTCHA.
 */
export function createExpiryRegistry(maxKeys: number = STATE_MAX_KEYS): ExpiryRegistry {
  const entries = new Map<string, number>()

  const cleanup = (now: number): void => {
    if (entries.size < maxKeys) return
    for (const [key, expiresAt] of entries) {
      if (expiresAt <= now) entries.delete(key)
    }
  }

  const fresh = (key: string, now: number): boolean => {
    const expiresAt = entries.get(key)
    if (expiresAt === undefined) return false
    if (expiresAt > now) return true
    entries.delete(key)
    return false
  }

  return {
    has(key, now) {
      return fresh(key, now)
    },
    issue(key, now, ttlMs) {
      cleanup(now)
      if (!entries.has(key) && entries.size >= maxKeys) return false
      entries.set(key, now + Math.max(0, ttlMs))
      return true
    },
    claim(key, now, ttlMs) {
      cleanup(now)
      if (fresh(key, now)) return false
      if (!entries.has(key) && entries.size >= maxKeys) return false
      entries.set(key, now + Math.max(0, ttlMs))
      return true
    },
    size() {
      return entries.size
    },
    reset() {
      entries.clear()
    },
  }
}

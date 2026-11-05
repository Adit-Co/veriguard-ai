import { TURNSTILE_ACTION } from './verify.js'
import { STATE_MAX_KEYS, createExpiryRegistry } from '../state/stores.js'

// Ambang eskalasi dinyatakan sebagai pecahan dari batas keras yang SUDAH dikonfigurasi
// (RATE_LIMIT_MAX_PER_IP), bukan angka absolut baru. Dengan begitu operator yang menyetel
// batasnya otomatis ikut menyetel titik eskalasi, dan rasio 0.5 dipilih karena:
// - di bawah ambang, pengguna normal tetap memindai tanpa CAPTCHA sama sekali;
// - masih ada kepala kosong sebelum batas keras, sehingga Turnstile menjadi langkah
//   perantara dan bukan pengganti pemeriksaan rate limit yang sudah ada.
export const TURNSTILE_ESCALATION_RATIO = 0.5

// Masa berlaku "sudah terverifikasi" sengaja lebih panjang dari jendela rate limit default
// (60 detik), sehingga saat izin ini kedaluwarsa pencacah per-IP sudah pasti kembali nol dan
// pengguna tidak langsung ditantang ulang.
export const TURNSTILE_SCAN_CLEARANCE_MS = 5 * 60_000

const clearances = createExpiryRegistry(STATE_MAX_KEYS)

export function turnstileScanThreshold(limitPerWindow: number): number {
  if (limitPerWindow <= 0) return 0
  return Math.max(1, Math.ceil(limitPerWindow * TURNSTILE_ESCALATION_RATIO))
}

export function turnstileScanClearanceKey(ip: string): string {
  return `turnstile-${TURNSTILE_ACTION.scan}:${ip}`
}

export function issueTurnstileClearance(
  key: string,
  now: number = Date.now(),
  ttlMs: number = TURNSTILE_SCAN_CLEARANCE_MS,
): void {
  clearances.issue(key, now, ttlMs)
}

export function hasTurnstileClearance(key: string, now: number = Date.now()): boolean {
  return clearances.has(key, now)
}

export function resetTurnstileClearance(): void {
  clearances.reset()
}

export function requiresTurnstileScanVerification(input: {
  secretConfigured: boolean
  limitPerWindow: number
  used: number | undefined
  clearanceActive: boolean
}): boolean {
  if (!input.secretConfigured) return false
  if (input.clearanceActive) return false
  if (input.used === undefined) return false
  const threshold = turnstileScanThreshold(input.limitPerWindow)
  if (threshold <= 0) return false
  return input.used > threshold
}

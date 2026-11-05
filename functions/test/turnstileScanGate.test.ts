import { beforeEach, describe, expect, it } from 'vitest'
import {
  TURNSTILE_ESCALATION_RATIO,
  TURNSTILE_SCAN_CLEARANCE_MS,
  hasTurnstileClearance,
  issueTurnstileClearance,
  requiresTurnstileScanVerification,
  resetTurnstileClearance,
  turnstileScanClearanceKey,
  turnstileScanThreshold,
} from '../src/turnstile/scanGate.js'

const NOW = 1_700_000_000_000

describe('gerbang CAPTCHA adaptif untuk pemeriksaan URL', () => {
  beforeEach(() => {
    resetTurnstileClearance()
  })

  it('menurunkan ambang dari batas keras yang sudah dikonfigurasi, bukan angka baru', () => {
    // RATE_LIMIT_MAX_PER_IP default 30 per jendela → tantangan mulai setelah permintaan ke-15.
    expect(TURNSTILE_ESCALATION_RATIO).toBe(0.5)
    expect(turnstileScanThreshold(30)).toBe(15)
    expect(turnstileScanThreshold(1)).toBe(1)
    expect(turnstileScanThreshold(7)).toBe(4)
    // Batas keras dinonaktifkan (limit <= 0): tidak ada titik eskalasi yang dikarang.
    expect(turnstileScanThreshold(0)).toBe(0)
    expect(turnstileScanThreshold(-5)).toBe(0)
  })

  it('hanya menuntut CAPTCHA saat alamat sudah melewati ambang dan belum terverifikasi', () => {
    const base = { secretConfigured: true, limitPerWindow: 30, clearanceActive: false }

    // Pemakaian biasa: jauh di bawah ambang, tidak ada tantangan.
    expect(requiresTurnstileScanVerification({ ...base, used: 1 })).toBe(false)
    expect(requiresTurnstileScanVerification({ ...base, used: 15 })).toBe(false)
    expect(requiresTurnstileScanVerification({ ...base, used: 16 })).toBe(true)

    // Turnstile tidak dikonfigurasi: fitur ini tidak aktif, bukan dilewati diam-diam.
    expect(
      requiresTurnstileScanVerification({ ...base, used: 99, secretConfigured: false }),
    ).toBe(false)
    // Pemakaian di bawah batas tanpa izin: tetap tidak ditantang.
    expect(
      requiresTurnstileScanVerification({ ...base, used: 99, limitPerWindow: 0 }),
    ).toBe(false)
    // Pembatas tidak mengembalikan hitungan (pemanggil lama): tidak menantang.
    expect(requiresTurnstileScanVerification({ ...base, used: undefined })).toBe(false)
  })

  it('izin pasca-verifikasi menekan tantangan ulang dan kedaluwarsa tepat waktu', () => {
    const key = turnstileScanClearanceKey('203.0.113.10')
    expect(hasTurnstileClearance(key, NOW)).toBe(false)

    issueTurnstileClearance(key, NOW)
    expect(hasTurnstileClearance(key, NOW)).toBe(true)
    expect(
      requiresTurnstileScanVerification({
        secretConfigured: true,
        limitPerWindow: 30,
        used: 40,
        clearanceActive: hasTurnstileClearance(key, NOW),
      }),
    ).toBe(false)

    expect(hasTurnstileClearance(key, NOW + TURNSTILE_SCAN_CLEARANCE_MS - 1)).toBe(true)
    expect(hasTurnstileClearance(key, NOW + TURNSTILE_SCAN_CLEARANCE_MS)).toBe(false)
  })

  it('izin hanya berlaku untuk kunci ip yang bersangkutan', () => {
    issueTurnstileClearance(turnstileScanClearanceKey('203.0.113.10'), NOW)
    expect(hasTurnstileClearance(turnstileScanClearanceKey('203.0.113.11'), NOW)).toBe(false)
  })

  it('kunci ip dibedakan dari kunci pembatas lain', () => {
    expect(turnstileScanClearanceKey('203.0.113.10')).toBe(
      'turnstile-scan:203.0.113.10',
    )
  })
})

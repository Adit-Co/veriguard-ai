import { describe, expect, it } from 'vitest'
import {
  USERNAME_MAX_LENGTH,
  USERNAME_MIN_LENGTH,
  isUsernameId,
  normalizeUsername,
  validateUsername,
} from './policy'

describe('normalisasi username', () => {
  it('memotong spasi dan mengubah huruf besar menjadi huruf kecil', () => {
    expect(normalizeUsername('  Gyat123  ')).toBe('gyat123')
    expect(normalizeUsername('ADITDEV')).toBe('aditdev')
  })

  it('menormalkan dua tulisan berbeda menjadi kunci yang sama', () => {
    expect(normalizeUsername('Gyat_123')).toBe(normalizeUsername('gyat_123'))
    expect(normalizeUsername('  GYAT_123 ')).toBe(normalizeUsername('gyat_123'))
  })
})

describe('validasi format username', () => {
  it('menerima username sah dan mengembalikan nilai normalisasi', () => {
    const result = validateUsername(' AditDev ')
    expect(result.valid).toBe(true)
    if (result.valid) expect(result.username).toBe('aditdev')
  })

  it('menerima batas panjang', () => {
    expect(validateUsername('a'.repeat(USERNAME_MIN_LENGTH)).valid).toBe(true)
    expect(validateUsername('z'.repeat(USERNAME_MAX_LENGTH)).valid).toBe(true)
  })

  it('menolak username kosong', () => {
    expect(validateUsername('   ')).toEqual({ valid: false, error: 'Username wajib diisi.' })
  })

  it('menolak spasi di tengah nilai', () => {
    const result = validateUsername('pengguna baru')
    expect(result.valid).toBe(false)
    if (!result.valid) expect(result.error).toContain('tidak boleh memuat spasi')
  })

  it('menolak username terlalu pendek', () => {
    const result = validateUsername('ab')
    expect(result.valid).toBe(false)
    if (!result.valid) expect(result.error).toContain(`minimal ${USERNAME_MIN_LENGTH}`)
  })

  it('menolak username terlalu panjang', () => {
    const result = validateUsername('a'.repeat(USERNAME_MAX_LENGTH + 1))
    expect(result.valid).toBe(false)
    if (!result.valid) expect(result.error).toContain(`maksimal ${USERNAME_MAX_LENGTH}`)
  })

  it('menolak karakter di luar huruf kecil, angka, dan garis bawah', () => {
    for (const value of ['pengguna-baru', 'pengguna.baru', 'pengguna@baru', 'Pengguna!']) {
      const result = validateUsername(value)
      expect(result.valid).toBe(false)
      if (!result.valid) expect(result.error).toContain('huruf kecil, angka, dan garis bawah')
    }
  })

  it('isUsernameId hanya menerima nilai yang sudah kanonis', () => {
    expect(isUsernameId('gyat123')).toBe(true)
    expect(isUsernameId('gyat_123')).toBe(true)
    expect(isUsernameId('Gyat123')).toBe(false)
    expect(isUsernameId('ab')).toBe(false)
    expect(isUsernameId('a'.repeat(USERNAME_MAX_LENGTH + 1))).toBe(false)
    expect(isUsernameId(null)).toBe(false)
    expect(isUsernameId(undefined)).toBe(false)
    expect(isUsernameId(42)).toBe(false)
  })
})

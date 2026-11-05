import { describe, expect, it } from 'vitest'
import type { AppUser, AuthStatus } from './context'
import {
  emailStateLabel,
  isVerifiedAccount,
  parseVerificationAction,
  remainingCooldownSeconds,
  verificationGate,
} from './verification'

describe('alur verifikasi email', () => {
  it('membaca kode aksi verifikasi dari query string', () => {
    expect(
      parseVerificationAction('?mode=verifyEmail&oobCode=kode-aman-123'),
    ).toEqual({
      mode: 'verifyEmail',
      oobCode: 'kode-aman-123',
      canApply: true,
    })
  })

  it('menolak mode lain, kode kosong, dan kode yang terlalu panjang', () => {
    expect(parseVerificationAction('?mode=resetPassword&oobCode=kode').canApply).toBe(false)
    expect(parseVerificationAction('?mode=verifyEmail&oobCode=').canApply).toBe(false)
    expect(parseVerificationAction(`?mode=verifyEmail&oobCode=${'x'.repeat(2049)}`).canApply).toBe(
      false,
    )
  })

  it('menghitung sisa cooldown tanpa nilai negatif', () => {
    expect(remainingCooldownSeconds(10_000, 9_000)).toBe(1)
    expect(remainingCooldownSeconds(10_000, 10_000)).toBe(0)
    expect(remainingCooldownSeconds(10_000, 12_000)).toBe(0)
    expect(remainingCooldownSeconds(Number.NaN, 12_000)).toBe(0)
  })

  it('hanya menyebut akun penuh bila sesi nyata dan email terkonfirmasi', () => {
    expect(isVerifiedAccount({ emailVerified: true, isAnonymous: false })).toBe(true)
    expect(isVerifiedAccount({ emailVerified: false, isAnonymous: false })).toBe(false)
    expect(isVerifiedAccount({ emailVerified: false, isAnonymous: true })).toBe(false)
    expect(isVerifiedAccount(null)).toBe(false)
  })

  it('memakai label status akun yang konsisten', () => {
    expect(emailStateLabel({ emailVerified: true, isAnonymous: false })).toBe('Terverifikasi')
    expect(emailStateLabel({ emailVerified: false, isAnonymous: false })).toBe(
      'Belum verifikasi email',
    )
    expect(emailStateLabel(null)).toBe('Belum verifikasi email')
  })
})

describe('P2: gerbang verifikasi memakai sesi yang masih dapat dipercaya', () => {
  const appUser = (overrides: Partial<AppUser> = {}): AppUser => ({
    uid: 'uid-1',
    email: 'pengguna@contoh.test',
    displayName: 'pengguna',
    emailVerified: true,
    isAnonymous: false,
    startedAt: null,
    ...overrides,
  })

  const firebase = (
    status: AuthStatus,
    user: AppUser | null,
  ) => ({ mode: 'firebase' as const, status, user })

  it('mengizinkan hanya saat sesi nyata dan email terkonfirmasi', () => {
    expect(verificationGate(firebase('ready', appUser()))).toBe('allow')
    expect(verificationGate(firebase('ready', appUser({ emailVerified: false })))).toBe('redirect')
  })

  it('menutup gerbang saat auth gagal selama akun masih tersisa', () => {
    // Sebelum perbaikan ini status 'error' lolos memakai klaim emailVerified terakhir,
    // padahal token sesi bisa saja sudah dicabut.
    expect(verificationGate(firebase('error', appUser()))).toBe('redirect')
    expect(verificationGate(firebase('error', appUser({ emailVerified: false })))).toBe('redirect')
  })

  it('tidak membangun tembok masuk bagi tamu dan sesi anonim', () => {
    expect(verificationGate(firebase('error', null))).toBe('allow')
    expect(verificationGate(firebase('ready', null))).toBe('allow')
    expect(verificationGate(firebase('error', appUser({ isAnonymous: true })))).toBe('allow')
    expect(verificationGate(firebase('loading', null))).toBe('allow')
    expect(verificationGate({ mode: 'demo', status: 'error', user: appUser() })).toBe('allow')
  })
})

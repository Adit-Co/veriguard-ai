import { describe, expect, it } from 'vitest'
import {
  authErrorMessage,
  authErrorMessageFor,
  describeFirestoreError,
  emailVerificationErrorMessage,
  firestoreErrorMessage,
} from './errors'

function firebaseError(code: string) {
  return Object.assign(new Error(code), { code })
}

describe('pemetaan error Firebase', () => {
  it('menjelaskan akses riwayat yang ditolak secara actionable', () => {
    const info = describeFirestoreError(firebaseError('permission-denied'))

    expect(info.kind).toBe('permission')
    expect(info.message).toContain('Aturan akses data')
    expect(firestoreErrorMessage(firebaseError('permission-denied'))).toBe(info.message)
  })

  it('membedakan sesi berakhir dan gangguan koneksi', () => {
    expect(describeFirestoreError(firebaseError('unauthenticated')).kind).toBe('session')
    expect(describeFirestoreError(firebaseError('unavailable')).kind).toBe('offline')
  })

  it('memakai pesan verifikasi untuk tautan invalid dan kedaluwarsa', () => {
    expect(emailVerificationErrorMessage(firebaseError('auth/invalid-action-code'))).toContain(
      'tidak valid',
    )
    expect(emailVerificationErrorMessage(firebaseError('auth/expired-action-code'))).toContain(
      'kedaluwarsa',
    )
    expect(emailVerificationErrorMessage(new Error('Tidak ada akun aktif.'))).toBe(
      'Tidak ada akun aktif.',
    )
  })
})

describe('VGL-41A — pesan login menyebut sebab yang sebenarnya', () => {
  const userNotFound = firebaseError('auth/user-not-found')
  const wrongPassword = firebaseError('auth/wrong-password')
  const invalidCredential = firebaseError('auth/invalid-credential')

  it('EMAIL_NOT_FOUND pada emulator lokal tidak lagi disebut kata sandi salah', () => {
    const message = authErrorMessageFor(userNotFound, true)

    expect(message).toContain('tidak terdaftar')
    expect(message).toContain('Emulator Firebase lokal')
    expect(message).not.toMatch(/tidak cocok/)
  })

  it('pada layanan produksi pemetaan tetap tergabung seperti semula', () => {
    // Produksi menjawab INVALID_LOGIN_CREDENTIALS untuk kedua sebab, jadi memisahkan
    // "akun tidak ada" dari "sandi salah" di sana akan membuka jalan enumerasi akun.
    const combined = 'Email atau kata sandi tidak cocok.'
    expect(authErrorMessageFor(userNotFound, false)).toBe(combined)
    expect(authErrorMessageFor(invalidCredential, false)).toBe(combined)
    expect(authErrorMessageFor(invalidCredential, true)).toBe(combined)
  })

  it('kata sandi yang memang salah tetap disebut dengan pesan kredensial', () => {
    expect(authErrorMessageFor(wrongPassword, true)).toBe('Email atau kata sandi tidak cocok.')
    expect(authErrorMessageFor(wrongPassword, false)).toBe('Email atau kata sandi tidak cocok.')
  })

  it('email berformat salah dan sebab tak terklasifikasi punya pesan sendiri', () => {
    expect(authErrorMessageFor(firebaseError('auth/invalid-email'), true)).toBe(
      'Format email tidak valid.',
    )
    expect(authErrorMessageFor(firebaseError('auth/network-request-failed'), true)).toBe(
      'Tidak dapat menghubungi layanan akun. Periksa koneksi internet.',
    )
    expect(authErrorMessageFor(firebaseError('auth/unknown-code'), true)).toBe(
      'Autentikasi gagal. Periksa data yang dimasukkan lalu coba lagi.',
    )
    expect(authErrorMessageFor({}, true)).toBe(
      'Autentikasi gagal. Periksa data yang dimasukkan lalu coba lagi.',
    )
  })

  it('authErrorMessage memakai keadaan instance yang sedang dipakai halaman', () => {
    // Di luar Emulator Auth lokal (kondisi build ini), user-not-found tetap tergabung.
    expect(authErrorMessage(userNotFound)).toBe('Email atau kata sandi tidak cocok.')
  })
})

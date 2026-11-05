import { useFirebaseEmulators } from './config'

const AUTH_ERROR_MESSAGES: Record<string, string> = {
  'auth/invalid-email': 'Format email tidak valid.',
  'auth/missing-email': 'Masukkan alamat email terlebih dahulu.',
  'auth/invalid-credential': 'Email atau kata sandi tidak cocok.',
  'auth/user-not-found': 'Email atau kata sandi tidak cocok.',
  'auth/wrong-password': 'Email atau kata sandi tidak cocok.',
  'auth/email-already-in-use': 'Email ini sudah terdaftar. Coba masuk atau pulihkan kata sandi.',
  'auth/weak-password': 'Kata sandi terlalu lemah. Gunakan minimal 8 karakter.',
  'auth/too-many-requests': 'Terlalu banyak percobaan. Tunggu sebentar lalu coba lagi.',
  'auth/network-request-failed': 'Tidak dapat menghubungi layanan akun. Periksa koneksi internet.',
  'auth/operation-not-allowed':
    'Metode email dan kata sandi belum tersedia pada layanan akun.',
  'auth/requires-recent-login': 'Silakan masuk ulang sebelum melakukan tindakan ini.',
  'auth/user-disabled': 'Akun ini dinonaktifkan.',
  'auth/email-already-verified': 'Email ini sudah terverifikasi.',
  'auth/expired-action-code':
    'Tautan verifikasi sudah kedaluwarsa. Kirim email verifikasi baru untuk melanjutkan.',
  'auth/invalid-action-code': 'Tautan verifikasi tidak valid atau sudah pernah dipakai.',
  'auth/argument-error': 'Tautan verifikasi tidak valid. Periksa kembali alamat lengkapnya.',
}

export type FirestoreErrorKind =
  | 'permission'
  | 'session'
  | 'offline'
  | 'configuration'
  | 'quota'
  | 'unknown'

export type FirestoreErrorInfo = {
  code: string | null
  kind: FirestoreErrorKind
  message: string
}

const FIRESTORE_ERROR_DETAILS: Record<
  string,
  { kind: FirestoreErrorKind; message: string }
> = {
  'permission-denied': {
    kind: 'permission',
    message:
      'Akses ke data akun ini tidak diizinkan. Aturan akses data mungkin belum diperbarui atau akun yang masuk bukan pemilik data.',
  },
  unauthenticated: {
    kind: 'session',
    message: 'Sesi akun sudah tidak berlaku. Masuk kembali untuk membuka data akun ini.',
  },
  unavailable: {
    kind: 'offline',
    message: 'Penyimpanan data tidak dapat dihubungi saat ini. Periksa koneksi lalu coba lagi.',
  },
  'failed-precondition': {
    kind: 'configuration',
    message:
      'Layanan data belum siap atau konfigurasi versi ini tidak cocok. Coba lagi nanti.',
  },
  'resource-exhausted': {
    kind: 'quota',
    message: 'Kuota layanan data tercapai. Coba lagi setelah kuota tersedia.',
  },
}

export function getFirebaseErrorCode(error: unknown): string | null {
  if (!error || typeof error !== 'object' || !('code' in error)) return null
  const code = (error as { code?: unknown }).code
  return typeof code === 'string' ? code : null
}

/**
 * VGL-41A — pesan harus menyebut sebab yang sebenarnya.
 *
 * `auth/user-not-found` hanya terbit bila layanan identitas menjawab EMAIL_NOT_FOUND. Emulator
 * Auth lokal melakukan itu (proteksi enumerasi mati), jadi pada halaman yang tersambung ke
 * emulator, "email atau kata sandi salah" adalah keterangan yang SALAH: akunnya memang tidak
 * ada pada instance ini, dan kata sandi pengguna tidak ikut salah. Di produksi Firebase menjawab
 * INVALID_LOGIN_CREDENTIALS untuk kedua sebab, sehingga pemisahan ini tidak pernah menjadi jalur
 * enumerasi akun bagi penyerang.
 */
const LOCAL_EMULATOR_ACCOUNT_ABSENT =
  'Email itu tidak terdaftar pada layanan akun yang sedang dipakai halaman ini (Emulator Firebase lokal). Kata sandi kamu tidak salah: instance ini bukan produksi, datanya kosong setiap emulator dijalankan ulang, dan akun demo tidak masuk lewat formulir ini. Buat akun lewat Daftar bila memang ingin mendaftarkannya di sini.'

export function authErrorMessageFor(error: unknown, localEmulatorInUse: boolean): string {
  const code = getFirebaseErrorCode(error)
  if (code === 'auth/user-not-found' && localEmulatorInUse) return LOCAL_EMULATOR_ACCOUNT_ABSENT
  if (code && AUTH_ERROR_MESSAGES[code]) return AUTH_ERROR_MESSAGES[code]
  return 'Autentikasi gagal. Periksa data yang dimasukkan lalu coba lagi.'
}

export function authErrorMessage(error: unknown): string {
  return authErrorMessageFor(error, useFirebaseEmulators)
}

export function emailVerificationErrorMessage(error: unknown): string {
  const code = getFirebaseErrorCode(error)
  if (code && AUTH_ERROR_MESSAGES[code]) return AUTH_ERROR_MESSAGES[code]
  if (!code && error instanceof Error && error.message.trim()) return error.message
  return 'Verifikasi email tidak dapat diproses. Periksa koneksi lalu coba lagi.'
}

export function describeFirestoreError(error: unknown): FirestoreErrorInfo {
  const code = getFirebaseErrorCode(error)
  const detail = code ? FIRESTORE_ERROR_DETAILS[code] : undefined
  if (detail) return { code, ...detail }

  return {
    code,
    kind: 'unknown',
    message: 'Data akun tidak dapat diakses. Periksa koneksi lalu coba lagi.',
  }
}

export function firestoreErrorMessage(error: unknown): string {
  return describeFirestoreError(error).message
}

import { getFirebaseErrorCode } from '../firebase/errors'
import { userFacingText } from '../uiText'

const WORKER_ERROR_MESSAGES: Record<string, string> = {
  unauthenticated: 'Sesi akun tidak berlaku. Masuk kembali untuk memakai pemeriksaan eksternal.',
  consent_required: 'Persetujuan pemeriksaan eksternal belum diberikan.',
  invalid_request: 'Permintaan pemeriksaan eksternal tidak valid.',
  invalid_url: 'URL ditolak oleh layanan pemeriksaan eksternal.',
  rate_limited: 'Batas pemeriksaan eksternal tercapai. Coba lagi nanti.',
  captcha_required: 'Layanan meminta verifikasi bahwa Anda bukan robot sebelum melanjutkan.',
  captcha_invalid: 'Verifikasi CAPTCHA tidak berlaku. Selesaikan verifikasi baru.',
  captcha_verification_failed: 'Verifikasi CAPTCHA tidak berlaku. Selesaikan verifikasi baru.',
  captcha_not_configured: 'Layanan verifikasi CAPTCHA belum disiapkan pada versi ini.',
  origin_not_allowed: 'Aplikasi ini tidak diizinkan memakai layanan pemeriksaan eksternal.',
  method_not_allowed: 'Permintaan pemeriksaan eksternal tidak valid.',
  unsupported_media_type: 'Format permintaan pemeriksaan eksternal tidak didukung.',
  payload_too_large: 'Permintaan pemeriksaan eksternal terlalu besar.',
  server_misconfigured: 'Layanan pemeriksaan eksternal belum siap digunakan.',
  worker_not_configured: 'Layanan pemeriksaan eksternal belum tersedia pada versi ini.',
  not_found: 'Layanan pemeriksaan eksternal tidak ditemukan.',
  unavailable: 'Layanan pemeriksaan eksternal tidak dapat dihubungi.',
  invalid_response: 'Respons pemeriksaan eksternal tidak valid.',
  internal: 'Pemeriksaan eksternal gagal diproses.',
  cancelled: 'Pemeriksaan eksternal dibatalkan.',
}

const CALLABLE_ERROR_MESSAGES: Record<string, string> = {
  'functions/unauthenticated': 'Sesi akun tidak berlaku. Masuk kembali untuk memakai pemeriksaan eksternal.',
  'functions/failed-precondition': 'Persetujuan atau konfigurasi pemeriksaan eksternal belum lengkap.',
  'functions/invalid-argument': 'URL ditolak oleh layanan pemeriksaan eksternal.',
  'functions/resource-exhausted': 'Batas pemeriksaan eksternal tercapai. Coba lagi nanti.',
  'functions/deadline-exceeded': 'Pemeriksaan eksternal melebihi batas waktu.',
  'functions/unavailable': 'Layanan pemeriksaan eksternal belum tersedia.',
  'functions/internal': 'Pemeriksaan eksternal gagal diproses.',
}

export const EXTERNAL_SCAN_CANCELLED_CODE = 'cancelled'
export const CAPTCHA_REQUIRED_CODE = 'captcha_required'
export const CAPTCHA_INVALID_CODE = 'captcha_invalid'

// Layanan meminta tantangan CAPTCHA, atau menolak token yang dikirim. Keduanya berarti
// "belum ada pemeriksaan yang berjalan", jadi hasil tidak boleh dianggap bersih.
export function isCaptchaChallenge(error: unknown): boolean {
  return (
    error instanceof ExternalScanRequestError &&
    (error.code === CAPTCHA_REQUIRED_CODE || error.code === CAPTCHA_INVALID_CODE)
  )
}

export class ExternalScanRequestError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'ExternalScanRequestError'
    this.code = code
  }
}

export function createExternalScanCancelledError(): ExternalScanRequestError {
  return new ExternalScanRequestError(
    EXTERNAL_SCAN_CANCELLED_CODE,
    'Pemeriksaan dibatalkan.',
  )
}

export function isExternalScanCancelled(error: unknown): boolean {
  return (
    error instanceof ExternalScanRequestError &&
    error.code === EXTERNAL_SCAN_CANCELLED_CODE
  )
}

export function externalScanErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message === 'timeout') {
    return 'Pemeriksaan eksternal melebihi batas waktu.'
  }

  if (error instanceof ExternalScanRequestError) {
    return WORKER_ERROR_MESSAGES[error.code] ?? userFacingText(error.message)
  }

  const code = getFirebaseErrorCode(error)
  if (code && CALLABLE_ERROR_MESSAGES[code]) return CALLABLE_ERROR_MESSAGES[code]
  if (code === 'auth/admin-restricted-operation' || code === 'auth/operation-not-allowed') {
    return 'Sesi tamu belum tersedia. Masuk dengan akun atau coba lagi nanti.'
  }
  return 'Pemeriksaan reputasi eksternal gagal dijalankan. Hasil internal tetap tersedia.'
}

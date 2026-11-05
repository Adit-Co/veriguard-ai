const SENSITIVE_PARAMETER_NAMES = new Set([
  'access_token',
  'account',
  'api_key',
  'apikey',
  'auth',
  'authorization',
  'card',
  'code',
  'cvv',
  'email',
  'iban',
  'key',
  'nik',
  'otp',
  'passwd',
  'password',
  'phone',
  'pin',
  'pwd',
  'rekening',
  'refresh_token',
  'secret',
  'session',
  'sessionid',
  'sid',
  'signature',
  'sig',
  'token',
])

const SENSITIVE_PATH_MARKERS = new Set([
  'auth',
  'invite',
  'login',
  'reset',
  'reset-password',
  'signin',
  'token',
  'verify',
])

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const PHONE_PATTERN = /^\+?\d[\d\s().-]{7,}$/
const JWT_PATTERN = /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/
const LONG_TOKEN_PATTERN = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_-]{32,}$/

export type SensitiveUrlResult = {
  sensitive: boolean
  reasons: string[]
}

function addReason(reasons: string[], reason: string): void {
  if (!reasons.includes(reason) && reasons.length < 3) {
    reasons.push(reason)
  }
}

function looksSensitiveValue(value: string): boolean {
  const trimmed = value.trim()
  if (!trimmed) return false

  return (
    EMAIL_PATTERN.test(trimmed) ||
    PHONE_PATTERN.test(trimmed) ||
    JWT_PATTERN.test(trimmed) ||
    LONG_TOKEN_PATTERN.test(trimmed)
  )
}

export function detectSensitiveUrl(raw: string): SensitiveUrlResult {
  const reasons: string[] = []

  let url: URL
  try {
    url = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`)
  } catch {
    return { sensitive: false, reasons }
  }

  for (const [key, value] of url.searchParams) {
    if (SENSITIVE_PARAMETER_NAMES.has(key.toLowerCase())) {
      addReason(reasons, 'URL memuat parameter yang tampak seperti token atau data pribadi.')
      continue
    }

    if (looksSensitiveValue(value)) {
      addReason(reasons, 'URL memuat nilai yang tampak seperti email, nomor telepon, atau token.')
    }
  }

  const segments = url.pathname.split('/').filter(Boolean)
  for (const segment of segments) {
    if (JWT_PATTERN.test(segment) || LONG_TOKEN_PATTERN.test(segment)) {
      addReason(reasons, 'URL memuat nilai panjang yang tampak seperti token akses.')
      break
    }
  }

  if (segments.some((segment) => SENSITIVE_PATH_MARKERS.has(segment.toLowerCase()))) {
    const hasLongSegment = segments.some(
      (segment) => segment.length >= 16 && !SENSITIVE_PATH_MARKERS.has(segment.toLowerCase()),
    )
    if (hasLongSegment) {
      addReason(reasons, 'URL memuat jalur yang tampak seperti tautan verifikasi atau reset.')
    }
  }

  return { sensitive: reasons.length > 0, reasons }
}

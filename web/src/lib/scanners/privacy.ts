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

export const REDACTED_PATH_SEGMENT = '[dirahasiakan]'

/**
 * Salinan URL yang boleh tinggal di penyimpanan permanen peramban. Dipakai hanya untuk URL
 * yang sudah ditandai sensitif, dan nilainya dibuang (bukan sekadar ditutupi): kredensial di
 * userinfo, seluruh query dan fragment, serta segmen jalur yang berbentuk token. Host dan
 * jalur biasa dipertahankan supaya riwayat masih dapat dikenali dan diperiksa ulang.
 */
export function redactSensitiveUrlForStorage(raw: string): string {
  let url: URL
  try {
    url = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`)
  } catch {
    return raw
  }

  url.username = ''
  url.password = ''
  url.search = ''
  url.hash = ''

  const segments = url.pathname.split('/').filter(Boolean)
  const hasSecretMarker = segments.some((segment) => SENSITIVE_PATH_MARKERS.has(segment.toLowerCase()))
  const kept = segments
    .map((segment) =>
      JWT_PATTERN.test(segment) ||
      LONG_TOKEN_PATTERN.test(segment) ||
      (hasSecretMarker && segment.length >= 16 && !SENSITIVE_PATH_MARKERS.has(segment.toLowerCase()))
        ? REDACTED_PATH_SEGMENT
        : segment,
    )
    .slice(0, 8)

  url.pathname = kept.length > 0 ? `/${kept.join('/')}` : '/'
  return url.toString()
}

const MIN_SECRET_FRAGMENT_LENGTH = 8

/**
 * Potongan URL yang tidak boleh tertinggal di teks manapun pada riwayat: nilai parameter,
 * kredensial userinfo, dan segmen jalur yang berbentuk token. Dinilai dari URL ASLI, jadi
 * pemanggil cukup memberikannya sekali untuk menyapu seluruh field turunan.
 */
export function sensitiveUrlFragments(raw: string): string[] {
  let url: URL
  try {
    url = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`)
  } catch {
    return []
  }

  const values = [...url.searchParams.values()]
  if (url.username) values.push(url.username)
  if (url.password) values.push(url.password)

  const segments = url.pathname.split('/').filter(Boolean)
  const hasSecretMarker = segments.some((segment) =>
    SENSITIVE_PATH_MARKERS.has(segment.toLowerCase()),
  )
  for (const segment of segments) {
    if (
      JWT_PATTERN.test(segment) ||
      LONG_TOKEN_PATTERN.test(segment) ||
      (hasSecretMarker && segment.length >= 16)
    ) {
      values.push(segment)
    }
  }

  const fragments = new Set<string>()
  for (const value of values) {
    const trimmed = value.trim()
    if (trimmed.length < MIN_SECRET_FRAGMENT_LENGTH) continue
    fragments.add(trimmed)
    const encoded = encodeURIComponent(trimmed)
    if (encoded !== trimmed) fragments.add(encoded)
  }

  return [...fragments].sort((left, right) => right.length - left.length)
}

/** Ganti setiap potongan sensitif yang masih muncul di dalam sepotong teks. */
export function redactSecretFragments(text: string, fragments: readonly string[]): string {
  if (!text || fragments.length === 0) return text

  let redacted = text
  for (const fragment of fragments) {
    if (redacted.includes(fragment)) {
      redacted = redacted.split(fragment).join(REDACTED_PATH_SEGMENT)
    }
  }

  return redacted
}

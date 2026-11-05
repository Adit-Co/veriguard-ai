export const USERNAME_MIN_LENGTH = 3
export const USERNAME_MAX_LENGTH = 20
const USERNAME_PATTERN = /^[a-z0-9_]{3,20}$/

export type UsernameValidation =
  | { valid: true; username: string }
  | { valid: false; error: string }

export function normalizeUsername(value: string): string {
  return value.trim().toLowerCase()
}

export function validateUsername(value: string): UsernameValidation {
  const trimmed = value.trim()

  if (!trimmed) {
    return { valid: false, error: 'Username wajib diisi.' }
  }

  if (/\s/.test(trimmed)) {
    return { valid: false, error: 'Username tidak boleh memuat spasi.' }
  }

  const username = trimmed.toLowerCase()

  if (username.length < USERNAME_MIN_LENGTH) {
    return {
      valid: false,
      error: `Username minimal ${USERNAME_MIN_LENGTH} karakter.`,
    }
  }

  if (username.length > USERNAME_MAX_LENGTH) {
    return {
      valid: false,
      error: `Username maksimal ${USERNAME_MAX_LENGTH} karakter.`,
    }
  }

  if (!USERNAME_PATTERN.test(username)) {
    return {
      valid: false,
      error: 'Username hanya boleh berisi huruf kecil, angka, dan garis bawah (_).',
    }
  }

  return { valid: true, username }
}

export function isUsernameId(value: unknown): value is string {
  return typeof value === 'string' && USERNAME_PATTERN.test(value)
}

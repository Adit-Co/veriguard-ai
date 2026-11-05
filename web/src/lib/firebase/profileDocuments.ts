import { normalizeUsername, validateUsername } from '../usernames/policy'

export type UserProfileIdentity = {
  uid: string
  email: string | null
  displayName: string | null
  username?: string | null
}

export type UserProfileDocument = {
  uid: string
  email: string | null
  displayName: string
  username: string | null
  createdAt: string
  lastLoginAt: string
}

const MAX_EMAIL_LENGTH = 254
const MAX_DISPLAY_NAME_LENGTH = 80
const MAX_DATE_LENGTH = 40

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function isValidIsoDate(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_DATE_LENGTH &&
    !Number.isNaN(Date.parse(value))
  )
}

function normalizedEmail(email: string | null): string | null {
  const value = email?.trim() ?? ''
  return value ? value.slice(0, MAX_EMAIL_LENGTH) : null
}

function normalizedDisplayName(identity: UserProfileIdentity): string {
  const value = identity.displayName?.trim() || identity.email?.trim() || 'Pengguna'
  return value.slice(0, MAX_DISPLAY_NAME_LENGTH)
}

// Profil hanya menyalin username yang bentuknya sah. Nilai liar tidak pernah
// masuk ke dokumen profil meskipun pointer klaimnya termanipulasi.
function normalizedUsername(username: string | null | undefined): string | null {
  const value = username?.trim() ?? ''
  if (!value) return null
  const checked = validateUsername(value)
  return checked.valid ? checked.username : null
}

export function buildUserProfileDocument(
  identity: UserProfileIdentity,
  existingCreatedAt: string | null,
  now: string = new Date().toISOString(),
): UserProfileDocument {
  return {
    uid: identity.uid,
    email: normalizedEmail(identity.email),
    displayName: normalizedDisplayName(identity),
    username: normalizedUsername(identity.username),
    createdAt: isValidIsoDate(existingCreatedAt) ? existingCreatedAt : now,
    lastLoginAt: now,
  }
}

export function readProfileCreatedAt(
  data: Record<string, unknown> | undefined,
  expectedUid: string,
): string | null {
  if (!data || data.uid !== expectedUid) return null
  return isValidIsoDate(data.createdAt) ? data.createdAt : null
}

// Dokumen profil lama tidak punya field username sama sekali. Nilai yang tidak
// sah diperlakukan sama seperti tidak ada, sehingga tidak pernah menimpa klaim.
export function readProfileUsername(
  data: Record<string, unknown> | undefined,
  expectedUid: string,
): string | null {
  if (!data || data.uid !== expectedUid) return null
  if (!('username' in data) || data.username === null) return null
  return normalizeUsername(String(data.username)) || null
}

export function isUserProfileDocument(
  value: unknown,
  expectedUid?: string,
): value is UserProfileDocument {
  if (!isRecord(value)) return false
  if (expectedUid !== undefined && value.uid !== expectedUid) return false

  const username = value.username
  const usernameAllowed =
    username === undefined ||
    username === null ||
    (typeof username === 'string' && normalizeUsername(username) === username)

  return (
    typeof value.uid === 'string' &&
    value.uid.length > 0 &&
    value.uid.length <= 128 &&
    (value.email === null ||
      (typeof value.email === 'string' && value.email.length <= MAX_EMAIL_LENGTH)) &&
    typeof value.displayName === 'string' &&
    value.displayName.length > 0 &&
    value.displayName.length <= MAX_DISPLAY_NAME_LENGTH &&
    usernameAllowed &&
    isValidIsoDate(value.createdAt) &&
    isValidIsoDate(value.lastLoginAt)
  )
}

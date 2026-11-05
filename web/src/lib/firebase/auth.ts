import {
  applyActionCode,
  createUserWithEmailAndPassword,
  deleteUser,
  sendEmailVerification,
  sendPasswordResetEmail,
  signInAnonymously,
  signInWithEmailAndPassword,
  signOut,
  updateProfile,
  type User,
} from 'firebase/auth'
import { getFirebaseClient } from './client'
import { getFirebaseErrorCode } from './errors'
import {
  acquireLoginAttempt,
  classifyLoginError,
  LoginCooldownError,
  reportLoginAttempt,
} from '../auth/loginGuard'

export type EmailVerificationResult = {
  verified: boolean
  signedIn: boolean
}

/**
 * VGL-38: izin cooldown diminta SEBELUM kredensial dikirim, dan hasil Firebase dilaporkan apa
 * adanya (kegagalan kredensial menaikkan tingkat; gangguan layanan dan rate limit pihak layanan
 * tidak). Gerbang ini membatasi klien aplikasi; panggilan langsung ke identitytoolkit tidak
 * lewat jalur ini dan dilaporkan sebagai batasan arsitektur.
 */
export async function signInWithEmail(email: string, password: string) {
  const { auth } = getFirebaseClient()

  const { handle, cooldown } = await acquireLoginAttempt(email)
  if (cooldown.active) throw new LoginCooldownError(cooldown.retryAfterMs, cooldown.level)

  try {
    const credential = await signInWithEmailAndPassword(auth, email.trim(), password)
    await reportLoginAttempt(handle, email, 'success')
    return credential.user
  } catch (error) {
    await reportLoginAttempt(handle, email, classifyLoginError(error))
    throw error
  }
}

export async function ensureAnonymousSession() {
  const { auth } = getFirebaseClient()
  await auth.authStateReady()

  if (auth.currentUser) return auth.currentUser

  const credential = await signInAnonymously(auth)
  return credential.user
}

export async function createEmailAccount(
  displayName: string,
  email: string,
  password: string,
): Promise<User> {
  const { auth } = getFirebaseClient()
  const credential = await createUserWithEmailAndPassword(auth, email.trim(), password)
  const normalizedName = displayName.trim()

  if (normalizedName) {
    await updateProfile(credential.user, { displayName: normalizedName }).catch(() => undefined)
  }

  return credential.user
}

/**
 * Kegagalan kirim email tidak membatalkan akun; halaman verifikasi menyediakan kirim ulang.
 */
export async function sendVerificationEmail(user: User): Promise<boolean> {
  try {
    await sendEmailVerification(user)
    return true
  } catch {
    return false
  }
}

/**
 * Rollback hanya untuk akun yang baru saja dibuat percobaan pendaftaran yang sama dan
 * belum dipakai. Akun yang sudah ada tidak pernah dihapus dari jalur ini.
 */
export async function deleteUnclaimedAccountJustCreated(user: User): Promise<boolean> {
  const { auth } = getFirebaseClient()
  if (auth.currentUser?.uid !== user.uid) return false
  if (user.emailVerified) return false

  try {
    await deleteUser(user)
    return true
  } catch {
    await signOut(auth).catch(() => undefined)
    return false
  }
}

export async function signOutFromFirebase() {
  const { auth } = getFirebaseClient()
  await signOut(auth)
}

export async function requestPasswordReset(email: string) {
  const { auth } = getFirebaseClient()

  try {
    await sendPasswordResetEmail(auth, email.trim())
  } catch (error) {
    if (getFirebaseErrorCode(error) === 'auth/user-not-found') return
    throw error
  }
}

export async function sendVerificationEmailToCurrentUser() {
  const { auth } = getFirebaseClient()
  if (!auth.currentUser) {
    throw new Error('Tidak ada akun yang sedang masuk.')
  }
  await sendEmailVerification(auth.currentUser)
}

export async function reloadEmailVerification(): Promise<EmailVerificationResult> {
  const { auth } = getFirebaseClient()
  const user = auth.currentUser
  if (!user) return { verified: false, signedIn: false }

  await user.reload()
  if (user.emailVerified) await refreshTokenClaims(user)
  return { verified: user.emailVerified, signedIn: true }
}

export async function applyEmailVerificationCode(
  code: string,
): Promise<EmailVerificationResult> {
  const { auth } = getFirebaseClient()
  const normalizedCode = code.trim()
  if (!normalizedCode) {
    throw Object.assign(new Error('Kode verifikasi tidak valid.'), {
      code: 'auth/invalid-action-code',
    })
  }

  await applyActionCode(auth, normalizedCode)

  const user = auth.currentUser
  if (!user) return { verified: true, signedIn: false }

  await user.reload()
  if (user.emailVerified) await refreshTokenClaims(user)
  return { verified: user.emailVerified, signedIn: true }
}

// Aturan Firestore membaca klaim email_verified dari token ID. Token lama tetap
// berisi false sampai kedaluwarsa, jadi token diminta ulang segera setelah
// verifikasi. Kegagalan jaringan tidak boleh menggagalkan verifikasi itu sendiri.
async function refreshTokenClaims(user: User): Promise<void> {
  try {
    await user.getIdToken(true)
  } catch {
    // Token akan diperbarui otomatis oleh SDK saat kedaluwarsa.
  }
}

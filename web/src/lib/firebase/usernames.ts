import { doc, getDoc, runTransaction } from 'firebase/firestore'
import { getFirebaseClient } from './client'
import { getFirebaseErrorCode } from './errors'
import { normalizeUsername, validateUsername } from '../usernames/policy'

export const USERNAME_CLAIM_DOCUMENT = 'current'

export type UsernameClaim = {
  username: string
  uid: string
  createdAt: string
}

export type UsernameClaimFailureCode =
  | 'invalid-username'
  | 'taken'
  | 'account-has-username'
  | 'session'
  | 'configuration'
  | 'offline'

export const USERNAME_CLAIM_MESSAGES: Record<UsernameClaimFailureCode, string> = {
  'invalid-username': 'Username tidak valid. Gunakan 3-20 karakter: huruf kecil, angka, dan _.',
  taken: 'Username sudah dipakai akun lain. Pilih username lain.',
  'account-has-username': 'Akun ini sudah memiliki username dan tidak dapat menggantinya.',
  session: 'Sesi akun tidak ditemukan. Masuk kembali lalu coba klaim username lagi.',
  configuration:
    'Penyimpanan username menolak penulisan. Aturan akses data mungkin belum diperbarui.',
  offline: 'Penyimpanan username tidak dapat dihubungi. Periksa koneksi lalu coba lagi.',
}

const USERNAME_CLAIM_RETRY_MESSAGES: Record<'configuration' | 'session', string> = {
  configuration:
    'Username belum dapat dipasang. Masuk kembali lalu coba lagi, atau hubungi pengelola layanan bila aturan akses data belum diperbarui.',
  session: 'Sesi akun tidak dapat dipakai untuk memasang username. Masuk kembali lalu coba lagi.',
}

export class UsernameClaimError extends Error {
  readonly code: UsernameClaimFailureCode

  constructor(code: UsernameClaimFailureCode, message?: string) {
    super(message ?? USERNAME_CLAIM_MESSAGES[code])
    this.name = 'UsernameClaimError'
    this.code = code
  }
}

function failureCodeFromFirebase(error: unknown): UsernameClaimFailureCode {
  const code = getFirebaseErrorCode(error) ?? ''
  if (code === 'permission-denied') return 'taken'
  if (code === 'unauthenticated') return 'session'
  if (code === 'unavailable' || code === 'network-request-failed') return 'offline'
  return 'configuration'
}

export function usernameClaimErrorMessage(error: unknown): string {
  if (error instanceof UsernameClaimError) return error.message
  return USERNAME_CLAIM_MESSAGES[failureCodeFromFirebase(error)]
}

function readClaimData(
  data: Record<string, unknown> | undefined | null,
  expectedUid: string,
  expectedUsername: string,
): UsernameClaim | null {
  if (!data) return null
  if (data.uid !== expectedUid || data.username !== expectedUsername) return null
  if (typeof data.createdAt !== 'string' || !data.createdAt) return null

  return { username: expectedUsername, uid: expectedUid, createdAt: data.createdAt }
}

/**
 * Atribut username milik satu akun. Dokumen pointer hanya boleh dibaca pemiliknya,
 * jadi fungsi ini aman dipakai ulang setiap kali profil perlu menampilkan username.
 */
export async function readUsernameClaim(uid: string): Promise<UsernameClaim | null> {
  const normalizedUid = uid.trim()
  if (!normalizedUid) return null

  const { db } = getFirebaseClient()
  const snapshot = await getDoc(
    doc(db, 'users', normalizedUid, 'username', USERNAME_CLAIM_DOCUMENT),
  )
  if (!snapshot.exists()) return null

  const data = snapshot.data() as Record<string, unknown> | undefined
  const rawUsername = typeof data?.username === 'string' ? data.username : ''
  const username = normalizeUsername(rawUsername)
  if (!username) return null

  return readClaimData(data, normalizedUid, username)
}

/**
 * Klaim username: satu akun satu username, satu username satu akun.
 *
 * Keunikan ditegakkan di server, bukan dari pemeriksaan ketersediaan di klien:
 * dokumen `usernames/{username}` hanya boleh dibuat dan tidak pernah boleh
 * diperbarui atau dihapus. Bila nama sudah dipakai, tulisannya diklasifikasikan
 * sebagai update dan ditolak aturan, sehingga transaksi dibatalkan tanpa menyisakan
 * pointer dan tanpa menimpa pemilik lama.
 */
export async function claimUsername(
  uid: string,
  rawUsername: string,
  now: string = new Date().toISOString(),
): Promise<UsernameClaim> {
  const checked = validateUsername(rawUsername)
  if (!checked.valid) throw new UsernameClaimError('invalid-username', checked.error)

  const normalizedUid = uid.trim()
  if (!normalizedUid || normalizedUid.includes('/')) {
    throw new UsernameClaimError('session')
  }

  const username = checked.username
  const { db } = getFirebaseClient()
  const claimRef = doc(db, 'users', normalizedUid, 'username', USERNAME_CLAIM_DOCUMENT)
  const registryRef = doc(db, 'usernames', username)

  try {
    return await runTransaction(db, async (transaction) => {
      // Pemilik tidak dapat berpindah atau melepas nama: pointer yang sudah ada
      // selalu milik username yang sama, jadi percobaan nama lain ditolak di sini
      // sebelum ada tulisan yang dikirim.
      const existing = await transaction.get(claimRef)

      if (existing.exists()) {
        const retained = readClaimData(
          existing.data() as Record<string, unknown> | undefined,
          normalizedUid,
          username,
        )
        if (retained) return retained
        throw new UsernameClaimError('account-has-username')
      }

      const claim: UsernameClaim = { username, uid: normalizedUid, createdAt: now }
      transaction.set(registryRef, { uid: normalizedUid, createdAt: now })
      transaction.set(claimRef, claim)
      return claim
    })
  } catch (error) {
    if (error instanceof UsernameClaimError) throw error
    throw new UsernameClaimError(failureCodeFromFirebase(error))
  }
}

/**
 * Klaim username untuk akun yang sudah ada dan belum memilikinya (akun lama sebelum
 * fitur ini aktif). Hanya dibaca lewat transaksi milik klaim yang sama; bila gagal,
 * pengguna diarahkan masuk ulang alih-alih akun atau klaim orang lain disentuh.
 */
export async function claimUsernameForCurrentUser(
  rawUsername: string,
  now: string = new Date().toISOString(),
): Promise<UsernameClaim> {
  const { auth } = getFirebaseClient()
  const user = auth.currentUser

  if (!user || user.isAnonymous) throw new UsernameClaimError('session')

  try {
    const claim = await claimUsername(user.uid, rawUsername, now)
    await user.reload()
    return claim
  } catch (error) {
    const failure =
      error instanceof UsernameClaimError
        ? error
        : new UsernameClaimError(failureCodeFromFirebase(error))

    // Nama yang sudah dipakai tetap dilaporkan apa adanya. Hanya kegagalan yang
    // memang dipulihkan dengan sesi baru yang diarahkan untuk masuk ulang.
    if (failure.code === 'configuration' || failure.code === 'session') {
      throw new UsernameClaimError(failure.code, USERNAME_CLAIM_RETRY_MESSAGES[failure.code])
    }
    throw failure
  }
}

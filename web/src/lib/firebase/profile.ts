import { doc, runTransaction } from 'firebase/firestore'
import { getFirebaseClient } from './client'
import { readUsernameClaim } from './usernames'
import {
  buildUserProfileDocument,
  readProfileCreatedAt,
  readProfileUsername,
  type UserProfileDocument,
  type UserProfileIdentity,
} from './profileDocuments'

async function usernameForProfile(uid: string): Promise<string | null> {
  try {
    const claim = await readUsernameClaim(uid)
    return claim?.username ?? null
  } catch {
    // Pointer klaim belum dapat dibaca (misalnya aturan belum diperbarui). Profil
    // tetap disinkronkan tanpa username; nilai lama tidak hilang karena klaim
    // sendiri tidak pernah ditulis ulang.
    return null
  }
}

export async function syncUserProfile(
  identity: UserProfileIdentity,
  now: string = new Date().toISOString(),
): Promise<UserProfileDocument> {
  const uid = identity.uid.trim()

  if (!uid || uid.includes('/')) {
    throw new Error('UID akun tidak valid untuk sinkronisasi profil.')
  }

  const claimedUsername = identity.username === undefined ? await usernameForProfile(uid) : null
  const { db } = getFirebaseClient()
  const ref = doc(db, 'users', uid)

  return runTransaction(db, async (transaction) => {
    const snapshot = await transaction.get(ref)
    const existingData = snapshot.exists() ? (snapshot.data() as Record<string, unknown>) : undefined
    const existingCreatedAt = readProfileCreatedAt(existingData, uid)
    const existingUsername = readProfileUsername(existingData, uid)
    const profile = buildUserProfileDocument(
      {
        ...identity,
        username: claimedUsername ?? identity.username ?? existingUsername,
      },
      existingCreatedAt,
      now,
    )

    transaction.set(ref, profile)
    return profile
  })
}

import { doc, getDoc } from 'firebase/firestore'
import { useCallback, useEffect, useRef, useState } from 'react'
import { getFirebaseClient } from '../firebase/client'
import { getFirebaseErrorCode } from '../firebase/errors'
import { useAuth } from './useAuth'

export type AdminRoleStatus = 'loading' | 'admin' | 'none' | 'error'

type AdminRoleSnapshot = {
  uid: string | null
  status: AdminRoleStatus
  error: string | null
}

const INITIAL_SNAPSHOT: AdminRoleSnapshot = {
  uid: null,
  status: 'none',
  error: null,
}

export async function isAdminAllowlisted(uid: string): Promise<boolean> {
  const { db } = getFirebaseClient()
  try {
    const snapshot = await getDoc(doc(db, 'admins', uid))
    if (!snapshot.exists()) return false
    const data = snapshot.data()
    return data.active === true && data.role === 'admin'
  } catch (error) {
    // Dokumen tidak ada juga dapat muncul sebagai permission-denied pada aturan
    // tertentu. Keduanya berarti bukan admin, bukan alasan untuk menaikkan akses.
    if (getFirebaseErrorCode(error) === 'permission-denied') return false
    throw error
  }
}

/**
 * Peran hanya dipakai untuk tampilan dan navigasi. Batas keamanan sebenarnya ada
 * di Firestore Rules: setiap baca/tulis moderasi memeriksa allowlist admins/{uid}.
 */
export function useAdminRole() {
  const { mode, status: authStatus, user } = useAuth()
  const eligibleUid =
    mode === 'firebase' &&
    authStatus === 'ready' &&
    user &&
    !user.isAnonymous &&
    user.emailVerified
      ? user.uid
      : null
  const [snapshot, setSnapshot] = useState<AdminRoleSnapshot>(INITIAL_SNAPSHOT)
  const requestRef = useRef(0)

  const refresh = useCallback(async () => {
    if (!eligibleUid) {
      requestRef.current += 1
      setSnapshot(INITIAL_SNAPSHOT)
      return
    }

    const request = requestRef.current + 1
    requestRef.current = request
    setSnapshot({ uid: eligibleUid, status: 'loading', error: null })

    try {
      const admin = await isAdminAllowlisted(eligibleUid)
      if (requestRef.current !== request) return
      setSnapshot({
        uid: eligibleUid,
        status: admin ? 'admin' : 'none',
        error: null,
      })
    } catch (error) {
      if (requestRef.current !== request) return
      setSnapshot({
        uid: eligibleUid,
        status: 'error',
        error:
          getFirebaseErrorCode(error) === 'permission-denied'
            ? 'Peran admin tidak dapat dibaca oleh akun ini.'
            : 'Peran admin belum dapat diverifikasi. Periksa koneksi lalu coba lagi.',
      })
    }
  }, [eligibleUid])

  useEffect(() => {
    // oxlint-disable-next-line react/set-state-in-effect -- verifikasi peran dari Firestore
    void refresh()
  }, [refresh])

  const currentUid = eligibleUid
  const status: AdminRoleStatus =
    currentUid === null
      ? 'none'
      : snapshot.uid !== currentUid
        ? 'loading'
        : snapshot.status

  return {
    status,
    isAdmin: status === 'admin',
    error: snapshot.uid === currentUid ? snapshot.error : null,
    refresh,
  }
}

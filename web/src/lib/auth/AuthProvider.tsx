import { onAuthStateChanged, type User } from 'firebase/auth'
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  applyEmailVerificationCode,
  createEmailAccount,
  deleteUnclaimedAccountJustCreated,
  ensureAnonymousSession,
  reloadEmailVerification,
  requestPasswordReset,
  sendVerificationEmail,
  sendVerificationEmailToCurrentUser,
  signInWithEmail,
  signOutFromFirebase,
} from '../firebase/auth'
import { getFirebaseClient } from '../firebase/client'
import { userFacingText } from '../uiText'
import { firebaseConfigState } from '../firebase/config'
import { authErrorMessage, firestoreErrorMessage } from '../firebase/errors'
import { syncUserProfile } from '../firebase/profile'
import type { UserProfileDocument } from '../firebase/profileDocuments'
import {
  UsernameClaimError,
  claimUsername,
  claimUsernameForCurrentUser,
} from '../firebase/usernames'
import { validateUsername } from '../usernames/policy'
import {
  endLocalDemoSession,
  getLocalDemoSession,
  startLocalDemoSession,
  type LocalDemoSession,
} from '../session/session'
import {
  AuthContext,
  type AppUser,
  type AuthContextValue,
  type AuthStatus,
  type ProfileSyncStatus,
} from './context'

function toAppUser(user: User): AppUser {
  return {
    uid: user.uid,
    email: user.email,
    displayName: user.displayName?.trim() || user.email || 'Pengguna',
    emailVerified: user.emailVerified,
    isAnonymous: user.isAnonymous,
    startedAt: null,
  }
}

function toDemoUser(session: LocalDemoSession): AppUser {
  return {
    uid: 'local-demo',
    email: null,
    displayName: session.displayName,
    emailVerified: false,
    isAnonymous: false,
    startedAt: session.startedAt,
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [demoSession, setDemoSession] = useState<LocalDemoSession | null>(() =>
    firebaseConfigState.configured ? null : getLocalDemoSession(),
  )
  const [firebaseUser, setFirebaseUser] = useState<AppUser | null>(null)
  const [status, setStatus] = useState<AuthStatus>(
    firebaseConfigState.configured ? 'loading' : 'ready',
  )
  const [initializationError, setInitializationError] = useState<string | null>(null)
  const [profile, setProfile] = useState<UserProfileDocument | null>(null)
  const [profileStatus, setProfileStatus] = useState<ProfileSyncStatus>('idle')
  const [profileError, setProfileError] = useState<string | null>(null)
  const activeRef = useRef(true)
  const firebaseUserRef = useRef<User | null>(null)
  const profileRequestRef = useRef(0)
  const profileSyncedForRef = useRef<string | null>(null)

  useEffect(() => {
    activeRef.current = true
    return () => {
      activeRef.current = false
      profileRequestRef.current += 1
    }
  }, [])

  const clearProfile = useCallback(() => {
    profileRequestRef.current += 1
    profileSyncedForRef.current = null
    setProfile(null)
    setProfileStatus('idle')
    setProfileError(null)
  }, [])

  const updateActiveUser = useCallback((user: User) => {
    firebaseUserRef.current = user
    setFirebaseUser(toAppUser(user))
    setStatus('ready')
  }, [])

  const syncProfile = useCallback(async (user: User) => {
    if (!activeRef.current) return false

    const request = profileRequestRef.current + 1
    profileRequestRef.current = request
    setProfileStatus('syncing')
    setProfileError(null)

    try {
      const syncedProfile = await syncUserProfile({
        uid: user.uid,
        email: user.email,
        displayName: user.displayName,
      })

      if (!activeRef.current || profileRequestRef.current !== request) return false
      setProfile(syncedProfile)
      setProfileStatus('synced')
      return true
    } catch (error) {
      if (!activeRef.current || profileRequestRef.current !== request) return false
      setProfileStatus('error')
      setProfileError(firestoreErrorMessage(error))
      return false
    }
  }, [])

  const retryProfileSync = useCallback(async () => {
    const currentUser = firebaseUserRef.current
    if (!currentUser) return
    await syncProfile(currentUser)
  }, [syncProfile])

  const ensureGuestSession = useCallback(async () => {
    if (!firebaseConfigState.configured) return
    await ensureAnonymousSession()
  }, [])

  useEffect(() => {
    if (!firebaseConfigState.configured) return

    let active = true
    let unsubscribe: () => void = () => undefined

    try {
      const { auth } = getFirebaseClient()
      unsubscribe = onAuthStateChanged(
        auth,
        (user) => {
          if (!active) return
          firebaseUserRef.current = user

          if (user) {
            updateActiveUser(user)
            if (user.isAnonymous || !user.emailVerified) {
              clearProfile()
            }
          } else {
            setFirebaseUser(null)
            setStatus('ready')
            clearProfile()
          }
        },
        (error) => {
          if (!active) return
          setInitializationError(authErrorMessage(error))
          setStatus('error')
        },
      )
    } catch (error) {
      queueMicrotask(() => {
        if (!active) return
        setInitializationError(
          error instanceof Error
            ? userFacingText(error.message)
            : 'Layanan akun tidak dapat diinisialisasi.',
        )
        setStatus('error')
      })
    }

    return () => {
      active = false
      unsubscribe()
    }
  }, [clearProfile, syncProfile, updateActiveUser])

  // Sinkron profil hanya untuk akun berverifikasi. onAuthStateChanged tidak
  // selalu menyala ulang saat email dikonfirmasi, jadi transisi status di sini
  // yang memicu sinkron pertama kali. Ref mencegah loop sinkron berkelanjutan.
  useEffect(() => {
    if (!firebaseConfigState.configured) return

    const rawUser = firebaseUserRef.current
    if (!rawUser || !firebaseUser || rawUser.uid !== firebaseUser.uid) return
    if (rawUser.isAnonymous || !firebaseUser.emailVerified) return
    if (profileSyncedForRef.current === rawUser.uid) return

    profileSyncedForRef.current = rawUser.uid
    void syncProfile(rawUser)
  }, [firebaseUser, syncProfile])

  const startDemoSession = useCallback((displayName: string) => {
    const session = startLocalDemoSession(displayName)
    setDemoSession(session)
  }, [])

  const endDemoSession = useCallback(() => {
    endLocalDemoSession()
    setDemoSession(null)
  }, [])

  const signIn = useCallback(
    async (email: string, password: string) => {
      const user = await signInWithEmail(email, password)
      updateActiveUser(user)
      return { emailVerified: user.emailVerified }
    },
    [updateActiveUser],
  )

  const signUp = useCallback(
    async (displayName: string, email: string, password: string, username: string) => {
      const checked = validateUsername(username)
      if (!checked.valid) throw new UsernameClaimError('invalid-username', checked.error)

      const user = await createEmailAccount(displayName, email, password)
      updateActiveUser(user)

      try {
        const claim = await claimUsername(user.uid, checked.username)
        const verificationSent = await sendVerificationEmail(user)
        return {
          emailVerified: user.emailVerified,
          verificationSent,
          username: claim.username,
        }
      } catch (error) {
        const rolledBack = await deleteUnclaimedAccountJustCreated(user)
        if (rolledBack) {
          firebaseUserRef.current = null
          setFirebaseUser(null)
          clearProfile()
          throw error
        }

        // Penghapusan tidak aman terjadi. Sisa akun dibiarkan apa adanya (email belum
        // terverifikasi, username belum terklaim) lalu sesi ditutup agar pemiliknya
        // dapat masuk ulang dan mengklaim username sendiri.
        profileSyncedForRef.current = null
        await signOutFromFirebase().catch(() => undefined)
        firebaseUserRef.current = null
        setFirebaseUser(null)
        clearProfile()
        throw new UsernameClaimError(
          'configuration',
          'Akun berhasil dibuat, tetapi username belum terpasang. Masuk dengan email ini, lalu klaim username pada halaman Pengaturan.',
        )
      }
    },
    [clearProfile, updateActiveUser],
  )

  const claimExistingUsername = useCallback(
    async (username: string) => {
      const checked = validateUsername(username)
      if (!checked.valid) throw new UsernameClaimError('invalid-username', checked.error)

      const rawUser = firebaseUserRef.current
      if (!rawUser || rawUser.isAnonymous) throw new UsernameClaimError('session')

      const claim = await claimUsernameForCurrentUser(checked.username)
      profileSyncedForRef.current = claim.uid
      const profileSynced = await syncProfile(rawUser)
      return { username: claim.username, profileSynced }
    },
    [syncProfile],
  )

  const signOut = useCallback(async () => {
    if (firebaseConfigState.configured) {
      await signOutFromFirebase()
      firebaseUserRef.current = null
      setFirebaseUser(null)
      clearProfile()
      return
    }

    endLocalDemoSession()
    setDemoSession(null)
    clearProfile()
  }, [clearProfile])

  const resetPassword = useCallback(async (email: string) => {
    await requestPasswordReset(email)
  }, [])

  const resendVerificationEmail = useCallback(async () => {
    await sendVerificationEmailToCurrentUser()
  }, [])

  const refreshEmailVerification = useCallback(async () => {
    const result = await reloadEmailVerification()
    if (result.signedIn && activeRef.current) {
      const currentUser = firebaseUserRef.current
      if (currentUser) updateActiveUser(currentUser)
    }
    return result
  }, [updateActiveUser])

  const applyVerificationCode = useCallback(
    async (code: string) => {
      const result = await applyEmailVerificationCode(code)
      if (result.signedIn && activeRef.current) {
        const currentUser = firebaseUserRef.current
        if (currentUser) updateActiveUser(currentUser)
      }
      return result
    },
    [updateActiveUser],
  )

  const mode = firebaseConfigState.configured ? 'firebase' : 'demo'
  const user = mode === 'firebase' ? firebaseUser : demoSession ? toDemoUser(demoSession) : null

  const value = useMemo<AuthContextValue>(
    () => ({
      mode,
      status,
      user,
      isFirebaseConfigured: firebaseConfigState.configured,
      configurationMissingKeys: firebaseConfigState.missingKeys,
      initializationError,
      profile,
      profileStatus,
      profileError,
      retryProfileSync,
      ensureGuestSession,
      startDemoSession,
      endDemoSession,
      signIn,
      signUp,
      claimExistingUsername,
      signOut,
      resetPassword,
      resendVerificationEmail,
      refreshEmailVerification,
      applyVerificationCode,
    }),
    [
      applyVerificationCode,
      claimExistingUsername,
      endDemoSession,
      ensureGuestSession,
      initializationError,
      mode,
      profile,
      profileError,
      profileStatus,
      refreshEmailVerification,
      resetPassword,
      resendVerificationEmail,
      retryProfileSync,
      signIn,
      signOut,
      signUp,
      startDemoSession,
      status,
      user,
    ],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

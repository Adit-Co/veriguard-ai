import { createContext } from 'react'
import type { EmailVerificationResult } from '../firebase/auth'
import type { UserProfileDocument } from '../firebase/profileDocuments'

export type AuthMode = 'demo' | 'firebase'
export type AuthStatus = 'loading' | 'ready' | 'error'
export type ProfileSyncStatus = 'idle' | 'syncing' | 'synced' | 'error'

export type AppUser = {
  uid: string
  email: string | null
  displayName: string
  emailVerified: boolean
  isAnonymous: boolean
  startedAt: string | null
}

export type SignInResult = {
  emailVerified: boolean
}

export type SignUpResult = {
  emailVerified: boolean
  verificationSent: boolean
  username: string
}

export type ClaimUsernameResult = {
  username: string
  profileSynced: boolean
}

export type AuthContextValue = {
  mode: AuthMode
  status: AuthStatus
  user: AppUser | null
  isFirebaseConfigured: boolean
  configurationMissingKeys: string[]
  initializationError: string | null
  profile: UserProfileDocument | null
  profileStatus: ProfileSyncStatus
  profileError: string | null
  retryProfileSync: () => Promise<void>
  ensureGuestSession: () => Promise<void>
  startDemoSession: (displayName: string) => void
  endDemoSession: () => void
  signIn: (email: string, password: string) => Promise<SignInResult>
  signUp: (
    displayName: string,
    email: string,
    password: string,
    username: string,
  ) => Promise<SignUpResult>
  claimExistingUsername: (username: string) => Promise<ClaimUsernameResult>
  signOut: () => Promise<void>
  resetPassword: (email: string) => Promise<void>
  resendVerificationEmail: () => Promise<void>
  refreshEmailVerification: () => Promise<EmailVerificationResult>
  applyVerificationCode: (code: string) => Promise<EmailVerificationResult>
}

export const AuthContext = createContext<AuthContextValue | null>(null)

// @vitest-environment jsdom

import { render, waitFor } from '@testing-library/react'
import { act } from '@testing-library/react'
import { useContext, useEffect } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthContext, type AuthContextValue } from './context'

const mocks = vi.hoisted(() => ({
  onAuthStateChanged: vi.fn(),
  syncUserProfile: vi.fn(),
  signOutFromFirebase: vi.fn(),
  reloadEmailVerification: vi.fn(),
  applyEmailVerificationCode: vi.fn(),
  createEmailAccount: vi.fn(),
  sendVerificationEmail: vi.fn(),
  deleteUnclaimedAccountJustCreated: vi.fn(),
  claimUsername: vi.fn(),
  claimUsernameForCurrentUser: vi.fn(),
}))

vi.mock('firebase/auth', () => ({
  onAuthStateChanged: mocks.onAuthStateChanged,
}))

vi.mock('../firebase/config', () => ({
  firebaseConfigState: { configured: true, missingKeys: [] },
  isFirebaseConfigured: true,
}))

vi.mock('../firebase/client', () => ({
  getFirebaseClient: () => ({ auth: {}, db: {} }),
}))

vi.mock('../firebase/profile', () => ({
  syncUserProfile: mocks.syncUserProfile,
}))

// UsernameClaimError tetap kelas aslinya supaya pemeriksaan galat di produksi
// (instanceof) juga berlaku pada pengujian.
vi.mock('../firebase/usernames', async () => {
  const actual = await vi.importActual<typeof import('../firebase/usernames')>(
    '../firebase/usernames',
  )
  return {
    ...actual,
    claimUsername: mocks.claimUsername,
    claimUsernameForCurrentUser: mocks.claimUsernameForCurrentUser,
  }
})

vi.mock('../firebase/auth', () => ({
  applyEmailVerificationCode: mocks.applyEmailVerificationCode,
  createEmailAccount: mocks.createEmailAccount,
  deleteUnclaimedAccountJustCreated: mocks.deleteUnclaimedAccountJustCreated,
  ensureAnonymousSession: vi.fn(async () => undefined),
  reloadEmailVerification: mocks.reloadEmailVerification,
  requestPasswordReset: vi.fn(async () => undefined),
  sendVerificationEmail: mocks.sendVerificationEmail,
  sendVerificationEmailToCurrentUser: vi.fn(async () => undefined),
  signInWithEmail: vi.fn(async () => ({})),
  signOutFromFirebase: mocks.signOutFromFirebase,
}))

import { AuthProvider } from './AuthProvider'
import { UsernameClaimError } from '../firebase/usernames'
import type { UserProfileDocument } from '../firebase/profileDocuments'

type AuthListener = (user: unknown) => void

let listener: AuthListener = () => undefined
let latest: AuthContextValue | null = null

function firebaseUser(overrides: Record<string, unknown> = {}) {
  return {
    uid: 'user-a',
    email: 'user-a@example.com',
    displayName: 'Pengguna A',
    emailVerified: true,
    isAnonymous: false,
    ...overrides,
  }
}

function profileFixture(): UserProfileDocument {
  return {
    uid: 'user-a',
    email: 'user-a@example.com',
    displayName: 'Pengguna A',
    username: 'pengguna_a',
    createdAt: '2026-10-01T00:00:00.000Z',
    lastLoginAt: '2026-10-20T00:00:00.000Z',
  }
}

function Consumer() {
  const value = useContext(AuthContext)
  useEffect(() => {
    latest = value
  })
  return null
}

function emit(user: unknown) {
  act(() => {
    listener(user)
  })
}

afterEach(() => {
  vi.clearAllMocks()
  listener = () => undefined
  latest = null
})

describe('sinkronisasi profil AuthProvider', () => {
  it('tidak menyimpan profil akun yang emailnya belum terkonfirmasi', async () => {
    mocks.syncUserProfile.mockResolvedValue(profileFixture())

    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    )

    const captured = mocks.onAuthStateChanged.mock.calls.at(-1)?.[1] as AuthListener
    listener = captured
    emit(firebaseUser({ emailVerified: false }))

    expect(latest?.user?.emailVerified).toBe(false)
    expect(latest?.profile).toBeNull()
    expect(latest?.profileStatus).toBe('idle')
    expect(mocks.syncUserProfile).not.toHaveBeenCalled()
  })

  it('menyinkronkan profil setelah email terkonfirmasi', async () => {
    mocks.syncUserProfile.mockResolvedValue(profileFixture())

    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    )
    listener = mocks.onAuthStateChanged.mock.calls.at(-1)![1] as AuthListener

    emit(firebaseUser({ emailVerified: false }))
    await act(async () => {
      emit(firebaseUser({ emailVerified: true }))
      await Promise.resolve()
    })

    await waitFor(() => expect(mocks.syncUserProfile).toHaveBeenCalledTimes(1))
    expect(latest?.profileStatus).toBe('synced')
  })

  it('tidak mengulang sinkron profil tanpa perubahan status', async () => {
    mocks.syncUserProfile.mockResolvedValue(profileFixture())

    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    )
    listener = mocks.onAuthStateChanged.mock.calls.at(-1)![1] as AuthListener

    await act(async () => {
      emit(firebaseUser({ emailVerified: true }))
      await Promise.resolve()
    })
    await act(async () => {
      emit(firebaseUser({ emailVerified: true }))
      await Promise.resolve()
    })

    expect(mocks.syncUserProfile).toHaveBeenCalledTimes(1)
  })

  it('membersihkan profil untuk sesi anonim dan setelah keluar', async () => {
    mocks.syncUserProfile.mockResolvedValue(profileFixture())

    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    )
    listener = mocks.onAuthStateChanged.mock.calls.at(-1)![1] as AuthListener

    await act(async () => {
      emit(firebaseUser({ emailVerified: true }))
      await Promise.resolve()
    })
    expect(latest?.profileStatus).toBe('synced')

    emit(firebaseUser({ uid: 'guest-1', email: null, isAnonymous: true, emailVerified: false }))
    expect(latest?.profile).toBeNull()
    expect(latest?.profileStatus).toBe('idle')

    emit(null)
    expect(latest?.profile).toBeNull()
  })

  it('status verifikasi hasil reload dipakai sebagai sumber kebenaran', async () => {
    mocks.syncUserProfile.mockResolvedValue(profileFixture())

    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    )
    listener = mocks.onAuthStateChanged.mock.calls.at(-1)![1] as AuthListener
    const user = firebaseUser({ emailVerified: false })
    emit(user)

    mocks.reloadEmailVerification.mockImplementation(async () => {
      user.emailVerified = true
      return { verified: true, signedIn: true }
    })

    await act(async () => {
      await latest?.refreshEmailVerification()
      await Promise.resolve()
    })

    expect(latest?.user?.emailVerified).toBe(true)
    await waitFor(() => expect(mocks.syncUserProfile).toHaveBeenCalledTimes(1))
  })

  it('mewariskan status tanpa user saat mode firebase tetapi belum masuk', () => {
    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    )
    listener = mocks.onAuthStateChanged.mock.calls.at(-1)![1] as AuthListener

    emit(null)
    expect(latest?.user).toBeNull()
    expect(latest?.status).toBe('ready')
  })
})

describe('pendaftaran dengan username', () => {
  const REGISTER_INPUT = ['Pengguna Baru', 'pengguna@contoh.com', 'sandiyaku123', 'Gyat123'] as const

  function mount() {
    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    )
    listener = mocks.onAuthStateChanged.mock.calls.at(-1)![1] as AuthListener
  }

  beforeEach(() => {
    mocks.createEmailAccount.mockReset().mockResolvedValue(
      firebaseUser({ emailVerified: false, displayName: 'Pengguna Baru' }),
    )
    mocks.claimUsername.mockReset().mockResolvedValue({
      username: 'gyat123',
      uid: 'user-a',
      createdAt: '2026-10-30T00:00:00.000Z',
    })
    mocks.sendVerificationEmail.mockReset().mockResolvedValue(true)
    mocks.deleteUnclaimedAccountJustCreated.mockReset().mockResolvedValue(false)
    mocks.signOutFromFirebase.mockReset().mockResolvedValue(undefined)
  })

  it('skenario 1:akun dibuat, username diklaim, baru lalu email verifikasi dikirim', async () => {
    const user = firebaseUser({ emailVerified: false })
    mocks.createEmailAccount.mockResolvedValue(user)
    mount()

    const result = await act(async () => latest!.signUp(...REGISTER_INPUT))

    expect(mocks.createEmailAccount).toHaveBeenCalledWith(
      'Pengguna Baru',
      'pengguna@contoh.com',
      'sandiyaku123',
    )
    expect(mocks.claimUsername).toHaveBeenCalledWith('user-a', 'gyat123')
    expect(mocks.sendVerificationEmail).toHaveBeenCalledWith(user)
    expect(result).toEqual({
      emailVerified: false,
      verificationSent: true,
      username: 'gyat123',
    })
    expect(latest?.user?.uid).toBe('user-a')
    expect(mocks.deleteUnclaimedAccountJustCreated).not.toHaveBeenCalled()
  })

  it('profil belum ditulis selama email belum terkonfirmasi', async () => {
    mount()

    await act(async () => latest!.signUp(...REGISTER_INPUT))

    expect(mocks.syncUserProfile).not.toHaveBeenCalled()
    expect(latest?.profile).toBeNull()
  })

  it('skenario 5:format username ditolak sebelum akun dibuat', async () => {
    mount()

    const failure = await act(async () =>
      latest!
        .signUp('Pengguna Baru', 'pengguna@contoh.com', 'sandiyaku123', 'ab')
        .catch((error: unknown) => error),
    )

    expect((failure as UsernameClaimError).code).toBe('invalid-username')
    expect(mocks.createEmailAccount).not.toHaveBeenCalled()
    expect(mocks.claimUsername).not.toHaveBeenCalled()
  })

  it('skenario 2 dan 7:username sudah dipakai → akun baru dirollback, email tidak dikirim', async () => {
    mocks.claimUsername.mockRejectedValue(new UsernameClaimError('taken'))
    mocks.deleteUnclaimedAccountJustCreated.mockResolvedValue(true)
    mount()

    const failure = await act(async () =>
      latest!.signUp(...REGISTER_INPUT).catch((error: unknown) => error),
    )

    expect(failure).toBeInstanceOf(UsernameClaimError)
    expect((failure as UsernameClaimError).code).toBe('taken')
    expect(mocks.sendVerificationEmail).not.toHaveBeenCalled()
    expect(mocks.deleteUnclaimedAccountJustCreated).toHaveBeenCalledTimes(1)
    expect(latest?.user).toBeNull()
  })

  it('skenario 8:rollback tidak mungkin → sesi ditutup tanpa menghapus akun lain', async () => {
    mocks.claimUsername.mockRejectedValue(new UsernameClaimError('offline'))
    mocks.deleteUnclaimedAccountJustCreated.mockResolvedValue(false)
    mount()

    const failure = await act(async () =>
      latest!.signUp(...REGISTER_INPUT).catch((error: unknown) => error),
    )

    expect((failure as UsernameClaimError).code).toBe('configuration')
    expect((failure as Error).message).toContain('Pengaturan')
    expect(mocks.signOutFromFirebase).toHaveBeenCalledTimes(1)
    expect(latest?.user).toBeNull()
  })

  it('email verifikasi tetap dikirim setelah username terpasang', async () => {
    mount()

    await act(async () => latest!.signUp(...REGISTER_INPUT))

    expect(mocks.sendVerificationEmail).toHaveBeenCalledTimes(1)
  })

  it('skenario 9:akun lama yang sudah terverifikasi dapat memasang username dan profil ikut diperbarui', async () => {
    mocks.syncUserProfile.mockResolvedValue(profileFixture())
    mocks.claimUsernameForCurrentUser.mockResolvedValue({
      username: 'aditdev',
      uid: 'user-a',
      createdAt: '2026-10-30T00:00:00.000Z',
    })
    mount()

    await act(async () => {
      emit(firebaseUser({ emailVerified: true }))
      await Promise.resolve()
    })
    await waitFor(() => expect(mocks.syncUserProfile).toHaveBeenCalledTimes(1))

    const result = await act(async () => latest!.claimExistingUsername('AditDev'))

    expect(mocks.claimUsernameForCurrentUser).toHaveBeenCalledWith('aditdev')
    expect(result).toEqual({ username: 'aditdev', profileSynced: true })
    expect(mocks.syncUserProfile).toHaveBeenCalledTimes(2)
  })

  it('klaim akun lama tanpa sesi masuk menghasilkan pesan sesi', async () => {
    mount()
    emit(null)

    const failure = await act(async () =>
      latest!.claimExistingUsername('aditdev').catch((error: unknown) => error),
    )

    expect((failure as UsernameClaimError).code).toBe('session')
    expect(mocks.claimUsernameForCurrentUser).not.toHaveBeenCalled()
  })
})

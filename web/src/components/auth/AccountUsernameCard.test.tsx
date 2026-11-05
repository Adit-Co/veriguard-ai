// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { AppUser, AuthContextValue } from '../../lib/auth/context'
import type { UserProfileDocument } from '../../lib/firebase/profileDocuments'

const mocks = vi.hoisted(() => ({ useAuth: vi.fn(), claimExistingUsername: vi.fn() }))

vi.mock('../../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))

import { AccountUsernameCard } from './AccountUsernameCard'
import { UsernameClaimError } from '../../lib/firebase/usernames'

function account(overrides: Partial<AppUser> = {}): AppUser {
  return {
    uid: 'user-a',
    email: 'user-a@example.com',
    displayName: 'Pengguna A',
    emailVerified: true,
    isAnonymous: false,
    startedAt: null,
    ...overrides,
  }
}

function profileWith(username: string | null): UserProfileDocument {
  return {
    uid: 'user-a',
    email: 'user-a@example.com',
    displayName: 'Pengguna A',
    username,
    createdAt: '2026-10-01T00:00:00.000Z',
    lastLoginAt: '2026-10-30T00:00:00.000Z',
  }
}

function authFixture(overrides: Partial<AuthContextValue> = {}): AuthContextValue {
  return {
    mode: 'firebase',
    status: 'ready',
    user: account(),
    isFirebaseConfigured: true,
    configurationMissingKeys: [],
    initializationError: null,
    profile: profileWith(null),
    profileStatus: 'synced',
    profileError: null,
    retryProfileSync: vi.fn(async () => undefined),
    ensureGuestSession: vi.fn(async () => undefined),
    startDemoSession: vi.fn(),
    endDemoSession: vi.fn(),
    signIn: vi.fn(),
    signUp: vi.fn(),
    claimExistingUsername: mocks.claimExistingUsername,
    signOut: vi.fn(async () => undefined),
    resetPassword: vi.fn(),
    resendVerificationEmail: vi.fn(async () => undefined),
    refreshEmailVerification: vi.fn(async () => ({ verified: true, signedIn: true })),
    applyVerificationCode: vi.fn(async () => ({ verified: true, signedIn: true })),
    ...overrides,
  }
}

beforeEach(() => {
  mocks.claimExistingUsername.mockReset().mockResolvedValue({
    username: 'aditdev',
    profileSynced: true,
  })
})

afterEach(() => {
  cleanup()
})

describe('kartu username akun', () => {
  it('skenario 6:pemilik lama melihat username yang sudah terpasang tanpa formulir', () => {
    mocks.useAuth.mockReturnValue(authFixture({ profile: profileWith('gyat123') }))
    render(<AccountUsernameCard />)

    expect(screen.getByText('@gyat123')).toBeTruthy()
    expect(screen.queryByRole('textbox')).toBeNull()
  })

  it('skenario 9:akun terverifikasi tanpa username mendapat jalur pemasangan mandiri', async () => {
    mocks.useAuth.mockReturnValue(authFixture())
    const user = userEvent.setup()
    render(<AccountUsernameCard />)

    await user.type(screen.getByLabelText('Username'), 'AditDev')
    await user.click(screen.getByRole('button', { name: 'Pasang username' }))

    await waitFor(() => expect(mocks.claimExistingUsername).toHaveBeenCalledWith('aditdev'))
    expect(await screen.findByText('@aditdev')).toBeTruthy()
  })

  it('username yang sudah dipakai dilaporkan tanpa menghapus formulir secara menyesatkan', async () => {
    mocks.claimExistingUsername.mockRejectedValue(new UsernameClaimError('taken'))
    mocks.useAuth.mockReturnValue(authFixture())
    const user = userEvent.setup()
    render(<AccountUsernameCard />)

    await user.type(screen.getByLabelText('Username'), 'gyat123')
    await user.click(screen.getByRole('button', { name: 'Pasang username' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('Username sudah dipakai akun lain')
    expect(mocks.claimExistingUsername).toHaveBeenCalledTimes(1)
  })

  it('format tidak valid dihentikan sebelum memanggil layanan data', async () => {
    mocks.useAuth.mockReturnValue(authFixture())
    const user = userEvent.setup()
    render(<AccountUsernameCard />)

    await user.type(screen.getByLabelText('Username'), 'ab')
    await user.click(screen.getByRole('button', { name: 'Pasang username' }))

    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(mocks.claimExistingUsername).not.toHaveBeenCalled()
  })

  it('mode demo tidak menampilkan kartu username', () => {
    mocks.useAuth.mockReturnValue(authFixture({ mode: 'demo', profile: null, user: null }))
    render(<AccountUsernameCard />)

    expect(screen.queryByText('Username akun')).toBeNull()
  })
})

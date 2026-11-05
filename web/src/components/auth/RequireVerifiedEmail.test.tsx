// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ReactElement, ReactNode } from 'react'
import type { AppUser, AuthContextValue } from '../../lib/auth/context'

const mocks = vi.hoisted(() => ({ useAuth: vi.fn() }))

vi.mock('../../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))

import { RequireVerifiedEmail } from './RequireVerifiedEmail'
import { appRoutes } from '../../router'
import {
  VERIFICATION_EMAIL_PATH,
  verificationGate,
} from '../../lib/auth/verification'

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

function authFixture(overrides: Partial<AuthContextValue> = {}): AuthContextValue {
  return {
    mode: 'firebase',
    status: 'ready',
    user: account(),
    isFirebaseConfigured: true,
    configurationMissingKeys: [],
    initializationError: null,
    profile: null,
    profileStatus: 'idle',
    profileError: null,
    retryProfileSync: vi.fn(async () => undefined),
    ensureGuestSession: vi.fn(async () => undefined),
    startDemoSession: vi.fn(),
    endDemoSession: vi.fn(),
    signIn: vi.fn(),
    signUp: vi.fn(),
    claimExistingUsername: vi.fn(),
    signOut: vi.fn(async () => undefined),
    resetPassword: vi.fn(),
    resendVerificationEmail: vi.fn(),
    refreshEmailVerification: vi.fn(),
    applyVerificationCode: vi.fn(),
    ...overrides,
  }
}

function LocationProbe() {
  const location = useLocation()
  return (
    <div data-testid="probe">
      {`${location.pathname}${location.search}`}|{JSON.stringify(location.state ?? null)}
    </div>
  )
}

function renderGuarded(
  auth: AuthContextValue,
  path: string,
  children: ReactNode = <div>isi halaman terlindungi</div>,
) {
  mocks.useAuth.mockReturnValue(auth)

  const pattern = path.split('?')[0]

  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path={pattern}
          element={<RequireVerifiedEmail>{children}</RequireVerifiedEmail>}
        />
        <Route path={VERIFICATION_EMAIL_PATH} element={<LocationProbe />} />
        <Route path="*" element={<div data-testid="other">rute lain</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

afterEach(() => {
  cleanup()
  vi.resetAllMocks()
})

describe('keputusan gerbang verifikasi email', () => {
  it('mengalihkan akun masuk yang emailnya belum terkonfirmasi', () => {
    expect(verificationGate(authFixture({ user: account({ emailVerified: false }) }))).toBe(
      'redirect',
    )
  })

  it('mengizinkan akun yang emailnya sudah terkonfirmasi', () => {
    expect(verificationGate(authFixture())).toBe('allow')
  })

  it('tidak memaksa verifikasi bagi sesi anonim karena tamu memakai jalur publik', () => {
    expect(
      verificationGate(
        authFixture({ user: account({ uid: 'guest-1', email: null, isAnonymous: true }) }),
      ),
    ).toBe('allow')
  })

  it('tidak mengalihkan sebelum sesi diketahui atau saat belum masuk', () => {
    expect(verificationGate(authFixture({ status: 'loading', user: null }))).toBe('allow')
    expect(verificationGate(authFixture({ user: null }))).toBe('allow')
    expect(verificationGate(authFixture({ mode: 'demo', user: account({ emailVerified: false }) }))).toBe(
      'allow',
    )
  })

  it('hanya membaca emailVerified, bukan ada tidaknya user', () => {
    const auth = authFixture({ user: account({ emailVerified: false }) })
    expect(Boolean(auth.user)).toBe(true)
    expect(verificationGate(auth)).toBe('redirect')
  })
})

describe('gerbang rute saat dirender', () => {
  it('mengarahkan ulang ke halaman verifikasi dan tidak merender isi halaman', () => {
    renderGuarded(authFixture({ user: account({ emailVerified: false }) }), '/dashboard')

    expect(screen.queryByText('isi halaman terlindungi')).toBeNull()
    expect(screen.getByTestId('probe').textContent).toContain(VERIFICATION_EMAIL_PATH)
  })

  it('menyimpan alamat tujuan termasuk query string di state pengalihan', () => {
    renderGuarded(
      authFixture({ user: account({ emailVerified: false }) }),
      '/riwayat?type=link&risk=high',
      <div>riwayat</div>,
    )

    const probe = screen.getByTestId('probe').textContent ?? ''
    expect(probe).toContain('"from":"/riwayat?type=link&risk=high"')
    expect(probe).toContain(VERIFICATION_EMAIL_PATH)
  })

  it('merender halaman seperti biasa untuk akun terverifikasi', () => {
    renderGuarded(authFixture(), '/dashboard')

    expect(screen.getByText('isi halaman terlindungi')).toBeTruthy()
    expect(screen.queryByTestId('probe')).toBeNull()
  })

  it('tidak mengubah jalur tamu pada halaman terlindungi', () => {
    renderGuarded(
      authFixture({ user: account({ uid: 'guest-1', email: null, isAnonymous: true }) }),
      '/periksa',
    )

    expect(screen.getByText('isi halaman terlindungi')).toBeTruthy()
  })
})

describe('pemasangan gerbang pada tabel rute', () => {
  const guardedPaths = ['periksa', 'hasil/:id', 'komunitas', 'riwayat', 'dashboard', 'dashboard/admin']
  const openPaths = [
    'verifikasi-email',
    'masuk',
    'daftar',
    'pengaturan',
    'edukasi',
    'edukasi/:slug',
  ]

  function isGuarded(element: ReactElement | undefined): boolean {
    return element?.type === RequireVerifiedEmail
  }

  it('membungkus setiap rute fitur akun dengan gerbang verifikasi', () => {
    for (const path of guardedPaths) {
      const route = appRoutes.find((entry) => entry.path === path)
      expect(route, `rute ${path} harus ada`).toBeTruthy()
      expect(isGuarded(route?.element as ReactElement | undefined), `${path} tidak digerbangi`).toBe(
        true,
      )
    }
  })

  it('membiarkan halaman verifikasi, masuk, daftar, pengaturan, dan edukasi terbuka', () => {
    for (const path of openPaths) {
      const route = appRoutes.find((entry) => entry.path === path)
      expect(route, `rute ${path} harus ada`).toBeTruthy()
      expect(isGuarded(route?.element as ReactElement | undefined)).toBe(false)
    }
  })

  it('membiarkan rute landing tanpa gerbang', () => {
    const index = appRoutes.find((entry) => entry.index === true)
    expect(index).toBeTruthy()
    expect(isGuarded(index?.element as ReactElement | undefined)).toBe(false)
  })
})

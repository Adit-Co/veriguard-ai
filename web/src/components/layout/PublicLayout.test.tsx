// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import type { AuthContextValue } from '../../lib/auth/context'
import { PublicLayout } from './PublicLayout'

const mocks = vi.hoisted(() => ({
  useAuth: vi.fn(),
}))

vi.mock('../../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))

// Navbar butuh konteks auth; status tamu cukup untuk menguji keputusan footer.
function guestState(): AuthContextValue {
  return {
    mode: 'firebase',
    status: 'ready',
    user: null,
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
  } as unknown as AuthContextValue
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route element={<PublicLayout />}>
          <Route path="*" element={<div data-testid="isi">isi halaman</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  mocks.useAuth.mockReturnValue(guestState())
})

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

// VGL-37C — aturan footer ditegakkan per route, bukan dengan menghapus komponen
// Footer atau menyembunyikannya lewat CSS global.
describe('footer situs hanya disembunyikan pada halaman autentikasi', () => {
  it.each(['/masuk', '/daftar', '/masuk/', '/daftar/'])(
    'tanpa footer di %s, konten tetap tampil',
    (path) => {
      const { container } = renderAt(path)
      expect(container.querySelector('footer')).toBeNull()
      expect(screen.getByTestId('isi')).toBeTruthy()
      expect(container.querySelector('header')).toBeTruthy()
    },
  )

  it.each([
    '/',
    '/periksa',
    '/edukasi',
    '/edukasi/mengenali-phishing',
    '/komunitas',
    '/riwayat',
    '/dashboard',
    '/pengaturan',
    '/verifikasi-email',
    '/rute-tidak-ada',
  ])('footer tetap ada di %s', (path) => {
    const { container } = renderAt(path)
    expect(container.querySelector('footer')).toBeTruthy()
  })
})

// VGL-37C — latar sinematik juga route-scoped, dan dipasang pada <main> (bukan elemen
// tambahan) karena layer ekstra mengubah antialiasing teks di dalam kartu baseline.
describe('latar autentikasi hanya terpasang pada /masuk dan /daftar', () => {
  it.each(['/masuk', '/daftar', '/masuk/', '/daftar/'])(
    '%s memakai latar pada main tanpa elemen backdrop tambahan',
    (path) => {
      const { container } = renderAt(path)
      const main = container.querySelector('main')
      expect(main?.className).toContain('auth-canvas')
      expect(main?.className).toContain('flex-1')
      expect(container.querySelector('.auth-backdrop')).toBeNull()
    },
  )

  it.each([
    '/',
    '/periksa',
    '/edukasi',
    '/komunitas',
    '/riwayat',
    '/dashboard',
    '/pengaturan',
  ])('%s mempertahankan main tanpa latar', (path) => {
    const { container } = renderAt(path)
    expect(container.querySelector('main')?.className).toBe('flex-1')
  })
})

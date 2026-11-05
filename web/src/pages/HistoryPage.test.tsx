// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import type { ScanResult } from '../lib/analysis'
import type { AuthContextValue } from '../lib/auth/context'

const mocks = vi.hoisted(() => ({
  useAuth: vi.fn(),
  useScanHistory: vi.fn(),
}))

vi.mock('../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))
vi.mock('../lib/scans/useScanHistory', () => ({
  useScanHistory: mocks.useScanHistory,
}))

import { HistoryPage } from './HistoryPage'

function authFixture(overrides: Partial<AuthContextValue> = {}): AuthContextValue {
  return {
    mode: 'firebase',
    status: 'ready',
    user: {
      uid: 'user-a',
      email: 'user-a@example.com',
      displayName: 'Pengguna A',
      emailVerified: true,
      isAnonymous: false,
      startedAt: null,
    },
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

function scanFixture(): ScanResult {
  return {
    id: 'scan-account-a',
    mode: 'link',
    input: 'https://contoh-situs.id/login',
    displayTarget: 'contoh-situs.id/login',
    riskScore: 65,
    riskLevel: 'high',
    headline: 'Indikasi phishing',
    summary: 'Tautan menyerupai halaman login bank.',
    reasons: [],
    patterns: [],
    recommendations: [],
    technical: [],
    meta: {
      engineVersion: 'test',
      signalCount: 0,
      inputLength: 32,
      aiStatus: 'not_used',
    },
    createdAt: '2026-10-20T02:00:00.000Z',
  }
}

function historyFixture(overrides: Record<string, unknown> = {}) {
  return {
    scans: [scanFixture()],
    loading: false,
    error: null,
    errorKind: null,
    source: 'cloud',
    pendingLocalCount: 0,
    syncMessage: null,
    refresh: vi.fn(async () => undefined),
    remove: vi.fn(async () => undefined),
    clear: vi.fn(async () => undefined),
    redactAll: vi.fn(async () => 0),
    syncLocalHistory: vi.fn(async () => ({ uploaded: 0, failed: 0, message: null })),
    ...overrides,
  }
}

function LoginStub() {
  const location = useLocation()
  const state = location.state as { from?: string } | null
  return <div data-testid="login-stub">{`masuk dari:${state?.from ?? '-'}`}</div>
}

function renderPage(route = '/riwayat?type=link&risk=high') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <Routes>
        <Route path="/riwayat" element={<HistoryPage />} />
        <Route path="/masuk" element={<LoginStub />} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  mocks.useAuth.mockReturnValue(authFixture())
  mocks.useScanHistory.mockReturnValue(historyFixture())
})

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

describe('Riwayat akun', () => {
  it('mengalihkan sesi Firebase yang belum masuk ke halaman masuk dengan alamat balik', () => {
    mocks.useAuth.mockReturnValue(authFixture({ user: null }))

    renderPage()

    expect(screen.getByTestId('login-stub').textContent).toBe(
      'masuk dari:/riwayat?type=link&risk=high',
    )
    expect(screen.queryByText('contoh-situs.id/login')).toBeNull()
    expect(screen.queryByText('Riwayat pemeriksaan')).toBeNull()
  })

  it('mengalihkan sesi anonim dan tidak menampilkan riwayat yang tersisa di state', () => {
    mocks.useAuth.mockReturnValue(
      authFixture({
        user: {
          uid: 'guest-1',
          email: null,
          displayName: 'Tamu',
          emailVerified: false,
          isAnonymous: true,
          startedAt: null,
        },
      }),
    )

    renderPage()

    expect(screen.getByTestId('login-stub').textContent).toBe(
      'masuk dari:/riwayat?type=link&risk=high',
    )
    expect(screen.queryByText('contoh-situs.id/login')).toBeNull()
  })

  it('tidak menampilkan riwayat akun saat sesi masih dipulihkan', () => {
    mocks.useAuth.mockReturnValue(authFixture({ status: 'loading', user: null }))

    renderPage()

    expect(screen.getByText('Memeriksa sesi akun…')).toBeTruthy()
    expect(screen.queryByTestId('login-stub')).toBeNull()
    expect(screen.queryByText('contoh-situs.id/login')).toBeNull()
  })

  it('menghapus tampilan akun segera setelah keluar tanpa menampilkan data lokal', () => {
    const view = renderPage()
    expect(screen.getByText('contoh-situs.id/login')).toBeTruthy()

    mocks.useAuth.mockReturnValue(authFixture({ user: null }))
    view.rerender(
      <MemoryRouter initialEntries={['/riwayat?type=link&risk=high']}>
        <Routes>
          <Route path="/riwayat" element={<HistoryPage />} />
          <Route path="/masuk" element={<LoginStub />} />
        </Routes>
      </MemoryRouter>,
    )

    expect(screen.getByTestId('login-stub')).toBeTruthy()
    expect(screen.queryByText('contoh-situs.id/login')).toBeNull()
  })

  it('mempertahankan riwayat lokal untuk sesi demo tanpa mengalihkan ke login', () => {
    mocks.useAuth.mockReturnValue(authFixture({ mode: 'demo', user: null }))
    mocks.useScanHistory.mockReturnValue(historyFixture({ source: 'local' }))

    renderPage()

    expect(screen.queryByTestId('login-stub')).toBeNull()
    expect(screen.getByText('contoh-situs.id/login')).toBeTruthy()
    expect(screen.getByText(/Riwayat disimpan di browser perangkat ini/)).toBeTruthy()
    expect(screen.getByText(/riwayat perangkat ini dikirim ke akun/)).toBeTruthy()
  })

  it('menampilkan riwayat milik akun yang sedang masuk', () => {
    renderPage()

    expect(screen.queryByTestId('login-stub')).toBeNull()
    expect(screen.getByText('contoh-situs.id/login')).toBeTruthy()
    expect(screen.getByText(/Riwayat dimuat dari penyimpanan data akun ini/)).toBeTruthy()
  })

  it('menjelaskan bahwa riwayat perangkat dikirim ke akun tanpa menghapus lebih dulu', () => {
    mocks.useScanHistory.mockReturnValue(historyFixture({ scans: [] }))

    renderPage('/riwayat')

    expect(screen.getByText('Belum ada riwayat')).toBeTruthy()
    expect(screen.getByText(/dikirim ke akun begitu halaman/)).toBeTruthy()
    expect(screen.getByText(/tetap tersimpan di browser dan tidak pernah dihapus lebih dulu/)).toBeTruthy()
  })

  it('menawarkan ulang sinkronisasi hanya saat masih ada riwayat perangkat yang mengantre', async () => {
    const syncLocalHistory = vi.fn(async () => ({ uploaded: 2, failed: 0, message: null }))
    mocks.useScanHistory.mockReturnValue(
      historyFixture({ pendingLocalCount: 2, syncMessage: 'Koneksi terputus.', syncLocalHistory }),
    )

    renderPage('/riwayat')

    expect(screen.getByText(/2 pemeriksaan masih tertahan di perangkat ini/)).toBeTruthy()
    expect(screen.getByText(/Koneksi terputus\./)).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: 'Sinkronkan sekarang' }))

    await waitFor(() => expect(syncLocalHistory).toHaveBeenCalledTimes(1))
    expect(screen.queryByText('Tindakan gagal')).toBeNull()
  })

  it('tetap menyembunyikan peringatan sinkronisasi untuk riwayat lokal perangkat', () => {
    mocks.useAuth.mockReturnValue(authFixture({ mode: 'demo', user: null }))
    mocks.useScanHistory.mockReturnValue(
      historyFixture({ source: 'local', pendingLocalCount: 3 }),
    )

    renderPage('/riwayat')

    expect(screen.queryByText(/masih tertahan di perangkat ini/)).toBeNull()
  })
})

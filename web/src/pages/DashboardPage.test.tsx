// @vitest-environment jsdom

import { cleanup, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import type { ScanResult } from '../lib/analysis'
import type { AuthContextValue } from '../lib/auth/context'

const mocks = vi.hoisted(() => ({
  useAuth: vi.fn(),
  useAdminRole: vi.fn(),
  useScanHistory: vi.fn(),
}))

vi.mock('../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))
vi.mock('../lib/auth/useAdminRole', () => ({ useAdminRole: mocks.useAdminRole }))
vi.mock('../lib/scans/useScanHistory', () => ({
  useScanHistory: mocks.useScanHistory,
}))

import { DashboardPage } from './DashboardPage'

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

function scanFixture(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    id: 'scan-a-1',
    mode: 'link',
    input: 'https://contoh-situs.id/login',
    displayTarget: 'contoh-situs.id/login',
    riskScore: 78,
    riskLevel: 'high',
    headline: 'Indikasi phishing',
    summary: 'Tautan menyerupai halaman login bank.',
    reasons: [],
    patterns: [
      {
        id: 'phishing',
        label: 'Phishing',
        description: 'Menyerupai layanan resmi.',
        confidence: 'high',
      },
    ],
    recommendations: [],
    technical: [],
    meta: {
      engineVersion: 'test',
      signalCount: 1,
      inputLength: 32,
      aiStatus: 'not_used',
    },
    createdAt: '2026-10-20T02:00:00.000Z',
    ...overrides,
  }
}

function historyFixture(overrides: Record<string, unknown> = {}) {
  return {
    scans: [],
    loading: false,
    error: null,
    errorKind: null,
    source: 'cloud',
    refresh: vi.fn(async () => undefined),
    remove: vi.fn(async () => undefined),
    clear: vi.fn(async () => undefined),
    redactAll: vi.fn(async () => 0),
    ...overrides,
  }
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Routes>
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/dashboard/admin" element={<div>admin-stub</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  mocks.useAuth.mockReturnValue(authFixture())
  mocks.useAdminRole.mockReturnValue({
    status: 'none',
    isAdmin: false,
    error: null,
    refresh: vi.fn(async () => undefined),
  })
  mocks.useScanHistory.mockReturnValue(historyFixture())
})

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

describe('Dashboard Saya', () => {
  it('menampilkan keadaan kosong yang jelas tanpa syarat jumlah pemeriksaan', () => {
    renderPage()

    expect(screen.getByText('Belum ada pemeriksaan tersimpan')).toBeTruthy()
    expect(screen.queryByText(/Butuh \d+ pemeriksaan lagi/)).toBeNull()
    expect(screen.queryByText(/minimal tiga pemeriksaan/i)).toBeNull()
    expect(screen.getByRole('link', { name: /Mulai pemeriksaan/ })).toBeTruthy()
  })

  it('menampilkan statistik akun setelah satu pemeriksaan tersimpan', () => {
    mocks.useScanHistory.mockReturnValue(historyFixture({ scans: [scanFixture()] }))

    renderPage()

    const totalCard = screen.getByText('Total pemeriksaan').closest('.rounded-card')
    expect(totalCard).toBeTruthy()
    expect(within(totalCard as HTMLElement).getByText('1')).toBeTruthy()
    expect(screen.getByText('Distribusi risiko')).toBeTruthy()
    expect(screen.getByText('Riwayat terbaru')).toBeTruthy()
    expect(screen.getByRole('link', { name: 'contoh-situs.id/login' }).getAttribute('href')).toBe(
      '/hasil/scan-a-1',
    )
    expect(screen.queryByText(/Butuh \d+ pemeriksaan lagi/)).toBeNull()
  })

  it('pengguna biasa hanya melihat Dashboard Saya', () => {
    renderPage()

    const tabs = screen.getByRole('navigation', { name: 'Bagian dashboard' })
    expect(within(tabs).getByRole('link', { name: 'Dashboard Saya' })).toBeTruthy()
    expect(within(tabs).queryByRole('link', { name: 'Dashboard Admin' })).toBeNull()
  })

  it('admin melihat tautan Dashboard Admin tanpa kehilangan Dashboard Saya', () => {
    mocks.useAdminRole.mockReturnValue({
      status: 'admin',
      isAdmin: true,
      error: null,
      refresh: vi.fn(async () => undefined),
    })

    renderPage()

    const tabs = screen.getByRole('navigation', { name: 'Bagian dashboard' })
    expect(within(tabs).getByRole('link', { name: 'Dashboard Saya' })).toBeTruthy()
    expect(
      within(tabs).getByRole('link', { name: 'Dashboard Admin' }).getAttribute('href'),
    ).toBe('/dashboard/admin')
  })

  it('sesi anonim diperlakukan sebagai belum masuk tanpa menampilkan statistik', () => {
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
    mocks.useScanHistory.mockReturnValue(historyFixture({ scans: [scanFixture()] }))

    renderPage()

    expect(screen.getByText('Dashboard memerlukan sesi')).toBeTruthy()
    expect(screen.queryByText('Total pemeriksaan')).toBeNull()
    expect(screen.queryByRole('navigation', { name: 'Bagian dashboard' })).toBeNull()
  })
})

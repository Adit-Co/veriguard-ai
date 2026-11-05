// @vitest-environment jsdom

import { webcrypto } from 'node:crypto'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import type { ScanResult } from '../lib/analysis'
import type { AuthContextValue } from '../lib/auth/context'
import { getPreferences, PREFERENCES_STORAGE_KEY } from '../lib/preferences/preferences'
import { MULTI_SOURCE_STORAGE_KEY } from '../lib/scanners/reportStore'
import { PENDING_SYNC_STORAGE_KEY } from '../lib/scans/pendingSyncStore'
import { SESSION_STORAGE_KEY } from '../lib/session/session'
import { SCAN_STORAGE_KEY } from '../lib/storage/scanStore'
import { SITE_ANALYSIS_STORAGE_KEY } from '../lib/website/analysisStore'

const mocks = vi.hoisted(() => ({
  useAuth: vi.fn(),
  useScanHistory: vi.fn(),
  demoAvailability: vi.fn(),
}))

vi.mock('../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))
vi.mock('../lib/scans/useScanHistory', () => ({ useScanHistory: mocks.useScanHistory }))
// VGL-41E: hanya pagar ketersediaan demo yang ditiru. Pencocokan identitas dan penyamaran
// berjalan lewat jalur asli, jadi yang teruji adalah tampilan yang dilihat pengguna.
vi.mock('../lib/auth/demoLogin', () => ({
  demoLoginAvailability: mocks.demoAvailability,
}))

import { SettingsPage } from './SettingsPage'

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
    id: 'scan-1',
    mode: 'message',
    input: 'hubungi saya di https://contoh.com/masuk',
    displayTarget: 'pesan',
    riskScore: 65,
    riskLevel: 'high',
    headline: 'Indikasi penipuan',
    summary: 'Pesan mengajak membuka tautan login.',
    reasons: [],
    patterns: [],
    recommendations: [],
    technical: [],
    meta: {
      engineVersion: 'test',
      signalCount: 0,
      inputLength: 38,
      aiStatus: 'not_used',
      inputStored: 'full',
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
    refresh: vi.fn(async () => undefined),
    remove: vi.fn(async () => undefined),
    clear: vi.fn(async () => undefined),
    redactAll: vi.fn(async () => 1),
    ...overrides,
  }
}

function seedAppStorage(): void {
  window.localStorage.setItem(SCAN_STORAGE_KEY, '[{"rusak":true}]')
  window.localStorage.setItem(MULTI_SOURCE_STORAGE_KEY, '{"scan-1":{"rusak":true}}')
  window.localStorage.setItem(SITE_ANALYSIS_STORAGE_KEY, '{"scan-1":{"rusak":true}}')
  window.localStorage.setItem(
    SESSION_STORAGE_KEY,
    JSON.stringify({
      kind: 'local-demo',
      displayName: 'Pengguna A',
      startedAt: '2026-10-20T02:00:00.000Z',
    }),
  )
  window.localStorage.setItem(
    PREFERENCES_STORAGE_KEY,
    JSON.stringify({ defaultScanMode: 'message', reduceMotion: true }),
  )
  window.localStorage.setItem(
    PENDING_SYNC_STORAGE_KEY,
    JSON.stringify({ uid: 'user-a', scanIds: ['scan-1'] }),
  )
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/pengaturan']}>
      <SettingsPage />
    </MemoryRouter>,
  )
}

function localKeysPresent(): string[] {
  return [
    SCAN_STORAGE_KEY,
    MULTI_SOURCE_STORAGE_KEY,
    SITE_ANALYSIS_STORAGE_KEY,
    SESSION_STORAGE_KEY,
    PREFERENCES_STORAGE_KEY,
    PENDING_SYNC_STORAGE_KEY,
  ].filter((key) => window.localStorage.getItem(key) !== null)
}

beforeEach(() => {
  window.localStorage.clear()
  mocks.useAuth.mockReturnValue(authFixture())
  mocks.useScanHistory.mockReturnValue(historyFixture())
  // Default: pagar demo tertutup, sama seperti build tanpa bendera.
  mocks.demoAvailability.mockReturnValue({ available: false, reason: 'Login demo tidak diaktifkan.' })
})

afterEach(() => {
  cleanup()
  window.localStorage.clear()
  vi.clearAllMocks()
})

describe('Hapus semua data lokal', () => {
  it('menghapus seluruh kunci aplikasi untuk akun terverifikasi tanpa menyentuh riwayat akun', async () => {
    seedAppStorage()
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    const history = historyFixture({ source: 'cloud' })
    mocks.useScanHistory.mockReturnValue(history)

    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Hapus semua data lokal' }))

    await waitFor(() => expect(screen.getByRole('status').textContent).toContain('Riwayat akun'))
    expect(localKeysPresent()).toEqual([])
    expect(getPreferences().defaultScanMode).toBe('link')
    // Riwayat akun hanya pergi lewat tombol "Hapus riwayat" yang terpisah.
    expect(history.clear).not.toHaveBeenCalled()
    expect(confirm.mock.calls[0]?.[0]).toContain('Riwayat di akun TIDAK ikut terhapus')
  })

  it('tetap tersedia dan tuntas saat riwayat dibaca dari perangkat', async () => {
    seedAppStorage()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    mocks.useAuth.mockReturnValue(authFixture({ mode: 'demo' }))
    mocks.useScanHistory.mockReturnValue(
      historyFixture({ source: 'local', scans: [scanFixture()] }),
    )

    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Hapus semua data lokal' }))

    await waitFor(() =>
      expect(screen.getByRole('status').textContent).toContain(
        'Preferensi kembali ke pengaturan awal.',
      ),
    )
    expect(localKeysPresent()).toEqual([])
  })

  it('tetap tersedia untuk akun yang emailnya belum terverifikasi', async () => {
    seedAppStorage()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    mocks.useAuth.mockReturnValue(
      authFixture({ user: { ...authFixture().user!, emailVerified: false } }),
    )
    mocks.useScanHistory.mockReturnValue(historyFixture({ source: 'local' }))

    renderPage()
    const button = screen.getByRole('button', { name: 'Hapus semua data lokal' })
    fireEvent.click(button)

    await waitFor(() => expect(localKeysPresent()).toEqual([]))
  })

  it('tidak menghapus apa pun ketika pembatalan dipilih', async () => {
    seedAppStorage()
    vi.spyOn(window, 'confirm').mockReturnValue(false)

    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Hapus semua data lokal' }))

    await waitFor(() => expect(screen.getByRole('status').textContent).toBe(''))
    expect(localKeysPresent()).toHaveLength(6)
  })

  it('menyimpan kunci pihak ketiga di luar daftar hapus', async () => {
    seedAppStorage()
    window.localStorage.setItem('firebaseLocalStorageDb', 'milik sdk')
    window.localStorage.setItem('capcha-token-cache', 'milik layanan')
    vi.spyOn(window, 'confirm').mockReturnValue(true)

    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Hapus semua data lokal' }))

    await waitFor(() => expect(localKeysPresent()).toEqual([]))
    expect(window.localStorage.getItem('firebaseLocalStorageDb')).toBe('milik sdk')
    expect(window.localStorage.getItem('capcha-token-cache')).toBe('milik layanan')
  })
})

const DEMO_ADMIN_EMAIL = 'aleksatya4@gmail.com'
const DEMO_USER_EMAIL = 'akusipemain@gmail.com'
const MASKED_EMAIL = '••••••••@••••••••'

async function digestOf(email: string): Promise<string> {
  const bytes = new TextEncoder().encode(email.trim().toLowerCase())
  const buffer = await webcrypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function serveDemoIdentities(digests: string[]): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(
      async () =>
        ({ ok: true, status: 200, json: async () => ({ digests }) }) as unknown as Response,
    ),
  )
}

describe('VGL-41E — kartu akun dan sesi pada halaman Pengaturan', () => {
  beforeEach(() => {
    vi.stubGlobal('crypto', webcrypto)
    mocks.demoAvailability.mockReturnValue({ available: true, reason: null })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('email Demo Admin tersamar dan tidak tertinggal di DOM', async () => {
    serveDemoIdentities([await digestOf(DEMO_ADMIN_EMAIL), await digestOf(DEMO_USER_EMAIL)])
    mocks.useAuth.mockReturnValue(
      authFixture({ user: { ...authFixture().user!, email: DEMO_ADMIN_EMAIL, displayName: 'Admin Demo' } }),
    )

    renderPage()

    await waitFor(() => expect(screen.getByText(MASKED_EMAIL)).toBeTruthy())
    expect(document.body.innerHTML).not.toContain(DEMO_ADMIN_EMAIL)
  })

  it('email Demo User tersamar dengan bentuk yang sama', async () => {
    serveDemoIdentities([await digestOf(DEMO_ADMIN_EMAIL), await digestOf(DEMO_USER_EMAIL)])
    mocks.useAuth.mockReturnValue(
      authFixture({ user: { ...authFixture().user!, email: DEMO_USER_EMAIL, displayName: 'Pengguna Demo' } }),
    )

    renderPage()

    await waitFor(() => expect(screen.getByText(MASKED_EMAIL)).toBeTruthy())
    expect(document.body.innerHTML).not.toContain(DEMO_USER_EMAIL)
  })

  it('akun biasa tetap menampilkan email aslinya', async () => {
    serveDemoIdentities([await digestOf(DEMO_ADMIN_EMAIL), await digestOf(DEMO_USER_EMAIL)])

    renderPage()

    await waitFor(() => expect(screen.getByText('user-a@example.com')).toBeTruthy())
    expect(screen.queryByText(MASKED_EMAIL)).toBeNull()
  })

  it('pindah akun mengikuti akun yang sedang masuk', async () => {
    const digests = [await digestOf(DEMO_ADMIN_EMAIL), await digestOf(DEMO_USER_EMAIL)]
    serveDemoIdentities(digests)
    mocks.useAuth.mockReturnValue(
      authFixture({ user: { ...authFixture().user!, email: DEMO_ADMIN_EMAIL, displayName: 'Admin Demo' } }),
    )

    const view = renderPage()
    await waitFor(() => expect(screen.getByText(MASKED_EMAIL)).toBeTruthy())

    // Beralih ke akun biasa pada halaman yang sama: samaran sesi sebelumnya harus hilang.
    mocks.useAuth.mockReturnValue(authFixture())
    view.rerender(
      <MemoryRouter initialEntries={['/pengaturan']}>
        <SettingsPage />
      </MemoryRouter>,
    )

    await waitFor(() => expect(screen.getByText('user-a@example.com')).toBeTruthy())
    expect(screen.queryByText(MASKED_EMAIL)).toBeNull()
  })

  it('setelah keluar tidak ada samaran maupun email yang tertinggal', async () => {
    serveDemoIdentities([await digestOf(DEMO_ADMIN_EMAIL)])
    mocks.useAuth.mockReturnValue(
      authFixture({ user: { ...authFixture().user!, email: DEMO_ADMIN_EMAIL, displayName: 'Admin Demo' } }),
    )

    const view = renderPage()
    await waitFor(() => expect(screen.getByText(MASKED_EMAIL)).toBeTruthy())

    mocks.useAuth.mockReturnValue(authFixture({ user: null }))
    view.rerender(
      <MemoryRouter initialEntries={['/pengaturan']}>
        <SettingsPage />
      </MemoryRouter>,
    )

    await waitFor(() => expect(screen.queryByText(MASKED_EMAIL)).toBeNull())
    expect(document.body.innerHTML).not.toContain(DEMO_ADMIN_EMAIL)
  })

  it('tanpa pagar demo, alamat akun masuk tampil seperti sebelumnya dan tidak ada permintaan identitas', async () => {
    mocks.demoAvailability.mockReturnValue({ available: false, reason: 'Login demo tidak diaktifkan.' })
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    mocks.useAuth.mockReturnValue(
      authFixture({ user: { ...authFixture().user!, email: DEMO_ADMIN_EMAIL } }),
    )

    renderPage()

    await waitFor(() => expect(screen.getByText(DEMO_ADMIN_EMAIL)).toBeTruthy())
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})

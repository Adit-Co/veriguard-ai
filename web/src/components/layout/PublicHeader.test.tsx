// @vitest-environment jsdom
/// <reference types="node" />

import { webcrypto } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { AuthContextValue } from '../../lib/auth/context'
import { PublicHeader } from './PublicHeader'

// VGL-34 — navbar sebelum/sesudah login, entry point registrasi, dan logo satu baris.

const mocks = vi.hoisted(() => ({
  useAuth: vi.fn(),
  demoAvailability: vi.fn(),
}))

vi.mock('../../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))
// VGL-41E: hanya pagar ketersediaan demo yang ditiru; pencocokan identitas dan penyamarannya
// berjalan asli supaya yang teruji adalah jalur yang dipakai pengguna.
vi.mock('../../lib/auth/demoLogin', () => ({
  demoLoginAvailability: mocks.demoAvailability,
}))

const HEADER_PATH = resolve(process.cwd(), 'src/components/layout/PublicHeader.tsx')
const LOGIN_PATH = resolve(process.cwd(), 'src/pages/LoginPage.tsx')
const ROUTER_PATH = resolve(process.cwd(), 'src/router.tsx')
const COMMUNITY_PATH = resolve(process.cwd(), 'src/pages/CommunityReportsPage.tsx')

/** @param {Partial<AuthContextValue>} overrides */
function authState(overrides: Partial<AuthContextValue> = {}): AuthContextValue {
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
    ...overrides,
  }
}

function signedInUser(): NonNullable<AuthContextValue['user']> {
  return {
    uid: 'user-1',
    email: 'sari@example.com',
    displayName: 'Sari Puspita',
    emailVerified: true,
    isAnonymous: false,
    startedAt: null,
  }
}

function renderHeader() {
  return render(
    <MemoryRouter>
      <PublicHeader />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  localStorage.clear()
  delete document.documentElement.dataset.theme
  mocks.useAuth.mockReturnValue(authState())
  // Default: pagar demo tertutup, sama seperti build tanpa bendera.
  mocks.demoAvailability.mockReturnValue({ available: false, reason: 'Login demo tidak diaktifkan.' })
})

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

describe('VGL-34 navbar sebelum login', () => {
  it('1. memuat Masuk tanpa Daftar dan tanpa Laporkan URL', () => {
    renderHeader()

    expect(screen.getByRole('link', { name: 'Masuk' }).getAttribute('href')).toBe('/masuk')
    // VGL-36: entry point "Laporkan URL" dihapus dari navbar; rute dan formulirnya tetap
    // ada di halaman Komunitas, jadi yang diuji di sini adalah keabsennya di header.
    expect(screen.queryByRole('link', { name: 'Laporkan URL' })).toBeNull()
    expect(screen.queryByText('Laporkan URL')).toBeNull()
    expect(screen.queryByRole('link', { name: 'Daftar' })).toBeNull()
  })

  it('2. urutan menu utama tidak berubah', () => {
    renderHeader()

    const nav = screen.getByRole('navigation', { name: 'Navigasi utama' })
    const labels = within(nav)
      .getAllByRole('link')
      .map((link) => link.textContent)

    expect(labels).toEqual(['Periksa', 'Komunitas', 'Riwayat', 'Dashboard', 'Edukasi'])
  })

  it('3. menu seluler tidak memuat Daftar maupun Laporkan URL', async () => {
    const user = userEvent.setup()
    renderHeader()

    await user.click(screen.getByRole('button', { name: 'Buka menu' }))

    const mobileNav = screen.getByRole('navigation', { name: 'Navigasi seluler' })
    const menu = mobileNav.parentElement as HTMLElement
    expect(within(menu).getByRole('link', { name: 'Masuk' })).toBeTruthy()
    expect(within(menu).queryByRole('link', { name: 'Daftar' })).toBeNull()
    expect(within(menu).queryByRole('link', { name: 'Laporkan URL' })).toBeNull()
  })

  it('4. route /daftar dan tautan registrasi di halaman Masuk tetap ada', () => {
    const router = readFileSync(ROUTER_PATH, 'utf8')
    expect(router).toContain('/daftar')

    const login = readFileSync(LOGIN_PATH, 'utf8')
    expect(login).toContain('Daftar dengan email')
    expect(login).toMatch(/to="\/daftar"/)

    const header = readFileSync(HEADER_PATH, 'utf8')
    expect(header).not.toMatch(/to="\/daftar"/)
  })
})

describe('VGL-34 logo dan sakelar tema di navbar', () => {
  it('5. logo satu baris: nowrap dan tidak menyusut', () => {
    renderHeader()

    const logo = screen.getByRole('link', { name: /VERIGUARD AI/ })
    expect(logo.className).toContain('shrink-0')
    expect(logo.textContent).toBe('VERIGUARD AI')

    const wordmark = logo.lastElementChild as HTMLElement
    expect(wordmark.className).toContain('whitespace-nowrap')
  })

  it('6. satu sakelar tema global dengan label DARK/LIGHT yang accessible', () => {
    renderHeader()

    expect(screen.getAllByRole('radiogroup')).toHaveLength(1)
    expect(screen.getByRole('radiogroup', { name: 'Tema tampilan' })).toBeTruthy()
    expect(screen.getByRole('radio', { name: 'DARK' }).getAttribute('aria-checked')).toBe('false')
    expect(screen.getByRole('radio', { name: 'LIGHT' }).getAttribute('aria-checked')).toBe('true')
  })
})

describe('VGL-34 navbar setelah login', () => {
  it('7. menu akun menggantikan Masuk, tanpa Daftar dan tanpa Laporkan URL', () => {
    mocks.useAuth.mockReturnValue(authState({ user: signedInUser() }))
    renderHeader()

    expect(screen.queryByRole('link', { name: 'Masuk' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'Daftar' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'Laporkan URL' })).toBeNull()
    expect(screen.getByText('Sari Puspita')).toBeTruthy()
  })

  it('8. struktur baris navbar sama sebelum dan sesudah login', () => {
    renderHeader()
    const before = screen.getByRole('banner').className
    cleanup()

    mocks.useAuth.mockReturnValue(authState({ user: signedInUser() }))
    renderHeader()

    expect(screen.getByRole('banner').className).toBe(before)
    expect(before).toContain('border-b')
  })
})

// VGL-36 — komposisi tiga zona, urutan wajib sakelar tema → aksi akun, dan keabsenan
// entry point "Laporkan URL" tanpa menghapus fitur laporan itu sendiri.
describe('VGL-36 urutan kontrol kanan dan komposisi menu', () => {
  /** @param {HTMLElement} a @param {HTMLElement} b */
  const follows = (a: HTMLElement, b: HTMLElement) =>
    Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING)

  it('9. sakelar tema berada tepat di kiri tombol Masuk', () => {
    renderHeader()

    const theme = screen.getByRole('radiogroup', { name: 'Tema tampilan' })
    const masuk = screen.getByRole('link', { name: 'Masuk' })

    expect(follows(theme, masuk)).toBe(true)
    expect(theme.parentElement?.className).toContain('ml-auto')
  })

  it('10. sakelar tema tetap satu-satunya dan beralih sebelum informasi akun', () => {
    mocks.useAuth.mockReturnValue(authState({ user: signedInUser() }))
    renderHeader()

    expect(screen.getAllByRole('radiogroup')).toHaveLength(1)

    const theme = screen.getByRole('radiogroup', { name: 'Tema tampilan' })
    const akun = screen.getByRole('button', { name: 'Sari Puspita' })

    expect(follows(theme, akun)).toBe(true)
  })

  it('11. kelompok menu mengisi ruang tengah dan berjarak, bukan menumpuk di samping logo', () => {
    renderHeader()

    const nav = screen.getByRole('navigation', { name: 'Navigasi utama' })

    expect(nav.className).toContain('grow')
    expect(nav.className).toContain('shrink-0')
    expect(nav.className).toContain('justify-center')
    expect(nav.className).toMatch(/\bgap-2\b/)
    expect(nav.className).toContain('xl:gap-3')
    expect(nav.className).toContain('2xl:gap-4')
    expect(within(nav).getByRole('link', { name: 'Periksa' }).className).toContain(
      'whitespace-nowrap',
    )
  })

  it('12. sakelar tema tetap tersedia ketika panel seluler terbuka', async () => {
    const user = userEvent.setup()
    renderHeader()

    await user.click(screen.getByRole('button', { name: 'Buka menu' }))

    const theme = screen.getByRole('radiogroup', { name: 'Tema tampilan' })
    const panel = screen.getByRole('navigation', { name: 'Navigasi seluler' }).parentElement as HTMLElement
    const masuk = within(panel).getByRole('link', { name: 'Masuk' })

    expect(follows(theme, masuk)).toBe(true)
    // Panel tidak membuat sakelar kedua; satu sumber state tetap dipertahankan.
    expect(screen.getAllByRole('radiogroup')).toHaveLength(1)
  })

  it('13. tombol Masuk memakai varian soft berbasis token merek, bukan warna hardcoded', () => {
    renderHeader()

    const masuk = screen.getByRole('link', { name: 'Masuk' })

    expect(masuk.className).toContain('rounded-btn')
    expect(masuk.className).toContain('h-9')
    expect(masuk.className).toContain('bg-accent-soft')
    expect(masuk.className).toContain('text-accent')
    expect(masuk.className).toContain('hover:bg-accent')
    expect(masuk.className).toMatch(/focus-visible:ring-2/)
  })

  it('14. fitur laporan URL tetap utuh di halaman Komunitas', () => {
    const community = readFileSync(COMMUNITY_PATH, 'utf8')

    expect(community).toContain('id="community-report-form"')
    expect(community).toContain('Laporkan URL')

    const header = readFileSync(HEADER_PATH, 'utf8')
    expect(header).not.toMatch(/to="\/komunitas#community-report-form"/)
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

function accountFor(email: string, displayName: string): NonNullable<AuthContextValue['user']> {
  return { ...signedInUser(), email, displayName }
}

describe('VGL-41E — menu profil navbar menyamar hanya untuk akun demo', () => {
  beforeEach(() => {
    vi.stubGlobal('crypto', webcrypto)
    mocks.demoAvailability.mockReturnValue({ available: true, reason: null })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('1. dropdown navbar menyamar dan alamat aslinya tidak ada di DOM', async () => {
    serveDemoIdentities([await digestOf(DEMO_ADMIN_EMAIL), await digestOf(DEMO_USER_EMAIL)])
    mocks.useAuth.mockReturnValue(authState({ user: accountFor(DEMO_ADMIN_EMAIL, 'Admin Demo') }))
    const user = userEvent.setup()
    renderHeader()

    await user.click(await screen.findByRole('button', { name: /Admin Demo/ }))

    await waitFor(() => expect(screen.getByText(MASKED_EMAIL)).toBeTruthy())
    // Tidak ada jalur baca lain: atribut, tooltip, maupun elemen tersembunyi tidak memuatnya.
    expect(document.body.innerHTML).not.toContain(DEMO_ADMIN_EMAIL)
  })

  it('2. panel akun pada menu seluler tersamar sama rata', async () => {
    serveDemoIdentities([await digestOf(DEMO_ADMIN_EMAIL), await digestOf(DEMO_USER_EMAIL)])
    mocks.useAuth.mockReturnValue(authState({ user: accountFor(DEMO_USER_EMAIL, 'Pengguna Demo') }))
    const user = userEvent.setup()
    renderHeader()

    await user.click(screen.getByRole('button', { name: 'Buka menu' }))

    await waitFor(() => expect(screen.getByText(MASKED_EMAIL)).toBeTruthy())
    expect(document.body.innerHTML).not.toContain(DEMO_USER_EMAIL)
  })

  it('3. akun biasa tetap menampilkan email aslinya di navbar', async () => {
    serveDemoIdentities([await digestOf(DEMO_ADMIN_EMAIL), await digestOf(DEMO_USER_EMAIL)])
    mocks.useAuth.mockReturnValue(authState({ user: signedInUser() }))
    const user = userEvent.setup()
    renderHeader()

    await user.click(await screen.findByRole('button', { name: /Sari Puspita/ }))

    await waitFor(() => expect(screen.getByText('sari@example.com')).toBeTruthy())
    expect(screen.queryByText(MASKED_EMAIL)).toBeNull()
  })

  it('4. tanpa pagar demo tidak ada permintaan identitas maupun penyamaran', async () => {
    mocks.demoAvailability.mockReturnValue({ available: false, reason: 'Login demo tidak diaktifkan.' })
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    mocks.useAuth.mockReturnValue(authState({ user: accountFor(DEMO_ADMIN_EMAIL, 'Admin Demo') }))
    const user = userEvent.setup()
    renderHeader()

    await user.click(await screen.findByRole('button', { name: /Admin Demo/ }))

    await waitFor(() => expect(screen.getByText(DEMO_ADMIN_EMAIL)).toBeTruthy())
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})

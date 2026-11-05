// @vitest-environment jsdom

import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import type { AuthContextValue } from '../../lib/auth/context'
import { Footer } from './Footer'

const mocks = vi.hoisted(() => ({
  useAuth: vi.fn(),
}))

vi.mock('../../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))

function authState(overrides: Partial<AuthContextValue> = {}): AuthContextValue {
  return {
    mode: 'firebase',
    status: 'ready',
    user: {
      uid: 'user-1',
      email: 'sari@example.com',
      displayName: 'Sari Puspita',
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

function renderFooter() {
  return render(
    <MemoryRouter>
      <Footer />
    </MemoryRouter>,
  )
}

function linkHref(name: RegExp): string {
  const link = screen.getByRole('link', { name })
  return link.getAttribute('href') ?? ''
}

describe('footer dan laporan bug', () => {
  beforeEach(() => {
    localStorage.clear()
    document.body.style.overflow = ''
    mocks.useAuth.mockReturnValue(authState())
  })

  afterEach(() => {
    cleanup()
    vi.clearAllMocks()
  })

  it('mempertahankan navigasi dan menampilkan menu bantuan', () => {
    renderFooter()

    for (const label of [
      'Periksa',
      'Community Reports',
      'Riwayat',
      'Dashboard',
      'Edukasi',
      'Pengaturan',
    ]) {
      expect(screen.getByRole('link', { name: label })).toBeTruthy()
    }

    expect(screen.getByRole('button', { name: 'Laporkan Bug' })).toBeTruthy()
    expect(screen.getByText('Tentang hasil')).toBeTruthy()
    expect(
      screen.getByText(/Hasil pemeriksaan didasarkan pada analisis indikator keamanan/),
    ).toBeTruthy()
  })

  it('menempatkan Laporkan Bug di kolom Tentang hasil', () => {
    renderFooter()

    const navigation = screen.getByRole('navigation', {
      name: 'Navigasi kaki halaman',
    })
    expect(
      within(navigation).queryByRole('button', { name: 'Laporkan Bug' }),
    ).toBeNull()

    const aboutTitle = screen.getByText('Tentang hasil')
    const aboutColumn = aboutTitle.parentElement
    expect(aboutColumn).not.toBeNull()

    const description = within(aboutColumn!).getByText(
      /Hasil pemeriksaan didasarkan pada analisis indikator keamanan/,
    )
    const button = within(aboutColumn!).getByRole('button', { name: 'Laporkan Bug' })
    expect(
      description.compareDocumentPosition(button) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy()
  })

  it('membuka modal, mengisi nama login, dan menutup dengan Batal', async () => {
    const user = userEvent.setup()
    renderFooter()
    const trigger = screen.getByRole('button', { name: 'Laporkan Bug' })

    await user.click(trigger)

    const dialog = screen.getByRole('dialog', { name: 'Laporkan Bug' })
    expect(within(dialog).getByText(/Menemukan masalah di VERIGUARD/)).toBeTruthy()
    expect(document.body.style.overflow).toBe('hidden')

    const whatsAppUrl = new URL(linkHref(/WhatsApp/))
    expect(whatsAppUrl.origin).toBe('https://wa.me')
    expect(whatsAppUrl.pathname).toBe('/62881038202105')
    expect(whatsAppUrl.searchParams.get('text')).toBe(
      'Hallo min, saya Sari Puspita. Saya mau melaporkan bug pada website VERIGUARD AI.\n\nMohon bantu dicek ya. Terima kasih 🙏',
    )

    const gmailUrl = new URL(linkHref(/Gmail/))
    expect(gmailUrl.protocol).toBe('mailto:')
    expect(gmailUrl.pathname).toBe('r10885053@gmail.com')
    expect(gmailUrl.searchParams.get('subject')).toBe('Laporan Bug VERIGUARD AI')
    const gmailBody = gmailUrl.searchParams.get('body') ?? ''
    expect(gmailBody).toContain('Nama pengguna: Sari Puspita')
    expect(gmailBody).toContain('Detail bug:')
    expect(gmailBody).toContain('[Silakan jelaskan masalah yang ditemukan]')

    await user.click(within(dialog).getByRole('button', { name: 'Batal' }))

    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.body.style.overflow).toBe('')
    await waitFor(() => expect(document.activeElement).toBe(trigger))
  })

  it('menutup modal dengan Escape', async () => {
    const user = userEvent.setup()
    renderFooter()

    await user.click(screen.getByRole('button', { name: 'Laporkan Bug' }))
    expect(screen.getByRole('dialog', { name: 'Laporkan Bug' })).toBeTruthy()

    await user.keyboard('{Escape}')

    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('memakai fallback tanpa nama palsu saat pengguna anonim', async () => {
    const user = userEvent.setup()
    mocks.useAuth.mockReturnValue(
      authState({
        user: {
          uid: 'guest-1',
          email: null,
          displayName: 'Pengguna',
          emailVerified: false,
          isAnonymous: true,
          startedAt: null,
        },
      }),
    )
    renderFooter()

    await user.click(screen.getByRole('button', { name: 'Laporkan Bug' }))

    const whatsAppUrl = new URL(linkHref(/WhatsApp/))
    expect(whatsAppUrl.searchParams.get('text')).toBe(
      'Hallo min, saya ingin melaporkan bug pada website VERIGUARD AI.',
    )

    const gmailUrl = new URL(linkHref(/Gmail/))
    const gmailBody = gmailUrl.searchParams.get('body') ?? ''
    expect(gmailBody).not.toContain('Nama pengguna:')
    expect(gmailBody).not.toContain('Pengguna')
    expect(gmailBody).toContain('Halo Admin VERIGUARD AI,')
    expect(gmailBody).toContain('Terima kasih.')
  })
})

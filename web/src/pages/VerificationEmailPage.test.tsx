// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AppUser, AuthContextValue } from '../lib/auth/context'
import { VERIFICATION_EMAIL_PATH } from '../lib/auth/verification'

const mocks = vi.hoisted(() => ({ useAuth: vi.fn() }))

vi.mock('../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))

import { VerificationEmailPage } from './VerificationEmailPage'

function account(overrides: Partial<AppUser> = {}): AppUser {
  return {
    uid: 'user-a',
    email: 'user-a@example.com',
    displayName: 'Pengguna A',
    emailVerified: false,
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
    resendVerificationEmail: vi.fn(async () => undefined),
    refreshEmailVerification: vi.fn(async () => ({ verified: false, signedIn: true })),
    applyVerificationCode: vi.fn(async () => ({ verified: true, signedIn: true })),
    ...overrides,
  }
}

function LocationProbe() {
  const location = useLocation()
  return <div data-testid="probe">{`${location.pathname}${location.search}`}</div>
}

function renderPage(input = VERIFICATION_EMAIL_PATH, state?: unknown) {
  const [pathname, query = ''] = input.split('?')

  return render(
    <MemoryRouter initialEntries={[{ pathname, search: query ? `?${query}` : '', state }]}>
      <Routes>
        <Route path={VERIFICATION_EMAIL_PATH} element={<VerificationEmailPage />} />
        <Route path="/masuk" element={<LocationProbe />} />
        <Route path="*" element={<div data-testid="other">rute lain</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

function buttonByLabel(label: string): HTMLButtonElement {
  return screen.getByText(label).closest('button') as HTMLButtonElement
}

function currentAuth(): AuthContextValue {
  return mocks.useAuth.mock.results.at(-1)?.value as AuthContextValue
}

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

describe('halaman verifikasi email untuk akun yang belum terkonfirmasi', () => {
  it('menampilkan email akun dan status belum diverifikasi', () => {
    mocks.useAuth.mockReturnValue(authFixture())
    renderPage()

    expect(screen.getByText('user-a@example.com')).toBeTruthy()
    expect(screen.getByText('Email belum diverifikasi')).toBeTruthy()
  })

  it('tidak memberi tautan lanjut tanpa verifikasi ke rute terlindungi', () => {
    mocks.useAuth.mockReturnValue(authFixture())
    const view = renderPage()

    expect(screen.queryByText('Lanjutkan tanpa verifikasi')).toBeNull()
    expect(view.container.querySelector('a[href="/dashboard"]')).toBeNull()
    expect(view.baseElement.textContent).toContain('Fitur akun dilindungi')
  })

  it('memeriksa status sekali saat halaman dibuka ulang', async () => {
    const auth = authFixture()
    mocks.useAuth.mockReturnValue(auth)
    renderPage()
    await act(async () => {
      await Promise.resolve()
    })

    expect(auth.refreshEmailVerification).toHaveBeenCalledTimes(1)
  })

  it('memakai reload Firebase saat pengguna menekan periksa status', async () => {
    const auth = authFixture()
    mocks.useAuth.mockReturnValue(auth)
    renderPage()
    await act(async () => {
      await Promise.resolve()
    })

    fireEvent.click(buttonByLabel('Saya sudah verifikasi'))
    await act(async () => {
      await Promise.resolve()
    })

    expect(auth.refreshEmailVerification).toHaveBeenCalled()
    expect(screen.getByText('Email belum terverifikasi')).toBeTruthy()
  })

  it('menampilkan sukses setelah status berubah menjadi terverifikasi', async () => {
    const auth = authFixture({
      refreshEmailVerification: vi.fn(async () => ({ verified: true, signedIn: true })),
    })
    mocks.useAuth.mockReturnValue(auth)
    renderPage()
    await act(async () => {
      await Promise.resolve()
    })

    fireEvent.click(buttonByLabel('Saya sudah verifikasi'))
    await act(async () => {
      await Promise.resolve()
    })

    expect(screen.getByText('Email berhasil diverifikasi')).toBeTruthy()
    expect(screen.getByText('Status akun sudah diperbarui. Kamu dapat melanjutkan ke aplikasi.')).toBeTruthy()
  })

  it('memeriksa ulang status ketika tab kembali aktif', async () => {
    const auth = authFixture()
    mocks.useAuth.mockReturnValue(auth)
    renderPage()
    await act(async () => {
      await Promise.resolve()
    })
    const before = vi.mocked(auth.refreshEmailVerification).mock.calls.length

    await act(async () => {
      window.dispatchEvent(new Event('focus'))
      await Promise.resolve()
    })

    expect(vi.mocked(auth.refreshEmailVerification).mock.calls.length).toBeGreaterThan(before)
  })

  it('menampilkan galat tanpa menghentikan halaman saat status gagal diperiksa', async () => {
    const auth = authFixture({
      refreshEmailVerification: vi.fn(async () => {
        throw new Error('offline')
      }),
    })
    mocks.useAuth.mockReturnValue(auth)
    renderPage()
    await act(async () => {
      await Promise.resolve()
    })

    expect(screen.getByText('Status verifikasi belum dapat diperiksa')).toBeTruthy()
  })

  it('mengirim ulang email lalu mengunci tombol selama cooldown', async () => {
    const auth = authFixture()
    mocks.useAuth.mockReturnValue(auth)
    renderPage()

    const resend = buttonByLabel('Kirim ulang email verifikasi')
    fireEvent.click(resend)
    await act(async () => {
      await Promise.resolve()
    })

    expect(auth.resendVerificationEmail).toHaveBeenCalledTimes(1)
    expect(screen.getByText('Email verifikasi dikirim')).toBeTruthy()

    const cooling = buttonByLabel(`Kirim ulang dalam 60 dtk`)
    expect(cooling.disabled).toBe(true)
  })

  it('menyediakan opsi keluar yang aman tanpa menghapus akun', async () => {
    const auth = authFixture()
    mocks.useAuth.mockReturnValue(auth)
    renderPage()

    fireEvent.click(buttonByLabel('Keluar dan pakai akun lain'))
    await act(async () => {
      await Promise.resolve()
    })

    expect(auth.signOut).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('probe').textContent).toBe('/masuk')
  })

  it('melaporkan galat bila sesi gagal dikeluarkan', async () => {
    const auth = authFixture({
      signOut: vi.fn(async () => {
        throw new Error('boom')
      }),
    })
    mocks.useAuth.mockReturnValue(auth)
    renderPage()

    fireEvent.click(buttonByLabel('Keluar dan pakai akun lain'))
    await act(async () => {
      await Promise.resolve()
    })

    expect(screen.getByText('Akun gagal dikeluarkan')).toBeTruthy()
    expect(screen.getByText('Email belum diverifikasi')).toBeTruthy()
    expect(screen.queryByTestId('probe')).toBeNull()
  })

  it('memakai satu halaman verifikasi tanpa duplikat alur', () => {
    mocks.useAuth.mockReturnValue(authFixture())
    const view = renderPage()

    expect(view.container.querySelectorAll('[data-testid="other"]')).toHaveLength(0)
    expect(screen.getAllByText('Verifikasi email')).toHaveLength(1)
  })
})

describe('tautan verifikasi dari email', () => {
  it('memakai kode aksi verifyEmail untuk menetapkan status terverifikasi', async () => {
    const auth = authFixture()
    mocks.useAuth.mockReturnValue(auth)
    renderPage(`${VERIFICATION_EMAIL_PATH}?mode=verifyEmail&oobCode=kode-123`)

    await act(async () => {
      await Promise.resolve()
    })

    expect(auth.applyVerificationCode).toHaveBeenCalledWith('kode-123')
    expect(screen.getByText('Email terverifikasi')).toBeTruthy()
    expect(screen.queryByText('Email belum diverifikasi')).toBeNull()
  })

  it('tidak mengirim kode untuk mode lain', async () => {
    const auth = authFixture()
    mocks.useAuth.mockReturnValue(auth)
    renderPage(`${VERIFICATION_EMAIL_PATH}?mode=resetPassword&oobCode=kode-123`)

    await act(async () => {
      await Promise.resolve()
    })

    expect(auth.applyVerificationCode).not.toHaveBeenCalled()
  })

  it('menampilkan status terverifikasi dan menghapus ajakan verifikasi', () => {
    mocks.useAuth.mockReturnValue(authFixture({ user: account({ emailVerified: true }) }))
    const view = renderPage()

    expect(screen.getByText('Email terverifikasi')).toBeTruthy()
    expect(screen.queryByText('Email belum diverifikasi')).toBeNull()
    expect(view.container.querySelector('a[href="/dashboard"]')).toBeTruthy()
  })
})

describe('perilaku sebelum masuk dan di luar mode firebase', () => {
  it('meminta pengguna masuk ketika sesi tidak ada', () => {
    mocks.useAuth.mockReturnValue(authFixture({ user: null }))
    const view = renderPage()

    expect(screen.getByText('Masuk untuk memeriksa verifikasi')).toBeTruthy()
    expect(view.container.querySelector('a[href="/masuk"]')).toBeTruthy()
    expect(screen.queryByText('Keluar dan pakai akun lain')).toBeNull()
  })

  it('tidak menawarkan verifikasi pada sesi demo lokal', () => {
    mocks.useAuth.mockReturnValue(
      authFixture({
        mode: 'demo',
        user: account({ emailVerified: false, uid: 'local-demo', email: null }),
      }),
    )
    renderPage()

    expect(screen.getByText('Verifikasi email belum tersedia')).toBeTruthy()
    expect(currentAuth().mode).toBe('demo')
  })
})

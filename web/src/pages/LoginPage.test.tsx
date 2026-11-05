// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import type { AuthContextValue } from '../lib/auth/context'
import type { LoginGuardCooldown } from '../lib/auth/loginGuard'
import { LoginCooldownError } from '../lib/auth/loginGuard'
import { DemoLoginError } from '../lib/auth/demoLogin'
import { LoginPage } from './LoginPage'

const mocks = vi.hoisted(() => ({
  useAuth: vi.fn(),
  readLoginCooldown: vi.fn(),
  demoAvailability: vi.fn(),
  signInWithDemoAccount: vi.fn(),
}))

vi.mock('../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))
// Kelas error-nya harus tetap asli agar instanceof di LoginPage mengenali penolakan gerbang;
// hanya pembacaan keadaan cooldown yang dikendalikan test.
vi.mock('../lib/auth/loginGuard', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/auth/loginGuard')>()),
  readLoginCooldown: mocks.readLoginCooldown,
}))
// Hal yang sama untuk login demo: DemoLoginError dibiarkan asli (instanceof dipakai LoginPage),
// hanya pagar ketersediaan dan penukaran sesi yang dikendalikan.
vi.mock('../lib/auth/demoLogin', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/auth/demoLogin')>()),
  demoLoginAvailability: mocks.demoAvailability,
  signInWithDemoAccount: mocks.signInWithDemoAccount,
}))

const IDLE: LoginGuardCooldown = {
  active: false,
  retryAfterMs: 0,
  level: 0,
  failures: 0,
  attemptsLeft: 3,
  attemptsPerLevel: 3,
  authority: 'none',
}

function cooldown(overrides: Partial<LoginGuardCooldown> = {}): LoginGuardCooldown {
  return { ...IDLE, ...overrides }
}

function authFixture(overrides: Partial<AuthContextValue> = {}): AuthContextValue {
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
    signIn: vi.fn(async () => ({ emailVerified: true })),
    signUp: vi.fn(),
    claimExistingUsername: vi.fn(),
    signOut: vi.fn(async () => undefined),
    resetPassword: vi.fn(async () => undefined),
    resendVerificationEmail: vi.fn(async () => undefined),
    refreshEmailVerification: vi.fn(async () => ({ verified: false, signedIn: false })),
    applyVerificationCode: vi.fn(async () => ({ verified: true, signedIn: false })),
    ...overrides,
  }
}

function renderLogin(overrides: Partial<AuthContextValue> = {}) {
  mocks.useAuth.mockReturnValue(authFixture(overrides))
  return render(
    <MemoryRouter>
      <LoginPage />
    </MemoryRouter>,
  )
}

function LocationProbe() {
  const location = useLocation()
  return <span data-testid="location">{location.pathname}</span>
}

/**
 * Varian dengan probe lokasi: login demo harus benar-benar mengarahkan ke dashboard, dan
 * kegagalan tidak boleh berpindah. Probe dirender di rute lain, jadi perpindahan terlihat.
 */
function renderLoginAt(
  initialPath = '/masuk',
  overrides: Partial<AuthContextValue> = {},
  initialState: unknown = undefined,
) {
  mocks.useAuth.mockReturnValue(authFixture(overrides))
  return render(
    <MemoryRouter
      initialEntries={[
        { pathname: initialPath, state: initialState as Record<string, unknown> },
      ]}
    >
      <Routes>
        <Route path="/masuk" element={<LoginPage />} />
        <Route path="*" element={<LocationProbe />} />
      </Routes>
    </MemoryRouter>,
  )
}

function signedInUser(): AuthContextValue['user'] {
  return {
    uid: 'uid-demo',
    email: 'akusipemain@gmail.com',
    displayName: 'Pengguna Demo',
    emailVerified: true,
    isAnonymous: false,
    startedAt: null,
  }
}

function authState(): AuthContextValue {
  return mocks.useAuth.mock.results.at(-1)?.value as AuthContextValue
}

beforeEach(() => {
  window.localStorage.clear()
  mocks.readLoginCooldown.mockResolvedValue(IDLE)
  // Default: pagar menolak, sama seperti build tanpa bendera. Tiap test demo menyalakan
  // sendiri kalau memang menguji keadaan aktif.
  mocks.demoAvailability.mockReturnValue({ available: false, reason: 'Login demo tidak diaktifkan.' })
  mocks.signInWithDemoAccount.mockResolvedValue({ user: {}, adminClaim: false })
})

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

describe('VGL-38 — halaman masuk saat cooldown aktif', () => {
  it('menampilkan pembatasan, menonaktifkan tombol, dan tetap menampilkan form', async () => {
    mocks.readLoginCooldown.mockResolvedValue(
      cooldown({ active: true, retryAfterMs: 120_000, level: 1, failures: 1, authority: 'server' }),
    )
    renderLogin()

    await waitFor(() => {
      expect(screen.getByText(/Terlalu banyak percobaan login/i)).toBeTruthy()
      expect(screen.getByText(/sisa waktu 2 menit/i)).toBeTruthy()
    })

    const submit = screen.getByRole('button', { name: /Menunggu/i }) as HTMLButtonElement
    expect(submit.disabled).toBe(true)

    // Form tidak dihilangkan: field email dan kata sandi tetap ada dan dapat dibaca.
    expect(screen.getByLabelText(/^Email$/i)).toBeTruthy()
    expect(screen.getByLabelText(/Kata sandi/i)).toBeTruthy()
  })

  it('tidak menampilkan notifikasi layanan ketika pembatasan sedang bicara', async () => {
    mocks.readLoginCooldown.mockResolvedValue(
      cooldown({ active: true, retryAfterMs: 3_600_000, level: 2, failures: 2, authority: 'server' }),
    )
    renderLogin()

    await waitFor(() => {
      expect(screen.getByText(/Terlalu banyak percobaan login/i)).toBeTruthy()
    })
    expect(screen.queryByText(/Autentikasi email dan kata sandi terhubung/i)).toBeNull()
  })

  it('penolakan gerbang tidak memunculkan pesan "autentikasi gagal" ganda', async () => {
    renderLogin({
      signIn: vi.fn(async () => {
        throw new LoginCooldownError(120_000, 1)
      }),
    })

    fireEvent.change(screen.getByLabelText(/^Email$/i), { target: { value: 'sasaran@contoh.com' } })
    fireEvent.change(screen.getByLabelText(/Kata sandi/i), { target: { value: 'rahasia123' } })
    fireEvent.submit(screen.getByRole('button', { name: /Masuk/i }))

    await waitFor(() => {
      expect(mocks.readLoginCooldown.mock.calls.length).toBeGreaterThan(1)
    })
    expect(screen.queryByText(/Autentikasi gagal/i)).toBeNull()
  })

  it('kegagalan jaringan bukan cooldown dan bukan password salah', async () => {
    const networkError = Object.assign(new Error('network'), { code: 'auth/network-request-failed' })
    renderLogin({
      signIn: vi.fn(async () => {
        throw networkError
      }),
    })

    fireEvent.change(screen.getByLabelText(/^Email$/i), { target: { value: 'sasaran@contoh.com' } })
    fireEvent.change(screen.getByLabelText(/Kata sandi/i), { target: { value: 'rahasia123' } })
    fireEvent.submit(screen.getByRole('button', { name: /Masuk/i }))

    await waitFor(() => {
      expect(screen.getByText(/Tidak dapat menghubungi layanan akun/i)).toBeTruthy()
    })
    expect(screen.queryByText(/Terlalu banyak percobaan login/i)).toBeNull()
    expect(authState()).toBeTruthy()
  })
})

describe('VGL-38 — halaman masuk tanpa cooldown (regression)', () => {
  it('tombol Masuk aktif dan panel pembatasan tidak dirender', async () => {
    renderLogin()

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Masuk/i })).toBeTruthy()
    })
    expect((screen.getByRole('button', { name: /Masuk/i }) as HTMLButtonElement).disabled).toBe(false)
    expect(screen.queryByText(/Terlalu banyak percobaan login/i)).toBeNull()
    // Kesempatan penuh = tidak ada baris kesempatan (geometri VGL-37C tidak berubah).
    expect(screen.queryByText(/Kesempatan login tersisa/i)).toBeNull()
  })
})

describe('VGL-39A — halaman masuk menampilkan sisa kesempatan', () => {
  it('baris kesempatan muncul dari angka gerbang, bukan hitungan klien', async () => {
    mocks.readLoginCooldown.mockResolvedValue(
      cooldown({ failures: 1, attemptsLeft: 2, attemptsPerLevel: 3, authority: 'server' }),
    )
    renderLogin()

    await waitFor(() => {
      expect(screen.getByText('Kesempatan login tersisa: 2 dari 3')).toBeTruthy()
    })
    // Kesempatan berkurang belum mengunci: form dan tombol tetap siap dipakai.
    expect(screen.queryByText(/Terlalu banyak percobaan login/i)).toBeNull()
    expect((screen.getByRole('button', { name: /Masuk/i }) as HTMLButtonElement).disabled).toBe(false)
  })

  it('sisa satu kesempatan terakhir tetap tampil dan tombol masih aktif', async () => {
    mocks.readLoginCooldown.mockResolvedValue(
      cooldown({ failures: 2, attemptsLeft: 1, attemptsPerLevel: 3, authority: 'server' }),
    )
    renderLogin()

    await waitFor(() => {
      expect(screen.getByText('Kesempatan login tersisa: 1 dari 3')).toBeTruthy()
    })
    expect((screen.getByRole('button', { name: /Masuk/i }) as HTMLButtonElement).disabled).toBe(false)
  })

  it('kesempatan tidak ditampilkan sebagai angka sementara sumber terkunci', async () => {
    mocks.readLoginCooldown.mockResolvedValue(
      cooldown({
        active: true,
        retryAfterMs: 120_000,
        level: 1,
        failures: 0,
        attemptsLeft: 0,
        attemptsPerLevel: 3,
        authority: 'server',
      }),
    )
    renderLogin()

    await waitFor(() => {
      expect(screen.getByText(/sisa waktu 2 menit/i)).toBeTruthy()
    })
    expect(screen.queryByText(/Kesempatan login tersisa/i)).toBeNull()
  })

  it('setelah cooldown tingkat 1 berakhir, kesempatan kembali 3 dan tombol aktif lagi', async () => {
    mocks.readLoginCooldown.mockResolvedValue(
      cooldown({
        active: true,
        retryAfterMs: 120_000,
        level: 1,
        attemptsLeft: 0,
        attemptsPerLevel: 3,
        authority: 'server',
      }),
    )
    const first = renderLogin()
    await waitFor(() => expect(screen.getByText(/Terlalu banyak percobaan login/i)).toBeTruthy())
    cleanup()

    // Gerbang menyatakan masa tunggu selesai pada tingkat yang sama, dengan 3 kesempatan baru.
    // Tab yang dimuat ulang membaca keadaan itu dari gerbang, bukan dari hitungan sendiri.
    mocks.readLoginCooldown.mockResolvedValue(
      cooldown({ level: 1, attemptsLeft: 3, attemptsPerLevel: 3, authority: 'server' }),
    )
    first.unmount()
    renderLogin()

    await waitFor(() => {
      expect((screen.getByRole('button', { name: /Masuk/i }) as HTMLButtonElement).disabled).toBe(false)
    })
    expect(screen.queryByText(/Terlalu banyak percobaan login/i)).toBeNull()
    expect(screen.queryByText(/Kesempatan login tersisa/i)).toBeNull()
  })
})

describe('BAGIAN 4 & 5 — tombol akun demo', () => {
  function enableDemoGate() {
    mocks.demoAvailability.mockReturnValue({ available: true, reason: null })
  }

  it('tidak dirender saat pagar menolak, sehingga default halaman tetap bersih', async () => {
    renderLogin()

    await waitFor(() => expect(screen.getByRole('button', { name: /^Masuk$/ })).toBeTruthy())
    expect(screen.queryByText('Akun Demo')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Demo Admin' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Demo User' })).toBeNull()
    // Form login reguler tidak boleh hilang ketika fitur demo nonaktif.
    expect(screen.getByLabelText(/^Email$/i)).toBeTruthy()
    expect(screen.getByLabelText(/Kata sandi/i)).toBeTruthy()
  })

  it('dua tombol kecil sejajar muncul saat pagar lolos, form reguler tetap utuh', async () => {
    enableDemoGate()
    renderLogin()

    const masuk = screen.getByRole('button', { name: /^Masuk$/ })
    await waitFor(() => expect(screen.getByText('atau coba akun demo')).toBeTruthy())
    const admin = screen.getByRole('button', { name: 'Demo Admin' }) as HTMLButtonElement
    const user = screen.getByRole('button', { name: 'Demo User' }) as HTMLButtonElement

    // Tidak ada kartu besar khusus demo: kedua tombol duduk di kartu login yang sama,
    // tepat di bawah tombol Masuk, dan dipisahkan oleh satu teks kecil.
    expect(screen.queryByText('Akun Demo')).toBeNull()
    expect(admin.closest('[class*="px-8"]')).toBe(masuk.closest('[class*="px-8"]'))
    // Sejajar horizontal dengan lebar setara: satu grid dua kolom, satu induk yang sama.
    expect(admin.parentElement).toBe(user.parentElement)
    expect(admin.parentElement?.className).toContain('grid-cols-2')
    // Lebih kecil dan lebih subtle daripada tombol Masuk (secondary + tinggi 32px vs 36px).
    expect(admin.className).toContain('h-8')
    expect(admin.className).toContain('border-line')
    expect(masuk.className).not.toContain('h-8')
    expect(masuk.className).toContain('bg-accent')
    expect(admin.disabled).toBe(false)
    expect(user.disabled).toBe(false)

    expect(screen.getByLabelText(/^Email$/i)).toBeTruthy()
    expect(screen.getByLabelText(/Kata sandi/i)).toBeTruthy()
    expect(screen.getByRole('button', { name: /Lupa kata sandi/i })).toBeTruthy()
    expect(screen.getByText(/Daftar dengan email/i)).toBeTruthy()
  })

  it('klik admin menukar sesi lewat server lalu mengarahkan ke dashboard', async () => {
    enableDemoGate()
    renderLoginAt('/masuk')

    fireEvent.click(screen.getByRole('button', { name: 'Demo Admin' }))

    await waitFor(() => {
      expect(screen.getByTestId('location').textContent).toBe('/dashboard')
    })
    expect(mocks.signInWithDemoAccount).toHaveBeenCalledTimes(1)
    expect(mocks.signInWithDemoAccount).toHaveBeenCalledWith('admin')
  })

  it('klik user memakai kunci user, bukan admin', async () => {
    enableDemoGate()
    renderLoginAt('/masuk')

    fireEvent.click(screen.getByRole('button', { name: 'Demo User' }))

    await waitFor(() => {
      expect(screen.getByTestId('location').textContent).toBe('/dashboard')
    })
    expect(mocks.signInWithDemoAccount).toHaveBeenCalledWith('user')
  })

  it('target asal dipertahankan: dari rute terlindungi, login demo kembali ke sana', async () => {
    enableDemoGate()
    renderLoginAt('/masuk', {}, { from: '/riwayat' })

    fireEvent.click(screen.getByRole('button', { name: 'Demo User' }))

    await waitFor(() => {
      expect(screen.getByTestId('location').textContent).toBe('/riwayat')
    })
  })

  it('kegagalan demo menampilkan penolakan dan tidak berpindah sama sekali', async () => {
    enableDemoGate()
    mocks.signInWithDemoAccount.mockRejectedValue(
      new DemoLoginError('Login demo tidak aktif pada lingkungan ini.'),
    )
    renderLoginAt('/masuk')

    fireEvent.click(screen.getByRole('button', { name: 'Demo Admin' }))

    await waitFor(() => {
      expect(screen.getByText(/Login demo tidak aktif pada lingkungan ini/i)).toBeTruthy()
    })
    expect(screen.getByText('Autentikasi gagal')).toBeTruthy()
    // Tidak ada perpindahan: probe rute lain tidak pernah terpasang.
    expect(screen.queryByTestId('location')).toBeNull()
    // Sekali gagal, tombol kembali aktif dan tidak ada state "sedang masuk" yang tertinggal.
    expect(
      (screen.getByRole('button', { name: 'Demo Admin' }) as HTMLButtonElement).disabled,
    ).toBe(false)
  })

  it('galat tak terklasifikasi tidak berakhir dengan sesi maupun peran', async () => {
    enableDemoGate()
    mocks.signInWithDemoAccount.mockRejectedValue(new Error('galat tak terduga'))
    renderLogin()

    fireEvent.click(screen.getByRole('button', { name: 'Demo User' }))

    await waitFor(() => {
      expect(screen.getByText(/Peran tidak diberikan tanpa verifikasi server/i)).toBeTruthy()
    })
    expect(screen.queryByTestId('location')).toBeNull()
  })

  it('klik berulang hanya mengirim satu permintaan dan menampilkan keadaan memuat', async () => {
    enableDemoGate()
    let settle!: (value: { user: object; adminClaim: boolean }) => void
    mocks.signInWithDemoAccount.mockImplementation(
      () => new Promise((resolve) => { settle = resolve }),
    )
    renderLogin()

    const admin = screen.getByRole('button', { name: 'Demo Admin' })
    const user = screen.getByRole('button', { name: 'Demo User' })
    fireEvent.click(admin)
    fireEvent.click(admin)
    fireEvent.click(user)

    // VGL-41C: klik demo membaca gerbang pada sumbernya (asinkron) sebelum mengirim permintaan,
    // jadi "satu permintaan" baru terlihat setelah satu tick. Yang diuji tidak berubah: tiga klik
    // beruntun hanya boleh menghasilkan satu penukaran sesi.
    await waitFor(() => expect(mocks.signInWithDemoAccount).toHaveBeenCalledTimes(1))
    // Kedua tombol demo masuk ke keadaan memuat: tidak ada tombol ketiga yang bisa dipakai
    // untuk menyalakan permintaan tambahan selama sesi belum selesai.
    const loading = screen.getAllByRole('button', { name: /Menyiapkan…/ }) as HTMLButtonElement[]
    expect(loading).toHaveLength(2)
    expect(loading.every((button) => button.disabled)).toBe(true)
    expect(screen.queryByRole('button', { name: 'Demo User' })).toBeNull()

    settle({ user: {}, adminClaim: true })
    await waitFor(() => {
      expect(
        (screen.getByRole('button', { name: 'Demo Admin' }) as HTMLButtonElement).disabled,
      ).toBe(false)
    })
  })

  it('cooldown VGL-38 ikut mengunci tombol demo', async () => {
    enableDemoGate()
    mocks.readLoginCooldown.mockResolvedValue(
      cooldown({ active: true, retryAfterMs: 120_000, level: 1, failures: 1, authority: 'server' }),
    )
    renderLogin()

    await waitFor(() => {
      expect(screen.getByText(/Terlalu banyak percobaan login/i)).toBeTruthy()
    })
    const admin = screen.getByRole('button', { name: 'Demo Admin' }) as HTMLButtonElement
    const user = screen.getByRole('button', { name: 'Demo User' }) as HTMLButtonElement
    expect(admin.disabled).toBe(true)
    expect(user.disabled).toBe(true)

    fireEvent.click(admin)
    expect(mocks.signInWithDemoAccount).not.toHaveBeenCalled()
  })

  it('sesi akun aktif menyembunyikan tombol demo', async () => {
    enableDemoGate()
    renderLogin({ user: signedInUser() })

    await waitFor(() => expect(screen.getByText('Akun aktif')).toBeTruthy())
    expect(screen.queryByText('Akun Demo')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Demo Admin' })).toBeNull()
  })

  it('pratinjau lokal tanpa akun tidak menawarkan peran apa pun dan tidak memakai jalur demo', async () => {
    enableDemoGate()
    renderLogin({
      mode: 'demo',
      user: null,
      startDemoSession: vi.fn(),
    })

    const preview = screen.getByRole('button', { name: /Mulai sesi demo lokal/ })
    expect(preview).toBeTruthy()
    expect(screen.queryByText('Akun Demo')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Demo Admin' })).toBeNull()

    fireEvent.click(preview)
    expect(mocks.signInWithDemoAccount).not.toHaveBeenCalled()
  })
})

describe('VGL-41C — jalur demo membaca ulang gerbang pada sumbernya', () => {
  function enableDemoGate() {
    mocks.demoAvailability.mockReturnValue({ available: true, reason: null })
  }

  it('keadaan terkunci yang datang setelah polling tetap memblokir klik demo', async () => {
    enableDemoGate()
    // Polling hook sedang idle; pembacaan authoritative menjawab terkunci (mis. tab lain baru
    // menghabiskan tiga kesempatan).
    let firstRead = true
    mocks.readLoginCooldown.mockImplementation(async () => {
      if (firstRead) {
        firstRead = false
        return IDLE
      }
      return cooldown({ active: true, retryAfterMs: 120_000, level: 1, failures: 3, authority: 'server' })
    })
    renderLogin()

    const admin = screen.getByRole('button', { name: 'Demo Admin' }) as HTMLButtonElement
    await waitFor(() => expect(admin.disabled).toBe(false))

    fireEvent.click(admin)
    await waitFor(() => expect(mocks.readLoginCooldown.mock.calls.length).toBeGreaterThan(1))
    expect(mocks.signInWithDemoAccount).not.toHaveBeenCalled()
  })

  it('gerbang yang menjawab bebas tetap menukar sesi demo seperti semula', async () => {
    enableDemoGate()
    renderLogin()

    const admin = screen.getByRole('button', { name: 'Demo Admin' })
    await waitFor(() => expect(admin).toBeTruthy())
    fireEvent.click(admin)

    await waitFor(() => expect(mocks.signInWithDemoAccount).toHaveBeenCalledTimes(1))
    expect(mocks.signInWithDemoAccount.mock.calls[0]?.[0]).toBe('admin')
  })
})

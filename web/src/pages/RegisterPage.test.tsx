// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useEffect } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import type { AuthContextValue } from '../lib/auth/context'
import type { TurnstileStatus } from '../components/turnstile/Turnstile'

const mocks = vi.hoisted(() => ({
  signUp: vi.fn(),
  isTurnstileEnabled: vi.fn(),
  turnstileSiteKey: vi.fn(),
  requestTurnstileVerification: vi.fn(),
  turnstileErrorMessage: vi.fn(),
  solve: vi.fn(),
  expire: vi.fn(),
  raiseError: vi.fn(),
  widgetStatus: vi.fn(),
  setStatus: null as null | ((status: TurnstileStatus) => void),
  lastAttempt: 0,
}))

vi.mock('../lib/auth/useAuth', () => ({ useAuth: () => auth }))
vi.mock('../lib/turnstile/client', () => ({
  isTurnstileEnabled: mocks.isTurnstileEnabled,
  turnstileSiteKey: mocks.turnstileSiteKey,
  requestTurnstileVerification: mocks.requestTurnstileVerification,
  turnstileErrorMessage: mocks.turnstileErrorMessage,
}))
// Widget asli memuat skrip Cloudflare dan tidak berjalan di jsdom. Mock ini meniru kontrak
// komponen: status widget, token saat tantangan diselesaikan, kedaluwarsa, dan galat.
vi.mock('../components/turnstile/Turnstile', () => ({
  Turnstile: ({
    action,
    onToken,
    onExpire,
    onError,
    onStatusChange,
    attempt = 0,
  }: {
    action: string
    onToken: (token: string) => void
    onExpire: () => void
    onError: () => void
    onStatusChange: (status: TurnstileStatus) => void
    attempt?: number
  }) => {
    useEffect(() => {
      mocks.setStatus = onStatusChange
      onStatusChange(mocks.widgetStatus())
    }, [onStatusChange])
    useEffect(() => {
      // attempt naik hanya saat pengguna meminta token baru pada widget yang sama.
      if (attempt > 0 && attempt !== mocks.lastAttempt) {
        mocks.lastAttempt = attempt
        onToken(`token-percobaan-${attempt + 1}`)
      }
    })
    return (
      <div data-testid={`turnstile-${action}`} data-turnstile-widget={action}>
        <button type="button" onClick={() => mocks.solve(onToken)}>
          Selesaikan CAPTCHA uji
        </button>
        <button type="button" onClick={() => mocks.expire(onExpire)}>
          Token CAPTCHA kedaluwarsa
        </button>
        <button type="button" onClick={() => mocks.raiseError(onError)}>
          Widget CAPTCHA gagal
        </button>
      </div>
    )
  },
}))

import { RegisterPage } from './RegisterPage'
import { UsernameClaimError } from '../lib/firebase/usernames'

const auth: AuthContextValue = {
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
  signUp: mocks.signUp,
  claimExistingUsername: vi.fn(async () => ({ username: 'pengguna_baru', profileSynced: true })),
  signOut: vi.fn(async () => undefined),
  resetPassword: vi.fn(),
  resendVerificationEmail: vi.fn(),
  refreshEmailVerification: vi.fn(),
  applyVerificationCode: vi.fn(),
}

function LocationProbe() {
  const location = useLocation()
  return <span data-testid="location">{`${location.pathname}:${JSON.stringify(location.state ?? {})}`}</span>
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/daftar']}>
      <Routes>
        <Route path="/daftar" element={<RegisterPage />} />
        <Route path="*" element={<LocationProbe />} />
      </Routes>
    </MemoryRouter>,
  )
}

function submitButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: /Daftar dengan email|Membuat akun|Memverifikasi/ }) as
    HTMLButtonElement
}

function widgetCount(container: HTMLElement): number {
  return container.querySelectorAll('[data-turnstile-widget]').length
}

async function fillForm(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText('Nama tampilan'), 'Pengguna Baru')
  await user.type(screen.getByLabelText('Username'), 'pengguna_baru')
  await user.type(screen.getByLabelText('Email'), 'pengguna@contoh.com')
  await user.type(screen.getByLabelText('Kata sandi'), 'sandiyaku123')
  await user.type(screen.getByLabelText('Ulangi kata sandi'), 'sandiyaku123')
}

async function errorText(): Promise<string> {
  const alert = await screen.findByRole('alert')
  return alert.textContent ?? ''
}

const solveButton = () => screen.getByTestId('turnstile-register').querySelector('button')!

/** Meniru server siteverify sungguhan: satu token hanya bisa diverifikasi sekali. */
function singleUseServer() {
  const used = new Set<string>()
  mocks.requestTurnstileVerification.mockImplementation(async (token: string) => {
    if (used.has(token)) throw new Error('Token CAPTCHA sudah pernah dipakai.')
    used.add(token)
  })
}

beforeEach(() => {
  mocks.setStatus = null
  mocks.lastAttempt = 0
  mocks.signUp.mockReset().mockResolvedValue({ emailVerified: false, verificationSent: true })
  mocks.isTurnstileEnabled.mockReset().mockReturnValue(true)
  mocks.turnstileSiteKey.mockReset().mockReturnValue('SITEKEY-UJI')
  mocks.requestTurnstileVerification.mockReset().mockResolvedValue(undefined)
  mocks.turnstileErrorMessage.mockReset().mockImplementation((error: unknown) =>
    error instanceof Error ? error.message : 'Verifikasi CAPTCHA gagal.',
  )
  mocks.widgetStatus.mockReset().mockReturnValue('ready' satisfies TurnstileStatus)
  mocks.solve.mockReset().mockImplementation((onToken: (value: string) => void) =>
    onToken('token-pendaftaran'),
  )
  mocks.expire.mockReset().mockImplementation((onExpire: () => void) => onExpire())
  mocks.raiseError.mockReset().mockImplementation((onError: () => void) => onError())
})

afterEach(() => {
  cleanup()
})

describe('halaman pendaftaran saat baru dibuka', () => {
  it('skenario 1: membuka halaman tanpa interaksi tidak memunculkan pesan gagal', async () => {
    const { container } = renderPage()

    await screen.findByTestId('turnstile-register')
    expect(screen.queryByRole('alert')).toBeNull()
    expect(container.textContent).not.toContain('Pendaftaran gagal')
    expect(container.textContent).not.toContain('Verifikasi CAPTCHA gagal')
  })

  it('skenario 1b: tidak ada permintaan verifikasi otomatis saat halaman dimuat', async () => {
    renderPage()

    await screen.findByTestId('turnstile-register')
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(mocks.requestTurnstileVerification).not.toHaveBeenCalled()
  })

  it('skenario 12: memuat ulang halaman juga tidak memunculkan pesan gagal', async () => {
    const first = renderPage()
    await screen.findByTestId('turnstile-register')
    const user = userEvent.setup()
    await fillForm(user)
    await user.click(solveButton())
    await user.click(submitButton())
    await waitFor(() => expect(mocks.signUp).toHaveBeenCalledTimes(1))
    cleanup()
    first.unmount()

    renderPage()
    await screen.findByTestId('turnstile-register')
    expect(screen.queryByRole('alert')).toBeNull()
    expect(mocks.requestTurnstileVerification).toHaveBeenCalledTimes(1)
  })

  it('skenario 10: hanya ada satu widget CAPTCHA pada formulir', async () => {
    const { container } = renderPage()

    await screen.findByTestId('turnstile-register')
    expect(widgetCount(container)).toBe(1)
  })

  it('label Verifikasi manusia tidak lagi ditampilkan', async () => {
    renderPage()

    await screen.findByTestId('turnstile-register')
    expect(screen.queryByText('Verifikasi manusia')).toBeNull()
  })
})

describe('tombol daftar dan gerbang CAPTCHA', () => {
  it('skenario 2: menekan daftar tanpa menyelesaikan CAPTCHA menampilkan pesan yang sesuai', async () => {
    const user = userEvent.setup()
    renderPage()

    await fillForm(user)
    expect(submitButton().disabled).toBe(false)
    await user.click(submitButton())

    expect(await errorText()).toContain('Silakan selesaikan verifikasi CAPTCHA terlebih dahulu')
    expect(mocks.requestTurnstileVerification).not.toHaveBeenCalled()
    expect(mocks.signUp).not.toHaveBeenCalled()
  })

  it('skenario 3: token dari widget diterima tanpa memicu verifikasi otomatis', async () => {
    const user = userEvent.setup()
    renderPage()

    await fillForm(user)
    await user.click(solveButton())

    expect(mocks.requestTurnstileVerification).not.toHaveBeenCalled()
    expect(screen.queryByRole('alert')).toBeNull()

    await user.click(submitButton())
    await waitFor(() =>
      expect(mocks.requestTurnstileVerification).toHaveBeenCalledWith('token-pendaftaran'),
    )
  })

  it('skenario 4 dan 5: token divalidasi backend lebih dulu, lalu Firebase Auth dipanggil', async () => {
    const user = userEvent.setup()
    renderPage()

    await fillForm(user)
    await user.click(solveButton())
    await user.click(submitButton())

    await waitFor(() => expect(mocks.signUp).toHaveBeenCalledTimes(1))
    expect(mocks.requestTurnstileVerification).toHaveBeenCalledTimes(1)
    expect(mocks.signUp).toHaveBeenCalledWith(
      'Pengguna Baru',
      'pengguna@contoh.com',
      'sandiyaku123',
      'pengguna_baru',
    )
    expect(screen.getByTestId('location').textContent).toContain('/verifikasi-email')
    expect(screen.getByTestId('location').textContent).toContain('"justRegistered":true')
    expect(screen.getByTestId('location').textContent).toContain('"verificationSent":true')
  })

  it('skenario 6: token invalid menghentikan registrasi tanpa memanggil Firebase', async () => {
    mocks.requestTurnstileVerification.mockRejectedValue(
      new Error('Verifikasi CAPTCHA tidak berlaku. Selesaikan verifikasi baru.'),
    )
    const user = userEvent.setup()
    const { container } = renderPage()

    await fillForm(user)
    await user.click(solveButton())
    await user.click(submitButton())

    expect(await errorText()).toContain('Verifikasi CAPTCHA tidak berlaku')
    expect(mocks.signUp).not.toHaveBeenCalled()
    // Widget yang sama tetap satu, tidak ada CAPTCHA kedua.
    expect(widgetCount(container)).toBe(1)
  })

  it('skenario 7: token kedaluwarsa menghentikan registrasi', async () => {
    mocks.requestTurnstileVerification.mockRejectedValue(
      new Error('Token CAPTCHA kedaluwarsa, selesaikan ulang verifikasi.'),
    )
    const user = userEvent.setup()
    renderPage()

    await fillForm(user)
    await user.click(solveButton())
    await user.click(submitButton())

    expect(await errorText()).toContain('kedaluwarsa')
    expect(mocks.signUp).not.toHaveBeenCalled()
  })

  it('skenario 8: backend tidak tersedia atau timeout menghentikan registrasi', async () => {
    mocks.requestTurnstileVerification.mockRejectedValue(
      new Error('Verifikasi CAPTCHA melebihi batas waktu. Coba lagi.'),
    )
    const user = userEvent.setup()
    renderPage()

    await fillForm(user)
    await user.click(solveButton())
    await user.click(submitButton())

    expect(await errorText()).toContain('melebihi batas waktu')
    expect(mocks.signUp).not.toHaveBeenCalled()
  })

  it('skenario 9: token yang sudah diverifikasi tidak dikirim ulang ke server', async () => {
    singleUseServer()
    const user = userEvent.setup()
    renderPage()

    await fillForm(user)
    await user.click(solveButton())

    // Percobaan pertama: verifikasi berhasil, pembuatan akun gagal karena sebab lain.
    mocks.signUp.mockRejectedValueOnce(new Error('email-already-in-use'))
    await user.click(submitButton())
    expect(await errorText()).toContain('Autentikasi gagal')
    expect(mocks.requestTurnstileVerification).toHaveBeenCalledTimes(1)

    // Percobaan kedua memakai token yang sama: tidak ada pengiriman ulang ke siteverify,
    // dan pengguna tidak diminta menyelesaikan CAPTCHA kedua.
    await user.click(submitButton())
    await waitFor(() => expect(mocks.signUp).toHaveBeenCalledTimes(2))
    expect(mocks.requestTurnstileVerification).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('Silakan selesaikan verifikasi CAPTCHA terlebih dahulu')).toBeNull()
  })

  it('skenario 11: tidak ada widget duplikat setelah submit', async () => {
    const user = userEvent.setup()
    const { container } = renderPage()

    await fillForm(user)
    await user.click(solveButton())
    mocks.signUp.mockRejectedValueOnce(new Error('email-already-in-use'))
    await user.click(submitButton())
    await waitFor(() => expect(mocks.signUp).toHaveBeenCalledTimes(1))

    expect(widgetCount(container)).toBe(1)
  })

  it('skenario 13: setelah token ditolak, pengguna mengambil token baru pada widget yang sama', async () => {
    mocks.requestTurnstileVerification.mockRejectedValueOnce(
      new Error('Token CAPTCHA ditolak server.'),
    )
    const user = userEvent.setup()
    const { container } = renderPage()

    await fillForm(user)
    await user.click(solveButton())
    await user.click(submitButton())
    expect(await errorText()).toContain('Token CAPTCHA ditolak server')

    await user.click(screen.getByRole('button', { name: 'Ambil token baru pada verifikasi ini' }))
    // Token baru diminta pada widget yang sama, bukan lewat widget kedua.
    expect(screen.getAllByTestId('turnstile-register')).toHaveLength(1)
    expect(widgetCount(container)).toBe(1)

    await user.click(submitButton())

    await waitFor(() => expect(mocks.signUp).toHaveBeenCalledTimes(1))
    expect(mocks.requestTurnstileVerification).toHaveBeenCalledTimes(2)
    expect(mocks.requestTurnstileVerification).toHaveBeenNthCalledWith(1, 'token-pendaftaran')
    expect(mocks.requestTurnstileVerification).toHaveBeenNthCalledWith(2, 'token-percobaan-2')
  })

  it('widget yang masih dimuat memberi informasi, bukan pesan gagal', async () => {
    mocks.widgetStatus.mockReturnValue('loading' satisfies TurnstileStatus)
    const user = userEvent.setup()
    const { container } = renderPage()

    await fillForm(user)
    await user.click(submitButton())

    const status = await screen.findByRole('status')
    expect(status.textContent).toContain('sedang dimuat')
    expect(screen.queryByRole('alert')).toBeNull()
    expect(container.textContent).not.toContain('Pendaftaran gagal')
    expect(mocks.requestTurnstileVerification).not.toHaveBeenCalled()
    expect(mocks.signUp).not.toHaveBeenCalled()
  })

  it('widget yang gagal dimuat menghentikan registrasi saat tombol ditekan', async () => {
    const user = userEvent.setup()
    renderPage()

    await fillForm(user)
    act(() => mocks.setStatus?.('failed'))
    await user.click(submitButton())

    expect(await errorText()).toContain('Verifikasi CAPTCHA tidak dapat dimuat')
    expect(mocks.requestTurnstileVerification).not.toHaveBeenCalled()
    expect(mocks.signUp).not.toHaveBeenCalled()
  })

  it('token yang kedaluwarsa sebelum submit membuat registrasi meminta verifikasi ulang', async () => {
    const user = userEvent.setup()
    renderPage()

    await fillForm(user)
    await user.click(solveButton())
    await user.click(screen.getByRole('button', { name: 'Token CAPTCHA kedaluwarsa' }))
    await user.click(submitButton())

    expect(await errorText()).toContain('Silakan selesaikan verifikasi CAPTCHA terlebih dahulu')
    expect(mocks.requestTurnstileVerification).not.toHaveBeenCalled()
    expect(mocks.signUp).not.toHaveBeenCalled()
  })

  it('validasi formulir yang sudah ada berjalan sebelum CAPTCHA', async () => {
    const user = userEvent.setup()
    renderPage()

    await user.type(screen.getByLabelText('Nama tampilan'), 'Pengguna')
    await user.type(screen.getByLabelText('Username'), 'pengguna_baru')
    await user.type(screen.getByLabelText('Email'), 'pengguna@contoh.com')
    await user.type(screen.getByLabelText('Kata sandi'), 'pendek1')
    await user.type(screen.getByLabelText('Ulangi kata sandi'), 'pendek1')
    await user.click(submitButton())

    expect(await errorText()).toContain('Kata sandi minimal 8 karakter')
    expect(mocks.requestTurnstileVerification).not.toHaveBeenCalled()

    await user.type(screen.getByLabelText('Kata sandi'), 'lengkap')
    await user.type(screen.getByLabelText('Ulangi kata sandi'), 'berbeda')
    await user.click(submitButton())

    expect(await errorText()).toContain('Konfirmasi kata sandi tidak cocok')
    expect(mocks.requestTurnstileVerification).not.toHaveBeenCalled()
  })
})

describe('susunan kartu pendaftaran (VGL-37)', () => {
  function cardOfForm(form: Element): Element {
    const card = form.parentElement
    if (!card?.classList.contains('rounded-card')) {
      throw new Error('Formulir tidak berada di dalam kartu.')
    }
    return card
  }

  function comesBefore(earlier: Element, later: Element): boolean {
    return (earlier.compareDocumentPosition(later) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0
  }

  it('skenario R1: kartu dibuka dengan judul, sama seperti box login', async () => {
    const { container } = renderPage()
    await screen.findByTestId('turnstile-register')

    const form = container.querySelector('form')
    if (!form) throw new Error('Formulir pendaftaran tidak ditemukan.')
    const card = cardOfForm(form)

    const title = card.querySelector('p')
    expect(title?.textContent).toBe('Buat akun dengan email')
    // Judul adalah isi pertama; formulir datang setelahnya.
    expect(card.firstElementChild).toBe(title)
    expect(comesBefore(title!, form)).toBe(true)
  })

  it('skenario R2: pesan status berada di atas kartu, bukan di dalamnya', async () => {
    const user = userEvent.setup()
    const { container } = renderPage()

    await fillForm(user)
    await user.click(submitButton())
    const alert = await screen.findByRole('alert')

    const card = cardOfForm(container.querySelector('form')!)
    expect(card.contains(alert)).toBe(false)
    expect(comesBefore(alert, card)).toBe(true)
  })

  it('skenario R3: tombol submit memakai tinggi yang sama dengan tombol masuk', async () => {
    renderPage()

    await screen.findByTestId('turnstile-register')
    expect(submitButton().className).toContain('h-9')
  })

  it('skenario R4: tautan silang ke masuk berada di dalam panel, bukan kalimat telanjang', async () => {
    renderPage()

    await screen.findByTestId('turnstile-register')
    const link = screen.getByRole('link', { name: 'Masuk' })
    const panel = link.parentElement?.parentElement
    expect(panel?.className).toContain('rounded-card')
    expect(panel?.className).toContain('bg-subtle')
  })
})

describe('konfigurasi wajib Cloudflare Turnstile', () => {
  it('Site Key kosong: pendaftaran dihentikan dan tidak ada jalur tanpa CAPTCHA', async () => {
    mocks.turnstileSiteKey.mockReturnValue(null)
    mocks.isTurnstileEnabled.mockReturnValue(false)
    const user = userEvent.setup()
    const { container } = renderPage()

    await fillForm(user)

    // Pesan konfigurasi tampil tanpa menunggu klik, dan tidak satu pun nilai kunci dicetak.
    const status = await screen.findByRole('status')
    expect(status.textContent).toContain('Verifikasi CAPTCHA belum dikonfigurasi')
    expect(status.textContent).not.toContain('SITEKEY')
    expect(container.innerHTML).not.toContain('SECRET')

    expect(screen.queryByTestId('turnstile-register')).toBeNull()
    expect(submitButton().disabled).toBe(true)
    await user.click(submitButton())
    expect(mocks.signUp).not.toHaveBeenCalled()

    // Submit paksa (melewati tombol yang dikunci) tetap berhenti di pemeriksaan handler.
    const form = container.querySelector('form')
    if (!form) throw new Error('Formulir pendaftaran tidak ditemukan.')
    fireEvent.submit(form)
    expect(await errorText()).toContain('pendaftaran dihentikan')
    expect(mocks.requestTurnstileVerification).not.toHaveBeenCalled()
    expect(mocks.signUp).not.toHaveBeenCalled()
  })

  it('Secret Key backend kosong: verifikasi menjawab konfigurasi gagal dan registrasi berhenti', async () => {
    // Pesan ini yang dihasilkan turnstileErrorMessage untuk kode captcha_not_configured,
    // pembuktiannya ada di src/lib/turnstile/client.test.ts.
    mocks.requestTurnstileVerification.mockRejectedValue(
      new Error('Layanan verifikasi CAPTCHA belum disiapkan pada versi ini.'),
    )
    const user = userEvent.setup()
    renderPage()

    await fillForm(user)
    await user.click(solveButton())
    await user.click(submitButton())

    expect(await errorText()).toContain('Layanan verifikasi CAPTCHA belum disiapkan')
    expect(mocks.signUp).not.toHaveBeenCalled()
  })

  it('Kedua kunci tersedia: alur normal berjalan tanpa pesan konfigurasi', async () => {
    const user = userEvent.setup()
    const { container } = renderPage()

    await fillForm(user)
    expect(screen.queryByText('Verifikasi CAPTCHA belum dikonfigurasi')).toBeNull()

    await user.click(solveButton())
    await user.click(submitButton())

    await waitFor(() => expect(mocks.signUp).toHaveBeenCalledTimes(1))
    expect(screen.queryByText('Verifikasi CAPTCHA belum dikonfigurasi')).toBeNull()
    expect(container.textContent).not.toContain('Pendaftaran gagal')
  })
})

describe('username pada pendaftaran', () => {
  async function fillWithoutUsername(user: ReturnType<typeof userEvent.setup>) {
    await user.type(screen.getByLabelText('Nama tampilan'), 'Pengguna Baru')
    await user.type(screen.getByLabelText('Email'), 'pengguna@contoh.com')
    await user.type(screen.getByLabelText('Kata sandi'), 'sandiyaku123')
    await user.type(screen.getByLabelText('Ulangi kata sandi'), 'sandiyaku123')
  }

  it('username adalah bidang wajib pada formulir pendaftaran', async () => {
    renderPage()

    const field = await screen.findByLabelText('Username')
    expect((field as HTMLInputElement).required).toBe(true)
  })

  it('username terlalu pendek ditolak sebelum CAPTCHA diverifikasi', async () => {
    const user = userEvent.setup()
    renderPage()

    await fillWithoutUsername(user)
    await user.type(screen.getByLabelText('Username'), 'ab')
    await user.click(solveButton())
    await user.click(submitButton())

    expect(await errorText()).toContain('Username minimal 3 karakter')
    expect(mocks.requestTurnstileVerification).not.toHaveBeenCalled()
    expect(mocks.signUp).not.toHaveBeenCalled()
  })

  it('username dengan simbol ditolak sebelum CAPTCHA diverifikasi', async () => {
    const user = userEvent.setup()
    renderPage()

    await fillWithoutUsername(user)
    await user.type(screen.getByLabelText('Username'), 'pengguna@baru')
    await user.click(solveButton())
    await user.click(submitButton())

    expect(await errorText()).toContain('huruf kecil, angka, dan garis bawah')
    expect(mocks.requestTurnstileVerification).not.toHaveBeenCalled()
    expect(mocks.signUp).not.toHaveBeenCalled()
  })

  it('username dengan spasi ditolak sebelum CAPTCHA diverifikasi', async () => {
    const user = userEvent.setup()
    renderPage()

    await fillWithoutUsername(user)
    await user.type(screen.getByLabelText('Username'), 'pengguna baru')
    await user.click(solveButton())
    await user.click(submitButton())

    expect(await errorText()).toContain('tidak boleh memuat spasi')
    expect(mocks.requestTurnstileVerification).not.toHaveBeenCalled()
    expect(mocks.signUp).not.toHaveBeenCalled()
  })

  it('username huruf besar dinormalisasi menjadi huruf kecil saat akun dibuat', async () => {
    const user = userEvent.setup()
    renderPage()

    await fillWithoutUsername(user)
    await user.type(screen.getByLabelText('Username'), 'Gyat123')
    await user.click(solveButton())
    await user.click(submitButton())

    await waitFor(() => expect(mocks.signUp).toHaveBeenCalledTimes(1))
    expect(mocks.signUp).toHaveBeenCalledWith(
      'Pengguna Baru',
      'pengguna@contoh.com',
      'sandiyaku123',
      'gyat123',
    )
  })

  it('username yang sudah dipakai menghentikan pendaftaran dengan pesan yang jelas', async () => {
    mocks.signUp.mockRejectedValue(new UsernameClaimError('taken'))
    const user = userEvent.setup()
    renderPage()

    await fillForm(user)
    await user.click(solveButton())
    await user.click(submitButton())

    expect(await errorText()).toContain('Username sudah dipakai akun lain')

    await user.click(submitButton())
    await waitFor(() => expect(mocks.signUp).toHaveBeenCalledTimes(2))
    // Token yang sama tidak diverifikasi ulang ke server untuk percobaan kedua.
    expect(mocks.requestTurnstileVerification).toHaveBeenCalledTimes(1)
  })

  it('pendaftaran berhasil tetap diarahkan ke halaman verifikasi email', async () => {
    const user = userEvent.setup()
    renderPage()

    await fillForm(user)
    await user.click(solveButton())
    await user.click(submitButton())

    await waitFor(() => expect(mocks.signUp).toHaveBeenCalledTimes(1))
    const location = screen.getByTestId('location').textContent ?? ''
    expect(location).toContain('/verifikasi-email')
    expect(location).toContain('"justRegistered":true')
  })
})

// @vitest-environment jsdom

import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import type { AuthContextValue } from '../lib/auth/context'
import type { CommunityLatestReportEntry } from '../lib/community/types'

const mocks = vi.hoisted(() => ({
  useAuth: vi.fn(),
  listLatestCommunityReports: vi.fn(),
  submitCommunityReport: vi.fn(),
  loadPublicModerationStatuses: vi.fn(),
}))

vi.mock('../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))
vi.mock('../lib/firebase/config', () => ({ isFirebaseConfigured: true }))
vi.mock('../lib/community/communityService', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/community/communityService')>()
  return {
    ...actual,
    listLatestCommunityReports: mocks.listLatestCommunityReports,
    submitCommunityReport: mocks.submitCommunityReport,
  }
})
vi.mock('../lib/moderation/moderationService', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../lib/moderation/moderationService')>()
  return {
    ...actual,
    loadPublicModerationStatuses: mocks.loadPublicModerationStatuses,
  }
})

import { CommunityServiceError } from '../lib/community/communityService'
import { COMMUNITY_DAILY_FEED_LIMIT } from '../lib/community/sparkProtocol'
import {
  COMMUNITY_DAILY_LIMIT_MESSAGE,
  COMMUNITY_LATEST_EMPTY_MESSAGE,
} from '../lib/community/types'
import { CommunityReportsPage } from './CommunityReportsPage'

const DAILY_LIMIT_DETAILS = { reason: 'daily_limit_reached' }

function authFixture(overrides: Partial<AuthContextValue>): AuthContextValue {
  return {
    mode: 'firebase',
    status: 'ready',
    user: {
      uid: 'user-1',
      email: 'pengguna@example.com',
      displayName: 'Pengguna',
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

const signedIn = authFixture({})
const anonymous = authFixture({
  user: {
    uid: 'guest-1',
    email: null,
    displayName: '',
    emailVerified: false,
    isAnonymous: true,
    startedAt: null,
  },
})
const unverified = authFixture({
  user: {
    uid: 'user-2',
    email: 'belum@example.com',
    displayName: 'Belum Verifikasi',
    emailVerified: false,
    isAnonymous: false,
    startedAt: null,
  },
})
const demo = authFixture({ mode: 'demo', user: null })
const loadingSession = authFixture({ status: 'loading', user: null })

function entry(
  overrides: Partial<CommunityLatestReportEntry> = {},
): CommunityLatestReportEntry {
  return {
    id: 'a'.repeat(32),
    userName: 'Rani(sensor)',
    reportText: 'Halaman meminta kata sandi lewat formulir yang menyerupai bank.',
    category: 'phishing',
    reportedUrl: 'https://contoh-situs.id/login',
    hostname: 'contoh-situs.id',
    createdAt: '2026-10-20T02:00:00.000Z',
    ...overrides,
  }
}

function LoginStub() {
  const location = useLocation()
  const state = location.state as { from?: string } | null
  return <div data-testid="login-stub">{`masuk dari:${state?.from ?? '-'}`}</div>
}

function renderPage(route = '/komunitas') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <Routes>
        <Route path="/komunitas" element={<CommunityReportsPage />} />
        <Route path="/masuk" element={<LoginStub />} />
      </Routes>
    </MemoryRouter>,
  )
}

async function fillUrl(user: ReturnType<typeof userEvent.setup>, value?: string) {
  await user.type(
    screen.getByLabelText('URL yang dilaporkan'),
    value ?? 'Contoh-Situs.id:443/login?utm_source=sms&b=2#form',
  )
}

async function fillReport(user: ReturnType<typeof userEvent.setup>) {
  await fillUrl(user)
  await user.selectOptions(screen.getByLabelText('Kategori'), 'phishing')
  await user.type(
    screen.getByLabelText('Alasan singkat'),
    'Formulirnya meminta kata sandi bank dan kode OTP secara bersamaan.',
  )
}

async function submitForm(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: /(kirim|mengirim)/i }))
}

beforeEach(() => {
  mocks.useAuth.mockReturnValue(signedIn)
  mocks.listLatestCommunityReports.mockResolvedValue([])
  mocks.loadPublicModerationStatuses.mockResolvedValue({
    statuses: new Map(),
    unavailable: false,
  })
  mocks.submitCommunityReport.mockResolvedValue({
    created: true,
    report: {
      userName: 'Pengguna',
      category: 'phishing',
      reason: 'Formulirnya meminta kata sandi bank.',
      createdAt: '2026-10-20T02:00:00.000Z',
      updatedAt: '2026-10-20T02:00:00.000Z',
    },
    summary: {
      hostname: 'contoh-situs.id',
      reportCount: 1,
      reporterCount: 1,
      categoryCounts: { phishing: 1 },
      firstReportedAt: '2026-10-20T02:00:00.000Z',
      lastReportedAt: '2026-10-20T02:00:00.000Z',
      lastActivityAt: '2026-10-20T02:00:00.000Z',
      moderationStatus: 'community_reported',
      reviewRequired: false,
      reviewReason: null,
      verificationSource: null,
      verifiedAt: null,
      aggregatesComplete: true,
    },
  })
})

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
  Reflect.deleteProperty(navigator, 'clipboard')
})

describe('Community Reports page: gerbang login', () => {
  it('mengalihkan sesi anonim ke halaman masuk aplikasi tanpa menampilkan formulir', () => {
    mocks.useAuth.mockReturnValue(anonymous)

    renderPage()

    expect(screen.getByTestId('login-stub').textContent).toBe('masuk dari:/komunitas')
    expect(screen.queryByRole('heading', { name: 'Community Reports' })).toBeNull()
    expect(screen.queryByLabelText('URL yang dilaporkan')).toBeNull()
    expect(mocks.submitCommunityReport).not.toHaveBeenCalled()
    expect(mocks.listLatestCommunityReports).not.toHaveBeenCalled()
  })

  it('membawa alamat balik termasuk URL yang sedang dibuka', () => {
    mocks.useAuth.mockReturnValue(anonymous)

    renderPage('/komunitas?url=https%3A%2F%2Fcontoh-situs.id%2Flogin%3Futm_source%3Dsms')

    const expected = `/komunitas?url=${encodeURIComponent(
      'https://contoh-situs.id/login?utm_source=sms',
    )}`
    expect(screen.getByTestId('login-stub').textContent).toBe(`masuk dari:${expected}`)
  })

  it('menampilkan formulir untuk akun yang masuk tanpa memuat daftar secara otomatis', () => {
    renderPage()

    expect(screen.getByRole('heading', { name: 'Community Reports' })).toBeTruthy()
    expect(screen.getByLabelText('URL yang dilaporkan')).toBeTruthy()
    expect(screen.getByText('Daftar belum dimuat')).toBeTruthy()
    expect(mocks.listLatestCommunityReports).not.toHaveBeenCalled()
  })

  it('belum mengalihkan saat status sesi belum diketahui', () => {
    mocks.useAuth.mockReturnValue(loadingSession)

    renderPage()

    expect(screen.queryByTestId('login-stub')).toBeNull()
    expect(screen.getByText(/Tunggu sebentar/)).toBeTruthy()
  })

  it('sesi tanpa hak lapor tidak pernah memanggil layanan daftar laporan', async () => {
    const user = userEvent.setup()
    mocks.useAuth.mockReturnValue(demo)

    renderPage()

    expect(screen.queryByTestId('login-stub')).toBeNull()
    await fillReport(user)
    await submitForm(user)

    expect(
      await screen.findByText(/Sesi demo lokal tidak dapat mengirim laporan/),
    ).toBeTruthy()
    expect(mocks.submitCommunityReport).not.toHaveBeenCalled()
    expect(mocks.listLatestCommunityReports).not.toHaveBeenCalled()
  })

  it('sesi yang tidak berhak menampilkan status daftar khusus, bukan keadaan kosong', () => {
    mocks.useAuth.mockReturnValue(demo)

    renderPage()

    expect(screen.getByText('Daftar laporan belum dimuat')).toBeTruthy()
    const action = screen.getByRole('button', { name: /Tampilkan laporan/ }) as HTMLButtonElement
    expect(action.disabled).toBe(true)
    expect(screen.queryByText(COMMUNITY_LATEST_EMPTY_MESSAGE)).toBeNull()
    expect(screen.queryByText(/Memuat laporan komunitas/)).toBeNull()
    expect(mocks.listLatestCommunityReports).not.toHaveBeenCalled()
  })

  it('akun belum terverifikasi tidak dialihkan, tetapi daftar dan kiriman diblokir', async () => {
    const user = userEvent.setup()
    mocks.useAuth.mockReturnValue(unverified)

    renderPage()

    expect(screen.queryByTestId('login-stub')).toBeNull()
    expect(screen.getByText('Verifikasi email diperlukan')).toBeTruthy()
    const verifyLinks = screen.getAllByRole('link', { name: /Verifikasi email akun/ })
    expect(verifyLinks.some((link) => link.getAttribute('href') === '/verifikasi-email')).toBe(true)
    expect(screen.getByText('Daftar laporan belum dimuat')).toBeTruthy()
    expect(screen.queryByText(COMMUNITY_LATEST_EMPTY_MESSAGE)).toBeNull()
    expect(mocks.listLatestCommunityReports).not.toHaveBeenCalled()
    expect(mocks.loadPublicModerationStatuses).not.toHaveBeenCalled()

    await fillReport(user)
    await user.click(screen.getByRole('button', { name: /Verifikasi email untuk mengirim/i }))

    expect(
      await screen.findByText(/Verifikasi email akun terlebih dahulu/),
    ).toBeTruthy()
    expect(mocks.submitCommunityReport).not.toHaveBeenCalled()
  })
})

describe('Community Reports page: pengiriman dan batas harian', () => {
  it('mengirim URL yang sudah dinormalisasi dan memuat ulang umpan komunitas', async () => {
    const user = userEvent.setup()
    renderPage()

    await fillReport(user)
    await submitForm(user)

    expect(await screen.findByText('Laporan tercatat')).toBeTruthy()
    expect(mocks.submitCommunityReport).toHaveBeenCalledWith({
      url: 'https://contoh-situs.id/login?b=2',
      category: 'phishing',
      reason: 'Formulirnya meminta kata sandi bank dan kode OTP secara bersamaan.',
    })
    await waitFor(() => {
      expect(mocks.listLatestCommunityReports).toHaveBeenCalledWith({
        forceRefresh: true,
      })
    })
  })

  it('menampilkan pesan status harian yang baku tanpa kata penolakan', async () => {
    const user = userEvent.setup()
    mocks.submitCommunityReport.mockRejectedValue(
      new CommunityServiceError('resource-exhausted', COMMUNITY_DAILY_LIMIT_MESSAGE, DAILY_LIMIT_DETAILS),
    )
    renderPage()

    await fillReport(user)
    await submitForm(user)

    expect(await screen.findByText(COMMUNITY_DAILY_LIMIT_MESSAGE)).toBeTruthy()
    expect(screen.getByText('Pelaporan harian sudah terpakai')).toBeTruthy()
    expect(
      screen.getByText(/Setiap akun dapat mengirim satu laporan per hari/),
    ).toBeTruthy()
    expect(document.body.textContent).not.toMatch(/WIB|UTC\+7|kalender/i)
    expect(
      screen.getByText(
        /Laporanmu yang sebelumnya tetap tersimpan dan tidak diubah/,
      ),
    ).toBeTruthy()
    expect(screen.queryByText('Laporan tercatat')).toBeNull()
    expect(screen.queryByText('Laporan belum terkirim')).toBeNull()
    expect(document.body.textContent).not.toMatch(/ditolak/i)
    expect(mocks.listLatestCommunityReports).not.toHaveBeenCalled()
  })

  it('tetap menyatakan laporan tersimpan ketika ringkasan tidak dapat dibaca', async () => {
    const user = userEvent.setup()
    mocks.submitCommunityReport.mockResolvedValue({
      created: true,
      summary: null,
      report: null,
    })
    renderPage()

    await fillReport(user)
    await submitForm(user)

    expect(await screen.findByText('Laporan tercatat')).toBeTruthy()
    expect(screen.getByText(/Jumlah laporan aktif belum dapat dimuat/)).toBeTruthy()
    expect(screen.queryByText(/Total laporan aktif/)).toBeNull()
  })

  it('kegagalan layanan memakai pesan error sendiri, bukan pesan batas harian', async () => {
    const user = userEvent.setup()
    mocks.submitCommunityReport.mockRejectedValue(
      new CommunityServiceError('unavailable', 'Layanan Community Reports tidak dapat dihubungi.'),
    )
    renderPage()

    await fillReport(user)
    await submitForm(user)

    expect(await screen.findByText('Laporan belum terkirim')).toBeTruthy()
    expect(screen.getByText('Layanan Community Reports tidak dapat dihubungi.')).toBeTruthy()
    expect(screen.queryByText(COMMUNITY_DAILY_LIMIT_MESSAGE)).toBeNull()
    expect(mocks.listLatestCommunityReports).not.toHaveBeenCalled()
  })

  it('menolak formulir tidak lengkap tanpa memanggil backend', async () => {
    const user = userEvent.setup()
    renderPage()

    await user.type(screen.getByLabelText('URL yang dilaporkan'), 'https://contoh-situs.id/login')
    await submitForm(user)

    expect(await screen.findByText('Pilih kategori yang paling sesuai.')).toBeTruthy()
    expect(screen.getByText('Alasan minimal 20 karakter.')).toBeTruthy()
    expect(mocks.submitCommunityReport).not.toHaveBeenCalled()
  })
})

describe('Community Reports page: umpan laporan komunitas', () => {
  it('memuat tanpa perlu mengisi URL dan hanya setelah tombol ditekan', async () => {
    const user = userEvent.setup()
    mocks.listLatestCommunityReports.mockResolvedValue([entry()])

    renderPage()

    const action = screen.getByRole('button', { name: /Tampilkan laporan/ }) as HTMLButtonElement
    expect(action.disabled).toBe(false)
    expect(mocks.listLatestCommunityReports).not.toHaveBeenCalled()

    await user.click(action)

    expect(await screen.findByText('Ran', { exact: true })).toBeTruthy()
    expect(mocks.listLatestCommunityReports).toHaveBeenCalledWith({ forceRefresh: false })
    expect(screen.queryByText(/URL dimuat:/)).toBeNull()
  })

  it('menampilkan nama tersamar dan URL laporan, terbaru lebih dulu', async () => {
    const user = userEvent.setup()
    mocks.listLatestCommunityReports.mockResolvedValue([
      entry(),
      entry({
        id: 'b'.repeat(32),
        userName: 'Bima(sensor)',
        reportText: 'Penjual tidak mengirim barang setelah pembayaran lunas.',
        category: 'marketplace',
        reportedUrl: 'https://toko-bima.example/produk/123',
        hostname: 'toko-bima.example',
      }),
    ])

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    expect(await screen.findByText('Ran', { exact: true })).toBeTruthy()
    expect(screen.getByText('Bim', { exact: true })).toBeTruthy()
    expect(screen.queryByText('Rani Halim')).toBeNull()
    expect(screen.queryByText('Bima Santosa')).toBeNull()
    expect(screen.getByText('https://contoh-situs.id/login', { exact: true })).toBeTruthy()
    expect(
      screen.getByText('https://toko-bima.example/produk/123', { exact: true }),
    ).toBeTruthy()
    expect(
      screen.queryByText('Halaman meminta kata sandi lewat formulir yang menyerupai bank.'),
    ).toBeNull()
    const items = screen.getAllByRole('listitem')
    expect(items[0].textContent).toContain('Rani(sensor)')
    expect(items[1].textContent).toContain('Bima(sensor)')
  })

  it('membatasi tinggi visual daftar laporan dengan scroll internal, bukan dengan memotong data', async () => {
    const user = userEvent.setup()
    mocks.listLatestCommunityReports.mockResolvedValue(
      Array.from({ length: 12 }, (_, index) =>
        entry({
          id: index.toString(16).padStart(32, '0'),
          userName: `Rani${index}(sensor)`,
        }),
      ),
    )

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    const list = await screen.findByRole('list')
    const scroller = list.parentElement as HTMLElement
    expect(scroller.className).toContain('max-h-')
    expect(scroller.className).toContain('overflow-y-auto')
    // Tinggi tidak dipatok tetap: kartu harus menyusut saat laporan sedikit.
    expect(scroller.className).not.toMatch(/(^|\s)h-\[/)
    expect(scroller.getAttribute('role')).toBe('region')
    expect(scroller.tabIndex).toBe(0)

    // Semua laporan yang tersedia tetap dirender di dalam area scroll (tidak ada yang dibuang).
    expect(list.children).toHaveLength(COMMUNITY_DAILY_FEED_LIMIT)

    // Catatan pembatasan berada di luar area scroll sehingga tetap terbaca tanpa menggulir.
    const caveat = screen.getByText(/Nama pelapor ditampilkan secara tersamarkan/)
    expect(scroller.contains(caveat)).toBe(false)
    expect(
      scroller.contains(screen.getByText(/Status moderasi menunjukkan hasil peninjauan/)),
    ).toBe(false)
  })

  it('daftar satu laporan memakai wadah scroll yang sama tanpa ruang kosong paksa', async () => {
    const user = userEvent.setup()
    mocks.listLatestCommunityReports.mockResolvedValue([entry()])

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    const list = await screen.findByRole('list')
    const scroller = list.parentElement as HTMLElement
    expect(list.children).toHaveLength(1)
    expect(scroller.className).toContain('max-h-')
    expect(scroller.className).not.toMatch(/(^|\s)h-\[/)
  })

  it('memakai hostname untuk dokumen lama tanpa URL dan fallback bila keduanya tidak ada', async () => {
    const user = userEvent.setup()
    mocks.listLatestCommunityReports.mockResolvedValue([
      entry({ id: 'b'.repeat(32), reportedUrl: null }),
      entry({
        id: 'c'.repeat(32),
        userName: 'Bima(sensor)',
        reportedUrl: null,
        hostname: null,
      }),
    ])

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    expect(await screen.findByText('contoh-situs.id', { exact: true })).toBeTruthy()
    expect(
      screen.getByText('Alamat tidak tersedia pada daftar publik.', { exact: true }),
    ).toBeTruthy()
    const items = screen.getAllByRole('listitem')
    expect(within(items[0]).getByText('Phishing atau login palsu')).toBeTruthy()
    expect(within(items[0]).queryByText(/Halaman meminta kata sandi/)).toBeNull()
  })

  it('menampilkan status moderasi nyata dan membedakannya dari laporan belum diverifikasi', async () => {
    const user = userEvent.setup()
    const confirmedId = 'a'.repeat(32)
    const pendingId = 'b'.repeat(32)
    const unverifiedId = 'c'.repeat(32)
    mocks.listLatestCommunityReports.mockResolvedValue([
      entry({
        id: confirmedId,
        userName: 'Rani Halim',
        reportedUrl: 'https://bank-palsu.example/login',
      }),
      entry({
        id: pendingId,
        userName: 'Bima Santosa',
        reportedUrl: 'https://toko-bima.example/produk/123',
      }),
      entry({
        id: unverifiedId,
        userName: 'Citra Dewi',
        reportedUrl: 'https://belum-ditinjau.example/halaman',
      }),
    ])
    mocks.loadPublicModerationStatuses.mockResolvedValue({
      statuses: new Map([
        [
          confirmedId,
          { status: 'confirmed_malicious', updatedAt: '2026-10-21T03:00:00.000Z' },
        ],
        [pendingId, { status: 'pending', updatedAt: null }],
      ]),
      unavailable: false,
    })

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    expect(
      await screen.findByText('Terverifikasi berbahaya', { selector: 'span' }),
    ).toBeTruthy()
    expect(screen.getByText('Menunggu peninjauan')).toBeTruthy()
    expect(await screen.findByText('Belum diverifikasi')).toBeTruthy()
    expect(mocks.loadPublicModerationStatuses).toHaveBeenCalledWith([
      confirmedId,
      pendingId,
      unverifiedId,
    ])

    const items = screen.getAllByRole('listitem')
    expect(within(items[0]).getByText('Terverifikasi berbahaya')).toBeTruthy()
    expect(within(items[0]).queryByText('Belum diverifikasi')).toBeNull()
    expect(within(items[0]).getByText(/Status moderasi diperbarui/)).toBeTruthy()
    expect(within(items[1]).getByText('Menunggu peninjauan')).toBeTruthy()
    expect(within(items[2]).getByText('Belum diverifikasi')).toBeTruthy()
    expect(within(items[2]).queryByText('Terverifikasi berbahaya')).toBeNull()
  })

  it('tidak menyebut status belum diverifikasi saat pembacaan status gagal', async () => {
    const user = userEvent.setup()
    mocks.listLatestCommunityReports.mockResolvedValue([entry()])
    mocks.loadPublicModerationStatuses.mockResolvedValue({
      statuses: new Map(),
      unavailable: true,
    })

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    expect(await screen.findByText('Status tidak tersedia')).toBeTruthy()
    expect(screen.getByText('Sebagian status moderasi tidak dapat dimuat')).toBeTruthy()
    expect(screen.queryByText('Belum diverifikasi')).toBeNull()
    expect(
      screen.queryByText('Terverifikasi berbahaya', { selector: 'span' }),
    ).toBeNull()
  })

  it('menampilkan status pemeriksaan sebelum hasil moderasi selesai dibaca', async () => {
    const user = userEvent.setup()
    let resolveStatuses: (value: {
      statuses: Map<string, { status: string; updatedAt: string | null }>
      unavailable: boolean
    }) => void = () => undefined
    mocks.listLatestCommunityReports.mockResolvedValue([entry()])
    mocks.loadPublicModerationStatuses.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveStatuses = resolve
        }),
    )

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    expect(await screen.findByText('Memeriksa status…')).toBeTruthy()
    expect(screen.queryByText('Belum diverifikasi')).toBeNull()

    resolveStatuses({ statuses: new Map(), unavailable: false })
    expect(await screen.findByText('Belum diverifikasi')).toBeTruthy()
    expect(screen.queryByText('Memeriksa status…')).toBeNull()
  })

  it('menyalin URL tersanitasi tanpa query, fragment, atau kredensial', async () => {
    const user = userEvent.setup()
    const writeText = vi.fn(async (_value: string) => undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })
    mocks.listLatestCommunityReports.mockResolvedValue([
      entry({
        reportedUrl: 'https://contoh-situs.id/reset/abc?token=rahasia#bagian',
      }),
    ])

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))
    await screen.findByText('https://contoh-situs.id/reset/abc', { exact: true })
    await user.click(screen.getByRole('button', { name: 'Salin URL laporan' }))

    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith('https://contoh-situs.id/reset/abc')
    })
    expect(screen.getByText('URL tersalin')).toBeTruthy()
    expect(writeText.mock.calls[0][0]).not.toContain('token=rahasia')
    expect(writeText.mock.calls[0][0]).not.toContain('#bagian')
  })

  it('memisahkan nama terlihat dan bagian tersensor yang diburamkan', async () => {
    const user = userEvent.setup()
    mocks.listLatestCommunityReports.mockResolvedValue([entry({ userName: 'zackjaka' })])

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    const visible = await screen.findByText('zack', { exact: true })
    const blurred = screen.getByText('jaka', { exact: true })

    expect(visible.nextElementSibling).toBe(blurred)
    expect(visible.getAttribute('style')).toBeNull()
    expect(visible.parentElement?.className).toContain('gap-x-2')
    expect(blurred.style.filter).toBe('blur(4px)')
    expect(blurred.className).toContain('select-none')
    expect(screen.getAllByText('jaka', { exact: true })).toEqual([blurred])
    expect(
      Array.from(document.querySelectorAll('*')).flatMap((element) =>
        Array.from(element.attributes).filter((attribute) =>
          attribute.value.includes('jaka'),
        ),
      ),
    ).toHaveLength(0)
    expect(
      Array.from(document.querySelectorAll('[hidden], [aria-hidden="true"]')).filter(
        (node) => node.textContent?.includes('jaka'),
      ),
    ).toHaveLength(0)
  })

  it('memakai fallback bintang yang menempel untuk nama pendek', async () => {
    const user = userEvent.setup()
    mocks.listLatestCommunityReports.mockResolvedValue([entry({ userName: 'Dewi' })])

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    const visible = await screen.findByText('Dewi', { exact: true })
    const stars = screen.getByText('****', { exact: true })

    expect(visible.nextElementSibling).toBe(stars)
    expect(visible.parentElement).toBe(stars.parentElement)
    expect(stars.getAttribute('style')).toBeNull()
    expect(stars.parentElement?.className).not.toContain('gap-x-2')
  })

  it('menyusun nama, waktu, status, dan URL tersanitasi dalam kartu horizontal', async () => {
    const user = userEvent.setup()
    const reportText = 'Halaman meminta kata sandi lewat formulir yang menyerupai bank.'
    mocks.listLatestCommunityReports.mockResolvedValue([entry({ reportText })])

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))
    await screen.findByText('Ran', { exact: true })
    await screen.findByText('Belum diverifikasi')

    const list = screen.getByRole('list')
    expect(list.className).toContain('flex-col')
    expect(list.className).not.toContain('grid-cols')

    const item = screen.getAllByRole('listitem')[0]
    const row = item.firstElementChild
    expect(row?.className).toContain('flex-wrap')
    expect(row?.className).toContain('justify-between')

    const name = within(item).getByText('Ran', { exact: true })
    const dateLine = within(item).getByText('20 Okt 2026, 10.00 WITA')
    const websiteLabel = within(item).getByText('Alamat yang dilaporkan')
    const websiteNote = within(item).getByText(/sudah disanitasi/)
    const websiteValue = within(item).getByText('https://contoh-situs.id/login', {
      exact: true,
    })
    const category = within(item).getByText('Phishing atau login palsu')
    const status = within(item).getByText('Belum diverifikasi')

    const isBefore = (first: Node, second: Node) =>
      Boolean(
        first.compareDocumentPosition(second) & Node.DOCUMENT_POSITION_FOLLOWING,
      )

    expect(isBefore(name, dateLine)).toBe(true)
    expect(isBefore(dateLine, category)).toBe(true)
    expect(isBefore(category, status)).toBe(true)
    expect(isBefore(status, websiteLabel)).toBe(true)
    expect(isBefore(websiteLabel, websiteNote)).toBe(true)
    expect(isBefore(websiteNote, websiteValue)).toBe(true)

    expect(name.closest('p')?.className).toContain('text-base')
    expect(dateLine.className).toContain('mt-1')
    expect(dateLine.className).toContain('text-xs')
    expect(websiteValue.className).toContain('min-w-0')
    expect(websiteValue.className).toContain('break-all')
    expect(websiteValue.className).toContain('font-mono')
    expect(within(item).queryByText(reportText)).toBeNull()
    expect(within(item).queryByRole('link')).toBeNull()
    expect(websiteValue.closest('a')).toBeNull()

    const copy = within(item).getByRole('button', { name: 'Salin URL laporan' })
    expect(copy).toBeTruthy()
  })

  it('tidak menampilkan query atau fragment sensitif dan tidak membuat URL aktif', async () => {
    const user = userEvent.setup()
    mocks.listLatestCommunityReports.mockResolvedValue([
      entry({
        reportedUrl: 'https://contoh-situs.id/reset/abc?token=rahasia&code=123#bagian',
      }),
    ])

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    expect(
      await screen.findByText('https://contoh-situs.id/reset/abc', { exact: true }),
    ).toBeTruthy()
    expect(document.body.textContent).not.toContain('token=rahasia')
    expect(document.body.textContent).not.toContain('code=123')
    expect(document.body.textContent).not.toContain('#bagian')
    const item = screen.getAllByRole('listitem')[0]
    expect(within(item).queryByRole('link')).toBeNull()
  })

  it('membatasi daftar pada kapasitas panel dan memakai waktu WITA', async () => {
    const user = userEvent.setup()
    const entries = Array.from(
      { length: COMMUNITY_DAILY_FEED_LIMIT + 2 },
      (_unused, index) =>
        entry({
          id: (index + 1).toString(16).padStart(32, '0'),
          reportedUrl: `https://situs-${index + 1}.contoh.id/halaman`,
          hostname: `situs-${index + 1}.contoh.id`,
        }),
    )
    mocks.listLatestCommunityReports.mockResolvedValue(entries)

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    await screen.findByText('https://situs-1.contoh.id/halaman', { exact: true })
    const items = screen.getAllByRole('listitem')
    expect(items).toHaveLength(COMMUNITY_DAILY_FEED_LIMIT)
    expect(items[0].textContent).toContain('20 Okt 2026, 10.00 WITA')
    expect(items[COMMUNITY_DAILY_FEED_LIMIT - 1].textContent).toContain(
      `https://situs-${COMMUNITY_DAILY_FEED_LIMIT}.contoh.id/halaman`,
    )
    expect(
      screen.queryByText(`https://situs-${COMMUNITY_DAILY_FEED_LIMIT + 1}.contoh.id/halaman`, {
        exact: true,
      }),
    ).toBeNull()
  })

  it('tidak menampilkan teks alasan bebas atau kontrol buka-tutup pada kartu', async () => {
    const user = userEvent.setup()
    const longText =
      'Laporan panjang ini menjelaskan secara rinci bagaimana formulir menyalin halaman bank, meminta kata sandi, lalu meminta kode OTP yang dikirim ke ponsel korban tanpa memberi kesempatan memeriksa alamat sebenarnya.'
    mocks.listLatestCommunityReports.mockResolvedValue([entry({ reportText: longText })])

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    expect(
      await screen.findByText('https://contoh-situs.id/login', { exact: true }),
    ).toBeTruthy()
    expect(screen.queryByText(longText)).toBeNull()
    expect(screen.queryByRole('button', { name: 'Selengkapnya' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Ringkas' })).toBeNull()
  })

  it('hanya menampilkan URL tersanitasi, bukan nama mentah, email, UID, atau tautan aktif', async () => {
    const user = userEvent.setup()
    mocks.listLatestCommunityReports.mockResolvedValue([
      entry({
        userName: 'anaks(sensor)',
        reportedUrl: 'https://contoh-situs.id/login?token=rahasia#bagian',
        hostname: 'contoh-situs.id',
      }),
    ])

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    expect(await screen.findByText('anak', { exact: true })).toBeTruthy()
    const item = screen.getAllByRole('listitem')[0]
    expect(within(item).getByText('https://contoh-situs.id/login', { exact: true })).toBeTruthy()
    expect(document.body.textContent).not.toContain('anaksigma')
    expect(document.body.textContent).not.toContain('pengguna@example.com')
    expect(document.body.textContent).not.toContain('user-1')
    expect(document.body.textContent).not.toContain('token=rahasia')
    expect(document.body.textContent).not.toContain('#bagian')
    expect(document.body.textContent).not.toContain('utm_source')
    expect(screen.queryByText(/URL dimuat:/)).toBeNull()
    expect(within(item).queryByRole('link')).toBeNull()
    expect(
      Array.from(document.querySelectorAll('a')).filter((anchor) =>
        (anchor.getAttribute('href') ?? '').includes('contoh-situs.id'),
      ),
    ).toHaveLength(0)
  })

  it('memakai keadaan kosong yang alami tanpa istilah teknis', async () => {
    const user = userEvent.setup()

    renderPage()

    expect(screen.queryByText(COMMUNITY_LATEST_EMPTY_MESSAGE)).toBeNull()

    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    expect(await screen.findByText(COMMUNITY_LATEST_EMPTY_MESSAGE)).toBeTruthy()
    expect(
      screen.getByText(/Laporan yang dibagikan hari ini akan muncul di sini/),
    ).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()

    const text = document.body.textContent ?? ''
    expect(text).not.toMatch(/24 jam/i)
    expect(text).not.toMatch(/database/i)
    expect(text).not.toMatch(/firestore/i)
    expect(text).not.toMatch(/spark/i)
    expect(text).not.toMatch(/collection/i)
    expect(text).not.toMatch(/URL lain/i)
    expect(text).not.toMatch(/maksimal 20/i)
    expect(text).toContain(
      'Nama pelapor ditampilkan secara tersamarkan dan bukan merupakan identitas yang terverifikasi.',
    )
    expect(text).toContain(
      'Status moderasi menunjukkan hasil peninjauan manual oleh moderator.',
    )
    expect(text).toContain(
      'Kecuali berstatus Terverifikasi berbahaya, status tersebut bukan jaminan bahwa tautan aman.',
    )
    expect(text).toContain(
      'Laporan komunitas tidak secara otomatis mengubah skor atau hasil pemeriksaan VERIGUARD.',
    )
    expect(text).toContain('daftar laporan terbaru')
  })

  it('memisahkan status memuat, gagal, dan kosong', async () => {
    const user = userEvent.setup()
    let resolveList: (value: CommunityLatestReportEntry[]) => void = () => undefined
    mocks.listLatestCommunityReports.mockImplementation(
      () =>
        new Promise<CommunityLatestReportEntry[]>((resolve) => {
          resolveList = resolve
        }),
    )

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    expect(screen.getByText(/Memuat laporan komunitas/)).toBeTruthy()

    resolveList([entry()])
    await screen.findByText('Ran', { exact: true })
    expect(screen.queryByText(/Memuat laporan komunitas/)).toBeNull()

    mocks.listLatestCommunityReports.mockRejectedValueOnce(
      new CommunityServiceError('unavailable', 'Layanan komunitas tidak dapat dihubungi.'),
    )
    await user.click(screen.getByRole('button', { name: /Muat ulang/ }))

    expect(await screen.findByText('Laporan komunitas belum dapat ditampilkan')).toBeTruthy()
    expect(screen.getByText('Layanan komunitas tidak dapat dihubungi.')).toBeTruthy()
    expect(
      screen
        .getByText('Laporan komunitas belum dapat ditampilkan')
        .closest('[data-error-code]')
        ?.getAttribute('data-error-code'),
    ).toBe('unavailable')
    expect(screen.queryByText(COMMUNITY_LATEST_EMPTY_MESSAGE)).toBeNull()
    expect(screen.queryByText('Ran', { exact: true })).toBeNull()
  })

  it('Coba lagi menjalankan ulang permintaan lalu memperbarui umpan saat berhasil', async () => {
    const user = userEvent.setup()
    let resolveRetry: (value: CommunityLatestReportEntry[]) => void = () => undefined
    mocks.listLatestCommunityReports
      .mockRejectedValueOnce(
        new CommunityServiceError('unavailable', 'Layanan komunitas tidak dapat dihubungi.'),
      )
      .mockImplementationOnce(
        () =>
          new Promise<CommunityLatestReportEntry[]>((resolve) => {
            resolveRetry = resolve
          }),
      )

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))
    await screen.findByText('Laporan komunitas belum dapat ditampilkan')

    await user.click(screen.getByRole('button', { name: 'Coba lagi' }))

    expect(screen.getByText(/Memuat laporan komunitas/)).toBeTruthy()
    expect(mocks.listLatestCommunityReports).toHaveBeenLastCalledWith({
      forceRefresh: true,
    })

    resolveRetry([entry()])
    expect(await screen.findByText('Ran', { exact: true })).toBeTruthy()
    expect(screen.queryByText('Laporan komunitas belum dapat ditampilkan')).toBeNull()
    expect(screen.queryByText(COMMUNITY_LATEST_EMPTY_MESSAGE)).toBeNull()
  })

  it('menampilkan copy ramah saat akses daftar laporan ditolak', async () => {
    const user = userEvent.setup()
    mocks.listLatestCommunityReports.mockRejectedValueOnce(
      new CommunityServiceError(
        'permission-denied',
        'Laporan komunitas tidak dapat dibaca karena akun ini tidak memiliki izin. Sesi sudah diperbarui, tetapi akses tetap ditolak. Coba masuk kembali; bila masih gagal, hubungi pengelola layanan.',
      ),
    )

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))

    expect(await screen.findByText('Laporan komunitas belum dapat ditampilkan')).toBeTruthy()
    expect(
      screen.getByText(
        'Laporan komunitas sedang mengalami kendala saat dimuat. Silakan coba lagi.',
      ),
    ).toBeTruthy()
    expect(screen.getByText(/Hasil pemindaian tetap dapat digunakan/)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Coba lagi' })).toBeTruthy()
    expect(
      screen
        .getByText('Laporan komunitas belum dapat ditampilkan')
        .closest('[data-error-code]')
        ?.getAttribute('data-error-code'),
    ).toBe('permission-denied')
    expect(document.body.textContent).not.toMatch(
      /tidak memiliki izin|sesi sudah diperbarui|pengelola layanan/i,
    )
  })

  it('menonaktifkan tombol selama memuat dan memakai muat ulang untuk permintaan berikutnya', async () => {
    const user = userEvent.setup()
    let resolveList: (value: CommunityLatestReportEntry[]) => void = () => undefined
    mocks.listLatestCommunityReports.mockImplementationOnce(
      () =>
        new Promise<CommunityLatestReportEntry[]>((resolve) => {
          resolveList = resolve
        }),
    )

    renderPage()
    const action = screen.getByRole('button', { name: /Tampilkan laporan/ }) as HTMLButtonElement
    await user.click(action)

    expect(action.disabled).toBe(true)
    await user.click(action)
    expect(mocks.listLatestCommunityReports).toHaveBeenCalledTimes(1)

    resolveList([])
    await screen.findByText(COMMUNITY_LATEST_EMPTY_MESSAGE)

    mocks.listLatestCommunityReports.mockResolvedValueOnce([entry()])
    await user.click(screen.getByRole('button', { name: /Muat ulang/ }))

    expect(await screen.findByText('Ran', { exact: true })).toBeTruthy()
    expect(mocks.listLatestCommunityReports).toHaveBeenNthCalledWith(1, {
      forceRefresh: false,
    })
    expect(mocks.listLatestCommunityReports).toHaveBeenNthCalledWith(2, {
      forceRefresh: true,
    })
  })

  it('mempertahankan umpan saat URL pada formulir diubah', async () => {
    const user = userEvent.setup()
    mocks.listLatestCommunityReports.mockResolvedValue([entry()])

    renderPage()
    await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))
    expect(await screen.findByText('Ran', { exact: true })).toBeTruthy()

    await user.type(screen.getByLabelText('URL yang dilaporkan'), '/admin')

    expect(screen.getByText('Ran', { exact: true })).toBeTruthy()
    expect(mocks.listLatestCommunityReports).toHaveBeenCalledTimes(1)
    expect(screen.queryByText(/URL dimuat:/)).toBeNull()
  })

  it('memuat ulang umpan setelah tanggal WITA berganti saat tab kembali terlihat', async () => {
    const user = userEvent.setup()
    const nowSpy = vi
      .spyOn(Date, 'now')
      .mockReturnValue(Date.parse('2026-10-20T02:00:00.000Z'))
    const visibilitySpy = vi
      .spyOn(document, 'visibilityState', 'get')
      .mockReturnValue('visible')
    mocks.listLatestCommunityReports.mockResolvedValue([entry()])

    try {
      renderPage()
      await user.click(screen.getByRole('button', { name: /Tampilkan laporan/ }))
      expect(await screen.findByText('Ran', { exact: true })).toBeTruthy()
      expect(mocks.listLatestCommunityReports).toHaveBeenCalledTimes(1)

      await act(async () => {
        document.dispatchEvent(new Event('visibilitychange'))
      })
      expect(mocks.listLatestCommunityReports).toHaveBeenCalledTimes(1)

      nowSpy.mockReturnValue(Date.parse('2026-10-21T02:00:00.000Z'))
      await act(async () => {
        document.dispatchEvent(new Event('visibilitychange'))
      })

      await waitFor(() => {
        expect(mocks.listLatestCommunityReports).toHaveBeenCalledTimes(2)
      })
      expect(mocks.listLatestCommunityReports).toHaveBeenLastCalledWith({
        forceRefresh: true,
      })
    } finally {
      visibilitySpy.mockRestore()
      nowSpy.mockRestore()
    }
  })
})

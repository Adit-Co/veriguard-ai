import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { AuthContextValue } from '../../lib/auth/context'
import type {
  CommunityContext,
  CommunityReportEntry,
  CommunitySummary,
} from '../../lib/community/types'

const mocks = vi.hoisted(() => ({
  useCommunityContext: vi.fn(),
  useAuth: vi.fn(),
}))

vi.mock('../../lib/community/useCommunityContext', () => ({
  useCommunityContext: mocks.useCommunityContext,
}))

vi.mock('../../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))

vi.mock('../../lib/firebase/config', () => ({ isFirebaseConfigured: true }))

import { CommunityContextPanel } from './CommunityContextPanel'

const NOW = Date.parse('2026-10-20T04:00:00.000Z')
const SCANNED_URL = 'https://contoh-situs.id/login'

function authFixture(overrides: Partial<AuthContextValue> = {}): AuthContextValue {
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

const verifiedAuth = authFixture()
const unverifiedAuth = authFixture({
  user: {
    uid: 'user-1',
    email: 'pengguna@example.com',
    displayName: 'Pengguna',
    emailVerified: false,
    isAnonymous: false,
    startedAt: null,
  },
})
const signedOutAuth = authFixture({ user: null })

type PanelState = {
  status: 'idle' | 'loading' | 'ready' | 'error'
  normalizedUrl: string | null
  context: CommunityContext | null
  error: string | null
  refresh: () => Promise<void>
}

function summary(overrides: Partial<CommunitySummary> = {}): CommunitySummary {
  return {
    hostname: 'contoh-situs.id',
    reportCount: 2,
    reporterCount: 2,
    categoryCounts: { phishing: 2 },
    firstReportedAt: new Date(NOW - 3 * 86_400_000).toISOString(),
    lastReportedAt: new Date(NOW - 86_400_000).toISOString(),
    lastActivityAt: new Date(NOW - 86_400_000).toISOString(),
    moderationStatus: 'community_reported',
    reviewRequired: false,
    reviewReason: null,
    verificationSource: null,
    verifiedAt: null,
    aggregatesComplete: true,
    ...overrides,
  }
}

function entry(overrides: Partial<CommunityReportEntry> = {}): CommunityReportEntry {
  return {
    id: 'a'.repeat(32),
    userName: 'Rani Halim',
    reportText: 'Halaman meminta kata sandi lewat formulir yang menyerupai bank.',
    category: 'phishing',
    hostname: 'contoh-situs.id',
    createdAt: new Date(NOW - 86_400_000).toISOString(),
    updatedAt: new Date(NOW - 86_400_000).toISOString(),
    ...overrides,
  }
}

function state(overrides: Partial<PanelState> = {}): PanelState {
  return {
    status: 'ready',
    normalizedUrl: SCANNED_URL,
    context: { summary: null, report: null, reports: [] },
    error: null,
    refresh: async () => undefined,
    ...overrides,
  }
}

function withReports(reports: CommunityReportEntry[], base: Partial<CommunitySummary> = {}): PanelState {
  return state({
    context: { summary: summary({ reportCount: reports.length, ...base }), report: null, reports },
  })
}

function render(): string {
  return renderToStaticMarkup(
    <MemoryRouter initialEntries={['/hasil']}>
      <CommunityContextPanel url={SCANNED_URL} />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  mocks.useAuth.mockReturnValue(verifiedAuth)
  mocks.useCommunityContext.mockReturnValue(state())
  // Skor reputasi memakai umur laporan; jam dibekukan agar pengujian tidak berubah-ubah.
  vi.spyOn(Date, 'now').mockReturnValue(NOW)
})

afterEach(() => {
  vi.clearAllMocks()
  vi.restoreAllMocks()
})

describe('CommunityContextPanel', () => {
  it('memisahkan Skor Reputasi dari Skor Indikasi Internal', () => {
    mocks.useCommunityContext.mockReturnValue(
      withReports([entry(), entry({ userName: 'Bima Santosa' })]),
    )

    const markup = render()

    expect(markup).toContain('Skor Reputasi')
    expect(markup).toContain('Skor Reputasi 30 dari 100')
    expect(markup).toContain('tidak berubah karena ada laporan')
    expect(markup).toContain('Tidak mengubah Skor Indikasi Internal')
    expect(markup).toContain('2 pseudonim pelapor')
    expect(markup).toContain('bukan bukti akun unik')
  })

  it('memakai jumlah akun unik, bukan jumlah laporan, sebagai dasar bobot', () => {
    mocks.useCommunityContext.mockReturnValue(
      withReports([entry(), entry({ userName: 'Bima Santosa' })], { reporterCount: 1 }),
    )

    const markup = render()

    expect(markup).toContain('Skor Reputasi 22 dari 100')
    expect(markup).toContain('2 laporan aktif oleh 1 pseudonim pelapor')
  })

  it('menampilkan nama tersamar dan isi laporan nyata untuk URL yang diperiksa', () => {
    mocks.useCommunityContext.mockReturnValue(
      withReports([
        entry(),
        entry({
          userName: 'Bima Santosa',
          reportText: 'Penjual hilang setelah pembayaran, barang tidak dikirim.',
          category: 'marketplace',
        }),
      ]),
    )

    const markup = render()

    expect(markup).toContain('Laporan komunitas untuk URL ini')
    expect(markup).toContain('>Rani</span>')
    expect(markup).toContain('> Halim</span>')
    expect(markup).toContain('>Bima</span>')
    expect(markup).toContain('> Santosa</span>')
    expect(markup).toContain('filter:blur(4px)')
    expect(markup).not.toContain('Rani Halim')
    expect(markup).not.toContain('Bima Santosa')
    expect(markup).toContain('Penjual hilang setelah pembayaran')
    expect(markup).toContain('Halaman meminta kata sandi lewat formulir yang menyerupai bank.')
    expect(markup).toContain('dugaan pengguna, bukan hasil pemeriksaan')
  })

  it('tidak merender nama mentah, email, UID, atau markup laporan sebagai HTML', () => {
    mocks.useCommunityContext.mockReturnValue(
      withReports([
        entry({
          userName: 'anaksigma',
          reportText: '<img src=x onerror=alert(1)>',
        }),
      ]),
    )

    const markup = render()

    expect(markup).toContain('>anak</span>')
    expect(markup).toContain('>sigma</span>')
    expect(markup).toContain('filter:blur(4px)')
    expect(markup).not.toContain('anaksigma')
    expect(markup).not.toContain('pengguna@example.com')
    expect(markup).not.toContain('user-1')
    expect(markup).toContain('&lt;img src=x onerror=alert(1)&gt;')
    expect(markup).not.toContain('<img')
  })

  it('tidak mengarang skor ketika tidak ada laporan yang cocok', () => {
    mocks.useCommunityContext.mockReturnValue(state())

    const markup = render()

    expect(markup).toContain('Belum ada laporan komunitas')
    expect(markup).toContain('Tidak ada skor yang dikarang untuk keadaan kosong')
    expect(markup).not.toContain('dari 100')
  })

  it('membedakan memuat, gagal, dan kosong', () => {
    mocks.useCommunityContext.mockReturnValue(state({ status: 'loading', context: null }))
    const loading = render()
    expect(loading).toContain('Memeriksa konteks komunitas')
    expect(loading).not.toContain('Konteks komunitas tidak tersedia')

    mocks.useCommunityContext.mockReturnValue(
      state({
        status: 'error',
        context: null,
        error: 'Layanan komunitas tidak dapat dihubungi. Coba lagi nanti.',
      }),
    )
    const failed = render()
    expect(failed).toContain('Konteks komunitas tidak tersedia')
    expect(failed).toContain('Layanan komunitas tidak dapat dihubungi. Coba lagi nanti.')
    expect(failed).not.toContain('Belum ada laporan komunitas')
    expect(failed).not.toContain('Skor Reputasi')
  })

  it('hanya menaikkan reputasi lewat data nyata: moderasi menaikkan, pembersihan menurunkan', () => {
    const reports = [entry(), entry({ userName: 'Bima Santosa' })]

    mocks.useCommunityContext.mockReturnValue(withReports(reports, { moderationStatus: 'verified_malicious' }))
    const verified = render()

    mocks.useCommunityContext.mockReturnValue(withReports(reports, { moderationStatus: 'cleared' }))
    const cleared = render()

    expect(verified).toContain('Skor Reputasi 65 dari 100')
    expect(verified).toContain('Diverifikasi berbahaya oleh moderator')
    expect(cleared).toContain('Skor Reputasi 10 dari 100')
  })

  it('blokir akun belum terverifikasi tanpa memanggil pembacaan laporan', () => {
    mocks.useAuth.mockReturnValue(unverifiedAuth)

    const markup = render()

    expect(markup).toContain('Konteks komunitas belum dimuat')
    expect(markup).toContain('Verifikasi email akun')
    expect(markup).not.toContain('Belum ada laporan komunitas')
    expect(mocks.useCommunityContext.mock.calls[0][1]).toBe(false)
  })

  it('meminta masuk sebelum membaca konteks untuk tamu', () => {
    mocks.useAuth.mockReturnValue(signedOutAuth)

    const markup = render()

    expect(markup).toContain('Masuk dengan akun')
    expect(markup).toContain('Konteks komunitas belum dimuat')
    expect(markup).not.toContain('Belum ada laporan komunitas')
    expect(mocks.useCommunityContext.mock.calls[0][1]).toBe(false)
  })

  it('tidak menampilkan skor dari agregat yang terpotong', () => {
    mocks.useCommunityContext.mockReturnValue(
      withReports([entry(), entry({ userName: 'Bima Santosa' })], {
        reporterCount: 0,
        categoryCounts: {},
        aggregatesComplete: false,
      }),
    )

    const markup = render()

    expect(markup).toContain('Ringkasan memindai hingga 300 laporan terbaru')
    expect(markup).toContain('Skor Reputasi tidak ditampilkan')
    expect(markup).not.toContain('dari 100')
    expect(markup).not.toContain('aria-label="Skor Reputasi')
  })
})

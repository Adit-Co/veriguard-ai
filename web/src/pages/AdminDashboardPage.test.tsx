// @vitest-environment jsdom

import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import type { AuthContextValue } from '../lib/auth/context'
import type { ModerationQueueSnapshot } from '../lib/moderation/moderationService'
import type {
  AdminModerationReport,
  ModerationHistoryEntry,
} from '../lib/moderation/types'

const mocks = vi.hoisted(() => ({
  useAuth: vi.fn(),
  useAdminRole: vi.fn(),
  loadModerationQueue: vi.fn(),
  loadModerationHistory: vi.fn(),
  applyModerationDecision: vi.fn(),
}))

vi.mock('../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))
vi.mock('../lib/auth/useAdminRole', () => ({ useAdminRole: mocks.useAdminRole }))
vi.mock('../lib/moderation/moderationService', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../lib/moderation/moderationService')>()
  return {
    ...actual,
    loadModerationQueue: mocks.loadModerationQueue,
    loadModerationHistory: mocks.loadModerationHistory,
    applyModerationDecision: mocks.applyModerationDecision,
  }
})

import { AdminDashboardPage } from './AdminDashboardPage'

function authFixture(): AuthContextValue {
  return {
    mode: 'firebase',
    status: 'ready',
    user: {
      uid: 'admin-uid',
      email: 'admin@example.com',
      displayName: 'Admin',
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
  }
}

function adminRoleFixture(
  overrides: Partial<{
    status: 'loading' | 'admin' | 'none' | 'error'
    isAdmin: boolean
    error: string | null
  }> = {},
) {
  return {
    status: 'admin',
    isAdmin: true,
    error: null,
    refresh: vi.fn(async () => undefined),
    ...overrides,
  }
}

function reportFixture(
  overrides: Partial<AdminModerationReport> = {},
): AdminModerationReport {
  return {
    id: 'a'.repeat(32),
    urlHash: 'b'.repeat(64),
    userName: 'Rani Halim',
    reportText: 'Formulir meminta kata sandi dan kode OTP.',
    category: 'phishing',
    reportedUrl: 'https://contoh-situs.id/login',
    hostname: 'contoh-situs.id',
    createdAt: '2026-10-20T02:00:00.000Z',
    moderation: null,
    ...overrides,
  }
}

function terminalReportFixture(): AdminModerationReport {
  return reportFixture({
    id: 'c'.repeat(32),
    userName: 'Bima Santosa',
    reportedUrl: 'https://toko-bima.example/produk/123',
    hostname: 'toko-bima.example',
    category: 'marketplace',
    moderation: {
      status: 'confirmed_malicious',
      note: 'Halaman menyalin formulir pembayaran resmi.',
      updatedAt: '2026-10-21T04:00:00.000Z',
      updatedBy: 'admin-uid',
    },
  })
}

function snapshotFixture(
  reports: AdminModerationReport[],
  overrides: Partial<ModerationQueueSnapshot> = {},
): ModerationQueueSnapshot {
  return {
    reports,
    reportsTruncated: false,
    moderationTruncated: false,
    ...overrides,
  }
}

function historyFixture(): ModerationHistoryEntry {
  return {
    id: 'created_review',
    action: 'created',
    fromStatus: null,
    toStatus: 'review',
    note: 'Memeriksa bukti laporan.',
    actorUid: 'admin-uid',
    createdAt: '2026-10-21T04:00:00.000Z',
  }
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/dashboard/admin']}>
      <Routes>
        <Route path="/dashboard/admin" element={<AdminDashboardPage />} />
        <Route path="/dashboard" element={<div>dashboard-saya-stub</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

async function selectQueueReport(user: ReturnType<typeof userEvent.setup>) {
  await user.click(
    screen.getByRole('button', { name: /contoh-situs\.id\/login/ }),
  )
}

beforeEach(() => {
  mocks.useAuth.mockReturnValue(authFixture())
  mocks.useAdminRole.mockReturnValue(adminRoleFixture())
  mocks.loadModerationQueue.mockResolvedValue(snapshotFixture([reportFixture()]))
  mocks.loadModerationHistory.mockResolvedValue([])
  mocks.applyModerationDecision.mockResolvedValue(undefined)
})

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

describe('Dashboard Admin: otorisasi tampilan', () => {
  it('pengguna biasa hanya mendapat penolakan dan tidak memuat antrean', () => {
    mocks.useAdminRole.mockReturnValue(
      adminRoleFixture({ status: 'none', isAdmin: false }),
    )

    renderPage()

    expect(screen.getByText('Akses Dashboard Admin diperlukan')).toBeTruthy()
    expect(mocks.loadModerationQueue).not.toHaveBeenCalled()
    expect(screen.queryByText('https://contoh-situs.id/login')).toBeNull()
    expect(
      screen.getByRole('link', { name: /Kembali ke Dashboard Saya/ }).getAttribute('href'),
    ).toBe('/dashboard')
  })

  it('tidak membaca data moderasi selama peran admin belum diverifikasi', () => {
    mocks.useAdminRole.mockReturnValue(
      adminRoleFixture({ status: 'loading', isAdmin: false }),
    )

    renderPage()

    expect(screen.getByText('Memeriksa izin admin…')).toBeTruthy()
    expect(mocks.loadModerationQueue).not.toHaveBeenCalled()
  })

  it('menampilkan kegagalan peran tanpa memuat antrean', () => {
    mocks.useAdminRole.mockReturnValue(
      adminRoleFixture({
        status: 'error',
        isAdmin: false,
        error: 'Peran admin belum dapat diverifikasi.',
      }),
    )

    renderPage()

    expect(screen.getByText('Peran admin tidak dapat diverifikasi')).toBeTruthy()
    expect(mocks.loadModerationQueue).not.toHaveBeenCalled()
  })
})

describe('Dashboard Admin: antrean dan keputusan', () => {
  it('menampilkan metrik dan tren dari laporan yang benar-benar dimuat', async () => {
    mocks.loadModerationQueue.mockResolvedValue(
      snapshotFixture([reportFixture(), terminalReportFixture()]),
    )

    renderPage()

    expect(await screen.findByText('Antrean laporan')).toBeTruthy()
    expect(screen.getByText('Tren laporan 7 hari')).toBeTruthy()

    const totalCard = screen.getByText('Dari antrean yang berhasil dibaca')
      .parentElement as HTMLElement
    expect(within(totalCard).getByText('2')).toBeTruthy()
    const awaitingCard = screen.getByText(/belum ada catatan · 0 menunggu · 0 ditinjau/)
      .parentElement as HTMLElement
    expect(within(awaitingCard).getByText('1')).toBeTruthy()
    const confirmedCard = screen.getByText('Keputusan manual moderator')
      .parentElement as HTMLElement
    expect(within(confirmedCard).getByText('1')).toBeTruthy()
    const decidedCard = screen.getByText(/belum cukup bukti · 0 ditolak/)
      .parentElement as HTMLElement
    expect(within(decidedCard).getByText('1')).toBeTruthy()

    expect(mocks.loadModerationQueue).toHaveBeenCalledTimes(1)
  })

  it('membuka detail bukti tanpa mengubah status dan memuat audit', async () => {
    const user = userEvent.setup()
    renderPage()
    await screen.findByText('Antrean laporan')

    await selectQueueReport(user)

    expect(await screen.findByText('Alasan yang dilaporkan pengguna')).toBeTruthy()
    const detailCard = screen.getByText('Detail laporan').closest(
      '.rounded-card',
    ) as HTMLElement
    expect(
      within(detailCard).getByText('https://contoh-situs.id/login', { exact: true }),
    ).toBeTruthy()
    expect(screen.getByText(/Formulir meminta kata sandi dan kode OTP/)).toBeTruthy()
    expect(screen.getByText('Catatan internal moderator')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Mulai tinjau' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Tolak laporan' })).toBeTruthy()
    expect(await screen.findByText(/Belum ada tindakan moderasi/)).toBeTruthy()
    expect(mocks.loadModerationHistory).toHaveBeenCalledWith(reportFixture().id)
    expect(mocks.applyModerationDecision).not.toHaveBeenCalled()
  })

  it('meminta konfirmasi lalu menyimpan keputusan dengan catatan dan memuat ulang', async () => {
    const user = userEvent.setup()
    const reviewed = reportFixture({
      moderation: {
        status: 'review',
        note: 'Memeriksa bukti laporan.',
        updatedAt: '2026-10-21T04:00:00.000Z',
        updatedBy: 'admin-uid',
      },
    })
    mocks.loadModerationQueue
      .mockResolvedValueOnce(snapshotFixture([reportFixture()]))
      .mockResolvedValueOnce(snapshotFixture([reviewed]))
    mocks.loadModerationHistory
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([historyFixture()])

    renderPage()
    await screen.findByText('Antrean laporan')
    await selectQueueReport(user)
    await screen.findByText('Alasan yang dilaporkan pengguna')

    await user.click(screen.getByRole('button', { name: 'Mulai tinjau' }))
    expect(
      screen.getByRole('group', { name: 'Konfirmasi tindakan moderasi' }),
    ).toBeTruthy()

    await user.type(
      screen.getByLabelText('Catatan internal (opsional)'),
      'Memeriksa bukti laporan.',
    )
    await user.click(
      screen.getByRole('button', { name: 'Konfirmasi: Mulai tinjau' }),
    )

    await waitFor(() => {
      expect(mocks.applyModerationDecision).toHaveBeenCalledWith({
        reportId: reportFixture().id,
        urlHash: reportFixture().urlHash,
        currentStatus: null,
        nextStatus: 'review',
        note: 'Memeriksa bukti laporan.',
      })
    })
    expect(await screen.findByText('Keputusan moderasi tersimpan')).toBeTruthy()
    expect(mocks.loadModerationQueue).toHaveBeenCalledTimes(2)
    await waitFor(() => {
      expect(mocks.loadModerationHistory).toHaveBeenLastCalledWith(reportFixture().id)
    })
    expect(screen.getByText('Catatan dibuat')).toBeTruthy()
    expect(screen.getAllByText('Sedang ditinjau').length).toBeGreaterThan(0)
  })

  it('tidak menawarkan tindakan untuk status akhir', async () => {
    const user = userEvent.setup()
    mocks.loadModerationQueue.mockResolvedValue(
      snapshotFixture([terminalReportFixture()]),
    )

    renderPage()
    await screen.findByText('Antrean laporan')
    await user.click(
      screen.getByRole('button', { name: /toko-bima\.example\/produk\/123/ }),
    )

    expect(
      await screen.findByText(/Status akhir sudah ditetapkan/),
    ).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Mulai tinjau' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Tolak laporan' })).toBeNull()
    expect(screen.getByText('Halaman menyalin formulir pembayaran resmi.')).toBeTruthy()
  })

  it('menyatakan batas pembacaan secara eksplisit saat data terpotong', async () => {
    mocks.loadModerationQueue.mockResolvedValue(
      snapshotFixture([reportFixture()], { reportsTruncated: true }),
    )

    renderPage()

    expect(await screen.findByText('Antrean dibatasi 500 laporan')).toBeTruthy()
    expect(screen.getByText(/Statistik dan tren hanya menghitung data yang termuat/)).toBeTruthy()
  })

  it('menampilkan kegagalan antrean tanpa mengarang data', async () => {
    const permissionError = Object.assign(new Error('denied'), {
      code: 'permission-denied',
    })
    mocks.loadModerationQueue.mockRejectedValue(permissionError)

    renderPage()

    expect(await screen.findByText('Antrean moderasi gagal dimuat')).toBeTruthy()
    expect(screen.getByText(/Tindakan ditolak oleh sistem penyimpanan/)).toBeTruthy()
    expect(screen.getByText('Akses ditolak')).toBeTruthy()
    expect(screen.getByText('permission-denied')).toBeTruthy()
    expect(screen.queryByText('Laporan termuat')).toBeNull()
  })

  it('menampilkan kode dan tautan indeks untuk kegagalan failed-precondition', async () => {
    const indexUrl =
      'https://console.firebase.google.com/v1/r/project/YOUR_FIREBASE_PROJECT_ID/firestore/indexes?create_exemption=abc123'
    const indexError = Object.assign(
      new Error(
        `The query requires a COLLECTION_GROUP_ASC index for collection reports and field reporterKey. You can create it here: ${indexUrl}`,
      ),
      { code: 'failed-precondition' },
    )
    mocks.loadModerationQueue.mockRejectedValue(indexError)

    renderPage()

    expect(await screen.findByText('Antrean moderasi gagal dimuat')).toBeTruthy()
    expect(screen.getByText('Konfigurasi penyimpanan data')).toBeTruthy()
    expect(screen.getByText('failed-precondition')).toBeTruthy()
    expect(screen.getByText(/COLLECTION_GROUP_ASC/)).toBeTruthy()

    const link = screen.getByRole('link', {
      name: 'Buka panduan perbaikan indeks data',
    })
    expect(link.getAttribute('href')).toBe(indexUrl)
    expect(link.getAttribute('target')).toBe('_blank')
    expect(link.getAttribute('rel')).toBe('noreferrer')
    expect(screen.queryByText('Laporan termuat')).toBeNull()
  })
})

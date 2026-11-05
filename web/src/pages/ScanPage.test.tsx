// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import type { AuthContextValue } from '../lib/auth/context'
import type { ScanDraft } from '../lib/analysis/types'
import type { MultiSourceReport, ScanUrlMultiSourceResponse } from '../lib/scanners/types'

const mocks = vi.hoisted(() => ({
  requestExternalScanStream: vi.fn(),
  saveScanReport: vi.fn(),
  saveScanForUser: vi.fn(),
  isMultiSourceEnabled: vi.fn(),
  isWorkerConfigured: vi.fn(),
  useAuth: vi.fn(),
}))

vi.mock('../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))
vi.mock('../lib/scans/saveScan', () => ({ saveScanForUser: mocks.saveScanForUser }))
vi.mock('../lib/scanners/reportStore', () => ({ saveScanReport: mocks.saveScanReport }))
vi.mock('../lib/scanners/client', () => ({
  isMultiSourceEnabled: mocks.isMultiSourceEnabled,
  isWorkerConfigured: mocks.isWorkerConfigured,
  requestExternalScanStream: mocks.requestExternalScanStream,
}))

import { ScanPage } from './ScanPage'

const firebaseAuth: AuthContextValue = {
  mode: 'firebase',
  status: 'ready',
  user: {
    uid: 'user-1',
    email: 'user@example.com',
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
}

function externalResponse(): ScanUrlMultiSourceResponse {
  const providers = [
    ['urlscan', 'URLScan.io'],
    ['virustotal', 'VirusTotal'],
    ['openphish', 'OpenPhish'],
    ['threatfox', 'ThreatFox (abuse.ch)'],
    ['radar', 'Cloudflare Radar URL Scanner'],
    ['otx', 'AlienVault OTX'],
    ['hybrid', 'Hybrid Analysis'],
    ['safebrowsing', 'Google Safe Browsing'],
  ] as const

  return {
    providers: providers.map(([id, label]) => ({
      id,
      label,
      status: 'success',
      verdict: 'clean',
      score: 0,
      summary: 'Tidak ditemukan indikasi.',
      signals: [],
      reason: null,
      durationMs: 100,
    })),
    sharedWithProviders: [...providers.map(([id]) => id)],
    sensitiveUrl: false,
    privacyReasons: [],
    generatedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 500,
  }
}

function ResultStub() {
  const location = useLocation()
  const state = location.state as { syncNotice?: string | null } | null
  return <p>{`halaman hasil${state?.syncNotice ? `|${state.syncNotice}` : ''}`}</p>
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/periksa?mode=link']}>
      <Routes>
        <Route path="/periksa" element={<ScanPage />} />
        <Route path="/hasil/:id" element={<ResultStub />} />
      </Routes>
    </MemoryRouter>,
  )
}

async function submitLink(value: string) {
  const user = userEvent.setup()
  await user.type(screen.getByLabelText('Tautan yang diperiksa'), value)
  await user.click(screen.getByRole('button', { name: 'Periksa tautan' }))
  await waitFor(() => expect(mocks.saveScanReport).toHaveBeenCalledTimes(1))
  return mocks.saveScanReport.mock.calls[0][1] as MultiSourceReport
}

function holdExternalStream() {
  let seenSignal: AbortSignal | undefined
  mocks.requestExternalScanStream.mockImplementationOnce(
    (
      _url: string,
      _scanId: string,
      options: { signal?: AbortSignal },
    ) =>
      new Promise<ScanUrlMultiSourceResponse>((_resolve, reject) => {
        seenSignal = options.signal
        options.signal?.addEventListener(
          'abort',
          () => reject(new Error('stream dibatalkan')),
          { once: true },
        )
      }),
  )
  return () => seenSignal
}

async function startPendingScan() {
  const user = userEvent.setup()
  await user.type(screen.getByLabelText('Tautan yang diperiksa'), 'https://contoh.com/path')
  await user.click(screen.getByRole('button', { name: 'Periksa tautan' }))
  await waitFor(
    () => expect(mocks.requestExternalScanStream).toHaveBeenCalledTimes(1),
    { timeout: 3000 },
  )
  return user
}

describe('ScanPage alur pemeriksaan eksternal', () => {
  beforeEach(() => {
    localStorage.clear()
    mocks.useAuth.mockReturnValue(firebaseAuth)
    mocks.isMultiSourceEnabled.mockReturnValue(true)
    mocks.isWorkerConfigured.mockReturnValue(true)
    mocks.requestExternalScanStream.mockResolvedValue(externalResponse())
    mocks.saveScanReport.mockReset()
    mocks.saveScanForUser.mockReset()
    mocks.requestExternalScanStream.mockClear()
    mocks.saveScanForUser.mockImplementation(async (draft: ScanDraft) => ({
      scan: {
        ...draft,
        id: 'scan-test',
        createdAt: '2026-01-01T00:00:00.000Z',
      },
      source: 'cloud',
      syncError: null,
    }))
  })

  afterEach(() => {
    cleanup()
  })

  it('otomatis memulai external scan tanpa checkbox consent', async () => {
    renderPage()

    expect(
      screen.queryByRole('checkbox', { name: /provider eksternal/i }),
    ).toBeNull()

    const report = await submitLink('https://contoh.com/path')

    expect(mocks.requestExternalScanStream).toHaveBeenCalledTimes(1)
    expect(mocks.requestExternalScanStream).toHaveBeenCalledWith(
      'https://contoh.com/path',
      expect.any(String),
      expect.objectContaining({ onEvent: expect.any(Function) }),
    )
    expect(report.externalRequested).toBe(true)
    expect(report.externalShared).toBe(true)
    expect(report.externalError).toBeNull()
  })

  it('tetap memindai untuk pengguna tanpa akun (tanpa sesi Firebase)', async () => {
    mocks.useAuth.mockReturnValue({
      ...firebaseAuth,
      mode: 'demo',
      user: null,
    } as AuthContextValue)
    renderPage()

    const report = await submitLink('https://contoh.com/path')

    expect(mocks.requestExternalScanStream).toHaveBeenCalledTimes(1)
    expect(mocks.saveScanForUser.mock.calls[0]?.[2]).toBeNull()
    expect(report.externalRequested).toBe(true)
    expect(report.externalError).toBeNull()
  })

  it('tetap mencatat request saat layanan eksternal gagal', async () => {
    mocks.requestExternalScanStream.mockRejectedValueOnce(new Error('network down'))
    renderPage()

    const report = await submitLink('https://contoh.com/path')

    expect(mocks.requestExternalScanStream).toHaveBeenCalledTimes(1)
    expect(report.externalRequested).toBe(true)
    expect(report.externalShared).toBe(false)
    expect(report.externalError).toBeTruthy()
  })

  it('mempertahankan provider yang sudah selesai saat stream gagal', async () => {
    const completed = externalResponse().providers[0]!
    mocks.requestExternalScanStream.mockImplementationOnce(
      async (_url: string, scanId: string, options: { onEvent?: (event: unknown) => void }) => {
        options.onEvent?.({
          type: 'init',
          scanId,
          startedAt: '2026-01-01T00:00:00.000Z',
          sensitiveUrl: false,
          privacyReasons: [],
          providers: [{ id: 'urlscan', label: 'URLScan.io', state: 'queued' }],
        })
        options.onEvent?.({
          type: 'provider',
          scanId,
          provider: {
            id: 'urlscan',
            label: 'URLScan.io',
            state: 'completed',
            result: completed,
            shared: true,
          },
        })
        throw new Error('stream down')
      },
    )
    renderPage()

    const report = await submitLink('https://contoh.com/path')

    expect(report.externalError).toBeTruthy()
    expect(report.providers.find((provider) => provider.id === 'urlscan')?.status).toBe(
      'success',
    )
    expect(report.externalShared).toBe(true)
  })

  it('menampilkan alasan konfigurasi tanpa memanggil layanan eksternal', async () => {
    mocks.isWorkerConfigured.mockReturnValue(false)
    renderPage()

    const report = await submitLink('https://contoh.com/path')

    expect(mocks.requestExternalScanStream).not.toHaveBeenCalled()
    expect(report.externalRequested).toBe(false)
    expect(report.externalShared).toBe(false)
    expect(report.externalError).toContain('belum tersedia')
  })

  it('tidak mengirim URL sensitif dan menampilkan alasannya', async () => {
    renderPage()

    const report = await submitLink('https://contoh.com/?token=rahasia')

    expect(mocks.requestExternalScanStream).not.toHaveBeenCalled()
    expect(report.externalRequested).toBe(false)
    expect(report.externalShared).toBe(false)
    expect(report.sensitiveUrl).toBe(true)
    expect(report.notes.some((note) => note.includes('data sensitif'))).toBe(true)
  })

  it('pembatalan eksplisit menghentikan stream tanpa menyimpan hasil', async () => {
    const signalOf = holdExternalStream()
    renderPage()
    const user = await startPendingScan()

    await user.click(
      screen.getByRole('button', { name: 'Batalkan pemeriksaan' }),
    )

    expect(signalOf()?.aborted).toBe(true)
    expect(await screen.findByText('Pemeriksaan dihentikan')).toBeTruthy()
    expect(
      screen.getByText(/tidak ada hasil baru yang disimpan/),
    ).toBeTruthy()
    expect(mocks.saveScanForUser).not.toHaveBeenCalled()
    expect(mocks.saveScanReport).not.toHaveBeenCalled()
    expect(screen.queryByText('halaman hasil')).toBeNull()
    expect(screen.getByRole('button', { name: 'Periksa tautan' })).toBeTruthy()
  })

  it('meninggalkan halaman membatalkan stream tanpa menyimpan hasil', async () => {
    const signalOf = holdExternalStream()
    const view = renderPage()
    await startPendingScan()

    view.unmount()

    expect(signalOf()?.aborted).toBe(true)
    await new Promise((resolve) => globalThis.setTimeout(resolve, 0))
    expect(mocks.saveScanForUser).not.toHaveBeenCalled()
    expect(mocks.saveScanReport).not.toHaveBeenCalled()
  })

  // Stream yang mengirim init (semua agen mengantre) lalu ditahan tanpa hasil.
  function holdAfterInit() {
    mocks.requestExternalScanStream.mockImplementationOnce(
      (_url: string, scanId: string, options: { onEvent?: (event: unknown) => void; signal?: AbortSignal }) => {
        options.onEvent?.({
          type: 'init',
          scanId,
          startedAt: '2026-01-01T00:00:00.000Z',
          sensitiveUrl: false,
          privacyReasons: [],
          providers: externalResponse().providers.map((provider) => ({
            id: provider.id,
            label: provider.label,
            state: 'queued',
          })),
        })
        return new Promise<ScanUrlMultiSourceResponse>((_resolve, reject) => {
          options.signal?.addEventListener('abort', () => reject(new Error('stream dibatalkan')), { once: true })
        })
      },
    )
  }

  it('menyiapkan antarmuka loading sebelum agen mana pun memberi hasil', async () => {
    holdAfterInit()
    renderPage()

    await startPendingScan()

    expect(screen.getByText('Memeriksa tautan…')).toBeTruthy()
    expect(screen.getByText('Memeriksa laporan agen keamanan')).toBeTruthy()
    expect(screen.getAllByText('Menunggu giliran.')).toHaveLength(8)
    expect(screen.getByText('0/8 selesai')).toBeTruthy()
    expect(screen.queryByText('Berjalan')).toBeNull()

    await userEvent.setup().click(screen.getByRole('button', { name: 'Batalkan pemeriksaan' }))
  })

  it('menyimpan metadata laporan lama tanpa catatan mekanisme pengambilan hasil', async () => {
    const reused = externalResponse()
    reused.providers = reused.providers.map((provider) =>
      provider.id === 'urlscan'
        ? {
            ...provider,
            summary:
              'Menggunakan laporan URLScan yang sudah ada (dibuat 2 jam lalu). URLScan tidak menemukan indikasi berbahaya.',
            evidence: {
              source: 'existing_report',
              observedAt: '2026-01-01T00:00:00.000Z',
              ageMs: 2 * 60 * 60_000,
            },
          }
        : provider,
    )
    mocks.requestExternalScanStream.mockImplementationOnce(
      async (_url: string, scanId: string, options: { onEvent?: (event: unknown) => void }) => {
        options.onEvent?.({
          type: 'init',
          scanId,
          startedAt: '2026-01-01T00:00:00.000Z',
          sensitiveUrl: false,
          privacyReasons: [],
          providers: reused.providers.map((provider) => ({
            id: provider.id,
            label: provider.label,
            state: 'queued',
          })),
        })
        options.onEvent?.({
          type: 'provider',
          scanId,
          provider: {
            id: 'urlscan',
            label: 'URLScan.io',
            state: 'completed',
            result: reused.providers[0]!,
            shared: true,
          },
        })
        return reused
      },
    )
    renderPage()

    const report = await submitLink('https://contoh.com/path')

    // Laporan yang tersimpan tidak lagi memuat catatan tentang cara hasil diperoleh,
    // tetapi metadata asal bukti tetap akurat agar waktu laporan dapat ditampilkan.
    expect(
      report.notes.some((note) => /laporan yang sudah ada|bukan pemindaian/i.test(note)),
    ).toBe(false)
    expect(report.providers.find((provider) => provider.id === 'urlscan')?.evidence?.source).toBe(
      'existing_report',
    )
    expect(
      report.providers.find((provider) => provider.id === 'urlscan')?.evidence?.observedAt,
    ).toBe('2026-01-01T00:00:00.000Z')
  })

  it('tetap menampilkan loading sampai lantai waktunya walau hasil datang seketika', async () => {
    const user = userEvent.setup()
    renderPage()

    await user.type(screen.getByLabelText('Tautan yang diperiksa'), 'https://contoh.com/path')
    const startedAt = Date.now()
    await user.click(screen.getByRole('button', { name: 'Periksa tautan' }))

    expect(await screen.findByText('halaman hasil', {}, { timeout: 5_000 })).toBeTruthy()
    const report = mocks.saveScanReport.mock.calls[0]![1] as MultiSourceReport

    expect(mocks.requestExternalScanStream).toHaveBeenCalledTimes(1)
    expect(report.externalRequested).toBe(true)
    expect(Date.now() - startedAt).toBeGreaterThanOrEqual(1_200)
  })

  it('tetap membuka hasil dengan peringatan saat riwayat akun gagal ditulis', async () => {
    // VGL-17: kegagalan sinkronisasi tidak boleh menyembunyikan hasil maupun berpura-pura sukses.
    mocks.saveScanForUser.mockImplementationOnce(async (draft: ScanDraft) => ({
      scan: {
        ...draft,
        id: 'scan-tertahan',
        createdAt: '2026-01-01T00:00:00.000Z',
      },
      source: 'local',
      syncError: 'Riwayat akun tidak dapat dihubungi. Hasil tetap tersimpan di perangkat ini.',
    }))
    renderPage()

    await submitLink('https://contoh.com/path')

    const notice = await screen.findByText(/^halaman hasil\|/, {}, { timeout: 5_000 })
    expect(notice.textContent).toContain('Hasil tetap tersimpan di perangkat ini')
    expect(mocks.saveScanReport).toHaveBeenCalledTimes(1)
  })

  it('menampilkan batas pemeriksaan sesuai copy terbaru', () => {
    renderPage()
    const text = document.body.textContent ?? ''

    expect(text).toContain(
      'VERIGUARD menganalisis tautan berdasarkan indikator keamanan dan reputasi digital.',
    )
    expect(text).toContain(
      'Pemeriksaan didukung oleh agen eksternal untuk mengenali potensi ancaman.',
    )
    expect(text).toContain(
      'Privasi URL dan pesan pengguna tetap menjadi perhatian dalam proses pemeriksaan.',
    )
    expect(text).toContain(
      'Sistem menggunakan aturan keamanan dan indikator heuristik untuk mendeteksi aktivitas mencurigakan.',
    )
    expect(text).toContain(
      'Hasil pemeriksaan menunjukkan tingkat risiko sebagai bahan pertimbangan sebelum mengakses tautan.',
    )
    expect(text).toContain('Informasi Pemeriksaan')
  })
})

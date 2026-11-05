// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import type { AuthContextValue } from '../lib/auth/context'
import type { ScanDraft } from '../lib/analysis/types'
import type { ScanUrlMultiSourceResponse } from '../lib/scanners/types'
import { ExternalScanRequestError } from '../lib/scanners/errors'

const mocks = vi.hoisted(() => ({
  requestExternalScanStream: vi.fn(),
  saveScanReport: vi.fn(),
  saveScanForUser: vi.fn(),
  isMultiSourceEnabled: vi.fn(),
  isWorkerConfigured: vi.fn(),
  useAuth: vi.fn(),
  solve: vi.fn(),
}))

const widget = vi.hoisted(() => ({ onToken: null as null | ((token: string) => void) }))

vi.mock('../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))
vi.mock('../lib/scans/saveScan', () => ({ saveScanForUser: mocks.saveScanForUser }))
vi.mock('../lib/scanners/reportStore', () => ({ saveScanReport: mocks.saveScanReport }))
vi.mock('../lib/scanners/client', () => ({
  isMultiSourceEnabled: mocks.isMultiSourceEnabled,
  isWorkerConfigured: mocks.isWorkerConfigured,
  requestExternalScanStream: mocks.requestExternalScanStream,
}))
vi.mock('../components/turnstile/Turnstile', () => ({
  Turnstile: ({
    action,
    onToken,
  }: {
    action: string
    onToken: (token: string) => void
  }) => {
    widget.onToken = onToken
    return (
      <div data-testid={`turnstile-${action}`}>
        <button type="button" onClick={() => mocks.solve(onToken)}>
          Selesaikan CAPTCHA uji
        </button>
      </div>
    )
  },
}))

import { ScanPage } from './ScanPage'

const auth: AuthContextValue = {
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
  return {
    providers: [
      {
        id: 'virustotal',
        label: 'VirusTotal',
        status: 'success',
        verdict: 'clean',
        score: 0,
        summary: 'Tidak ditemukan indikasi.',
        signals: [],
        reason: null,
        durationMs: 100,
      },
    ],
    sharedWithProviders: ['virustotal'],
    sensitiveUrl: false,
    privacyReasons: [],
    generatedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 500,
  }
}

function captchaError(code = 'captcha_required'): ExternalScanRequestError {
  return new ExternalScanRequestError(
    code,
    'Layanan meminta verifikasi bahwa Anda bukan robot sebelum melanjutkan.',
  )
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/periksa?mode=link']}>
      <Routes>
        <Route path="/periksa" element={<ScanPage />} />
        <Route path="/hasil/:id" element={<p>halaman hasil</p>} />
      </Routes>
    </MemoryRouter>,
  )
}

function callArgs(index: number): { url: string; scanId: string; captchaToken?: string | null } {
  const call = mocks.requestExternalScanStream.mock.calls[index] as
    | [string, string, { captchaToken?: string | null }]
    | undefined
  if (!call) throw new Error('Permintaan pemeriksaan tidak ditemukan.')
  return { url: call[0], scanId: call[1], captchaToken: call[2]?.captchaToken ?? null }
}

async function startScan(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText('Tautan yang diperiksa'), 'https://contoh.com/path')
  await user.click(screen.getByRole('button', { name: 'Periksa tautan' }))
  await waitFor(() => expect(mocks.requestExternalScanStream).toHaveBeenCalledTimes(1), {
    timeout: 4000,
  })
}

beforeEach(() => {
  localStorage.clear()
  widget.onToken = null
  mocks.solve.mockReset().mockImplementation((onToken: (token: string) => void) =>
    onToken('token-pemeriksaan'),
  )
  mocks.useAuth.mockReturnValue(auth)
  mocks.isMultiSourceEnabled.mockReturnValue(true)
  mocks.isWorkerConfigured.mockReturnValue(true)
  mocks.requestExternalScanStream.mockReset().mockResolvedValue(externalResponse())
  mocks.saveScanReport.mockReset()
  mocks.saveScanForUser.mockReset().mockImplementation(async (draft: ScanDraft) => ({
    scan: { ...draft, id: 'scan-test', createdAt: '2026-01-01T00:00:00.000Z' },
    source: 'cloud',
  }))
})

afterEach(() => {
  cleanup()
})

describe('CAPTCHA adaptif pada halaman pemeriksaan', () => {
  it('pemeriksaan biasa tidak menampilkan CAPTCHA dan tidak mengirim token', async () => {
    const user = userEvent.setup()
    renderPage()

    await startScan(user)

    expect(screen.queryByText('Verifikasi diperlukan untuk melanjutkan')).toBeNull()
    expect(callArgs(0).captchaToken).toBeNull()
    await waitFor(() => expect(screen.getByText('halaman hasil')).toBeTruthy(), {
      timeout: 4000,
    })
  })

  it('menampilkan kartu verifikasi hanya ketika layanan memintanya', async () => {
    mocks.requestExternalScanStream.mockRejectedValueOnce(captchaError())
    const user = userEvent.setup()
    renderPage()

    await startScan(user)

    expect(await screen.findByText('Verifikasi diperlukan untuk melanjutkan')).toBeTruthy()
    expect(screen.getByTestId('turnstile-scan')).toBeTruthy()
    // Tidak ada hasil palsu: pemeriksaan belum berjalan, jadi tidak ada yang disimpan.
    expect(mocks.saveScanForUser).not.toHaveBeenCalled()
    expect(screen.queryByText('halaman hasil')).toBeNull()
  })

  it('mengulang pemeriksaan asli dengan scanId yang sama setelah token diverifikasi', async () => {
    mocks.requestExternalScanStream.mockRejectedValueOnce(captchaError())
    const user = userEvent.setup()
    renderPage()

    await startScan(user)
    await screen.findByText('Verifikasi diperlukan untuk melanjutkan')

    await user.click(screen.getByRole('button', { name: 'Selesaikan CAPTCHA uji' }))
    await user.click(screen.getByRole('button', { name: 'Lanjutkan pemeriksaan' }))

    await waitFor(() => expect(mocks.requestExternalScanStream).toHaveBeenCalledTimes(2), {
      timeout: 4000,
    })
    expect(callArgs(1)).toEqual({
      url: 'https://contoh.com/path',
      scanId: callArgs(0).scanId,
      captchaToken: 'token-pemeriksaan',
    })
    await waitFor(() => expect(screen.getByText('halaman hasil')).toBeTruthy(), {
      timeout: 4000,
    })
  })

  it('tidak mengulang otomatis dan tidak menyisipkan hasil ketika verifikasi ditolak', async () => {
    mocks.requestExternalScanStream.mockRejectedValueOnce(captchaError())
    mocks.requestExternalScanStream.mockRejectedValueOnce(captchaError('captcha_invalid'))
    const user = userEvent.setup()
    renderPage()

    await startScan(user)
    await screen.findByText('Verifikasi diperlukan untuk melanjutkan')

    await user.click(screen.getByRole('button', { name: 'Selesaikan CAPTCHA uji' }))
    await user.click(screen.getByRole('button', { name: 'Lanjutkan pemeriksaan' }))

    await waitFor(() => expect(mocks.requestExternalScanStream).toHaveBeenCalledTimes(2), {
      timeout: 4000,
    })
    expect(await screen.findByText('Verifikasi diperlukan untuk melanjutkan')).toBeTruthy()

    // Tidak ada permintaan ketiga: tantangan berikutnya menunggu interaksi pengguna baru,
    // sehingga tidak ada lingkaran CAPTCHA otomatis.
    await new Promise((resolve) => setTimeout(resolve, 250))
    expect(mocks.requestExternalScanStream).toHaveBeenCalledTimes(2)
    expect(mocks.saveScanForUser).not.toHaveBeenCalled()
    expect(screen.queryByText('halaman hasil')).toBeNull()
  })

  it('menutup tantangan tanpa menjalankan pemeriksaan bila dibatalkan', async () => {
    mocks.requestExternalScanStream.mockRejectedValueOnce(captchaError())
    const user = userEvent.setup()
    renderPage()

    await startScan(user)
    await screen.findByText('Verifikasi diperlukan untuk melanjutkan')

    await user.click(screen.getByRole('button', { name: 'Batalkan' }))

    expect(screen.queryByText('Verifikasi diperlukan untuk melanjutkan')).toBeNull()
    await new Promise((resolve) => setTimeout(resolve, 250))
    expect(mocks.requestExternalScanStream).toHaveBeenCalledTimes(1)
    expect(mocks.saveScanForUser).not.toHaveBeenCalled()
  })

  it('meminta verifikasi baru ketika isi_url diubah setelah tantangan muncul', async () => {
    mocks.requestExternalScanStream.mockRejectedValueOnce(captchaError())
    const user = userEvent.setup()
    renderPage()

    await startScan(user)
    await screen.findByText('Verifikasi diperlukan untuk melanjutkan')

    await user.type(screen.getByLabelText('Tautan yang diperiksa'), '/lain')
    expect(screen.queryByText('Verifikasi diperlukan untuk melanjutkan')).toBeNull()

    await user.click(screen.getByRole('button', { name: 'Periksa tautan' }))
    await waitFor(() => expect(mocks.requestExternalScanStream).toHaveBeenCalledTimes(2), {
      timeout: 4000,
    })
    // Tantangan lama tidak dipakai untuk URL baru.
    expect(callArgs(1)).toMatchObject({ url: 'https://contoh.com/path/lain' })
    expect(callArgs(1).captchaToken).toBeNull()
    expect(callArgs(1).scanId).not.toBe(callArgs(0).scanId)
  })
})

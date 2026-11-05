// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import type { ScanResult } from '../lib/analysis'
import type { AuthContextValue } from '../lib/auth/context'
import type { RiskFusion, SiteAnalysisResponse } from '../lib/website/types'
import { EXTERNAL_PROVIDER_IDS } from '../lib/scanners/types'

const mocks = vi.hoisted(() => ({
  useAuth: vi.fn(),
  useScan: vi.fn(),
  useSiteAnalysis: vi.fn(),
  useCommunityContext: vi.fn(),
  getScanReport: vi.fn(),
}))

vi.mock('../lib/auth/useAuth', () => ({ useAuth: mocks.useAuth }))
vi.mock('../lib/scans/useScan', () => ({ useScan: mocks.useScan }))
vi.mock('../lib/website/useSiteAnalysis', () => ({ useSiteAnalysis: mocks.useSiteAnalysis }))
vi.mock('../lib/community/useCommunityContext', () => ({
  useCommunityContext: mocks.useCommunityContext,
}))
vi.mock('../lib/scanners/reportStore', () => ({ getScanReport: mocks.getScanReport }))

import { ResultPage } from './ResultPage'

function authFixture(): AuthContextValue {
  return {
    mode: 'firebase',
    status: 'ready',
    user: {
      uid: 'user-a',
      email: 'user-a@example.com',
      displayName: 'Pengguna A',
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

function scanFixture(): ScanResult {
  return {
    id: 'scan-1',
    mode: 'link',
    input: 'https://contoh.com/masuk',
    displayTarget: 'contoh.com/masuk',
    riskScore: 65,
    riskLevel: 'high',
    headline: 'Indikasi phishing',
    summary: 'Tautan menyerupai halaman login bank.',
    reasons: [
      {
        id: 'lookalike-domain',
        label: 'Domain mirip',
        detail: 'contoh.com menyerupai domain bank',
        severity: 'danger',
        weight: 40,
        category: 'domain',
      },
    ],
    patterns: [],
    recommendations: ['Verifikasi melalui kanal resmi.'],
    technical: [],
    meta: {
      engineVersion: 'test',
      signalCount: 1,
      inputLength: 24,
      aiStatus: 'not_used',
      inputStored: 'full',
    },
    createdAt: '2026-10-20T02:00:00.000Z',
  }
}

function renderPage(state?: unknown) {
  return render(
    <MemoryRouter
      initialEntries={[{ pathname: '/hasil/scan-1', search: '', state: state as never }]}
    >
      <Routes>
        <Route path="/hasil/:id" element={<ResultPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  mocks.useAuth.mockReturnValue(authFixture())
  mocks.useScan.mockReturnValue({
    scan: scanFixture(),
    loading: false,
    error: null,
    source: 'cloud',
    retry: vi.fn(async () => undefined),
  })
  mocks.useSiteAnalysis.mockReturnValue({
    state: 'idle',
    data: null,
    error: null,
    available: false,
    autoRun: false,
    run: vi.fn(async () => undefined),
    reset: vi.fn(),
  })
  mocks.useCommunityContext.mockReturnValue({
    status: 'idle',
    normalizedUrl: null,
    context: null,
    error: null,
    refresh: vi.fn(async () => undefined),
  })
  mocks.getScanReport.mockReturnValue(null)
})

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

describe('Hasil dengan riwayat yang tertahan', () => {
  it('menampilkan peringatan sinkronisasi tanpa menghilangkan isi hasil', () => {
    renderPage({
      syncNotice: 'Riwayat akun tidak dapat dihubungi. Hasil tetap tersimpan di perangkat ini.',
    })

    expect(screen.getByText(/Hasil tersimpan di perangkat ini/)).toBeTruthy()
    expect(
      screen.getByText(/Riwayat akun tidak dapat dihubungi/),
    ).toBeTruthy()
    expect(screen.getByText('Indikasi phishing')).toBeTruthy()
    expect(screen.getByText('Tautan menyerupai halaman login bank.')).toBeTruthy()
  })

  it('tidak menampilkan peringatan untuk hasil yang benar-benar tersimpan di akun', () => {
    renderPage({ multiSourceReport: null })

    expect(screen.queryByText(/Hasil tersimpan di perangkat ini/)).toBeNull()
  })

  it('mengabaikan status sinkronisasi yang bukan teks', () => {
    renderPage({ syncNotice: 42 })

    expect(screen.queryByText(/Hasil tersimpan di perangkat ini/)).toBeNull()
  })

  it('tidak menampilkan peringatan saat hasil dibuka ulang dari riwayat', () => {
    renderPage()

    expect(screen.queryByText(/Hasil tersimpan di perangkat ini/)).toBeNull()
    expect(screen.getByText('Indikasi phishing')).toBeTruthy()
  })
})

describe('Nilai analisis internal di blok Internal Reputasi Ancaman', () => {
  function riskFixture(overrides: Partial<RiskFusion> = {}): RiskFusion {
    return {
      status: 'limited',
      level: 'low',
      riskScore: 9,
      confidence: 'low',
      confidenceDetail: '1 bukti risiko dari 1 kategori berbeda, cakupan pemeriksaan 3/17.',
      coverage: {
        totalChecks: 17,
        succeeded: 3,
        unavailable: 12,
        failed: 2,
        ratio: 0.18,
        byCategory: [],
      },
      evidence: [],
      notEvaluated: ['Sertifikat TLS tidak terbaca dari runtime ini.'],
      notes: [],
      ...overrides,
    }
  }

  function mockAnalysis(risk: RiskFusion | null): void {
    mocks.useSiteAnalysis.mockReturnValue({
      state: 'ready',
      data: {
        version: 1,
        target: 'https://contoh.com/masuk',
        hostname: 'contoh.com',
        generatedAt: '2026-10-20T02:00:00.000Z',
        durationMs: 900,
        probe: { available: true, name: 'node-dns-tls-http', detail: null },
        risk,
      } as unknown as SiteAnalysisResponse,
      error: null,
      available: true,
      autoRun: false,
      run: vi.fn(async () => undefined),
      reset: vi.fn(),
    })
  }

  it('menampilkan Skor Analisis Situs di dalam blok Internal, satu kali saja', () => {
    mockAnalysis(riskFixture())

    renderPage()

    // Blok Internal yang sudah ada (heuristik leksikal) dan nilai analisis situs tampil berdekatan.
    expect(screen.getByText('Indikasi internal · heuristik leksikal')).toBeTruthy()
    expect(screen.getAllByText('Skor Analisis Situs')).toHaveLength(1)
    expect(screen.getByText('Skor fusi')).toBeTruthy()
    expect(
      screen.getByRole('img', { name: 'Skor fusi analisis situs 9 dari 100' }),
    ).toBeTruthy()
    expect(screen.getByText('Tingkat risiko: Rendah')).toBeTruthy()
    // Sumber angka tetap dinyatakan terpisah: tidak ada penggabungan skor.
    expect(document.body.textContent).toContain(
      `terpisah dari skor heuristik leksikal maupun vonis ${EXTERNAL_PROVIDER_IDS.length} agen`,
    )
    // Menu tetap ada dan tidak di-render ulang: panel bagian situs hanya tampil saat dipilih.
    expect(screen.getByRole('button', { name: 'Website Intelligence' })).toBeTruthy()
    expect(screen.queryByText('Network Identity')).toBeNull()
  })

  it('tidak mengarang nilai analisis situs ketika belum ada hasilnya', () => {
    mockAnalysis(null)

    renderPage()

    expect(screen.getAllByText('Skor Analisis Situs')).toHaveLength(1)
    expect(screen.getByText('Belum dinilai')).toBeTruthy()
    expect(screen.getByRole('img', { name: 'Skor heuristik leksikal 65 dari 100' })).toBeTruthy()
  })

  it('tidak menampilkan kartu internal saat analisis situs belum berjalan', () => {
    mocks.useSiteAnalysis.mockReturnValue({
      state: 'idle',
      data: null,
      error: null,
      available: true,
      autoRun: false,
      run: vi.fn(async () => undefined),
      reset: vi.fn(),
    })

    renderPage()

    expect(screen.queryByText('Skor Analisis Situs')).toBeNull()
    expect(screen.getByText('Indikasi internal · heuristik leksikal')).toBeTruthy()
  })
})

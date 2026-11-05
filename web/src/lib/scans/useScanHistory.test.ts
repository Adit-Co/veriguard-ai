// @vitest-environment jsdom

import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ScanDraft, ScanResult } from '../analysis/types'
import type { AppUser, AuthContextValue } from '../auth/context'
import { clearScans, listScans } from '../storage/scanStore'

const mocks = vi.hoisted(() => ({
  useAuth: vi.fn(),
  listCloudScans: vi.fn(),
  getCloudScan: vi.fn(),
  deleteCloudScan: vi.fn(),
  clearCloudScans: vi.fn(),
  redactCloudMessageContents: vi.fn(),
  saveCloudScan: vi.fn(),
  pruneCloudScans: vi.fn(async () => 0),
}))

vi.mock('../auth/useAuth', () => ({ useAuth: mocks.useAuth }))
vi.mock('../firebase/scans', () => ({
  clearCloudScans: mocks.clearCloudScans,
  deleteCloudScan: mocks.deleteCloudScan,
  getCloudScan: mocks.getCloudScan,
  listCloudScans: mocks.listCloudScans,
  pruneCloudScans: mocks.pruneCloudScans,
  redactCloudMessageContents: mocks.redactCloudMessageContents,
  saveCloudScan: mocks.saveCloudScan,
}))

import { resetLocalHistoryMergePasses } from './localHistoryMigration'
import { clearPendingSync, pendingScanIds } from './pendingSyncStore'
import { useScanHistory } from './useScanHistory'
import { useScan } from './useScan'
import { saveScanForUser } from './saveScan'

function account(overrides: Partial<AppUser> = {}): AppUser {
  return {
    uid: 'user-a',
    email: 'user-a@example.com',
    displayName: 'Pengguna A',
    emailVerified: true,
    isAnonymous: false,
    startedAt: null,
    ...overrides,
  }
}

function authFixture(user: AppUser | null): AuthContextValue {
  return {
    mode: 'firebase',
    status: user ? 'ready' : 'loading',
    user,
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

function scanFixture(id: string): ScanResult {
  return {
    id,
    mode: 'link',
    input: `https://contoh.com/${id}`,
    displayTarget: `contoh.com/${id}`,
    riskScore: 20,
    riskLevel: 'low',
    headline: 'Risiko rendah',
    summary: 'Tidak ada indikator kuat.',
    reasons: [],
    patterns: [],
    recommendations: [],
    technical: [],
    meta: { engineVersion: 'test', signalCount: 0, inputLength: 20, aiStatus: 'not_used' },
    createdAt: '2026-10-20T02:00:00.000Z',
  }
}

function draftFixture(id: string): ScanDraft {
  return {
    mode: 'link',
    input: `https://contoh.com/perangkat/${id}`,
    displayTarget: `contoh.com/perangkat/${id}`,
    riskScore: 20,
    riskLevel: 'low',
    headline: 'Risiko rendah',
    summary: 'Tidak ada indikator kuat.',
    reasons: [],
    patterns: [],
    recommendations: [],
    technical: [],
    meta: { engineVersion: 'test', signalCount: 0, inputLength: 20, aiStatus: 'not_used' },
  }
}

beforeEach(() => {
  clearScans()
  clearPendingSync()
  resetLocalHistoryMergePasses()
  mocks.saveCloudScan.mockReset()
  mocks.saveCloudScan.mockResolvedValue(undefined)
  mocks.pruneCloudScans.mockClear()
})

afterEach(() => {
  clearScans()
  clearPendingSync()
  resetLocalHistoryMergePasses()
  vi.clearAllMocks()
})

describe('riwayat pemeriksaan dan verifikasi email', () => {
  it('membaca Firestore untuk akun yang emailnya terkonfirmasi', async () => {
    mocks.listCloudScans.mockResolvedValue([scanFixture('cloud-1')])
    mocks.useAuth.mockReturnValue(authFixture(account()))

    const { result } = renderHook(() => useScanHistory())
    await waitFor(() => expect(result.current.loading).toBe(false))

    expect(result.current.source).toBe('cloud')
    expect(mocks.listCloudScans).toHaveBeenCalledWith('user-a')
  })

  it('tidak membaca data cloud untuk akun yang belum verifikasi email', async () => {
    mocks.useAuth.mockReturnValue(authFixture(account({ emailVerified: false })))

    const { result } = renderHook(() => useScanHistory())
    await waitFor(() => expect(result.current.loading).toBe(false))

    expect(result.current.source).toBe('local')
    expect(mocks.listCloudScans).not.toHaveBeenCalled()
    expect(result.current.scans).toEqual([])
  })

  it('tidak membaca data cloud untuk sesi anonim dan belum masuk', async () => {
    mocks.useAuth.mockReturnValue(
      authFixture(account({ uid: 'guest-1', email: null, isAnonymous: true })),
    )

    const { result } = renderHook(() => useScanHistory())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.source).toBe('local')
    expect(mocks.listCloudScans).not.toHaveBeenCalled()
  })

  it('membaca hasil lokal untuk akun yang belum verifikasi email', async () => {
    mocks.useAuth.mockReturnValue(authFixture(account({ emailVerified: false })))

    const { result } = renderHook(() => useScan('cloud-1'))
    await waitFor(() => expect(result.current.loading).toBe(false))

    expect(mocks.getCloudScan).not.toHaveBeenCalled()
    expect(result.current.scan).toBeNull()
  })

  it('menghapus lewat localStorage, bukan Firestore, saat akun belum terkonfirmasi', async () => {
    mocks.useAuth.mockReturnValue(authFixture(account({ emailVerified: false })))

    const { result } = renderHook(() => useScanHistory())
    await waitFor(() => expect(result.current.loading).toBe(false))

    await result.current.remove('scan-x')
    expect(mocks.deleteCloudScan).not.toHaveBeenCalled()
  })
})

describe('pemulihan hasil saat Firestore bermasalah atau akun berpindah sumber', () => {
  function draftFixture(id: string): ScanDraft {
    const input = `https://contoh.com/${id}`
    return {
      mode: 'link',
      input,
      displayTarget: input,
      riskScore: 20,
      riskLevel: 'low',
      headline: 'Risiko rendah',
      summary: 'Tidak ada indikator kuat.',
      reasons: [],
      patterns: [],
      recommendations: [],
      technical: [],
      meta: { engineVersion: 'test', signalCount: 0, inputLength: input.length, aiStatus: 'not_used' },
    }
  }

  it('kegagalan baca riwayat tampil sebagai error dan bisa diulang', async () => {
    mocks.useAuth.mockReturnValue(authFixture(account()))
    const berhasil = scanFixture('cloud-9')
    let gagal = true
    mocks.getCloudScan.mockReset().mockImplementation(async () => {
      if (gagal) {
        throw { code: 'permission-denied', message: 'Missing or insufficient permissions.' }
      }
      return berhasil
    })

    const { result } = renderHook(() => useScan('cloud-9'))
    await waitFor(() => expect(result.current.loading).toBe(false))

    expect(result.current.scan).toBeNull()
    expect(result.current.error).toMatch(/tidak diizinkan/i)

    gagal = false
    await act(async () => {
      await result.current.retry()
    })

    await waitFor(() => expect(result.current.scan?.id).toBe('cloud-9'))
    expect(result.current.error).toBeNull()
  })

  it('akun terverifikasi tidak pernah jatuh ke riwayat lokal perangkat', async () => {
    mocks.useAuth.mockReturnValue(authFixture(account()))
    mocks.getCloudScan.mockReset().mockResolvedValue(null)
    const local = await saveScanForUser(draftFixture('lokal-cuma-di-perangkat'), {}, null)

    const { result } = renderHook(() => useScan(local.scan.id))
    await waitFor(() => expect(result.current.loading).toBe(false))

    expect(mocks.getCloudScan).toHaveBeenCalledWith('user-a', local.scan.id)
    expect(result.current.scan).toBeNull()
  })

  it('hasil pemeriksaan tamu tetap terbaca setelah penyimpanan dibaca ulang', async () => {
    mocks.useAuth.mockReturnValue(authFixture(account({ emailVerified: false })))
    const { scan } = await saveScanForUser(
      { ...draftFixture('terkunci'), input: 'https://contoh.com/masuk?token=abcdef1234567890' },
      {},
      null,
    )

    const { result } = renderHook(() => useScan(scan.id))
    await waitFor(() => expect(result.current.loading).toBe(false))

    expect(mocks.getCloudScan).not.toHaveBeenCalled()
    expect(result.current.scan?.input).toBe('https://contoh.com/masuk')
    expect(window.localStorage.getItem('veriguard.scans.v1')).not.toContain('abcdef1234567890')
  })
})

describe('riwayat perangkat bergabung ke akun dan penghapusan yang tuntas', () => {
  async function seedGuestScan(id: string) {
    const saved = await saveScanForUser(draftFixture(id), {}, null)
    return saved.scan
  }

  it('mengirim riwayat tamu ke akun sebelum daftar riwayat dibaca', async () => {
    const guest = await seedGuestScan('tamu')
    mocks.useAuth.mockReturnValue(authFixture(account()))
    mocks.listCloudScans.mockResolvedValue([])

    const { result } = renderHook(() => useScanHistory())
    await waitFor(() => expect(result.current.loading).toBe(false))

    expect(mocks.saveCloudScan).toHaveBeenCalledWith('user-a', expect.objectContaining({ id: guest.id }))
    expect(listScans()).toHaveLength(0)
    expect(result.current.pendingLocalCount).toBe(0)
    expect(result.current.syncMessage).toBeNull()
  })

  it('melaporkan riwayat yang tertahan dan bisa dikirim ulang', async () => {
    await seedGuestScan('tertahan')
    mocks.useAuth.mockReturnValue(authFixture(account()))
    mocks.listCloudScans.mockResolvedValue([scanFixture('cloud-1')])
    mocks.saveCloudScan.mockRejectedValue({
      code: 'unavailable',
      message: 'Backend is currently unavailable.',
    })

    const { result } = renderHook(() => useScanHistory())
    await waitFor(() => expect(result.current.loading).toBe(false))

    expect(result.current.scans.map((scan) => scan.id)).toEqual(['cloud-1'])
    expect(result.current.pendingLocalCount).toBe(1)
    expect(result.current.syncMessage).toMatch(/tidak dapat dihubungi/i)

    mocks.saveCloudScan.mockResolvedValue(undefined)
    let outcome: { uploaded: number; failed: number } = { uploaded: 0, failed: 1 }
    await act(async () => {
      outcome = await result.current.syncLocalHistory()
    })

    expect(outcome).toMatchObject({ uploaded: 1, failed: 0 })
    await waitFor(() => expect(result.current.pendingLocalCount).toBe(0))
    expect(listScans()).toHaveLength(0)
  })

  it('akun terverifikasi tidak melewatkan kegagalan sinkronisasi sebagai sukses', async () => {
    await seedGuestScan('gagal')
    mocks.useAuth.mockReturnValue(authFixture(account()))
    mocks.listCloudScans.mockResolvedValue([])
    mocks.saveCloudScan.mockRejectedValue({ code: 'permission-denied', message: 'denied' })

    const { result } = renderHook(() => useScanHistory())
    await waitFor(() => expect(result.current.loading).toBe(false))

    expect(result.current.error).toBeNull()
    expect(result.current.pendingLocalCount).toBe(1)
    expect(result.current.syncMessage).toMatch(/tidak diizinkan/i)
  })

  it('hapus seluruh riwayat membersihkan salinan perangkat juga untuk akun terverifikasi', async () => {
    await seedGuestScan('perangkat')
    mocks.useAuth.mockReturnValue(authFixture(account()))
    mocks.listCloudScans.mockResolvedValue([scanFixture('cloud-1')])
    mocks.clearCloudScans.mockResolvedValue(undefined)

    const { result } = renderHook(() => useScanHistory())
    await waitFor(() => expect(result.current.loading).toBe(false))

    await act(async () => {
      await result.current.clear()
    })

    expect(mocks.clearCloudScans).toHaveBeenCalledWith('user-a')
    expect(listScans()).toHaveLength(0)
    expect(pendingScanIds('user-a')).toEqual([])
    expect(result.current.scans).toEqual([])
  })

  it('penghapusan lokal tetap berjalan saat penghapusan akun gagal', async () => {
    await seedGuestScan('perangkat2')
    mocks.useAuth.mockReturnValue(authFixture(account()))
    mocks.listCloudScans.mockResolvedValue([scanFixture('cloud-1')])
    mocks.clearCloudScans.mockRejectedValue({ code: 'unavailable', message: 'offline' })

    const { result } = renderHook(() => useScanHistory())
    await waitFor(() => expect(result.current.loading).toBe(false))

    let thrown: unknown = null
    await act(async () => {
      try {
        await result.current.clear()
      } catch (error) {
        thrown = error
      }
    })

    expect(thrown).toBeTruthy()
    expect(listScans()).toHaveLength(0)
  })

  it('riwayat yang dihapus pengguna tidak dikirim ke akun pada percobaan berikutnya', async () => {
    const queued = await seedGuestScan('diantre')
    mocks.useAuth.mockReturnValue(authFixture(account()))
    mocks.listCloudScans.mockResolvedValue([])
    mocks.deleteCloudScan.mockResolvedValue(undefined)
    mocks.saveCloudScan.mockRejectedValue({ code: 'unavailable', message: 'offline' })

    const { result } = renderHook(() => useScanHistory())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.pendingLocalCount).toBe(1)

    await act(async () => {
      await result.current.remove(queued.id)
    })

    expect(mocks.deleteCloudScan).toHaveBeenCalledWith('user-a', queued.id)
    expect(listScans()).toHaveLength(0)
    expect(pendingScanIds('user-a')).toEqual([])

    mocks.saveCloudScan.mockClear().mockResolvedValue(undefined)
    await act(async () => {
      await result.current.syncLocalHistory()
    })

    expect(mocks.saveCloudScan).not.toHaveBeenCalled()
    expect(result.current.pendingLocalCount).toBe(0)
  })

  it('hasil yang belum tersinkronisasi tetap dapat dibuka dari halaman hasil', async () => {
    mocks.useAuth.mockReturnValue(authFixture(account()))
    mocks.getCloudScan.mockReset().mockResolvedValue(null)
    mocks.saveCloudScan.mockRejectedValue({ code: 'unavailable', message: 'offline' })

    const { scan } = await saveScanForUser(draftFixture('belum-sinkron'), {}, 'user-a')

    const { result } = renderHook(() => useScan(scan.id))
    await waitFor(() => expect(result.current.loading).toBe(false))

    expect(result.current.scan?.id).toBe(scan.id)
    expect(result.current.error).toBeNull()
  })

  it('riwayat lokal sesi yang belum terverifikasi tidak ikut terkirim', async () => {
    await seedGuestScan('belum-verif')
    mocks.useAuth.mockReturnValue(authFixture(account({ emailVerified: false })))

    const { result } = renderHook(() => useScanHistory())
    await waitFor(() => expect(result.current.loading).toBe(false))

    expect(result.current.source).toBe('local')
    expect(mocks.saveCloudScan).not.toHaveBeenCalled()
    expect(listScans()).toHaveLength(1)
    expect(result.current.pendingLocalCount).toBe(0)
  })
})

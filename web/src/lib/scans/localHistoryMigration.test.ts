import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ScanDraft } from '../analysis/types'
import { clearScans, listScans, saveScan } from '../storage/scanStore'

const cloud = vi.hoisted(() => ({
  saveCloudScan: vi.fn(),
  pruneCloudScans: vi.fn(async () => 0),
}))

vi.mock('../firebase/scans', () => ({
  saveCloudScan: cloud.saveCloudScan,
  pruneCloudScans: cloud.pruneCloudScans,
}))

import {
  mergeLocalScansIntoAccount,
  resetLocalHistoryMergePasses,
  retryMergeLocalScans,
} from './localHistoryMigration'
import { clearPendingSync, pendingScanIds, rememberPendingScan } from './pendingSyncStore'

function draft(input: string): ScanDraft {
  return {
    mode: 'link',
    input,
    displayTarget: input,
    riskScore: 10,
    riskLevel: 'low',
    headline: 'Indikasi risiko rendah',
    summary: 'Tidak banyak indikator risiko ditemukan.',
    reasons: [],
    patterns: [],
    recommendations: [],
    technical: [],
    meta: {
      engineVersion: 'test',
      signalCount: 0,
      inputLength: input.length,
      aiStatus: 'not_used',
    },
  }
}

function failure(code: string) {
  return Object.assign(new Error('firestore unavailable'), { code })
}

describe('penggabungan riwayat perangkat ke akun', () => {
  beforeEach(() => {
    clearScans()
    clearPendingSync()
    resetLocalHistoryMergePasses()
    vi.clearAllMocks()
    cloud.saveCloudScan.mockResolvedValue(undefined)
  })

  it('mengirim seluruh riwayat tamu ke akun dengan id yang sama lalu melepas salinan perangkat', async () => {
    const first = saveScan(draft('https://contoh.com/satu'))
    const second = saveScan(draft('https://contoh.com/dua'))

    const result = await mergeLocalScansIntoAccount('user-a')

    expect(result).toMatchObject({ uploaded: 2, failed: 0, message: null })
    expect(cloud.saveCloudScan.mock.calls.map(([uid]) => uid)).toEqual(['user-a', 'user-a'])
    expect(cloud.saveCloudScan.mock.calls.map(([, scan]) => scan.id).sort()).toEqual(
      [first.id, second.id].sort(),
    )
    expect(cloud.saveCloudScan.mock.calls.map(([, scan]) => scan.input).sort()).toEqual([
      'https://contoh.com/dua',
      'https://contoh.com/satu',
    ])
    expect(listScans()).toHaveLength(0)
    expect(pendingScanIds('user-a')).toEqual([])
  })

  it('dijalankan berulang tanpa membuat dokumen kembar', async () => {
    saveScan(draft('https://contoh.com/satu'))

    await mergeLocalScansIntoAccount('user-a')
    resetLocalHistoryMergePasses()
    const secondPass = await mergeLocalScansIntoAccount('user-a')

    expect(secondPass).toMatchObject({ uploaded: 0, failed: 0 })
    expect(cloud.saveCloudScan).toHaveBeenCalledTimes(1)
  })

  it('hanya menjalankan satu jalan per akun per sesi aplikasi', async () => {
    saveScan(draft('https://contoh.com/satu'))

    const [a, b] = await Promise.all([
      mergeLocalScansIntoAccount('user-a'),
      mergeLocalScansIntoAccount('user-a'),
    ])

    expect(a).toBe(b)
    expect(cloud.saveCloudScan).toHaveBeenCalledTimes(1)
  })

  it('menahan sisanya di perangkat saat Firestore gagal di tengah jalan', async () => {
    const uploaded = saveScan(draft('https://contoh.com/lolos'))
    const retained = saveScan(draft('https://contoh.com/gagal'))

    cloud.saveCloudScan.mockImplementation(async (
      _uid: string,
      scan: { id: string; input: string },
    ) => {
      if (scan.input === 'https://contoh.com/gagal') throw failure('unavailable')
    })

    const result = await mergeLocalScansIntoAccount('user-a')

    expect(result.uploaded).toBe(1)
    expect(result.failed).toBe(1)
    expect(result.message).toMatch(/tidak dapat dihubungi/i)
    expect(listScans().map((scan) => scan.input)).toEqual(['https://contoh.com/gagal'])
    expect(pendingScanIds('user-a')).toEqual([retained.id])
    expect(pendingScanIds('user-a')).not.toContain(uploaded.id)
  })

  it('percobaan ulang mengirim entri yang tertinggal', async () => {
    saveScan(draft('https://contoh.com/tertinggal'))
    cloud.saveCloudScan.mockRejectedValueOnce(failure('unavailable'))

    const firstPass = await mergeLocalScansIntoAccount('user-a')
    expect(firstPass.failed).toBe(1)

    const retryPass = await retryMergeLocalScans('user-a')

    expect(retryPass).toMatchObject({ uploaded: 1, failed: 0, message: null })
    expect(listScans()).toHaveLength(0)
    expect(cloud.saveCloudScan).toHaveBeenCalledTimes(2)
  })

  it('tidak mengirim apa pun saat riwayat perangkat kosong', async () => {
    const result = await mergeLocalScansIntoAccount('user-a')

    expect(result).toEqual({ uploaded: 0, failed: 0, message: null })
    expect(cloud.saveCloudScan).not.toHaveBeenCalled()
    expect(cloud.pruneCloudScans).not.toHaveBeenCalled()
  })

  it('tidak pernah mengirim ke uid kosong', async () => {
    saveScan(draft('https://contoh.com/tamu'))

    const result = await mergeLocalScansIntoAccount('')

    expect(result).toEqual({ uploaded: 0, failed: 0, message: null })
    expect(cloud.saveCloudScan).not.toHaveBeenCalled()
    expect(listScans()).toHaveLength(1)
  })

  it('antrean akun lama tidak ikut terkirim ke akun yang baru masuk', async () => {
    const stale = saveScan(draft('https://contoh.com/pengguna-lama'))
    rememberPendingScan('user-a', stale.id)

    const result = await mergeLocalScansIntoAccount('user-b')

    expect(result.uploaded).toBe(1)
    expect(cloud.saveCloudScan.mock.calls.map(([uid]) => uid)).toEqual(['user-b'])
    expect(pendingScanIds('user-a')).toEqual([])
  })

  it('id di antrean yang tidak lagi ada di perangkat dilewati, bukan ditulis ulang', async () => {
    rememberPendingScan('user-a', 'sudah-dihapus')

    const result = await mergeLocalScansIntoAccount('user-a')

    expect(result).toMatchObject({ uploaded: 0, failed: 0 })
    expect(cloud.saveCloudScan).not.toHaveBeenCalled()
    expect(pendingScanIds('user-a')).toEqual([])
  })

  it('menjaga bentuk dokumen yang sudah disamarkan saat riwayat perangkat dikirim', async () => {
    saveScan(draft('https://contoh.com/masuk?token=abcdef1234567890'))

    await mergeLocalScansIntoAccount('user-a')

    const [, sent] = cloud.saveCloudScan.mock.calls[0] as unknown as [
      string,
      { input: string; meta: { inputStored?: string } },
    ]
    expect(sent.input).toBe('https://contoh.com/masuk')
    expect(sent.meta.inputStored).toBe('redacted')
  })

  it('menjadwalkan pemangkasan retensi hanya bila ada riwayat yang benar-benar terkirim', async () => {
    saveScan(draft('https://contoh.com/satu'))
    cloud.saveCloudScan.mockRejectedValue(failure('unavailable'))

    await mergeLocalScansIntoAccount('user-a')
    expect(cloud.pruneCloudScans).not.toHaveBeenCalled()

    cloud.saveCloudScan.mockResolvedValue(undefined)
    const retried = await retryMergeLocalScans('user-a')
    expect(retried.uploaded).toBe(1)
    expect(cloud.pruneCloudScans).toHaveBeenCalledWith('user-a')
  })
})

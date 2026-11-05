import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ScanDraft } from '../analysis/types'
import { clearScans, listScans } from '../storage/scanStore'

const cloud = vi.hoisted(() => ({
  saveCloudScan: vi.fn(),
  pruneCloudScans: vi.fn(async () => 0),
}))

vi.mock('../firebase/scans', () => ({
  saveCloudScan: cloud.saveCloudScan,
  pruneCloudScans: cloud.pruneCloudScans,
}))

import { resetLocalHistoryMergePasses } from './localHistoryMigration'
import { clearPendingSync, pendingScanIds } from './pendingSyncStore'
import { saveScanForUser } from './saveScan'

function makeDraft(input: string): ScanDraft {
  return {
    mode: 'link',
    input,
    displayTarget: input,
    riskScore: 0,
    riskLevel: 'low',
    headline: 'Indikasi risiko rendah',
    summary: 'Tidak banyak indikator risiko ditemukan.',
    reasons: [],
    patterns: [],
    recommendations: ['Verifikasi melalui kanal resmi.'],
    technical: [],
    meta: {
      engineVersion: 'test',
      signalCount: 0,
      inputLength: input.length,
      aiStatus: 'not_used',
    },
  }
}

function firebaseFailure(code: string) {
  return Object.assign(new Error('gateway timeout'), { code })
}

describe('penyimpanan hasil per pengguna', () => {
  beforeEach(() => {
    clearScans()
    clearPendingSync()
    resetLocalHistoryMergePasses()
    vi.clearAllMocks()
    cloud.saveCloudScan.mockResolvedValue(undefined)
  })

  it('menyimpan ke Firestore saat pengguna Firebase aktif', async () => {
    const result = await saveScanForUser(makeDraft('https://contoh.com/akun'), {}, 'user-1')

    expect(result.source).toBe('cloud')
    expect(result.syncError).toBeNull()
    expect(cloud.saveCloudScan).toHaveBeenCalledWith('user-1', result.scan)
    expect(listScans()).toHaveLength(0)
    expect(pendingScanIds('user-1')).toEqual([])
  })

  it('memangkas retensi riwayat akun setelah hasil tersimpan', async () => {
    await saveScanForUser(makeDraft('https://contoh.com/retensi'), {}, 'user-1')

    expect(cloud.pruneCloudScans).toHaveBeenCalledWith('user-1')
  })

  it('hanya menjalankan pemangkasan retensi sekali per sesi aplikasi', async () => {
    await saveScanForUser(makeDraft('https://contoh.com/satu'), {}, 'user-1')
    await saveScanForUser(makeDraft('https://contoh.com/dua'), {}, 'user-1')

    expect(cloud.pruneCloudScans).toHaveBeenCalledTimes(1)
  })

  it('tetap memakai localStorage tanpa sesi Firebase', async () => {
    const result = await saveScanForUser(makeDraft('https://contoh.com/lokal'), {}, null)

    expect(result.source).toBe('local')
    expect(result.syncError).toBeNull()
    expect(cloud.saveCloudScan).not.toHaveBeenCalled()
    expect(listScans().map((scan) => scan.input)).toEqual(['https://contoh.com/lokal'])
  })

  it('tidak mengirim URL sensitif apa adanya ke dokumen milik akun', async () => {
    const draft = makeDraft('https://contoh.com/masuk?token=abcdef1234567890')
    const { scan } = await saveScanForUser(draft, {}, 'user-1')

    expect(scan.input).toBe('https://contoh.com/masuk?token=abcdef1234567890')
    expect(cloud.saveCloudScan.mock.calls[0]?.[1]).toMatchObject({
      input: 'https://contoh.com/masuk',
      displayTarget: 'contoh.com/masuk',
    })
  })

  it('tidak menyimpan URL sensitif apa adanya di localStorage', async () => {
    const { scan } = await saveScanForUser(
      makeDraft('https://contoh.com/masuk?token=abcdef1234567890'),
      {},
      null,
    )

    expect(scan.input).toContain('token=')
    expect(listScans().map((item) => item.input)).toEqual(['https://contoh.com/masuk'])
  })

  describe('riwayat akun gagal ditulis', () => {
    const failures: Array<{ label: string; code: string; expected: RegExp }> = [
      { label: 'waktu tunggu habis', code: 'unavailable', expected: /tidak dapat dihubungi/i },
      { label: 'akses ditolak', code: 'permission-denied', expected: /tidak diizinkan/i },
      { label: 'sesi berakhir', code: 'unauthenticated', expected: /masuk kembali/i },
    ]

    for (const failure of failures) {
      it(`menahan hasil ${failure.label} di perangkat dan melaporkan kegagalan tanpa mengarang sukses`, async () => {
        cloud.saveCloudScan.mockRejectedValue(firebaseFailure(failure.code))

        const { scan, source, syncError } = await saveScanForUser(
          makeDraft(`https://contoh.com/${failure.code}`),
          {},
          'user-1',
        )

        expect(source).toBe('local')
        expect(syncError).toMatch(failure.expected)
        expect(listScans().map((item) => item.input)).toEqual([`https://contoh.com/${failure.code}`])
        expect(pendingScanIds('user-1')).toEqual([scan.id])
      })
    }

    it('menyimpan salinan yang sudah disamarkan saat sinkronisasi akun gagal', async () => {
      cloud.saveCloudScan.mockRejectedValue(firebaseFailure('unavailable'))

      await saveScanForUser(makeDraft('https://contoh.com/masuk?token=abcdef1234567890'), {}, 'user-1')

      expect(listScans().map((item) => item.input)).toEqual(['https://contoh.com/masuk'])
    })

    it('percobaan berulang atas pemeriksaan yang sama tidak membuat dokumen kembar', async () => {
      cloud.saveCloudScan.mockRejectedValue(firebaseFailure('unavailable'))

      const first = await saveScanForUser(makeDraft('https://contoh.com/berulang'), {}, 'user-1')
      const retry = await saveScanForUser(makeDraft('https://contoh.com/berulang'), {}, 'user-1')

      // Pemeriksaan identik menggantikan entri lama di perangkat, dan antrean menyimpan satu id.
      expect(retry.scan.id).not.toBe(first.scan.id)
      expect(listScans()).toHaveLength(1)
      expect(pendingScanIds('user-1')).toEqual([retry.scan.id])
    })

    it('kegagalan berturut-turut tidak menghapus riwayat yang sudah ada di perangkat', async () => {
      cloud.saveCloudScan.mockRejectedValue(firebaseFailure('unavailable'))

      for (const index of [1, 2, 3]) {
        await saveScanForUser(makeDraft(`https://contoh.com/gagal-${index}`), {}, 'user-1')
      }

      expect(listScans()).toHaveLength(3)
      expect(pendingScanIds('user-1')).toHaveLength(3)
    })
  })
})

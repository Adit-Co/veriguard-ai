import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ScanDraft } from '../analysis/types'
import { createScan, MAX_SAVED_SCANS } from '../storage/scanStore'
import { toCloudScanDocument } from './scanDocuments'

const firestore = vi.hoisted(() => ({
  collection: vi.fn(),
  deleteDoc: vi.fn(),
  doc: vi.fn(),
  getDoc: vi.fn(),
  getDocs: vi.fn(),
  limit: vi.fn(),
  orderBy: vi.fn(),
  query: vi.fn(),
  setDoc: vi.fn(),
  writeBatch: vi.fn(),
}))

const client = vi.hoisted(() => ({
  getFirebaseClient: vi.fn(),
}))

vi.mock('firebase/firestore', () => firestore)
vi.mock('./client', () => client)

import { getCloudScan, listCloudScans, pruneCloudScans } from './scans'

const database = { name: 'firestore-test' }

const batch = { delete: vi.fn(), commit: vi.fn(async () => undefined) }

function documentOf(input: string, ownerId = 'user-1', createdAt?: string) {
  const scan = makeScan(input)

  return {
    id: scan.id,
    ref: { path: `users/${ownerId}/scans/${scan.id}` },
    data: () => ({
      ...toCloudScanDocument(scan, ownerId),
      ...(createdAt ? { createdAt } : {}),
    }),
  }
}

function makeScan(input: string) {
  const draft: ScanDraft = {
    mode: 'link',
    input,
    displayTarget: input,
    riskScore: 20,
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
      inputStored: 'full',
    },
  }

  return createScan(draft)
}

describe('riwayat scan Firestore', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    client.getFirebaseClient.mockReturnValue({ db: database })
    firestore.collection.mockReturnValue({ path: 'users/user-1/scans' })
    firestore.query.mockReturnValue({ path: 'query' })
  })

  it('memuat scan milik pengguna dan menyaring dokumen pemilik lain', async () => {
    const ownScan = makeScan('https://milik-sendiri.example')
    const otherScan = makeScan('https://milik-orang-lain.example')
    firestore.getDocs.mockResolvedValue({
      docs: [
        {
          id: ownScan.id,
          data: () => toCloudScanDocument(ownScan, 'user-1'),
        },
        {
          id: otherScan.id,
          data: () => toCloudScanDocument(otherScan, 'user-2'),
        },
      ],
    })

    const scans = await listCloudScans('user-1')

    expect(firestore.collection).toHaveBeenCalledWith(database, 'users', 'user-1', 'scans')
    expect(scans).toEqual([ownScan])
  })

  it('menolak detail scan yang dimiliki pengguna lain', async () => {
    const otherScan = makeScan('https://milik-orang-lain.example')
    firestore.getDoc.mockResolvedValue({
      exists: () => true,
      id: otherScan.id,
      data: () => toCloudScanDocument(otherScan, 'user-2'),
    })

    await expect(getCloudScan('user-1', otherScan.id)).resolves.toBeNull()
  })

  it('meneruskan kegagalan pembacaan Firestore', async () => {
    const failure = new Error('unavailable')
    firestore.getDocs.mockRejectedValue(failure)

    await expect(listCloudScans('user-1')).rejects.toBe(failure)
  })
})

describe('retensi riwayat akun', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    client.getFirebaseClient.mockReturnValue({ db: database })
    firestore.collection.mockReturnValue({ path: 'users/user-1/scans' })
    firestore.query.mockReturnValue({ path: 'query' })
    firestore.writeBatch.mockReturnValue(batch)
    batch.delete.mockClear()
  })

  it('menghapus dokumen yang melewati masa retensi 90 hari', async () => {
    const aged = documentOf('https://tua.example', 'user-1', '2020-01-01T00:00:00.000Z')
    const fresh = documentOf('https://baru.example')
    firestore.getDocs.mockResolvedValue({ docs: [fresh, aged] })

    const removed = await pruneCloudScans('user-1')

    expect(removed).toBe(1)
    expect(firestore.orderBy).toHaveBeenCalledWith('createdAt', 'desc')
    expect(batch.delete).toHaveBeenCalledTimes(1)
    expect(batch.delete).toHaveBeenCalledWith(aged.ref)
  })

  it('menghapus dokumen yang melewati batas jumlah riwayat yang berlaku di perangkat', async () => {
    const docs = Array.from({ length: MAX_SAVED_SCANS + 3 }, (_unused, index) =>
      documentOf(`https://contoh.com/${index}`),
    )
    firestore.getDocs.mockResolvedValue({ docs })

    const removed = await pruneCloudScans('user-1')

    expect(removed).toBe(3)
    expect(batch.delete.mock.calls.map(([ref]) => ref.path)).toEqual(
      docs.slice(MAX_SAVED_SCANS).map((item) => item.ref.path),
    )
  })

  it('tidak menulis batch apa pun saat riwayat masih dalam kebijakan', async () => {
    firestore.getDocs.mockResolvedValue({ docs: [documentOf('https://contoh.com/baru')] })

    const removed = await pruneCloudScans('user-1')

    expect(removed).toBe(0)
    expect(firestore.writeBatch).not.toHaveBeenCalled()
  })

  it('menyimpan dokumen yang waktunya tidak dapat dibaca alih-alih menghapusnya', async () => {
    const broken = documentOf('https://rusak.example')
    firestore.getDocs.mockResolvedValue({
      docs: [{ ...broken, data: () => ({ ...broken.data(), createdAt: 'bukan waktu' }) }],
    })

    const removed = await pruneCloudScans('user-1')

    expect(removed).toBe(0)
    expect(batch.delete).not.toHaveBeenCalled()
  })

  it('meneruskan kegagalan penghapusan ke pemanggil', async () => {
    firestore.getDocs.mockResolvedValue({
      docs: [documentOf('https://tua.example', 'user-1', '2020-01-01T00:00:00.000Z')],
    })
    batch.commit.mockRejectedValueOnce(new Error('permission-denied'))

    await expect(pruneCloudScans('user-1')).rejects.toThrow('permission-denied')
  })
})

import { beforeEach, describe, expect, it, vi } from 'vitest'

const firestore = vi.hoisted(() => ({
  doc: vi.fn(),
  runTransaction: vi.fn(),
}))

const client = vi.hoisted(() => ({
  getFirebaseClient: vi.fn(),
}))

const claim = vi.hoisted(() => ({
  readUsernameClaim: vi.fn(),
}))

vi.mock('firebase/firestore', () => firestore)
vi.mock('./client', () => client)
vi.mock('./usernames', () => claim)

import { syncUserProfile } from './profile'

const NOW = '2026-10-21T10:00:00.000Z'
const CREATED_AT = '2025-01-02T03:04:05.000Z'
const database = { name: 'firestore-test' }
const reference = { path: 'users/user-1' }

describe('sinkronisasi profil Firestore', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    client.getFirebaseClient.mockReturnValue({ db: database })
    firestore.doc.mockReturnValue(reference)
    claim.readUsernameClaim.mockResolvedValue(null)
  })

  it('mempertahankan createdAt dari dokumen yang sudah ada', async () => {
    const set = vi.fn()
    const get = vi.fn().mockResolvedValue({
      exists: () => true,
      data: () => ({ uid: 'user-1', createdAt: CREATED_AT }),
    })
    firestore.runTransaction.mockImplementation(
      async (_db: unknown, callback: (transaction: unknown) => unknown) =>
        callback({ get, set }),
    )

    const profile = await syncUserProfile(
      { uid: 'user-1', email: 'pengguna@contoh.com', displayName: 'Pengguna' },
      NOW,
    )

    expect(firestore.doc).toHaveBeenCalledWith(database, 'users', 'user-1')
    expect(profile.createdAt).toBe(CREATED_AT)
    expect(profile.lastLoginAt).toBe(NOW)
    expect(set).toHaveBeenCalledWith(reference, profile)
  })

  it('skenario 9:skenario akun lama: profil tanpa klaim username tidak menaruh nilai palsu', async () => {
    const set = vi.fn()
    const get = vi.fn().mockResolvedValue({
      exists: () => true,
      data: () => ({
        uid: 'user-1',
        email: 'pengguna@contoh.com',
        displayName: 'Pengguna',
        createdAt: CREATED_AT,
        lastLoginAt: CREATED_AT,
      }),
    })
    firestore.runTransaction.mockImplementation(
      async (_db: unknown, callback: (transaction: unknown) => unknown) =>
        callback({ get, set }),
    )

    const profile = await syncUserProfile(
      { uid: 'user-1', email: 'pengguna@contoh.com', displayName: 'Pengguna' },
      NOW,
    )

    expect(claim.readUsernameClaim).toHaveBeenCalledWith('user-1')
    expect(profile.username).toBeNull()
    expect(profile.createdAt).toBe(CREATED_AT)
  })

  it('menyalin klaim username milik akun ke dokumen profil', async () => {
    claim.readUsernameClaim.mockResolvedValue({
      username: 'gyat123',
      uid: 'user-1',
      createdAt: CREATED_AT,
    })
    const set = vi.fn()
    const get = vi.fn().mockResolvedValue({ exists: () => false, data: () => undefined })
    firestore.runTransaction.mockImplementation(
      async (_db: unknown, callback: (transaction: unknown) => unknown) =>
        callback({ get, set }),
    )

    const profile = await syncUserProfile(
      { uid: 'user-1', email: 'pengguna@contoh.com', displayName: 'Pengguna' },
      NOW,
    )

    expect(profile.username).toBe('gyat123')
  })

  it('tidak menghapus username profil ketika klaim belum dapat dibaca', async () => {
    claim.readUsernameClaim.mockRejectedValue(
      Object.assign(new Error('permission-denied'), { code: 'permission-denied' }),
    )
    const set = vi.fn()
    const get = vi.fn().mockResolvedValue({
      exists: () => true,
      data: () => ({
        uid: 'user-1',
        email: 'pengguna@contoh.com',
        displayName: 'Pengguna',
        username: 'aditdev',
        createdAt: CREATED_AT,
        lastLoginAt: CREATED_AT,
      }),
    })
    firestore.runTransaction.mockImplementation(
      async (_db: unknown, callback: (transaction: unknown) => unknown) =>
        callback({ get, set }),
    )

    const profile = await syncUserProfile(
      { uid: 'user-1', email: 'pengguna@contoh.com', displayName: 'Pengguna' },
      NOW,
    )

    expect(profile.username).toBe('aditdev')
  })

  it('username eksplisit dari pemanggil dipakai tanpa membaca klaim', async () => {
    const set = vi.fn()
    const get = vi.fn().mockResolvedValue({ exists: () => false, data: () => undefined })
    firestore.runTransaction.mockImplementation(
      async (_db: unknown, callback: (transaction: unknown) => unknown) =>
        callback({ get, set }),
    )

    const profile = await syncUserProfile(
      { uid: 'user-1', email: null, displayName: null, username: 'AditDev' },
      NOW,
    )

    expect(claim.readUsernameClaim).not.toHaveBeenCalled()
    expect(profile.username).toBe('aditdev')
  })

  it('meneruskan kegagalan Firestore agar status UI dapat ditampilkan', async () => {
    const failure = new Error('permission-denied')
    firestore.runTransaction.mockRejectedValue(failure)

    await expect(
      syncUserProfile(
        { uid: 'user-1', email: 'pengguna@contoh.com', displayName: 'Pengguna' },
        NOW,
      ),
    ).rejects.toBe(failure)
  })

  it('menolak UID kosong sebelum menghubungi Firestore', async () => {
    await expect(
      syncUserProfile({ uid: '  ', email: null, displayName: null }, NOW),
    ).rejects.toThrow('UID akun tidak valid')

    expect(client.getFirebaseClient).not.toHaveBeenCalled()
    expect(firestore.runTransaction).not.toHaveBeenCalled()
  })
})

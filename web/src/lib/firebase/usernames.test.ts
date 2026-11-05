import { beforeEach, describe, expect, it, vi } from 'vitest'

/**
 * Firestore asli tidak berjalan di jsdom. Fake ini menjalankan bagian aturan
 * firestore.rules yang menegakkan keunikan username: hanya create yang diizinkan,
 * bentuk dokumen diperiksa, dan kepemilikan harus cocok. Dengan begitu pengujian
 * membuktikan apa yang benar-benar ditegakkan server, bukan asumsi klien.
 * Aturan yang sama belum dapat dijalankan pada emulator (Java tidak tersedia),
 * lihat catatan keterbatasan pada dokumentasi.
 */
const fx = vi.hoisted(() => {
  const USERNAME = /^[a-z0-9_]{3,20}$/
  const keys = (data: Record<string, unknown>) => Object.keys(data).sort().join(',')
  const denied = () => Object.assign(new Error('permission-denied'), { code: 'permission-denied' })

  const state = {
    store: new Map<string, Record<string, unknown>>(),
    pending: new Map<string, Record<string, unknown>>(),
    uid: null as string | null,
    anonymous: false,
    getFail: null as null | Error,
  }

  function sameCommit(path: string) {
    return state.pending.get(path) ?? null
  }

  function registryAllowed(username: string, data: Record<string, unknown>) {
    if (!USERNAME.test(username)) return false
    if (!state.uid || state.anonymous) return false
    if (keys(data) !== 'createdAt,uid') return false
    if (data.uid !== state.uid) return false
    if (typeof data.createdAt !== 'string' || !data.createdAt) return false
    const claim = sameCommit(`users/${state.uid}/username/current`)
    return Boolean(claim && claim.username === username && claim.uid === state.uid)
  }

  function claimAllowed(userId: string, claimId: string, data: Record<string, unknown>) {
    if (claimId !== 'current') return false
    if (keys(data) !== 'createdAt,uid,username') return false
    if (typeof data.username !== 'string' || !USERNAME.test(data.username)) return false
    if (data.uid !== userId) return false
    if (!state.uid || state.uid !== userId || state.anonymous) return false
    const registry = sameCommit(`usernames/${data.username}`)
    return Boolean(registry && registry.uid === userId)
  }

  function writeAllowed(path: string, data: Record<string, unknown>) {
    const segments = path.split('/')
    if (segments[0] === 'usernames') return registryAllowed(segments[1], data)
    if (segments[0] === 'users' && segments[2] === 'username') {
      return claimAllowed(segments[1], segments[3], data)
    }
    return false
  }

  function commit(path: string, data: Record<string, unknown>) {
    // Aturan tidak mengizinkan update atau delete. Tulisan ke dokumen yang sudah ada
    // diklasifikasikan sebagai update, sehingga klaim kedua atas nama yang sama ditolak
    // dan klaim lama tidak pernah dapat ditimpa.
    if (state.store.has(path)) throw denied()
    if (!writeAllowed(path, data)) throw denied()
    state.store.set(path, data)
  }

  function readOwnerOnly(path: string) {
    const segments = path.split('/')
    const data = state.store.get(path) ?? null
    if (!data || !state.uid || state.anonymous) return null
    if (segments[0] === 'users') return segments[1] === state.uid ? data : null
    if (segments[0] === 'usernames') return data.uid === state.uid ? data : null
    return null
  }

  return {
    state,
    doc: vi.fn((_db: unknown, ...segments: string[]) => ({ path: segments.join('/') })),
    getDoc: vi.fn(async (ref: { path: string }) => {
      if (state.getFail) {
        const failure = state.getFail
        state.getFail = null
        throw failure
      }
      const data = readOwnerOnly(ref.path)
      return { exists: () => Boolean(data), data: () => data }
    }),
    runTransaction: vi.fn(async (_db: unknown, callback: (transaction: unknown) => unknown) => {
      const writes: Array<{ path: string; data: Record<string, unknown> }> = []
      const pending = new Map<string, Record<string, unknown>>()
      const transaction = {
        get: async (ref: { path: string }) => {
          const data = state.store.get(ref.path) ?? null
          return { exists: () => Boolean(data), data: () => data }
        },
        set: (ref: { path: string }, data: Record<string, unknown>) => {
          writes.push({ path: ref.path, data })
          pending.set(ref.path, data)
        },
      }

      const result = await callback(transaction)

      // Komitmen berjalan sinkron per transaksi: transaksi yang tiba kedua melihat
      // dokumen hasil komitmen pertama dan ditolak, tanpa menghapus tulisan yang
      // sudah sah.
      state.pending = pending
      const applied: string[] = []
      try {
        for (const write of writes) {
          commit(write.path, write.data)
          applied.push(write.path)
        }
      } catch (error) {
        for (const path of applied) state.store.delete(path)
        throw error
      } finally {
        state.pending = new Map()
      }
      return result
    }),
    reset(uid: string | null, options: { anonymous?: boolean } = {}) {
      state.store = new Map()
      state.pending = new Map()
      state.uid = uid
      state.anonymous = Boolean(options.anonymous)
      state.getFail = null
    },
    seed(path: string, data: Record<string, unknown>) {
      state.store.set(path, data)
    },
    peek(path: string) {
      return state.store.get(path) ?? null
    },
  }
})

const client = vi.hoisted(() => ({ getFirebaseClient: vi.fn() }))

vi.mock('firebase/firestore', () => ({
  doc: fx.doc,
  getDoc: fx.getDoc,
  runTransaction: fx.runTransaction,
}))
vi.mock('./client', () => client)

import {
  UsernameClaimError,
  claimUsername,
  claimUsernameForCurrentUser,
  readUsernameClaim,
  usernameClaimErrorMessage,
} from './usernames'

const database = { name: 'firestore-username-test' }
const NOW = '2026-10-30T10:00:00.000Z'

function signIn(uid: string | null, options: { anonymous?: boolean } = {}) {
  fx.reset(uid, options)
  client.getFirebaseClient.mockReturnValue({
    db: database,
    auth: {
      currentUser: uid
        ? {
            uid,
            isAnonymous: Boolean(options.anonymous),
            reload: vi.fn(async () => undefined),
          }
        : null,
    },
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  signIn('user-a')
})

describe('klaim username pertama', () => {
  it('skenario 1:username baru membuat entri registry dan pointer milik akun', async () => {
    const claim = await claimUsername('user-a', 'aditdev', NOW)

    expect(claim).toEqual({ username: 'aditdev', uid: 'user-a', createdAt: NOW })
    expect(fx.peek('usernames/aditdev')).toEqual({ uid: 'user-a', createdAt: NOW })
    expect(fx.peek('users/user-a/username/current')).toEqual({
      username: 'aditdev',
      uid: 'user-a',
      createdAt: NOW,
    })
  })

  it('skenario 3:username dengan huruf besar menempati kunci yang sama', async () => {
    await claimUsername('user-a', 'Gyat123', NOW)
    expect(fx.peek('usernames/gyat123')?.uid).toBe('user-a')

    await expect(claimUsername('user-b', 'GYAT123', NOW)).rejects.toBeInstanceOf(
      UsernameClaimError,
    )
  })

  it('skenario 5:format username ditolak sebelum ada tulisan ke Firestore', async () => {
    for (const value of ['ab', 'a'.repeat(21), 'pengguna-baru', 'pengguna baru', '']) {
      const failure = await claimUsername('user-a', value, NOW).catch((error) => error)
      expect(failure).toBeInstanceOf(UsernameClaimError)
      expect((failure as UsernameClaimError).code).toBe('invalid-username')
    }
    expect(fx.runTransaction).not.toHaveBeenCalled()
  })

  it('menolak UID kosong atau UID berisi pemisah jalur', async () => {
    await expect(claimUsername('   ', 'aditdev', NOW)).rejects.toMatchObject({ code: 'session' })
    await expect(claimUsername('user/../admin', 'aditdev', NOW)).rejects.toMatchObject({
      code: 'session',
    })
    expect(fx.runTransaction).not.toHaveBeenCalled()
  })
})

describe('keunikan username', () => {
  it('skenario 2:akun kedua dengan username yang sama ditolak tanpa menimpa pemilik lama', async () => {
    await claimUsername('user-a', 'gyat123', NOW)
    signIn('user-b')
    fx.seed('usernames/gyat123', { uid: 'user-a', createdAt: NOW })
    fx.seed('users/user-a/username/current', {
      username: 'gyat123',
      uid: 'user-a',
      createdAt: NOW,
    })

    const failure = await claimUsername('user-b', 'gyat123', NOW).catch((error) => error)
    expect(failure).toBeInstanceOf(UsernameClaimError)
    expect((failure as UsernameClaimError).code).toBe('taken')
    expect(usernameClaimErrorMessage(failure)).toContain('sudah dipakai akun lain')

    // Klaim lama utuh dan tidak ada pointer yatim untuk user-b.
    expect(fx.peek('usernames/gyat123')).toEqual({ uid: 'user-a', createdAt: NOW })
    expect(fx.peek('users/user-b/username/current')).toBeNull()
  })

  it('skenario 4:dua klaim serentak atas nama yang sama tidak dapat keduanya berhasil', async () => {
    const results = await Promise.allSettled([
      claimUsername('user-a', 'gyat123', NOW),
      claimUsername('user-a', 'gyat123', NOW),
    ])

    const fulfilled = results.filter((result) => result.status === 'fulfilled')
    const rejected = results.filter((result) => result.status === 'rejected')
    expect(fulfilled).toHaveLength(1)
    expect(rejected).toHaveLength(1)
    expect(fx.peek('usernames/gyat123')?.uid).toBe('user-a')
  })

  it('registry tidak dapat ditimpa lewat jalur klien lain', async () => {
    await claimUsername('user-a', 'aditdev', NOW)
    const registry = fx.peek('usernames/aditdev')
    expect(registry).toEqual({ uid: 'user-a', createdAt: NOW })

    // Akun yang sama tidak dapat memindahkan klaimnya ke nama lain.
    await expect(claimUsername('user-a', 'aditdev2', NOW)).rejects.toMatchObject({
      code: 'account-has-username',
    })
    expect(fx.peek('usernames/aditdev2')).toBeNull()
    expect(fx.peek('usernames/aditdev')).toBe(registry)
  })
})

describe('pemilik lama mempertahankan username', () => {
  it('skenario 6:klaim ulang oleh pemilik yang sama bersifat idempoten', async () => {
    const first = await claimUsername('user-a', 'aditdev', NOW)
    const second = await claimUsername('user-a', 'ADITDEV', '2027-01-01T00:00:00.000Z')

    expect(second).toEqual(first)
    expect(fx.peek('usernames/aditdev')?.createdAt).toBe(NOW)
  })

  it('pointer yang memuat username lain untuk akun yang sama ditolak', async () => {
    fx.seed('users/user-a/username/current', {
      username: 'pemilik_lama',
      uid: 'user-a',
      createdAt: NOW,
    })

    await expect(claimUsername('user-a', 'aditdev', NOW)).rejects.toMatchObject({
      code: 'account-has-username',
    })
  })
})

describe('klaim username untuk akun yang sudah ada', () => {
  it('skenario 7:kegagalan klaim tidak meninggalkan registry atau pointer', async () => {
    signIn('user-b')
    fx.seed('usernames/gyat123', { uid: 'user-a', createdAt: NOW })

    await expect(claimUsernameForCurrentUser('gyat123')).rejects.toBeInstanceOf(UsernameClaimError)
    expect(fx.peek('usernames/gyat123')?.uid).toBe('user-a')
    expect(fx.peek('users/user-b/username/current')).toBeNull()
  })

  it('memasang username pada akun yang belum memilikinya lalu membacanya kembali', async () => {
    const claim = await claimUsernameForCurrentUser('AditDev')

    expect(claim.username).toBe('aditdev')
    expect(fx.peek('users/user-a/username/current')?.username).toBe('aditdev')
  })

  it('sesi anonim dan sesi kosong ditolak sebelum menulis apa pun', async () => {
    signIn('user-a', { anonymous: true })
    await expect(claimUsernameForCurrentUser('aditdev')).rejects.toMatchObject({ code: 'session' })

    signIn(null)
    await expect(claimUsernameForCurrentUser('aditdev')).rejects.toMatchObject({ code: 'session' })
    expect(fx.runTransaction).not.toHaveBeenCalled()
    expect(fx.peek('usernames/aditdev')).toBeNull()
  })

  it('perubahan aturan menjadi pesan yang mengarahkan masuk ulang', async () => {
    client.getFirebaseClient.mockReturnValue({
      db: database,
      auth: {
        currentUser: {
          uid: 'user-a',
          isAnonymous: false,
          reload: vi.fn(async () => {
            throw Object.assign(new Error('failed-precondition'), { code: 'failed-precondition' })
          }),
        },
      },
    })

    const failure = await claimUsernameForCurrentUser('aditdev').catch((error) => error)
    expect((failure as UsernameClaimError).code).toBe('configuration')
    expect(usernameClaimErrorMessage(failure)).toContain('Masuk kembali')
  })
})

describe('membaca klaim username', () => {
  it('mengembalikan username milik akun yang sedang masuk', async () => {
    await claimUsername('user-a', 'aditdev', NOW)

    const claim = await readUsernameClaim('user-a')
    expect(claim?.username).toBe('aditdev')
    expect(claim?.uid).toBe('user-a')
  })

  it('mengembalikan null ketika akun belum memiliki username', async () => {
    expect(await readUsernameClaim('user-a')).toBeNull()
    expect(await readUsernameClaim('')).toBeNull()
  })

  it('kegagalan baca diteruskan agar pemanggil dapat memutuskan sendiri', async () => {
    fx.state.getFail = Object.assign(new Error('permission-denied'), { code: 'permission-denied' })
    await expect(readUsernameClaim('user-a')).rejects.toThrow('permission-denied')
  })
})

describe('pesan galat klaim username', () => {
  it('memetakan kode Firestore ke pesan yang tidak membocorkan data akun', () => {
    expect(
      usernameClaimErrorMessage(Object.assign(new Error('x'), { code: 'permission-denied' })),
    ).toContain('sudah dipakai akun lain')
    expect(
      usernameClaimErrorMessage(Object.assign(new Error('x'), { code: 'unavailable' })),
    ).toContain('tidak dapat dihubungi')
    expect(
      usernameClaimErrorMessage(Object.assign(new Error('x'), { code: 'unauthenticated' })),
    ).toContain('Masuk kembali')
    expect(usernameClaimErrorMessage(new Error('x'))).toContain('Aturan akses data')
  })
})

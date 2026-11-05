import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'

/**
 * Uji pagar login demo (BAGIAN 4 & 5). Asumsi: vitest berjalan pada mode pengembangan
 * sehingga `import.meta.env.DEV` bernilai true — kalau tidak, jalur produksi yang menolak
 * login demo justru tidak tercapai dan test "tersedia" di bawah ini akan gagal, bukan lolos
 * diam-diam. Penolakan build produksi sendiri dibuktikan di sisi build
 * (config/productionEnv.ts + vite.config.ts `command === 'serve'`), bukan di sini.
 */

const mocks = vi.hoisted(() => ({
  configState: { configured: true, config: null as unknown, missingKeys: [] as string[] },
  useEmulators: false,
  authEmulatorUrl: '',
  signInWithCustomToken: vi.fn(),
  getFirebaseClient: vi.fn(),
}))

vi.mock('../firebase/config', () => ({
  // Getter, supaya tiap test bisa mengganti keadaan tanpa reload modul: bind named import
  // dievaluasi saat dipakai, bukan saat diimpor.
  get firebaseConfigState() {
    return mocks.configState
  },
  get isFirebaseConfigured() {
    return mocks.configState.configured
  },
  get useFirebaseEmulators() {
    return mocks.useEmulators
  },
  get authEmulatorUrl() {
    return mocks.authEmulatorUrl
  },
  get firestoreEmulatorHost() {
    return '127.0.0.1:8080'
  },
  get functionsEmulatorHost() {
    return '127.0.0.1:5001'
  },
}))

vi.mock('firebase/auth', () => ({
  signInWithCustomToken: mocks.signInWithCustomToken,
}))

vi.mock('../firebase/client', () => ({
  getFirebaseClient: mocks.getFirebaseClient,
}))

import {
  DEMO_SESSION_ENDPOINT,
  DemoLoginError,
  demoLoginAvailability,
  signInWithDemoAccount,
} from './demoLogin'

type FetchInit = { body?: string }

function jsonResponse(status: number, payload: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  } as unknown as Response
}

function stubFetch(response: Response | (() => Promise<Response>)): ReturnType<typeof vi.fn> {
  const impl =
    typeof response === 'function'
      ? response
      : async () => response
  const spy = vi.fn(impl as (input: string, init?: FetchInit) => Promise<Response>)
  vi.stubGlobal('fetch', spy)
  return spy
}

function demoUser(claims: Record<string, unknown>) {
  const getIdToken = vi.fn(async () => 'id-token-baru')
  const getIdTokenResult = vi.fn(async () => ({ claims }))
  return { uid: 'uid-demo', getIdToken, getIdTokenResult }
}

function readyEmulatorEnv(flag: string | undefined) {
  mocks.configState = { configured: true, config: null, missingKeys: [] }
  mocks.useEmulators = true
  mocks.authEmulatorUrl = 'http://127.0.0.1:9099'
  vi.stubEnv('VITE_ENABLE_DEMO_LOGIN', flag ?? '')
}

beforeEach(() => {
  mocks.getFirebaseClient.mockReturnValue({ auth: {} })
  mocks.signInWithCustomToken.mockReset()
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('BAGIAN 4 — pagar ketersediaan login demo', () => {
  it('default nonaktif: tanpa bendera, tidak tersedia', () => {
    readyEmulatorEnv(undefined)
    const gate = demoLoginAvailability()

    expect(gate.available).toBe(false)
    expect(gate.reason).toMatch(/tidak diaktifkan/i)
  })

  it('bendera aktif tetapi konfigurasi layanan akun belum lengkap', () => {
    readyEmulatorEnv('true')
    mocks.configState = { configured: false, config: null, missingKeys: ['VITE_FIREBASE_API_KEY'] }

    const gate = demoLoginAvailability()
    expect(gate.available).toBe(false)
    expect(gate.reason).toMatch(/konfigurasi/i)
  })

  it('tanpa emulator, login demo ditolak meski bendera aktif', () => {
    readyEmulatorEnv('1')
    mocks.useEmulators = false

    expect(demoLoginAvailability().available).toBe(false)
  })

  it('emulator non-loopback ditolak: tidak ada sesi demo ke proyek sungguhan', () => {
    for (const url of ['https://auth.example.com', 'http://10.0.0.5:9099', '', 'bukan-url']) {
      readyEmulatorEnv('true')
      mocks.authEmulatorUrl = url
      const gate = demoLoginAvailability()

      // Bentuk objek dipakai supaya URL yang gagal terlihat pada diff, tanpa pesan kustom.
      expect({ url, gate }).toEqual({
        url,
        gate: { available: false, reason: expect.stringMatching(/host lokal/i) },
      })
    }
  })

  it('emulator loopback + bendera aktif = tersedia', () => {
    for (const url of ['http://127.0.0.1:9099', 'http://localhost:9099', 'http://[::1]:9099']) {
      readyEmulatorEnv('true')
      mocks.authEmulatorUrl = url
      expect({ url, gate: demoLoginAvailability() }).toEqual({
        url,
        gate: { available: true, reason: null },
      })
    }
  })

  it('penolakan pagar menghentikan signInWithDemoAccount sebelum ada permintaan jaringan', async () => {
    readyEmulatorEnv(undefined)
    const fetchSpy = stubFetch(jsonResponse(200, { token: 'seharusnya-tidak-dipakai' }))

    await expect(signInWithDemoAccount('admin')).rejects.toBeInstanceOf(DemoLoginError)
    await expect(signInWithDemoAccount('admin')).rejects.toThrow(/tidak diaktifkan/i)

    expect(fetchSpy).not.toHaveBeenCalled()
    expect(mocks.signInWithCustomToken).not.toHaveBeenCalled()
  })
})

describe('BAGIAN 5 — peran dibaca dari token server, bukan dari respons HTTP', () => {
  it('hanya kunci akun yang dikirim; sesi memakai token custom dari dev server', async () => {
    readyEmulatorEnv('true')
    const user = demoUser({ admin: true })
    mocks.signInWithCustomToken.mockResolvedValue({ user })
    const fetchSpy = stubFetch(
      jsonResponse(200, { account: 'admin', email: 'admin@contoh.com', role: 'user', token: 'token-demo' }),
    )

    const result = await signInWithDemoAccount('admin')

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(fetchSpy.mock.calls[0]?.[0]).toBe(DEMO_SESSION_ENDPOINT)
    // Body hanya berisi kunci. Email/peran yang dikirim klien tidak pernah ada, jadi tidak ada
    // yang bisa dipalsukan dari peramban untuk meminta peran admin.
    expect(JSON.parse(fetchSpy.mock.calls[0]?.[1]?.body ?? '{}')).toEqual({ account: 'admin' })

    expect(mocks.signInWithCustomToken).toHaveBeenCalledOnce()
    expect(user.getIdToken).toHaveBeenCalledWith(true)
    expect(result.adminClaim).toBe(true)
    expect(result.user).toBe(user)
  })

  it('klaim admin pada body HTTP tidak berarti apa-apa bila ID token tidak memuatnya', async () => {
    readyEmulatorEnv('true')
    mocks.signInWithCustomToken.mockResolvedValue({ user: demoUser({}) })
    stubFetch(jsonResponse(200, { role: 'admin', admin: true, token: 'token-demo' }))

    const result = await signInWithDemoAccount('user')

    expect(result.adminClaim).toBe(false)
  })

  it('endpoint 404 berarti login demo tidak aktif dan layanan akun tidak disentuh', async () => {
    readyEmulatorEnv('true')
    stubFetch(jsonResponse(404, { error: 'tidak ada' }))

    await expect(signInWithDemoAccount('admin')).rejects.toThrow(/tidak aktif pada lingkungan ini/i)
    expect(mocks.signInWithCustomToken).not.toHaveBeenCalled()
  })

  it('pesan galat server diteruskan apa adanya dan tidak memicu penukaran token', async () => {
    readyEmulatorEnv('true')
    stubFetch(jsonResponse(502, { error: 'Emulator lokal tidak dapat menyiapkan sesi demo.' }))

    await expect(signInWithDemoAccount('user')).rejects.toThrow(/Emulator lokal tidak dapat menyiapkan/i)
    expect(mocks.signInWithCustomToken).not.toHaveBeenCalled()
  })

  it('respons tanpa token ditolak: tidak ada penukaran token kosong', async () => {
    readyEmulatorEnv('true')
    stubFetch(jsonResponse(200, { account: 'admin', role: 'admin' }))

    await expect(signInWithDemoAccount('admin')).rejects.toThrow(/tidak menerima token/i)
    expect(mocks.signInWithCustomToken).not.toHaveBeenCalled()
  })

  it('dev server tidak terjangkau → pesan prasyarat, bukan kegagalan senyap', async () => {
    readyEmulatorEnv('true')
    stubFetch(async () => {
      throw new TypeError('fetch failed')
    })

    await expect(signInWithDemoAccount('admin')).rejects.toThrow(/Jalankan dev server/i)
  })

  it('token demo yang ditolak layanan akun diberi pesan emulator', async () => {
    readyEmulatorEnv('true')
    stubFetch(jsonResponse(200, { token: 'token-demo' }))
    mocks.signInWithCustomToken.mockRejectedValue(
      Object.assign(new Error('invalid custom token'), { code: 'auth/invalid-custom-token' }),
    )

    await expect(signInWithDemoAccount('admin')).rejects.toThrow(/Token demo ditolak layanan akun/i)
  })

  it('kegagalan tak terklasifikasi tidak pernah berakhir dengan peran admin', async () => {
    readyEmulatorEnv('true')
    stubFetch(jsonResponse(200, { token: 'token-demo' }))
    mocks.signInWithCustomToken.mockRejectedValue(new Error('galat tak terduga'))

    await expect(signInWithDemoAccount('admin')).rejects.toThrow(
      /Peran tidak diberikan tanpa verifikasi server/i,
    )
  })
})

import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  FIREBASE_JWKS_URL,
  emulatorOriginFor,
  readBearerToken,
  resetFirebaseSigningKeys,
  verifyFirebaseIdToken,
} from '../src/auth/firebaseToken.js'

const PROJECT = 'YOUR_FIREBASE_PROJECT_ID'
const ISSUER = `https://securetoken.google.com/${PROJECT}`
const NOW = 1_800_000_000_000

function base64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const value of bytes) binary += String.fromCharCode(value)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function encodeJson(value: unknown): string {
  return base64Url(new TextEncoder().encode(JSON.stringify(value)))
}

let privateSigned: CryptoKey
let publicJwk: JsonWebKey
let otherPrivate: CryptoKey
let otherJwk: JsonWebKey

async function generate(): Promise<{ private: CryptoKey; jwk: JsonWebKey }> {
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )
  return {
    private: pair.privateKey,
    jwk: (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey,
  }
}

async function signToken(
  signingKey: CryptoKey,
  claims: Record<string, unknown>,
  headerOverrides: Record<string, unknown> = {},
): Promise<string> {
  const header = { alg: 'RS256', typ: 'JWT', kid: 'kunci-uji-1', ...headerOverrides }
  const input = `${encodeJson(header)}.${encodeJson(claims)}`
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    signingKey,
    new TextEncoder().encode(input),
  )
  return `${input}.${base64Url(new Uint8Array(signature))}`
}

function jwksFetch(keys: Array<Record<string, unknown>>, calls: string[] = []) {
  const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
    calls.push(String(input))
    return new Response(JSON.stringify({ keys }), {
      status: 200,
      headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600' },
    })
  })
  return fetchImpl as unknown as typeof fetch
}

function validClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: ISSUER,
    aud: PROJECT,
    sub: 'abcDEF123_-uid',
    iat: Math.floor(NOW / 1000),
    exp: Math.floor(NOW / 1000) + 3600,
    auth_time: Math.floor(NOW / 1000),
    firebase: { sign_in_provider: 'password' },
    ...overrides,
  }
}

function verify(token: unknown, fetchImpl: typeof fetch, extra: Record<string, unknown> = {}) {
  return verifyFirebaseIdToken(token, {
    projectId: PROJECT,
    fetchImpl,
    now: () => NOW,
    ...extra,
  })
}

beforeAll(async () => {
  const primary = await generate()
  privateSigned = primary.private
  publicJwk = primary.jwk
  const other = await generate()
  otherPrivate = other.private
  otherJwk = other.jwk
})

beforeEach(() => {
  resetFirebaseSigningKeys()
})

describe('verifikasi Firebase ID token (P1-2)', () => {
  it('menerima token sah dan mengembalikan uid plus provider', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk, use: 'sig', alg: 'RS256' }])
    const token = await signToken(privateSigned, validClaims())

    expect(await verify(token, fetchImpl)).toEqual({
      ok: true,
      uid: 'abcDEF123_-uid',
      email: null,
      providerId: 'password',
    })
  })

  it('mengembalikan email bila ada pada klaim', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])
    const token = await signToken(privateSigned, validClaims({ email: 'warga@contoh.id' }))

    const result = await verify(token, fetchImpl)
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.email).toBe('warga@contoh.id')
  })

  it('menolak token yang kedaluwarsa', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])
    const token = await signToken(
      privateSigned,
      validClaims({ exp: Math.floor(NOW / 1000) - 3600 }),
    )

    expect(await verify(token, fetchImpl)).toEqual({ ok: false, reason: 'expired' })
  })

  it('menolak token yang belum berlaku (nbf di masa depan)', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])
    const token = await signToken(
      privateSigned,
      validClaims({ nbf: Math.floor(NOW / 1000) + 3600 }),
    )

    expect(await verify(token, fetchImpl)).toEqual({ ok: false, reason: 'not_yet_valid' })
  })

  it('menolak issuer yang bukan penerbit proyek ini', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])
    const token = await signToken(
      privateSigned,
      validClaims({ iss: 'https://securetoken.google.com/proyek-lain' }),
    )

    expect(await verify(token, fetchImpl)).toEqual({ ok: false, reason: 'issuer_mismatch' })
  })

  it('menolak audience yang tidak cocok dengan proyek', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])
    const token = await signToken(privateSigned, validClaims({ aud: 'proyek-lain' }))

    expect(await verify(token, fetchImpl)).toEqual({ ok: false, reason: 'audience_mismatch' })
  })

  it('menerima bentuk aud array yang memuat proyek', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])
    const token = await signToken(privateSigned, validClaims({ aud: ['lain', PROJECT] }))

    expect((await verify(token, fetchImpl)).ok).toBe(true)
  })

  it('menolak tanda tangan yang diubah setelah token dibuat (tampered)', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])
    const token = await signToken(privateSigned, validClaims())
    const [header, payload, signature] = token.split('.')
    // Isi payload ditukar menjadi uid lain sementara tanda tangan tetap yang lama.
    const forgedPayload = encodeJson({ ...validClaims(), sub: 'uid-orang-lain' })

    const result = await verify(`${header}.${forgedPayload}.${signature}`, fetchImpl)

    expect(result).toEqual({ ok: false, reason: 'signature' })
    expect(forgedPayload).not.toBe(payload)
  })

  it('menolak token yang ditandatangani kunci lain dengan kid yang sama', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])
    const token = await signToken(otherPrivate, validClaims())

    expect(await verify(token, fetchImpl)).toEqual({ ok: false, reason: 'signature' })
  })

  it('menolak algoritma selain RS256, termasuk alg none', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])
    const unsigned = `${encodeJson({ alg: 'none', typ: 'JWT', kid: 'kunci-uji-1' })}.${encodeJson(validClaims())}.`

    expect(await verify(unsigned, fetchImpl)).toEqual({
      ok: false,
      reason: 'unsupported_algorithm',
    })

    // Header yang mengklaim algoritma lain ditolak sebelum kunci mana pun dipakai, bahkan
    // bila isi token sebenarnya ditandatangani RS256 oleh kunci yang sah.
    const forged = await signToken(privateSigned, validClaims(), { alg: 'HS256' })
    expect(await verify(forged, fetchImpl)).toEqual({ ok: false, reason: 'unsupported_algorithm' })
  })

  it('menolak bentuk token yang tidak sah', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])

    for (const bad of ['', '   ', 42, null, undefined, {}, 'satu-dua', 'a.b.c.d']) {
      expect(await verify(bad, fetchImpl)).toEqual({ ok: false, reason: 'malformed' })
    }

    const noKid = `${encodeJson({ alg: 'RS256' })}.${encodeJson(validClaims())}.AAA`
    expect(await verify(noKid, fetchImpl)).toEqual({ ok: false, reason: 'malformed' })

    const badBase64 = `${encodeJson({ alg: 'RS256', kid: 'k' })}.@@@@.AAA`
    expect(await verify(badBase64, fetchImpl)).toEqual({ ok: false, reason: 'malformed' })
  })

  it('menolak token yang lebih besar dari batas ukuran tanpa diproses', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])
    const huge = `${encodeJson({ alg: 'RS256', kid: 'kunci-uji-1' })}.${'A'.repeat(5000)}.AAA`

    expect(await verify(huge, fetchImpl)).toEqual({ ok: false, reason: 'too_large' })
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('menolak subject kosong, terlalu panjang, atau berisi karakter tak sah', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])

    for (const sub of ['', 'a'.repeat(129), 'uid dengan spasi', 'uid!']) {
      const token = await signToken(privateSigned, validClaims({ sub }))
      expect(await verify(token, fetchImpl)).toEqual({ ok: false, reason: 'subject_invalid' })
    }
  })

  it('memerlukan exp numerik pada payload', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])
    const claims = validClaims()
    delete claims.exp
    const token = await signToken(privateSigned, claims)

    expect(await verify(token, fetchImpl)).toEqual({ ok: false, reason: 'payload_invalid' })
  })

  it('gagal-tutup bila endpoint JWKS tidak dapat dijangkau', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('jaringan putus')
    }) as unknown as typeof fetch

    const token = await signToken(privateSigned, validClaims())
    expect(await verify(token, fetchImpl)).toEqual({ ok: false, reason: 'key_unavailable' })
  })

  it('gagal-tutup bila JWKS balasan tidak sah', async () => {
    const fetchImpl = vi.fn(async () => new Response('bukan json', { status: 200 })) as unknown as typeof fetch

    const token = await signToken(privateSigned, validClaims())
    expect(await verify(token, fetchImpl)).toEqual({ ok: false, reason: 'key_unavailable' })
  })

  it('menolak kid yang tidak ada di JWKS', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])
    const token = await signToken(privateSigned, validClaims(), { kid: 'kunci-tak-dikenal' })

    expect(await verify(token, fetchImpl)).toEqual({ ok: false, reason: 'key_unavailable' })
  })

  it('membatasi penyegaran paksa ketika kid asing datang bertubi-tubi', async () => {
    const calls: string[] = []
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }], calls)

    for (let index = 0; index < 8; index += 1) {
      const token = await signToken(privateSigned, validClaims(), {
        kid: `kid-acak-${index}`,
      })
      expect(await verify(token, fetchImpl)).toEqual({ ok: false, reason: 'key_unavailable' })
    }

    // Satu pemuatan awal + satu penyegaran paksa. Tanpa batas, tiap token berisi kid acak
    // (input penyerang) menambah satu permintaan keluar ke Google.
    expect(calls).toHaveLength(2)
  })

  it('membolehkan penyegaran paksa lagi setelah cooldown kunci lewat', async () => {
    const calls: string[] = []
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }], calls)
    const foreign = await signToken(privateSigned, validClaims(), { kid: 'kid-acak-1' })

    expect(await verify(foreign, fetchImpl)).toEqual({ ok: false, reason: 'key_unavailable' })
    expect(calls).toHaveLength(2)

    // now digeser lewat JWKS_RETRY_COOLDOWN_MS (masih jauh sebelum exp token), jadi kid
    // asing berikutnya boleh memicu satu penyegaran baru.
    const later = () => NOW + 61_000
    expect(await verify(foreign, fetchImpl, { now: later })).toEqual({
      ok: false,
      reason: 'key_unavailable',
    })
    expect(calls.length).toBeGreaterThan(2)
  })

  it('menyegarkan kunci satu kali ketika kid belum dikenal', async () => {
    const calls: string[] = []
    const rota: Array<Array<Record<string, unknown>>> = [
      [{ kid: 'kunci-uji-1', ...publicJwk }],
      [{ kid: 'kunci-baru-2', ...otherJwk }],
    ]
    let index = 0
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      calls.push(String(input))
      const keys = rota[Math.min(index, rota.length - 1)] ?? []
      index += 1
      return new Response(JSON.stringify({ keys }), {
        status: 200,
        headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600' },
      })
    }) as unknown as typeof fetch

    const old = await signToken(privateSigned, validClaims())
    expect((await verify(old, fetchImpl)).ok).toBe(true)

    const rotated = await signToken(otherPrivate, validClaims({ sub: 'uid-setelah-rotasi' }), {
      kid: 'kunci-baru-2',
    })
    const result = await verify(rotated, fetchImpl)

    expect(result.ok).toBe(true)
    if (result.ok) expect(result.uid).toBe('uid-setelah-rotasi')
    // Tidak ada permintaan ke URL lain selain endpoint kunci yang tetap.
    expect(new Set(calls)).toEqual(new Set([FIREBASE_JWKS_URL]))
  })

  it('memakai cache kunci sehingga JWKS tidak dikueri tiap permintaan', async () => {
    const calls: string[] = []
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }], calls)
    const token = await signToken(privateSigned, validClaims())

    for (let index = 0; index < 5; index += 1) {
      expect((await verify(token, fetchImpl)).ok).toBe(true)
    }
    expect(calls).toHaveLength(1)
  })

  it('tidak memakai proyek lain bila projectId tidak dikonfigurasi', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])
    const token = await signToken(privateSigned, validClaims())

    expect(
      await verifyFirebaseIdToken(token, { projectId: '', fetchImpl, now: () => NOW }),
    ).toEqual({ ok: false, reason: 'project_not_configured' })
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('tidak pernah membocorkan nilai token pada hasil', async () => {
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }])
    const token = await signToken(privateSigned, validClaims({ sub: 'uid-rahasia-uji' }))

    const accepted = await verify(token, fetchImpl)
    const rejected = await verifyFirebaseIdToken(`${token}x`, {
      projectId: PROJECT,
      fetchImpl,
      now: () => NOW,
    })

    expect(JSON.stringify(accepted)).not.toContain(token.slice(0, 24))
    expect(JSON.stringify(rejected)).not.toContain(token.slice(0, 24))
  })
})

function unsignedToken(claims: Record<string, unknown>, header: Record<string, unknown> = {}): string {
  return `${encodeJson({ alg: 'none', typ: 'JWT', ...header })}.${encodeJson(claims)}.`
}

function emulatorFetch(option: {
  localId?: string | null
  status?: number
  throwOnLookup?: boolean
  calls?: string[]
} = {}) {
  const calls = option.calls ?? []
  const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    calls.push(url)
    if (option.throwOnLookup) throw new Error('emulator mati')
    if (option.status && option.status !== 200) {
      return new Response(JSON.stringify({ error: { message: 'INVALID_IDENTIFIER' } }), {
        status: option.status,
        headers: { 'content-type': 'application/json' },
      })
    }
    return new Response(
      JSON.stringify({ users: option.localId === null ? [] : [{ localId: option.localId }] }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    )
  })
  return fetchImpl as unknown as typeof fetch
}

function verifyEmulator(
  token: string,
  fetchImpl: typeof fetch,
  emulatorHost = '127.0.0.1:9099',
) {
  return verifyFirebaseIdToken(token, {
    projectId: PROJECT,
    fetchImpl,
    now: () => NOW,
    emulatorHost,
  })
}

describe('VGL-40 — jalur Auth Emulator lokal', () => {
  const UID = 'uid-emulator-1'

  it('menerima token alg none yang diakui emulator loopback, dan mengonfirmasi lewat lookup', async () => {
    const calls: string[] = []
    const result = await verifyEmulator(
      unsignedToken(validClaims({ sub: UID })),
      emulatorFetch({ localId: UID, calls }),
    )

    expect(result).toEqual({ ok: true, uid: UID, email: null, providerId: 'password' })
    expect(calls).toHaveLength(1)
    expect(calls[0]).toContain('http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:lookup')
    // Kunci lookup adalah penanda tetap, bukan API key proyek.
    expect(calls[0]).toContain('key=veriguard-lokal')
  })

  it('menolak ketika emulator tidak mengenali token (localId berbeda atau kosong)', async () => {
    expect(
      await verifyEmulator(unsignedToken(validClaims({ sub: UID })), emulatorFetch({ localId: 'uid-lain' })),
    ).toEqual({ ok: false, reason: 'emulator_unverified' })
    expect(
      await verifyEmulator(unsignedToken(validClaims({ sub: UID })), emulatorFetch({ localId: null })),
    ).toEqual({ ok: false, reason: 'emulator_unverified' })
    expect(
      await verifyEmulator(unsignedToken(validClaims({ sub: UID })), emulatorFetch({ status: 400 })),
    ).toEqual({ ok: false, reason: 'emulator_unverified' })
  })

  it('menolak tanpa menyentuh jaringan ketika emulator tidak dapat dihubungi', async () => {
    const result = await verifyEmulator(
      unsignedToken(validClaims({ sub: UID })),
      emulatorFetch({ throwOnLookup: true }),
    )
    expect(result).toEqual({ ok: false, reason: 'emulator_unavailable' })
  })

  it('tetap menolak alg none bila emulator host tidak di-set atau bukan loopback', async () => {
    const fetchImpl = emulatorFetch({ localId: UID })
    const token = unsignedToken(validClaims({ sub: UID }))

    expect(await verify(token, fetchImpl)).toEqual({ ok: false, reason: 'unsupported_algorithm' })
    for (const host of ['', 'scan.example.com', 'https://emulator.example.com:9099', '10.0.0.5:9099', '0.0.0.0:9099']) {
      expect(await verifyEmulator(token, fetchImpl, host)).toEqual({
        ok: false,
        reason: 'unsupported_algorithm',
      })
    }
    // Tidak ada satu pun permintaan lookup untuk host yang tidak dipercaya.
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('tidak memangkas validasi klaim pada jalur emulator', async () => {
    const fetchImpl = emulatorFetch({ localId: UID })
    const seconds = Math.floor(NOW / 1000)

    expect(await verifyEmulator(unsignedToken(validClaims({ sub: UID, iss: 'https://lain.example.com' })), fetchImpl)).toEqual({
      ok: false,
      reason: 'issuer_mismatch',
    })
    expect(await verifyEmulator(unsignedToken(validClaims({ sub: UID, aud: 'proyek-lain' })), fetchImpl)).toEqual({
      ok: false,
      reason: 'audience_mismatch',
    })
    expect(await verifyEmulator(unsignedToken(validClaims({ sub: UID, exp: seconds - 7_200 })), fetchImpl)).toEqual({
      ok: false,
      reason: 'expired',
    })
    expect(await verifyEmulator(unsignedToken(validClaims({ sub: '' })), fetchImpl)).toEqual({
      ok: false,
      reason: 'subject_invalid',
    })
    // Header yang menyertakan kid tambahan tidak mengubah jalur emulator.
    expect(
      await verifyEmulator(unsignedToken(validClaims({ sub: UID }), { kid: 'x' }), fetchImpl),
    ).toEqual({ ok: true, uid: UID, email: null, providerId: 'password' })
  })

  it('token RS256 produksi tetap diverifikasi lewat JWKS walau emulator host ter-set', async () => {
    const calls: string[] = []
    const fetchImpl = jwksFetch([{ kid: 'kunci-uji-1', ...publicJwk }], calls)
    const token = await signToken(privateSigned, validClaims())

    const result = await verifyFirebaseIdToken(token, {
      projectId: PROJECT,
      fetchImpl,
      now: () => NOW,
      emulatorHost: '127.0.0.1:9099',
    })

    expect(result).toMatchObject({ ok: true, uid: 'abcDEF123_-uid' })
    expect(calls.some((url) => url === FIREBASE_JWKS_URL)).toBe(true)
  })

  it('badan respons lookup tidak pernah membocorkan token ke hasil verifikasi', async () => {
    const token = unsignedToken(validClaims({ sub: UID }))
    const result = await verifyEmulator(token, emulatorFetch({ localId: UID }))
    expect(JSON.stringify(result)).not.toContain(token.slice(0, 24))
  })
})

describe('emulatorOriginFor', () => {
  it('hanya menerima loopback', () => {
    for (const value of [
      '127.0.0.1:9099',
      'localhost:9099',
      '[::1]:9099',
      '127.0.1.1',
      'http://localhost:9099',
      '127.0.0.1:9099/',
    ]) {
      expect(emulatorOriginFor(value)).toMatch(/^http:\/\//)
    }
  })

  it('menolak host eksternal, nilai kosong, dan port tidak sah', () => {
    for (const value of ['', '   ', 'example.com', 'https://idp.example.com', '10.1.2.3:9099', '127.0.0.1:0', '127.0.0.1:99999', 'localhost;rm', '127.0.0.1:9099/evil', '::1:9099']) {
      expect(emulatorOriginFor(value)).toBeNull()
    }
    expect(emulatorOriginFor(null)).toBeNull()
    expect(emulatorOriginFor(undefined)).toBeNull()
  })
})

describe('readBearerToken', () => {  it('mengambil token dari header Authorization Bearer', () => {
    expect(readBearerToken('Bearer abc.def.ghi')).toBe('abc.def.ghi')
    expect(readBearerToken('bearer abc.def.ghi')).toBe('abc.def.ghi')
    expect(readBearerToken('  Bearer   abc.def.ghi  ')).toBe('abc.def.ghi')
  })

  it('mengabaikan header tanpa token atau skema lain', () => {
    expect(readBearerToken(null)).toBeNull()
    expect(readBearerToken(undefined)).toBeNull()
    expect(readBearerToken('')).toBeNull()
    expect(readBearerToken('Bearer')).toBeNull()
    expect(readBearerToken('Bearer    ')).toBeNull()
    expect(readBearerToken('Basic abc')).toBeNull()
  })
})

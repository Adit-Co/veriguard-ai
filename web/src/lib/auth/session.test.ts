import { describe, expect, it, vi } from 'vitest'
import type { Auth, User } from 'firebase/auth'
import { authorizationHeader } from './session'

function authWith(user: Partial<User> | null): Auth {
  return { currentUser: user as User | null } as unknown as Auth
}

describe('authorizationHeader (P1-2)', () => {
  it('mengirim bearer saat ada sesi aktif', async () => {
    const readToken = vi.fn(async () => 'id-token-uji')
    const header = await authorizationHeader({
      resolveAuth: () => authWith({ uid: 'u1' }),
      readToken,
    })

    expect(header).toEqual({ Authorization: 'Bearer id-token-uji' })
    expect(readToken).toHaveBeenCalledWith(expect.objectContaining({ uid: 'u1' }), false)
  })

  it('tetap tanpa header ketika tidak ada aplikasi, tidak ada auth, atau tidak ada user', async () => {
    expect(await authorizationHeader({ resolveAuth: () => null })).toEqual({})
    expect(await authorizationHeader({ resolveAuth: () => authWith(null) })).toEqual({})
    expect(await authorizationHeader({ resolveAuth: () => authWith({}), readToken: async () => '' })).toEqual({})
  })

  it('gagal-lembut ke tamu bila pengambilan token gagal', async () => {
    const header = await authorizationHeader({
      resolveAuth: () => authWith({ uid: 'u1' }),
      readToken: async () => {
        throw new Error('token unavailable')
      },
    })

    expect(header).toEqual({})
  })

  it('meneruskan permintaan refresh token', async () => {
    const readToken = vi.fn(async () => 'token-baru')
    await authorizationHeader({ resolveAuth: () => authWith({ uid: 'u1' }), readToken }, true)

    expect(readToken).toHaveBeenCalledWith(expect.objectContaining({ uid: 'u1' }), true)
  })

  it('tidak pernah mengembalikan header kosong yang berisi kata kunci token', async () => {
    const header = await authorizationHeader({
      resolveAuth: () => authWith({ uid: 'u1' }),
      readToken: async () => 'jwt.signature.rahasia',
    })

    expect(Object.keys(header)).toEqual(['Authorization'])
    expect(header.Authorization).toBe('Bearer jwt.signature.rahasia')
  })
})

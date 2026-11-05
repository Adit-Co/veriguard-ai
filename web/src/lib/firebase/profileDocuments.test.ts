import { describe, expect, it } from 'vitest'
import {
  buildUserProfileDocument,
  isUserProfileDocument,
  readProfileCreatedAt,
  readProfileUsername,
} from './profileDocuments'

const NOW = '2026-10-21T10:00:00.000Z'
const CREATED_AT = '2025-01-02T03:04:05.000Z'

describe('dokumen profil Firestore', () => {
  it('membangun profil dengan email dan nama yang dinormalisasi', () => {
    const profile = buildUserProfileDocument(
      {
        uid: 'user-1',
        email: '  pengguna@contoh.com ',
        displayName: '  Pengguna Uji  ',
      },
      null,
      NOW,
    )

    expect(profile).toEqual({
      uid: 'user-1',
      email: 'pengguna@contoh.com',
      displayName: 'Pengguna Uji',
      username: null,
      createdAt: NOW,
      lastLoginAt: NOW,
    })
    expect(isUserProfileDocument(profile, 'user-1')).toBe(true)
  })

  it('menyalin username yang sudah dinormalisasi ke dokumen profil', () => {
    const profile = buildUserProfileDocument(
      { uid: 'user-1', email: 'a@contoh.com', displayName: 'A', username: 'Gyat123' },
      null,
      NOW,
    )

    expect(profile.username).toBe('gyat123')
    expect(isUserProfileDocument(profile, 'user-1')).toBe(true)
  })

  it('tidak menyalin username yang bentuknya tidak sah ke profil', () => {
    for (const username of ['ab', 'pengguna-baru', 'ada spasi', '', null, undefined]) {
      const profile = buildUserProfileDocument(
        { uid: 'user-1', email: 'a@contoh.com', displayName: 'A', username },
        null,
        NOW,
      )
      expect(profile.username).toBeNull()
    }
  })

  it('readProfileUsername hanya membaca nilai milik UID yang sama', () => {
    expect(readProfileUsername({ uid: 'user-1', username: 'gyat123' }, 'user-1')).toBe('gyat123')
    expect(readProfileUsername({ uid: 'user-2', username: 'gyat123' }, 'user-1')).toBeNull()
    expect(readProfileUsername({ uid: 'user-1' }, 'user-1')).toBeNull()
    expect(readProfileUsername({ uid: 'user-1', username: null }, 'user-1')).toBeNull()
    expect(readProfileUsername(undefined, 'user-1')).toBeNull()
  })

  it('dokumen profil lama tanpa field username tetap dianggap sah', () => {
    const legacy = {
      uid: 'user-1',
      email: 'a@contoh.com',
      displayName: 'A',
      createdAt: CREATED_AT,
      lastLoginAt: NOW,
    }

    expect(isUserProfileDocument(legacy, 'user-1')).toBe(true)
    expect(isUserProfileDocument({ ...legacy, username: 'Gyat123' }, 'user-1')).toBe(false)
    expect(isUserProfileDocument({ ...legacy, username: 42 }, 'user-1')).toBe(false)
  })

  it('mempertahankan createdAt dan memperbarui lastLoginAt', () => {
    const profile = buildUserProfileDocument(
      { uid: 'user-1', email: null, displayName: null },
      CREATED_AT,
      NOW,
    )

    expect(profile.createdAt).toBe(CREATED_AT)
    expect(profile.lastLoginAt).toBe(NOW)
    expect(profile.email).toBeNull()
    expect(profile.displayName).toBe('Pengguna')
  })

  it('tidak memakai createdAt rusak atau milik UID lain', () => {
    expect(readProfileCreatedAt({ uid: 'user-1', createdAt: 'bukan-tanggal' }, 'user-1')).toBeNull()
    expect(readProfileCreatedAt({ uid: 'user-2', createdAt: CREATED_AT }, 'user-1')).toBeNull()
    expect(readProfileCreatedAt(undefined, 'user-1')).toBeNull()
  })

  it('menolak dokumen lintas pengguna dan struktur yang tidak valid', () => {
    const profile = buildUserProfileDocument(
      { uid: 'user-1', email: 'a@contoh.com', displayName: 'A' },
      null,
      NOW,
    )

    expect(isUserProfileDocument(profile, 'user-2')).toBe(false)
    expect(isUserProfileDocument({ ...profile, uid: '' })).toBe(false)
    expect(isUserProfileDocument({ ...profile, displayName: '' })).toBe(false)
    expect(isUserProfileDocument({ ...profile, createdAt: 'rusak' })).toBe(false)
    expect(isUserProfileDocument({ ...profile, email: 42 })).toBe(false)
  })
})

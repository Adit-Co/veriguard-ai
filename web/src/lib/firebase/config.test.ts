import { describe, expect, it } from 'vitest'
import { resolveFirebaseConfig } from './config'

const validEnv = {
  VITE_FIREBASE_API_KEY: 'api-key-publik',
  VITE_FIREBASE_AUTH_DOMAIN: 'contoh.firebaseapp.com',
  VITE_FIREBASE_PROJECT_ID: 'contoh-proyek',
  VITE_FIREBASE_APP_ID: '1:123:web:abc',
}

describe('konfigurasi Firebase', () => {
  it('menonaktifkan Firebase saat konfigurasi wajib belum lengkap', () => {
    const state = resolveFirebaseConfig({ VITE_FIREBASE_PROJECT_ID: 'contoh-proyek' })

    expect(state.configured).toBe(false)
    expect(state.config).toBeNull()
    expect(state.missingKeys).toEqual([
      'VITE_FIREBASE_API_KEY',
      'VITE_FIREBASE_AUTH_DOMAIN',
      'VITE_FIREBASE_APP_ID',
    ])
  })

  it('menganggap nilai kosong atau spasi sebagai tidak tersedia', () => {
    const state = resolveFirebaseConfig({
      ...validEnv,
      VITE_FIREBASE_API_KEY: '   ',
    })

    expect(state.configured).toBe(false)
    expect(state.missingKeys).toContain('VITE_FIREBASE_API_KEY')
  })

  it('membangun konfigurasi tanpa nilai opsional yang kosong', () => {
    const state = resolveFirebaseConfig({
      ...validEnv,
      VITE_FIREBASE_STORAGE_BUCKET: ' ',
      VITE_FIREBASE_MESSAGING_SENDER_ID: '123456789',
    })

    expect(state.configured).toBe(true)
    expect(state.config).toEqual({
      apiKey: 'api-key-publik',
      authDomain: 'contoh.firebaseapp.com',
      projectId: 'contoh-proyek',
      appId: '1:123:web:abc',
      messagingSenderId: '123456789',
    })
    expect(state.config).not.toHaveProperty('storageBucket')
  })
})

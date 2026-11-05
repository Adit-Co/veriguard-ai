import { describe, expect, it } from 'vitest'
import { withLocalDevOrigins } from '../src/index.js'

describe('origin dev lokal pada server lokal', () => {
  it('selalu menyertakan origin Vite localhost walaupun .env membatasi daftar', () => {
    const merged = withLocalDevOrigins('http://localhost:5173,http://127.0.0.1:5173')
    expect(merged).toContain('http://localhost:5173')
    expect(merged).toContain('http://localhost:5174')
    expect(merged.split(',')).toHaveLength(10)
  })

  it('mempertahankan origin produksi dari konfigurasi dan tidak duplikasi', () => {
    const merged = withLocalDevOrigins(
      'https://YOUR_FIREBASE_PROJECT_ID.web.app,http://localhost:5173',
    )
    expect(merged).toContain('https://YOUR_FIREBASE_PROJECT_ID.web.app')
    expect(merged.split(',').filter((entry) => entry === 'http://localhost:5173')).toHaveLength(1)
  })

  it('menangani konfigurasi kosong', () => {
    expect(withLocalDevOrigins(undefined).split(',')).toHaveLength(10)
  })
})

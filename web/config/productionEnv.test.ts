import { describe, expect, it } from 'vitest'
import {
  formatProductionEnvIssues,
  validateProductionEnv,
} from './productionEnv.ts'

const validEnv = {
  VITE_SCANNER_WORKER_URL: 'https://scanner.contoh.id',
}

describe('validasi environment produksi', () => {
  it('menerima endpoint HTTPS non-lokal', () => {
    expect(validateProductionEnv(validEnv)).toEqual([])
  })

  it('menerima VITE_API_BASE_URL sebagai endpoint utama', () => {
    expect(
      validateProductionEnv({
        VITE_API_BASE_URL: 'https://api.contoh.id',
        VITE_SCANNER_WORKER_URL: 'http://127.0.0.1:8787',
      }),
    ).toEqual([])
  })

  it('menghentikan build tanpa endpoint tanpa membuat pengganti', () => {
    const issues = validateProductionEnv({})

    expect(issues).toHaveLength(1)
    expect(issues[0].variable).toContain('VITE_API_BASE_URL')
    expect(issues[0].message).toMatch(/wajib diisi/i)
    expect(issues[0].message).toMatch(/tidak ada endpoint pengganti/i)
  })

  it.each([
    'http://127.0.0.1:8787',
    'http://localhost:8787',
    'https://localhost/scanner',
    'https://127.0.0.1/scanner',
    'https://[::1]/scanner',
    'https://scanner.localhost',
    'https://0.0.0.0/scanner',
  ])('menolak endpoint lokal %s', (endpoint) => {
    const issues = validateProductionEnv({ VITE_SCANNER_WORKER_URL: endpoint })

    expect(issues.some((issue) => /host lokal|loopback/i.test(issue.message))).toBe(true)
  })

  it('menolak endpoint non-HTTPS walau bukan host lokal', () => {
    const issues = validateProductionEnv({
      VITE_SCANNER_WORKER_URL: 'http://scanner.contoh.id',
    })

    expect(issues.some((issue) => /HTTPS/i.test(issue.message))).toBe(true)
  })

  it('menolak URL yang bukan absolut, kredensial tersemat, dan emulator produksi', () => {
    const malformed = validateProductionEnv({
      VITE_SCANNER_WORKER_URL: 'scanner.contoh.id',
    })
    expect(malformed.some((issue) => /URL absolut/i.test(issue.message))).toBe(true)

    const credentialed = validateProductionEnv({
      VITE_SCANNER_WORKER_URL: 'https://pengguna:rahasia@scanner.contoh.id',
    })
    expect(credentialed.some((issue) => /kredensial/i.test(issue.message))).toBe(true)

    const emulators = validateProductionEnv({
      ...validEnv,
      VITE_USE_EMULATORS: ' TRUE ',
    })
    expect(emulators.some((issue) => issue.variable === 'VITE_USE_EMULATORS')).toBe(true)
  })

  it('menolak jalur Cloud Functions lama di build produksi', () => {
    const issues = validateProductionEnv({
      ...validEnv,
      VITE_COMMUNITY_BACKEND: 'functions',
    })

    expect(issues.some((issue) => issue.variable === 'VITE_COMMUNITY_BACKEND')).toBe(true)
  })

  it('menolak bendera login demo di build produksi (true dan 1)', () => {
    for (const value of ['true', '1', ' TRUE ']) {
      const issues = validateProductionEnv({
        ...validEnv,
        VITE_ENABLE_DEMO_LOGIN: value,
      })
      expect(issues.some((issue) => issue.variable === 'VITE_ENABLE_DEMO_LOGIN')).toBe(true)
    }

    // Nonaktif (default) tidak menambah masalah, supaya build produksi normal tetap lolos.
    const clean = validateProductionEnv({ ...validEnv, VITE_ENABLE_DEMO_LOGIN: 'false' })
    expect(clean).toEqual([])
  })

  it('memformat pesan yang menyebut semua variabel bermasalah', () => {
    const message = formatProductionEnvIssues([
      { variable: 'VITE_SCANNER_WORKER_URL', message: 'contoh masalah' },
    ])

    expect(message).toContain('VITE_SCANNER_WORKER_URL: contoh masalah')
    expect(message).toContain('placeholder')
  })
})

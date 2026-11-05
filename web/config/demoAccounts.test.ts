import { describe, expect, it } from 'vitest'
import {
  DEMO_ACCOUNTS,
  DEMO_LOGIN_ENV_FLAG,
  MAX_DEMO_REQUEST_BYTES,
  demoAccountFor,
  demoLoginAvailability,
  emulatorCustomToken,
  isLoopbackEmulatorUrl,
  parseDemoSessionRequest,
} from './demoAccounts.ts'

// Pagar sisi server. Yang diuji adalah bahwa peran TIDAK PERNAH dibaca dari isi permintaan:
// satu-satunya bidang yang diterima adalah kunci akun, dan kunci itu dipetakan ke akun + peran
// yang sudah tetap di berkas ini.

const COMPLETE_ENV = {
  [DEMO_LOGIN_ENV_FLAG]: 'true',
  VITE_USE_EMULATORS: 'true',
  VITE_AUTH_EMULATOR_URL: 'http://127.0.0.1:9099',
  VITE_FIRESTORE_EMULATOR_HOST: '127.0.0.1:8080',
  VITE_FIREBASE_PROJECT_ID: 'demo-project',
  VITE_FIREBASE_API_KEY: 'demo-web-key',
}

function request(text: string) {
  return parseDemoSessionRequest(text)
}

describe('permintaan sesi demo hanya mengenal kunci akun', () => {
  it('menerima kedua kunci demo dan memetakannya ke peran sisi server', () => {
    expect(request('{"account":"admin"}')).toEqual({ account: DEMO_ACCOUNTS.admin })
    expect(request('{"account":"user"}')).toEqual({ account: DEMO_ACCOUNTS.user })
    expect(demoAccountFor('admin')?.role).toBe('admin')
    expect(demoAccountFor('user')?.role).toBe('user')
  })

  it('menolak permintaan yang mengklaim email atau peran', () => {
    expect(request(`{"account":"user","email":"${DEMO_ACCOUNTS.admin.email}"}`)).toEqual({
      error: 'unexpected-field',
    })
    expect(request('{"account":"user","role":"admin"}')).toEqual({
      error: 'unexpected-field',
    })
    expect(request('{"account":"user","admin":true}')).toEqual({ error: 'unexpected-field' })
    expect(request(`{"email":"${DEMO_ACCOUNTS.admin.email}"}`)).toEqual({
      error: 'unexpected-field',
    })
    expect(request('{"role":"admin"}')).toEqual({ error: 'unexpected-field' })
  })

  it('menolak kunci yang bukan akun demo', () => {
    for (const text of [
      '{"account":"ADMIN"}',
      '{"account":"superadmin"}',
      '{"account":""}',
      '{"account":null}',
      '{"account":1}',
      '{}',
      '[]',
      '"admin"',
      'bukan json',
    ]) {
      const parsed = request(text)
      expect('account' in parsed).toBe(false)
    }
  })

  it('membatasi ukuran permintaan sebelum melakukan parsing', () => {
    expect(request(`{"account":"${'a'.repeat(MAX_DEMO_REQUEST_BYTES)}"}`)).toEqual({
      error: 'too-large',
    })
  })
})

describe('token custom emulator tidak membawa peran', () => {
  it('hanya berisi uid', () => {
    const token = emulatorCustomToken('uid-demo-1')
    expect(JSON.parse(token)).toEqual({ uid: 'uid-demo-1' })
    expect(token).not.toContain('admin')
  })
})

describe('isLoopbackEmulatorUrl', () => {
  it('hanya menerima http pada host loopback', () => {
    for (const value of [
      'http://127.0.0.1:9099',
      'http://localhost:9099',
      'http://[::1]:9099',
      'http://auth.localhost:9099',
    ]) {
      expect(isLoopbackEmulatorUrl(value)).toBe(true)
    }

    for (const value of [
      '',
      'https://127.0.0.1:9099',
      'http://169.254.169.254',
      'http://auth.example.com',
      'http://[::ffff:8.8.8.8]:9099',
      'bukan url',
    ]) {
      expect(isLoopbackEmulatorUrl(value)).toBe(false)
    }
  })
})

describe('pagar login demo defaultnya nonaktif', () => {
  it('menolak ketika bendera tidak diisi', () => {
    const gate = demoLoginAvailability({}, 'development')
    expect(gate.available).toBe(false)
    expect(gate.reasons.join(' ')).toContain(DEMO_LOGIN_ENV_FLAG)
  })

  it('menolak pada NODE_ENV=production meskipun bendera dan emulator lengkap', () => {
    const gate = demoLoginAvailability(COMPLETE_ENV, 'production')
    expect(gate.available).toBe(false)
    expect(gate.reasons).toContain('Login demo tidak diizinkan pada NODE_ENV=production.')
  })

  it('menolak tanpa emulator, tanpa host loopback, dan tanpa konfigurasi lengkap', () => {
    expect(demoLoginAvailability({ ...COMPLETE_ENV, VITE_USE_EMULATORS: 'false' }, 'development').available).toBe(
      false,
    )
    expect(
      demoLoginAvailability(
        { ...COMPLETE_ENV, VITE_AUTH_EMULATOR_URL: 'https://demo-project.firebaseapp.com' },
        'development',
      ).available,
    ).toBe(false)
    expect(
      demoLoginAvailability({ ...COMPLETE_ENV, VITE_FIRESTORE_EMULATOR_HOST: '' }, 'development').available,
    ).toBe(false)
    expect(
      demoLoginAvailability({ ...COMPLETE_ENV, VITE_FIREBASE_API_KEY: '' }, 'development').available,
    ).toBe(false)
  })

  it('mengizinkan hanya bila seluruh syarat mode pengembangan terpenuhi', () => {
    const gate = demoLoginAvailability(COMPLETE_ENV, 'development')
    expect(gate).toEqual({ available: true, reasons: [] })
  })
})

import { describe, expect, it } from 'vitest'
import {
  EMULATOR_ENV_VAR,
  isEmulatorRequested,
  resolveDevEmulator,
  withDevEmulatorDecision,
} from './devAuthEnv.ts'

// Jaminan VGL-42: berkas .env tidak lagi bisa mengarahkan login normal ke Auth Emulator.
// Yang membuka emulator adalah proses peluncur dev server, bukan isi berkas.

const FILE_EMULATOR = { [EMULATOR_ENV_VAR]: 'true', NODE_ENV: 'development' }

describe('gerbang emulator dev server (VGL-42)', () => {
  it('mengabaikan permintaan emulator dari berkas .env', () => {
    expect(resolveDevEmulator({}, FILE_EMULATOR)).toEqual({
      active: false,
      source: 'berkas-diabaikan',
      fileRequested: true,
    })
  })

  it('mengaktifkan emulator hanya bila proses yang meminta', () => {
    expect(resolveDevEmulator({ [EMULATOR_ENV_VAR]: 'true' }, {})).toEqual({
      active: true,
      source: 'proses',
      fileRequested: false,
    })
    expect(resolveDevEmulator({ [EMULATOR_ENV_VAR]: ' TRUE ' }, FILE_EMULATOR).active).toBe(true)
  })

  it('tetap nonaktif ketika tidak ada yang meminta', () => {
    const decision = resolveDevEmulator({ [EMULATOR_ENV_VAR]: 'false' }, {})
    expect(decision).toEqual({ active: false, source: 'tidak-diminta', fileRequested: false })
  })

  it('menelan nilai yang bukan "true" apa adanya', () => {
    for (const value of ['1', 'yes', 'on', '', undefined]) {
      expect(isEmulatorRequested(value)).toBe(false)
    }
  })

  it('menulis keputusan ke env sisi Node tanpa menghapus kunci lain', () => {
    const env = { ...FILE_EMULATOR, VITE_ENABLE_DEMO_LOGIN: 'true', VITE_API_BASE_URL: 'x' }

    const off = withDevEmulatorDecision(env, resolveDevEmulator({}, env))
    expect(off[EMULATOR_ENV_VAR]).toBe('false')
    expect(off.VITE_ENABLE_DEMO_LOGIN).toBe('true')
    expect(off.VITE_API_BASE_URL).toBe('x')

    const on = withDevEmulatorDecision(env, resolveDevEmulator({ [EMULATOR_ENV_VAR]: 'true' }, env))
    expect(on[EMULATOR_ENV_VAR]).toBe('true')
  })

  it('env asli tidak termutasi oleh keputusan gerbang', () => {
    const env = { ...FILE_EMULATOR }
    withDevEmulatorDecision(env, resolveDevEmulator({}, env))
    expect(env[EMULATOR_ENV_VAR]).toBe('true')
  })
})

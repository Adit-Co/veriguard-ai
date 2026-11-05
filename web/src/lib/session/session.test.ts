import { beforeEach, describe, expect, it } from 'vitest'
import {
  DEFAULT_DISPLAY_NAME,
  endLocalDemoSession,
  getLocalDemoSession,
  MAX_DISPLAY_NAME_LENGTH,
  SESSION_STORAGE_KEY,
  startLocalDemoSession,
} from './session'

function createMemoryStorage(): Storage {
  const values = new Map<string, string>()

  return {
    get length() {
      return values.size
    },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => {
      values.delete(key)
    },
    setItem: (key, value) => {
      values.set(key, value)
    },
  }
}

describe('sesi demo lokal', () => {
  beforeEach(() => {
    Reflect.deleteProperty(globalThis, 'window')
    endLocalDemoSession()
  })

  it('memulai sesi dengan nama tampilan yang dibersihkan', () => {
    const session = startLocalDemoSession('  Penguji Demo  ')

    expect(session.kind).toBe('local-demo')
    expect(session.displayName).toBe('Penguji Demo')
    expect(session.startedAt).not.toBe('')
    expect(getLocalDemoSession()).toEqual(session)
  })

  it('memakai nama default dan membatasi panjang nama', () => {
    expect(startLocalDemoSession('   ').displayName).toBe(DEFAULT_DISPLAY_NAME)
    expect(startLocalDemoSession('a'.repeat(80)).displayName).toHaveLength(MAX_DISPLAY_NAME_LENGTH)
  })

  it('menyimpan dan mengakhiri sesi di penyimpanan lokal', () => {
    const storage = createMemoryStorage()
    Object.defineProperty(globalThis, 'window', {
      value: { localStorage: storage },
      configurable: true,
    })

    try {
      const session = startLocalDemoSession('Demo Lokal')
      expect(JSON.parse(storage.getItem(SESSION_STORAGE_KEY) ?? '{}')).toEqual(session)

      endLocalDemoSession()
      expect(storage.getItem(SESSION_STORAGE_KEY)).toBeNull()
      expect(getLocalDemoSession()).toBeNull()
    } finally {
      Reflect.deleteProperty(globalThis, 'window')
    }
  })

  it('menolak data sesi rusak', () => {
    const storage = createMemoryStorage()
    storage.setItem(SESSION_STORAGE_KEY, JSON.stringify({ kind: 'firebase', email: 'a@b.c' }))
    Object.defineProperty(globalThis, 'window', {
      value: { localStorage: storage },
      configurable: true,
    })

    try {
      expect(getLocalDemoSession()).toBeNull()
    } finally {
      Reflect.deleteProperty(globalThis, 'window')
    }
  })
})

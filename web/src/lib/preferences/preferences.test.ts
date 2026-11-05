import { beforeEach, describe, expect, it } from 'vitest'
import {
  DEFAULT_PREFERENCES,
  getPreferences,
  PREFERENCES_STORAGE_KEY,
  resetPreferences,
  updatePreferences,
} from './preferences'

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

describe('preferensi lokal', () => {
  beforeEach(() => {
    Reflect.deleteProperty(globalThis, 'window')
    resetPreferences()
  })

  it('memakai default tautan dan gerakan normal', () => {
    expect(getPreferences()).toEqual(DEFAULT_PREFERENCES)
    expect(getPreferences().defaultScanMode).toBe('link')
  })

  it('menyimpan perubahan preferensi di penyimpanan lokal', () => {
    const storage = createMemoryStorage()
    Object.defineProperty(globalThis, 'window', {
      value: { localStorage: storage },
      configurable: true,
    })

    try {
      const next = updatePreferences({ defaultScanMode: 'message', reduceMotion: true })

      expect(next.defaultScanMode).toBe('message')
      expect(next.reduceMotion).toBe(true)
      expect(JSON.parse(storage.getItem(PREFERENCES_STORAGE_KEY) ?? '{}')).toEqual({
        defaultScanMode: 'message',
        reduceMotion: true,
        theme: 'light',
      })
      expect(getPreferences()).toEqual(next)
    } finally {
      Reflect.deleteProperty(globalThis, 'window')
    }
  })

  it('mengabaikan nilai tersimpan yang tidak valid', () => {
    const storage = createMemoryStorage()
    storage.setItem(
      PREFERENCES_STORAGE_KEY,
      JSON.stringify({ defaultScanMode: 'lainnya', reduceMotion: 'ya' }),
    )
    Object.defineProperty(globalThis, 'window', {
      value: { localStorage: storage },
      configurable: true,
    })

    try {
      expect(getPreferences()).toEqual(DEFAULT_PREFERENCES)
    } finally {
      Reflect.deleteProperty(globalThis, 'window')
    }
  })

  it('mengembalikan preferensi ke default saat direset', () => {
    updatePreferences({ defaultScanMode: 'message', reduceMotion: true })
    expect(resetPreferences()).toEqual(DEFAULT_PREFERENCES)
    expect(getPreferences()).toEqual(DEFAULT_PREFERENCES)
  })
})

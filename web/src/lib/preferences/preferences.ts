import type { ScanMode } from '../analysis/types'

export type ThemeMode = 'light' | 'dark'

export type Preferences = {
  defaultScanMode: ScanMode
  reduceMotion: boolean
  // VGL-33B: tema disimpan LOCAL (localStorage), tidak pernah ke Firebase maupun backend.
  theme: ThemeMode
}

export const PREFERENCES_STORAGE_KEY = 'veriguard.preferences.v1'

export const DEFAULT_PREFERENCES: Preferences = {
  defaultScanMode: 'link',
  reduceMotion: false,
  theme: 'light',
}

let memoryPreferences: Preferences = { ...DEFAULT_PREFERENCES }

function getStorage(): Storage | null {
  if (typeof window === 'undefined') return null

  try {
    const storage = window.localStorage
    const probe = '__veriguard_preferences_probe__'
    storage.setItem(probe, '1')
    storage.removeItem(probe)
    return storage
  } catch {
    return null
  }
}

function normalizePreferences(value: unknown): Preferences {
  if (!value || typeof value !== 'object') return { ...DEFAULT_PREFERENCES }

  const candidate = value as Record<string, unknown>

  return {
    defaultScanMode:
      candidate.defaultScanMode === 'message' ? 'message' : DEFAULT_PREFERENCES.defaultScanMode,
    reduceMotion:
      typeof candidate.reduceMotion === 'boolean'
        ? candidate.reduceMotion
        : DEFAULT_PREFERENCES.reduceMotion,
    theme: candidate.theme === 'dark' ? 'dark' : DEFAULT_PREFERENCES.theme,
  }
}

export function getPreferences(): Preferences {
  const storage = getStorage()
  if (!storage) return { ...memoryPreferences }

  try {
    const raw = storage.getItem(PREFERENCES_STORAGE_KEY)
    if (!raw) return { ...memoryPreferences }

    const preferences = normalizePreferences(JSON.parse(raw))
    memoryPreferences = preferences
    return { ...preferences }
  } catch {
    return { ...memoryPreferences }
  }
}

export function updatePreferences(patch: Partial<Preferences>): Preferences {
  const next = normalizePreferences({ ...getPreferences(), ...patch })
  memoryPreferences = next

  const storage = getStorage()
  if (storage) {
    try {
      storage.setItem(PREFERENCES_STORAGE_KEY, JSON.stringify(next))
    } catch {
      // Preferensi tetap berlaku di memori meski penyimpanan tidak tersedia.
    }
  }

  return { ...next }
}

export function resetPreferences(): Preferences {
  memoryPreferences = { ...DEFAULT_PREFERENCES }

  const storage = getStorage()
  if (storage) {
    try {
      storage.removeItem(PREFERENCES_STORAGE_KEY)
    } catch {
      // Abaikan; preferensi memori sudah kembali ke default.
    }
  }

  return { ...DEFAULT_PREFERENCES }
}

export function applyPreferences(preferences = getPreferences()): void {
  if (typeof document === 'undefined') return

  if (preferences.reduceMotion) {
    document.documentElement.dataset.reduceMotion = 'true'
  } else {
    delete document.documentElement.dataset.reduceMotion
  }

  // Atribut tema selalu ditulis (light maupun dark) supaya keadaan DOM satu-satunya sumber
  // kebenaran; script anti-flash di index.html menulis atribut yang sama sebelum paint.
  document.documentElement.dataset.theme = preferences.theme
  const themeColor = document.querySelector('meta[name="theme-color"]')
  if (themeColor) {
    themeColor.setAttribute('content', preferences.theme === 'dark' ? '#0B1220' : '#F8FAFC')
  }
}

// @vitest-environment jsdom

import { beforeEach, describe, expect, it } from 'vitest'
import {
  LOGIN_CLIENT_ID_STORAGE_KEY,
  LOGIN_COOLDOWN_STORAGE_KEY,
} from '../auth/loginGuard'
import { getPreferences, PREFERENCES_STORAGE_KEY } from '../preferences/preferences'
import { MULTI_SOURCE_STORAGE_KEY } from '../scanners/reportStore'
import { PENDING_SYNC_STORAGE_KEY } from '../scans/pendingSyncStore'
import { getLocalDemoSession, SESSION_STORAGE_KEY } from '../session/session'
import { listScans, SCAN_STORAGE_KEY } from '../storage/scanStore'
import { SITE_ANALYSIS_STORAGE_KEY } from '../website/analysisStore'
import { APP_LOCAL_STORAGE_KEYS, clearLocalAppData } from './localData'

function seedAppStorage(): void {
  window.localStorage.setItem(SCAN_STORAGE_KEY, '[{"rusak":true}]')
  window.localStorage.setItem(MULTI_SOURCE_STORAGE_KEY, '{"scan-1":{"rusak":true}}')
  window.localStorage.setItem(SITE_ANALYSIS_STORAGE_KEY, '{"scan-1":{"rusak":true}}')
  window.localStorage.setItem(
    SESSION_STORAGE_KEY,
    JSON.stringify({ kind: 'local-demo', displayName: 'Pengguna A', startedAt: new Date().toISOString() }),
  )
  window.localStorage.setItem(PREFERENCES_STORAGE_KEY, JSON.stringify({ defaultScanMode: 'message' }))
  window.localStorage.setItem(PENDING_SYNC_STORAGE_KEY, JSON.stringify({ uid: 'user-a', scanIds: ['scan-1'] }))
  window.localStorage.setItem(LOGIN_CLIENT_ID_STORAGE_KEY, 'web-abcdef0123456789')
  window.localStorage.setItem(
    LOGIN_COOLDOWN_STORAGE_KEY,
    JSON.stringify({ endsAt: Date.now() + 120_000, level: 1, failures: 1 }),
  )
}

describe('penghapusan seluruh data lokal aplikasi', () => {
  beforeEach(() => {
    window.localStorage.clear()
    clearLocalAppData()
  })

  it('mencatat setiap kunci yang ditulis aplikasi', () => {
    expect([...APP_LOCAL_STORAGE_KEYS].sort()).toEqual(
      [
        SCAN_STORAGE_KEY,
        MULTI_SOURCE_STORAGE_KEY,
        SITE_ANALYSIS_STORAGE_KEY,
        SESSION_STORAGE_KEY,
        PREFERENCES_STORAGE_KEY,
        PENDING_SYNC_STORAGE_KEY,
        LOGIN_CLIENT_ID_STORAGE_KEY,
        LOGIN_COOLDOWN_STORAGE_KEY,
      ].sort(),
    )
  })

  it('melepas seluruh kunci milik aplikasi sekaligus', () => {
    seedAppStorage()

    clearLocalAppData()

    for (const key of APP_LOCAL_STORAGE_KEYS) {
      expect(window.localStorage.getItem(key), `kunci ${key} masih ada`).toBeNull()
    }
    expect(listScans()).toHaveLength(0)
    expect(getLocalDemoSession()).toBeNull()
    expect(getPreferences().defaultScanMode).toBe('link')
  })

  it('tidak menyentuh penyimpanan milik layanan lain', () => {
    seedAppStorage()
    window.localStorage.setItem('firebaseLocalStorageDb', 'milik sdk')
    window.localStorage.setItem('capcha-token-cache', 'milik layanan')

    clearLocalAppData()

    expect(window.localStorage.getItem('firebaseLocalStorageDb')).toBe('milik sdk')
    expect(window.localStorage.getItem('capcha-token-cache')).toBe('milik layanan')
  })

  it('bekerja sama seperti saat belum ada akun yang masuk', () => {
    // Tidak ada jalur bersyarat pada fungsi ini: isi penyimpanan yang sama, hasil yang sama.
    seedAppStorage()
    const before = APP_LOCAL_STORAGE_KEYS.map((key) => window.localStorage.getItem(key))

    clearLocalAppData()

    expect(before.every((value) => value !== null)).toBe(true)
    expect(APP_LOCAL_STORAGE_KEYS.map((key) => window.localStorage.getItem(key))).toEqual(
      APP_LOCAL_STORAGE_KEYS.map(() => null),
    )
  })
})

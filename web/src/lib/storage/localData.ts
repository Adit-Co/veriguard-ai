import { PREFERENCES_STORAGE_KEY, resetPreferences } from '../preferences/preferences'
import {
  clearLoginGuardLocalState,
  LOGIN_CLIENT_ID_STORAGE_KEY,
  LOGIN_COOLDOWN_STORAGE_KEY,
} from '../auth/loginGuard'
import { MULTI_SOURCE_STORAGE_KEY, clearScanReports } from '../scanners/reportStore'
import { clearPendingSync, PENDING_SYNC_STORAGE_KEY } from '../scans/pendingSyncStore'
import { endLocalDemoSession, SESSION_STORAGE_KEY } from '../session/session'
import { SCAN_STORAGE_KEY, clearScans } from '../storage/scanStore'
import { clearSiteAnalyses, SITE_ANALYSIS_STORAGE_KEY } from '../website/analysisStore'

// Semua kunci localStorage milik VERIGUARD. Ditulis di satu tempat supaya "hapus data lokal"
// tidak pernah bergantung pada status login atau sumber riwayat yang sedang aktif.
export const APP_LOCAL_STORAGE_KEYS = [
  SCAN_STORAGE_KEY,
  MULTI_SOURCE_STORAGE_KEY,
  SITE_ANALYSIS_STORAGE_KEY,
  SESSION_STORAGE_KEY,
  PREFERENCES_STORAGE_KEY,
  PENDING_SYNC_STORAGE_KEY,
  LOGIN_CLIENT_ID_STORAGE_KEY,
  LOGIN_COOLDOWN_STORAGE_KEY,
] as const

/**
 * VGL-17: setiap kunci dihapus lewat modul pemiliknya, bukan `localStorage.clear()`, supaya
 * penyimpanan Firebase Auth (IndexedDB), cookie tantangan, dan data milik ekstensi peramban
 * tidak ikut tersapu. Riwayat akun di Firestore TIDAK dihapus oleh fungsi ini.
 */
export function clearLocalAppData(): void {
  clearScans()
  clearScanReports()
  clearSiteAnalyses()
  clearPendingSync()
  endLocalDemoSession()
  resetPreferences()
  clearLoginGuardLocalState()
}

import type { MultiSourceReport } from './types'
import { isMultiSourceReport } from './validate'
import {
  redactSecretFragments,
  redactSensitiveUrlForStorage,
  sensitiveUrlFragments,
} from './privacy'

export const MULTI_SOURCE_STORAGE_KEY = 'veriguard.multiSourceReports.v1'
export const MAX_SAVED_REPORTS = 30

let memoryReports: Record<string, MultiSourceReport> = {}

/**
 * VGL-12: laporan yang menandai URL-nya sensitif tidak boleh menyimpan target aslinya di
 * penyimpanan permanen. Penyamaran dipakai hanya bila benar-benar mengubah nilai, supaya
 * pembacaan riwayat berikutnya tidak menulis ulang tanpa perlu.
 */
export function toStoredReport(report: MultiSourceReport): MultiSourceReport {
  if (report.sensitiveUrl !== true) return report

  const safeTarget = redactSensitiveUrlForStorage(report.target)
  if (safeTarget === report.target) return report

  const fragments = sensitiveUrlFragments(report.target)
  const scrub = (text: string) => redactSecretFragments(text, fragments)

  return {
    ...report,
    target: safeTarget,
    conflicts: report.conflicts.map(scrub),
    notes: report.notes.map(scrub),
  }
}

function getStorage(): Storage | null {
  if (typeof window === 'undefined') return null

  try {
    const storage = window.localStorage
    const probe = '__veriguard_multi_source_probe__'
    storage.setItem(probe, '1')
    storage.removeItem(probe)
    return storage
  } catch {
    return null
  }
}

// Hasil urai dikunci pada isi penyimpanan, bukan pada panggilan. `readAll` dipakai di jalur
// render, jadi membaca laporan yang tidak berubah tidak boleh mengurai ulang seluruh JSON dan
// menyisihkan setiap objek baru pada setiap render. Isi yang berbeda selalu menghasilkan
// objek baru, sehingga tidak ada laporan basi yang dapat terbaca.
type ParsedReports = { reports: Record<string, MultiSourceReport> | null; changed: boolean }

let parsedCache: { raw: string; value: ParsedReports } | null = null

function parseStoredReports(raw: string): ParsedReports {
  if (parsedCache && parsedCache.raw === raw) return parsedCache.value

  const parsed: unknown = JSON.parse(raw)
  let value: ParsedReports = { reports: null, changed: false }

  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
    const reports: Record<string, MultiSourceReport> = {}
    let changed = false

    for (const [scanId, entry] of Object.entries(parsed)) {
      if (!scanId || !isMultiSourceReport(entry)) continue

      const stored = toStoredReport(entry)
      if (stored !== entry) changed = true
      reports[scanId] = stored
    }

    value = { reports, changed }
  }

  parsedCache = { raw, value }
  return value
}

function readAll(): Record<string, MultiSourceReport> {
  const storage = getStorage()
  if (!storage) return { ...memoryReports }

  try {
    const raw = storage.getItem(MULTI_SOURCE_STORAGE_KEY)
    if (!raw) return { ...memoryReports }

    const parsed = parseStoredReports(raw)
    if (parsed.reports === null) return { ...memoryReports }

    const merged = { ...parsed.reports, ...memoryReports }
    memoryReports = merged
    if (parsed.changed) writeAll(merged)
    return { ...merged }
  } catch {
    return { ...memoryReports }
  }
}

function writeAll(reports: Record<string, MultiSourceReport>): boolean {
  const trimmed = Object.fromEntries(
    Object.entries(reports)
      .sort(([, left], [, right]) => Date.parse(right.generatedAt) - Date.parse(left.generatedAt))
      .slice(0, MAX_SAVED_REPORTS),
  )

  memoryReports = trimmed
  const storage = getStorage()
  if (!storage) return false

  try {
    storage.setItem(MULTI_SOURCE_STORAGE_KEY, JSON.stringify(trimmed))
    return true
  } catch {
    return false
  }
}

export function saveScanReport(scanId: string, report: MultiSourceReport): boolean {
  if (!scanId) return false

  const reports = readAll()
  reports[scanId] = toStoredReport(report)
  return writeAll(reports)
}

export function getScanReport(scanId: string): MultiSourceReport | null {
  if (!scanId) return null
  return readAll()[scanId] ?? null
}

export function deleteScanReport(scanId: string): void {
  const reports = readAll()
  if (!(scanId in reports)) return

  delete reports[scanId]
  writeAll(reports)
}

export function clearScanReports(): void {
  memoryReports = {}
  const storage = getStorage()
  if (!storage) return

  try {
    storage.removeItem(MULTI_SOURCE_STORAGE_KEY)
  } catch {
    // Data memori sudah dikosongkan.
  }
}

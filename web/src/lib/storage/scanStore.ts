import { truncate } from '../analysis/text'
import type { ScanDraft, ScanResult } from '../analysis/types'
import { redactMessagePreview } from '../privacy/redactMessage'
import {
  detectSensitiveUrl,
  redactSecretFragments,
  redactSensitiveUrlForStorage,
  sensitiveUrlFragments,
} from '../scanners/privacy'

export const SCAN_STORAGE_KEY = 'veriguard.scans.v1'
export const MAX_SAVED_SCANS = 30
// Retensi riwayat lokal: 90 hari. localStorage tidak dibersihkan oleh peramban dan ikut
// terbawa pencadangan perangkat, jadi pemeriksaan lama tidak boleh menumpuk selamanya.
export const SCAN_RETENTION_MS = 90 * 24 * 60 * 60 * 1_000

let memoryScans: ScanResult[] = []

function createId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID()
  }

  return `scan_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`
}

function getStorage(): Storage | null {
  if (typeof window === 'undefined') return null

  try {
    const storage = window.localStorage
    const probe = '__veriguard_probe__'
    storage.setItem(probe, '1')
    storage.removeItem(probe)
    return storage
  } catch {
    return null
  }
}

const REASON_SEVERITIES = new Set(['info', 'warning', 'danger'])
const REASON_CATEGORIES = new Set([
  'url-structure',
  'domain',
  'obfuscation',
  'request',
  'urgency',
  'impersonation',
  'transaction',
  'language',
])
const PATTERN_IDS = new Set([
  'phishing',
  'fake_login',
  'giveaway',
  'marketplace',
  'impersonation',
  'urgency',
  'investment',
  'job_scam',
  'otp_theft',
])
const PATTERN_CONFIDENCES = new Set(['low', 'medium', 'high'])
const TECHNICAL_TONES = new Set(['neutral', 'warning', 'danger'])

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object'
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
}

function isNonNegativeNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
}

function isAnalysisReason(value: unknown): boolean {
  if (!isRecord(value)) return false

  return (
    isNonEmptyString(value.id) &&
    isNonEmptyString(value.label) &&
    typeof value.detail === 'string' &&
    typeof value.severity === 'string' &&
    REASON_SEVERITIES.has(value.severity) &&
    isNonNegativeNumber(value.weight) &&
    typeof value.category === 'string' &&
    REASON_CATEGORIES.has(value.category)
  )
}

function isDetectedPattern(value: unknown): boolean {
  if (!isRecord(value)) return false

  return (
    typeof value.id === 'string' &&
    PATTERN_IDS.has(value.id) &&
    isNonEmptyString(value.label) &&
    typeof value.description === 'string' &&
    typeof value.confidence === 'string' &&
    PATTERN_CONFIDENCES.has(value.confidence)
  )
}

function isTechnicalItem(value: unknown): boolean {
  if (!isRecord(value)) return false

  return (
    isNonEmptyString(value.label) &&
    typeof value.value === 'string' &&
    (value.tone === undefined ||
      (typeof value.tone === 'string' && TECHNICAL_TONES.has(value.tone)))
  )
}

function isAnalysisMeta(value: unknown): boolean {
  if (!isRecord(value)) return false

  return (
    isNonEmptyString(value.engineVersion) &&
    isNonNegativeNumber(value.signalCount) &&
    isNonNegativeNumber(value.inputLength) &&
    value.aiStatus === 'not_used' &&
    (value.inputStored === undefined ||
      value.inputStored === 'full' ||
      value.inputStored === 'redacted')
  )
}

export function isScanResult(value: unknown): value is ScanResult {
  if (!isRecord(value)) return false

  return (
    isNonEmptyString(value.id) &&
    typeof value.createdAt === 'string' &&
    !Number.isNaN(Date.parse(value.createdAt)) &&
    (value.mode === 'link' || value.mode === 'message') &&
    (value.riskLevel === 'low' ||
      value.riskLevel === 'medium' ||
      value.riskLevel === 'high') &&
    typeof value.riskScore === 'number' &&
    Number.isFinite(value.riskScore) &&
    value.riskScore >= 0 &&
    value.riskScore <= 100 &&
    typeof value.input === 'string' &&
    typeof value.displayTarget === 'string' &&
    isNonEmptyString(value.headline) &&
    typeof value.summary === 'string' &&
    Array.isArray(value.reasons) &&
    value.reasons.every(isAnalysisReason) &&
    Array.isArray(value.patterns) &&
    value.patterns.every(isDetectedPattern) &&
    Array.isArray(value.recommendations) &&
    value.recommendations.every((item) => typeof item === 'string') &&
    Array.isArray(value.technical) &&
    value.technical.every(isTechnicalItem) &&
    isAnalysisMeta(value.meta)
  )
}

export function redactMessageScan(scan: ScanResult): ScanResult {
  const preview = redactMessagePreview(scan.input)

  return {
    ...scan,
    input: preview,
    displayTarget: preview,
    meta: { ...scan.meta, inputStored: 'redacted' },
  }
}

function readAll(): ScanResult[] {
  const storage = getStorage()

  if (!storage) {
    return [...memoryScans]
  }

  try {
    const raw = storage.getItem(SCAN_STORAGE_KEY)
    if (!raw) return []

    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []

    let changed = false

    const cutoff = Date.now() - SCAN_RETENTION_MS
    const scans: ScanResult[] = []
    for (const candidate of parsed) {
      if (!isScanResult(candidate)) continue

      if (Date.parse(candidate.createdAt) < cutoff) {
        changed = true
        continue
      }

      if (candidate.mode === 'message' && candidate.meta.inputStored === undefined) {
        changed = true
        scans.push(redactMessageScan(candidate))
        continue
      }

      // Riwayat yang ditulis sebelum URL sensitif ikut disamarkan: disusulkan saat dibaca
      // supaya token lama tidak tinggal di penyimpanan sampai pemilik menghapus riwayat.
      const stored = toStoredScan(candidate)
      if (stored !== candidate) {
        changed = true
        scans.push(stored)
        continue
      }

      scans.push(candidate)
    }

    const sorted = scans
      .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
      .slice(0, MAX_SAVED_SCANS)

    if (changed) {
      memoryScans = sorted
      try {
        storage.setItem(SCAN_STORAGE_KEY, JSON.stringify(sorted))
      } catch {
        // Data lama tetap disamarkan/dibuang di memori meski penyimpanan gagal diperbarui.
      }
    }

    return sorted
  } catch {
    return [...memoryScans]
  }
}

function writeAll(scans: ScanResult[]): void {
  const cutoff = Date.now() - SCAN_RETENTION_MS
  const trimmed = scans
    .filter((scan) => Date.parse(scan.createdAt) >= cutoff)
    .slice(0, MAX_SAVED_SCANS)
  memoryScans = trimmed

  const storage = getStorage()
  if (!storage) return

  try {
    storage.setItem(SCAN_STORAGE_KEY, JSON.stringify(trimmed))
  } catch {
    // Kuota penuh atau penyimpanan diblokir: riwayat tetap tersedia di memori sesi ini.
  }
}

export function createScan(draft: ScanDraft): ScanResult {
  return {
    ...draft,
    meta: { ...draft.meta, inputStored: draft.meta.inputStored ?? 'full' },
    id: createId(),
    createdAt: new Date().toISOString(),
  }
}

export type SaveScanOptions = {
  redactMessageInput?: boolean
}

function redactDraftMessage(draft: ScanDraft): ScanDraft {
  const preview = redactMessagePreview(draft.input)

  return {
    ...draft,
    input: preview,
    displayTarget: preview,
    meta: { ...draft.meta, inputStored: 'redacted' },
  }
}

/**
 * VGL-12: salinan yang siap disimpan ke penyimpanan permanen (localStorage maupun dokumen
 * Firestore milik akun). URL yang membawa token/kredensial disamarkan HANYA di salinan
 * tersimpan ini; objek yang dikembalikan ke pemanggil tetap memakai teks asli sehingga
 * pemeriksaan yang sedang berjalan tidak berubah. Riwayat yang dibuka kembali nanti
 * menampilkan bentuk yang sudah aman.
 */
export function toStoredScan(scan: ScanResult): ScanResult {
  if (scan.mode !== 'link' || scan.meta.inputStored === 'redacted') return scan
  if (!detectSensitiveUrl(scan.input).sensitive) return scan

  const safeInput = redactSensitiveUrlForStorage(scan.input)
  // Bentuk titik-tetap: kalau penyamaran tidak mengubah apa pun, jangan tandai
  // sudah disamarkan. Tanpa cek ini setiap pembacaan riwayat menganggap entri ini
  // belum aman dan menulis ulang penyimpanan.
  if (safeInput === scan.input) return scan

  // Analisis ikut mengulang sebagian alamat di dalam teks indikator dan rincian teknis,
  // jadi potongan sensitifnya disapu dari seluruh field yang dibaca pengguna.
  const fragments = sensitiveUrlFragments(scan.input)
  const scrub = (text: string) => redactSecretFragments(text, fragments)

  return {
    ...scan,
    input: safeInput,
    displayTarget: scrub(displayTargetFor(safeInput)),
    headline: scrub(scan.headline),
    summary: scrub(scan.summary),
    reasons: scan.reasons.map((reason) => ({
      ...reason,
      label: scrub(reason.label),
      detail: scrub(reason.detail),
    })),
    patterns: scan.patterns.map((pattern) => ({
      ...pattern,
      description: scrub(pattern.description),
    })),
    recommendations: scan.recommendations.map(scrub),
    technical: scan.technical.map((item) => ({
      ...item,
      label: scrub(item.label),
      value: scrub(item.value),
    })),
    meta: { ...scan.meta, inputStored: 'redacted' },
  }
}

function displayTargetFor(safeInput: string): string {
  try {
    const url = new URL(safeInput)
    return truncate(`${url.host}${url.pathname}`, 90)
  } catch {
    return truncate(safeInput, 90)
  }
}

export function prepareScan(draft: ScanDraft, options: SaveScanOptions = {}): ScanResult {
  const prepared =
    options.redactMessageInput && draft.mode === 'message'
      ? redactDraftMessage(draft)
      : draft
  return createScan(prepared)
}

export function persistPreparedScan(result: ScanResult): ScanResult {
  const stored = toStoredScan(result)
  const existing = readAll().filter(
    (scan) => !(scan.mode === stored.mode && scan.input === stored.input),
  )

  writeAll([stored, ...existing])
  return result
}

export function saveScan(draft: ScanDraft, options: SaveScanOptions = {}): ScanResult {
  return persistPreparedScan(prepareScan(draft, options))
}

export function listScans(): ScanResult[] {
  return readAll()
}

export function getScan(id: string): ScanResult | null {
  return readAll().find((scan) => scan.id === id) ?? null
}

export function deleteScan(id: string): void {
  writeAll(readAll().filter((scan) => scan.id !== id))
}

export function clearScans(): void {
  memoryScans = []
  const storage = getStorage()

  if (!storage) return

  try {
    storage.removeItem(SCAN_STORAGE_KEY)
  } catch {
    // Abaikan; data memori sudah dikosongkan.
  }
}

export function redactAllMessageContents(): number {
  const scans = readAll()
  let redactedCount = 0

  const next = scans.map((scan) => {
    if (scan.mode === 'message' && scan.meta.inputStored !== 'redacted') {
      redactedCount += 1
      return redactMessageScan(scan)
    }

    return scan
  })

  if (redactedCount > 0) writeAll(next)

  return redactedCount
}

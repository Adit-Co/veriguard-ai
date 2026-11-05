import type { SiteAnalysisResponse } from './types'
import { isSiteAnalysisResponse, parseSiteAnalysisResponse } from './validate'
import {
  detectSensitiveUrl,
  redactSensitiveUrlForStorage,
  sensitiveUrlFragments,
  redactSecretFragments,
} from '../scanners/privacy'

export const SITE_ANALYSIS_STORAGE_KEY = 'veriguard.websiteAnalyses.v1'
export const MAX_SAVED_ANALYSES = 20

let memoryAnalyses: Record<string, SiteAnalysisResponse> = {}

/**
 * VGL-12: analisis situs yang dijalankan pada URL sensitif tidak boleh meninggalkan token di
 * penyimpanan. Hanya alamat yang diulang-ulang di dalam respons (target, URL awal perilaku,
 * rincian probe) yang dibersihkan; skor dan temuan lain dibiarkan apa adanya.
 */
export function toStoredAnalysis(analysis: SiteAnalysisResponse): SiteAnalysisResponse {
  if (!detectSensitiveUrl(analysis.target).sensitive) return analysis

  const safeTarget = redactSensitiveUrlForStorage(analysis.target)
  if (safeTarget === analysis.target) return analysis

  const fragments = sensitiveUrlFragments(analysis.target)
  const scrub = (text: string) => redactSecretFragments(text, fragments)

  return {
    ...analysis,
    target: safeTarget,
    probe: {
      ...analysis.probe,
      detail: analysis.probe.detail === null ? null : scrub(analysis.probe.detail),
    },
    behavior: {
      ...analysis.behavior,
      initialUrl: scrub(redactSensitiveUrlForStorage(analysis.behavior.initialUrl)),
    },
  }
}

function getStorage(): Storage | null {
  if (typeof window === 'undefined') return null

  try {
    const storage = window.localStorage
    const probe = '__veriguard_site_analysis_probe__'
    storage.setItem(probe, '1')
    storage.removeItem(probe)
    return storage
  } catch {
    return null
  }
}

function readAll(): Record<string, SiteAnalysisResponse> {
  const storage = getStorage()
  if (!storage) return { ...memoryAnalyses }

  try {
    const raw = storage.getItem(SITE_ANALYSIS_STORAGE_KEY)
    if (!raw) return { ...memoryAnalyses }

    const parsed: unknown = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ...memoryAnalyses }
    }

    const stored: Record<string, SiteAnalysisResponse> = {}
    let changed = false
    for (const [scanId, value] of Object.entries(parsed)) {
      // Disalin ulang lewat parser agar entri lama yang belum punya bagian
      // kategori datang dengan bentuk yang sama seperti respons baru.
      if (!scanId || !isSiteAnalysisResponse(value)) continue

      const normalized = parseSiteAnalysisResponse(value)
      const safe = toStoredAnalysis(normalized)
      if (safe !== normalized) changed = true
      stored[scanId] = safe
    }

    const merged = { ...stored, ...memoryAnalyses }
    memoryAnalyses = merged
    if (changed) writeAll(merged)
    return { ...merged }
  } catch {
    return { ...memoryAnalyses }
  }
}

function writeAll(analyses: Record<string, SiteAnalysisResponse>): boolean {
  const trimmed = Object.fromEntries(
    Object.entries(analyses)
      .sort(([, left], [, right]) => Date.parse(right.generatedAt) - Date.parse(left.generatedAt))
      .slice(0, MAX_SAVED_ANALYSES),
  )

  memoryAnalyses = trimmed
  const storage = getStorage()
  if (!storage) return false

  try {
    storage.setItem(SITE_ANALYSIS_STORAGE_KEY, JSON.stringify(trimmed))
    return true
  } catch {
    return false
  }
}

export function saveSiteAnalysis(scanId: string, analysis: SiteAnalysisResponse): boolean {
  if (!scanId) return false

  const analyses = readAll()
  analyses[scanId] = toStoredAnalysis(analysis)
  return writeAll(analyses)
}

export function getSiteAnalysis(scanId: string): SiteAnalysisResponse | null {
  if (!scanId) return null
  return readAll()[scanId] ?? null
}

export function deleteSiteAnalysis(scanId: string): void {
  const analyses = readAll()
  if (!(scanId in analyses)) return

  delete analyses[scanId]
  writeAll(analyses)
}

export function clearSiteAnalyses(): void {
  memoryAnalyses = {}
  const storage = getStorage()
  if (!storage) return

  try {
    storage.removeItem(SITE_ANALYSIS_STORAGE_KEY)
  } catch {
    // Data memori sudah dikosongkan.
  }
}

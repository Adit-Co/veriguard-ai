import { beforeEach, describe, expect, it } from 'vitest'
import {
  SITE_ANALYSIS_MAX_TRACKED_KEYS,
  consumeSiteAnalysisRateLimit,
  resetSiteAnalysisRateLimit,
} from '../../functions/src/website/limits.js'

const NOW = 1_700_000_000_000
const WINDOW_MS = 10 * 60 * 1_000

beforeEach(() => {
  resetSiteAnalysisRateLimit()
})

describe('batas analisis situs', () => {
  it('membatasi tabel kunci dan menolak alamat baru saat penuh', () => {
    for (let index = 0; index < SITE_ANALYSIS_MAX_TRACKED_KEYS; index += 1) {
      expect(consumeSiteAnalysisRateLimit(`site:${index}`, NOW, 1, WINDOW_MS).allowed).toBe(true)
    }

    expect(consumeSiteAnalysisRateLimit('site:baru', NOW, 1, WINDOW_MS)).toEqual({
      allowed: false,
      retryAfterSeconds: WINDOW_MS / 1_000,
    })
    expect(consumeSiteAnalysisRateLimit('site:0', NOW, 1, WINDOW_MS).allowed).toBe(false)
  })

  it('menerima alamat baru setelah jendela kunci lama habis', () => {
    for (let index = 0; index < SITE_ANALYSIS_MAX_TRACKED_KEYS; index += 1) {
      consumeSiteAnalysisRateLimit(`site:${index}`, NOW, 1, WINDOW_MS)
    }
    expect(consumeSiteAnalysisRateLimit('site:baru', NOW, 1, WINDOW_MS).allowed).toBe(false)

    const afterWindow = NOW + WINDOW_MS + 1
    expect(consumeSiteAnalysisRateLimit('site:baru', afterWindow, 1, WINDOW_MS).allowed).toBe(true)
  })
})

// @vitest-environment jsdom

import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  SITE_ANALYSIS_STORAGE_KEY,
  MAX_SAVED_ANALYSES,
  clearSiteAnalyses,
  deleteSiteAnalysis,
  getSiteAnalysis,
  saveSiteAnalysis,
} from './analysisStore'
import { parseSiteAnalysisResponse } from './validate'
import { REDACTED_PATH_SEGMENT } from '../scanners/privacy'
import type { SiteAnalysisResponse } from './types'

function reportFor(day: number): SiteAnalysisResponse {
  const emptyLookup = {
    status: 'unavailable',
    source: 'tanpa probe',
    value: null,
    detail: null,
    queriedAt: '1970-01-01T00:00:00.000Z',
  }
  return parseSiteAnalysisResponse({
    version: 1,
    target: `https://contoh${day}.com/`,
    hostname: `contoh${day}.com`,
    generatedAt: new Date(Date.UTC(2026, 0, day + 1)).toISOString(),
    durationMs: 100,
    probe: { available: false, name: 'tanpa probe', detail: null },
    website: {
      status: 'unavailable',
      identity: {
        hostname: `contoh${day}.com`,
        addresses: emptyLookup,
        withheldAddresses: 0,
        asn: emptyLookup,
        intermediary: { state: 'unavailable', signals: [], note: null },
      },
      dns: [],
      tls: { httpsAvailable: emptyLookup, certificate: emptyLookup, certificateSource: null },
      response: { request: emptyLookup, headers: [] },
      notes: [],
    },
    technology: {
      status: 'unavailable',
      findings: [],
      categories: [],
      document: {},
      notes: [],
    },
    behavior: {
      status: 'unavailable',
      initialUrl: `https://contoh${day}.com/`,
      redirects: [],
      redirectCount: 0,
      redirectOutcome: 'unavailable',
      hosts: [],
      resources: null,
      securityHeaders: [],
      cookies: [],
      cookiesCollected: false,
      observations: [],
      notes: [],
    },
  })
}

describe('penyimpanan analisis situs', () => {
  beforeEach(() => {
    clearSiteAnalyses()
    window.localStorage.clear()
    vi.restoreAllMocks()
  })

  it('menyimpan lalu membaca kembali analisis per scan', () => {
    const report = reportFor(1)
    expect(saveSiteAnalysis('scan-1', report)).toBe(true)
    expect(getSiteAnalysis('scan-1')?.target).toBe('https://contoh1.com/')
    expect(window.localStorage.getItem(SITE_ANALYSIS_STORAGE_KEY)).toContain('scan-1')
  })

  it('mengabaikan scanId kosong dan mengembalikan null untuk id yang tidak ada', () => {
    expect(saveSiteAnalysis('', reportFor(2))).toBe(false)
    expect(getSiteAnalysis('')).toBeNull()
    expect(getSiteAnalysis('belum-ada')).toBeNull()
  })

  it('hanya menyimpan analisis terbaru sampai batas yang ditentukan', () => {
    const total = MAX_SAVED_ANALYSES + 6
    for (let index = 0; index < total; index += 1) {
      saveSiteAnalysis(`scan-${index}`, reportFor(index))
    }

    const stored = JSON.parse(String(window.localStorage.getItem(SITE_ANALYSIS_STORAGE_KEY))) as Record<
      string,
      { generatedAt: string }
    >
    expect(Object.keys(stored).length).toBe(MAX_SAVED_ANALYSES)
    // Tanggal paling tua (index 0) keluar dari penyimpanan, yang paling baru tetap ada.
    expect(stored['scan-0']).toBeUndefined()
    expect(stored[`scan-${total - 1}`]).toBeDefined()
    expect(getSiteAnalysis('scan-0')).toBeNull()
  })

  it('menghapus satu analisis tanpa mengganggu yang lain', () => {
    saveSiteAnalysis('scan-a', reportFor(1))
    saveSiteAnalysis('scan-b', reportFor(2))

    deleteSiteAnalysis('scan-a')
    expect(getSiteAnalysis('scan-a')).toBeNull()
    expect(getSiteAnalysis('scan-b')).not.toBeNull()

    deleteSiteAnalysis('tidak-ada')
    expect(getSiteAnalysis('scan-b')).not.toBeNull()
  })

  it('pulih dari data rusak di localStorage dan tetap bisa menyimpan', () => {
    window.localStorage.setItem(SITE_ANALYSIS_STORAGE_KEY, '{bukan json')
    expect(getSiteAnalysis('scan-x')).toBeNull()

    window.localStorage.setItem(
      SITE_ANALYSIS_STORAGE_KEY,
      JSON.stringify({ 'scan-lama': { version: 1, website: {} } }),
    )
    expect(getSiteAnalysis('scan-lama')).toBeNull()

    expect(saveSiteAnalysis('scan-baru', reportFor(3))).toBe(true)
    expect(getSiteAnalysis('scan-baru')).not.toBeNull()
    const stored = JSON.parse(String(window.localStorage.getItem(SITE_ANALYSIS_STORAGE_KEY)))
    expect(Object.keys(stored)).toEqual(['scan-baru'])
  })

  it('memakai penyimpanan cadangan saat localStorage menolak menulis', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('quota exceeded')
    })

    expect(saveSiteAnalysis('scan-offline', reportFor(4))).toBe(false)
    // Data tetap tersedia selama sesi, hanya tidak diklaim tersimpan permanen.
    expect(getSiteAnalysis('scan-offline')?.target).toBe('https://contoh4.com/')
  })

  it('menyamarkan target sensitif sebelum masuk localStorage', () => {
    const token = 'abcdefghijklmnop123456'
    const sensitive = reportFor(1)
    sensitive.target = `https://contoh1.com/reset/${token}?kunci=rahasia123`
    sensitive.behavior.initialUrl = sensitive.target
    sensitive.probe.detail = `Probe membuka https://contoh1.com/reset/${token}`

    expect(saveSiteAnalysis('scan-sensitif', sensitive)).toBe(true)

    const raw = String(window.localStorage.getItem(SITE_ANALYSIS_STORAGE_KEY))
    const stored = JSON.parse(raw) as Record<
      string,
      { target: string; behavior: { initialUrl: string } }
    >

    expect(raw).not.toContain(token)
    expect(raw).not.toContain('rahasia123')
    expect(stored['scan-sensitif']?.target).toBe(
      `https://contoh1.com/reset/${REDACTED_PATH_SEGMENT}`,
    )
    expect(stored['scan-sensitif']?.behavior.initialUrl).toBe(
      `https://contoh1.com/reset/${REDACTED_PATH_SEGMENT}`,
    )
    expect(sensitive.target).toContain(token)
  })

  it('membersihkan memori dan localStorage sekaligus', () => {    saveSiteAnalysis('scan-1', reportFor(1))
    clearSiteAnalyses()

    expect(getSiteAnalysis('scan-1')).toBeNull()
    expect(window.localStorage.getItem(SITE_ANALYSIS_STORAGE_KEY)).toBeNull()
  })
})

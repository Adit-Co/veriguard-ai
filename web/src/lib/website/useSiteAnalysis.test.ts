// @vitest-environment jsdom

import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ExternalScanRequestError } from '../scanners/errors'
import { clearSiteAnalyses, getSiteAnalysis, saveSiteAnalysis } from './analysisStore'

const mocks = vi.hoisted(() => ({
  requestSiteAnalysis: vi.fn(),
  isSiteAnalysisAvailable: vi.fn(),
}))

vi.mock('./client', () => ({
  requestSiteAnalysis: mocks.requestSiteAnalysis,
  isSiteAnalysisAvailable: mocks.isSiteAnalysisAvailable,
}))

import { useSiteAnalysis } from './useSiteAnalysis'
import type { SiteAnalysisResponse } from './types'

function reportFor(target: string): SiteAnalysisResponse {
  return buildReport(target)
}

function buildReport(target: string): SiteAnalysisResponse {
  const emptyLookup = {
    status: 'unavailable' as const,
    source: 'tanpa probe',
    value: null,
    detail: null,
    queriedAt: '1970-01-01T00:00:00.000Z',
  }
  return {
    version: 1,
    target,
    hostname: 'contoh.com',
    generatedAt: '2026-10-24T00:00:00.000Z',
    durationMs: 500,
    probe: { available: true, name: 'node-dns-tls-http', detail: null },
    website: {
      status: 'unavailable' as const,
      identity: {
        hostname: 'contoh.com',
        addresses: emptyLookup,
        withheldAddresses: 0,
        asn: emptyLookup,
        intermediary: { state: 'unavailable' as const, signals: [], note: 'Belum dapat dinilai.' },
      },
      dns: [],
      tls: { httpsAvailable: emptyLookup, certificate: emptyLookup, certificateSource: null },
      response: {
        request: emptyLookup,
        status: null,
        statusText: null,
        finalUrl: null,
        redirectCount: 0,
        elapsedMs: null,
        contentType: null,
        bytes: null,
        truncated: false,
        headers: [],
        withheldHeaders: 0,
      },
      notes: [],
    },
    technology: {
      status: 'unavailable' as const,
      findings: [],
      categories: [],
      document: { inspected: false, bytesScanned: 0, truncated: false, contentType: null, detail: 'Tidak ada dokumen.' },
      notes: [],
    },
    behavior: {
      status: 'unavailable' as const,
      initialUrl: target,
      redirects: [],
      redirectCount: 0,
      redirectOutcome: 'unavailable' as const,
      hosts: [],
      resources: null,
      securityHeaders: [],
      cookies: [],
      cookiesCollected: false,
      structure: {
        status: 'unavailable' as const,
        findings: [],
        hostname: 'contoh.com',
        scheme: 'https',
        port: null,
        labelCount: 2,
        registrableDomain: 'contoh.com',
        notes: ['Struktur URL dinilai dari teks URL, bukan dari permintaan tambahan.'],
      },
      forms: {
        inspected: false,
        forms: [],
        totals: { forms: 0, passwordFields: 0, externalActions: 0, insecureActions: 0 },
        capped: false,
        detail: 'Form dan kolom kredensial belum dapat diperiksa.',
      },
      observations: [],
      notes: [],
    },
    category: {
      status: 'unavailable' as const,
      primaryId: 'unknown' as const,
      primaryLabel: 'Tidak diketahui',
      confidence: 'low' as const,
      riskIndicated: false,
      summary: 'Data yang tersedia belum cukup untuk menentukan kategori website.',
      signals: [],
      alternatives: [],
      evidenceBasis: {
        documentInspected: false,
        titleAvailable: false,
        descriptionAvailable: false,
        visibleTextBytes: 0,
        redirectHops: 0,
      },
      notes: [],
    },
    // Bentuk respons lama: backend belum mengirim ketiga bagian ini.
    registration: null,
    page: null,
    risk: null,
  }
}

describe('useSiteAnalysis', () => {
  beforeEach(() => {
    clearSiteAnalyses()
    window.localStorage.clear()
    mocks.isSiteAnalysisAvailable.mockReturnValue(true)
    mocks.requestSiteAnalysis.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('mulai tanpa data dan hanya memanggil backend saat run', async () => {
    mocks.requestSiteAnalysis.mockResolvedValue(reportFor('https://contoh.com/'))
    const { result } = renderHook(() => useSiteAnalysis('scan-1', 'https://contoh.com/'))

    expect(result.current.state).toBe('idle')
    expect(result.current.data).toBeNull()
    expect(mocks.requestSiteAnalysis).not.toHaveBeenCalled()

    await act(async () => {
      await result.current.run()
    })

    expect(mocks.requestSiteAnalysis).toHaveBeenCalledTimes(1)
    expect(result.current.state).toBe('ready')
    expect(result.current.data?.target).toBe('https://contoh.com/')
    // Hasil disimpan per scanId sehingga berpindah menu tidak perlu memanggil ulang backend.
    expect(getSiteAnalysis('scan-1')?.target).toBe('https://contoh.com/')
  })

  it('memakai analisis yang sudah tersimpan tanpa permintaan baru', () => {
    const saved = reportFor('https://tersimpan.com/')
    saveSiteAnalysis('scan-2', saved)

    const { result } = renderHook(() => useSiteAnalysis('scan-2', 'https://tersimpan.com/'))
    expect(result.current.state).toBe('ready')
    expect(result.current.data?.target).toBe('https://tersimpan.com/')
    expect(mocks.requestSiteAnalysis).not.toHaveBeenCalled()
  })

  it('memisahkan kegagalan dari data dan memberi pesan yang dapat dibaca', async () => {
    mocks.requestSiteAnalysis.mockRejectedValue(
      new ExternalScanRequestError('invalid_url', 'URL ditolak oleh kebijakan keamanan backend.'),
    )

    const { result } = renderHook(() => useSiteAnalysis('scan-3', 'http://127.0.0.1/'))
    await act(async () => {
      await result.current.run()
    })

    expect(result.current.state).toBe('failed')
    expect(result.current.data).toBeNull()
    expect(result.current.error).toContain('kebijakan keamanan layanan analisis situs')
    expect(getSiteAnalysis('scan-3')).toBeNull()
  })

  it('selalu idle dan tanpa data bila backend tidak tersedia', async () => {
    mocks.isSiteAnalysisAvailable.mockReturnValue(false)
    const { result } = renderHook(() => useSiteAnalysis('scan-4', 'https://contoh.com/'))

    expect(result.current.available).toBe(false)
    expect(result.current.state).toBe('idle')

    await act(async () => {
      await result.current.run()
    })
    expect(mocks.requestSiteAnalysis).not.toHaveBeenCalled()
    expect(result.current.error).toBeNull()
    expect(result.current.state).toBe('idle')
  })

  it('membatalkan permintaan berjalan saat reset', async () => {
    let seenSignal: AbortSignal | undefined
    mocks.requestSiteAnalysis.mockImplementation(
      (_url: string, options: { signal?: AbortSignal }) =>
        new Promise((_resolve, reject) => {
          seenSignal = options.signal
          const error = new Error('AbortError')
          error.name = 'AbortError'
          options.signal?.addEventListener('abort', () => reject(error), { once: true })
        }),
    )

    const { result } = renderHook(() => useSiteAnalysis('scan-5', 'https://contoh.com/'))
    let running: Promise<void> | undefined
    await act(async () => {
      running = result.current.run()
      await waitFor(() => expect(seenSignal).toBeDefined())
      result.current.reset()
      await running
    })

    expect(seenSignal?.aborted).toBe(true)
    // Pembatalan tidak boleh meninggalkan data parsial maupun tersimpan di perangkat.
    expect(result.current.data).toBeNull()
    // Permintaan yang dibatalkan sendiri bukan kegagalan layanan: jangan tampilkan error.
    expect(result.current.state).toBe('idle')
    expect(result.current.error).toBeNull()
    expect(getSiteAnalysis('scan-5')).toBeNull()
  })

  it('menjalankan analisis otomatis dengan URL hasil scan', async () => {
    mocks.requestSiteAnalysis.mockResolvedValue(reportFor('https://contoh.com/'))

    const { result } = renderHook(() =>
      useSiteAnalysis('scan-6', 'https://contoh.com/', { autoRun: true }),
    )

    await waitFor(() => expect(result.current.state).toBe('ready'))
    expect(mocks.requestSiteAnalysis).toHaveBeenCalledTimes(1)
    expect(mocks.requestSiteAnalysis.mock.calls[0]?.[0]).toBe('https://contoh.com/')
    expect(result.current.data?.target).toBe('https://contoh.com/')
    expect(getSiteAnalysis('scan-6')?.target).toBe('https://contoh.com/')
  })

  it('tidak memanggil backend saat auto-run padahal hasil sudah tersimpan', async () => {
    saveSiteAnalysis('scan-7', reportFor('https://tersimpan.com/'))
    mocks.requestSiteAnalysis.mockResolvedValue(reportFor('https://tersimpan.com/'))

    const { result } = renderHook(() =>
      useSiteAnalysis('scan-7', 'https://tersimpan.com/', { autoRun: true }),
    )
    await act(async () => {
      await Promise.resolve()
    })

    expect(mocks.requestSiteAnalysis).not.toHaveBeenCalled()
    expect(result.current.state).toBe('ready')
  })

  it('tidak mengulang otomatis setelah auto-run gagal', async () => {
    mocks.requestSiteAnalysis.mockRejectedValue(
      new ExternalScanRequestError('not_found', 'Endpoint tidak ditemukan.'),
    )

    const { result, rerender } = renderHook(
      ({ nonce }: { nonce: number }) =>
        useSiteAnalysis(`scan-8-${nonce}`, 'https://contoh.com/', { autoRun: true }),
      { initialProps: { nonce: 0 } },
    )

    await waitFor(() => expect(result.current.state).toBe('failed'))
    expect(result.current.error).toContain('belum tersedia pada versi ini')
    rerender({ nonce: 0 })
    await act(async () => {
      await Promise.resolve()
    })

    expect(mocks.requestSiteAnalysis).toHaveBeenCalledTimes(1)
  })

  it('memakai ulang analisis otomatis saat scan berganti tanpa permintaan ganda', async () => {
    mocks.requestSiteAnalysis.mockResolvedValue(reportFor('https://contoh.com/'))

    const { result, rerender } = renderHook(
      ({ scanId }: { scanId: string }) =>
        useSiteAnalysis(scanId, 'https://contoh.com/', { autoRun: true }),
      { initialProps: { scanId: '' } },
    )

    await act(async () => {
      await Promise.resolve()
    })
    expect(mocks.requestSiteAnalysis).not.toHaveBeenCalled()

    rerender({ scanId: 'scan-9' })
    await waitFor(() => expect(result.current.state).toBe('ready'))
    expect(mocks.requestSiteAnalysis).toHaveBeenCalledTimes(1)
  })
})

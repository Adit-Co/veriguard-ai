import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ScanResult } from '../analysis/types'
import { buildLocalReport } from './report'
import { REDACTED_PATH_SEGMENT } from './privacy'
import {
  MULTI_SOURCE_STORAGE_KEY,
  clearScanReports,
  deleteScanReport,
  getScanReport,
  saveScanReport,
  toStoredReport,
} from './reportStore'

function makeScan(id: string): ScanResult {
  return {
    id,
    createdAt: '2026-01-01T00:00:00.000Z',
    mode: 'link',
    input: 'https://contoh.com/path',
    displayTarget: 'contoh.com/path',
    riskScore: 0,
    riskLevel: 'low',
    headline: 'Indikasi risiko rendah',
    summary: 'Tidak banyak indikator risiko ditemukan.',
    reasons: [],
    patterns: [],
    recommendations: ['Verifikasi melalui kanal resmi.'],
    technical: [],
    meta: {
      engineVersion: 'test',
      signalCount: 0,
      inputLength: 25,
      aiStatus: 'not_used',
    },
  }
}

describe('penyimpanan laporan multi-sumber', () => {
  beforeEach(() => {
    clearScanReports()
  })

  it('menyimpan, membaca, dan menghapus laporan per scan', () => {
    const report = buildLocalReport(makeScan('scan-1'))

    saveScanReport('scan-1', report)
    expect(getScanReport('scan-1')?.target).toBe('https://contoh.com/path')

    deleteScanReport('scan-1')
    expect(getScanReport('scan-1')).toBeNull()
  })

  it('membatasi laporan yang disimpan ke 30 terbaru', () => {
    for (let index = 0; index < 31; index += 1) {
      const report = buildLocalReport(makeScan(`scan-${index}`))
      report.generatedAt = new Date(Date.UTC(2026, 0, index + 1)).toISOString()
      saveScanReport(`scan-${index}`, report)
    }

    expect(getScanReport('scan-0')).toBeNull()
    expect(getScanReport('scan-30')).not.toBeNull()
  })

  it('mengabaikan laporan yang tidak valid saat dibaca', () => {
    expect(getScanReport('tidak-ada')).toBeNull()
  })

  it('mempertahankan laporan memori saat localStorage gagal menulis karena kuota', () => {
    const data = new Map<string, string>()
    let quotaExceeded = false
    const storage = {
      getItem: (key: string) => data.get(key) ?? null,
      setItem: (key: string, value: string) => {
        if (key === MULTI_SOURCE_STORAGE_KEY && quotaExceeded) {
          throw new DOMException('Kuota penyimpanan penuh', 'QuotaExceededError')
        }
        data.set(key, value)
      },
      removeItem: (key: string) => {
        data.delete(key)
      },
    } as Storage

    vi.stubGlobal('window', { localStorage: storage })

    try {
      const first = buildLocalReport(makeScan('scan-1'))
      expect(saveScanReport('scan-1', first)).toBe(true)

      quotaExceeded = true
      const second = buildLocalReport(makeScan('scan-2'))
      expect(saveScanReport('scan-2', second)).toBe(false)
      expect(getScanReport('scan-1')).not.toBeNull()
      expect(getScanReport('scan-2')).not.toBeNull()
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('melewatkan laporan yang tidak membawa URL sensitif tanpa perubahan', () => {
    const report = buildLocalReport(makeScan('scan-1'))

    expect(toStoredReport(report)).toBe(report)
  })

  describe('dengan localStorage', () => {
    afterEach(() => {
      vi.unstubAllGlobals()
    })

    function stubStorage(): {
      data: Map<string, string>
      setItem: ReturnType<typeof vi.fn>
    } {
      const data = new Map<string, string>()
      const setItem = vi.fn((key: string, value: string) => {
        data.set(key, value)
      })
      vi.stubGlobal('window', {
        localStorage: {
          length: data.size,
          clear: () => data.clear(),
          getItem: (key: string) => data.get(key) ?? null,
          key: (index: number) => [...data.keys()][index] ?? null,
          setItem,
          removeItem: (key: string) => {
            data.delete(key)
          },
        } satisfies Storage,
      })

      return { data, setItem }
    }

    it('menyimpan laporan sensitif dengan target yang sudah disamarkan', () => {
      stubStorage()

      const report = buildLocalReport(makeScan('scan-1'))
      report.target = 'https://contoh.com/masuk?token=abcdef1234567890'
      report.sensitiveUrl = true

      expect(saveScanReport('scan-1', report)).toBe(true)

      const stored = getScanReport('scan-1')
      expect(stored?.target).toBe('https://contoh.com/masuk')
      expect(stored?.sensitiveUrl).toBe(true)
      expect(report.target).toBe('https://contoh.com/masuk?token=abcdef1234567890')
    })

    it('menyamarkan laporan sensitif lama saat dibaca lalu menulis ulang sekali', () => {
      const { data, setItem } = stubStorage()

      const legacy = buildLocalReport(makeScan('scan-1'))
      legacy.target = 'https://contoh.com/reset/abcdefghijklmnop123456'
      legacy.sensitiveUrl = true
      data.set(MULTI_SOURCE_STORAGE_KEY, JSON.stringify({ 'scan-1': legacy }))

      const expected = `https://contoh.com/reset/${REDACTED_PATH_SEGMENT}`
      expect(getScanReport('scan-1')?.target).toBe(expected)

      const persistedWrites = () =>
        setItem.mock.calls.filter(([key]) => key === MULTI_SOURCE_STORAGE_KEY).length
      const writesBefore = persistedWrites()
      expect(getScanReport('scan-1')?.target).toBe(expected)
      expect(persistedWrites()).toBe(writesBefore)

      const persisted = JSON.parse(data.get(MULTI_SOURCE_STORAGE_KEY) ?? '{}') as {
        'scan-1': { target: string }
      }
      expect(persisted['scan-1']?.target).toBe(expected)
    })

    it('membaca ulang isi yang sama tanpa mengurai ulang penyimpanan', () => {
      const { data } = stubStorage()
      const report = buildLocalReport(makeScan('scan-1'))
      data.set(MULTI_SOURCE_STORAGE_KEY, JSON.stringify({ 'scan-1': report }))

      const parseSpy = vi.spyOn(JSON, 'parse')
      try {
        const first = getScanReport('scan-1')
        expect(first?.target).toBe(report.target)

        const parsesAfterFirst = parseSpy.mock.calls.length
        expect(getScanReport('scan-1')?.target).toBe(report.target)
        expect(getScanReport('scan-1')).toBe(first)
        expect(parseSpy.mock.calls.length).toBe(parsesAfterFirst)

        // Kunci cache adalah isi penyimpanan, bukan identitas panggilan: begitu isinya
        // berubah, entri baru ikut terbaca tanpa kehilangan salinan memori yang lebih baru.
        data.set(
          MULTI_SOURCE_STORAGE_KEY,
          JSON.stringify({
            'scan-1': { ...report, target: 'https://lain.example' },
            'scan-2': { ...report, target: 'https://baru.example' },
          }),
        )
        expect(getScanReport('scan-2')?.target).toBe('https://baru.example')
        expect(getScanReport('scan-1')?.target).toBe(report.target)
        expect(parseSpy.mock.calls.length).toBeGreaterThan(parsesAfterFirst)
      } finally {
        parseSpy.mockRestore()
      }
    })
  })
})

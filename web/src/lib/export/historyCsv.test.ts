import { describe, expect, it } from 'vitest'
import type { ScanResult } from '../analysis/types'
import {
  buildHistoryCsv,
  escapeCsvCell,
  HISTORY_CSV_HEADERS,
  historyCsvFilename,
  neutralizeCsvCell,
} from './historyCsv'

function makeScan(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    id: 'scan-1',
    createdAt: '2026-10-21T06:00:00.000Z',
    mode: 'link',
    input: 'https://contoh.com',
    displayTarget: 'contoh.com',
    riskScore: 64,
    riskLevel: 'high',
    headline: 'Indikasi risiko tinggi',
    summary: 'Beberapa indikator perlu diverifikasi.',
    reasons: [
      {
        id: 'brand_impersonation',
        label: 'Nama merek pada domain tidak resmi',
        detail: 'Detail indikator.',
        severity: 'danger',
        weight: 28,
        category: 'impersonation',
      },
    ],
    patterns: [
      {
        id: 'phishing',
        label: 'Phishing',
        description: 'Upaya memperoleh data.',
        confidence: 'high',
      },
    ],
    recommendations: ['Verifikasi melalui kanal resmi.'],
    technical: [],
    meta: {
      engineVersion: 'test',
      signalCount: 1,
      inputLength: 20,
      aiStatus: 'not_used',
      inputStored: 'full',
    },
    ...overrides,
  }
}

describe('ekspor CSV riwayat', () => {
  it('menetralkan sel yang dapat menjadi formula', () => {
    expect(neutralizeCsvCell('=SUM(A1:A2)')).toBe("'=SUM(A1:A2)")
    expect(neutralizeCsvCell('+1+1')).toBe("'+1+1")
    expect(neutralizeCsvCell('-2')).toBe("'-2")
    expect(neutralizeCsvCell('@SUM(A1)')).toBe("'@SUM(A1)")
    expect(neutralizeCsvCell('\t=cmd')).toBe("'\t=cmd")
    expect(neutralizeCsvCell('   =cmd')).toBe("'   =cmd")
  })

  it('mengapit sel, menggandakan tanda kutip, dan menghapus baris baru', () => {
    expect(escapeCsvCell('a,"b"')).toBe('"a,""b"""')
    expect(escapeCsvCell('baris1\nbaris2')).toBe('"baris1 baris2"')
  })

  it('menyusun header, BOM, baris, dan status redaksi', () => {
    const csv = buildHistoryCsv([
      makeScan(),
      makeScan({
        id: 'scan-2',
        mode: 'message',
        input: 'Cuplikan pesan [angka]',
        displayTarget: 'Cuplikan pesan [angka]',
        meta: {
          engineVersion: 'test',
          signalCount: 1,
          inputLength: 100,
          aiStatus: 'not_used',
          inputStored: 'redacted',
        },
      }),
    ])

    expect(csv.startsWith('\uFEFF')).toBe(true)
    expect(csv).toContain(`"${HISTORY_CSV_HEADERS[0]}"`)
    expect(csv.split('\r\n')).toHaveLength(3)
    expect(csv).toContain('"Ya"')
    expect(csv).toContain('"Tidak berlaku"')
    expect(csv).toContain('"https://contoh.com"')
  })

  it('menetralkan formula dari data pemeriksaan yang diekspor', () => {
    const csv = buildHistoryCsv([
      makeScan({
        input: '=HYPERLINK("https://evil.example","klik")',
        summary: '+cmd|/c calc',
      }),
    ])

    expect(csv).not.toContain(`,"=HYPERLINK`)
    expect(csv).not.toContain(`,"+cmd`)
    expect(csv).toContain(`"'=HYPERLINK`)
    expect(csv).toContain(`"'+cmd`)
  })

  it('membuat nama berkas dengan tanggal aman', () => {
    expect(historyCsvFilename(new Date('2026-10-21T12:00:00.000Z'))).toBe(
      'veriguard-riwayat-2026-10-21.csv',
    )
  })
})

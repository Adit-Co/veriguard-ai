import { describe, expect, it } from 'vitest'
import type { ScanDraft } from '../analysis/types'
import { createScan, toStoredScan } from '../storage/scanStore'
import { fromCloudScanDocument, toCloudScanDocument } from './scanDocuments'

function makeScan() {
  const draft: ScanDraft = {
    mode: 'link',
    input: 'https://contoh.example/login',
    displayTarget: 'https://contoh.example/login',
    riskScore: 20,
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
      inputLength: 28,
      aiStatus: 'not_used',
      inputStored: 'full',
    },
  }

  return createScan(draft)
}

describe('dokumen scan Firestore', () => {
  it('menyimpan ownerId dan mengembalikan scan yang valid', () => {
    const scan = makeScan()
    const document = toCloudScanDocument(scan, 'user-1')
    const parsed = fromCloudScanDocument(scan.id, document, 'user-1')

    expect(document.ownerId).toBe('user-1')
    expect(parsed).toEqual(scan)
    expect(parsed).not.toHaveProperty('ownerId')
  })

  it('menolak dokumen milik pengguna lain', () => {
    const scan = makeScan()

    expect(
      fromCloudScanDocument(scan.id, toCloudScanDocument(scan, 'user-1'), 'user-2'),
    ).toBeNull()
  })

  it('menolak dokumen dengan struktur scan rusak', () => {
    const scan = makeScan()
    const document = toCloudScanDocument(scan, 'user-1')

    expect(
      fromCloudScanDocument(scan.id, { ...document, reasons: [{ id: 'rusak' }] }, 'user-1'),
    ).toBeNull()
    expect(fromCloudScanDocument(scan.id, { ...document, ownerId: 123 }, 'user-1')).toBeNull()
  })

  it('salinan tersamar tetap menjadi dokumen yang sah saat dibaca perangkat lain', () => {
    const token = 'abcdefghijklmnop123456'
    const input = `https://contoh.example/reset?token=${token}`
    const draft: ScanDraft = {
      mode: 'link',
      input,
      displayTarget: `contoh.example${input.slice(input.indexOf('/'), 40)}`,
      riskScore: 40,
      riskLevel: 'medium',
      headline: 'Tautan membawa parameter sensitif',
      summary: `Alamat ${input} memakai parameter token.`,
      reasons: [
        {
          id: 'sensitive-query',
          label: 'Parameter token',
          detail: `Nilai ${token} dikirim di query.`,
          severity: 'warning',
          weight: 20,
          category: 'url-structure',
        },
      ],
      patterns: [],
      recommendations: ['Buka ulang alamat tanpa token.'],
      technical: [{ label: 'Alamat diperiksa', value: input }],
      meta: {
        engineVersion: 'test',
        signalCount: 1,
        inputLength: input.length,
        aiStatus: 'not_used',
      },
    }

    const stored = toStoredScan(createScan(draft))
    const document = toCloudScanDocument(stored, 'user-1')

    expect(stored.meta.inputStored).toBe('redacted')
    expect(JSON.stringify(document)).not.toContain(token)
    expect(fromCloudScanDocument(stored.id, document, 'user-1')).toEqual(stored)
  })
})

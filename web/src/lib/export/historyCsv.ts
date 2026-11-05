import { riskLabel } from '../analysis/risk'
import type { ScanResult } from '../analysis/types'

export const HISTORY_CSV_HEADERS = [
  'Waktu',
  'Jenis',
  'Target',
  'Tingkat risiko',
  'Skor indikator',
  'Ringkasan',
  'Indikator utama',
  'Pola',
  'Isi pesan disamarkan',
] as const

const FORMULA_PREFIX = /^[=+\-@\t\r]/
const FORMULA_AFTER_SPACE = /^\s+[=+\-@]/

export function neutralizeCsvCell(value: string): string {
  const normalized = value.replace(/\r\n?/g, '\n').replace(/\n/g, ' ')

  if (FORMULA_PREFIX.test(normalized) || FORMULA_AFTER_SPACE.test(normalized)) {
    return `'${normalized}`
  }

  return normalized
}

export function escapeCsvCell(value: string): string {
  const safe = neutralizeCsvCell(value)
  return `"${safe.replace(/"/g, '""')}"`
}

function scanRow(scan: ScanResult): string[] {
  return [
    scan.createdAt,
    scan.mode === 'link' ? 'Tautan' : 'Pesan',
    scan.input,
    riskLabel(scan.riskLevel),
    String(scan.riskScore),
    scan.summary,
    scan.reasons.map((reason) => reason.label).join('; '),
    scan.patterns.map((pattern) => pattern.label).join('; '),
    scan.mode === 'message'
      ? scan.meta.inputStored === 'redacted'
        ? 'Ya'
        : 'Tidak'
      : 'Tidak berlaku',
  ]
}

export function buildHistoryCsv(scans: ScanResult[]): string {
  const rows = [
    [...HISTORY_CSV_HEADERS],
    ...scans.map((scan) => scanRow(scan)),
  ]

  const csv = rows
    .map((row) => row.map((cell) => escapeCsvCell(cell)).join(','))
    .join('\r\n')

  return `\uFEFF${csv}`
}

export function historyCsvFilename(date = new Date()): string {
  return `veriguard-riwayat-${date.toISOString().slice(0, 10)}.csv`
}

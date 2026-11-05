import type { ScanResult } from '../analysis'
import { buildHistoryCsv, historyCsvFilename } from './historyCsv'

export function downloadHistoryCsv(scans: ScanResult[]): boolean {
  if (scans.length === 0) return false

  const blob = new Blob([buildHistoryCsv(scans)], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = historyCsvFilename()
  document.body.append(anchor)
  anchor.click()
  anchor.remove()

  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  return true
}

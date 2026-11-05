import type { ScanResult } from '../analysis/types'
import { isScanResult } from '../storage/scanStore'

export type CloudScanDocument = ScanResult & { ownerId: string }

export function toCloudScanDocument(scan: ScanResult, ownerId: string): CloudScanDocument {
  return {
    ...scan,
    technical: scan.technical.map(({ label, value, tone }) =>
      tone ? { label, value, tone } : { label, value },
    ),
    ownerId,
  }
}

export function fromCloudScanDocument(
  id: string,
  data: Record<string, unknown> | undefined,
  expectedOwnerId?: string,
): ScanResult | null {
  if (!data || typeof data.ownerId !== 'string') return null
  if (expectedOwnerId && data.ownerId !== expectedOwnerId) return null

  const scanData: Record<string, unknown> = { ...data }
  delete scanData.ownerId
  const candidate = { ...scanData, id }

  return isScanResult(candidate) ? candidate : null
}

import type { LookupStatus, SectionStatus } from '../../lib/website/types'

export type BadgeTone = 'neutral' | 'accent' | 'low' | 'medium' | 'high' | 'info'

const LOOKUP_TONES: Record<LookupStatus, { label: string; tone: BadgeTone }> = {
  success: { label: 'Berhasil', tone: 'low' },
  empty: { label: 'Tidak ada data', tone: 'neutral' },
  failed: { label: 'Gagal', tone: 'high' },
  timeout: { label: 'Melebihi batas waktu', tone: 'medium' },
  blocked: { label: 'Diblokir kebijakan', tone: 'medium' },
  unavailable: { label: 'Tidak tersedia', tone: 'neutral' },
}

const SECTION_TONES: Record<SectionStatus, { label: string; tone: BadgeTone }> = {
  complete: { label: 'Selesai', tone: 'low' },
  partial: { label: 'Sebagian tersedia', tone: 'medium' },
  unavailable: { label: 'Tidak tersedia', tone: 'neutral' },
  failed: { label: 'Gagal', tone: 'high' },
}

export function lookupBadge(status: LookupStatus): { label: string; tone: BadgeTone } {
  return LOOKUP_TONES[status]
}

export function sectionBadge(status: SectionStatus): { label: string; tone: BadgeTone } {
  return SECTION_TONES[status]
}

export function formatDateTime(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Waktu tidak diketahui'
  return new Intl.DateTimeFormat('id-ID', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

export function formatDuration(value: number): string {
  if (value < 1_000) return `${Math.round(value)} ms`
  return `${(value / 1_000).toFixed(1)} dtk`
}

export function formatBytes(value: number): string {
  if (value < 1_024) return `${value} B`
  if (value < 1_024 * 1_024) return `${(value / 1_024).toFixed(1)} KiB`
  return `${(value / (1_024 * 1_024)).toFixed(2)} MiB`
}

import type { Label, Split } from './metrics.js'

/**
 * Skema catatan dataset evaluasi. Semua teks HTML/registrasi di dalam dataset
 * adalah konstruk sintetis: harness tidak pernah menghubungi host sungguhan.
 * Lihat evaluation/MANIFEST.md untuk asal-usul dan lisensi.
 */

export const URL_CATEGORIES = [
  'known_phishing',
  'novel_phishing',
  'typosquat',
  'unicode_homoglyph',
  'redirect_shortener',
  'credential_harvesting',
  'legitimate',
  'legitimate_login_page',
  'brand_related_legitimate',
] as const

export type UrlCategory = (typeof URL_CATEGORIES)[number]

export const MESSAGE_CATEGORIES = [
  'indonesian_phishing_message',
  'indonesian_loan_offer_message',
  'benign_message_similar_keywords',
  'benign_official_notification',
] as const

export type MessageCategory = (typeof MESSAGE_CATEGORIES)[number]

export type RegistrationFixture = {
  createdAt: string | null
  expiresAt?: string | null
  registrar?: string | null
}

export type UrlRecord = {
  id: string
  split: Split
  label: Label
  category: UrlCategory
  url: string
  note?: string
  html?: string
  /**
   * Nilai Location yang dijawab fixture untuk tiap lompatan, berurutan dari
   * permintaan pertama; dokumen html dipakai setelah lompatan terakhir habis.
   */
  redirectChain?: string[]
  registration?: RegistrationFixture
}

export type MessageRecord = {
  id: string
  split: Split
  label: Label
  category: MessageCategory
  text: string
  note?: string
}

function fail(message: string): never {
  throw new Error(message)
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], what: string): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) {
    fail(`${what} tidak valid: ${JSON.stringify(value)}`)
  }
  return value as T
}

function stringOf(value: unknown, what: string): string {
  if (typeof value !== 'string' || value.trim() === '') fail(`${what} harus string tidak kosong`)
  return value
}

function parseLine(raw: string, index: number): unknown {
  const line = raw.trim()
  if (line === '' || line.startsWith('#')) return null
  try {
    return JSON.parse(line)
  } catch {
    return fail(`Baris ${index + 1} bukan JSON yang sah: ${line.slice(0, 80)}`)
  }
}

function assertUnique(ids: string[], id: string, where: string): void {
  if (ids.includes(id)) fail(`ID duplikat pada ${where}: ${id}`)
  ids.push(id)
}

export function parseUrlDataset(text: string): UrlRecord[] {
  const records: UrlRecord[] = []
  const ids: string[] = []

  text.split(/\r?\n/).forEach((raw, index) => {
    const value = parseLine(raw, index)
    if (value === null) return
    const record = value as Partial<UrlRecord>

    const id = stringOf(record.id, 'id')
    assertUnique(ids, id, 'dataset URL')

    const url = stringOf(record.url, 'url')
    let parsed: URL
    try {
      parsed = new URL(url)
    } catch {
      fail(`URL ${id} tidak dapat diurai: ${url}`)
    }
    // Validasi di sini memastikan dataset tidak memuat teks yang bukan URL;
    // harness tidak menambah skema secara diam-diam.
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      fail(`URL ${id} memakai skema ${parsed.protocol}`)
    }

    if (record.registration) {
      const created = record.registration.createdAt
      if (created !== null && (typeof created !== 'string' || Number.isNaN(Date.parse(created)))) {
        fail(`registration.createdAt pada ${id} bukan tanggal yang sah`)
      }
    }

    for (const hop of record.redirectChain ?? []) stringOf(hop, `redirectChain pada ${id}`)

    records.push({
      id,
      split: oneOf(record.split, ['dev', 'holdout'] as const, `split pada ${id}`),
      label: oneOf(record.label, ['phishing', 'legitimate'] as const, `label pada ${id}`),
      category: oneOf(record.category, URL_CATEGORIES, `category pada ${id}`),
      url,
      note: typeof record.note === 'string' ? record.note : undefined,
      html: typeof record.html === 'string' ? record.html : undefined,
      redirectChain: Array.isArray(record.redirectChain) ? record.redirectChain : undefined,
      registration: record.registration,
    })
  })

  return records
}

export function parseMessageDataset(text: string): MessageRecord[] {
  const records: MessageRecord[] = []
  const ids: string[] = []

  text.split(/\r?\n/).forEach((raw, index) => {
    const value = parseLine(raw, index)
    if (value === null) return
    const record = value as Partial<MessageRecord>

    const id = stringOf(record.id, 'id')
    assertUnique(ids, id, 'dataset pesan')

    records.push({
      id,
      split: oneOf(record.split, ['dev', 'holdout'] as const, `split pada ${id}`),
      label: oneOf(record.label, ['phishing', 'legitimate'] as const, `label pada ${id}`),
      category: oneOf(record.category, MESSAGE_CATEGORIES, `category pada ${id}`),
      text: stringOf(record.text, `text pada ${id}`),
      note: typeof record.note === 'string' ? record.note : undefined,
    })
  })

  return records
}

export function datasetCensus<T extends { split: Split; label: Label; category: string }>(
  records: readonly T[],
): string[] {
  const counts = new Map<string, number>()
  for (const record of records) {
    const key = `${record.split}/${record.label}/${record.category}`
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, n]) => `${key} = ${n}`)
}

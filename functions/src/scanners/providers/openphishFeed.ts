import { fetchJson, type FetchJsonResult } from '../http.js'
import type { ScanCacheConfig } from '../types.js'

// Feed komunitas resmi OpenPhish; berkas teks daftar URL phish, diperbarui ±12 jam.
// Isinya tidak bergantung pada URL yang diperiksa, jadi yang layak di-cache adalah
// UNDUHAN FEED-nya, bukan hasil per URL. Satu snapshot global berlaku untuk semua
// pemeriksaan dalam proses yang sama.
export const FEED_ENDPOINT =
  'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt'

export const FEED_TIMEOUT_MS = 8_000
// Penjaga saja: feed resmi berukuran belasan kilobyte.
const MAX_FEED_BYTES = 512_000

// Indeks pencarian dibangun sekali per unduhan feed. Isinya tidak bergantung pada URL yang
// diperiksa, jadi menguraikan setiap baris per pemeriksaan hanya membayar kerja yang sama
// berulang kali. Bentuk pencocokan tetap identik dengan pembacaan baris per baris.
export type FeedIndex = {
  lowerUrls: Set<string>
  hostCounts: Map<string, number>
}

export type FeedSnapshot = {
  lines: string[]
  index: FeedIndex
  fetchedAt: string
  fetchedAtMs: number
  ageMs: number
  // Snapshot dipakai melewati TTL-nya karena ulang-unduh sedang gagal. Selalu disoroti ke
  // pengguna; tidak pernah disajikan sebagai data segar.
  stale: boolean
  refreshFailure: string | null
}

export type FeedOutcome =
  | { ok: true; snapshot: FeedSnapshot }
  | { ok: false; reason: string; failure: Extract<FetchJsonResult, { ok: false }> | null }

export type FeedOptions = {
  fetchImpl: typeof fetch
  now: () => number
  // Kebijakan cache. Tanpa policy, snapshot tidak disimpan dan tiap pemeriksaan mengunduh
  // feed sendiri; penyatuan unduhan yang sedang berjalan tetap aktif.
  cache?: ScanCacheConfig
  timeoutMs?: number
}

type StoredSnapshot = {
  lines: string[]
  index: FeedIndex
  fetchedAtMs: number
}

type RefreshResult =
  | { ok: true; lines: string[]; index: FeedIndex; fetchedAtMs: number }
  | {
      ok: false
      reason: string
      failure: Extract<FetchJsonResult, { ok: false }> | null
    }

let stored: StoredSnapshot | null = null
let refreshing: Promise<RefreshResult> | null = null
let feedDownloads = 0

export function parseFeedLines(text: string): string[] {
  return text
    .slice(0, MAX_FEED_BYTES)
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('http'))
}

export function buildFeedIndex(lines: string[]): FeedIndex {
  const lowerUrls = new Set<string>()
  const hostCounts = new Map<string, number>()

  for (const line of lines) {
    lowerUrls.add(line.toLowerCase())
    try {
      const host = new URL(line).hostname.toLowerCase()
      hostCounts.set(host, (hostCounts.get(host) ?? 0) + 1)
    } catch {
      // Baris yang tidak dapat diurai dilewati; sama seperti pembacaan langsung.
    }
  }

  return { lowerUrls, hostCounts }
}

function toSnapshot(
  snapshot: StoredSnapshot,
  nowMs: number,
  stale: boolean,
  refreshFailure: string | null,
): FeedSnapshot {
  return {
    lines: snapshot.lines,
    index: snapshot.index,
    fetchedAt: new Date(snapshot.fetchedAtMs).toISOString(),
    fetchedAtMs: snapshot.fetchedAtMs,
    ageMs: Math.max(0, nowMs - snapshot.fetchedAtMs),
    stale,
    refreshFailure,
  }
}

function startRefresh(options: FeedOptions, keep: boolean): Promise<RefreshResult> {
  const startedAtMs = options.now()

  const run = (async (): Promise<RefreshResult> => {
    feedDownloads += 1
    const response = await fetchJson(
      options.fetchImpl,
      FEED_ENDPOINT,
      { headers: { Accept: 'text/plain' } },
      options.timeoutMs ?? FEED_TIMEOUT_MS,
      'text',
    )

    if (!response.ok) return { ok: false, reason: response.reason, failure: response }
    if (typeof response.data !== 'string' || response.data.trim() === '') {
      return {
        ok: false,
        reason: 'Feed komunitas OpenPhish kosong atau tidak dapat dibaca.',
        failure: null,
      }
    }

    const lines = parseFeedLines(response.data)
    if (lines.length === 0) {
      return {
        ok: false,
        reason: 'Feed komunitas OpenPhish tidak memuat entri yang dapat dibaca.',
        failure: null,
      }
    }

    // Hanya respons yang benar-benar terpakai yang menggantikan snapshot. Feed kosong atau
    // rusak tidak pernah menghapus daftar yang masih berguna.
    const index = buildFeedIndex(lines)
    if (keep) stored = { lines, index, fetchedAtMs: startedAtMs }
    return { ok: true, lines, index, fetchedAtMs: startedAtMs }
  })()

  refreshing = run
  const clear = (): void => {
    if (refreshing === run) refreshing = null
  }
  run.then(clear, clear)

  return run
}

export async function loadOpenPhishFeed(options: FeedOptions): Promise<FeedOutcome> {
  const cache = options.cache
  const ttlMs = cache?.openPhishFeedTtlMs ?? 0
  const staleTtlMs = cache?.openPhishFeedStaleTtlMs ?? 0

  if (ttlMs > 0 && stored && options.now() - stored.fetchedAtMs < ttlMs) {
    return { ok: true, snapshot: toSnapshot(stored, options.now(), false, null) }
  }

  // Unduhan yang sedang berjalan dipakai bersama; permintaan kedua tidak memicu unduhan
  // ketiga, bahkan ketika cache hasil dimatikan.
  const result = await (refreshing ?? startRefresh(options, ttlMs > 0))

  if (result.ok) {
    return {
      ok: true,
      snapshot: toSnapshot(
        { lines: result.lines, index: result.index, fetchedAtMs: result.fetchedAtMs },
        options.now(),
        false,
        null,
      ),
    }
  }

  // stale-if-error: snapshot yang umurnya masih masuk akal lebih baik daripada tidak ada
  // pemeriksaan sama sekali, selama labelnya jujur dan umurnya dibatasi jendela stale.
  if (staleTtlMs > 0 && stored && options.now() - stored.fetchedAtMs < staleTtlMs) {
    return {
      ok: true,
      snapshot: toSnapshot(stored, options.now(), true, result.reason),
    }
  }

  return { ok: false, reason: result.reason, failure: result.failure }
}

export function openPhishFeedDownloadCount(): number {
  return feedDownloads
}

export function resetOpenPhishFeedCache(): void {
  stored = null
  refreshing = null
  feedDownloads = 0
}

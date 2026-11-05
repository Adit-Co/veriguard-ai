import { fetchJson } from '../http.js'
import {
  booleanValue,
  errorCheck,
  failureCheck,
  formatObservedAt,
  notFoundCheck,
  recordValue,
} from '../result.js'
import {
  FEED_TIMEOUT_MS,
  loadOpenPhishFeed,
  type FeedSnapshot,
} from './openphishFeed.js'
import type {
  ProviderAdapter,
  ProviderCheck,
  ProviderSignal,
  ScannerConfig,
} from '../types.js'

// Endpoint lookup berkunci; hanya dipanggil bila pemilik mengisi OPENPHISH_API_KEY.
const LOOKUP_ENDPOINT = 'https://openphish.eu/api/check'
const LOOKUP_TIMEOUT_MS = 6_000

type KeyedOutcome =
  | { configured: false }
  | { configured: true; found: boolean | null; failure: string | null }

function readFeed(
  snapshot: FeedSnapshot,
  url: string,
  hostname: string,
): { exactMatch: boolean; hostMatches: number } {
  // Indeks sudah dibangun saat feed diunduh, jadi pemeriksaan tidak lagi mengurai ulang
  // seluruh baris untuk setiap URL.
  return {
    exactMatch: snapshot.index.lowerUrls.has(url.toLowerCase()),
    hostMatches: snapshot.index.hostCounts.get(hostname) ?? 0,
  }
}

// Umur snapshot feed selalu disebut bila hasil dibangun di atas data yang lebih tua dari
// TTL normalnya: vonis tidak berubah, tetapi kecocokan bisa saja berasal dari entri yang
// sudah lama. Waktu terakhir data diambil ditampilkan sebagai tanggal, bukan sebagai umur
// entri, dan penyebab kegagalan pemulihan data tidak ikut dikirim ke antarmuka.
function staleFeedSignal(snapshot: FeedSnapshot): ProviderSignal {
  return {
    label: 'Data feed belum terbaru',
    detail: `Sumber data agen ini terakhir diperbarui ${formatObservedAt(snapshot.fetchedAt)}, jadi kecocokan yang ditemukan bisa lebih tua dari pemeriksaan ini.`,
    severity: 'warning',
  }
}

async function fetchKeyedLookup(
  context: Parameters<ProviderAdapter['check']>[0],
  config: ScannerConfig,
): Promise<KeyedOutcome> {
  if (!config.openPhishApiKey) return { configured: false }

  const response = await fetchJson(
    context.fetchImpl,
    `${LOOKUP_ENDPOINT}?url=${encodeURIComponent(context.url)}`,
    { headers: { Authorization: `Bearer ${config.openPhishApiKey}` } },
    LOOKUP_TIMEOUT_MS,
  )

  if (!response.ok) {
    return { configured: true, found: null, failure: response.reason }
  }

  const found = booleanValue(recordValue(response.data)?.found)
  if (found === null) {
    return {
      configured: true,
      found: null,
      failure: 'Respons lookup OpenPhish tidak memuat field found.',
    }
  }

  return { configured: true, found, failure: null }
}

export const openPhishAdapter: ProviderAdapter = {
  id: 'openphish',
  label: 'OpenPhish',
  // Dua permintaan baca masing-masing dibatasi 8 dan 6 detik; batas provider dibuat eksplisit
  // agar mirror lookup yang lambat tidak ikut menahan anggaran provider lain.
  timeoutMs: 20_000,
  isConfigured: () => true,
  async check(context, config): Promise<ProviderCheck> {
    const [feed, keyed] = await Promise.all([
      loadOpenPhishFeed({
        fetchImpl: context.fetchImpl,
        now: context.now,
        timeoutMs: FEED_TIMEOUT_MS,
        ...(config.scanCache ? { cache: config.scanCache } : {}),
      }),
      fetchKeyedLookup(context, config),
    ])

    const failures: string[] = []
    if (!feed.ok) failures.push(feed.reason)
    if (keyed.configured && keyed.failure) failures.push(keyed.failure)
    const snapshot = feed.ok ? feed.snapshot : null
    const usingStaleFeed = snapshot?.stale === true
    const match = snapshot ? readFeed(snapshot, context.url, context.hostname) : null

    const withProvenance = (check: ProviderCheck): ProviderCheck =>
      usingStaleFeed
        ? {
            ...check,
            signals: [...check.signals, staleFeedSignal(snapshot)],
            staleEvidence: true,
          }
        : check

    if (keyed.configured && keyed.found === true) {
      return withProvenance({
        status: 'success',
        verdict: 'malicious',
        score: 85,
        summary: 'OpenPhish melaporkan URL ini sebagai phishing aktif pada endpoint berkuncinya.',
        signals: [
          {
            label: 'URL tercatat pada lookup OpenPhish',
            detail: 'Sumber: endpoint lookup berkunci (bukan feed komunitas).',
            severity: 'danger',
          },
        ],
        reason: null,
      })
    }

    if (match?.exactMatch) {
      return withProvenance({
        status: 'success',
        verdict: 'malicious',
        score: 85,
        summary: 'OpenPhish mencatat URL ini pada feed komunitas resminya.',
        signals: [
          {
            label: 'URL tercatat di feed OpenPhish',
            detail: 'Entri feed identik dengan URL yang diperiksa.',
            severity: 'danger',
          },
        ],
        reason: null,
      })
    }

    // Cocok pada hostname yang sama: bukti nyata dari feed, tetapi levelnya bukan URL persis.
    if (match && match.hostMatches > 0) {
      return withProvenance({
        status: 'success',
        verdict: 'suspicious',
        score: 55,
        summary: `OpenPhish tidak mencatat URL ini persis, tetapi feed-nya memuat ${match.hostMatches} phish pada hostname yang sama.`,
        signals: [
          {
            label: 'Hostname tercatat di feed OpenPhish',
            detail: 'Pencocokan tingkat hostname, bukan kecocokan URL persis.',
            severity: 'warning',
          },
        ],
        reason: 'Vonis diberikan pada tingkat hostname; URL persis yang diperiksa tidak tercantum.',
      })
    }

    // Feed gagal tetapi sumber berkunci tetap menjawab "tidak ada": pakai jawabannya dan
    // catat kegagalannya. Bila tidak ada sumber yang menjawab, laporkan kegagalan teknis.
    if (!feed.ok && !(keyed.configured && keyed.found === false)) {
      if (feed.failure) return failureCheck(feed.failure)

      return errorCheck(
        failures.join(' ').slice(0, 240) || 'Sumber data OpenPhish tidak dapat dibaca.',
      )
    }

    const note = !feed.ok
      ? `Feed komunitas tidak dapat dibaca: ${feed.reason}`
      : keyed.configured && keyed.failure
        ? `Lookup berkunci gagal: ${keyed.failure}`
        : null

    const signals: ProviderSignal[] = [
      {
        label: 'Sumber data',
        detail: 'Feed komunitas OpenPhish (diperbarui ±12 jam, cakupan sampel publik terbatas).',
        severity: 'info',
      },
    ]

    // Tidak tercatat bukan bukti aman: status tetap not_found, tidak pernah menjadi clean.
    return withProvenance({
      ...notFoundCheck('OpenPhish tidak mencatat URL ini pada feed komunitasnya.'),
      signals,
      reason: `Tidak tercatat pada satu sumber phish bukan bukti URL aman.${note ? ` ${note}` : ''}`,
    })
  },
}

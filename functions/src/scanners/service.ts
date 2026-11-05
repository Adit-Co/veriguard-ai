import { readScannerConfig } from './config.js'
import { detectSensitiveUrl } from './privacy.js'
import { PROVIDER_ADAPTERS } from './providers/index.js'
import { consumeScanRateLimit } from './rateLimit.js'
import {
  buildProviderCacheKeys,
  pruneProviderCache,
  readProviderCache,
  scanDedupKey,
  writeProviderCache,
} from './providerCache.js'
import { runSharedScan } from './inFlight.js'
import { clampScore, errorCheck, notConfiguredCheck, skippedCheck, timeoutCheck } from './result.js'
import type {
  MultiSourceScanResponse,
  ProviderAdapter,
  ProviderCheck,
  ProviderContext,
  ProviderResult,
  ProviderResultCache,
  ScanCacheMeta,
  ScanProgressEvent,
  ScannerConfig,
  ScannerProviderId,
} from './types.js'
import { normalizeScanUrl, ScanUrlError } from './url.js'
import type { RateLimitDecision } from '../state/stores.js'

const DEFAULT_PROVIDER_TIMEOUT_MS = 50_000
// Tetap di bawah DEFAULT_SCAN_TIMEOUT_MS agar satu provider lambat tidak menyetop seluruh scan.
const MAX_PROVIDER_TIMEOUT_MS = 75_000
const DEFAULT_PROVIDER_CONCURRENCY = 4
const DEFAULT_SCAN_TIMEOUT_MS = 80_000
const MAX_SCAN_TIMEOUT_MS = 85_000

/**
 * Pemakan kuota pemeriksaan. Bentuknya sengaja sama dengan consumeScanRateLimit supaya
 * pemanggil boleh menyuntikkan hitungan yang hidup di state bersama (Durable Object Worker)
 * dan tidak bergantung pada memori satu isolate.
 */
export type ScanQuotaConsumer = (
  uid: string,
  now: number,
) => RateLimitDecision | Promise<RateLimitDecision>

export type RunMultiSourceScanInput = {
  uid: string
  url: string
  scanId?: string
  config?: ScannerConfig
  fetchImpl?: typeof fetch
  now?: () => number
  sleep?: (ms: number) => Promise<void>
  adapters?: ProviderAdapter[]
  concurrency?: number
  providerTimeoutMs?: number
  scanTimeoutMs?: number
  signal?: AbortSignal
  onEvent?: (event: ScanProgressEvent) => void | Promise<void>
  // Tanpa konsumen ini kuota dihitung di memori proses (lihat rateLimit.ts): isolate lain
  // tidak ikut melihatnya, jadi batas bisa terbagi sebanyak jumlah isolate.
  consumeRateLimit?: ScanQuotaConsumer
}

// Gerbang yang sudah dinilai sekali per permintaan. Dibagikan ke pelaksanaan yang mungkin
// dipakai bersama beberapa permintaan supaya batas laju TIDAK dihitung dua kali.
type ScanGates = {
  normalizedUrl: string
  privacy: ReturnType<typeof detectSensitiveUrl>
  scanLimit: ReturnType<typeof consumeScanRateLimit> | null
  cacheKeys: Partial<Record<ScannerProviderId, string>> | null
}

type ProviderExecution = {
  id: ScannerProviderId
  shared: boolean
  result: ProviderResult
}

class ProviderTimeoutError extends Error {
  constructor() {
    super('timeout')
    this.name = 'ProviderTimeoutError'
  }
}

class ProviderAbortedError extends Error {
  constructor() {
    super('aborted')
    this.name = 'ProviderAbortedError'
  }
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

function createScanId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID()
  }

  return `scan_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`
}

function combineSignals(
  ...signals: Array<AbortSignal | undefined>
): AbortSignal | undefined {
  const active = signals.filter((signal): signal is AbortSignal => Boolean(signal))
  if (active.length === 0) return undefined
  if (active.length === 1) return active[0]

  const anySignal = (
    AbortSignal as typeof AbortSignal & {
      any?: (signals: AbortSignal[]) => AbortSignal
    }
  ).any

  if (typeof anySignal === 'function') return anySignal(active)

  const controller = new AbortController()
  for (const signal of active) {
    if (signal.aborted) {
      controller.abort(signal.reason)
      break
    }
    signal.addEventListener('abort', () => controller.abort(signal.reason), { once: true })
  }
  return controller.signal
}

function abortPromise(
  signal: AbortSignal,
  wasTimeout: () => boolean,
): Promise<never> {
  return new Promise((_resolve, reject) => {
    const onAbort = () => {
      reject(wasTimeout() ? new ProviderTimeoutError() : new ProviderAbortedError())
    }

    if (signal.aborted) {
      onAbort()
      return
    }

    signal.addEventListener('abort', onAbort, { once: true })
  })
}

async function withProviderTimeout<T>(
  task: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
  externalSignal?: AbortSignal,
): Promise<T> {
  const controller = new AbortController()
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeoutMs)
  const onExternalAbort = () => controller.abort()
  externalSignal?.addEventListener('abort', onExternalAbort, { once: true })

  try {
    if (externalSignal?.aborted) controller.abort()
    return await Promise.race([
      task(controller.signal),
      abortPromise(controller.signal, () => timedOut),
    ])
  } finally {
    clearTimeout(timer)
    externalSignal?.removeEventListener('abort', onExternalAbort)
  }
}

function toResult(
  adapter: ProviderAdapter,
  check: ProviderCheck,
  durationMs: number,
): ProviderResult {
  return {
    id: adapter.id,
    label: adapter.label,
    status: check.status,
    verdict: check.verdict,
    score: check.score === null ? null : clampScore(check.score),
    summary: check.summary,
    signals: check.signals.slice(0, 5),
    reason: check.reason ?? null,
    durationMs,
    ...(check.evidence ? { evidence: check.evidence } : {}),
    ...(check.negative ? { negative: check.negative } : {}),
  }
}

function withCacheMeta(
  result: ProviderResult,
  cache: ProviderResultCache,
): ProviderResult {
  return { ...result, cache }
}

// Ringkasan cache tingkat scan. `requestsAvoided` adalah jumlah agen yang jawabannya
// dipakai ulang, dan setiap satu di antaranya berarti minimal satu permintaan HTTP nyata
// yang tidak dikirim.
function buildScanCacheMeta(input: {
  reused: ScannerProviderId[]
  refreshed: ScannerProviderId[]
  oldestReusedAtMs: number | null
  nowMs: number
}): ScanCacheMeta {
  const { reused, refreshed } = input
  const status =
    reused.length === 0 ? 'miss' : refreshed.length === 0 ? 'hit' : 'partial'

  return {
    status,
    hit: status === 'hit',
    observedAt:
      input.oldestReusedAtMs === null ? null : new Date(input.oldestReusedAtMs).toISOString(),
    ageMs: input.oldestReusedAtMs === null ? 0 : Math.max(0, input.nowMs - input.oldestReusedAtMs),
    reusedProviders: reused,
    refreshedProviders: refreshed,
    requestsAvoided: reused.length,
  }
}

function uniformResponse(
  adapters: ProviderAdapter[],
  check: ProviderCheck,
  privacyReasons: string[],
  sensitive: boolean,
  startedAt: number,
  now: () => number,
  sharedWithProviders: ScannerProviderId[] = [],
): MultiSourceScanResponse {
  return {
    providers: adapters.map((adapter) => toResult(adapter, check, 0)),
    sharedWithProviders,
    sensitiveUrl: sensitive,
    privacyReasons,
    generatedAt: new Date(startedAt).toISOString(),
    durationMs: Math.max(0, now() - startedAt),
  }
}

function readConcurrency(value: number | undefined, total: number): number {
  if (!Number.isFinite(value)) return Math.min(DEFAULT_PROVIDER_CONCURRENCY, total)
  return Math.max(1, Math.min(total, Math.floor(value as number)))
}

function readTimeout(value: number | undefined): number {
  if (!Number.isFinite(value)) return DEFAULT_PROVIDER_TIMEOUT_MS
  // Batas atas dijaga tetap di bawah DEFAULT_SCAN_TIMEOUT_MS agar satu provider yang lambat
  // tidak membuat seluruh scan melampaui tenggat proses.
  return Math.max(1_000, Math.min(MAX_PROVIDER_TIMEOUT_MS, Math.floor(value as number)))
}

function readScanTimeout(value: number | undefined): number {
  if (!Number.isFinite(value)) return DEFAULT_SCAN_TIMEOUT_MS
  return Math.max(1_000, Math.min(MAX_SCAN_TIMEOUT_MS, Math.floor(value as number)))
}

async function executeScan(
  input: RunMultiSourceScanInput,
  resolvedGates?: ScanGates,
): Promise<MultiSourceScanResponse> {
  const now = input.now ?? Date.now
  const startedAt = now()
  const scanId = input.scanId?.trim() || createScanId()
  const adapters = input.adapters ?? PROVIDER_ADAPTERS
  const normalizedUrl = resolvedGates?.normalizedUrl ?? normalizeScanUrl(input.url)
  const privacy = resolvedGates?.privacy ?? detectSensitiveUrl(normalizedUrl)
  const config = input.config ?? readScannerConfig()
  const emit = async (event: ScanProgressEvent): Promise<void> => {
    if (!input.onEvent) return
    try {
      await input.onEvent(event)
    } catch {
      // Koneksi stream dapat tertutup sebelum provider selesai.
    }
  }
  const emitInit = async (
    sensitiveUrl: boolean,
    privacyReasons: string[],
  ): Promise<void> => {
    await emit({
      type: 'init',
      scanId,
      startedAt: new Date(startedAt).toISOString(),
      sensitiveUrl,
      privacyReasons,
      providers: adapters.map((adapter) => ({
        id: adapter.id,
        label: adapter.label,
        state: 'queued',
      })),
    })
  }
  const finishUniform = async (
    response: MultiSourceScanResponse,
  ): Promise<MultiSourceScanResponse> => {
    await emitInit(response.sensitiveUrl, response.privacyReasons)
    for (const result of response.providers) {
      await emit({
        type: 'provider',
        scanId,
        provider: {
          id: result.id,
          label: result.label,
          state: 'completed',
          result,
          shared: false,
        },
      })
    }
    await emit({ type: 'done', scanId, response })
    return response
  }

  if (privacy.sensitive) {
    const response = uniformResponse(
      adapters,
      skippedCheck('URL tidak dikirim karena memuat data sensitif.'),
      privacy.reasons,
      true,
      startedAt,
      now,
    )
    return finishUniform(response)
  }

  const scanLimit =
    resolvedGates?.scanLimit ?? (await (input.consumeRateLimit ?? consumeScanRateLimit)(input.uid, startedAt))
  if (!scanLimit.allowed) {
    const response = uniformResponse(
      adapters,
      {
        status: 'rate_limited',
        verdict: 'inconclusive',
        score: null,
        summary: 'Batas pemeriksaan eksternal tercapai.',
        signals: [],
        reason: `Batas pemeriksaan milik VERIGUARD tercapai, bukan kuota agen. Coba lagi dalam ±${scanLimit.retryAfterSeconds} detik.`,
      },
      [],
      false,
      startedAt,
      now,
    )
    return finishUniform(response)
  }

  const hostname = new URL(normalizedUrl).hostname
  const baseFetch = input.fetchImpl ?? fetch
  const sleep = input.sleep ?? defaultSleep
  const configured = new Set<ScannerProviderId>(
    adapters
      .filter((adapter) => adapter.isConfigured(config))
      .map((adapter) => adapter.id),
  )

  await emitInit(false, [])

  // Batas waktu keseluruhan proses scan. Harus tetap di bawah STREAM_TIMEOUT_MS
  // (90 detik) di web/src/lib/scanners/client.ts agar stream SSE tidak terputus
  // oleh sisi klien sebelum respons final terkirim.
  const deadlineControl = new AbortController()
  const deadlineTimer = setTimeout(
    () => deadlineControl.abort(),
    readScanTimeout(input.scanTimeoutMs),
  )
  const scanAbort = combineSignals(input.signal, deadlineControl.signal)

  try {
    const executions: Array<ProviderExecution | undefined> = new Array(adapters.length)
    const queue: Array<{ adapter: ProviderAdapter; index: number }> = []

    for (const [index, adapter] of adapters.entries()) {
      if (configured.has(adapter.id)) {
        queue.push({ adapter, index })
        continue
      }

      const required = adapter.requiredEnv ?? []
      const result = toResult(
        adapter,
        notConfiguredCheck(
          adapter.notConfiguredReason ??
            (required.length > 0
              ? `Provider ${adapter.label} belum dikonfigurasi. Isi ${required.join(', ')} di konfigurasi backend.`
              : `Provider ${adapter.label} belum dikonfigurasi di backend.`),
        ),
        0,
      )
      executions[index] = { id: adapter.id, shared: false, result }
      await emit({
        type: 'provider',
        scanId,
        provider: {
          id: adapter.id,
          label: adapter.label,
          state: 'completed',
          result,
          shared: false,
        },
      })
    }

    const concurrency = readConcurrency(input.concurrency, queue.length || 1)
    const defaultTimeoutMs = readTimeout(input.providerTimeoutMs)
    const timeoutFor = (adapter: ProviderAdapter): number =>
      adapter.timeoutMs === undefined ? defaultTimeoutMs : readTimeout(adapter.timeoutMs)
    let cursor = 0

    // Cache dibaca PER AGEN sesaat sebelum agen jalan: agen yang kena cache tidak pernah
    // memanggil fetchImpl sama sekali, jadi hematnya nyata, bukan sekadar menyimpan respons.
    const cacheKeys = resolvedGates?.cacheKeys ?? null
    const reusedProviders: ScannerProviderId[] = []
    const refreshedProviders: ScannerProviderId[] = []
    let oldestReusedAtMs: number | null = null

    const pendingReason = (): string => {
      if (deadlineControl.signal.aborted) {
        return 'Batas waktu keseluruhan proses scan tercapai.'
      }
      return 'Pemeriksaan dihentikan sebelum provider dijalankan.'
    }

    const runNext = async (): Promise<void> => {
      while (cursor < queue.length) {
        const item = queue[cursor]
        cursor += 1
        if (!item) return

        const { adapter, index } = item
        if (scanAbort?.aborted) {
          const result = toResult(adapter, skippedCheck(pendingReason()), 0)
          executions[index] = { id: adapter.id, shared: false, result }
          await emit({
            type: 'provider',
            scanId,
            provider: {
              id: adapter.id,
              label: adapter.label,
              state: 'completed',
              result,
              shared: false,
            },
          })
          continue
        }

        // Semua agen yang benar-benar diselesaikan pada permintaan ini lebih dulu tampil
        // berjalan di antarmuka — termasuk agen yang jawabannya diambil dari cache. Urutan
        // progres tetap sama untuk pengguna tanpa menambah permintaan keluar apa pun.
        await emit({
          type: 'provider',
          scanId,
          provider: {
            id: adapter.id,
            label: adapter.label,
            state: 'running',
          },
        })

        const cacheKey = cacheKeys?.[adapter.id]
        if (cacheKey) {
          const cached = readProviderCache(adapter.id, cacheKey, now)
          if (cached) {
            const result = withCacheMeta(
              toResult(adapter, cached.entry.check, 0),
              {
                hit: true,
                observedAt: cached.entry.observedAt,
                ageMs: cached.ageMs,
                stale: cached.entry.check.staleEvidence === true,
              },
            )
            executions[index] = { id: adapter.id, shared: false, result }
            reusedProviders.push(adapter.id)
            oldestReusedAtMs =
              oldestReusedAtMs === null
                ? cached.entry.observedAtMs
                : Math.min(oldestReusedAtMs, cached.entry.observedAtMs)
            await emit({
              type: 'provider',
              scanId,
              provider: {
                id: adapter.id,
                label: adapter.label,
                state: 'completed',
                result,
                // Tidak ada satu pun byte dikirim ke agen ini pada permintaan tersebut.
                shared: false,
              },
            })
            continue
          }
        }

        let shared = false
        const providerStartedAt = now()
        try {
          const check = await withProviderTimeout(
            async (providerSignal) => {
              const trackedFetch: typeof fetch = (request, init) => {
                shared = true
                const signal = combineSignals(init?.signal ?? undefined, providerSignal)
                return baseFetch(request, { ...init, signal })
              }
              const providerSleep = async (ms: number): Promise<void> => {
                if (providerSignal.aborted) throw new ProviderAbortedError()
                await sleep(ms)
                if (providerSignal.aborted) throw new ProviderAbortedError()
              }
              const context: ProviderContext = {
                url: normalizedUrl,
                hostname,
                fetchImpl: trackedFetch,
                now,
                sleep: providerSleep,
                signal: providerSignal,
              }
              return adapter.check(context, config)
            },
            timeoutFor(adapter),
            scanAbort,
          )

          const fresh = toResult(
            adapter,
            check,
            Math.max(0, now() - providerStartedAt),
          )
          const stored = cacheKey
            ? writeProviderCache(adapter.id, cacheKey, check, config, now)
            : null
          const result = stored
            ? withCacheMeta(fresh, {
                hit: false,
                observedAt: stored.observedAt,
                ageMs: 0,
                stale: check.staleEvidence === true,
              })
            : fresh
          executions[index] = { id: adapter.id, shared, result }
          refreshedProviders.push(adapter.id)
          await emit({
            type: 'provider',
            scanId,
            provider: {
              id: adapter.id,
              label: adapter.label,
              state: 'completed',
              result,
              shared,
            },
          })
        } catch (error) {
          const timedOut = error instanceof ProviderTimeoutError
          const aborted = error instanceof ProviderAbortedError
          const deadlineExceeded = !input.signal?.aborted && deadlineControl.signal.aborted
          const check = aborted
            ? deadlineExceeded
              ? timeoutCheck('Batas waktu keseluruhan proses scan tercapai.')
              : skippedCheck('Pemeriksaan dihentikan.')
            : timedOut
              ? timeoutCheck('Provider melebihi batas waktu pemrosesan.')
              : errorCheck('Provider gagal diproses.')
          const fresh = toResult(
            adapter,
            check,
            Math.max(0, now() - providerStartedAt),
          )
          // Kegagalan sementara ikut disimpan sebentar dengan STATUS aslinya (rate_limited /
          // unavailable / timeout) supaya satu gelombang kegagalan tidak memicu spam
          // permintaan. Status kegagalan tidak pernah diubah menjadi not_found.
          const stored = cacheKey
            ? writeProviderCache(adapter.id, cacheKey, check, config, now)
            : null
          const result = stored
            ? withCacheMeta(fresh, {
                hit: false,
                observedAt: stored.observedAt,
                ageMs: 0,
                stale: false,
              })
            : fresh
          executions[index] = { id: adapter.id, shared, result }
          refreshedProviders.push(adapter.id)
          await emit({
            type: 'provider',
            scanId,
            provider: {
              id: adapter.id,
              label: adapter.label,
              state: 'completed',
              result,
              shared,
            },
          })
        }
      }
    }

    await Promise.all(Array.from({ length: concurrency }, () => runNext()))

    const completed = executions.filter(
      (execution): execution is ProviderExecution => Boolean(execution),
    )
    const response: MultiSourceScanResponse = {
      providers: completed.map((execution) => execution.result),
      sharedWithProviders: completed
        .filter((execution) => execution.shared)
        .map((execution) => execution.id),
      sensitiveUrl: false,
      privacyReasons: [],
      generatedAt: new Date(startedAt).toISOString(),
      durationMs: Math.max(0, now() - startedAt),
      ...(cacheKeys
        ? {
            cache: buildScanCacheMeta({
              reused: reusedProviders,
              refreshed: refreshedProviders,
              oldestReusedAtMs,
              nowMs: now(),
            }),
          }
        : {}),
    }

    await emit({ type: 'done', scanId, response })
    return response
  } finally {
    clearTimeout(deadlineTimer)
  }
}

// Titik masuk publik. Gerbang privasi dan batas laju dinilai sekali di sini, lalu
// hasilnya diteruskan ke pelaksanaan yang mungkin dipakai bersama supaya batas laju tidak
// berkurang dua kali untuk satu pekerjaan.
export async function runMultiSourceScan(
  input: RunMultiSourceScanInput,
): Promise<MultiSourceScanResponse> {
  const now = input.now ?? Date.now
  const adapters = input.adapters ?? PROVIDER_ADAPTERS
  const config = input.config ?? readScannerConfig()

  let normalizedUrl: string
  try {
    normalizedUrl = normalizeScanUrl(input.url)
  } catch {
    // URL tidak valid: biarkan executeScan mengangkat galat yang sama seperti sebelumnya.
    return executeScan(input)
  }

  const privacy = detectSensitiveUrl(normalizedUrl)

  if (privacy.sensitive) {
    // Sama seperti sebelumnya: URL sensitif tidak memakai jatah batas laju, tidak pernah
    // di-hash, tidak disimpan, dan tidak pernah digabung dengan permintaan lain.
    return executeScan(input, {
      normalizedUrl,
      privacy,
      scanLimit: { allowed: true, retryAfterSeconds: 0 },
      cacheKeys: null,
    })
  }

  // Sampah kedaluwarsa dibuang pada awal pemeriksaan, bukan hanya saat memori penuh,
  // supaya entri yang tidak mungkin dipakai lagi tidak menahan tempat.
  pruneProviderCache(now)

  const scanLimit = await (input.consumeRateLimit ?? consumeScanRateLimit)(input.uid, now())

  if (!scanLimit.allowed) {
    // Permintaan yang kena batas laju tidak mengambil pekerjaan milik permintaan lain.
    return executeScan(input, {
      normalizedUrl,
      privacy,
      scanLimit,
      cacheKeys: null,
    })
  }

  const scanId = input.scanId?.trim() || createScanId()
  const providerTimeoutMs = readTimeout(input.providerTimeoutMs)
  const scanTimeoutMs = readScanTimeout(input.scanTimeoutMs)

  return runSharedScan({
    key: scanDedupKey({
      normalizedUrl,
      adapterIds: adapters.map((adapter) => adapter.id),
      providerTimeoutMs,
      scanTimeoutMs,
    }),
    scanId,
    startedAt: now(),
    now,
    signal: input.signal,
    onEvent: input.onEvent,
    run: (emit, signal) =>
      executeScan(
        { ...input, scanId, signal, onEvent: emit },
        {
          normalizedUrl,
          privacy,
          scanLimit,
          cacheKeys: buildProviderCacheKeys(
            adapters.map((adapter) => adapter.id),
            normalizedUrl,
            config,
          ),
        },
      ),
  })
}

export { ScanUrlError }

import type { MultiSourceScanResponse, ScanProgressEvent } from './types.js'

// Register scan yang sedang berjalan. Permintaan identik yang datang bersamaan memakai
// satu pelaksanaan, tetapi setiap permintaan tetap punya scanId, stream event, dan
// durasinya sendiri: hasil pelaksanaan disharing lalu ditulis-ulang saat dikirim, bukan
// stream-nya yang digabung. Dengan begitu satu klien yang putus tidak merusak klien lain.
//
// Batasan yang dijaga:
// - Kunci selalu hash; URL mentah tidak pernah menjadi key registry.
// - Pekerjaan berhenti hanya jika WAITER TERAKHIR pergi, sehingga perilaku "semua klien
//   menutup koneksi -> hentikan panggilan provider" tetap utuh.
// - Ukuran registry terikat; bila penuh, permintaan baru berjalan sendiri sehingga tidak
//   pernah mengantre tanpa batas.

export const MAX_INFLIGHT_SCANS = 32

export type SharedScanOptions = {
  key: string
  scanId: string
  startedAt: number
  now: () => number
  signal?: AbortSignal
  onEvent?: (event: ScanProgressEvent) => void | Promise<void>
  run: (
    emit: (event: ScanProgressEvent) => void,
    signal: AbortSignal | undefined,
  ) => Promise<MultiSourceScanResponse>
}

type Waiter = {
  scanId: string
  startedAt: number
  joined: boolean
  // Klien yang menutup stream tetap tercatat sampai pelaksanaan selesai supaya janjinya
  // tidak menggantung; ia hanya berhenti dihitung untuk keputusan "hentikan pekerjaan".
  detached: boolean
  onEvent?: (event: ScanProgressEvent) => void | Promise<void>
  resolve: (response: MultiSourceScanResponse) => void
  reject: (error: unknown) => void
  detach: () => void
}

type SharedScan = {
  key: string
  now: () => number
  controller: AbortController
  waiters: Set<Waiter>
  initEvent: ScanProgressEvent | null
  providerEvents: Map<string, ScanProgressEvent>
}

const registry = new Map<string, SharedScan>()

function forward(
  onEvent: SharedScanOptions['onEvent'],
  event: ScanProgressEvent,
): void {
  if (!onEvent) return
  try {
    void Promise.resolve(onEvent(event)).catch(() => {
      // Stream klien bisa tertutup sebelum provider selesai; abaikan seperti sebelumnya.
    })
  } catch {
    // Writer yang mati tidak boleh menghentikan pelaksanaan bersama.
  }
}

function deliver(waiter: Waiter, event: ScanProgressEvent, scan: SharedScan): void {
  if (!waiter.onEvent) return

  // Respons final ikut ditulis-ulang karena durasi dan penanda dedup per permintaan.
  if (event.type === 'done') {
    forward(waiter.onEvent, {
      ...event,
      scanId: waiter.scanId,
      response: adjustResponse(event.response, waiter, scan),
    })
    return
  }

  forward(waiter.onEvent, { ...event, scanId: waiter.scanId })
}

// Klien yang bergabung ke pelaksanaan milik klien lain tidak memulai pekerjaan baru dan
// bisa jadi menunggu lebih lama dari pelaksanaannya sendiri. Keduanya dilaporkan apa
// adanya: durasi dihitung dari permintaan masing-masing dan cache.deduplicated menandai
// hasil ini dipakai bersama.
function adjustResponse(
  response: MultiSourceScanResponse,
  waiter: Waiter,
  scan: SharedScan,
): MultiSourceScanResponse {
  if (!waiter.joined) return response

  const waitedMs = Math.max(0, scan.now() - waiter.startedAt)

  return {
    ...response,
    durationMs: waitedMs,
    cache: {
      ...(response.cache ?? {
        status: 'miss' as const,
        hit: false,
        observedAt: null,
        ageMs: 0,
        reusedProviders: [],
        refreshedProviders: [],
        requestsAvoided: 0,
      }),
      deduplicated: true,
    },
  }
}

// Penonton yang datang belakangan mendapat snapshot status yang sama dengan yang sudah
// dilihat klien pertama: init + status terakhir setiap agen.
function replay(scan: SharedScan, waiter: Waiter): void {
  if (scan.initEvent) deliver(waiter, scan.initEvent, scan)
  for (const event of scan.providerEvents.values()) {
    deliver(waiter, event, scan)
  }
}

export function runSharedScan(options: SharedScanOptions): Promise<MultiSourceScanResponse> {
  const existing = registry.get(options.key)
  let scan = existing
  // Penanda siapa yang memulai pekerjaan dan siapa yang sekadar ikut. Hanya yang ikut
  // punya durasi sendiri dan perlu dilaporkan sebagai hasil berbagi.
  const joined = existing !== undefined

  if (!scan) {
    if (registry.size >= MAX_INFLIGHT_SCANS) {
      // Registry penuh: jalankan sendiri tanpa berbagi. Event diteruskan apa adanya karena
      // pelaksanaan ini tidak disharing dengan permintaan lain.
      return options.run((event) => forward(options.onEvent, event), options.signal)
    }

    scan = {
      key: options.key,
      now: options.now,
      controller: new AbortController(),
      waiters: new Set(),
      initEvent: null,
      providerEvents: new Map(),
    }

    const current = scan

    const emit = (event: ScanProgressEvent): void => {
      if (event.type === 'init') {
        current.initEvent = event
      } else if (event.type === 'provider') {
        current.providerEvents.set(event.provider.id, event)
      }
      for (const waiter of current.waiters) {
        deliver(waiter, event, current)
      }
    }

    registry.set(options.key, current)

    const settle = (settleWaiter: (waiter: Waiter) => void): void => {
      if (registry.get(options.key) === current) registry.delete(options.key)
      for (const waiter of current.waiters) settleWaiter(waiter)
      current.waiters.clear()
    }

    void options
      .run(emit, current.controller.signal)
      .then(
        (response) => {
          settle((waiter) => waiter.resolve(adjustResponse(response, waiter, current)))
        },
        (error: unknown) => {
          // Kegagalan pelaksanaan tetap disampaikan ke semua permintaan yang berbagi,
          // sama seperti kegagalan yang dilihat klien tunggal hari ini.
          settle((waiter) => waiter.reject(error))
        },
      )
  }

  const target = scan

  return new Promise<MultiSourceScanResponse>((resolve, reject) => {
    const waiter: Waiter = {
      scanId: options.scanId,
      startedAt: options.startedAt,
      joined,
      detached: false,
      onEvent: options.onEvent,
      resolve,
      reject,
      detach: () => {
        if (waiter.detached) return
        waiter.detached = true
        // Hanya waiter terakhir yang masih hidup yang boleh menghentikan pekerjaan bersama.
        if (![...target.waiters].some((other) => !other.detached)) target.controller.abort()
      },
    }

    target.waiters.add(waiter)
    // Status yang sudah terlanjur dikirim sebelum permintaan ini tercatat, diputar ulang
    // agar setiap klien melihat urutan yang sama: init, lalu status agen terkini.
    replay(target, waiter)

    if (options.signal) {
      if (options.signal.aborted) waiter.detach()
      else options.signal.addEventListener('abort', waiter.detach, { once: true })
    }
  })
}

export function inFlightScanCount(): number {
  return registry.size
}

export function resetInFlightScans(): void {
  for (const scan of registry.values()) {
    scan.controller.abort()
  }
  registry.clear()
}

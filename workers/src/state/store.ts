import {
  SITE_ANALYSIS_RATE_LIMIT,
  consumeSiteAnalysisRateLimit,
} from '../../../functions/src/website/limits.js'
import type { RateLimitDecision } from '../../../functions/src/state/stores.js'
import {
  TURNSTILE_SCAN_CLEARANCE_MS,
  hasTurnstileClearance,
  issueTurnstileClearance,
} from '../../../functions/src/turnstile/scanGate.js'
import type { TurnstileTokenRegistry } from '../../../functions/src/turnstile/verify.js'
import { consumeEdgeRateLimit } from '../rateLimit.js'
import { SCAN_STATE_STORAGE_ERROR_CODES } from './scanState.js'
import type { ScanStateRequest, ScanStateResponse } from './scanState.js'
import { createCorrelationId, emitScanStateEvent, isolateNonce, shortActorId } from './telemetry.js'

/**
 * P1-3: satu pintu untuk seluruh state sementara Worker.
 *
 * Ada dua implementasi dengan kontrak yang sama persis:
 *  - memori (variabel modul di isolate ini) — dipakai host Node lokal, Cloud Functions, dan
 *    juga Worker bila binding Durable Object tidak ada atau sedang gagal;
 *  - Durable Object — satu tabel bersama untuk semua isolate, sehingga batas per-IP, izin
 *    CAPTCHA, dan anti-replay token tidak bisa dilewati dengan berpindah isolate.
 *
 * Arah gagal saat DO tidak tercapai adalah kembali ke memori isolate, yaitu persis perilaku
 * sebelum P1-3. Ia tidak pernah lebih longgar dari batas yang sudah berjalan hari ini dan
 * tidak pernah lebih ketat daripada menolak satu permintaan.
 *
 * VGL-28: setiap kali arah gagal itu diambil, sekarang ada catatannya (`ScanStateRpcDiagnostic`
 * dan `readScanStateRpcHealth()`). Angka dari memori isolate tidak boleh dilaporkan sebagai
 * batas laju terdistribusi.
 */
export type ScanStateStore = {
  consumeCounter(key: string, limit: number, windowMs: number, now: number): Promise<RateLimitDecision>
  consumeSiteWindow(key: string, now: number): Promise<RateLimitDecision>
  hasClearance(key: string, now: number): Promise<boolean>
  issueClearance(key: string, now: number): Promise<void>
}

// Stub Durable Object diturunkan secara struktural agar host Node (`server/`) tidak perlu
// tipe runtime Cloudflare. Hanya dua metode namespace yang benar-benar dipakai runtime.
export type ScanStateObjectId = { toString(): string }

export type ScanStateStub = {
  fetch(input: string, init?: RequestInit): Promise<Response>
}

export type ScanStateNamespace = {
  idFromName(name: string): ScanStateObjectId
  get(id: ScanStateObjectId): ScanStateStub
}

// DO tunggal tempat semua isolate berbagi tabel. Nama tetap ini selalu menunjuk instance yang
// sama, sehingga seluruh isolate menulis ke satu pencacah.
export const SCAN_STATE_DO_NAME = 'veriguard-scan-state'
const SCAN_STATE_DO_URL = 'https://veriguard-scan-state.internal/state'

// Permintaan RPC berada di jalur panas setiap request. Batas singkat: lebih baik satu request
// jatuh ke memori isolate daripada seluruh antrean menunggu DO yang macet.
const RPC_TIMEOUT_MS = 1_500
// Setelah gagal, jangan coba DO lagi selama jendela ini; kegagalan berulang tidak boleh
// menambah latensi pada setiap request.
const RPC_BREAKER_MS = 30_000

/**
 * VGL-28 R1: diagnostik RPC Durable Object.
 *
 * Sebelum perubahan ini, seluruh kegagalan RPC masuk ke `catch {}` kosong: tidak ada nama galat,
 * tidak ada status HTTP, tidak ada catatan bahwa keputusan yang dipakai adalah memori isolate.
 * Akibatnya produksi selalu terlihat "DO tidak terpakai" apa pun penyebabnya (VGL-27 §3.2).
 *
 * Aturan isinya: hanya field yang boleh muncul di log publik. Tidak ada kunci state (di dalamnya
 * ada alamat IP), tidak ada body permintaan, tidak ada token, dan pesan galat pihak ketiga
 * disanitasi lebih dulu. Fungsinya menjelaskan PENYEBAB, bukan merekam DATA.
 */
export type ScanStateRpcFailureCategory =
  | 'rpc_timeout'
  | 'rpc_http_error'
  | 'rpc_parse_error'
  | 'rpc_validation_error'
  | 'rpc_exception'
  | 'rpc_breaker_open'

export type ScanStateRpcDiagnostic = {
  source: 'scan_state_rpc'
  category: ScanStateRpcFailureCategory
  operation: ScanStateRequest['action']
  durationMs: number
  /** Setiap catatan diagnostik berarti keputusan yang dipakai pemanggil adalah memori isolate. */
  fallbackUsed: true
  breakerOpenMs?: number
  httpStatus?: number
  errorName?: string
  detail?: string
  /**
   * VGL-30F R4: penghubung ke catatan actor (`scan_state_evt ... corr` yang sama) dan nonce
   * isolate Worker tempat keputusan memori diambil. Keduanya acak dan tidak menurunkan identitas
   * pengguna maupun isi kunci state.
   */
  correlationId?: string
  workerNonce?: string
}

export type ScanStateRpcReporter = (diagnostic: ScanStateRpcDiagnostic) => void

const DIAGNOSTIC_DETAIL_MAX_CHARS = 160
const DIAGNOSTIC_INTERNAL_URL = /https:\/\/veriguard-scan-state\.internal\S*/g
const DIAGNOSTIC_LONG_TOKEN = /[A-Za-z0-9+/=_-]{20,}/g
const DIAGNOSTIC_IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g

function sanitizeDiagnosticDetail(value: string): string {
  return value
    .replace(/\r?\n/g, ' ')
    .replace(DIAGNOSTIC_INTERNAL_URL, '<do-endpoint>')
    .replace(DIAGNOSTIC_IPV4, '<redacted-ip>')
    .replace(DIAGNOSTIC_LONG_TOKEN, '<redacted>')
    .replace(/\s{2,}/g, ' ')
    .trim()
    .slice(0, DIAGNOSTIC_DETAIL_MAX_CHARS)
}

/**
 * Ringkasan kesehatan RPC per isolate. Dipakai test untuk membuktikan bahwa fallback terlihat,
 * dan supaya tidak ada jalur yang bisa mengklaim "batas laju terdistribusi" sementara
 * `fallbackCount` masih bertambah.
 */
export type ScanStateRpcHealth = {
  durableSuccessCount: number
  fallbackCount: number
  lastFailureCategory?: ScanStateRpcFailureCategory
  breakerOpen: boolean
}

const rpcHealth: ScanStateRpcHealth = {
  durableSuccessCount: 0,
  fallbackCount: 0,
  breakerOpen: false,
}

export function readScanStateRpcHealth(): ScanStateRpcHealth {
  return { ...rpcHealth }
}

export function resetScanStateRpcHealth(): void {
  rpcHealth.durableSuccessCount = 0
  rpcHealth.fallbackCount = 0
  rpcHealth.breakerOpen = false
  delete rpcHealth.lastFailureCategory
}

export function reportScanStateRpcDiagnostic(diagnostic: ScanStateRpcDiagnostic): void {
  // console* di Worker ditangkap `wrangler tail`; bentuknya JSON satu baris agar mudah difilter.
  console.warn(`scan_state_rpc ${JSON.stringify(diagnostic)}`)
}

export function createMemoryStateStore(): ScanStateStore {
  return {
    async consumeCounter(key, limit, windowMs, now) {
      return consumeEdgeRateLimit(key, limit, windowMs, now)
    },
    async consumeSiteWindow(key, now) {
      return consumeSiteAnalysisRateLimit(
        key,
        now,
        SITE_ANALYSIS_RATE_LIMIT.maxAnalyses,
        SITE_ANALYSIS_RATE_LIMIT.windowMs,
      )
    },
    async hasClearance(key, now) {
      return hasTurnstileClearance(key, now)
    },
    async issueClearance(key, now) {
      issueTurnstileClearance(key, now, TURNSTILE_SCAN_CLEARANCE_MS)
    },
  }
}

function isScanStateResponse(value: unknown): value is ScanStateResponse {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const payload = value as Record<string, unknown>
  if (typeof payload.ok !== 'boolean') return false
  if (payload.allowed !== undefined && typeof payload.allowed !== 'boolean') return false
  if (
    payload.retryAfterSeconds !== undefined &&
    typeof payload.retryAfterSeconds !== 'number'
  ) {
    return false
  }
  if (payload.used !== undefined && typeof payload.used !== 'number') return false
  if (
    payload.reservation !== undefined &&
    payload.reservation !== 'reserved' &&
    payload.reservation !== 'reused' &&
    payload.reservation !== 'full'
  ) {
    return false
  }
  // Kode galat hanya boleh salah satu yang dikenali; nilai lain membuat bentuk respons dianggap
  // tidak dikenal (kategori rpc_validation_error) alih-alih memicu penolakan gagal-tertutup.
  if (
    payload.error_code !== undefined &&
    !SCAN_STATE_STORAGE_ERROR_CODES.includes(payload.error_code as (typeof SCAN_STATE_STORAGE_ERROR_CODES)[number])
  ) {
    return false
  }
  return true
}

/**
 * VGL-30F §4: actor memahami permintaan tetapi tidak bisa menuliskannya ke penyimpanan.
 * Ini BUKAN kegagalan RPC yang boleh jatuh ke memori isolate: menerima izin dari state yang
 * tidak tersimpan adalah persis gagal-buka yang dilarang. Pemanggil menurunkan penolakan, dan
 * untuk jalur CAPTCHA arahnya juga aman (menantang ulang, bukan melepas anti-replay).
 */
function isStorageFailure(response: ScanStateResponse): boolean {
  return response.error_code !== undefined
}

function toDecision(response: ScanStateResponse): RateLimitDecision {
  return {
    allowed: response.allowed === true,
    retryAfterSeconds:
      typeof response.retryAfterSeconds === 'number' && response.retryAfterSeconds > 0
        ? Math.ceil(response.retryAfterSeconds)
        : 0,
    ...(typeof response.used === 'number' ? { used: response.used } : {}),
  }
}

export type ScanStateRpc = (request: ScanStateRequest) => Promise<ScanStateResponse | null>

export function createStateRpc(
  namespace: ScanStateNamespace,
  report: ScanStateRpcReporter = reportScanStateRpcDiagnostic,
): ScanStateRpc {
  let breakerClosedUntil = 0
  // Satu catatan `rpc_breaker_open` per jendela pemutus: permintaan berikutnya tetap jatuh ke
  // memori, tetapi tidak menulis log yang sama 30 detik berturut-turut.
  let breakerLoggedFor = 0
  const workerNonce = isolateNonce('worker')
  // `actorId` diisi dari `idFromName` yang memang sudah dipanggil per permintaan: memanggilnya
  // sekali lagi di sini akan mengubah umur stub yang dipin tes VGL-28.
  let actorId: string | undefined

  /** Transisi pemutus adalah satu-satunya perubahan kondisi yang layak dicatat sendiri. */
  function noteBreaker(open: boolean, remainingMs: number): void {
    if (rpcHealth.breakerOpen === open) return
    rpcHealth.breakerOpen = open
    emitScanStateEvent({
      event: 'breaker_transition',
      src: 'worker',
      wn: workerNonce,
      aid: actorId,
      brk: open ? 'open' : 'closed',
      bleft: Math.max(0, remainingMs),
    })
  }

  function fail(
    diagnostic: Omit<ScanStateRpcDiagnostic, 'source' | 'fallbackUsed'> & { corr?: string },
  ): null {
    const { corr, ...rest } = diagnostic
    rpcHealth.fallbackCount += 1
    rpcHealth.lastFailureCategory = rest.category
    if (rest.category !== 'rpc_breaker_open') {
      breakerClosedUntil = Date.now() + RPC_BREAKER_MS
      noteBreaker(true, breakerClosedUntil - Date.now())
    }
    try {
      report({
        source: 'scan_state_rpc',
        fallbackUsed: true,
        breakerOpenMs: RPC_BREAKER_MS,
        correlationId: corr,
        workerNonce,
        ...rest,
      })
    } catch {
      // Diagnostik tidak boleh menggagalkan permintaan; arah gagal tetap memori isolate.
    }
    return null
  }

  return async function call(request) {
    const operation = request.action
    // Correlation id dibuat per panggilan: ia satu-satunya benang yang menyambungkan catatan
    // Worker (termasuk yang jatuh ke memori) dengan catatan instance actor.
    const corr = createCorrelationId()
    const now = Date.now()
    if (now < breakerClosedUntil) {
      if (breakerLoggedFor !== breakerClosedUntil) {
        breakerLoggedFor = breakerClosedUntil
        fail({
          category: 'rpc_breaker_open',
          operation,
          durationMs: 0,
          breakerOpenMs: breakerClosedUntil - now,
          corr,
        })
      }
      return null
    }

    const startedAt = Date.now()
    const elapsed = () => Date.now() - startedAt
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), RPC_TIMEOUT_MS)
    try {
      // Stub dibuat per panggilan, bukan disimpan di closure builder. workerd menolak I/O RPC
      // yang dipegang lintas konteks permintaan (`Cannot perform I/O on behalf of a different
      // request`) sehingga setiap stub hanya sah untuk satu panggilan (VGL-28; penyebab yang
      // dulu dibuang diam-diam oleh `catch {}`).
      const objectId = namespace.idFromName(SCAN_STATE_DO_NAME)
      actorId = shortActorId(objectId.toString())
      const stub = namespace.get(objectId)
      const response = await stub.fetch(SCAN_STATE_DO_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...request, corr }),
        signal: controller.signal,
      })
      if (!response.ok) {
        await response.body?.cancel().catch(() => undefined)
        // Status HTTP bukan 2xx: DO menolak permintaannya (405/413/415/400) atau runtime
        // mengembalikan galat. Sebabnya dicatat, bukan dibuang.
        return fail({
          category: 'rpc_http_error',
          operation,
          durationMs: elapsed(),
          httpStatus: response.status,
          errorName: 'RpcHttpError',
          detail: sanitizeDiagnosticDetail(`status ${response.status}`),
          corr,
        })
      }

      let payload: unknown
      try {
        payload = await response.json()
      } catch (error) {
        if (controller.signal.aborted) {
          return fail({
            category: 'rpc_timeout',
            operation,
            durationMs: elapsed(),
            errorName: 'AbortError',
            detail: 'pembacaan body melebihi RPC_TIMEOUT_MS',
            corr,
          })
        }
        return fail({
          category: 'rpc_parse_error',
          operation,
          durationMs: elapsed(),
          errorName: error instanceof Error ? error.name : typeof error,
          detail: sanitizeDiagnosticDetail(error instanceof Error ? error.message : String(error)),
          corr,
        })
      }

      if (!isScanStateResponse(payload)) {
        // HTTP 200 tetapi bentuk body tidak dikenali. `shape` sengaja hanya menyebut field
        // yang ada (nama field tetap, tidak ada nilai) supaya penyebabnya terbaca tanpa
        // mengalirkan isi respons ke log.
        const received = payload && typeof payload === 'object' && !Array.isArray(payload)
          ? Object.keys(payload as Record<string, unknown>).filter((key) => /^[a-z_]{2,20}$/.test(key)).sort()
          : []
        return fail({
          category: 'rpc_validation_error',
          operation,
          durationMs: elapsed(),
          errorName: 'ResponseShapeError',
          detail: sanitizeDiagnosticDetail(`bentuk respons tidak dikenali; field=${received.join(',') || '<>'}`),
          corr,
        })
      }

      if (payload.ok !== true) {
        // HTTP 200 dengan `ok: false` = DO tidak menerima permintaannya. Tanpa catatan ini,
        // jalur jatuh ke memori masih ada yang diam (VGL-27 §3.2 baris `:156-160`).
        return fail({
          category: 'rpc_validation_error',
          operation,
          durationMs: elapsed(),
          errorName: 'DurableObjectRejected',
          detail: sanitizeDiagnosticDetail('respons ok:false'),
          corr,
        })
      }

      rpcHealth.durableSuccessCount += 1
      noteBreaker(false, 0)
      if (payload.error_code !== undefined) {
        // Actor menjawab tetapi tidak dari penyimpanan. Ini dicatat di sini (bukan di facade)
        // karena hanya lapisan RPC yang memegang correlation id permintaan ini.
        emitScanStateEvent({
          event: 'durable_error',
          src: 'worker',
          op: operation,
          cat: payload.error_code,
          corr,
          wn: workerNonce,
          aid: actorId,
          dur_ms: elapsed(),
        })
      }
      return payload
    } catch (error) {
      // Jalur ini adalah tempat kegagalan dulu dibuang tanpa jejak.
      const timedOut = controller.signal.aborted
      return fail({
        category: timedOut ? 'rpc_timeout' : 'rpc_exception',
        operation,
        durationMs: elapsed(),
        errorName: error instanceof Error ? error.name : typeof error,
        detail: sanitizeDiagnosticDetail(error instanceof Error ? error.message : String(error)),
        corr,
      })
    } finally {
      clearTimeout(timer)
    }
  }
}

export function createDurableStateStore(
  call: ScanStateRpc,
  fallback: ScanStateStore = createMemoryStateStore(),
): ScanStateStore {
  // Penolakan gagal-tertutup untuk galat penyimpanan: tanpa `used`, supaya gerbang CAPTCHA tidak
  // membaca angka yang tidak pernah dihitung, dan `retryAfterSeconds` kecil supaya pengguna
  // mencoba lagi alih-alih diberi jeda panjang yang tidak berdasar.
  const storageDeny = (): RateLimitDecision => ({ allowed: false, retryAfterSeconds: 1 })

  return {
    async consumeCounter(key, limit, windowMs, now) {
      const response = await call({ action: 'counter', key, limit, windowMs })
      if (response && isStorageFailure(response)) return storageDeny()
      if (!response || !response.ok) return fallback.consumeCounter(key, limit, windowMs, now)
      return toDecision(response)
    },
    async consumeSiteWindow(key, now) {
      const response = await call({
        action: 'window',
        key,
        limit: SITE_ANALYSIS_RATE_LIMIT.maxAnalyses,
        windowMs: SITE_ANALYSIS_RATE_LIMIT.windowMs,
      })
      if (response && isStorageFailure(response)) return storageDeny()
      if (!response || !response.ok) return fallback.consumeSiteWindow(key, now)
      return toDecision(response)
    },
    async hasClearance(key, now) {
      const response = await call({ action: 'has', key })
      // Galat penyimpanan dibaca sebagai "tidak berizin": arah gagal menantang CAPTCHA lagi,
      // bukan melepas syarat verifikasi.
      if (response && isStorageFailure(response)) return false
      if (!response || !response.ok) return fallback.hasClearance(key, now)
      return response.allowed === true
    },
    async issueClearance(key, now) {
      const response = await call({ action: 'issue', key, ttlMs: TURNSTILE_SCAN_CLEARANCE_MS })
      if (response && isStorageFailure(response)) return
      if (!response || !response.ok) {
        await fallback.issueClearance(key, now)
      }
    },
  }
}

export function createDurableTokenRegistry(call: ScanStateRpc): TurnstileTokenRegistry {
  return {
    async reserve(fingerprint) {
      const response = await call({ action: 'reserve', key: fingerprint })
      // Galat penyimpanan dibaca sebagai "sudah dipakai": anti-replay tidak pernah boleh
      // dinyatakan berhasil oleh state yang gagal ditulis.
      if (response && isStorageFailure(response)) return 'reused'
      // RPC gagal atau breaker terbuka: jangan turun ke registry memori isolate. Memori
      // isolate bukan state bersama, jadi token yang sama dari isolate lain akan lolos dan
      // satu CAPTCHA yang sudah dipecah bisa dipakai ulang — justru jaminan yang hendak
      // diberikan DO. Pemanggil menjawab 428 sehingga klien menyelesaikan tantangan baru,
      // dan breaker menutup sendiri setelah jendela cobanya lewat.
      if (!response || !response.ok) return 'reused'
      const reservation = response.reservation
      switch (reservation) {
        case 'reserved':
        case 'reused':
        case 'full':
          return reservation
        default:
          // Nilai tak dikenal diperlakukan sebagai "sudah dipakai": arah gagal yang menolak,
          // bukan yang mengizinkan.
          return 'reused'
      }
    },
    async release(fingerprint) {
      // Melepas reservasi hanya dilakukan ketika state bersama benar-benar menerimanya.
      // Gagal melepas berarti satu sidik token tetap tercatat terpakai — arah yang benar:
      // token tidak pernah boleh dilepas untuk dipakai ulang hanya karena RPC-nya tidak
      // sampai, dan tidak ada memori isolate yang bisa dijadikan pengganti.
      const response = await call({ action: 'release', key: fingerprint })
      if (!response || !response.ok || isStorageFailure(response)) return
    },
  }
}

export type WorkerState = {
  store: ScanStateStore
  // undefined = pakai registry memori bawaan verifier (perilakunya persis seperti sebelum
  // binding DO ada, dan tetap bisa direset dari tes).
  tokenRegistry?: TurnstileTokenRegistry
}

const sharedState = new WeakMap<ScanStateNamespace, WorkerState>()

export function resolveWorkerState(
  namespace: ScanStateNamespace | undefined,
  fallback: ScanStateStore,
): WorkerState {
  if (!namespace) return { store: fallback }

  const cached = sharedState.get(namespace)
  if (cached) return cached

  const call = createStateRpc(namespace)
  const created: WorkerState = {
    store: createDurableStateStore(call, fallback),
    tokenRegistry: createDurableTokenRegistry(call),
  }
  sharedState.set(namespace, created)
  return created
}

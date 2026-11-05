import {
  STATE_MAX_KEYS,
  createExpiryRegistry,
  createFixedWindowCounter,
  createSlidingWindowLimiter,
} from '../../../functions/src/state/stores.js'
import {
  TURNSTILE_TOKEN_RETENTION_MS,
  createMemoryTurnstileTokenRegistry,
} from '../../../functions/src/turnstile/verify.js'
import type { TurnstileTokenReservation } from '../../../functions/src/turnstile/verify.js'
import { createStateKeyRing } from './stateKeys.js'
import type { StateKeyRing } from './stateKeys.js'
import { SCAN_STATE_KINDS, createDurableStateOps } from './durableState.js'
import type { DurableStateIdentity, DurableStateOps, DurableStorageSurface } from './durableState.js'
import {
  createNonce,
  emitScanStateEvent,
  isolateNonce,
  nextActorInstanceSequence,
  shortActorId,
} from './telemetry.js'

/**
 * P1-3: satu Durable Object yang memegang state bersama untuk seluruh isolate Worker.
 *
 * Kenapa Durable Object dan bukan KV: KV bersifat eventually consistent dan tanpa operasi
 * atomik, jadi read-modify-write rate limit di dua request paralel saling menimpa. DO
 * dijalankan single-threaded per instance; setiap operasi keputusan adalah read-modify-write
 * sinkron (dibungkus `transactionSync`), sehingga increment tidak pernah hilang.
 *
 * VGL-30F R1 mengganti kebijakan lama "state sengaja tidak persisten": VGL-30D membuktikan (F2)
 * bahwa setiap instance actor yang di-evict menghapus pencacah, izin CAPTCHA, dan registry
 * anti-replay, sehingga batas laju dan anti-replay bisa dilewati dengan menunggu hibernasi.
 * Penyimpanan SQL actor sekarang sumber kebenaran untuk ketiga jenis state itu, dan keputusan
 * izin dihitung dari hasil tulis yang sudah berhasil.
 *
 * VGL-30H K-1/K-3: bahan kunci datang dari CINCIN versi (`SCAN_STATE_KEY_V<n>` sebagai secret +
 * `SCAN_STATE_KEY_ACTIVE` sebagai label di `[vars]`), bukan dari satu salt. Setiap identitas
 * di-hash pada versi aktif DAN pada setiap versi lama yang masih ada, semua perhitungan itu
 * selesai SEBELUM transaksi dibuka, lalu operasi tulis memindahkan baris versi lama ke versi
 * aktif dalam transaksi yang sama.
 *
 * KEYING TETAP TIDAK AKTIF DI KONFIGURASI MANA PUN. Ring butuh (a) minimal satu secret
 * `SCAN_STATE_KEY_V<n>` dan (b) `SCAN_STATE_KEY_ACTIVE` yang menunjuk salah satunya. Produksi dan
 * staging tidak punya keduanya, dan VGL-30H dilarang membuat secret, jadi resolver mengembalikan
 * `available:false` dan jalur durable tidak pernah menyala. Tanpa ring, kelas ini berperilaku
 * persis seperti sebelum R1 (field instance + `functions/src/state/stores.ts`), dan itu bukan
 * "durable state aktif" — jangan mengklaim sebaliknya.
 *
 * Salt lama (`SCAN_STATE_KEY_SALT`) tidak mengaktifkan penulisan. Ia hanya menjadi SUMBER BACA
 * untuk baris tanpa prefiks yang ditulis kode pra-VGL-30H, dan hanya dipakai bila ada versi aktif
 * yang sah. Tidak ada kode yang menurunkan digest baru dari digest lama: `key_hash` tidak dapat
 * dibalik, jadi setiap versi dihitung ulang dari identitas asal pada permintaan ini.
 *
 * Aksi `window` (jendela geser analisis situs) sengaja tetap di memori instance: ia tidak termasuk
 * cakupan R1 yang disetujui (pencacah, izin CAPTCHA, anti-replay token), dan perilakunya dibiarkan
 * seperti hari ini alih-alih diubah diam-diam.
 *
 * DO ini tidak memiliki route publik; hanya bisa dijangkau dari dalam Worker melalui binding
 * namespace. Ia juga tidak pernah menyimpan rahasia: yang tersimpan hanya hitungan, cap waktu, dan
 * digest kunci. Materi kunci dipakai untuk HMAC dan tidak pernah ditulis ke tabel maupun ke catatan;
 * yang keluar ke catatan hanyalah LABEL versi (`kv`).
 *
 * Tipe `state`/`env` di bawah dibuat struktural (bukan dari @cloudflare/workers-types) supaya
 * host Node (`server/`) yang mengimpor paket ini tetap bisa type-check tanpa tipe runtime
 * Cloudflare.
 */
export type ScanStateStorage = {
  // Runtime mengembalikan `undefined` untuk kunci yang belum pernah ditulis, sementara tipe lama
  // menulis `null`. Biarkan struktural dan jangan bergantung padanya: tidak ada jalur keputusan di
  // kelas ini yang membaca storage KV — yang dibaca adalah `sql`.
  get<T = unknown>(key: string): Promise<T | null>
  put<T = unknown>(key: string, value: T): Promise<void>
}

export type ScanStateContext = {
  storage: ScanStateStorage
  waitUntil(promise: Promise<unknown>): void
  passThroughOnException?(): void
}

export type ScanStateEnv = Record<string, unknown>

export const SCAN_STATE_ACTIONS = {
  counter: 'counter',
  window: 'window',
  has: 'has',
  issue: 'issue',
  reserve: 'reserve',
  release: 'release',
} as const

export type ScanStateRequest =
  | { action: 'counter'; key: string; limit: number; windowMs: number }
  | { action: 'window'; key: string; limit: number; windowMs: number }
  | { action: 'has'; key: string }
  | { action: 'issue'; key: string; ttlMs: number }
  | { action: 'reserve'; key: string }
  | { action: 'release'; key: string }

// Pembungkus RPC: `corr` ditambahkan pemanggil (store.ts) untuk menyambungkan catatan Worker ke
// catatan actor. Ia bukan bagian kebijakan dan tidak boleh membawa apa pun selain id acak.
export type ScanStateRpcEnvelope = ScanStateRequest & { corr?: string }

export const SCAN_STATE_STORAGE_ERROR_CODES = ['storage_unavailable', 'schema_version'] as const

export type ScanStateStorageErrorCode = (typeof SCAN_STATE_STORAGE_ERROR_CODES)[number]

export type ScanStateResponse = {
  ok: boolean
  allowed?: boolean
  retryAfterSeconds?: number
  used?: number
  reservation?: TurnstileTokenReservation
  /**
   * Ada bila actor memahami permintaan tetapi tidak bisa menyelesaikannya dari penyimpanan.
   * Sisi Store memetakannya ke penolakan (bukan ke memori isolate): lihat store.ts.
   */
  error_code?: ScanStateStorageErrorCode
}

const MAX_KEY_LENGTH = 256
// Permintaan ke DO membawa body kecil; batas ini hanya menjaga agar tabel tidak diisi
// kunci raksasa dari bugs pemanggil, bukan kebijakan privasi.
const MAX_BODY_BYTES = 4_096
const MAX_CORRELATION_LENGTH = 32
// Janitor sapuan kedaluwarsa; hanya dipasang ketika jalur durable aktif.
const SWEEP_ALARM_INTERVAL_MS = 60_000

function readKey(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const key = value.trim()
  if (!key || key.length > MAX_KEY_LENGTH) return null
  return key
}

function readNumber(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null
  return value
}

// Correlation id hanya boleh huruf/angka dan pendek: ia masuk ke catatan diagnostik, jadi nilai
// dari pemanggil disaring dan yang mencurigakan dibuang (permintaannya tetap dilayani).
function readCorrelation(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined
  const corr = value.replace(/[^a-z0-9]/gi, '').toLowerCase()
  if (!corr || corr.length > MAX_CORRELATION_LENGTH) return undefined
  return corr
}

function json(response: ScanStateResponse, status = 200): Response {
  return new Response(JSON.stringify(response), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  })
}

// Arah gagal saat penyimpanan bermasalah: MENOLAK, tanpa `used` (supaya gerbang CAPTCHA tidak
// membaca angka yang tidak ada), dan dengan kode yang dikenali sisi Store.
function storageFailure(code: ScanStateStorageErrorCode): ScanStateResponse {
  return { ok: true, allowed: false, retryAfterSeconds: 1, error_code: code }
}

type DurableRouting = {
  ops: DurableStateOps
  ring: StateKeyRing
  identity: DurableStateIdentity
}

export class ScanStateDurableObject {
  private readonly counters = createFixedWindowCounter(STATE_MAX_KEYS)
  private readonly windows = createSlidingWindowLimiter(STATE_MAX_KEYS)
  private readonly clearances = createExpiryRegistry(STATE_MAX_KEYS)
  // Registry token memakai pabrik yang SAMA dengan default verifier, sehingga semantik
  // 'reserved' | 'reused' | 'full' identik baik saat disimpan di isolate maupun di DO.
  private readonly tokens = createMemoryTurnstileTokenRegistry(
    TURNSTILE_TOKEN_RETENTION_MS,
    STATE_MAX_KEYS,
  )

  // Nama parameter mengikuti kontrak runtime Workers (state, env). Keduanya disimpan sejak
  // VGL-30F: `state.storage.sql` adalah sumber kebenaran dan `env` tempat ring kunci dibaca.
  private readonly state: ScanStateContext
  private readonly env: ScanStateEnv
  private readonly instanceNonce = createNonce()
  private readonly bootMs = Date.now()
  private routing: DurableRouting | undefined
  private routingDecided = false
  private alarmScheduled = false

  constructor(
    state: ScanStateContext,
    env: ScanStateEnv,
  ) {
    this.state = state
    this.env = env
  }

  /**
   * Bootstrap sengaja SINKRON dan malas, bukan `blockConcurrencyWhile`: seluruh penyiapan skema
   * adalah pernyataan SQLite sinkron, jadi tidak ada `await` yang bisa disela permintaan lain, dan
   * host Node/fixture tes yang tidak punya `blockConcurrencyWhile` tetap bisa memakai kelas ini.
   * Actor restart memanggilnya ulang; `CREATE TABLE IF NOT EXISTS` membuatnya idempoten.
   */
  private resolveRouting(corr?: string): DurableRouting | undefined {
    if (this.routingDecided) {
      if (this.routing && corr) this.routing.identity.corr = corr
      return this.routing
    }
    this.routingDecided = true

    const ring = createStateKeyRing(this.env)
    const surface = this.state.storage as unknown as DurableStorageSurface
    const sqlReady =
      typeof surface.sql?.exec === 'function' && typeof surface.transactionSync === 'function'

    if (!ring.available || !sqlReady) {
      // Catatan ini yang membedakan "durable memang tidak diaktifkan" (keputusan pemilik) dari
      // "durable aktif tetapi penyimpanan gagal" (insiden). Nilai kunci tidak pernah ikut: yang
      // keluar hanya alasan dan, bila ada, label versi.
      emitScanStateEvent({
        event: 'actor_instance_started',
        src: 'actor',
        an: this.instanceNonce,
        rn: isolateNonce('actor'),
        iseq: nextActorInstanceSequence(),
        aid: this.shortActorId(),
        corr,
        out: 'volatile',
        kind: ring.reason ?? 'sql_unavailable',
        kv: ring.activeLabel,
      })
      return undefined
    }

    const identity: DurableStateIdentity = {
      rn: isolateNonce('actor'),
      an: this.instanceNonce,
      iseq: nextActorInstanceSequence(),
      aid: this.shortActorId(),
      bootMs: this.bootMs,
      corr,
    }
    this.routing = {
      ring,
      identity,
      ops: createDurableStateOps({ storage: surface, identity, maxKeys: STATE_MAX_KEYS }),
    }
    return this.routing
  }

  private shortActorId(): string | undefined {
    const holder = this.state as unknown as { id?: { toString?(): string } }
    const id = holder.id?.toString?.()
    return id ? shortActorId(id) : undefined
  }

  private scheduleSweepAlarm(): void {
    if (this.alarmScheduled) return
    const storage = this.state.storage as unknown as DurableStorageSurface
    if (typeof storage.setAlarm !== 'function') return
    this.alarmScheduled = true
    try {
      const scheduled = storage.setAlarm.call(storage, Date.now() + SWEEP_ALARM_INTERVAL_MS)
      if (scheduled instanceof Promise) this.state.waitUntil(scheduled)
    } catch {
      // Alarm hanya kebersihan; tanpanya sapuan tetap berjalan lewat ambang waktu di jalur tulis.
      this.alarmScheduled = false
    }
  }

  /** Janitor kedaluwarsa. Hanya bekerja bila jalur durable aktif. */
  async alarm(): Promise<void> {
    const routing = this.resolveRouting()
    if (!routing) return
    routing.ops.sweepExpired(Date.now())
    this.scheduleSweepAlarm()
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return json({ ok: false }, 405)
    }

    const contentType = request.headers.get('content-type') ?? ''
    if (contentType.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return json({ ok: false }, 415)
    }

    const lengthHeader = Number.parseInt(request.headers.get('content-length') ?? '', 10)
    if (Number.isFinite(lengthHeader) && lengthHeader > MAX_BODY_BYTES) {
      return json({ ok: false }, 413)
    }

    let payload: unknown
    try {
      const text = await request.text()
      if (text.length > MAX_BODY_BYTES) return json({ ok: false }, 413)
      payload = JSON.parse(text) as unknown
    } catch {
      return json({ ok: false }, 400)
    }

    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return json({ ok: false }, 400)
    }

    const body = payload as Record<string, unknown>
    const action = body.action
    const key = readKey(body.key)
    if (!key) return json({ ok: false }, 400)

    const now = Date.now()
    const routing = this.resolveRouting(readCorrelation(body.corr))

    // Tiga jenis state dalam cakupan R1 diarahkan ke penyimpanan durable. Saat routing tidak
    // aktif (ring belum dipasang), seluruh aksi memakai struktur memori seperti sebelumnya,
    // termasuk `window`.
    if (routing && action !== SCAN_STATE_ACTIONS.window) {
      const durable = await this.durableDecision(routing, action, body, key, now)
      if (durable) return durable
    }

    switch (action) {
      case SCAN_STATE_ACTIONS.counter: {
        const limit = readNumber(body.limit)
        const windowMs = readNumber(body.windowMs)
        if (limit === null || windowMs === null) return json({ ok: false }, 400)
        const decision = this.counters.consume(key, limit, windowMs, now)
        return json({
          ok: true,
          allowed: decision.allowed,
          retryAfterSeconds: decision.retryAfterSeconds,
          ...(decision.used === undefined ? {} : { used: decision.used }),
        })
      }
      case SCAN_STATE_ACTIONS.window: {
        const limit = readNumber(body.limit)
        const windowMs = readNumber(body.windowMs)
        if (limit === null || windowMs === null) return json({ ok: false }, 400)
        const decision = this.windows.consume(key, now, limit, windowMs)
        return json({
          ok: true,
          allowed: decision.allowed,
          retryAfterSeconds: decision.retryAfterSeconds,
          ...(decision.used === undefined ? {} : { used: decision.used }),
        })
      }
      case SCAN_STATE_ACTIONS.has:
        return json({ ok: true, allowed: this.clearances.has(key, now) })
      case SCAN_STATE_ACTIONS.issue: {
        const ttlMs = readNumber(body.ttlMs)
        if (ttlMs === null) return json({ ok: false }, 400)
        // Gagal mencatat (tabel penuh) dibiarkan sebagai "tidak berizin": pemanggil akan
        // menantang CAPTCHA lagi, bukan memberi izin.
        return json({ ok: true, allowed: this.clearances.issue(key, now, ttlMs) })
      }
      case SCAN_STATE_ACTIONS.reserve:
        return json({ ok: true, reservation: this.tokens.reserve(key, now) })
      case SCAN_STATE_ACTIONS.release: {
        this.tokens.release(key)
        return json({ ok: true })
      }
      default:
        return json({ ok: false }, 400)
    }
  }

  /**
   * Satu operasi durable = satu transaksi. Satu-satunya `await` adalah perhitungan HMAC untuk
   * SEMUA versi yang perlu dicari, dan itu terjadi SEBELUM `ops` dipanggil; `durableState.ts`
   * membungkus baca-tulisnya dengan `transactionSync` tanpa `await` di dalamnya.
   *
   * `null` dikembalikan bila bentuk permintaan memang tidak lengkap, supaya permintaan itu dijawab
   * 400 seperti sebelumnya. Galat penyimpanan menghasilkan respons gagal-tertutup.
   */
  private async durableDecision(
    routing: DurableRouting,
    action: unknown,
    body: Record<string, unknown>,
    key: string,
    now: number,
  ): Promise<Response | null> {
    const limit = readNumber(body.limit)
    const windowMs = readNumber(body.windowMs)
    const ttlMs = readNumber(body.ttlMs)
    if (action === SCAN_STATE_ACTIONS.counter && (limit === null || windowMs === null)) return null
    if (action === SCAN_STATE_ACTIONS.issue && ttlMs === null) return null

    const kind =
      action === SCAN_STATE_ACTIONS.counter
        ? SCAN_STATE_KINDS.counter
        : action === SCAN_STATE_ACTIONS.reserve || action === SCAN_STATE_ACTIONS.release
          ? SCAN_STATE_KINDS.token
          : SCAN_STATE_KINDS.clearance

    const record = await routing.ring.digestsFor(kind, key)
    if (record === null) {
      // Keyer tidak menghasilkan digest: tolak, jangan pernah menulis teks aslinya dan jangan
      // pernah menulis ke bentuk `key_hash` yang tidak dikenali.
      return json(storageFailure('storage_unavailable'))
    }

    switch (action) {
      case SCAN_STATE_ACTIONS.counter: {
        const outcome = routing.ops.consumeCounter({
          record,
          limit: limit!,
          windowMs: windowMs!,
          now,
        })
        if (outcome.status === 'error') return json(storageFailure(outcome.code))
        this.scheduleSweepAlarm()
        return json({
          ok: true,
          allowed: outcome.value.allowed,
          retryAfterSeconds: outcome.value.retryAfterSeconds,
          ...(outcome.value.used === undefined ? {} : { used: outcome.value.used }),
        })
      }
      case SCAN_STATE_ACTIONS.has: {
        const outcome = routing.ops.hasClearance(record, now)
        if (outcome.status === 'error') return json(storageFailure(outcome.code))
        return json({ ok: true, allowed: outcome.value })
      }
      case SCAN_STATE_ACTIONS.issue: {
        const outcome = routing.ops.issueClearance(record, now, ttlMs!)
        if (outcome.status === 'error') return json(storageFailure(outcome.code))
        this.scheduleSweepAlarm()
        return json({ ok: true, allowed: outcome.value })
      }
      case SCAN_STATE_ACTIONS.reserve: {
        const outcome = routing.ops.reserveToken(record, now, TURNSTILE_TOKEN_RETENTION_MS)
        if (outcome.status === 'error') return json(storageFailure(outcome.code))
        this.scheduleSweepAlarm()
        return json({ ok: true, reservation: outcome.value })
      }
      case SCAN_STATE_ACTIONS.release: {
        const outcome = routing.ops.releaseToken(record)
        if (outcome.status === 'error') return json(storageFailure(outcome.code))
        return json({ ok: true })
      }
      default:
        return null
    }
  }
}

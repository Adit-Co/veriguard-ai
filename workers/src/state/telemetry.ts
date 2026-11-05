/**
 * VGL-30F R4: instrumentasi state yang bisa dibaca tanpa membocorkan state.
 *
 * Yang dicari lewat catatan ini (VGL-30D/F2 dan VGL-30E §3): bedanyakan "pencacah turun ke nol"
 * sebagai kerugian restart actor vs restart isolate Worker, dan bedakan keputusan yang datang
 * dari penyimpanan durable vs memori isolate. Sebelum ini, satu-satunya catatan adalah
 * `scan_state_rpc` (VGL-28) yang hanya muncul saat RPC GAGAL — jadi jalur yang berhasil buta
 * terhadap identitas instance, dan F2 tidak bisa dibuktikan dari log.
 *
 * Aturan isi catatan (keras):
 *  - Tidak ada kunci state, IP, UID, URL, token, atau payload permintaan di sini. Bentuk event di
 *    bawah hanya menerima field yang isinya ditetapkan kode ini sendiri: nama konstanta, angka,
 *    durasi, dan nonce pendek. Karena tidak ada string pihak ketiga yang masuk, tidak ada jalur
 *    bagi data sensitif untuk ikut terserialisasi.
 *  - `corr` adalah penghubung satu permintaan Worker ke satu permintaan RPC. Ia acak, berumur
 *    pendek, dan tidak menurunkan apa pun tentang identitas pengguna.
 *  - Tidak ada endpoint diagnostik publik baru: keluarannya `console.warn`, yang ditangkap
 *    `wrangler tail` sama seperti catatan VGL-28.
 *
 * Pemetaan kelas kejadian ke catatan:
 *  - identitas isolate Worker / isolate actor, lifecycle instance actor, restorasi state,
 *    operasi storage, transisi pemutus  -> `scan_state_evt` (berkas ini)
 *  - kegagalan RPC + "keputusan diambil memori isolate" (`fallbackUsed: true`) -> `scan_state_rpc`
 *    (store.ts), sekarang membawa `corr` supaya keduanya bisa disambung.
 */

export const SCAN_STATE_EVENT_LOG_PREFIX = 'scan_state_evt'

export type ScanStateEventSource = 'worker' | 'actor'

export type ScanStateEventName =
  | 'worker_isolate_identity'
  | 'actor_isolate_identity'
  | 'actor_instance_started'
  | 'actor_counters_restored'
  | 'actor_clearances_restored'
  | 'actor_tokens_restored'
  | 'durable_read'
  | 'durable_write'
  | 'durable_error'
  | 'breaker_transition'

export type ScanStateEvent = {
  v: 1
  ts: number
  event: ScanStateEventName
  src: ScanStateEventSource
  /** Nonce isolate tempat catatan ini dibuat. Worker: `wn`; actor: `rn`. */
  wn?: string
  rn?: string
  /** Nonce instance actor; berubah setiap kali actor dihidupkan ulang. */
  an?: string
  /** actor id dipotong 8 karakter: cukup untuk menggolongkan actor, bukan untuk dipakai ulang. */
  aid?: string
  /** Urutan instance actor dalam isolate actor ini; ulang dari 1 saat isolate actor berganti. */
  iseq?: number
  /** Penghubung permintaan; hanya sah di dalam satu permintaan Worker. */
  corr?: string
  op?: string
  /** Hasil keputusan, ditetapkan oleh kode pemanggil dari konstanta. */
  out?: string
  dur_ms?: number
  rows?: number
  kind?: string
  /** Umur baris saat dibaca kembali, dalam ms (bukti restorasi lintas restart). */
  age_ms?: number
  cat?: string
  brk?: 'open' | 'closed'
  bleft?: number
  /** LABEL versi kunci yang aktif (mis. `v2`), atau `legacy`. Bukan materi kunci, bukan digest. */
  kv?: string
}

export type ScanStateEventInput = Omit<ScanStateEvent, 'v' | 'ts'>

const EVENT_RING_LIMIT = 200
// Operasi baca durable mengikuti setiap keputusan: direkam semua, dicatat 1 dari 10, supaya
// jalur panas tidak menggandakan volume log.
const DURABLE_READ_SAMPLE_RATE = 10

const eventRing: ScanStateEvent[] = []
const isolateNonces = new Map<ScanStateEventSource, string>()
let actorInstanceSequence = 0
let readSampleCounter = 0

function randomNonce(chars: number): string {
  const cryptoGlobal = (globalThis as { crypto?: { randomUUID?(): string } }).crypto
  const source = cryptoGlobal?.randomUUID?.() ?? `${Date.now()}.${Math.random()}`
  return source.replace(/[^a-z0-9]/gi, '').toLowerCase().slice(0, chars)
}

/** Nonce pendek untuk identitas instance/permintaan. Bukan rahasia, bukan bahan kriptografis. */
export function createNonce(chars = 8): string {
  return randomNonce(chars)
}

/** Nonce per isolate (Worker dan actor terpisah), sekaligus catatan identitas pertama isolate itu. */
export function isolateNonce(source: ScanStateEventSource): string {
  const existing = isolateNonces.get(source)
  if (existing) return existing
  const created = randomNonce(8)
  isolateNonces.set(source, created)
  emitScanStateEvent({
    event: source === 'worker' ? 'worker_isolate_identity' : 'actor_isolate_identity',
    src: source,
    ...(source === 'worker' ? { wn: created } : { rn: created }),
  })
  return created
}

export function createCorrelationId(): string {
  return randomNonce(12)
}

export function nextActorInstanceSequence(): number {
  actorInstanceSequence += 1
  return actorInstanceSequence
}

/** `idFromName(...).toString()` bisa panjang; cukup prefix stabil untuk pengelompokan. */
export function shortActorId(id: string): string {
  return id.slice(0, 8)
}

export function emitScanStateEvent(input: ScanStateEventInput): void {
  const event: ScanStateEvent = { v: 1, ts: Date.now(), ...input }
  eventRing.push(event)
  if (eventRing.length > EVENT_RING_LIMIT) eventRing.shift()

  if (input.event === 'durable_read') {
    readSampleCounter = (readSampleCounter + 1) % DURABLE_READ_SAMPLE_RATE
    if (readSampleCounter !== 0) return
  }

  try {
    console.warn(`${SCAN_STATE_EVENT_LOG_PREFIX} ${JSON.stringify(event)}`)
  } catch {
    // Catatan tidak boleh menggagalkan keputusan; ring buffer tetap terisi untuk tes.
  }
}

export function readScanStateEvents(): ScanStateEvent[] {
  return eventRing.map((event) => ({ ...event }))
}

export function resetScanStateEvents(): void {
  eventRing.length = 0
  readSampleCounter = 0
  actorInstanceSequence = 0
}

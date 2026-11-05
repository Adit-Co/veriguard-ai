/**
 * VGL-30F R1: lapisan penyimpanan durable untuk state SCAN_STATE di Durable Object.
 *
 * Masalah yang ditutup (VGL-30D/F2): seluruh state DO sebelumnya hidup di field instance, dan
 * `state.storage` tidak pernah disentuh. Setiap instance actor di-evict (hibernasi, deploy,
 * migrasi, kegagalan runtime) pencacah, izin CAPTCHA, dan registry anti-replay ikut hilang.
 * Di sini penyimpanan SQL actor menjadi SATU-SATUNYA sumber kebenaran: keputusan izin dihitung
 * dari hasil tulis yang sudah berhasil, bukan dari memori yang belum tersimpan.
 *
 * Aturan yang dijaga kode ini:
 *  1. Satu operasi = satu `transactionSync` sinkron. Tidak ada `await` di dalam bagian keputusan,
 *     jadi actor single-threaded menjamin read-modify-write tidak saling menimpa. `sql.exec()`
 *     auto-commit per pernyataan, sehingga operasi multi-pernyataan WAJIB dibungkus.
 *  2. Bootstrap idempoten: `CREATE TABLE IF NOT EXISTS`, versi di `PRAGMA user_version` (dengan
 *     tabel cadangan bila runtime tidak mendukungnya), pemeriksaan `table_info` defensif, dan
 *     tidak pernah `DROP`/`ALTER` yang menghapus state. Namespace yang sudah berisi baris tetap
 *     dikenali, tidak dianggap kosong.
 *  3. Galat penyimpanan tidak boleh gagal-buka: pemanggil menerima kode yang dikenali
 *     (`storage_unavailable` / `schema_version`) dan sisi Store menolak keputusan, bukan jatuh ke
 *     memori isolate.
 *  4. Semantik keputusan identik dengan `functions/src/state/stores.ts` (jendela tetap, penolakan
 *     limit <= 0, tabel penuh menolak kunci BARU, penolakan tidak menaikkan `used`, izin kedaluwarsa
 *     dihapus saat disentuh). Paritas itu dites, bukan diasumsikan.
 *  5. Kunci yang ditulis adalah digest HMAC berversi (`stateKeys.ts`), bukan IP/UID. Bentuk
 *     `key_hash` adalah `v<n>:<64 hex>`; tanpa keyer, lapisan ini tidak diaktifkan.
 *  6. VGL-30H K-3: migrasi antarversi kunci adalah SATU transaksi salin-hapus. Baris versi lama
 *     dipindah ke versi aktif hanya bila operasi ini memang menulis; `used`, `window_start`,
 *     `expires_at`, dan `updated_at` disalin apa adanya (tidak di-increment ulang), dan baris lama
 *     dihapus pada transaksi yang sama supaya tidak ada dua baris untuk satu identitas.
 *
 * Tipe surface SQL di bawah struktural (bukan dari @cloudflare/workers-types) supaya host Node
 * yang mengimpor paket ini tetap bisa type-check, dan supaya uji unit bisa menjalankan kode yang
 * sama di atas SQLite sungguhan (`node:sqlite`) alih-alih tiruan.
 */

import { emitScanStateEvent } from './telemetry.js'
import type { ScanStateEventSource } from './telemetry.js'
import { isUsableKeyHash, keyHashLabel, parseKeyRecord } from './stateKeys.js'

export const VGL_STATE_SCHEMA_VERSION = 1
export const VGL_STATE_TABLE = 'vgl_state'
export const VGL_SCHEMA_TABLE = 'vgl_schema'

export const SCAN_STATE_KINDS = {
  counter: 'counter',
  clearance: 'clearance',
  token: 'token',
  meta: 'meta',
} as const

export type ScanStateKind = (typeof SCAN_STATE_KINDS)[keyof typeof SCAN_STATE_KINDS]

const MAX_RETRY_AFTER_SECONDS = 3_600
const SWEEP_INTERVAL_MS = 10_000
const SWEEP_BATCH_ROWS = 200
// Sensus versi bukan jalur keputusan: batas baris menjaga agar pembacaan penuh tidak berubah
// menjadi pemindaian tak terbatas pada namespace besar.
const CENSUS_ROW_LIMIT = 20_000
const REQUIRED_COLUMNS = ['kind', 'key_hash', 'used', 'window_start', 'expires_at', 'updated_at']

// Cermin `retryAfter()` di functions/src/state/stores.ts: minimal 1 detik, batas atas 3600.
function retryAfterSeconds(ms: number): number {
  if (!Number.isFinite(ms) || ms <= 0) return 1
  return Math.min(MAX_RETRY_AFTER_SECONDS, Math.max(1, Math.ceil(ms / 1_000)))
}

export type DurableSqlCursor = {
  columnNames?: string[]
  toArray?(): Record<string, unknown>[]
  raw?(): IterableIterator<unknown[]>
  one?(): Record<string, unknown>
}

export type DurableSqlStorage = {
  exec(query: string, ...bindings: unknown[]): DurableSqlCursor
}

export type DurableStorageSurface = {
  sql?: DurableSqlStorage
  transactionSync?<T>(closure: () => T): T
  setAlarm?(scheduledTime: number | Date): Promise<void> | void
  getAlarm?(): Promise<number | null>
}

export type DurableStateIdentity = {
  /** Nonce isolate actor (`telemetry.isolateNonce('actor')`). */
  rn: string
  /** Nonce instance actor ini; berubah setiap actor dihidupkan ulang. */
  an: string
  iseq: number
  /** actor id yang sudah dipotong. */
  aid?: string
  /** Penghubung permintaan Worker yang memicu operasi ini. */
  corr?: string
  /** Cap waktu instance actor dibuat, untuk mengenali baris hasil restorasi. */
  bootMs: number
}

export type DurableErrorCode = 'storage_unavailable' | 'schema_version'

export type DurableOutcome<T> =
  | { status: 'ok'; value: T }
  | { status: 'error'; code: DurableErrorCode }

export type DurableCounterValue = {
  allowed: boolean
  retryAfterSeconds: number
  used?: number
}

/**
 * VGL-30H K-3: satu identitas, semua digest yang perlu dicari. `activeHash` dipakai untuk menulis;
 * `retiredHashes` (urutan lama→baru) hanya untuk membaca dan memindahkan record. Keduanya sudah
 * dihitung pemanggil SEBELUM transaksi dibuka, karena HMAC bersifat async dan `transactionSync`
 * tidak boleh mengandung `await`.
 */
export type DurableKeyRecord = {
  activeHash: string
  retiredHashes?: string[]
}

export type DurableCounterInput = {
  record: DurableKeyRecord
  limit: number
  windowMs: number
  now: number
}

export type DurableTokenReservation = 'reserved' | 'reused' | 'full'

export type DurableBootstrap = {
  ok: boolean
  code?: DurableErrorCode
  detail?: string
  pragmaSupported: boolean
  restoredCounters: number
  restoredClearances: number
  restoredTokens: number
}

type StepResult<T> = { outcome: DurableOutcome<T>; rows: number; wrote: boolean }

function rowsOf(cursor: DurableSqlCursor | undefined): Record<string, unknown>[] {
  if (!cursor) return []
  if (typeof cursor.toArray === 'function') return cursor.toArray()
  if (cursor.raw) {
    const names = cursor.columnNames ?? []
    const collected: Record<string, unknown>[] = []
    for (const row of cursor.raw()) {
      const entry: Record<string, unknown> = {}
      names.forEach((name, index) => {
        entry[name] = row[index]
      })
      collected.push(entry)
    }
    return collected
  }
  return []
}

function firstRow(cursor: DurableSqlCursor | undefined): Record<string, unknown> | undefined {
  return rowsOf(cursor)[0]
}

function numberOf(row: Record<string, unknown> | undefined, field: string): number | null {
  const value = row?.[field]
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

type ResolvedKeyRecord = { activeHash: string; retiredHashes: string[] }

/**
 * Bentuk ulang permintaan kunci sebelum transaksi dibuka. Digest aktif yang tidak berprefiks versi
 * membuat operasi ditolak: menulis dengan hash tanpa versi akan mengembalikan bentuk pra-VGL-30H yang
 * justru ingin dipindah (K-2), dan digest aktif yang tidak dikenali bentuknya tidak akan terbaca lagi
 * oleh pencarian mana pun. Hash versi lama yang tidak dikenali dibuang dari pencarian karena memang
 * tidak akan pernah cocok; bentuk legacy (tanpa prefiks) tetap dicari karena baris pra-VGL-30H
 * berwujud begitu.
 */
function resolveKeyRecord(record: DurableKeyRecord | undefined): ResolvedKeyRecord | null {
  if (!record || typeof record.activeHash !== 'string') return null
  if (parseKeyRecord(record.activeHash).form !== 'versioned') return null
  const retiredHashes: string[] = []
  for (const candidate of record.retiredHashes ?? []) {
    if (candidate === record.activeHash) continue
    if (!isUsableKeyHash(candidate)) continue
    if (!retiredHashes.includes(candidate)) retiredHashes.push(candidate)
  }
  return { activeHash: record.activeHash, retiredHashes }
}

export type CreateDurableStateOptions = {
  storage: DurableStorageSurface
  identity: DurableStateIdentity
  maxKeys: number
  source?: ScanStateEventSource
}

export type DurableKeyVersionCensus = {
  /** Jumlah baris per label versi (`v1`, `v2`, `legacy`) pada kind beridentitas. */
  rowsByLabel: Record<string, number>
  /** Baris yang TIDAK memakai versi aktif; dasar penolakan penghapusan kunci (K-4 butir 9). */
  nonActiveRows: number
  /** Baris dengan `key_hash` yang tidak dikenali bentuknya; tidak pernah dianggap identitas. */
  malformedRows: number
}

export type DurableStateOps = {
  /** Permukaan SQL yang dibutuhkan tersedia di runtime ini. */
  readonly supported: boolean
  bootstrap(): DurableBootstrap
  consumeCounter(input: DurableCounterInput): DurableOutcome<DurableCounterValue>
  hasClearance(record: DurableKeyRecord, now: number): DurableOutcome<boolean>
  issueClearance(record: DurableKeyRecord, now: number, ttlMs: number): DurableOutcome<boolean>
  reserveToken(
    record: DurableKeyRecord,
    now: number,
    retentionMs: number,
  ): DurableOutcome<DurableTokenReservation>
  releaseToken(record: DurableKeyRecord): DurableOutcome<void>
  sweepExpired(now: number): number
  /** Sensus versi kunci; dibaca kebijakan retensi, bukan jalur keputusan. */
  inventoryKeyVersions(activeLabel: string): DurableOutcome<DurableKeyVersionCensus>
}

/**
 * Satu tabel untuk semua kind: `used` untuk pencacah, `window_start` untuk awal jendela tetap,
 * `expires_at` untuk umur (akhir jendela / akhir izin / akhir retensi token). `updated_at`
 * dipakai membuktikan restorasi: baris yang lebih tua dari instance ini bukan tulisan instance ini.
 * `WITHOUT ROWID` karena primary key-nya sudah (kind, key_hash) dan tidak ada pembacaan rentang
 * lain yang membutuhkannya.
 */
const CREATE_TABLE = `CREATE TABLE IF NOT EXISTS ${VGL_STATE_TABLE} (
  kind TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  window_start INTEGER,
  expires_at INTEGER,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (kind, key_hash)
) WITHOUT ROWID`

const CREATE_EXPIRY_INDEX = `CREATE INDEX IF NOT EXISTS vgl_state_expiry_idx ON ${VGL_STATE_TABLE} (expires_at)`

// Cadangan tempat mencatat versi skema bila runtime menolak PRAGMA yang bisa ditulis.
const CREATE_SCHEMA_TABLE = `CREATE TABLE IF NOT EXISTS ${VGL_SCHEMA_TABLE} (
  version INTEGER NOT NULL,
  applied_at INTEGER NOT NULL
)`

export function createDurableStateOps(options: CreateDurableStateOptions): DurableStateOps {
  const storage = options.storage
  const sql = storage.sql
  const transactionSync = storage.transactionSync
  const identity = options.identity
  const maxKeys = options.maxKeys
  const source = options.source ?? 'actor'

  const usable = (): boolean => typeof sql?.exec === 'function' && typeof transactionSync === 'function'

  let bootstrapped = false
  let bootstrapOutcome: DurableBootstrap | undefined

  // Dibaca saat emit, bukan saat dibuat: `corr` berubah tiap permintaan Worker yang masuk.
  function eventFields() {
    return {
      src: source,
      an: identity.an,
      rn: identity.rn,
      iseq: identity.iseq,
      aid: identity.aid,
      corr: identity.corr,
    }
  }

  function inTransaction<T>(closure: () => T): T {
    // `transactionSync` dipanggil dengan receiver `storage` karena runtime mengikatnya ke sana.
    const invoke = transactionSync as unknown as (this: unknown, fn: () => T) => T
    return invoke.call(storage, closure)
  }

  function fail(detail: string): DurableBootstrap {
    return {
      ok: false,
      code: 'storage_unavailable',
      detail,
      pragmaSupported: false,
      restoredCounters: 0,
      restoredClearances: 0,
      restoredTokens: 0,
    }
  }

  function currentVersion(): { pragmaSupported: boolean; version: number | null } {
    try {
      const row = firstRow(sql!.exec('PRAGMA user_version'))
      if (row) {
        const value = numberOf(row, 'user_version') ?? numberOf(row, Object.keys(row)[0] ?? '')
        if (value !== null) return { pragmaSupported: true, version: value }
      }
    } catch {
      // PRAGMA tidak tersedia di jalur ini: pakai tabel cadangan.
    }
    try {
      sql!.exec(CREATE_SCHEMA_TABLE)
      const row = firstRow(sql!.exec(`SELECT version FROM ${VGL_SCHEMA_TABLE} LIMIT 1`))
      const stored = numberOf(row, 'version')
      // Tabel cadangan kosong = namespace belum pernah di-bootstrap, bukan "tidak terbaca".
      return { pragmaSupported: false, version: stored === null ? 0 : stored }
    } catch {
      return { pragmaSupported: false, version: null }
    }
  }

  function writeVersion(version: number, now: number): void {
    try {
      sql!.exec(`PRAGMA user_version = ${version}`)
      const row = firstRow(sql!.exec('PRAGMA user_version'))
      if ((numberOf(row, 'user_version') ?? numberOf(row, Object.keys(row ?? {})[0] ?? '')) === version) {
        return
      }
    } catch {
      // PRAGMA tulis ditolak: pakai tabel cadangan.
    }
    try {
      sql!.exec(CREATE_SCHEMA_TABLE)
      sql!.exec(`DELETE FROM ${VGL_SCHEMA_TABLE}`)
      sql!.exec(`INSERT INTO ${VGL_SCHEMA_TABLE} (version, applied_at) VALUES (?, ?)`, version, now)
    } catch {
      // Versi gagal tercatat: bootstrap berikutnya akan membaca 0 dan membuat ulang tabel yang
      // sudah ada (idempoten), bukan menulis ke bentuk yang tidak dikenali.
    }
  }

  function tableColumns(): string[] | null {
    try {
      return rowsOf(sql!.exec(`PRAGMA table_info(${VGL_STATE_TABLE})`))
        .map((row) => (typeof row.name === 'string' ? row.name : ''))
        .filter((name) => name !== '')
    } catch {
      return null
    }
  }

  function countRows(kind: string): number {
    const row = firstRow(
      sql!.exec(`SELECT COUNT(*) AS total FROM ${VGL_STATE_TABLE} WHERE kind = ?`, kind),
    )
    return numberOf(row, 'total') ?? 0
  }

  function oldestUpdate(kind: string): number | null {
    const row = firstRow(
      sql!.exec(`SELECT MIN(updated_at) AS oldest FROM ${VGL_STATE_TABLE} WHERE kind = ?`, kind),
    )
    return numberOf(row, 'oldest')
  }

  /**
   * Penghapusan kedaluwarsa berbentuk dua langkah (SELECT lalu DELETE per baris) karena tabel ini
   * `WITHOUT ROWID`: `DELETE ... LIMIT` dan perbandingan row-value tidak dijamin ada di semua build
   * SQLite. Jumlah baris per sapuan tetap terbatas.
   */
  function deleteExpired(now: number, limit: number): number {
    const stale = rowsOf(
      sql!.exec(
        `SELECT kind, key_hash FROM ${VGL_STATE_TABLE}
         WHERE expires_at IS NOT NULL AND expires_at <= ? ORDER BY expires_at LIMIT ?`,
        now,
        limit,
      ),
    )
    for (const row of stale) {
      sql!.exec(
        `DELETE FROM ${VGL_STATE_TABLE} WHERE kind = ? AND key_hash = ?`,
        String(row.kind),
        String(row.key_hash),
      )
    }
    return stale.length
  }

  /** Sapuan berjendela: maksimal sekali tiap SWEEP_INTERVAL_MS, ditandai baris `meta`. */
  function sweepThrottled(now: number): number {
    const marker = firstRow(
      sql!.exec(
        `SELECT updated_at FROM ${VGL_STATE_TABLE} WHERE kind = ? AND key_hash = ?`,
        SCAN_STATE_KINDS.meta,
        'sweep',
      ),
    )
    const lastSweep = numberOf(marker, 'updated_at')
    if (lastSweep !== null && now - lastSweep < SWEEP_INTERVAL_MS) return 0
    const removed = deleteExpired(now, SWEEP_BATCH_ROWS)
    sql!.exec(
      `INSERT OR REPLACE INTO ${VGL_STATE_TABLE} (kind, key_hash, used, window_start, expires_at, updated_at)
       VALUES (?, ?, 0, NULL, NULL, ?)`,
      SCAN_STATE_KINDS.meta,
      'sweep',
      now,
    )
    return removed
  }

  function ensureSchema(now: number): {
    ok: boolean
    code?: DurableErrorCode
    detail?: string
    pragmaSupported: boolean
  } {
    const version = currentVersion()
    if (version.version === null) {
      return { ok: false, code: 'storage_unavailable', pragmaSupported: version.pragmaSupported }
    }
    if (version.version > VGL_STATE_SCHEMA_VERSION) {
      // Runtime/versi kode lebih baru dari yang kita kenal: jangan menulis apa pun.
      return { ok: false, code: 'schema_version', detail: 'versi_lebih_baru', pragmaSupported: version.pragmaSupported }
    }

    if (version.version === 0) {
      sql!.exec(CREATE_TABLE)
      sql!.exec(CREATE_EXPIRY_INDEX)
      writeVersion(VGL_STATE_SCHEMA_VERSION, now)
      return { ok: true, pragmaSupported: version.pragmaSupported }
    }

    // Versi cocok: periksa BENTUK tabel lebih dulu, sebelum CREATE INDEX. Indeks menunjuk kolom
    // yang wajib ada, dan membentrukannya pada tabel berbentu lain akan melempar sebelum
    // sempat melaporkan penyebab aslinya. Namespace yang sudah berisi baris diperlakukan
    // sebagai milik kita hanya kalau kolomnya lengkap.
    const columns = tableColumns()
    if (columns === null) {
      return { ok: false, code: 'storage_unavailable', pragmaSupported: version.pragmaSupported }
    }
    if (columns.length === 0) {
      // Versi tercatat tetapi tabelnya tidak ada (mis. namespace dipulihkan sebagian): buat ulang
      // bentuk yang sama, jangan menulis ke bentuk lain.
      sql!.exec(CREATE_TABLE)
      sql!.exec(CREATE_EXPIRY_INDEX)
      return { ok: true, pragmaSupported: version.pragmaSupported }
    }
    const missing = REQUIRED_COLUMNS.filter((column) => !columns.includes(column))
    if (missing.length > 0) {
      // Tidak ada ALTER yang menghapus atau mengganti bentuk kolom: kalau bentuknya tidak
      // dikenali, lebih baik gagal-tertutup daripada menulis ke tabel yang salah.
      return { ok: false, code: 'schema_version', detail: 'kolom_tidak_dikenali', pragmaSupported: version.pragmaSupported }
    }
    sql!.exec(CREATE_TABLE)
    sql!.exec(CREATE_EXPIRY_INDEX)
    return { ok: true, pragmaSupported: version.pragmaSupported }
  }

  function emitRestored(kind: ScanStateKind, event: 'actor_counters_restored' | 'actor_clearances_restored' | 'actor_tokens_restored', rows: number, ageMs: number): void {
    if (rows <= 0) return
    emitScanStateEvent({ ...eventFields(), event, kind, rows, age_ms: ageMs })
  }

  function runBootstrap(): DurableBootstrap {
    const now = Date.now()
    if (!usable()) {
      bootstrapped = true
      bootstrapOutcome = fail('permukaan_sql_tidak_tersedia')
      return bootstrapOutcome
    }

    let ensured: { ok: boolean; code?: DurableErrorCode; detail?: string; pragmaSupported: boolean }
    try {
      ensured = inTransaction(() => ensureSchema(now))
    } catch {
      bootstrapped = true
      bootstrapOutcome = fail('bootstrap_ditolak')
      emitScanStateEvent({ ...eventFields(), event: 'actor_instance_started', out: 'error', cat: 'storage_unavailable' })
      return bootstrapOutcome
    }

    const restored = { counters: 0, clearances: 0, tokens: 0, oldest: 0 }
    if (ensured.ok) {
      try {
        inTransaction(() => {
          restored.counters = countRows(SCAN_STATE_KINDS.counter)
          restored.clearances = countRows(SCAN_STATE_KINDS.clearance)
          restored.tokens = countRows(SCAN_STATE_KINDS.token)
          for (const kind of [
            SCAN_STATE_KINDS.counter,
            SCAN_STATE_KINDS.clearance,
            SCAN_STATE_KINDS.token,
          ] as const) {
            const oldest = oldestUpdate(kind)
            if (oldest !== null && oldest < identity.bootMs) restored.oldest = Math.max(restored.oldest, now - oldest)
          }
          return undefined
        })
      } catch {
        // Pembacaan restorasi hanya diagnostik; kegagalan di sini tidak mengubah keputusan dan
        // tidak menggagalkan bootstrap. Operasi berikutnya melaporkan galatnya sendiri.
      }
    }

    emitScanStateEvent({
      ...eventFields(),
      event: 'actor_instance_started',
      out: ensured.ok ? 'ok' : 'error',
      cat: ensured.ok ? undefined : ensured.code,
      rows: restored.counters + restored.clearances + restored.tokens,
    })
    if (ensured.ok) {
      emitRestored(SCAN_STATE_KINDS.counter, 'actor_counters_restored', restored.counters, restored.oldest)
      emitRestored(SCAN_STATE_KINDS.clearance, 'actor_clearances_restored', restored.clearances, restored.oldest)
      emitRestored(SCAN_STATE_KINDS.token, 'actor_tokens_restored', restored.tokens, restored.oldest)
    }

    bootstrapped = true
    bootstrapOutcome = {
      ok: ensured.ok,
      code: ensured.code,
      detail: ensured.detail,
      pragmaSupported: ensured.pragmaSupported,
      restoredCounters: restored.counters,
      restoredClearances: restored.clearances,
      restoredTokens: restored.tokens,
    }
    return bootstrapOutcome
  }

  function bootstrap(): DurableBootstrap {
    if (bootstrapOutcome) return bootstrapOutcome
    return runBootstrap()
  }

  /**
   * Satu transaksi untuk seluruh operasi keputusan. Kalau body melempar (mis. SQLite menutup
   * transaksi karena disk penuh), hasilnya selalu `storage_unavailable`: tidak ada jalur yang
   * mengembalikan keputusan izin dari state yang belum pasti tersimpan.
   */
  function step<T>(
    op: string,
    body: () => StepResult<T>,
    record?: DurableKeyRecord,
  ): DurableOutcome<T> {
    if (!usable()) return { status: 'error', code: 'storage_unavailable' }
    // Hanya LABEL versi yang boleh keluar ke catatan; materi kunci dan digest tidak pernah ikut.
    const label = record === undefined ? undefined : keyHashLabel(record.activeHash) ?? undefined
    const startedAt = Date.now()
    try {
      const { outcome, rows, wrote } = inTransaction(body)
      const durationMs = Date.now() - startedAt
      if (outcome.status === 'error') {
        emitScanStateEvent({ ...eventFields(), event: 'durable_error', op, cat: outcome.code, dur_ms: durationMs, ...(label === undefined ? {} : { kv: label }) })
      } else {
        // Setiap keputusan membaca; yang menulis juga mencatat tulisannya. `durable_read`
        // disampling 1/10 di telemetry supaya jalur panas tidak menggandakan volume log.
        emitScanStateEvent({ ...eventFields(), event: 'durable_read', op, rows, dur_ms: durationMs, ...(label === undefined ? {} : { kv: label }) })
        if (wrote) {
          emitScanStateEvent({
            ...eventFields(),
            event: 'durable_write',
            op,
            out: 'applied',
            rows,
            dur_ms: durationMs,
            ...(label === undefined ? {} : { kv: label }),
          })
        }
      }
      return outcome
    } catch {
      emitScanStateEvent({
        ...eventFields(),
        event: 'durable_error',
        op,
        cat: 'storage_unavailable',
        dur_ms: Date.now() - startedAt,
        ...(label === undefined ? {} : { kv: label }),
      })
      return { status: 'error', code: 'storage_unavailable' }
    }
  }

  function rejectWindow(windowMs: number): StepResult<DurableCounterValue> {
    return {
      outcome: { status: 'ok', value: { allowed: false, retryAfterSeconds: retryAfterSeconds(windowMs) } },
      rows: 0,
      wrote: false,
    }
  }

  const VALUE_COLUMNS = 'used, window_start, expires_at, updated_at'

  function selectRow(
    kind: ScanStateKind,
    keyHash: string,
    columns = VALUE_COLUMNS,
  ): Record<string, unknown> | undefined {
    return firstRow(
      sql!.exec(
        `SELECT ${columns} FROM ${VGL_STATE_TABLE} WHERE kind = ? AND key_hash = ?`,
        kind,
        keyHash,
      ),
    )
  }

  function deleteRow(kind: ScanStateKind, keyHash: string): void {
    sql!.exec(`DELETE FROM ${VGL_STATE_TABLE} WHERE kind = ? AND key_hash = ?`, kind, keyHash)
  }

  /**
   * Baris pertama yang ditemukan di versi lama, beserta identitas hash-nya. Urutan pencarian
   * mengikuti urutan ring (lama→baru) supaya hasil migrasi tidak bergantung pada waktu.
   */
  function findRetiredRow(
    kind: ScanStateKind,
    retiredHashes: string[],
    columns = VALUE_COLUMNS,
  ): { keyHash: string; row: Record<string, unknown> } | undefined {
    for (const keyHash of retiredHashes) {
      const row = selectRow(kind, keyHash, columns)
      if (row !== undefined) return { keyHash, row }
    }
    return undefined
  }

  function counterDeny(used: number, windowStart: number, windowMs: number, now: number): StepResult<DurableCounterValue> {
    // Cermin stores.ts:63-69: penolakan tidak menulis, `used` tetap seperti adanya.
    return {
      outcome: {
        status: 'ok',
        value: {
          allowed: false,
          retryAfterSeconds: retryAfterSeconds(windowStart + windowMs - now),
          used,
        },
      },
      rows: 0,
      wrote: false,
    }
  }

  return {
    get supported() {
      return usable()
    },

    bootstrap,

    consumeCounter(input: DurableCounterInput) {
      const ready = bootstrap()
      if (!ready.ok) return { status: 'error', code: ready.code ?? 'storage_unavailable' }
      const record = resolveKeyRecord(input.record)
      if (record === null) return { status: 'error', code: 'storage_unavailable' }

      return step<DurableCounterValue>(SCAN_STATE_KINDS.counter, () => {
        if (input.limit <= 0 || input.windowMs <= 0) {
          // Cermin stores.ts:48-50: batas nol berarti tidak ada kuota, bukan kuota tak terbatas.
          return rejectWindow(input.windowMs)
        }

        const active = selectRow(SCAN_STATE_KINDS.counter, record.activeHash, 'used, window_start')
        const used = numberOf(active, 'used')
        const windowStart = numberOf(active, 'window_start')

        if (
          active !== undefined &&
          used !== null &&
          windowStart !== null &&
          windowStart + input.windowMs > input.now
        ) {
          if (used >= input.limit) return counterDeny(used, windowStart, input.windowMs, input.now)
          const next = used + 1
          sql!.exec(
            `UPDATE ${VGL_STATE_TABLE} SET used = ?, expires_at = ?, updated_at = ? WHERE kind = ? AND key_hash = ?`,
            next,
            windowStart + input.windowMs,
            input.now,
            SCAN_STATE_KINDS.counter,
            record.activeHash,
          )
          return {
            outcome: { status: 'ok', value: { allowed: true, retryAfterSeconds: 0, used: next } },
            rows: 1,
            wrote: true,
          }
        }

        // Tidak ada jendela hidup di versi aktif. Versi lama hanya dicari kalau operasi ini memang
        // akan menulis: penolakan tidak boleh memicu migrasi (dan tidak boleh menambah tulis).
        const retired = findRetiredRow(SCAN_STATE_KINDS.counter, record.retiredHashes, 'used, window_start')
        const retiredUsed = numberOf(retired?.row, 'used')
        const retiredStart = numberOf(retired?.row, 'window_start')

        if (
          retired !== undefined &&
          retiredUsed !== null &&
          retiredStart !== null &&
          retiredStart + input.windowMs > input.now
        ) {
          if (retiredUsed >= input.limit) return counterDeny(retiredUsed, retiredStart, input.windowMs, input.now)
          // Re-key: SALIN `used` dan `window_start`, baru increment sekali untuk permintaan ini.
          // Menghitung ulang dari nol akan menghanguskan kuota; menuliskan "1" akan memberi
          // penyerang jendela baru.
          const next = retiredUsed + 1
          sql!.exec(
            `INSERT OR REPLACE INTO ${VGL_STATE_TABLE} (kind, key_hash, used, window_start, expires_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)`,
            SCAN_STATE_KINDS.counter,
            record.activeHash,
            next,
            retiredStart,
            retiredStart + input.windowMs,
            input.now,
          )
          deleteRow(SCAN_STATE_KINDS.counter, retired.keyHash)
          return {
            outcome: { status: 'ok', value: { allowed: true, retryAfterSeconds: 0, used: next } },
            rows: 2,
            wrote: true,
          }
        }

        if (active === undefined && retired === undefined) {
          sweepThrottled(input.now)
          if (countRows(SCAN_STATE_KINDS.counter) >= maxKeys) {
            // Cermin stores.ts:56-58: tabel penuh menolak kunci BARU, tidak mengusir yang hidup.
            return rejectWindow(input.windowMs)
          }
        }
        if (retired !== undefined) deleteRow(SCAN_STATE_KINDS.counter, retired.keyHash)
        sql!.exec(
          `INSERT OR REPLACE INTO ${VGL_STATE_TABLE} (kind, key_hash, used, window_start, expires_at, updated_at)
           VALUES (?, ?, 1, ?, ?, ?)`,
          SCAN_STATE_KINDS.counter,
          record.activeHash,
          input.now,
          input.now + input.windowMs,
          input.now,
        )
        return {
          outcome: { status: 'ok', value: { allowed: true, retryAfterSeconds: 0, used: 1 } },
          rows: 1,
          wrote: true,
        }
      }, record)
    },

    hasClearance(record: DurableKeyRecord, now: number) {
      const ready = bootstrap()
      if (!ready.ok) return { status: 'error', code: ready.code ?? 'storage_unavailable' }
      const resolved = resolveKeyRecord(record)
      if (resolved === null) return { status: 'error', code: 'storage_unavailable' }

      return step<boolean>('clearance_has', () => {
        const active = selectRow(SCAN_STATE_KINDS.clearance, resolved.activeHash, 'expires_at')
        if (active !== undefined) {
          const expiresAt = numberOf(active, 'expires_at')
          if (expiresAt !== null && expiresAt > now) {
            return { outcome: { status: 'ok', value: true }, rows: 1, wrote: false }
          }
          // Cermin createExpiryRegistry.fresh(): izin kedaluwarsa dihapus saat disentuh.
          deleteRow(SCAN_STATE_KINDS.clearance, resolved.activeHash)
          return { outcome: { status: 'ok', value: false }, rows: 1, wrote: true }
        }

        // Dual-read jalur baca: temuan versi lama dilaporkan TANPA menulis baris di versi aktif,
        // supaya rotasi tidak menambah tulis di jalur panas dan pengguna tidak tertantang ulang.
        let wrote = false
        for (const keyHash of resolved.retiredHashes) {
          const row = selectRow(SCAN_STATE_KINDS.clearance, keyHash, 'expires_at')
          if (row === undefined) continue
          const expiresAt = numberOf(row, 'expires_at')
          if (expiresAt !== null && expiresAt > now) {
            return { outcome: { status: 'ok', value: true }, rows: 1, wrote }
          }
          deleteRow(SCAN_STATE_KINDS.clearance, keyHash)
          wrote = true
        }
        return { outcome: { status: 'ok', value: false }, rows: 0, wrote }
      }, resolved)
    },

    issueClearance(record: DurableKeyRecord, now: number, ttlMs: number) {
      const ready = bootstrap()
      if (!ready.ok) return { status: 'error', code: ready.code ?? 'storage_unavailable' }
      const resolved = resolveKeyRecord(record)
      if (resolved === null) return { status: 'error', code: 'storage_unavailable' }

      return step<boolean>('clearance_issue', () => {
        const activeExists =
          selectRow(SCAN_STATE_KINDS.clearance, resolved.activeHash, 'key_hash') !== undefined
        const retired = activeExists
          ? undefined
          : findRetiredRow(SCAN_STATE_KINDS.clearance, resolved.retiredHashes, 'key_hash')
        if (!activeExists && retired === undefined) {
          sweepThrottled(now)
          if (countRows(SCAN_STATE_KINDS.clearance) >= maxKeys) {
            // Arah gagal tetap "tantang CAPTCHA lagi", sama seperti registry memori.
            return { outcome: { status: 'ok', value: false }, rows: 0, wrote: false }
          }
        }
        sql!.exec(
          `INSERT OR REPLACE INTO ${VGL_STATE_TABLE} (kind, key_hash, used, window_start, expires_at, updated_at)
           VALUES (?, ?, 0, NULL, ?, ?)`,
          SCAN_STATE_KINDS.clearance,
          resolved.activeHash,
          now + Math.max(0, ttlMs),
          now,
        )
        if (retired !== undefined) deleteRow(SCAN_STATE_KINDS.clearance, retired.keyHash)
        return {
          outcome: { status: 'ok', value: true },
          rows: retired === undefined ? 1 : 2,
          wrote: true,
        }
      }, resolved)
    },

    reserveToken(record: DurableKeyRecord, now: number, retentionMs: number) {
      const ready = bootstrap()
      if (!ready.ok) return { status: 'error', code: ready.code ?? 'storage_unavailable' }
      const resolved = resolveKeyRecord(record)
      if (resolved === null) return { status: 'error', code: 'storage_unavailable' }

      return step<DurableTokenReservation>('token_reserve', () => {
        const active = selectRow(SCAN_STATE_KINDS.token, resolved.activeHash, 'expires_at')
        const activeExpiry = numberOf(active, 'expires_at')
        if (activeExpiry !== null && activeExpiry > now) {
          return { outcome: { status: 'ok', value: 'reused' }, rows: 1, wrote: false }
        }
        if (active !== undefined) deleteRow(SCAN_STATE_KINDS.token, resolved.activeHash)

        const retired = findRetiredRow(SCAN_STATE_KINDS.token, resolved.retiredHashes, 'expires_at, updated_at')
        const retiredExpiry = numberOf(retired?.row, 'expires_at')
        if (retired !== undefined && retiredExpiry !== null && retiredExpiry > now) {
          // Anti-replay harus tetap berlaku setelah kuncinya bergeser: baris lama DIPINDAHKAN ke
          // versi aktif (expires_at utuh) dan baris lama dihapus pada transaksi yang sama.
          const retiredUpdated = numberOf(retired.row, 'updated_at')
          sql!.exec(
            `INSERT OR REPLACE INTO ${VGL_STATE_TABLE} (kind, key_hash, used, window_start, expires_at, updated_at)
             VALUES (?, ?, 0, NULL, ?, ?)`,
            SCAN_STATE_KINDS.token,
            resolved.activeHash,
            retiredExpiry,
            retiredUpdated ?? now,
          )
          deleteRow(SCAN_STATE_KINDS.token, retired.keyHash)
          return { outcome: { status: 'ok', value: 'reused' }, rows: 2, wrote: true }
        }

        sweepThrottled(now)
        if (countRows(SCAN_STATE_KINDS.token) >= maxKeys) {
          return { outcome: { status: 'ok', value: 'full' }, rows: 0, wrote: false }
        }
        if (retired !== undefined) deleteRow(SCAN_STATE_KINDS.token, retired.keyHash)
        sql!.exec(
          `INSERT OR REPLACE INTO ${VGL_STATE_TABLE} (kind, key_hash, used, window_start, expires_at, updated_at)
           VALUES (?, ?, 0, NULL, ?, ?)`,
          SCAN_STATE_KINDS.token,
          resolved.activeHash,
          now + Math.max(0, retentionMs),
          now,
        )
        return {
          outcome: { status: 'ok', value: 'reserved' },
          rows: retired === undefined ? 1 : 2,
          wrote: true,
        }
      }, resolved)
    },

    releaseToken(record: DurableKeyRecord) {
      const ready = bootstrap()
      if (!ready.ok) return { status: 'error', code: ready.code ?? 'storage_unavailable' }
      const resolved = resolveKeyRecord(record)
      if (resolved === null) return { status: 'error', code: 'storage_unavailable' }

      return step<void>('token_release', () => {
        // Release hanya menghapus yang memang ditemukan (VGL-30G §2.7): melepas cadangan di versi
        // aktif tidak boleh menyisakan baris versi lama yang masih menahan fingerprint yang sama.
        let removed = 0
        for (const keyHash of [resolved.activeHash, ...resolved.retiredHashes]) {
          if (selectRow(SCAN_STATE_KINDS.token, keyHash, 'key_hash') === undefined) continue
          deleteRow(SCAN_STATE_KINDS.token, keyHash)
          removed += 1
        }
        return { outcome: { status: 'ok', value: undefined }, rows: removed, wrote: removed > 0 }
      }, resolved)
    },

    inventoryKeyVersions(activeLabel: string) {
      if (!usable()) return { status: 'error', code: 'storage_unavailable' }
      if (!bootstrap().ok) return { status: 'error', code: 'storage_unavailable' }
      try {
        return {
          status: 'ok',
          value: inTransaction(() => {
            const rows = rowsOf(
              sql!.exec(
                `SELECT kind, key_hash FROM ${VGL_STATE_TABLE}
                 WHERE kind IN (?, ?, ?) LIMIT ?`,
                SCAN_STATE_KINDS.counter,
                SCAN_STATE_KINDS.clearance,
                SCAN_STATE_KINDS.token,
                CENSUS_ROW_LIMIT,
              ),
            )
            const rowsByLabel: Record<string, number> = {}
            let nonActiveRows = 0
            let malformedRows = 0
            for (const row of rows) {
              const label = keyHashLabel(row.key_hash)
              if (label === null) {
                malformedRows += 1
                continue
              }
              rowsByLabel[label] = (rowsByLabel[label] ?? 0) + 1
              if (label !== activeLabel) nonActiveRows += 1
            }
            return { rowsByLabel, nonActiveRows, malformedRows }
          }),
        }
      } catch {
        return { status: 'error', code: 'storage_unavailable' }
      }
    },

    sweepExpired(now: number) {
      if (!usable() || !bootstrap().ok) return 0
      try {
        return inTransaction(() => deleteExpired(now, SWEEP_BATCH_ROWS))
      } catch {
        return 0
      }
    },
  }
}

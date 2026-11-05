import { beforeEach, describe, expect, it } from 'vitest'
import { SCAN_STATE_KINDS, createDurableStateOps } from '../src/state/durableState.js'
import type { DurableKeyRecord, DurableStateIdentity, DurableStateOps } from '../src/state/durableState.js'
import { readScanStateEvents, resetScanStateEvents } from '../src/state/telemetry.js'
import { createDurableStorageProbe } from './helpers/durableSqlite.js'
import { hashesFor, makeRing, recordOf } from './helpers/keyRings.js'

/**
 * VGL-30H K-3: baca ganda (dual-read) dan re-key-on-write, dijalankan A′ seperti yang dirancang
 * VGL-30G §2.5.
 *
 * Empat hal yang wajib terbukti di sini, dan semuanya diperiksa pada SQLite sungguhan:
 *  1. record versi lama TETAP TERBACA ketika versi aktif berubah (kuota, izin, anti-replay);
 *  2. pemindahan dilakukan dengan MENYALIN, bukan menghitung ulang — `used`, `window_start`,
 *     `expires_at`, `updated_at` harus identik setelah pindah;
 *  3. salin + hapus terjadi di DALAM SATU transaksi, sehingga kegagalan di tengah tidak pernah
 *     meninggalkan state ganda atau hilang;
 *  4. penolakan dan operasi baca murni tidak menambah tulis.
 *
 * Jejak fixture (`tx:BEGIN`, `tx:COMMIT`, `tx:ROLLBACK`) dipakai sebagai bukti urutan, bukan hanya
 * hasil akhir.
 */

const WINDOW_MS = 60_000
const CLEARANCE_TTL_MS = 300_000
const TOKEN_RETENTION_MS = 600_000
const MAX_KEYS = 100

const retired = makeRing({ active: 'v1', labels: ['v1'] })
const active = makeRing({ active: 'v2', labels: ['v1', 'v2'] })
const fresh = makeRing({ active: 'v2', labels: ['v2'] })

let probe: ReturnType<typeof createDurableStorageProbe>

function identity(nonce: string, bootMs = 1_700_000_000_000): DurableStateIdentity {
  return { rn: 'rn-satu', an: nonce, iseq: 1, aid: 'actor000', bootMs }
}

function opsFor(ring: typeof retired, nonce: string): DurableStateOps {
  return createDurableStateOps({ storage: probe.storage, identity: identity(nonce), maxKeys: MAX_KEYS })
}

/** Semua penulisan "zaman v1" dibuat oleh instance yang aktifnya memang v1, seperti produksi dulu. */
function legacyOps(): DurableStateOps {
  return opsFor(retired, 'instance-v1')
}

function currentOps(): DurableStateOps {
  return opsFor(active, 'instance-v2')
}

function traceFrom(start: number): string[] {
  return probe
    .queries()
    .slice(start)
    .filter((entry) => entry.startsWith('tx:') || /^(SELECT|INSERT|DELETE)/.test(entry))
}

function statementsOf(trace: string[], verb: string): string[] {
  return trace.filter((entry) => entry.startsWith(verb))
}

beforeEach(() => {
  resetScanStateEvents()
  probe = createDurableStorageProbe()
})

describe('VGL-30H K-3: baca ganda', () => {
  it('izin yang diterbitkan di versi lama tetap terbaca tanpa menulis di versi aktif', async () => {
    const now = 1_700_000_000_000
    const v1Record = await recordOf(retired, SCAN_STATE_KINDS.clearance, 'ip:lama')
    const v2Record = await recordOf(active, SCAN_STATE_KINDS.clearance, 'ip:lama')

    expect(legacyOps().issueClearance(v1Record, now, CLEARANCE_TTL_MS)).toMatchObject({ value: true })

    const mark = probe.queries().length
    const outcome = currentOps().hasClearance(v2Record, now + 1_000)
    const trace = traceFrom(mark)

    expect(outcome).toMatchObject({ status: 'ok', value: true })
    expect(statementsOf(trace, 'INSERT')).toEqual([])
    expect(statementsOf(trace, 'DELETE')).toEqual([])
    expect(probe.rowFor(SCAN_STATE_KINDS.clearance, v2Record.activeHash)).toBeUndefined()
    expect(probe.rowFor(SCAN_STATE_KINDS.clearance, v1Record.activeHash)).toBeDefined()
  })

  it('baca di versi aktif tidak melakukan pencarian versi lama', async () => {
    const now = 1_700_000_000_000
    const ops = currentOps()
    const v2Record = await recordOf(active, SCAN_STATE_KINDS.clearance, 'ip:baru')

    ops.issueClearance(v2Record, now, CLEARANCE_TTL_MS)

    const mark = probe.queries().length
    expect(ops.hasClearance(v2Record, now + 1_000)).toMatchObject({ value: true })
    // Satu SELECT pada jalur cepat: `retiredHashes` tidak ditanya kalau versi aktif sudah cocok.
    expect(statementsOf(traceFrom(mark), 'SELECT')).toHaveLength(1)
  })

  it('cincin tanpa versi pensiun tidak bisa membaca record zaman lama (inilah yang ditutup K-3)', async () => {
    const now = 1_700_000_000_000
    const v1Record = await recordOf(retired, SCAN_STATE_KINDS.token, 'fp:abc')
    const noRetired = await recordOf(fresh, SCAN_STATE_KINDS.token, 'fp:abc')

    expect(legacyOps().reserveToken(v1Record, now, TOKEN_RETENTION_MS)).toMatchObject({ value: 'reserved' })
    expect(noRetired.retiredHashes ?? []).toEqual([])
    // Tanpa versi lama di ring, token lama tidak ditemukan: bukti bahwa dual-read adalah penyebab
    // state tetap terbaca, bukan kebetulan.
    expect(currentOps().reserveToken({ ...noRetired, retiredHashes: [v1Record.activeHash] }, now + 1, TOKEN_RETENTION_MS))
      .toMatchObject({ value: 'reused' })
  })
})

describe('VGL-30H K-3: re-key-on-write', () => {
  it('pencacah pindah ke versi aktif dengan data identik dan increment sekali', async () => {
    const now = 1_700_000_000_000
    const old = legacyOps()
    const v1Record = await recordOf(retired, SCAN_STATE_KINDS.counter, 'ip:x')

    old.consumeCounter({ record: v1Record, limit: 5, windowMs: WINDOW_MS, now })
    old.consumeCounter({ record: v1Record, limit: 5, windowMs: WINDOW_MS, now: now + 500 })
    const before = probe.rowFor(SCAN_STATE_KINDS.counter, v1Record.activeHash)!
    expect(before).toMatchObject({ used: 2, window_start: now })

    const v2Record = await recordOf(active, SCAN_STATE_KINDS.counter, 'ip:x')
    const migrating = currentOps()
    // Bootstrap dibuka lebih dulu supaya jejak yang dinilai adalah transaksi migrasi saja:
    // satu operasi keputusan = satu transaksi, dan bootstrap adalah transaksi terpisah.
    migrating.bootstrap()
    const mark = probe.queries().length
    const outcome = migrating.consumeCounter({
      record: v2Record,
      limit: 5,
      windowMs: WINDOW_MS,
      now: now + 1_000,
    })
    const trace = traceFrom(mark)
    const after = probe.rowFor(SCAN_STATE_KINDS.counter, v2Record.activeHash)!

    expect(outcome).toMatchObject({ status: 'ok', value: { allowed: true, used: 3 } })
    // MENYALIN, bukan menghitung ulang: jendela dan expiry asal bertahan utuh.
    expect(after.window_start).toBe(before.window_start)
    expect(after.expires_at).toBe(before.expires_at)
    expect(after.used).toBe(3)
    expect(after.updated_at).toBe(now + 1_000)
    // Baris lama hanya hilang kalau baris baru sudah ada, dan keduanya dalam transaksi yang sama.
    expect(probe.rowFor(SCAN_STATE_KINDS.counter, v1Record.activeHash)).toBeUndefined()
    expect(hashesFor(probe.db, SCAN_STATE_KINDS.counter)).toEqual([v2Record.activeHash])
    expect(trace[0]).toBe('tx:BEGIN')
    expect(trace[trace.length - 1]).toBe('tx:COMMIT')
    expect(trace.indexOf('tx:BEGIN')).toBe(trace.lastIndexOf('tx:BEGIN'))
    const insertAt = trace.findIndex((entry) => entry.startsWith('INSERT OR REPLACE'))
    const deleteAt = trace.findIndex((entry) => entry.startsWith('DELETE'))
    expect(insertAt).toBeGreaterThan(-1)
    expect(deleteAt).toBeGreaterThan(insertAt)
  })

  it('penolakan karena kuota habis tidak memindahkan apa pun', async () => {
    const now = 1_700_000_000_000
    const old = legacyOps()
    const v1Record = await recordOf(retired, SCAN_STATE_KINDS.counter, 'ip:penuh')
    old.consumeCounter({ record: v1Record, limit: 1, windowMs: WINDOW_MS, now })

    const v2Record = await recordOf(active, SCAN_STATE_KINDS.counter, 'ip:penuh')
    const mark = probe.queries().length
    const denied = currentOps().consumeCounter({ record: v2Record, limit: 1, windowMs: WINDOW_MS, now: now + 1 })

    expect(denied).toMatchObject({ status: 'ok', value: { allowed: false, used: 1 } })
    expect(traceFrom(mark).filter((entry) => /^(INSERT|DELETE)/.test(entry))).toEqual([])
    expect(hashesFor(probe.db, SCAN_STATE_KINDS.counter)).toEqual([v1Record.activeHash])
    if (denied.status === 'ok') expect(denied.value.retryAfterSeconds).toBeGreaterThan(0)
  })

  it('izin baru memindahkan record lama dan hanya versi aktif yang tersisa', async () => {
    const now = 1_700_000_000_000
    const v1Record = await recordOf(retired, SCAN_STATE_KINDS.clearance, 'ip:izin')
    legacyOps().issueClearance(v1Record, now, CLEARANCE_TTL_MS)

    const v2Record = await recordOf(active, SCAN_STATE_KINDS.clearance, 'ip:izin')
    expect(currentOps().issueClearance(v2Record, now + 1_000, CLEARANCE_TTL_MS)).toMatchObject({ value: true })

    expect(hashesFor(probe.db, SCAN_STATE_KINDS.clearance)).toEqual([v2Record.activeHash])
    expect(probe.rowFor(SCAN_STATE_KINDS.clearance, v2Record.activeHash)).toMatchObject({
      expires_at: now + 1_000 + CLEARANCE_TTL_MS,
    })
  })

  it('token: anti-replay bertahan lintas versi dan masa pakainya TIDAK memanjang', async () => {
    const now = 1_700_000_000_000
    const v1Record = await recordOf(retired, SCAN_STATE_KINDS.token, 'fp:abc')
    expect(legacyOps().reserveToken(v1Record, now, TOKEN_RETENTION_MS)).toMatchObject({ value: 'reserved' })
    const seeded = probe.rowFor(SCAN_STATE_KINDS.token, v1Record.activeHash)!

    const v2Record = await recordOf(active, SCAN_STATE_KINDS.token, 'fp:abc')
    const outcome = currentOps().reserveToken(v2Record, now + 10_000, TOKEN_RETENTION_MS)
    const moved = probe.rowFor(SCAN_STATE_KINDS.token, v2Record.activeHash)!

    expect(outcome).toMatchObject({ status: 'ok', value: 'reused' })
    // Batas anti-replay tidak boleh diperpanjang oleh rotasi kunci.
    expect(moved.expires_at).toBe(seeded.expires_at)
    expect(moved.updated_at).toBe(seeded.updated_at)
    expect(hashesFor(probe.db, SCAN_STATE_KINDS.token)).toEqual([v2Record.activeHash])
  })

  it('token versi lama yang sudah mati dibuang, bukan dipindah', async () => {
    const now = 1_700_000_000_000
    const v1Record = await recordOf(retired, SCAN_STATE_KINDS.token, 'fp:mati')
    legacyOps().reserveToken(v1Record, now, 1_000)

    const v2Record = await recordOf(active, SCAN_STATE_KINDS.token, 'fp:mati')
    expect(currentOps().reserveToken(v2Record, now + 5_000, TOKEN_RETENTION_MS)).toMatchObject({
      value: 'reserved',
    })
    expect(hashesFor(probe.db, SCAN_STATE_KINDS.token)).toEqual([v2Record.activeHash])
    expect(probe.rowFor(SCAN_STATE_KINDS.token, v2Record.activeHash)).toMatchObject({
      expires_at: now + 5_000 + TOKEN_RETENTION_MS,
    })
  })

  it('pelepasan token membersihkan kedua versi', async () => {
    const now = 1_700_000_000_000
    const v1Record = await recordOf(retired, SCAN_STATE_KINDS.token, 'fp:ganda')
    const v2Record = await recordOf(active, SCAN_STATE_KINDS.token, 'fp:ganda')

    legacyOps().reserveToken(v1Record, now, TOKEN_RETENTION_MS)
    currentOps().reserveToken({ ...v2Record, retiredHashes: [] }, now + 1, TOKEN_RETENTION_MS)
    expect(hashesFor(probe.db, SCAN_STATE_KINDS.token).sort()).toEqual([v1Record.activeHash, v2Record.activeHash].sort())

    expect(currentOps().releaseToken(v2Record)).toMatchObject({ status: 'ok' })
    expect(hashesFor(probe.db, SCAN_STATE_KINDS.token)).toEqual([])
  })

  it('label versi masuk ke catatan, materi kunci tidak pernah', async () => {
    const v2Record = await recordOf(active, SCAN_STATE_KINDS.counter, 'ip:catatan')
    currentOps().consumeCounter({ record: v2Record, limit: 2, windowMs: WINDOW_MS, now: Date.now() })

    const events = readScanStateEvents().filter((event) => event.event === 'durable_read')
    expect(events.at(-1)).toMatchObject({ op: SCAN_STATE_KINDS.counter, kv: 'v2' })
  })
})

describe('VGL-30H K-3: atomicity dan concurrency', () => {
  it('gagal saat menghapus baris lama me-rollback seluruh migrasi', async () => {
    const now = 1_700_000_000_000
    const v1Record = await recordOf(retired, SCAN_STATE_KINDS.counter, 'ip:rollback')
    legacyOps().consumeCounter({ record: v1Record, limit: 5, windowMs: WINDOW_MS, now })
    const seeded = probe.rowFor(SCAN_STATE_KINDS.counter, v1Record.activeHash)!

    const v2Record = await recordOf(active, SCAN_STATE_KINDS.counter, 'ip:rollback')
    probe.failNextMatching('DELETE FROM', 'hapus baris lama gagal')
    const outcome = currentOps().consumeCounter({ record: v2Record, limit: 5, windowMs: WINDOW_MS, now: now + 1 })

    expect(outcome).toEqual({ status: 'error', code: 'storage_unavailable' })
    // Baris baru tidak boleh tersisa kalau baris lama belum terhapus: yang tersisa persis seperti
    // sebelum permintaan ini.
    expect(probe.rowFor(SCAN_STATE_KINDS.counter, v2Record.activeHash)).toBeUndefined()
    expect(probe.rowFor(SCAN_STATE_KINDS.counter, v1Record.activeHash)).toMatchObject(seeded)
    expect(traceFrom(0)).toContain('tx:ROLLBACK')
    expect(readScanStateEvents().some((event) => event.event === 'durable_error')).toBe(true)
  })

  it('gagal saat menulis baris baru me-rollback tanpa menyentuh baris lama', async () => {
    const now = 1_700_000_000_000
    const v1Record = await recordOf(retired, SCAN_STATE_KINDS.counter, 'ip:insert-gagal')
    legacyOps().consumeCounter({ record: v1Record, limit: 5, windowMs: WINDOW_MS, now })

    const v2Record = await recordOf(active, SCAN_STATE_KINDS.counter, 'ip:insert-gagal')
    probe.failNextMatching('INSERT OR REPLACE', 'tulis gagal')
    expect(currentOps().consumeCounter({ record: v2Record, limit: 5, windowMs: WINDOW_MS, now: now + 1 })).toEqual({
      status: 'error',
      code: 'storage_unavailable',
    })

    expect(hashesFor(probe.db, SCAN_STATE_KINDS.counter)).toEqual([v1Record.activeHash])
    expect(probe.rowFor(SCAN_STATE_KINDS.counter, v1Record.activeHash)).toMatchObject({ used: 1 })
  })

  it('dua instance actor pada satu penyimpanan: permintaan selang-seling tidak kehilangan kuota', async () => {
    const v1Record = await recordOf(retired, SCAN_STATE_KINDS.counter, 'ip:serentak')
    legacyOps().consumeCounter({ record: v1Record, limit: 10, windowMs: WINDOW_MS, now: 1_700_000_000_000 })

    const v2Record = await recordOf(active, SCAN_STATE_KINDS.counter, 'ip:serentak')
    const left = currentOps()
    const right = currentOps()
    const facades = [left, right] as const

    const outcomes = Array.from({ length: 11 }, (_, index) =>
      facades[index % 2]!.consumeCounter({
        record: v2Record as DurableKeyRecord,
        limit: 10,
        windowMs: WINDOW_MS,
        now: 1_700_000_000_000 + index + 1,
      }),
    )

    const allowed = outcomes.filter((entry) => entry.status === 'ok' && entry.value.allowed)
    expect(allowed).toHaveLength(9)
    expect(
      allowed.map((entry) => (entry.status === 'ok' ? entry.value.used ?? -1 : -1)).sort((a, b) => a - b),
    ).toEqual([
      2, 3, 4, 5, 6, 7, 8, 9, 10,
    ])
    // Tidak ada duplikasi: hanya satu baris, di versi aktif.
    expect(hashesFor(probe.db, SCAN_STATE_KINDS.counter)).toEqual([v2Record.activeHash])
    expect(probe.rowFor(SCAN_STATE_KINDS.counter, v2Record.activeHash)).toMatchObject({ used: 10 })
  })

  it('permintaan serentak pada identitas BARU tetap menghormati batas kapasitas', async () => {
    const small = createDurableStateOps({
      storage: probe.storage,
      identity: identity('instance-kecil'),
      maxKeys: 2,
    })
    const now = 1_700_000_000_000

    for (const name of ['ip:a', 'ip:b']) {
      const record = await recordOf(active, SCAN_STATE_KINDS.counter, name)
      expect(small.consumeCounter({ record, limit: 1, windowMs: WINDOW_MS, now })).toMatchObject({
        value: { allowed: true },
      })
    }
    const extra = await recordOf(active, SCAN_STATE_KINDS.counter, 'ip:c')
    expect(small.consumeCounter({ record: extra, limit: 1, windowMs: WINDOW_MS, now })).toMatchObject({
      value: { allowed: false },
    })
    expect(hashesFor(probe.db, SCAN_STATE_KINDS.counter)).toHaveLength(2)
  })

  it('setiap operasi mengembalikan nilai sinkron: satu transaksi, tanpa await di dalamnya', async () => {
    const v2Record = await recordOf(active, SCAN_STATE_KINDS.counter, 'ip:sinkron')
    const ops = currentOps()

    const counter = ops.consumeCounter({ record: v2Record, limit: 5, windowMs: WINDOW_MS, now: Date.now() })
    expect(counter).not.toBeInstanceOf(Promise)

    const mark = probe.queries().length
    const clearanceRecord = await recordOf(active, SCAN_STATE_KINDS.clearance, 'ip:sinkron')
    ops.issueClearance(clearanceRecord, Date.now(), CLEARANCE_TTL_MS)
    const trace = traceFrom(mark)

    expect(trace.filter((entry) => entry === 'tx:BEGIN')).toHaveLength(1)
    expect(trace.filter((entry) => entry === 'tx:COMMIT')).toHaveLength(1)
    // Tidak ada BEGIN di dalam BEGIN: fixture SQLite akan menolak transaksi bersarang, dan kode
    // produksi tidak pernah membuka yang kedua.
    expect(trace.indexOf('tx:BEGIN')).toBeLessThan(trace.indexOf('tx:COMMIT'))
  })
})

describe('VGL-30H K-3: sensus versi untuk kebijakan retensi', () => {
  it('menghitung baris per label, baris non-aktif, dan baris yang bentuknya asing', async () => {
    const now = 1_700_000_000_000
    const v1 = await recordOf(retired, SCAN_STATE_KINDS.counter, 'ip:s1')
    const v1Other = await recordOf(retired, SCAN_STATE_KINDS.counter, 'ip:s2')
    // Identitas baru di versi aktif: sensus dinilai di atas keadaan yang benar-benar tersusun,
    // jadi tidak boleh ada migrasi yang diam-diam memindahkan baris 'ip:s1'.
    const v2 = await recordOf(active, SCAN_STATE_KINDS.counter, 'ip:s3')

    legacyOps().consumeCounter({ record: v1, limit: 5, windowMs: WINDOW_MS, now })
    legacyOps().consumeCounter({ record: v1Other, limit: 5, windowMs: WINDOW_MS, now })
    currentOps().consumeCounter({ record: v2, limit: 5, windowMs: WINDOW_MS, now })

    probe.db
      .prepare(
        `INSERT INTO vgl_state (kind, key_hash, used, window_start, expires_at, updated_at)
         VALUES (?, ?, 1, ?, ?, ?)`,
      )
      .run(SCAN_STATE_KINDS.counter, 'b'.repeat(64), now, now + WINDOW_MS, now)
    probe.db
      .prepare(
        `INSERT INTO vgl_state (kind, key_hash, used, window_start, expires_at, updated_at)
         VALUES (?, ?, 1, ?, ?, ?)`,
      )
      .run(SCAN_STATE_KINDS.counter, 'bukan-hash', now, now + WINDOW_MS, now)

    const census = currentOps().inventoryKeyVersions('v2')
    expect(census.status).toBe('ok')
    if (census.status !== 'ok') throw new Error('sensus gagal')

    expect(census.value.rowsByLabel).toEqual({ v1: 2, v2: 1, legacy: 1 })
    expect(census.value.nonActiveRows).toBe(3)
    expect(census.value.malformedRows).toBe(1)

    // Sensus mengikuti re-key-on-write: satu baris v1 yang dipindah pindah label, bukan hilang.
    const migrated = await recordOf(active, SCAN_STATE_KINDS.counter, 'ip:s1')
    currentOps().consumeCounter({ record: migrated, limit: 5, windowMs: WINDOW_MS, now: now + 1_000 })
    const sesudah = currentOps().inventoryKeyVersions('v2')
    if (sesudah.status !== 'ok') throw new Error('sensus kedua gagal')
    expect(sesudah.value.rowsByLabel).toEqual({ v1: 1, v2: 2, legacy: 1 })
    expect(sesudah.value.nonActiveRows).toBe(2)
    expect(sesudah.value.malformedRows).toBe(1)
  })

  it('sensus tidak menyentuh penanda internal sapuan', () => {
    const ops = currentOps()
    ops.bootstrap()
    probe.db
      .prepare(
        `INSERT INTO vgl_state (kind, key_hash, used, window_start, expires_at, updated_at)
         VALUES ('meta', 'sweep', 1, NULL, NULL, ?)`,
      )
      .run(Date.now())

    const census = ops.inventoryKeyVersions('v2')
    expect(census.status).toBe('ok')
    if (census.status !== 'ok') throw new Error('sensus gagal')
    expect(census.value.malformedRows).toBe(0)
    expect(census.value.rowsByLabel).toEqual({})
  })
})

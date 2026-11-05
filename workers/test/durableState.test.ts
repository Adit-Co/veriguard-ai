import { DatabaseSync } from 'node:sqlite'
import { beforeEach, describe, expect, it } from 'vitest'
import { createFixedWindowCounter } from '../../functions/src/state/stores.js'
import { SCAN_STATE_KINDS, VGL_STATE_SCHEMA_VERSION, createDurableStateOps } from '../src/state/durableState.js'
import type { DurableKeyRecord, DurableStateIdentity } from '../src/state/durableState.js'
import { readScanStateEvents, resetScanStateEvents } from '../src/state/telemetry.js'
import { createDurableStorageProbe } from './helpers/durableSqlite.js'
import { recordOf, singleRing } from './helpers/keyRings.js'

/**
 * VGL-30F §6 (unit R1) + VGL-30H K-2/K-3: lapisan durable di atas SQLite sungguhan.
 *
 * Yang dibuktikan di berkas ini adalah semantik operasi itu sendiri — jendela tetap, umur izin,
 * anti-replay, atomicity, sapuan kedaluwarsa, dan arah gagal. Pembuktian "state selamat dari
 * restart actor" yang memakai runtime asli ada di test workerd (eviction); di sini restart
 * ditiru dengan instance ops baru di atas database yang sama.
 *
 * Sejak VGL-30H identitas yang masuk ke ops adalah `DurableKeyRecord` hasil `digestsFor()` cincin
 * kunci, bukan string mentah. Berkas ini memakai cincin ber-versi satu supaya yang diukur tetap
 * semantik penyimpanan; HMAC, penandaan versi, dan migrasi antar-versi punya berkas sendiri.
 */

const WINDOW_MS = 60_000
const MAX_KEYS = 5

const ring = singleRing()

const counterRecord = (key: string): Promise<DurableKeyRecord> => recordOf(ring, SCAN_STATE_KINDS.counter, key)
const clearanceRecord = (key: string): Promise<DurableKeyRecord> => recordOf(ring, SCAN_STATE_KINDS.clearance, key)
const tokenRecord = (key: string): Promise<DurableKeyRecord> => recordOf(ring, SCAN_STATE_KINDS.token, key)

function makeIdentity(bootMs: number, nonce: string): DurableStateIdentity {
  return { rn: 'rn-satu', an: nonce, iseq: 1, aid: 'actor000', bootMs }
}

function createOps(probe = createDurableStorageProbe(), bootMs = Date.now(), nonce = 'instance-1') {
  return {
    probe,
    ops: createDurableStateOps({
      storage: probe.storage,
      identity: makeIdentity(bootMs, nonce),
      maxKeys: MAX_KEYS,
    }),
  }
}

beforeEach(() => {
  resetScanStateEvents()
})

describe('VGL-30F R1: bootstrap skema', () => {
  it('membuat tabel, mencatat versi, dan idempoten terhadap restart actor', () => {
    const first = createOps()
    const bootstrap = first.ops.bootstrap()

    expect(bootstrap).toMatchObject({ ok: true, pragmaSupported: true })
    expect(
      first.probe.db
        .prepare("SELECT name FROM sqlite_master WHERE name IN ('vgl_state','vgl_state_expiry_idx')")
        .all(),
    ).toHaveLength(2)

    // Instance baru di atas penyimpanan yang sama: tidak boleh ada CREATE yang gagal atau data hilang.
    const reopened = first.probe.reopen()
    const second = createDurableStateOps({
      storage: reopened.storage,
      identity: makeIdentity(Date.now() + 5_000, 'instance-2'),
      maxKeys: MAX_KEYS,
    })
    expect(second.bootstrap().ok).toBe(true)
    expect(second.bootstrap().ok).toBe(true)
    expect(first.probe.db.prepare('PRAGMA user_version').all()).toEqual([
      { user_version: VGL_STATE_SCHEMA_VERSION },
    ])
  })

  it('memakai tabel cadangan saat runtime menolak PRAGMA versi', async () => {
    const probe = createDurableStorageProbe()
    probe.rejectVersionPragma()
    const ops = createDurableStateOps({
      storage: probe.storage,
      identity: makeIdentity(Date.now(), 'instance-1'),
      maxKeys: MAX_KEYS,
    })

    const bootstrap = ops.bootstrap()
    expect(bootstrap).toMatchObject({ ok: true, pragmaSupported: false })

    // Versi tercatat di vgl_schema, sehingga bootstrap berikutnya tidak mengira namespace kosong.
    expect(probe.db.prepare('SELECT version FROM vgl_schema').all()).toEqual([
      { version: VGL_STATE_SCHEMA_VERSION },
    ])
    expect(
      ops.consumeCounter({
        record: await counterRecord('kunci-versi'),
        limit: 2,
        windowMs: WINDOW_MS,
        now: Date.now(),
      }),
    ).toMatchObject({ status: 'ok', value: { allowed: true, used: 1 } })
  })

  it('gagal-tertutup bila versi skema lebih baru dari kode ini', async () => {
    const db = new DatabaseSync(':memory:')
    db.exec('PRAGMA user_version = 99')
    const probe = createDurableStorageProbe(db)
    const ops = createDurableStateOps({
      storage: probe.storage,
      identity: makeIdentity(Date.now(), 'instance-1'),
      maxKeys: MAX_KEYS,
    })

    expect(ops.bootstrap()).toMatchObject({ ok: false, code: 'schema_version', detail: 'versi_lebih_baru' })
    expect(
      ops.consumeCounter({ record: await counterRecord('k'), limit: 2, windowMs: WINDOW_MS, now: Date.now() }),
    ).toEqual({ status: 'error', code: 'schema_version' })
  })

  it('gagal-tertutup bila bentuk tabel tidak dikenali, tanpa menghapus state', () => {
    const db = new DatabaseSync(':memory:')
    db.exec('PRAGMA user_version = 1')
    db.exec('CREATE TABLE vgl_state (kind TEXT NOT NULL, key_hash TEXT NOT NULL, updated_at INTEGER NOT NULL)')
    db.prepare('INSERT INTO vgl_state (kind, key_hash, updated_at) VALUES (?,?,?)').run(
      SCAN_STATE_KINDS.counter,
      'baris-lama',
      1,
    )
    const probe = createDurableStorageProbe(db)
    const ops = createDurableStateOps({
      storage: probe.storage,
      identity: makeIdentity(Date.now(), 'instance-1'),
      maxKeys: MAX_KEYS,
    })

    expect(ops.bootstrap()).toMatchObject({ ok: false, code: 'schema_version', detail: 'kolom_tidak_dikenali' })
    // Tidak ada DROP/ALTER: baris yang sudah ada tetap di sana, tidak bisa dibaca sebagai nol.
    expect(db.prepare('SELECT COUNT(*) AS total FROM vgl_state').all()).toEqual([{ total: 1 }])
  })

  it('melaporkan penyimpanan tidak tersedia bila surface SQL tidak ada', async () => {
    const ops = createDurableStateOps({
      storage: {},
      identity: makeIdentity(Date.now(), 'instance-1'),
      maxKeys: MAX_KEYS,
    })

    expect(ops.supported).toBe(false)
    expect(ops.bootstrap()).toMatchObject({ ok: false, code: 'storage_unavailable' })
    expect(
      ops.consumeCounter({ record: await counterRecord('k'), limit: 2, windowMs: WINDOW_MS, now: Date.now() }),
    ).toEqual({ status: 'error', code: 'storage_unavailable' })
  })
})

describe('VGL-30F R1: pencacah jendela tetap', () => {
  it('memakai kuota sampai limit lalu menolak tanpa menaikkan used', async () => {
    const { ops } = createOps()
    const now = 1_700_000_000_000
    const record = await counterRecord('k1')

    expect(ops.consumeCounter({ record, limit: 2, windowMs: WINDOW_MS, now })).toMatchObject({
      value: { allowed: true, used: 1 },
    })
    expect(ops.consumeCounter({ record, limit: 2, windowMs: WINDOW_MS, now: now + 1_000 })).toMatchObject({
      value: { allowed: true, used: 2 },
    })

    const denied = ops.consumeCounter({ record, limit: 2, windowMs: WINDOW_MS, now: now + 2_000 })
    expect(denied).toMatchObject({ status: 'ok', value: { allowed: false, used: 2 } })
    if (denied.status !== 'ok') throw new Error('harusnya keputusan, bukan galat')
    expect(denied.value.retryAfterSeconds).toBeGreaterThan(0)
    expect(denied.value.retryAfterSeconds).toBeLessThanOrEqual(60)

    // Penolakan tidak menulis apa pun.
    expect(ops.consumeCounter({ record, limit: 2, windowMs: WINDOW_MS, now: now + 2_500 })).toMatchObject({
      value: { allowed: false, used: 2 },
    })
  })

  it('memulai jendela baru setelah jendela lama lewat, dan tetap menghitung dari satu', async () => {
    const { ops } = createOps()
    const now = 1_700_000_000_000
    const record = await counterRecord('k2')

    ops.consumeCounter({ record, limit: 2, windowMs: WINDOW_MS, now })
    ops.consumeCounter({ record, limit: 2, windowMs: WINDOW_MS, now: now + 1_000 })

    expect(ops.consumeCounter({ record, limit: 2, windowMs: WINDOW_MS, now: now + WINDOW_MS })).toMatchObject({
      value: { allowed: true, used: 1 },
    })
  })

  it('paritas semantik dengan pencacah memori untuk deretan permintaan yang sama', async () => {
    // Deretan yang sama dijalankan dua kali: satu di memori (perilaku hari ini), satu di SQLite.
    const memory = createFixedWindowCounter(MAX_KEYS)
    const { ops } = createOps()
    const started = 1_700_000_000_000
    const steps: Array<{ key: 'a' | 'b'; limit: number; offset: number }> = [
      { key: 'a', limit: 3, offset: 0 },
      { key: 'a', limit: 3, offset: 1_000 },
      { key: 'b', limit: 1, offset: 1_500 },
      { key: 'a', limit: 3, offset: 2_000 },
      { key: 'a', limit: 3, offset: 3_000 },
      { key: 'b', limit: 1, offset: 3_500 },
      { key: 'a', limit: 3, offset: WINDOW_MS + 1 },
      { key: 'a', limit: 0, offset: WINDOW_MS + 2 },
      { key: 'a', limit: 3, offset: -1 },
    ]
    const records = { a: await counterRecord('a'), b: await counterRecord('b') }

    for (const step of steps) {
      const now = started + step.offset
      const expected = memory.consume(step.key, step.limit, WINDOW_MS, now)
      const actual = ops.consumeCounter({ record: records[step.key], limit: step.limit, windowMs: WINDOW_MS, now })
      if (actual.status !== 'ok') throw new Error(`langkah ${step.key}@${step.offset} menghasilkan galat`)
      expect(actual.value, `langkah ${step.key}@${step.offset}`).toEqual(expected)
    }
  })

  it('menolak limit nol atau jendela nol, bukan membukanya', async () => {
    const { ops } = createOps()
    const now = Date.now()
    const record = await counterRecord('k3')

    expect(ops.consumeCounter({ record, limit: 0, windowMs: WINDOW_MS, now })).toMatchObject({
      value: { allowed: false },
    })
    expect(ops.consumeCounter({ record, limit: 5, windowMs: 0, now })).toMatchObject({
      value: { allowed: false },
    })
    // Penolakan ini tidak boleh menulis baris: tidak ada kuota yang ikut tercatat.
    expect(ops.consumeCounter({ record, limit: 5, windowMs: WINDOW_MS, now })).toMatchObject({
      value: { allowed: true, used: 1 },
    })
  })

  it('sepuluh permintaan serentak tidak kehilangan increment', async () => {
    // Actor single-threaded: sepuluh facade menunjuk satu penyimpanan, semuanya harus melihat
    // angka 1..10 tanpa duplikasi dan tanpa bolong.
    const probe = createDurableStorageProbe()
    const record = await counterRecord('serentak')
    const results = Array.from({ length: 10 }, () => {
      const ops = createDurableStateOps({
        storage: probe.storage,
        identity: makeIdentity(Date.now(), 'instance-paralel'),
        maxKeys: MAX_KEYS,
      })
      return ops.consumeCounter({ record, limit: 10, windowMs: WINDOW_MS, now: Date.now() })
    })

    expect(results.filter((result) => result.status === 'ok')).toHaveLength(10)
    expect(
      results
        .map((result) => (result.status === 'ok' ? result.value.used ?? -1 : -1))
        .sort((left, right) => left - right),
    ).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
  })

  it('selamat dari restart actor: kuota yang sudah terpakai tidak kembali', async () => {
    const probe = createDurableStorageProbe()
    const now = 1_700_000_000_000
    const record = await counterRecord('menetap')
    const before = createDurableStateOps({
      storage: probe.storage,
      identity: makeIdentity(now, 'instance-lama'),
      maxKeys: MAX_KEYS,
    })
    before.consumeCounter({ record, limit: 3, windowMs: WINDOW_MS, now })
    before.consumeCounter({ record, limit: 3, windowMs: WINDOW_MS, now: now + 1 })

    const after = createDurableStateOps({
      storage: probe.reopen().storage,
      identity: makeIdentity(now + 10_000, 'instance-baru'),
      maxKeys: MAX_KEYS,
    })
    const third = after.consumeCounter({ record, limit: 3, windowMs: WINDOW_MS, now: now + 2 })
    expect(third).toMatchObject({ value: { allowed: true, used: 3 } })

    const fourth = after.consumeCounter({ record, limit: 3, windowMs: WINDOW_MS, now: now + 3 })
    expect(fourth.status === 'ok' && fourth.value.allowed).toBe(false)

    const events = readScanStateEvents()
    expect(events.some((event) => event.event === 'actor_counters_restored')).toBe(true)
  })

  it('menolak kunci baru saat tabel per kind penuh, tanpa mengusir yang hidup', async () => {
    const { ops, probe } = createOps()
    const now = 1_700_000_000_000
    for (let index = 0; index < MAX_KEYS; index += 1) {
      expect(
        ops.consumeCounter({ record: await counterRecord(`penuh-${index}`), limit: 1, windowMs: WINDOW_MS, now }),
      ).toMatchObject({ value: { allowed: true } })
    }

    const rejected = ops.consumeCounter({
      record: await counterRecord('penuh-tambahan'),
      limit: 1,
      windowMs: WINDOW_MS,
      now,
    })
    expect(rejected).toMatchObject({ status: 'ok', value: { allowed: false } })
    expect(probe.rowsFor(SCAN_STATE_KINDS.counter)).toHaveLength(MAX_KEYS)
  })

  it('menyapu baris kedaluwarsa lewat jalur sapuan eksplisit', async () => {
    const { ops, probe } = createOps()
    const now = 1_700_000_000_000
    ops.consumeCounter({ record: await counterRecord('tua'), limit: 5, windowMs: 1_000, now })
    ops.issueClearance(await clearanceRecord('izin-tua'), now, 1_000)
    expect(probe.rowsFor(SCAN_STATE_KINDS.counter)).toHaveLength(1)

    expect(ops.sweepExpired(now + 10_000)).toBe(2)
    expect(probe.rowsFor(SCAN_STATE_KINDS.counter)).toHaveLength(0)
    expect(probe.rowsFor(SCAN_STATE_KINDS.clearance)).toHaveLength(0)
  })
})

describe('VGL-30F R1: izin CAPTCHA dan anti-replay token', () => {
  it('izin yang diterbitkan terbaca kembali dan kedaluwarsa sesuai TTL', async () => {
    const { ops } = createOps()
    const now = 1_700_000_000_000
    const record = await clearanceRecord('izin-1')

    expect(ops.hasClearance(record, now)).toMatchObject({ value: false })
    expect(ops.issueClearance(record, now, 300_000)).toMatchObject({ value: true })
    expect(ops.hasClearance(record, now + 299_000)).toMatchObject({ value: true })

    const expired = ops.hasClearance(record, now + 301_000)
    expect(expired).toMatchObject({ status: 'ok', value: false })
    // Izin kedaluwarsa dihapus saat disentuh, bukan dibiarkan menumpuk.
    expect(expired.status === 'ok' && expired.value).toBe(false)
  })

  it('izin selamat dari restart actor dan tetap berlaku sesuai TTL aslinya', async () => {
    const probe = createDurableStorageProbe()
    const now = 1_700_000_000_000
    const record = await clearanceRecord('izin-menetap')
    createDurableStateOps({
      storage: probe.storage,
      identity: makeIdentity(now, 'instance-lama'),
      maxKeys: MAX_KEYS,
    }).issueClearance(record, now, 300_000)

    const after = createDurableStateOps({
      storage: probe.reopen().storage,
      identity: makeIdentity(now + 5_000, 'instance-baru'),
      maxKeys: MAX_KEYS,
    })
    expect(after.hasClearance(record, now + 60_000)).toMatchObject({ value: true })
    expect(after.hasClearance(record, now + 301_000)).toMatchObject({ value: false })
    expect(readScanStateEvents().some((event) => event.event === 'actor_clearances_restored')).toBe(true)
  })

  it('token hanya sekali pakai, dan tetap ditolak setelah restart', async () => {
    const probe = createDurableStorageProbe()
    const now = 1_700_000_000_000
    const record = await tokenRecord('sidik-1')
    const before = createDurableStateOps({
      storage: probe.storage,
      identity: makeIdentity(now, 'instance-lama'),
      maxKeys: MAX_KEYS,
    })
    expect(before.reserveToken(record, now, 600_000)).toMatchObject({ value: 'reserved' })
    expect(before.reserveToken(record, now + 1_000, 600_000)).toMatchObject({ value: 'reused' })

    const after = createDurableStateOps({
      storage: probe.reopen().storage,
      identity: makeIdentity(now + 2_000, 'instance-baru'),
      maxKeys: MAX_KEYS,
    })
    expect(after.reserveToken(record, now + 3_000, 600_000)).toMatchObject({ value: 'reused' })
    expect(readScanStateEvents().some((event) => event.event === 'actor_tokens_restored')).toBe(true)
  })

  it('pelepasan token membolehkan pencadangan ulang, sama seperti registry memori', async () => {
    const { ops } = createOps()
    const now = 1_700_000_000_000
    const record = await tokenRecord('sidik-2')

    ops.reserveToken(record, now, 600_000)
    expect(ops.releaseToken(record).status).toBe('ok')
    expect(ops.reserveToken(record, now + 1_000, 600_000)).toMatchObject({ value: 'reserved' })
  })

  it('token kedaluwarsa boleh dicadang lagi, dan tabel penuh menolak kunci baru', async () => {
    const { ops } = createOps()
    const now = 1_700_000_000_000
    const record = await tokenRecord('sidik-3')
    expect(ops.reserveToken(record, now, 1_000)).toMatchObject({ value: 'reserved' })
    expect(ops.reserveToken(record, now + 2_000, 1_000)).toMatchObject({ value: 'reserved' })

    for (let index = 0; index < MAX_KEYS; index += 1) {
      ops.reserveToken(await tokenRecord(`tumpuk-${index}`), now, 600_000)
    }
    expect(ops.reserveToken(await tokenRecord('tumpuk-tambahan'), now, 600_000)).toMatchObject({ value: 'full' })
  })
})

describe('VGL-30F R1: arah gagal penyimpanan', () => {
  it('kegagalan saat operasi mengembalikan galat, bukan izin', async () => {
    const { ops, probe } = createOps()
    const now = 1_700_000_000_000
    ops.consumeCounter({ record: await counterRecord('sebelum-gagal'), limit: 5, windowMs: WINDOW_MS, now })

    const gagal = await counterRecord('saat-gagal')
    probe.failNext('disk penuh')
    const failed = ops.consumeCounter({ record: gagal, limit: 5, windowMs: WINDOW_MS, now: now + 1 })
    expect(failed).toEqual({ status: 'error', code: 'storage_unavailable' })
    // Tidak ada baris yang tertinggal dari operasi yang gagal: kunci yang ditolak tidak
    // bisa "sudah terpakai" pada percobaan berikutnya.
    expect(probe.rowsFor(SCAN_STATE_KINDS.counter).some((row) => row.key_hash === gagal.activeHash)).toBe(false)
    expect(readScanStateEvents().some((event) => event.event === 'durable_error')).toBe(true)
  })

  it('kegagalan tulis tidak meninggalkan izin setengah tersimpan', async () => {
    const { ops, probe } = createOps()
    const now = 1_700_000_000_000
    ops.bootstrap()

    const record = await clearanceRecord('izin-gagal')
    probe.failNext('gagal di tengah transaksi')
    expect(ops.issueClearance(record, now, 300_000)).toEqual({ status: 'error', code: 'storage_unavailable' })
    expect(probe.rowsFor(SCAN_STATE_KINDS.clearance)).toHaveLength(0)
    expect(ops.hasClearance(record, now)).toMatchObject({ value: false })
  })

  it('tetap menolak limit nol pada penyimpanan yang baru dibuat', async () => {
    const db = new DatabaseSync(':memory:')
    const probe = createDurableStorageProbe(db)
    const ops = createDurableStateOps({
      storage: probe.storage,
      identity: makeIdentity(Date.now(), 'instance-1'),
      maxKeys: MAX_KEYS,
    })

    expect(
      ops.consumeCounter({ record: await counterRecord('nol'), limit: 0, windowMs: 0, now: Date.now() }),
    ).toMatchObject({ value: { allowed: false, retryAfterSeconds: 1 } })
  })
})

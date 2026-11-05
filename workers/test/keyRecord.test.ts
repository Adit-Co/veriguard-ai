import { DatabaseSync } from 'node:sqlite'
import { beforeEach, describe, expect, it } from 'vitest'
import {
  LEGACY_LABEL,
  encodeVersionedKeyHash,
  isUsableKeyHash,
  keyHashLabel,
  parseKeyRecord,
} from '../src/state/stateKeys.js'
import { SCAN_STATE_KINDS, VGL_STATE_TABLE, createDurableStateOps } from '../src/state/durableState.js'
import { resetScanStateEvents } from '../src/state/telemetry.js'
import { createDurableStorageProbe } from './helpers/durableSqlite.js'
import { TEST_LEGACY_SALT, hashesFor, makeRing, recordOf } from './helpers/keyRings.js'

/**
 * VGL-30H K-2: penyandian versi pada identitas record (`v<n>:<digest>`) dan dampaknya pada skema.
 *
 * Bentuk yang dipilih (VGL-30G §2.3 opsi A) menaruh versi di DALAM kolom `key_hash` yang sudah ada,
 * jadi tidak ada ALTER TABLE, tidak ada DROP, dan tidak ada indeks baru. Berkas ini membuktikan dua
 * hal yang berbeda: parser menerima/menolak bentuk dengan benar, dan skema SQLite yang sudah berjalan
 * menampung ketiga bentuk (versi baru, versi lama, legacy) sekaligus.
 */

const HEX64 = 'a'.repeat(64)
const HEX64_B = 'b'.repeat(64)

beforeEach(() => {
  resetScanStateEvents()
})

describe('VGL-30H K-2: pembacaan bentuk key_hash', () => {
  it('v1 dan v2 yang sah terbaca sebagai versi yang tepat', () => {
    expect(parseKeyRecord(encodeVersionedKeyHash('v1', HEX64))).toEqual({
      form: 'versioned',
      label: 'v1',
      digest: HEX64,
    })
    expect(parseKeyRecord(encodeVersionedKeyHash('v2', HEX64_B))).toMatchObject({ form: 'versioned', label: 'v2' })
    expect(keyHashLabel(encodeVersionedKeyHash('v999', HEX64))).toBe('v999')
  })

  it('record tanpa prefiks (pra-VGL-30H) terbaca sebagai legacy, bukan sebagai versi', () => {
    const parsed = parseKeyRecord(HEX64)
    expect(parsed).toEqual({ form: 'legacy', digest: HEX64 })
    expect(keyHashLabel(HEX64)).toBe(LEGACY_LABEL)
    expect(isUsableKeyHash(HEX64)).toBe(true)
  })

  it.each([
    ['x1:hex', 'prefiks bukan v'],
    ['1:hex', 'prefiks tanpa huruf'],
    ['vv1:hex', 'prefiks ganda'],
    ['V1:hex', 'huruf besar pada prefiks'],
    [':hex', 'prefiks kosong'],
  ])('prefiks tidak valid (%s) ditolak', (value) => {
    expect(parseKeyRecord(value)).toEqual({ form: 'invalid', reason: 'malformed_prefix' })
    expect(isUsableKeyHash(value)).toBe(false)
    expect(keyHashLabel(value)).toBeNull()
  })

  it.each([
    ['v1:' + 'z'.repeat(64), 'bukan heksadesimal'],
    ['v1:' + HEX64.slice(0, 63), 'kependekan'],
    ['v1:' + HEX64 + '0', 'kepanjangan'],
    ['v1:ABC' + HEX64.slice(3), 'huruf besar pada digest'],
    ['v1:', 'digest kosong'],
  ])('digest tidak valid (%s) ditolak', (value) => {
    expect(parseKeyRecord(value)).toEqual({ form: 'invalid', reason: 'digest_malformed' })
  })

  // `v:` berbentuk seperti versi (huruf v, tanpa angka) jadi yang ditolak adalah ANGKA versinya,
  // bukan bentuk prefiksnya: alasan harus menyebut penyebab yang sebenarnya.
  it.each(['v:hex', 'v0:' + HEX64, 'v1000:' + HEX64, 'v01:' + HEX64])('versi tidak dikenal (%s) ditolak', (value) => {
    expect(parseKeyRecord(value)).toEqual({ form: 'invalid', reason: 'unknown_version' })
    expect(isUsableKeyHash(value)).toBe(false)
  })

  it.each([[''], ['x'], ['a'.repeat(63)], ['a'.repeat(65)], [null], [undefined], [42]])(
    'bentuk asing (%s) tidak pernah dianggap identitas',
    (value) => {
      expect(parseKeyRecord(value).form).toBe('invalid')
      expect(isUsableKeyHash(value)).toBe(false)
    },
  )

  it('round-trip: encode lalu parse tidak mengubah apa pun', () => {
    for (const label of ['v1', 'v7', 'v999']) {
      const encoded = encodeVersionedKeyHash(label, HEX64)
      const parsed = parseKeyRecord(encoded)
      expect(parsed.form).toBe('versioned')
      if (parsed.form === 'versioned') {
        expect(parsed.label).toBe(label)
        expect(parsed.digest).toBe(HEX64)
        expect(`${parsed.label}:${parsed.digest}`).toBe(encoded)
      }
    }
  })
})

describe('VGL-30H K-2: dampak pada skema SQLite yang sudah ada', () => {
  function bootstrapDb(): { db: DatabaseSync; ops: ReturnType<typeof createDurableStateOps> } {
    const probe = createDurableStorageProbe()
    const ops = createDurableStateOps({
      storage: probe.storage,
      identity: { rn: 'rn', an: 'an', iseq: 1, bootMs: Date.now() },
      maxKeys: 100,
    })
    expect(ops.bootstrap().ok).toBe(true)
    return { db: probe.db, ops }
  }

  it('kolom dan indeks tidak berubah: key_hash TEXT bagian dari PRIMARY KEY (kind, key_hash)', () => {
    const { db } = bootstrapDb()

    const columns = db.prepare(`PRAGMA table_info(${VGL_STATE_TABLE})`).all() as Array<{
      name: string
      type: string
      pk: number
    }>
    expect(columns.map((column) => column.name)).toEqual([
      'kind',
      'key_hash',
      'used',
      'window_start',
      'expires_at',
      'updated_at',
    ])
    expect(columns.find((column) => column.name === 'key_hash')).toMatchObject({ type: 'TEXT', pk: 2 })
    expect(columns.some((column) => /check|default/i.test(JSON.stringify(column)))).toBe(false)

    // Nama indeks kunci utama berbeda antar runtime (`primary` di workerd, `sqlite_autoindex_...`
    // di Node), jadi yang dinilai adalah SIFATNYA: tetap satu indeks unik atas (kind, key_hash)
    // plus indeks umur. Tidak ada indeks baru yang perlu dibuat untuk prefiks versi.
    const indexes = db.prepare(`PRAGMA index_list(${VGL_STATE_TABLE})`).all() as Array<{
      name: string
      unique: number
    }>
    expect(indexes).toHaveLength(2)
    expect(indexes.map((index) => index.name).sort()).toContain('vgl_state_expiry_idx')
    const pkIndex = indexes.find((index) => index.name !== 'vgl_state_expiry_idx')
    if (!pkIndex) throw new Error('indeks kunci utama tidak ditemukan')
    expect(pkIndex.unique).toBe(1)
    const pkColumns = db.prepare(`PRAGMA index_info(${pkIndex.name})`).all() as Array<{ name: string }>
    expect(pkColumns.map((column) => column.name)).toEqual(['kind', 'key_hash'])
  })

  it('satu kind menampung versi baru, versi lama, dan legacy sekaligus tanpa tabrakan', () => {
    const { db } = bootstrapDb()
    const insert = db.prepare(
      `INSERT INTO ${VGL_STATE_TABLE} (kind, key_hash, used, window_start, expires_at, updated_at)
       VALUES (?, ?, 1, ?, ?, ?)`,
    )
    const v1 = encodeVersionedKeyHash('v1', HEX64)
    const v2 = encodeVersionedKeyHash('v2', HEX64)

    insert.run(SCAN_STATE_KINDS.counter, v1, 1, 61_000, 1)
    insert.run(SCAN_STATE_KINDS.counter, v2, 1, 61_000, 1)
    insert.run(SCAN_STATE_KINDS.counter, HEX64, 1, 61_000, 1)

    expect(hashesFor(db, SCAN_STATE_KINDS.counter).sort()).toEqual([HEX64, v1, v2].sort())
    // Digest yang sama tidak boleh tercatat dua kali pada versi yang sama: PRIMARY KEY menolaknya.
    expect(() => insert.run(SCAN_STATE_KINDS.counter, v1, 1, 61_000, 1)).toThrow()
  })

  it('indeks kedaluwarsa tetap memotong baris berversi (sapuan tidak buta terhadap prefiks)', () => {
    const { db, ops } = bootstrapDb()
    db.prepare(
      `INSERT INTO ${VGL_STATE_TABLE} (kind, key_hash, used, window_start, expires_at, updated_at)
       VALUES (?, ?, 1, ?, ?, ?)`,
    ).run(SCAN_STATE_KINDS.token, encodeVersionedKeyHash('v1', HEX64), 1, 1_000, 1)

    expect(ops.sweepExpired(2_000)).toBe(1)
    expect(hashesFor(db, SCAN_STATE_KINDS.token)).toEqual([])
  })

  it('jalur tulis menolak digest aktif tanpa prefiks versi: legacy hanya untuk dibaca', async () => {
    const { ops } = bootstrapDb()
    const legacyOnly = { activeHash: HEX64 }

    expect(ops.consumeCounter({ record: legacyOnly, limit: 1, windowMs: 60_000, now: Date.now() })).toEqual({
      status: 'error',
      code: 'storage_unavailable',
    })
    expect(ops.hasClearance({ activeHash: 'bukan-hash' }, Date.now())).toEqual({
      status: 'error',
      code: 'storage_unavailable',
    })
  })

  it('ops tetap mencari hash legacy di daftar pensiun lalu memindahkannya', async () => {
    const { db, ops } = bootstrapDb()
    const legacyRing = makeRing({ active: 'v1', labels: ['v1'], legacySalt: TEST_LEGACY_SALT })
    const now = 1_700_000_000_000

    const digest = await legacyRing.digestsFor(SCAN_STATE_KINDS.counter, 'warisan')
    const legacyHash = digest!.retiredHashes[0]
    expect(legacyHash).toMatch(/^[0-9a-f]{64}$/)

    db.prepare(
      `INSERT INTO ${VGL_STATE_TABLE} (kind, key_hash, used, window_start, expires_at, updated_at)
       VALUES (?, ?, 4, ?, ?, ?)`,
    ).run(SCAN_STATE_KINDS.counter, legacyHash, now, now + 60_000, now)

    const record = await recordOf(legacyRing, SCAN_STATE_KINDS.counter, 'warisan')
    const outcome = ops.consumeCounter({ record, limit: 10, windowMs: 60_000, now: now + 1_000 })

    expect(outcome).toMatchObject({ status: 'ok', value: { allowed: true, used: 5 } })
    // Baris warisan sudah berpindah bentuk: hanya digest berversi yang tertinggal.
    expect(hashesFor(db, SCAN_STATE_KINDS.counter)).toEqual([record.activeHash])
  })
})

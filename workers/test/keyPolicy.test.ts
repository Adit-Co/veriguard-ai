import { describe, expect, it } from 'vitest'
import {
  KEY_EMERGENCY_REPLAY_WINDOW_MS,
  KEY_RETENTION_EMERGENCY_MS,
  KEY_RETENTION_HARD_FLOOR_MS,
  KEY_RETENTION_SCHEDULED_MS,
  describeKeyRingStatus,
  evaluateKeyRetention,
} from '../src/state/keyPolicy.js'
import type { KeyRetentionPolicyInput } from '../src/state/keyPolicy.js'
import { SCAN_STATE_KINDS, createDurableStateOps } from '../src/state/durableState.js'
import { createDurableStorageProbe } from './helpers/durableSqlite.js'
import { makeRing, recordOf, syntheticKey } from './helpers/keyRings.js'

/**
 * VGL-30H K-4: kebijakan retensi kunci lama.
 *
 * Matriks yang diwajibkan brief: rotasi 25 menit ditolak, 26 menit memenuhi lantai keras, 24 jam
 * memenuhi retensi terjadwal, pencabutan darurat mengeluarkan peringatan lubang replay 600 s, kunci
 * yang masih dipakai sebuah record memblokir penghapusan, jam mundur/timestamp tidak valid ditolak,
 * dan tidak ada penghapusan secret otomatis. Jam selalu disuntik, jadi semuanya diuji tanpa menunggu.
 */

const MINUTE = 60_000
const RETIRED_AT = 1_700_000_000_000

function base(input: Partial<KeyRetentionPolicyInput>): KeyRetentionPolicyInput {
  return {
    mode: 'scheduled',
    activeLabel: 'v2',
    candidateLabel: 'v1',
    retiredSinceMs: RETIRED_AT,
    nowMs: RETIRED_AT,
    ...input,
  }
}

describe('VGL-30H K-4: retensi terjadwal dan lantai keras', () => {
  it('lantai keras 26 menit dan retensi terjadwal 24 jam memakai angka yang ditetapkan', () => {
    expect(KEY_RETENTION_HARD_FLOOR_MS).toBe(26 * MINUTE)
    expect(KEY_RETENTION_SCHEDULED_MS).toBe(24 * 60 * MINUTE)
    expect(KEY_RETENTION_EMERGENCY_MS).toBe(0)
    expect(KEY_EMERGENCY_REPLAY_WINDOW_MS).toBe(600_000)
  })

  it('rotasi pada menit ke-25 ditolak: di bawah lantai keras', () => {
    const decision = evaluateKeyRetention(
      base({ retiredSinceMs: RETIRED_AT, nowMs: RETIRED_AT + 25 * MINUTE }),
    )

    expect(decision.removable).toBe(false)
    expect(decision.hardFloorSatisfied).toBe(false)
    expect(decision.blockers).toContain('below_hard_floor')
    expect(decision.blockers).toContain('below_scheduled_retention')
  })

  it('rotasi pada menit ke-26 memenuhi lantai keras, tetapi masih di bawah retensi terjadwal', () => {
    const decision = evaluateKeyRetention(base({ nowMs: RETIRED_AT + 26 * MINUTE }))

    expect(decision.hardFloorSatisfied).toBe(true)
    expect(decision.scheduledRetentionSatisfied).toBe(false)
    expect(decision.blockers).toEqual(['below_scheduled_retention'])
    expect(decision.removable).toBe(false)
  })

  it('rotasi terjadwal setelah 24 jam boleh, tanpa baris yang tersisa', () => {
    const decision = evaluateKeyRetention(base({ nowMs: RETIRED_AT + 24 * 60 * MINUTE, rowsByLabel: { v1: 0 } }))

    expect(decision.blockers).toEqual([])
    expect(decision.warnings).toEqual([])
    expect(decision.removable).toBe(true)
    expect(decision.elapsedMs).toBe(24 * 60 * MINUTE)
  })

  it('batas dapat diset ulang untuk uji, tanpa mengubah angka bawaan', () => {
    const decision = evaluateKeyRetention(
      base({ nowMs: RETIRED_AT + 5 * MINUTE, hardFloorMs: 4 * MINUTE, scheduledRetentionMs: 5 * MINUTE }),
    )
    expect(decision.removable).toBe(true)
    expect(decision.hardFloorSatisfied).toBe(true)
  })
})

describe('VGL-30H K-4: keadaan darurat', () => {
  it('pencabutan darurat saat itu juga, dengan peringatan lubang anti-replay 600 s tertulis', () => {
    const decision = evaluateKeyRetention(base({ mode: 'emergency', nowMs: RETIRED_AT + 1_000 }))

    expect(decision.removable).toBe(true)
    expect(decision.warnings).toContain('emergency_replay_window')
    expect(decision.hardFloorSatisfied).toBe(false)
    expect(decision.instructions.join(' ')).toMatch(/600 s/)
  })

  it('peringatan darurat menyebut konsekuensi yang sebenarnya: token dapat diulang, izin hilang', () => {
    const decision = evaluateKeyRetention(base({ mode: 'emergency', rowsByLabel: { v1: 4 } }))

    expect(decision.warnings).toEqual(['emergency_replay_window', 'emergency_records_dropped'])
    expect(decision.candidateRows).toBe(4)
    expect(decision.instructions.join(' ')).toContain('4 baris masih memakai versi v1')
  })

  it('darurat tetap menolak label yang salah, bukan menghapus apa pun yang tidak dikenali', () => {
    const decision = evaluateKeyRetention(base({ mode: 'emergency', candidateLabel: 'v2' }))
    expect(decision.removable).toBe(false)
    expect(decision.blockers).toContain('candidate_is_active')
  })
})

describe('VGL-30H K-4: record yang masih memakai kunci lama adalah penghalang', () => {
  it('24 jam lewat bukan berarti kuncinya bebas dipakai', () => {
    const decision = evaluateKeyRetention(
      base({ nowMs: RETIRED_AT + 25 * 60 * MINUTE, rowsByLabel: { v1: 3, v2: 41 } }),
    )

    expect(decision.hardFloorSatisfied).toBe(true)
    expect(decision.scheduledRetentionSatisfied).toBe(true)
    expect(decision.blockers).toEqual(['records_still_keyed'])
    expect(decision.removable).toBe(false)
    expect(decision.candidateRows).toBe(3)
  })

  it('sensus actor memberi angka itu: sebelum re-key blokir, setelah re-key lolos', async () => {
    const probe = createDurableStorageProbe()
    const oldRing = makeRing({ active: 'v1', labels: ['v1'] })
    const newRing = makeRing({ active: 'v2', labels: ['v1', 'v2'] })
    const now = 1_700_000_000_000

    const identity = { rn: 'rn', an: 'an', iseq: 1, bootMs: now }
    const ops = createDurableStateOps({ storage: probe.storage, identity, maxKeys: 50 })
    const seedRecord = await recordOf(oldRing, SCAN_STATE_KINDS.token, 'fp:belum-dipindah')
    ops.reserveToken(seedRecord, now, 600_000)

    const before = ops.inventoryKeyVersions('v2')
    expect(before.status).toBe('ok')
    if (before.status !== 'ok') throw new Error('sensus gagal')

    const blocked = evaluateKeyRetention(
      base({
        nowMs: RETIRED_AT + 26 * MINUTE,
        rowsByLabel: before.value.rowsByLabel,
      }),
    )
    expect(blocked.blockers).toContain('records_still_keyed')

    // Permintaan yang menulis pada versi aktif akan memindahkan baris itu (K-3): sensus ulang,
    // kunci lama tidak lagi dipakai siapa pun.
    const movedRecord = await recordOf(newRing, SCAN_STATE_KINDS.token, 'fp:belum-dipindah')
    expect(ops.reserveToken(movedRecord, now + 1_000, 600_000)).toMatchObject({ value: 'reused' })

    const after = ops.inventoryKeyVersions('v2')
    expect(after.status).toBe('ok')
    if (after.status !== 'ok') throw new Error('sensus gagal')

    const allowed = evaluateKeyRetention(base({ nowMs: RETIRED_AT + 24 * 60 * MINUTE, rowsByLabel: after.value.rowsByLabel }))
    expect(allowed.removable).toBe(true)
  })

  it('baris warisan tanpa prefiks juga memblokir pencabutan salt', () => {
    const decision = evaluateKeyRetention(
      base({ candidateLabel: 'legacy', nowMs: RETIRED_AT + 24 * 60 * MINUTE, rowsByLabel: { legacy: 2 } }),
    )
    expect(decision.blockers).toEqual(['records_still_keyed'])
  })
})

describe('VGL-30H K-4: jam dan validasi', () => {
  it('jam mundur ditolak, elapsed tidak pernah negatif', () => {
    const decision = evaluateKeyRetention(base({ nowMs: RETIRED_AT - 1_000 }))
    expect(decision.blockers).toContain('clock_invalid')
    expect(decision.elapsedMs).toBe(0)
    expect(decision.removable).toBe(false)
  })

  it.each([
    ['NaN sebagai now', Number.NaN, RETIRED_AT],
    ['Infinity sebagai retired', RETIRED_AT, Number.POSITIVE_INFINITY],
    ['waktu negatif', -5, RETIRED_AT],
  ])('%s ditolak', (_label, retired, now) => {
    const decision = evaluateKeyRetention(base({ retiredSinceMs: retired, nowMs: now }))
    expect(decision.blockers).toContain('clock_invalid')
  })

  it('label yang bukan versi dan bukan legacy ditolak', () => {
    const decision = evaluateKeyRetention(base({ activeLabel: 'saya-aktif', candidateLabel: 'v1' }))
    expect(decision.blockers).toContain('label_invalid')

    const unknown = evaluateKeyRetention(base({ candidateLabel: 'v77' }))
    expect(unknown.blockers).not.toContain('label_invalid')
    expect(unknown.candidateLabel).toBe('v77')
  })

  it('keputusan bersifat murni: input tidak diubah dan evaluasi berulang sama', () => {
    const input = base({ nowMs: RETIRED_AT + 24 * 60 * MINUTE, rowsByLabel: { v1: 1 } })
    const snapshot = JSON.parse(JSON.stringify(input)) as KeyRetentionPolicyInput

    const first = evaluateKeyRetention(input)
    const second = evaluateKeyRetention(input)

    expect(second).toEqual(first)
    expect(input).toEqual(snapshot)
  })
})

describe('VGL-30H K-4: tidak ada penghapusan otomatis', () => {
  it('modul hanya mengevaluasi: tidak ada jalur tulis, tidak ada nama yang menghapus secret', () => {
    const exports = Object.keys({
      evaluateKeyRetention,
      describeKeyRingStatus,
      KEY_RETENTION_HARD_FLOOR_MS,
      KEY_RETENTION_SCHEDULED_MS,
      KEY_RETENTION_EMERGENCY_MS,
      KEY_EMERGENCY_REPLAY_WINDOW_MS,
    })

    expect(exports.some((name) => /delete|remove|revoke|destroy|unset|rotate/i.test(name))).toBe(false)
    const decision = evaluateKeyRetention(base({ nowMs: RETIRED_AT + 24 * 60 * MINUTE }))
    expect(decision.instructions.join(' ')).toContain('penghapusan secret selalu tindakan pemilik')
  })

  it('status cincin menyebut panjang materi, tidak pernah nilainya', () => {
    const v1 = syntheticKey(1)
    const v2 = syntheticKey(2)
    const status = describeKeyRingStatus({
      activeLabel: 'v2',
      readableLabels: ['v1', 'v2'],
      excludedLabels: ['v3'],
      materialByLabel: { v1, v2, v3: 'pendek' },
      rowsByLabel: { v1: 7, v2: 90 },
    })

    const dump = JSON.stringify(status)
    expect(dump).not.toContain(v1)
    expect(dump).not.toContain(v2)
    expect(status).toEqual([
      { label: 'v1', role: 'readable', materialPresent: true, materialLengthOk: true, rows: 7 },
      { label: 'v2', role: 'active', materialPresent: true, materialLengthOk: true, rows: 90 },
      { label: 'v3', role: 'excluded', materialPresent: true, materialLengthOk: false, rows: 0 },
    ])
  })
})

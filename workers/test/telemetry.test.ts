import { beforeEach, describe, expect, it, vi } from 'vitest'
import { SCAN_STATE_KINDS, createDurableStateOps } from '../src/state/durableState.js'
import {
  SCAN_STATE_EVENT_LOG_PREFIX,
  createCorrelationId,
  createNonce,
  emitScanStateEvent,
  isolateNonce,
  nextActorInstanceSequence,
  readScanStateEvents,
  resetScanStateEvents,
  shortActorId,
} from '../src/state/telemetry.js'
import type { ScanStateEvent } from '../src/state/telemetry.js'
import { createDurableStorageProbe } from './helpers/durableSqlite.js'
import { recordOf, singleRing } from './helpers/keyRings.js'

/**
 * VGL-30F §6 (unit R4) + VGL-30H R4: bentuk catatan, sampling, dan rahasianya yang TIDAK ada.
 *
 * R4 hanya berguna kalau catatan tidak bisa membawa data sensitif. Dua jalur dibuktikan di sini:
 *  1. bentuk event hanya punya field bernama tetap (`v,ts,event,src,wn,rn,aid,an,iseq,corr,op,out,
 *     dur_ms,rows,kind,age_ms,cat,brk,bleft,kv`), jadi tidak ada tempat untuk menyimpan IP/UID/URL/token;
 *  2. nilai yang masuk lewat jalur itu ditetapkan pemanggil dari konstanta — diuji dengan sengaja
 *     memakai kunci yang berisi IP dan memastikan IP maupun digest-nya tidak muncul di baris log.
 *     Yang boleh keluar dari identitas kunci hanyalah LABEL versi (`kv`), bukan materi kunci.
 */

/** Nama field yang diizinkan pada satu baris `scan_state_evt`. Tidak ada yang lain. */
const ALLOWED_EVENT_KEYS = [
  'v', 'ts', 'event', 'src', 'wn', 'rn', 'aid', 'an', 'iseq', 'corr',
  'op', 'out', 'dur_ms', 'rows', 'kind', 'age_ms', 'cat', 'brk', 'bleft', 'kv',
] as const

const READ_SAMPLE_RATE = 10
const RING_LIMIT = 200

function warnLines(spied: { mock: { calls: unknown[][] } }): string[] {
  return spied.mock.calls.map((call) => String(call[0]))
}

beforeEach(() => {
  resetScanStateEvents()
})

describe('VGL-30F R4: bentuk dan isi catatan', () => {
  it('setiap event hanya memakai field yang terdaftar', () => {
    emitScanStateEvent({ event: 'durable_write', src: 'actor', op: 'counter', out: 'applied', rows: 1, dur_ms: 2 })
    emitScanStateEvent({ event: 'breaker_transition', src: 'worker', brk: 'open', bleft: 28_000, corr: 'abc' })
    emitScanStateEvent({ event: 'actor_instance_started', src: 'actor', an: 'aaaa1111', iseq: 3, out: 'ok' })

    const events = readScanStateEvents()
    expect(events).toHaveLength(3)
    for (const event of events) {
      expect(Object.keys(event).filter((key) => !ALLOWED_EVENT_KEYS.includes(key as (typeof ALLOWED_EVENT_KEYS)[number])))
        .toEqual([])
      expect(event.v).toBe(1)
      expect(typeof event.ts).toBe('number')
      expect(event.src).toMatch(/^(worker|actor)$/)
    }
  })

  it('kunci state dan digest-nya tidak ikut tercetak di catatan', async () => {
    // Kunci state sengaja diisi string yang paling tidak boleh muncul di log.
    const probe = createDurableStorageProbe()
    const ops = createDurableStateOps({
      storage: probe.storage,
      identity: { rn: 'rn-uji', an: 'an-uji', iseq: 1, aid: 'actor-uji', corr: 'corr-uji', bootMs: Date.now() },
      maxKeys: 5,
    })
    const ring = singleRing()
    const secretish = 'ip:203.0.113.99'
    const counterRecord = await recordOf(ring, SCAN_STATE_KINDS.counter, secretish)
    ops.bootstrap()
    ops.consumeCounter({ record: counterRecord, limit: 2, windowMs: 60_000, now: Date.now() })
    ops.reserveToken(await recordOf(ring, SCAN_STATE_KINDS.token, 'sidik-token-penuh'), Date.now(), 60_000)
    ops.issueClearance(
      await recordOf(ring, SCAN_STATE_KINDS.clearance, `turnstile-scan:uid-1234567890${secretish}`),
      Date.now(),
      300_000,
    )

    const spy = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    for (const event of readScanStateEvents()) {
      // `durable_read` sengaja disampling 1 dari 10, jadi dicetak di test sampling, bukan di sini.
      if (event.event === 'durable_read') continue
      spy.mockClear()
      emitScanStateEvent(event)
      const line = warnLines(spy).join('\n')
      expect(line).toContain(SCAN_STATE_EVENT_LOG_PREFIX)
      expect(line).not.toContain('203.0.113.99')
      expect(line).not.toContain('sidik-token-penuh')
      expect(line).not.toContain('uid-1234567890')
      expect(line).not.toContain(secretish)
      // Digest juga tidak boleh keluar: yang mengidentifikasi letak baris hanyalah label versi.
      expect(line).not.toContain(counterRecord.activeHash)
      if (event.kv !== undefined) expect(event.kv).toBe('v1')
    }
    spy.mockRestore()

    // Tabel menyimpan digest berversi, jadi barisnya sendiri tidak menyebut identitas asal.
    const stored = probe.rowsFor(SCAN_STATE_KINDS.counter).map((row) => String(row.key_hash))
    expect(stored.some((hash) => hash === counterRecord.activeHash)).toBe(true)
    expect(JSON.stringify(stored)).not.toContain('203.0.113.99')
  })

  it('durable_read dicatat 1 dari 10, sementara ring mencatat semuanya', () => {
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    for (let index = 0; index < READ_SAMPLE_RATE * 3; index += 1) {
      emitScanStateEvent({ event: 'durable_read', src: 'actor', op: 'counter' })
    }
    const reads = warnLines(spy).filter((line) => line.includes('"event":"durable_read"'))
    expect(reads).toHaveLength(3)
    expect(readScanStateEvents().filter((event) => event.event === 'durable_read')).toHaveLength(READ_SAMPLE_RATE * 3)
    spy.mockRestore()
  })

  it('kelas event lain dicatat tanpa sampling', () => {
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    for (const op of ['counter', 'clearance_has', 'token_reserve']) {
      emitScanStateEvent({ event: 'durable_write', src: 'actor', op, out: 'applied' })
    }
    expect(warnLines(spy).filter((line) => line.includes('"event":"durable_write"'))).toHaveLength(3)
    spy.mockRestore()
  })

  it('console.warn yang gagal tidak menggagalkan keputusan', () => {
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {
      throw new Error('log ditolak runtime')
    })
    expect(() =>
      emitScanStateEvent({ event: 'durable_error', src: 'actor', op: 'counter', cat: 'storage_unavailable' }),
    ).not.toThrow()
    expect(readScanStateEvents()).toHaveLength(1)
    spy.mockRestore()
  })

  it('ring buffer dibatasi dan membuang yang paling tua', () => {
    for (let index = 0; index < RING_LIMIT + 25; index += 1) {
      emitScanStateEvent({ event: 'durable_write', src: 'actor', op: `ops-${index}` })
    }

    const events = readScanStateEvents()
    expect(events).toHaveLength(RING_LIMIT)
    const last = events[events.length - 1] as ScanStateEvent
    expect(last.op).toBe(`ops-${RING_LIMIT + 24}`)
    expect(events.some((event) => event.op === 'ops-0')).toBe(false)
  })

  it('reset mengosongkan ring dan ulang hitung instance', () => {
    emitScanStateEvent({ event: 'durable_write', src: 'actor', op: 'counter' })
    expect(nextActorInstanceSequence()).toBe(1)
    expect(nextActorInstanceSequence()).toBe(2)

    resetScanStateEvents()
    expect(readScanStateEvents()).toHaveLength(0)
    expect(nextActorInstanceSequence()).toBe(1)
  })

  it('baris yang dibaca kembali adalah salinan, bukan isi ring', () => {
    emitScanStateEvent({ event: 'durable_write', src: 'actor', op: 'counter', rows: 1 })
    const copy = readScanStateEvents()[0] as ScanStateEvent
    copy.op = 'diubah'

    expect(readScanStateEvents()[0]?.op).toBe('counter')
  })
})

describe('VGL-30F R4: identitas isolate, instance, dan permintaan', () => {
  it('nonce isolate stabil dan identitasnya hanya dicatat sekali per isolate', async () => {
    // Modul baru = isolate baru: nonce dan cache-nya tidak boleh bocor ke test lain.
    vi.resetModules()
    const fresh = await import('../src/state/telemetry.js')
    fresh.resetScanStateEvents()

    const worker = fresh.isolateNonce('worker')
    expect(worker).toMatch(/^[a-z0-9]{8}$/)
    expect(fresh.isolateNonce('worker')).toBe(worker)

    const actor = fresh.isolateNonce('actor')
    expect(actor).toMatch(/^[a-z0-9]{8}$/)
    expect(actor).not.toBe(worker)

    const ids = fresh
      .readScanStateEvents()
      .filter((event) => event.event === 'worker_isolate_identity' || event.event === 'actor_isolate_identity')
    expect(ids).toHaveLength(2)
    expect(ids[0]).toMatchObject({ event: 'worker_isolate_identity', src: 'worker', wn: worker })
    expect(ids[0]).not.toHaveProperty('rn')
    expect(ids[1]).toMatchObject({ event: 'actor_isolate_identity', src: 'actor', rn: actor })
    expect(ids[1]).not.toHaveProperty('wn')
  })

  it('nonce permintaan cukup pendek, terurut, dan hanya huruf/angka kecil', () => {
    expect(createNonce()).toMatch(/^[a-z0-9]{8}$/)
    expect(createCorrelationId()).toMatch(/^[a-z0-9]{12}$/)
    expect(shortActorId('0123456789abcdef-680a9eac5625432c8bbf870e57005480')).toBe('01234567')

    const seen = new Set<string>()
    for (let index = 0; index < 200; index += 1) seen.add(createCorrelationId())
    expect(seen.size).toBeGreaterThan(190)
  })

  it('corr pada event hanya nilai yang diberikan pemanggil, tidak pernah dibentuk dari kunci', () => {
    const corr = createCorrelationId()
    emitScanStateEvent({ event: 'durable_read', src: 'worker', op: 'counter', corr })
    expect(readScanStateEvents()[0]?.corr).toBe(corr)
  })
})

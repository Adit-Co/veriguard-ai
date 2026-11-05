import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { MultiSourceScanResponse } from '../../functions/src/scanners/types.js'
import { resetSiteAnalysisRateLimit } from '../../functions/src/website/limits.js'
import { resetTurnstileClearance } from '../../functions/src/turnstile/scanGate.js'
import { resetTurnstileTokenRegistry } from '../../functions/src/turnstile/verify.js'
import { createWorker, type Env } from '../src/index.js'
import { resetEdgeRateLimit } from '../src/rateLimit.js'
import { SCAN_STATE_KINDS } from '../src/state/durableState.js'
import { ScanStateDurableObject } from '../src/state/scanState.js'
import type { ScanStateContext, ScanStateResponse } from '../src/state/scanState.js'
import { readScanStateEvents, resetScanStateEvents } from '../src/state/telemetry.js'
import {
  createDurableStateStore,
  createDurableTokenRegistry,
  createStateRpc,
  createMemoryStateStore,
  resolveWorkerState,
} from '../src/state/store.js'
import type { ScanStateNamespace, ScanStateRpcDiagnostic } from '../src/state/store.js'
import { createDurableStorageProbe } from './helpers/durableSqlite.js'
import type { DurableStorageProbe } from './helpers/durableSqlite.js'
import { makeRing, ringEnv, singleRing, syntheticKey } from './helpers/keyRings.js'

const ORIGIN = 'http://localhost:5173'
const NOW = 1_700_000_000_000
const IP = '203.0.113.10'

// DO tidak memakai storage (lihat catatan di kelasnya), jadi konteks palsunya hanya perlu
// memenuhi bentuknya.
const DO_STATE: ScanStateContext = {
  storage: {
    get: async () => null,
    put: async () => undefined,
  },
  waitUntil: () => undefined,
}

/**
 * Meniru Durable Object singleton: setiap stub namespace menunjuk SATU instance kelas yang
 * sama, seperti dua isolate Worker yang memakai `idFromName` dengan nama yang sama.
 */
function createFakeScanStateNamespace(): {
  namespace: ScanStateNamespace
  calls: () => number
} {
  const instance = new ScanStateDurableObject(DO_STATE, {})
  let calls = 0

  return {
    calls: () => calls,
    namespace: {
      idFromName: () => ({ toString: () => 'fake-scan-state-id' }),
      get: () => ({
        fetch: async (_input: string, init?: RequestInit) => {
          calls += 1
          return instance.fetch(
            new Request('https://veriguard-scan-state.internal/state', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: typeof init?.body === 'string' ? init.body : '{}',
            }),
          )
        },
      }),
    },
  }
}

function createStaticResponseNamespace(payload: unknown): ScanStateNamespace {
  return {
    idFromName: () => ({ toString: () => 'statis' }),
    get: () => ({
      fetch: async () =>
        new Response(JSON.stringify(payload), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
    }),
  }
}

function scanResponse(): MultiSourceScanResponse {
  return {
    providers: [],
    sharedWithProviders: [],
    sensitiveUrl: false,
    privacyReasons: [],
    generatedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 10,
  }
}

function postScan(): Request {
  return new Request('https://worker.test/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'CF-Connecting-IP': IP,
      Origin: ORIGIN,
    },
    body: JSON.stringify({ url: 'https://contoh.com', consent: true }),
  })
}

async function invoke(worker: ExportedHandler<Env>, request: Request, env: Env) {
  if (!worker.fetch) throw new Error('Handler fetch Worker tidak tersedia.')
  return worker.fetch(
    request as unknown as Request<unknown, IncomingRequestCfProperties<unknown>>,
    env,
    {} as ExecutionContext,
  )
}

describe('P1-3: Durable Object sebagai state bersama antar isolate', () => {
  it('satu batas per-IP berlaku untuk dua store yang menunjuk DO yang sama', async () => {
    const { namespace } = createFakeScanStateNamespace()
    // Dua facade terpisah = dua isolate. Keduanya harus melihat angka yang sama.
    const isolateA = createDurableStateStore(createStateRpc(namespace), createMemoryStateStore())
    const isolateB = createDurableStateStore(createStateRpc(namespace), createMemoryStateStore())

    expect(await isolateA.consumeCounter(`ip:${IP}`, 2, 60_000, Date.now())).toMatchObject({
      allowed: true,
      used: 1,
    })
    expect(await isolateB.consumeCounter(`ip:${IP}`, 2, 60_000, Date.now())).toMatchObject({
      allowed: true,
      used: 2,
    })

    const third = await isolateA.consumeCounter(`ip:${IP}`, 2, 60_000, Date.now())
    expect(third.allowed).toBe(false)
    expect(third.retryAfterSeconds).toBeGreaterThan(0)
  })

  it('batas nol di Durable Object menutup gerbang, bukan membukanya', async () => {
    const { namespace } = createFakeScanStateNamespace()
    const store = createDurableStateStore(createStateRpc(namespace), createMemoryStateStore())

    const decision = await store.consumeCounter(`ip:${IP}`, 0, 60_000, Date.now())
    expect(decision.allowed).toBe(false)
    expect(decision.retryAfterSeconds).toBeGreaterThan(0)
  })

  it('izin CAPTCHA dari satu isolate terlihat oleh isolate lain', async () => {
    const { namespace } = createFakeScanStateNamespace()
    const isolateA = createDurableStateStore(createStateRpc(namespace), createMemoryStateStore())
    const isolateB = createDurableStateStore(createStateRpc(namespace), createMemoryStateStore())

    const key = 'turnstile-scan-uid:abc'
    expect(await isolateA.hasClearance(key, Date.now())).toBe(false)

    await isolateA.issueClearance(key, Date.now())
    expect(await isolateB.hasClearance(key, Date.now())).toBe(true)
  })

  it('satu token hanya dapat ditukar sekali meskipun dari isolate berbeda', async () => {
    const { namespace } = createFakeScanStateNamespace()
    const isolateA = createDurableTokenRegistry(createStateRpc(namespace))
    const isolateB = createDurableTokenRegistry(createStateRpc(namespace))

    expect(await isolateA.reserve('sidik-a', Date.now())).toBe('reserved')
    expect(await isolateB.reserve('sidik-a', Date.now())).toBe('reused')

    // Pembebasan hanya terjadi bila Cloudflare tidak memproses token (mis. jaringan gagal);
    // sesudah itu token yang sama boleh dicoba lagi.
    await isolateA.release('sidik-a')
    expect(await isolateB.reserve('sidik-a', Date.now())).toBe('reserved')
  })

  it('analisis situs berbagi jendela geser antar isolate', async () => {
    const { namespace } = createFakeScanStateNamespace()
    const isolateA = createDurableStateStore(createStateRpc(namespace), createMemoryStateStore())
    const isolateB = createDurableStateStore(createStateRpc(namespace), createMemoryStateStore())
    const key = `site:guest:${IP}`

    for (const store of [isolateA, isolateB, isolateA, isolateB]) {
      expect((await store.consumeSiteWindow(key, Date.now())).allowed).toBe(true)
    }

    const blocked = await isolateA.consumeSiteWindow(key, Date.now())
    expect(blocked.allowed).toBe(false)
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0)
  })

  it('permintaan serentak ke DO yang sama tidak kehilangan increment', async () => {
    const { namespace } = createFakeScanStateNamespace()
    const storeA = createDurableStateStore(createStateRpc(namespace), createMemoryStateStore())
    const storeB = createDurableStateStore(createStateRpc(namespace), createMemoryStateStore())

    const decisions = await Promise.all(
      Array.from({ length: 20 }, (_, index) =>
        (index % 2 === 0 ? storeA : storeB).consumeCounter(`ip:${IP}`, 10, 60_000, NOW),
      ),
    )

    const allowed = decisions.filter((decision) => decision.allowed)
    const denied = decisions.filter((decision) => !decision.allowed)
    expect(allowed).toHaveLength(10)
    expect(denied).toHaveLength(10)
    // Kuota dilaporkan apa adanya: 1..10, tanpa loncatan maupun duplikasi.
    expect(allowed.map((decision) => decision.used ?? 0).sort((left, right) => left - right))
      .toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
  })

  it('satu sidik jari CAPTCHA hanya dapat dicadang sekali walau diminta serentak', async () => {
    const { namespace } = createFakeScanStateNamespace()
    const call = createStateRpc(namespace)
    const registries = [createDurableTokenRegistry(call), createDurableTokenRegistry(call)]

    const reservations = await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        registries[index % 2].reserve('sidik-serentak', NOW),
      ),
    )

    expect(reservations.filter((reservation) => reservation === 'reserved')).toHaveLength(1)
    expect(reservations.filter((reservation) => reservation === 'reused')).toHaveLength(7)
  })

  it('respons DO yang tidak lengkap diperlakukan sebagai tidak diizinkan', async () => {
    resetEdgeRateLimit()
    const store = createDurableStateStore(
      createStateRpc(createStaticResponseNamespace({ ok: true } satisfies ScanStateResponse)),
      createMemoryStateStore(),
    )

    // Bentuk tanpa `allowed` tidak boleh dibaca sebagai "silakan lanjut".
    const decision = await store.consumeCounter(`ip:${IP}`, 5, 60_000, Date.now())
    expect(decision.allowed).toBe(false)
  })

  it('DO yang tidak terjangkau kembali ke memori isolate dan tidak dihampiri lagi', async () => {
    resetEdgeRateLimit()
    const fetchImpl = vi.fn(async () => {
      throw new Error('DO tidak terjangkau')
    })
    const namespace: ScanStateNamespace = {
      idFromName: () => ({ toString: () => 'rusak' }),
      get: () => ({ fetch: fetchImpl }),
    }
    const store = createDurableStateStore(createStateRpc(namespace), createMemoryStateStore())

    expect((await store.consumeCounter(`ip:${IP}`, 1, 60_000, Date.now())).allowed).toBe(true)
    // Batas yang sama tetap ditegakkan oleh memori isolate, dan circuit breaker membuat
    // permintaan berikutnya tidak menambah latensi RPC lagi.
    expect((await store.consumeCounter(`ip:${IP}`, 1, 60_000, Date.now())).allowed).toBe(false)
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })

  it('tanpa binding, worker memakai store memori tanpa registry DO', () => {
    const fallback = createMemoryStateStore()
    const state = resolveWorkerState(undefined, fallback)

    expect(state.store).toBe(fallback)
    expect(state.tokenRegistry).toBeUndefined()
  })

  it('store memori memakai pembatas modul yang sama seperti sebelumnya', async () => {
    resetEdgeRateLimit()
    resetSiteAnalysisRateLimit()
    resetTurnstileClearance()
    resetTurnstileTokenRegistry()

    const store = createMemoryStateStore()
    expect((await store.consumeCounter('ip:x', 1, 60_000, NOW)).allowed).toBe(true)
    expect((await store.consumeCounter('ip:x', 1, 60_000, NOW)).allowed).toBe(false)

    const key = 'turnstile-scan-guest:x'
    expect(await store.hasClearance(key, NOW)).toBe(false)
    await store.issueClearance(key, NOW)
    expect(await store.hasClearance(key, NOW)).toBe(true)

    expect((await store.consumeSiteWindow('site:x', NOW)).allowed).toBe(true)

    // RPC yang gagal TIDAK menurunkan anti-replay ke registry memori isolate: memori
    // isolate bukan state bersama, jadi satu token bisa dipakai ulang dari isolate lain.
    // Arah gagalnya menolak, dan klien menjawabnya dengan tantangan CAPTCHA baru.
    const registry = createDurableTokenRegistry(async () => null)
    expect(await registry.reserve('sidik-x', NOW)).toBe('reused')
    expect(await registry.reserve('sidik-y', NOW)).toBe('reused')
    await expect(registry.release('sidik-x')).resolves.toBeUndefined()
  })
})

describe('P1-3: Worker dengan binding SCAN_STATE berbagi batas lintas instance', () => {
  it('menolak request kedua dari IP yang sama meski datang dari isolate berbeda', async () => {
    const { namespace, calls } = createFakeScanStateNamespace()
    const env: Env = {
      ALLOWED_ORIGINS: ORIGIN,
      RATE_LIMIT_MAX_PER_IP: '1',
      RATE_LIMIT_WINDOW_SECONDS: '60',
      SCAN_STATE: namespace,
    }

    const workerA = createWorker({ runScan: vi.fn(async () => scanResponse()), now: () => NOW })
    const workerB = createWorker({ runScan: vi.fn(async () => scanResponse()), now: () => NOW })

    const first = await invoke(workerA, postScan(), env)
    expect(first.status).toBe(200)

    // Isolate B tidak punya pencacah sendiri: ia melihat angka A dan menjawab 429.
    const second = await invoke(workerB, postScan(), env)
    expect(second.status).toBe(429)
    expect(await second.json()).toMatchObject({ error: { code: 'rate_limited' } })

    expect(calls()).toBeGreaterThan(0)
  })

})

describe('VGL-28 R1/R3: diagnostik RPC dan umur stub', () => {
  it('kegagalan RPC dicatat dengan kategori, dan detailnya disanitasi', async () => {
    const records: ScanStateRpcDiagnostic[] = []
    const namespace: ScanStateNamespace = {
      idFromName: () => ({ toString: () => 'id' }),
      get: () => ({
        fetch: async () => {
          throw new Error(
            'Cannot perform I/O on behalf of a different request ' +
              '(https://veriguard-scan-state.internal/state, kunci ip:203.0.113.99)',
          )
        },
      }),
    }

    const call = createStateRpc(namespace, (diagnostic) => records.push(diagnostic))
    expect(await call({ action: 'counter', key: 'ip:203.0.113.99', limit: 5, windowMs: 60_000 })).toBeNull()

    expect(records).toHaveLength(1)
    expect(records[0]).toMatchObject({ category: 'rpc_exception', fallbackUsed: true, operation: 'counter' })
    const detail = records[0].detail ?? ''
    expect(detail).toContain('<do-endpoint>')
    expect(detail).toContain('<redacted-ip>')
    expect(detail).not.toContain('203.0.113.99')
    expect(JSON.stringify(records[0])).not.toContain('ip:203.0.113.99')
  })

  it('stub DO dibuat per panggilan RPC, bukan disimpan di closure builder', async () => {
    // Bentuk lama menyimpan satu stub untuk seluruh permintaan; workerd menolak I/O-nya di
    // konteks permintaan berikutnya (VGL-28). Pin unit supaya pola itu tidak kembali.
    const idFromName = vi.fn(() => ({ toString: () => 'id' }))
    const get = vi.fn(() => ({
      fetch: async () =>
        new Response(
          JSON.stringify({ ok: true, allowed: true, used: 1, retryAfterSeconds: 0 } satisfies ScanStateResponse),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
    }))
    const call = createStateRpc({ get, idFromName } as unknown as ScanStateNamespace, () => undefined)

    await call({ action: 'counter', key: 'ip:x', limit: 5, windowMs: 60_000 })
    await call({ action: 'counter', key: 'ip:x', limit: 5, windowMs: 60_000 })

    expect(get).toHaveBeenCalledTimes(2)
    expect(idFromName).toHaveBeenCalledTimes(2)
  })
})

/**
 * VGL-30F §6 (tingkat actor): routing durable pada `ScanStateDurableObject` di atas SQLite
 * sungguhan. Yang diuji di sini adalah PERMINTAAN MASUK-SALUAR KELUAR actor, bukan semantik
 * operasi (itu `durableState.test.ts`) dan bukan evict runtime (itu `durableObjectEviction.test.ts`).
 */

// Materi kunci sintetis (VGL-30H §5). Nilainya tidak dirahasiakan, tidak pernah dikirim ke
// produksi/staging, dan tidak pernah ditulis ke tabel maupun ke catatan; ia ada di sini hanya
// supaya jalur durable berversi punya kunci untuk diuji. VGL-30H melarang membuat secret
// sungguhan, jadi cincin dipasang lewat env suntikan, bukan lewat `wrangler secret`.
const ACTOR_ID = 'abcdef0123456789'

function actorContext(probe: DurableStorageProbe): ScanStateContext {
  return {
    storage: {
      ...probe.storage,
      get: async () => null,
      put: async () => undefined,
    },
    waitUntil: () => undefined,
    id: { toString: () => ACTOR_ID },
  } as unknown as ScanStateContext
}

// Konfigurasi durable ditulis EKSPISIT di setiap test: jalur aktif hanya bila env benar-benar
// membawa versi aktif + materialnya, dan helper tidak boleh menyediakannya secara diam-diam.
function durableEnv(): Record<string, unknown> {
  return ringEnv({ active: 'v1', labels: ['v1'] })
}

async function askActor(
  instance: ScanStateDurableObject,
  body: Record<string, unknown>,
): Promise<{ status: number; payload: ScanStateResponse }> {
  const response = await instance.fetch(
    new Request('https://veriguard-scan-state.internal/state', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  )
  return { status: response.status, payload: (await response.json()) as ScanStateResponse }
}

/** Namespace yang menunjuk satu instance actor, seperti `idFromName` di dunia nyata. */
function namespaceFor(instance: ScanStateDurableObject): ScanStateNamespace {
  return {
    idFromName: () => ({ toString: () => ACTOR_ID }),
    get: () => ({
      fetch: async (_input: string, init?: RequestInit) =>
        instance.fetch(
          new Request('https://veriguard-scan-state.internal/state', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: typeof init?.body === 'string' ? init.body : '{}',
          }),
        ),
    }),
  }
}

describe('VGL-30F R1: jalur durable tidak aktif tanpa kunci yang disetujui', () => {
  beforeEach(() => {
    resetScanStateEvents()
  })

  it('tanpa key ring, actor menjawab dari memori instance dan tidak menyentuh SQL sama sekali', async () => {
    const probe = createDurableStorageProbe()
    const instance = new ScanStateDurableObject(actorContext(probe), {})

    expect((await askActor(instance, { action: 'counter', key: `ip:${IP}`, limit: 1, windowMs: 60_000 })).payload)
      .toMatchObject({ ok: true, allowed: true, used: 1 })
    expect((await askActor(instance, { action: 'counter', key: `ip:${IP}`, limit: 1, windowMs: 60_000 })).payload)
      .toMatchObject({ allowed: false })

    // Inilah F2 yang belum ditutup: instance baru = kuota baru. Perilaku ini SENGAJA sama
    // dengan sebelum R1, dan berubah hanya bila pemilik memasang key ring.
    const restarted = new ScanStateDurableObject(actorContext(probe), {})
    expect((await askActor(restarted, { action: 'counter', key: `ip:${IP}`, limit: 1, windowMs: 60_000 })).payload)
      .toMatchObject({ allowed: true, used: 1 })

    expect(probe.queries()).toEqual([])
    expect(readScanStateEvents()).toContainEqual(
      expect.objectContaining({ event: 'actor_instance_started', src: 'actor', out: 'volatile', kind: 'no_keys' }),
    )
  })

  it('hanya salt warisan tidak mengaktifkan jalur durable, dan nilainya tidak dilaporkan', async () => {
    // Bentuk produksi/staging sebelum VGL-30H: salt terpasang, tidak ada versi aktif.
    const probe = createDurableStorageProbe()
    const instance = new ScanStateDurableObject(
      actorContext(probe),
      ringEnv({ active: 'v1', labels: [], legacySalt: 'salt-lama-tidak-cukup-untuk-versi' }),
    )

    expect((await askActor(instance, { action: 'reserve', key: 'sidik-a' })).payload).toMatchObject({
      reservation: 'reserved',
    })
    expect(probe.queries()).toEqual([])
    expect(readScanStateEvents()).toContainEqual(expect.objectContaining({ out: 'volatile', kind: 'no_keys' }))
  })

  it('material versi terlalu pendek tidak mengaktifkan durable dan panjangnya tidak dilaporkan', async () => {
    const probe = createDurableStorageProbe()
    const instance = new ScanStateDurableObject(
      actorContext(probe),
      ringEnv({ active: 'v1', labels: ['v1'], materialOverride: { v1: 'pendek' } }),
    )

    expect((await askActor(instance, { action: 'counter', key: `ip:${IP}`, limit: 1, windowMs: 60_000 })).payload)
      .toMatchObject({ allowed: true })
    expect(probe.queries()).toEqual([])
    const dump = JSON.stringify(readScanStateEvents())
    expect(dump).toContain('no_keys')
    // Nilai material tidak pernah ikut ke catatan, walau materialnya jelas-jelas ditolak.
    expect(dump).not.toContain('pendek')
  })

  it('versi aktif menunjuk secret yang tidak dipasang: durable tetap inert', async () => {
    const probe = createDurableStorageProbe()
    const instance = new ScanStateDurableObject(actorContext(probe), ringEnv({ active: 'v7', labels: ['v1'] }))

    expect((await askActor(instance, { action: 'counter', key: `ip:${IP}`, limit: 1, windowMs: 60_000 })).payload)
      .toMatchObject({ allowed: true, used: 1 })
    expect(probe.queries()).toEqual([])
    expect(readScanStateEvents()).toContainEqual(
      expect.objectContaining({ out: 'volatile', kind: 'active_version_absent' }),
    )
  })

  it('permintaan tetap dilayani meski permukaan SQL ada tetapi key ring tidak ada', async () => {
    // Ini bentuk produksi/staging hari ini: binding DO aktif, `state.storage.sql` tersedia.
    const probe = createDurableStorageProbe()
    const instance = new ScanStateDurableObject(actorContext(probe), {})
    const answered = await askActor(instance, { action: 'counter', key: `ip:${IP}`, limit: 1, windowMs: 60_000 })
    expect(answered.status).toBe(200)
    expect(answered.payload.allowed).toBe(true)
  })
})

describe('VGL-30F R1: routing durable pada actor', () => {
  beforeEach(() => {
    resetScanStateEvents()
  })

  it('kuota yang sudah terpakai bertahan melewati instance actor baru', async () => {
    const probe = createDurableStorageProbe()
    const first = new ScanStateDurableObject(actorContext(probe), durableEnv())
    const body = { action: 'counter', key: `ip:${IP}`, limit: 2, windowMs: 60_000 }

    expect((await askActor(first, body)).payload).toMatchObject({ allowed: true, used: 1 })
    expect((await askActor(first, body)).payload).toMatchObject({ allowed: true, used: 2 })
    expect((await askActor(first, body)).payload).toMatchObject({ allowed: false, used: 2 })

    // Instance baru di atas penyimpanan yang sama: restart actor tidak mengembalikan kuota.
    const reopened = createDurableStorageProbe(probe.db)
    const restarted = new ScanStateDurableObject(actorContext(reopened), durableEnv())
    const blocked = await askActor(restarted, body)
    expect(blocked.payload).toMatchObject({ allowed: false, used: 2 })
    expect(readScanStateEvents()).toContainEqual(
      expect.objectContaining({ event: 'actor_counters_restored', kind: SCAN_STATE_KINDS.counter, rows: 1 }),
    )
  })

  it('kunci di tabel durable adalah record berversi ber-HMAC, bukan IP, UID, atau sidik jari', async () => {
    const probe = createDurableStorageProbe()
    const instance = new ScanStateDurableObject(actorContext(probe), durableEnv())

    await askActor(instance, { action: 'counter', key: `ip:${IP}`, limit: 5, windowMs: 60_000 })
    await askActor(instance, { action: 'issue', key: 'turnstile-scan:uid-1234567890', ttlMs: 300_000 })
    await askActor(instance, { action: 'reserve', key: 'sidik-token-sangat-rahasia' })

    const rows = probe.db.prepare('SELECT kind, key_hash FROM vgl_state').all() as Array<{
      kind: string
      key_hash: string
    }>
    const stateRows = rows.filter((row) => row.kind !== SCAN_STATE_KINDS.meta)
    expect(stateRows).toHaveLength(3)
    for (const row of stateRows) {
      expect(row.key_hash).toMatch(/^v1:[0-9a-f]{64}$/)
    }
    // Satu-satunya nilai teks yang boleh ada di tabel adalah nama konstanta penanda sapuan
    // (kind `meta`, kunci `sweep`) — ditetapkan kode, bukan berasal dari permintaan.
    for (const row of rows.filter((item) => item.kind === SCAN_STATE_KINDS.meta)) {
      expect(row.key_hash).toBe('sweep')
    }
    const dump = JSON.stringify(rows)
    expect(dump).not.toContain(IP)
    expect(dump).not.toContain('uid-1234567890')
    expect(dump).not.toContain('sidik-token-sangat-rahasia')
    expect(dump).not.toContain(syntheticKey(1).slice(0, 12))
  })

  it('digest berbeda untuk kind berbeda walau kunci aslinya sama', async () => {
    const keyer = singleRing()
    expect(keyer.available).toBe(true)
    const sebagaiCounter = await keyer.digestsFor(SCAN_STATE_KINDS.counter, `ip:${IP}`)
    const sebagaiToken = await keyer.digestsFor(SCAN_STATE_KINDS.token, `ip:${IP}`)
    if (!sebagaiCounter || !sebagaiToken) throw new Error('cincin aktif harus menghasilkan digest')
    expect(sebagaiCounter.activeHash).toMatch(/^v1:[0-9a-f]{64}$/)
    expect(sebagaiToken.activeHash).toMatch(/^v1:[0-9a-f]{64}$/)
    expect(sebagaiCounter.activeHash).not.toBe(sebagaiToken.activeHash)

    // Digest-nya deterministik: instance actor mana pun menghitung kunci yang sama.
    const lagi = await makeRing({ active: 'v1', labels: ['v1'] }).digestsFor(SCAN_STATE_KINDS.counter, `ip:${IP}`)
    expect(lagi?.activeHash).toBe(sebagaiCounter.activeHash)
    // Materi lain = digest lain, sehingga tabel hasil salin-tembak tidak bisa dibaca tanpa kunci.
    const materiLain = await makeRing({
      active: 'v1',
      labels: ['v1'],
      materialOverride: { v1: `${syntheticKey(1)}lain` },
    }).digestsFor(SCAN_STATE_KINDS.counter, `ip:${IP}`)
    expect(materiLain?.activeHash).not.toBe(sebagaiCounter.activeHash)
  })

  it('token yang sudah dipakai tetap ditolak setelah actor dihidupkan ulang', async () => {
    const probe = createDurableStorageProbe()
    const first = new ScanStateDurableObject(actorContext(probe), durableEnv())
    expect((await askActor(first, { action: 'reserve', key: 'sidik-1' })).payload).toMatchObject({
      reservation: 'reserved',
    })

    const restarted = new ScanStateDurableObject(actorContext(createDurableStorageProbe(probe.db)), durableEnv())
    expect((await askActor(restarted, { action: 'reserve', key: 'sidik-1' })).payload).toMatchObject({
      reservation: 'reused',
    })
    expect(readScanStateEvents()).toContainEqual(
      expect.objectContaining({ event: 'actor_tokens_restored', kind: SCAN_STATE_KINDS.token, rows: 1 }),
    )
  })

  it('izin CAPTCHA terbaca oleh instance baru, dan `window` sengaja tetap di memori', async () => {
    const probe = createDurableStorageProbe()
    const first = new ScanStateDurableObject(actorContext(probe), durableEnv())
    expect(
      (await askActor(first, { action: 'issue', key: 'turnstile-scan-uid:abc', ttlMs: 300_000 })).payload.allowed,
    ).toBe(true)

    const restarted = new ScanStateDurableObject(actorContext(createDurableStorageProbe(probe.db)), durableEnv())
    expect((await askActor(restarted, { action: 'has', key: 'turnstile-scan-uid:abc' })).payload).toMatchObject({
      allowed: true,
    })
    expect(readScanStateEvents()).toContainEqual(
      expect.objectContaining({ event: 'actor_clearances_restored', kind: SCAN_STATE_KINDS.clearance, rows: 1 }),
    )

    // Cakupan R1 tidak mencakup jendela geser analisis situs: ia tidak boleh ikut berpindah diam-diam.
    const jendela = { action: 'window', key: `site:guest:${IP}`, limit: 2, windowMs: 60_000 }
    for (const instance of [first, restarted]) {
      expect((await askActor(instance, jendela)).payload).toMatchObject({ allowed: true, used: 1 })
    }
  })

  it('permintaan tidak lengkap tetap dijawab 400, bukan penolakan durable', async () => {
    const instance = new ScanStateDurableObject(actorContext(createDurableStorageProbe()), durableEnv())

    expect((await askActor(instance, { action: 'counter', key: `ip:${IP}`, windowMs: 60_000 })).status).toBe(400)
    expect((await askActor(instance, { action: 'counter', key: `ip:${IP}`, limit: 5 })).status).toBe(400)
    expect((await askActor(instance, { action: 'issue', key: 'uid:abc' })).status).toBe(400)
  })

  it('corr dari pemanggil muncul di catatan actor dan tidak lolos ke saluar keputusan', async () => {
    const instance = new ScanStateDurableObject(actorContext(createDurableStorageProbe()), durableEnv())
    const answered = await askActor(instance, {
      action: 'counter',
      key: `ip:${IP}`,
      limit: 5,
      windowMs: 60_000,
      corr: 'Corr-Uji-0001',
    })

    expect(answered.payload).toMatchObject({ ok: true, allowed: true })
    expect(JSON.stringify(answered.payload)).not.toContain('corr')
    // Nilai yang diterima actor disaring (huruf/angka kecil saja) sebelum masuk catatan: `corr`
    // dari pemanggil tidak pernah dipakai apa adanya.
    expect(readScanStateEvents()).toContainEqual(expect.objectContaining({ corr: 'corruji0001', aid: 'abcdef01' }))
  })

  it('corr yang terlalu panjang atau berisi karakter lain dibuang, permintaannya tetap dilayani', async () => {
    const instance = new ScanStateDurableObject(actorContext(createDurableStorageProbe()), durableEnv())
    const answered = await askActor(instance, {
      action: 'counter',
      key: `ip:${IP}`,
      limit: 5,
      windowMs: 60_000,
      corr: `http://contoh.com/${IP}?token=rahasia`,
    })

    expect(answered.payload.allowed).toBe(true)
    const dump = JSON.stringify(readScanStateEvents())
    expect(dump).not.toContain('contoh.com')
    expect(dump).not.toContain(IP)
  })
})

describe('VGL-30F §4: galat penyimpanan gagal-tertutup di sisi store', () => {
  beforeEach(() => {
    resetScanStateEvents()
  })

  /** Actor dengan penyimpanan yang bisa disakiti, dibalik facade store seperti di Worker. */
  function storeOverActor(probe: DurableStorageProbe) {
    const instance = new ScanStateDurableObject(actorContext(probe), durableEnv())
    const call = createStateRpc(namespaceFor(instance), () => undefined)
    return {
      store: createDurableStateStore(call, createMemoryStateStore()),
      registry: createDurableTokenRegistry(call),
      call,
    }
  }

  it('penolakan storage tidak pernah dibaca sebagai izin, dan tidak jatuh ke memori', async () => {
    const probe = createDurableStorageProbe()
    const { store, registry } = storeOverActor(probe)

    // Satu permintaan berhasil lebih dulu supaya bootstrap tidak ikut kena suntikan galat.
    expect((await store.consumeCounter(`ip:${IP}`, 5, 60_000, NOW)).allowed).toBe(true)

    probe.failNext('SQL_ERROR: penyimpanan tidak tersedia')
    const decision = await store.consumeCounter(`ip:${IP}`, 5, 60_000, NOW)
    expect(decision).toEqual({ allowed: false, retryAfterSeconds: 1 })
    // Store memori isolate PASTI mengizinkan pada kunci/limit yang sama: kalau facade jatuh ke
    // fallback, keputusan ini akan `true`. Jadi hasilnya membuktikan arah gagal-tertutup.
    const memory = createMemoryStateStore()
    expect((await memory.consumeCounter('ip:kunci-lain', 5, 60_000, NOW)).allowed).toBe(true)

    probe.failNext('SQL_ERROR: penyimpanan tidak tersedia')
    expect(await store.hasClearance('turnstile-scan-uid:abc', NOW)).toBe(false)

    probe.failNext('SQL_ERROR: penyimpanan tidak tersedia')
    expect(await registry.reserve('sidik-yang-belum-pernah', NOW)).toBe('reused')
  })

  it('izin yang diterbitkan saat penyimpanan sehat tetap terbaca, dan gagal-tertutup tidak menulis baris', async () => {
    const probe = createDurableStorageProbe()
    const { store } = storeOverActor(probe)

    await store.issueClearance('turnstile-scan-uid:abc', NOW)
    expect(await store.hasClearance('turnstile-scan-uid:abc', NOW)).toBe(true)

    probe.failNext('SQL_ERROR: tulis ditolak')
    await store.issueClearance('turnstile-scan-uid:baru', NOW)
    expect(await store.hasClearance('turnstile-scan-uid:baru', NOW)).toBe(false)
    // Hanya izin yang diterbitkan saat sehat yang ada di tabel: kegagalan tulis tidak
    // meninggalkan baris setengah jadi.
    expect(probe.rowsFor(SCAN_STATE_KINDS.clearance)).toHaveLength(1)
  })

  it('error_code yang tidak dikenali tidak dipercaya sebagai bentuk sah', async () => {
    const records: ScanStateRpcDiagnostic[] = []
    const namespace: ScanStateNamespace = {
      idFromName: () => ({ toString: () => ACTOR_ID }),
      get: () => ({
        fetch: async () =>
          new Response(
            // Kode galat di luar daftar yang dikenali: bentuk respons harus ditolak, bukan dipercaya.
            JSON.stringify({ ok: true, allowed: true, error_code: 'boleh_terus' }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          ),
      }),
    }
    const call = createStateRpc(namespace, (diagnostic) => records.push(diagnostic))
    const store = createDurableStateStore(call, createMemoryStateStore())

    // Bentuk respons ditolak (rpc_validation_error) lalu keputusan diambil memori isolate, sama
    // seperti VGL-28 — bukan dibaca sebagai izin dari saluar yang tidak dikenal.
    const decision = await store.consumeCounter(`ip:${IP}`, 1, 60_000, NOW)
    expect(records.map((record) => record.category)).toEqual(['rpc_validation_error'])
    expect(decision.allowed).toBe(true)
    expect(readScanStateEvents().some((event) => event.event === 'durable_error')).toBe(false)
  })

  it('galat storage actor dan catatan worker dibagikan oleh corr yang sama', async () => {
    const probe = createDurableStorageProbe()
    const { call } = storeOverActor(probe)

    // Satu permintaan sehat lebih dulu. Kegagalan pada PRAGMA versi MEMANG dipulihkan (jalur
    // cadangan `vgl_schema`), jadi yang diuji di sini adalah galat di tengah operasi, yang tidak
    // bisa dipulihkan dan harus gagal-tertutup.
    await call({ action: 'counter', key: 'ip:permintaan-pemanasan', limit: 5, windowMs: 60_000 })

    probe.failNext('SQL_ERROR: gagal di tengah transaksi')
    await call({ action: 'counter', key: `ip:${IP}`, limit: 5, windowMs: 60_000 })

    const events = readScanStateEvents()
    const workerSide = events.filter((event) => event.src === 'worker' && event.event === 'durable_error')
    const actorSide = events.filter((event) => event.src === 'actor')
    expect(workerSide).toHaveLength(1)
    expect(workerSide[0]).toMatchObject({ cat: 'storage_unavailable', op: 'counter', wn: expect.any(String) })
    expect(actorSide.length).toBeGreaterThan(0)
    expect(actorSide.map((event) => event.corr)).toContain(workerSide[0]?.corr)
    expect(JSON.stringify(events)).not.toContain(IP)
  })
})

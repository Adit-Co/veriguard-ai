import { createTestHarness } from 'wrangler'
import type { TestHarness } from 'wrangler'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

/**
 * VGL-28 R5: uji integrasi Durable Object pada runtime sungguhan.
 *
 * `test/scanState.test.ts` membangun namespace tiruan, jadi kelasnya tidak pernah benar-benar
 * didaftarkan sebagai actor workerd. Berkas ini menjalankan `test/support/doProbeWorker.ts` lewat
 * `createTestHarness()` — bundling dan runtime yang sama dengan `wrangler dev`, dengan konfigurasi
 * `test/support/doProbe.wrangler.toml` yang meniru binding dan migrasi produksi. Yang dibuktikan:
 * nama kelas dikenali, stub benar-benar ter-instansiasi, RPC 200 diterima dan divalidasi,
 * pencacah bertahan antar permintaan, dan setiap kegagalan jatuh ke fallback dengan catatan
 * diagnostik.
 *
 * Batasan yang harus dibaca jujur: harness menjalankan SATU isolate Worker, jadi "dua facade" di
 * sini menguji pembagian state pada actor yang sama, bukan pembagian proses antar isolate fisik
 * seperti di produksi.
 */

const PROBE_CONFIG = 'test/support/doProbe.wrangler.toml'
const PROBE_ORIGIN = 'http://probe.test/'

type ProbeRecord = Record<string, unknown>

let server: TestHarness | undefined

async function probe(search: string): Promise<ProbeRecord> {
  const instance = server
  if (!instance) throw new Error('Harness workerd belum siap.')
  const response = await instance.fetch(`${PROBE_ORIGIN}?${search}`)
  return (await response.json()) as ProbeRecord
}

beforeAll(async () => {
  server = createTestHarness({ root: '.', workers: [{ configPath: PROBE_CONFIG }] })
  await server.listen()
}, 180_000)

afterAll(async () => {
  await server?.close()
  server = undefined
})

describe('VGL-28 R5: registrasi dan binding Durable Object di workerd', () => {
  it('binding SCAN_STATE tersedia dan menghasilkan stub yang bisa dipanggil', async () => {
    const result = await probe('probe=registration')

    expect(result.bindingPresent).toBe(true)
    expect(result.idIsString).toBe(true)
    expect(result.stubHasFetch).toBe(true)
  }, 30_000)

  it('permintaan RPC benar-benar sampai ke kelas DO dan dijawab 200 + JSON valid', async () => {
    const result = await probe(
      `probe=raw&payload=${encodeURIComponent(JSON.stringify({ action: 'counter', key: 'probe:raw', limit: 5, windowMs: 60_000 }))}`,
    )

    expect(result.status).toBe(200)
    expect(String(result.contentType)).toContain('application/json')
    expect(JSON.parse(String(result.text))).toMatchObject({ ok: true, allowed: true, used: 1 })
  }, 30_000)

  it('respons penolakan DO memakai status 4xx, bukan 200 kosong', async () => {
    const result = await probe(
      `probe=raw&payload=${encodeURIComponent(JSON.stringify({ action: 'counter', key: 'probe:raw-bad', limit: 'lima', windowMs: 60_000 }))}`,
    )

    expect(result.status).toBe(400)
    expect(JSON.parse(String(result.text))).toMatchObject({ ok: false })
  }, 30_000)
})

describe('VGL-28 R5: rate limiting dan state bersama lewat DO', () => {
  it('dua facade menunjuk satu actor: kuota habis pada batas, bukan di atasnya', async () => {
    const key = `probe:counter:${Date.now()}`
    const result = await probe(`probe=counter&key=${key}&limit=3`)
    const decisions = result.decisions as Array<{ allowed: boolean; used?: number }>

    expect(result.bindingPresent).toBe(true)
    expect(result.diagnostics).toEqual([])
    expect(result.allowed).toBe(3)
    expect(result.blocked).toBe(1)
    // Pencacah jendela tetap melaporkan angka yang sedang berjalan ketika menolak (3), bukan
    // menghapusnya: `used` inilah yang dibaca gerbang eskalasi Turnstile di `index.ts:557-565`.
    expect(decisions.map((decision) => decision.used)).toEqual([1, 2, 3, 3])
  }, 30_000)

  it('31 permintaan serentak pada satu kunci: tepat 30 lolos dan 1 ditolak', async () => {
    // Standin terkontrol untuk eksperimen E1 VGL-27. Dengan kunci yang sama dan DO yang menjawab,
    // actor single-threaded tidak boleh kehilangan increment: 30 lolos + 1 429.
    const key = `probe:parallel:${Date.now()}`
    const result = await probe(`probe=parallel&key=${key}&limit=30`)

    expect(result.allowed).toBe(30)
    expect(result.blocked).toBe(1)
    expect(result.diagnostics).toEqual([])
    expect(result.usages as number[]).toEqual([...Array.from({ length: 30 }, (_, index) => index + 1), 30])
  }, 30_000)

  it('pencacah DO bertahan antar permintaan Worker (instance actor dipakai ulang)', async () => {
    const key = `probe:persist:${Date.now()}`
    const first = await probe(`probe=persist&key=${key}`)
    const second = await probe(`probe=persist&key=${key}`)

    const firstDecision = first.decision as { used?: number }
    const secondDecision = second.decision as { used?: number }

    expect(firstDecision.used).toBe(1)
    expect(secondDecision.used).toBe(2)
  }, 30_000)

  it('facade yang disimpan per isolate (bentuk produksi) tetap memakai DO di permintaan kedua', async () => {
    // `resolveWorkerState` menyimpan satu facade per isolate dan dipakai ulang lintas permintaan
    // — bentuk yang dipakai Worker produksi. Kalau stub tidak ikut dibuat ulang per panggilan,
    // permintaan kedua menghasilkan `rpc_exception` dan diam-diam jatuh ke memori.
    const key = `probe:sharedFacade:${Date.now()}`
    const first = await probe(`probe=sharedFacade&key=${key}`)
    const second = await probe(`probe=sharedFacade&key=${key}`)

    expect(first.facadeCreatedThisRequest).toBe(true)
    expect(second.facadeCreatedThisRequest).toBe(false)
    expect((first.decision as { used?: number }).used).toBe(1)
    expect((second.decision as { used?: number }).used).toBe(2)
    expect(first.diagnostics).toEqual([])
    expect(second.diagnostics).toEqual([])
  }, 30_000)

  it('stub DO yang disimpan lintas permintaan ditolak workerd — sebab kegagalan VGL-27', async () => {
    // Sisi pembuktian: bentuk lama `createStateRpc` menyimpan SATU stub di closure builder.
    // Stub itu hanya sah untuk konteks permintaan tempat ia dibuat; dipakai pada permintaan
    // berikutnya, workerd menolak I/O-nya. Uji ini mengunci alasan perubahan di store.ts.
    const key = `probe:latchedStub:${Date.now()}`
    const first = await probe(`probe=latchedStub&key=${key}`)
    const second = await probe(`probe=latchedStub&key=${key}`)

    expect(first.use).toBe(1)
    expect(first.status).toBe(200)
    expect(first.ok).toBe(true)

    expect(second.use).toBe(2)
    expect(second.failedStage).toBe('fetch')
    expect(second.errorHead as string).toContain('Cannot perform I/O')
  }, 30_000)

  it('izin CAPTCHA yang diterbitkan satu facade terlihat oleh facade lain', async () => {
    const key = `probe:clearance:${Date.now()}`
    const result = await probe(`probe=clearance&key=${key}`)

    expect(result.before).toBe(false)
    expect(result.after).toBe(true)
    expect(result.diagnostics).toEqual([])
  }, 30_000)

  it('satu sidik jari token hanya dapat dicadang sekali walau dari facade berbeda', async () => {
    const key = `probe:token:${Date.now()}`
    const result = await probe(`probe=tokens&key=${key}`)

    expect(result.first).toBe('reserved')
    expect(result.second).toBe('reused')
    // Setelah release, token yang sama boleh dicoba lagi (perilaku verifier yang ada).
    expect(result.third).toBe('reserved')
    expect(result.diagnostics).toEqual([])
  }, 30_000)
})

describe('VGL-28 R5: diagnostik, circuit breaker, dan fallback', () => {
  it('DO yang menolak permintaan tercatat sebagai diagnostik, bukan hilang diam-diam', async () => {
    const result = await probe('probe=rejected')
    const diagnostics = result.diagnostics as Array<Record<string, unknown>>

    expect(result.bindingPresent).toBe(true)
    expect(result.rejectedIsNull).toBe(true)
    expect(diagnostics.length).toBeGreaterThan(0)
    expect(diagnostics[0]).toMatchObject({
      source: 'scan_state_rpc',
      category: 'rpc_http_error',
      operation: 'counter',
      httpStatus: 400,
      fallbackUsed: true,
    })
    expect(typeof diagnostics[0]?.durationMs).toBe('number')
  }, 30_000)

  it('setelah gagal, pemutus arus menahan percobaan berikutnya dan tetap memakai memori', async () => {
    const result = await probe('probe=rejected')
    const diagnostics = result.diagnostics as Array<Record<string, unknown>>
    const categories = diagnostics.map((record) => record.category)

    expect(result.breakerShortCircuitIsNull).toBe(true)
    expect(categories).toContain('rpc_breaker_open')
    // Arah gagal: batas memori tetap menolak permintaan ke-2 pada batas 1, tidak melonggarkan.
    expect(result.fallbackFirst).toBe(true)
    expect(result.fallbackSecond).toBe(false)
    const health = result.health as { durableSuccessCount: number; fallbackCount: number; breakerOpen: boolean }
    expect(health.fallbackCount).toBeGreaterThan(0)
    expect(health.breakerOpen).toBe(true)
  }, 30_000)

  it('diagnostik tidak pernah memuat isi state: hanya nama operasi dan kategori galat', async () => {
    const result = await probe('probe=rejected')
    const serialized = JSON.stringify(result.diagnostics)
    const keyPattern = /probe:reject|203\.0\.113|ip:/

    expect(serialized.length).toBeLessThan(4000)
    expect(keyPattern.test(serialized)).toBe(false)
  }, 30_000)
})

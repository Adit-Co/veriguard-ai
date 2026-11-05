import { createTestHarness } from 'wrangler'
import type { TestHarness } from 'wrangler'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

/**
 * VGL-30F §6: pembuktian W1/W2/W3 pada runtime workerd sungguhan.
 *
 * Yang membedakan berkas ini dari bukti unit di `durableState.test.ts`: di sini actor-nya benar-benar
 * berjalan di workerd dengan SQLite milik runtime, dan `evictDurableObject()` adalah API harness yang
 * mengakhiri instance actor TANPA menghapus penyimpanan SQLite-nya — persis peristiwa yang memproduksi
 * F2 (VGL-30D). Setiap bukti dijalankan dua kali, pada dua konfigurasi yang sama kecuali satu variabel:
 *  - `doProbe.wrangler.toml` (tanpa key ring → jalur durable tidak aktif = perilaku hari ini), dan
 *  - `doProbeDurable.wrangler.toml` (key ring fixture test-only → jalur durable aktif).
 * Kontrol yang pertama itu penting: kalau konfigurasi tanpa kunci juga "bertahan", yang diukur
 * bukan persistensi, tapi evict yang tidak terjadi.
 *
 * Batasan yang harus dibaca jujur: harness menjalankan SATU isolate Worker, jadi berkas ini
 * membuktikan "state selamat dari restart actor", BUKAN "dua isolate fisik berbagi state".
 * Bukti lintas-isolate tetap milik eksperimen staging dan tidak boleh disamakan.
 *
 * Label mengikuti §6 brief: W1 = pencacah, W2 = izin CAPTCHA (clearance), W3 = token anti-replay.
 */

const VOLATILE_CONFIG = 'test/support/doProbe.wrangler.toml'
const DURABLE_CONFIG = 'test/support/doProbeDurable.wrangler.toml'
const PROBE_ORIGIN = 'http://probe.test/'
const DO_CLASS = 'ScanStateDurableObject'
const DO_NAME = 'veriguard-scan-state'

type ProbeRecord = Record<string, unknown>

const harnesses: Array<{ label: string; server: TestHarness }> = []

async function start(label: string, configPath: string): Promise<TestHarness> {
  const server = createTestHarness({ root: '.', workers: [{ configPath }] })
  await server.listen()
  harnesses.push({ label, server })
  return server
}

let volatile: TestHarness
let durable: TestHarness

beforeAll(async () => {
  volatile = await start('volatile', VOLATILE_CONFIG)
  durable = await start('durable', DURABLE_CONFIG)
}, 240_000)

afterAll(async () => {
  for (const entry of harnesses) await entry.server.close()
  harnesses.length = 0
})

async function probe(server: TestHarness, search: string): Promise<ProbeRecord> {
  const response = await server.fetch(`${PROBE_ORIGIN}?${search}`)
  return (await response.json()) as ProbeRecord
}

function step(server: TestHarness, operation: string, key: string, limit = 100): Promise<ProbeRecord> {
  return probe(server, `probe=step&op=${operation}&key=${encodeURIComponent(key)}&limit=${limit}`)
}

async function evict(server: TestHarness): Promise<void> {
  await server.getWorker().evictDurableObject(DO_CLASS, { name: DO_NAME })
}

function logText(server: TestHarness): string {
  return server
    .getLogs()
    .map((log) => {
      const record = log as unknown as { logs?: unknown[]; message?: string }
      if (Array.isArray(record.logs)) return record.logs.map((part) => String(part)).join(' ')
      return typeof record.message === 'string' ? record.message : JSON.stringify(record)
    })
    .join('\n')
}

function events(server: TestHarness): Record<string, unknown>[] {
  const lines: string[] = []
  for (const line of logText(server).split('\n')) {
    const start = line.indexOf('scan_state_evt ')
    if (start === -1) continue
    lines.push(line.slice(start + 'scan_state_evt '.length))
  }
  return lines
    .map((raw) => {
      try {
        return JSON.parse(raw) as Record<string, unknown>
      } catch {
        return undefined
      }
    })
    .filter((event): event is Record<string, unknown> => Boolean(event))
}

describe('VGL-30F W1: pencacah jendela tetap melewati evict actor', () => {
  it('kontrol tanpa key ring: evict menghapus kuota (inilah F2)', async () => {
    const key = `w1:volatile:${Date.now()}`

    expect(await step(volatile, 'counter', key, 3)).toMatchObject({ decision: { allowed: true, used: 1 } })
    await evict(volatile)
    // Instance baru = memori baru: kuota kembali ke 1 padahal jendela 60 detik belum lewat.
    expect(await step(volatile, 'counter', key, 3)).toMatchObject({ decision: { allowed: true, used: 1 } })

    const started = events(volatile).filter((event) => event.event === 'actor_instance_started')
    expect(started.length).toBeGreaterThanOrEqual(2)
    expect(started.every((event) => event.out === 'volatile')).toBe(true)
    expect(new Set(started.map((event) => event.an)).size).toBe(started.length)
  }, 60_000)

  it('dengan key ring: kuota terpakai bertahan, dan tetap bertahan setelah evict berulang', async () => {
    const key = `w1:durable:${Date.now()}`

    expect(await step(durable, 'counter', key, 3)).toMatchObject({ decision: { allowed: true, used: 1 } })
    await evict(durable)
    expect(await step(durable, 'counter', key, 3)).toMatchObject({ decision: { allowed: true, used: 2 } })
    await evict(durable)
    expect(await step(durable, 'counter', key, 3)).toMatchObject({ decision: { allowed: true, used: 3 } })
    await evict(durable)
    expect(await step(durable, 'counter', key, 3)).toMatchObject({ decision: { allowed: false, used: 3 } })

    const restored = events(durable).filter((event) => event.event === 'actor_counters_restored')
    expect(restored.length).toBeGreaterThanOrEqual(2)
    expect(restored.some((event) => Number(event.rows) >= 1)).toBe(true)
    const started = events(durable).filter((event) => event.event === 'actor_instance_started')
    expect(started.some((event) => event.out === 'ok')).toBe(true)
    expect(new Set(started.map((event) => event.an)).size).toBe(started.length)
  }, 60_000)

  it('permintaan serentak pada actor yang baru dihidupkan ulang tidak kehilangan increment', async () => {
    const key = `w1:parallel:${Date.now()}`
    await step(durable, 'counter', key, 1)
    await evict(durable)

    const result = await probe(durable, `probe=parallel&key=${encodeURIComponent(key)}&limit=30`)
    // Batas dihitung dari jendela yang SUDAH terpakai di penyimpanan: 1 terpakai di SQLite + 31
    // percobaan probe pada limit 30 → 29 lolos, 2 ditolak, tanpa duplikasi angka `used`.
    expect(result.blocked).toBe(2)
    expect(result.allowed).toBe(29)
    expect(result.diagnostics).toEqual([])
    const usages = result.usages as number[]
    expect(new Set(usages.filter((value) => value > 0)).size).toBe(29)
  }, 60_000)
})

describe('VGL-30F W2: izin CAPTCHA (clearance) melewati evict actor', () => {
  it('kontrol tanpa key ring: izin hilang saat actor di-evict', async () => {
    const key = `w2:volatile:${Date.now()}`

    await step(volatile, 'issue', key)
    expect(await step(volatile, 'has', key)).toMatchObject({ cleared: true })
    await evict(volatile)
    expect(await step(volatile, 'has', key)).toMatchObject({ cleared: false })
  }, 60_000)

  it('dengan key ring: izin yang diterbitkan tetap terbaca setelah evict', async () => {
    const key = `w2:durable:${Date.now()}`

    await step(durable, 'issue', key)
    await evict(durable)
    expect(await step(durable, 'has', key)).toMatchObject({ cleared: true })

    const restored = events(durable).filter((event) => event.event === 'actor_clearances_restored')
    expect(restored.length).toBeGreaterThanOrEqual(1)
  }, 60_000)
})

describe('VGL-30F W3: token anti-replay melewati evict actor', () => {
  it('kontrol tanpa key ring: token yang sama boleh dicadang lagi setelah evict', async () => {
    const fingerprint = `w3:volatile:${Date.now()}`

    expect(await step(volatile, 'reserve', fingerprint)).toMatchObject({ reservation: 'reserved' })
    await evict(volatile)
    expect(await step(volatile, 'reserve', fingerprint)).toMatchObject({ reservation: 'reserved' })
  }, 60_000)

  it('dengan key ring: token terpakai tetap ditolak setelah actor dihidupkan ulang', async () => {
    const fingerprint = `w3:durable:${Date.now()}`

    expect(await step(durable, 'reserve', fingerprint)).toMatchObject({ reservation: 'reserved' })
    await evict(durable)
    expect(await step(durable, 'reserve', fingerprint)).toMatchObject({ reservation: 'reused' })

    const restored = events(durable).filter((event) => event.event === 'actor_tokens_restored')
    expect(restored.length).toBeGreaterThanOrEqual(1)
    expect(restored.some((event) => Number(event.rows) >= 1)).toBe(true)
  }, 60_000)

  it('rilis token yang belum tertukar tetap membuka jalan setelah evict', async () => {
    const fingerprint = `w3:release:${Date.now()}`

    expect(await step(durable, 'reserve', fingerprint)).toMatchObject({ reservation: 'reserved' })
    await step(durable, 'release', fingerprint)
    await evict(durable)
    expect(await step(durable, 'reserve', fingerprint)).toMatchObject({ reservation: 'reserved' })
  }, 60_000)
})

describe('VGL-30F §6: bentuk penyimpanan dan catatan di workerd', () => {
  it('evict melepas memori instance tetapi penyimpanan actor tetap terdaftar', async () => {
    // `listDurableObjectIds` mendaftar instance yang punya penyimpanan SQLite di runtime. Setelah
    // evict, id-nya tetap ada — yang dibuang hanyalah memori instance. Karena file penyimpanan
    // dibuat runtime sejak actor di-instansiasi (juga pada konfigurasi tanpa key ring), yang membuktikan
    // persistensi STATE adalah W1/W2/W3 di atas, bukan ada/tidaknya file ini.
    const before = await durable.getWorker().listDurableObjectIds(DO_CLASS)
    expect(before.length).toBeGreaterThan(0)
    await evict(durable)
    expect(await durable.getWorker().listDurableObjectIds(DO_CLASS)).toEqual(before)
  }, 60_000)

  it('bentuk baris dibuktikan di unit; di workerd yang diamati hanyalah keluaran DO dan catatannya', async () => {
    // Membaca `vgl_state` langsung dari harness butuh `getDurableObjectStorage().exec()`, yang hanya
    // bekerja bila kelasnya `extends DurableObject` (RPC). Kelas produksi sengaja tidak diubah, jadi
    // bentuk baris (digest HMAC berversi, tanpa teks kunci) dibuktikan di `scanState.test.ts` dan
    // `durableState.test.ts` dengan SQLite sungguhan. Yang bisa diamati dari sini: tidak ada teks
    // kunci, IP, atau materi kunci yang keluar lewat catatan maupun respons DO.
    const key = `priv:${Date.now()}`
    const raw = await probe(durable, `probe=raw&payload=${encodeURIComponent(JSON.stringify({
      action: 'counter',
      key: `ip:203.0.113.77:${key}`,
      limit: 5,
      windowMs: 60_000,
    }))}`)

    expect(raw.status).toBe(200)
    expect(String(raw.text)).not.toContain('203.0.113.77')
    expect(String(raw.text)).not.toContain(key)
    expect(String(raw.text)).not.toContain('hanya-untuk-uji-lokal')

    const dump = logText(durable)
    expect(dump).not.toContain('203.0.113.77')
    expect(dump).not.toContain(key)
    expect(dump).not.toContain('hanya-untuk-uji-lokal')
  }, 60_000)

  it('instance actor yang baru tercatat dengan nonce berbeda, tanpa isi state', async () => {
    const key = `w4:${Date.now()}`
    await step(durable, 'counter', key, 5)
    await evict(durable)
    await step(durable, 'counter', key, 5)

    const started = events(durable).filter(
      (event) => event.event === 'actor_instance_started' && event.out === 'ok',
    )
    expect(started.length).toBeGreaterThanOrEqual(2)
    expect(new Set(started.map((event) => event.an)).size).toBe(started.length)
    // Nonce berubah, actor id tetap: inilah pembeda "instance baru" dari "actor lain".
    expect(new Set(started.map((event) => event.aid)).size).toBe(1)

    const dump = JSON.stringify(events(durable))
    expect(dump).not.toContain(key)
    expect(dump).not.toContain('203.0.113')
    expect(dump).not.toContain('hanya-untuk-uji-lokal')
  }, 60_000)
})

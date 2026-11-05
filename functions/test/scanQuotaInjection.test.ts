import { beforeEach, describe, expect, it, vi } from 'vitest'
import { resetScanState } from './helpers/scanState.js'
import { inFlightScanCount } from '../src/scanners/inFlight.js'
import { runMultiSourceScan } from '../src/scanners/service.js'
import {
  SCAN_RATE_LIMIT,
  consumeScanRateLimit,
  resetScanRateLimit,
} from '../src/scanners/rateLimit.js'
import type { ProviderAdapter, ProviderCheck, ScannerProviderId } from '../src/scanners/types.js'
import type { RateLimitDecision } from '../src/state/stores.js'

const CLEAN_CHECK: ProviderCheck = {
  status: 'success',
  verdict: 'clean',
  score: 0,
  summary: 'Tidak ditemukan indikasi.',
  signals: [],
  reason: null,
}

const ALLOW: RateLimitDecision = { allowed: true, retryAfterSeconds: 0 }

function adapter(id: ScannerProviderId, check: ProviderAdapter['check']): ProviderAdapter {
  return { id, label: id, isConfigured: () => true, check }
}

function blocked(retryAfterSeconds = 60): RateLimitDecision {
  return { allowed: false, retryAfterSeconds }
}

beforeEach(() => {
  resetScanState()
  resetScanRateLimit()
})

describe('kuota pemeriksaan yang disuntikkan dari state bersama', () => {
  it('memakai konsumen kuota pemanggil, bukan pencacah memori proses', async () => {
    const check = vi.fn(async () => CLEAN_CHECK)
    const consume = vi.fn(() => blocked(120))

    const result = await runMultiSourceScan({
      uid: 'durable-blocked',
      url: 'https://contoh.com/a',
      adapters: [adapter('urlscan', check)],
      consumeRateLimit: consume,
    })

    // Permintaan ditolak kuota sebelum ada provider yang keluar jaringan.
    expect(consume).toHaveBeenCalledWith('durable-blocked', expect.any(Number))
    expect(check).not.toHaveBeenCalled()
    expect(result.providers.map((provider) => provider.status)).toEqual(['rate_limited'])
    expect(result.providers[0].reason).toContain('120 detik')
  })

  it('melayani permintaan ketika state bersama mengizinkan', async () => {
    const check = vi.fn(async () => CLEAN_CHECK)
    const consume = vi.fn(() => ALLOW)

    const result = await runMultiSourceScan({
      uid: 'durable-allowed',
      url: 'https://contoh.com/b',
      adapters: [adapter('virustotal', check)],
      consumeRateLimit: consume,
    })

    expect(check).toHaveBeenCalledTimes(1)
    expect(result.providers.map((provider) => provider.status)).toEqual(['success'])
  })

  it('menerima konsumen asinkron karena Durable Object berada di balik RPC', async () => {
    const check = vi.fn(async () => CLEAN_CHECK)
    const result = await runMultiSourceScan({
      uid: 'durable-async',
      url: 'https://contoh.com/c',
      adapters: [adapter('otx', check)],
      consumeRateLimit: async () => Promise.resolve(blocked(5)),
    })

    expect(check).not.toHaveBeenCalled()
    expect(result.providers[0].status).toBe('rate_limited')
  })

  it('tidak menyentuh kuota state bersama untuk URL yang diblokir privasi', async () => {
    const consume = vi.fn(() => ALLOW)
    const check = vi.fn(async () => CLEAN_CHECK)

    const result = await runMultiSourceScan({
      uid: 'durable-sensitive',
      url: 'https://example.com/reset?token=rahasia123456',
      adapters: [adapter('openphish', check)],
      consumeRateLimit: consume,
    })

    expect(consume).not.toHaveBeenCalled()
    expect(check).not.toHaveBeenCalled()
    expect(result.sensitiveUrl).toBe(true)
  })

  it('kuota state bersama tidak ikut terpakai ketika pemanggil menyuntikkan konsumen', async () => {
    // Ini inti perbaikannya: pemanggil produksi (Worker dengan Durable Object) menghitung
    // di state bersama, sementara pencacah memori proses tetap utuh untuk deployment
    // Functions standalone yang tidak menyuntikkan apa pun.
    const before = consumeScanRateLimit('durable-isolated', Date.now())
    expect(before.allowed).toBe(true)

    await runMultiSourceScan({
      uid: 'durable-isolated',
      url: 'https://contoh.com/d',
      adapters: [adapter('threatfox', vi.fn(async () => CLEAN_CHECK))],
      consumeRateLimit: vi.fn(() => ALLOW),
    })

    const after = consumeScanRateLimit('durable-isolated', Date.now())
    expect(after.allowed).toBe(true)
    expect(after.used).toBe(2)
    expect(before.used).toBe(1)

    // Tanpa konsumen, jalur lama masih memakainya dan tetap bisa penuh. Batas loop harus
    // sebanyak maxScans: limiter menolak ketika jumlah pemakaian sudah >= limit, jadi
    // maxScans - 1 konsumsi masih menyisakan satu jatah dan permintaannya belum terisi penuh.
    for (let index = 0; index < SCAN_RATE_LIMIT.maxScans; index += 1) {
      await runMultiSourceScan({
        uid: 'memory-only',
        url: 'https://contoh.com/e',
        adapters: [adapter('radar', vi.fn(async () => CLEAN_CHECK))],
      })
    }
    expect(consumeScanRateLimit('memory-only', Date.now()).allowed).toBe(false)
  })

  // Kontrak yang diaudit lebih dulu di service.ts:677 dan :336. Titik masuk publik memakai
  // konsumen SATU kali per permintaan lalu meneruskan hasilnya sebagai gerbang yang sudah
  // dinilai; executeScan hanya menghitung sendiri bila gerbangnya belum ada. Karena itu
  // kegagalan konsumen harus menghentikan permintaan (fail-closed), dan pekerjaan yang
  // dipakai bersama tidak boleh menambah jatah yang sudah dibayar.
  it('permintaan gagal tertutup ketika konsumen kuota sinkron mengangkat galat', async () => {
    const check = vi.fn(async () => CLEAN_CHECK)
    const consume = vi.fn(() => {
      throw new Error('state kuota tidak dapat dihubungi')
    })

    await expect(
      runMultiSourceScan({
        uid: 'boom-sync',
        url: 'https://contoh.com/f',
        adapters: [adapter('otx', check)],
        consumeRateLimit: consume,
      }),
    ).rejects.toThrow(/state kuota tidak dapat dihubungi/)

    expect(consume).toHaveBeenCalledTimes(1)
    expect(check).not.toHaveBeenCalled()
    // Tidak ada pekerjaan yang tertinggal di registry sehingga permintaan berikutnya ikut macet.
    expect(inFlightScanCount()).toBe(0)
  })

  it('permintaan gagal tertutup ketika konsumen asinkron ditolak (Durable Object di balik RPC)', async () => {
    const check = vi.fn(async () => CLEAN_CHECK)
    const consume = vi.fn(async () => {
      throw new Error('kuota DO gagal')
    })

    await expect(
      runMultiSourceScan({
        uid: 'boom-async',
        url: 'https://contoh.com/g',
        adapters: [adapter('phish', check)],
        consumeRateLimit: consume,
      }),
    ).rejects.toThrow(/kuota DO gagal/)

    expect(check).not.toHaveBeenCalled()
    expect(inFlightScanCount()).toBe(0)
  })

  it('pekerjaan bersama memakai satu jatah per permintaan dan tidak menambah konsumsi', async () => {
    let calls = 0
    let releaseGate: () => void = () => undefined
    const shared = adapter('phish', async () => {
      calls += 1
      await new Promise<void>((resolve) => {
        releaseGate = resolve
      })
      return CLEAN_CHECK
    })
    const consume = vi.fn(() => ALLOW)

    const first = runMultiSourceScan({
      uid: 'share-a',
      url: 'https://contoh.com/h',
      adapters: [shared],
      consumeRateLimit: consume,
    })

    for (let attempt = 0; attempt < 200 && !(calls > 0 && inFlightScanCount() === 1); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0))
    }
    expect(calls).toBe(1)

    const second = runMultiSourceScan({
      uid: 'share-b',
      url: 'https://contoh.com/h',
      adapters: [shared],
      consumeRateLimit: consume,
    })

    // Permintaan kedua ikut pekerjaan yang sedang berjalan, bukan memulai pekerjaan baru.
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(inFlightScanCount()).toBe(1)
    expect(calls).toBe(1)
    expect(consume).toHaveBeenCalledTimes(2)
    expect(consume.mock.calls.map((entry) => entry[0])).toEqual(['share-a', 'share-b'])

    releaseGate()
    const [a, b] = await Promise.all([first, second])

    expect(a.cache?.deduplicated).toBeUndefined()
    expect(b.cache?.deduplicated).toBe(true)
    expect(calls).toBe(1)
    // Dua permintaan, satu pelaksanaan: tetap dua konsumsi dan tidak lebih. Tidak ada permintaan
    // yang lolos tanpa dihitung, dan tidak ada jatah hangus karena pekerjaan dibagi.
    expect(consume).toHaveBeenCalledTimes(2)
    expect(inFlightScanCount()).toBe(0)
  })

  it('permintaan yang ditolak kuota tidak ikut mengambil pekerjaan permintaan lain', async () => {
    let calls = 0
    let releaseGate: () => void = () => undefined
    const shared = adapter('phish', async () => {
      calls += 1
      await new Promise<void>((resolve) => {
        releaseGate = resolve
      })
      return CLEAN_CHECK
    })

    const first = runMultiSourceScan({
      uid: 'early-owner',
      url: 'https://contoh.com/i',
      adapters: [shared],
      consumeRateLimit: vi.fn(() => ALLOW),
    })

    for (let attempt = 0; attempt < 200 && !(calls > 0 && inFlightScanCount() === 1); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0))
    }

    const late = await runMultiSourceScan({
      uid: 'late-blocked',
      url: 'https://contoh.com/i',
      adapters: [shared],
      consumeRateLimit: vi.fn(() => blocked(30)),
    })

    expect(late.providers[0]?.status).toBe('rate_limited')
    expect(late.cache?.deduplicated).toBeUndefined()

    releaseGate()
    await first
    expect(calls).toBe(1)
    expect(inFlightScanCount()).toBe(0)
  })
})

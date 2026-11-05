import { createHash } from 'node:crypto'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Timestamp } from 'firebase-admin/firestore'
import { FakeFirestore } from './helpers/fakeFirestore.js'
import {
  dnsVerdict,
  enforceCommunityReportRetention,
  formatRetentionLog,
  resolveRetentionDays,
} from '../src/community/retention.js'

vi.mock('node:dns', () => ({
  promises: { resolve4: vi.fn(), resolve6: vi.fn() },
}))

const DAY_MS = 24 * 60 * 60 * 1000
const NOW = Date.parse('2026-10-20T04:00:00Z')

const { promises: dnsMock } = await import('node:dns')
const resolver = dnsMock as unknown as {
  resolve4: ReturnType<typeof vi.fn>
  resolve6: ReturnType<typeof vi.fn>
}

function hashUrl(url: string): string {
  return createHash('sha256').update(url).digest('hex')
}

function summaryPath(url: string): string {
  return `communitySummaries/${hashUrl(url)}`
}

let db: FakeFirestore
let seedSeq = 0

function seedReport(
  url: string,
  options: Partial<Record<string, unknown>> = {},
  uid = 'uid-owner',
): string {
  seedSeq += 1
  const path = `users/${uid}/communityReports/laporan-${seedSeq}`
  db.seed(path, {
    ownerId: 'uid-owner',
    userName: 'Pemilik',
    urlHash: hashUrl(url),
    url,
    hostname: new URL(url).hostname,
    category: 'phishing',
    reason: 'Halaman meminta kata sandi lewat formulir yang menyerupai bank.',
    createdAt: Timestamp.fromMillis(NOW - 120 * DAY_MS),
    updatedAt: Timestamp.fromMillis(NOW - 120 * DAY_MS),
    ...options,
  })
  return path
}

function seedSummary(url: string, reportCount: number, reporterCount = reportCount): void {
  db.seed(summaryPath(url), {
    url,
    urlHash: hashUrl(url),
    hostname: new URL(url).hostname,
    reportCount,
    reporterCount,
    categoryCounts: { phishing: reportCount },
    updatedAt: Timestamp.fromMillis(NOW - 120 * DAY_MS),
  })
}

beforeEach(() => {
  db = new FakeFirestore()
  seedSeq = 0
  resolver.resolve4.mockReset()
  resolver.resolve6.mockReset()
})

describe('konfigurasi masa retensi', () => {
  it('memakai 90 hari sebagai baku dan dipaksa tetap di rentang 30-90', () => {
    expect(resolveRetentionDays(undefined)).toBe(90)
    expect(resolveRetentionDays('')).toBe(90)
    expect(resolveRetentionDays('not-a-number')).toBe(90)
    expect(resolveRetentionDays('45')).toBe(45)
    expect(resolveRetentionDays('7')).toBe(30)
    expect(resolveRetentionDays('3650')).toBe(90)
  })
})

describe('bukti tidakaktif dari DNS', () => {
  it('hanya NXDOMAIN pada semua tipe record yang dihitung sebagai tidakaktif', async () => {
    const nxdomain = Object.assign(new Error('queryA ENOTFOUND'), { code: 'ENOTFOUND' })
    resolver.resolve4.mockRejectedValue(nxdomain)
    resolver.resolve6.mockRejectedValue(nxdomain)

    await expect(dnsVerdict('situs-mati.id')).resolves.toBe('inactive')
  })

  it('timeout atau SERVFAIL bukan bukti mati', async () => {
    const transient = Object.assign(new Error('queryA EAI_AGAIN'), { code: 'EAI_AGAIN' })
    resolver.resolve4.mockRejectedValue(transient)
    resolver.resolve6.mockRejectedValue(transient)

    await expect(dnsVerdict('situs-masalah.id')).resolves.toBe('inconclusive')
  })

  it('satu record yang masih terjawab berarti situs hidup', async () => {
    resolver.resolve4.mockResolvedValue(['93.184.216.34'])
    resolver.resolve6.mockRejectedValue(
      Object.assign(new Error('queryAAAA ENOTFOUND'), { code: 'ENOTFOUND' }),
    )

    await expect(dnsVerdict('situs-hidup.id')).resolves.toBe('reachable')
  })

  it('tidak memakai NXDOMAIN untuk literal IP sebagai bukti mati', async () => {
    await expect(dnsVerdict('8.8.8.8')).resolves.toBe('inconclusive')
    await expect(dnsVerdict('[2001:4860:4860::8888]')).resolves.toBe('inconclusive')

    expect(resolver.resolve4).not.toHaveBeenCalled()
    expect(resolver.resolve6).not.toHaveBeenCalled()
  })
})

describe('pembersihan retensi laporan komunitas', () => {
  it('tidak menghapus hanya berdasarkan umur: pemeriksaan pertama hanya mencatat bukti', async () => {
    const url = 'https://situs-lama.id/login'
    const path = seedReport(url)

    const outcome = await enforceCommunityReportRetention({
      db: db as never,
      verifyInactivity: async () => 'inactive',
      now: () => NOW,
      retentionDays: 90,
      batchSize: 25,
    })

    expect(outcome).toMatchObject({ scanned: 1, deleted: 0, retained: 1, retentionDays: 90 })
    expect(db.has(path)).toBe(true)
    expect(db.peek(path)?.retentionChecks).toBe(1)
    expect(db.peek(path)?.lastRetentionCheckAt).toBeInstanceOf(Timestamp)
    expect(db.peek(path)?.createdAt).toBeInstanceOf(Timestamp)
  })

  it('menghapus setelah tua DAN ketidakhidupan terkonfirmasi berulang dengan jeda', async () => {
    const url = 'https://situs-mati.id/promo'
    const path = seedReport(url, {
      retentionChecks: 1,
      lastRetentionCheckAt: Timestamp.fromMillis(NOW - 8 * DAY_MS),
    })
    seedSummary(url, 1)

    const outcome = await enforceCommunityReportRetention({
      db: db as never,
      verifyInactivity: async () => 'inactive',
      now: () => NOW,
      retentionDays: 90,
      batchSize: 25,
    })

    expect(outcome.deleted).toBe(1)
    expect(outcome.retained).toBe(0)
    expect(db.has(path)).toBe(false)
    expect(db.peek(summaryPath(url))?.reportCount).toBe(0)
    expect(db.peek(summaryPath(url))?.reporterCount).toBe(0)
    expect(db.peek(summaryPath(url))?.categoryCounts).toEqual({})
  })

  it('jeda antar-pemeriksaan yang terlalu singkat belum cukup untuk menghapus', async () => {
    const url = 'https://situs-baru-mati.id/promo'
    const path = seedReport(url, {
      retentionChecks: 1,
      lastRetentionCheckAt: Timestamp.fromMillis(NOW - DAY_MS),
    })

    const outcome = await enforceCommunityReportRetention({
      db: db as never,
      verifyInactivity: async () => 'inactive',
      now: () => NOW,
      retentionDays: 90,
      batchSize: 25,
    })

    expect(outcome.deleted).toBe(0)
    expect(db.has(path)).toBe(true)
    // Stempel pemeriksaan pertama tidak boleh digeser, kalau tidak jeda 7 hari tak pernah tercapai.
    expect(db.peek(path)?.retentionChecks).toBe(1)
    expect(db.peek(path)?.lastRetentionCheckAt).toEqual(
      Timestamp.fromMillis(NOW - DAY_MS),
    )
  })

  it('menghapus pada pemeriksaan harian berikutnya setelah jeda 7 hari terpenuhi', async () => {
    const url = 'https://situs-mati-lambat.id/promo'
    const path = seedReport(url, {
      retentionChecks: 1,
      lastRetentionCheckAt: Timestamp.fromMillis(NOW - DAY_MS),
    })
    seedSummary(url, 1)

    for (const daysLater of [2, 4, 6]) {
      const outcome = await enforceCommunityReportRetention({
        db: db as never,
        verifyInactivity: async () => 'inactive',
        now: () => NOW - DAY_MS + daysLater * DAY_MS,
        retentionDays: 90,
        batchSize: 25,
      })
      expect(outcome.deleted).toBe(0)
      expect(db.peek(path)?.lastRetentionCheckAt).toEqual(Timestamp.fromMillis(NOW - DAY_MS))
    }

    const finalOutcome = await enforceCommunityReportRetention({
      db: db as never,
      verifyInactivity: async () => 'inactive',
      now: () => NOW + 7 * DAY_MS,
      retentionDays: 90,
      batchSize: 25,
    })

    expect(finalOutcome.deleted).toBe(1)
    expect(db.has(path)).toBe(false)
    expect(db.peek(summaryPath(url))?.reportCount).toBe(0)
  })

  it('jumlah akun unik tidak berkurang saat pemilik masih punya laporan lain untuk URL itu', async () => {
    const url = 'https://situs-dua-laporan.id/promo'
    seedReport(url, {
      createdAt: Timestamp.fromMillis(NOW - 150 * DAY_MS),
      retentionChecks: 1,
      lastRetentionCheckAt: Timestamp.fromMillis(NOW - 8 * DAY_MS),
    })
    seedReport(url, {
      createdAt: Timestamp.fromMillis(NOW - 140 * DAY_MS),
      retentionChecks: 1,
      lastRetentionCheckAt: Timestamp.fromMillis(NOW - 8 * DAY_MS),
    })
    seedSummary(url, 2, 1)

    const outcome = await enforceCommunityReportRetention({
      db: db as never,
      verifyInactivity: async () => 'inactive',
      now: () => NOW,
      retentionDays: 90,
      batchSize: 25,
    })

    expect(outcome.deleted).toBe(2)
    expect(db.peek(summaryPath(url))?.reportCount).toBe(0)
    expect(db.peek(summaryPath(url))?.reporterCount).toBe(0)
  })

  it('host yang kembali hidup membatalkan bukti lama tanpa menghapus laporan', async () => {
    const url = 'https://situs-pulih.id/login'
    const path = seedReport(url, {
      retentionChecks: 2,
      lastRetentionCheckAt: Timestamp.fromMillis(NOW - 30 * DAY_MS),
    })

    const outcome = await enforceCommunityReportRetention({
      db: db as never,
      verifyInactivity: async () => 'reachable',
      now: () => NOW,
      retentionDays: 90,
      batchSize: 25,
    })

    expect(outcome.deleted).toBe(0)
    expect(db.has(path)).toBe(true)
    expect(db.peek(path)?.retentionChecks).toBe(0)
  })

  it('hasil yang belum pasti atau verifier yang gagal tidak pernah menghapus', async () => {
    const unclear = seedReport('https://situs-ragu.id/login', {
      retentionChecks: 3,
      lastRetentionCheckAt: Timestamp.fromMillis(NOW - 40 * DAY_MS),
    })
    const broken = seedReport('https://situs-error.id/login', {
      retentionChecks: 3,
      lastRetentionCheckAt: Timestamp.fromMillis(NOW - 40 * DAY_MS),
      hostname: 'situs-error-dns.id',
    })

    const outcome = await enforceCommunityReportRetention({
      db: db as never,
      verifyInactivity: async (hostname) => {
        if (hostname === 'situs-error-dns.id') throw new Error('DNS timeout')
        return 'inconclusive'
      },
      now: () => NOW,
      retentionDays: 90,
      batchSize: 25,
    })

    expect(outcome.deleted).toBe(0)
    expect(outcome.scanned).toBe(2)
    expect(outcome.detail).toBe('verifier-inconclusive:1')
    expect(db.has(unclear)).toBe(true)
    expect(db.has(broken)).toBe(true)
  })

  it('laporan tanpa stempel waktu dipertahankan karena umurnya tidak pasti', async () => {
    const url = 'https://situs-tanpa-stempel.id/login'
    const path = seedReport(url, {
      createdAt: null,
      retentionChecks: 2,
      lastRetentionCheckAt: Timestamp.fromMillis(NOW - 20 * DAY_MS),
    })

    const outcome = await enforceCommunityReportRetention({
      db: db as never,
      verifyInactivity: async () => 'inactive',
      now: () => NOW,
      retentionDays: 90,
      batchSize: 25,
    })

    expect(outcome.deleted).toBe(0)
    expect(db.has(path)).toBe(true)
  })

  it('laporan yang masih di dalam masa retensi tidak ikut dipindai', async () => {
    seedReport('https://situs-baru.id/login', {
      createdAt: Timestamp.fromMillis(NOW - 10 * DAY_MS),
      updatedAt: Timestamp.fromMillis(NOW - 10 * DAY_MS),
    })

    const outcome = await enforceCommunityReportRetention({
      db: db as never,
      verifyInactivity: async () => 'inactive',
      now: () => NOW,
      retentionDays: 90,
      batchSize: 25,
    })

    expect(outcome).toMatchObject({ scanned: 0, deleted: 0, detail: 'empty' })
  })

  it('satu run dibatasi satu batch agar tidak menghapus massal', async () => {
    for (let index = 0; index < 5; index += 1) {
      seedReport(`https://situs-${index}.id/promo`, {
        retentionChecks: 1,
        lastRetentionCheckAt: Timestamp.fromMillis(NOW - 8 * DAY_MS),
      })
    }

    const outcome = await enforceCommunityReportRetention({
      db: db as never,
      verifyInactivity: async () => 'inactive',
      now: () => NOW,
      retentionDays: 90,
      batchSize: 2,
    })

    expect(outcome.scanned).toBe(2)
    expect(outcome.deleted).toBe(2)
    expect(db.paths().filter((path) => path.includes('/communityReports/'))).toHaveLength(3)
  })

  it('log retensi tidak memuat isi laporan, URL, atau nama pelapor', async () => {
    seedReport('https://rahasia-pelapor.id/login', {
      retentionChecks: 1,
      lastRetentionCheckAt: Timestamp.fromMillis(NOW - 8 * DAY_MS),
    })

    const outcome = await enforceCommunityReportRetention({
      db: db as never,
      verifyInactivity: async () => 'inactive',
      now: () => NOW,
      retentionDays: 90,
      batchSize: 25,
    })

    const line = formatRetentionLog(outcome)
    expect(line).not.toContain('rahasia-pelapor')
    expect(line).not.toContain('Pemilik')
    expect(line).not.toContain('kata sandi')
    expect(JSON.parse(line)).toMatchObject({ event: 'community_report_retention', deleted: 1 })
  })
})

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => {
  class FakeTimestamp {
    private readonly millis: number

    constructor(millis: number) {
      this.millis = millis
    }

    toMillis() {
      return this.millis
    }

    toDate() {
      return new Date(this.millis)
    }

    static fromMillis(millis: number) {
      return new FakeTimestamp(millis)
    }
  }

  return {
    FakeTimestamp,
    getFirebaseClient: vi.fn(),
    syncUserProfile: vi.fn(),
    collection: vi.fn(),
    doc: vi.fn(),
    getCountFromServer: vi.fn(),
    getDoc: vi.fn(),
    getDocs: vi.fn(),
    limit: vi.fn(),
    orderBy: vi.fn(),
    query: vi.fn(),
    runTransaction: vi.fn(),
    serverTimestamp: vi.fn(() => ({ __serverTimestamp: true })),
    where: vi.fn(),
  }
})

vi.mock('firebase/firestore', () => ({
  Timestamp: mocks.FakeTimestamp,
  collection: mocks.collection,
  doc: mocks.doc,
  getCountFromServer: mocks.getCountFromServer,
  getDoc: mocks.getDoc,
  getDocs: mocks.getDocs,
  limit: mocks.limit,
  orderBy: mocks.orderBy,
  query: mocks.query,
  runTransaction: mocks.runTransaction,
  serverTimestamp: mocks.serverTimestamp,
  where: mocks.where,
}))

vi.mock('../firebase/client', () => ({ getFirebaseClient: mocks.getFirebaseClient }))
vi.mock('../firebase/config', () => ({ isFirebaseConfigured: true }))
vi.mock('../firebase/profile', () => ({ syncUserProfile: mocks.syncUserProfile }))

import {
  getCommunityContext,
  listLatestCommunityReports,
  resetCommunityCacheForTests,
  submitCommunityReport,
} from './communityFirestoreService'
import { CommunityServiceError } from './communityErrors'
import {
  COMMUNITY_CONTEXT_SCAN_LIMIT,
  COMMUNITY_DAILY_FEED_LIMIT,
  COMMUNITY_LATEST_LIMIT,
  communityDailyFeedDayEndMs,
  communityDailyFeedDayId,
  communityDailyFeedDayStartMs,
  communityDayId,
  communityUrlHash,
} from './sparkProtocol'
import { COMMUNITY_DAILY_LIMIT_MESSAGE, type CommunityCategory } from './types'
import { maskReporterName } from './reporterName'

const NOW = Date.parse('2026-10-25T06:00:00Z')
const TARGET_URL = 'https://contoh.id/login'
const OTHER_URL = 'https://contoh.id/admin'
const INPUT = {
  url: TARGET_URL,
  category: 'phishing' as CommunityCategory,
  reason: 'Formulir meminta kata sandi dan kode OTP sekaligus.',
}
const REPORTER_KEY = 'a'.repeat(64)
const OTHER_REPORTER_KEY = 'b'.repeat(64)

type State = {
  exists: boolean
  data?: Record<string, unknown>
}

type Ref = {
  kind:
    | 'collection'
    | 'profile'
    | 'key'
    | 'marker'
    | 'report'
    | 'feedHead'
    | 'feedEntry'
    | 'dailyReports'
    | 'dailyEntry'
    | 'other'
  path: string
  segments: string[]
}

let nowMs = NOW
let count = 0
let profileState: State
let keyState: State
let markerState: State
let reportState: State
let feedHeadState: State
let feedEntryStates: Map<string, State>
let scanDocs: { id: string; data: Record<string, unknown> }[]
let dailyDocs: { id: string; data: Record<string, unknown> }[]
let sets: { ref: Ref; data: Record<string, unknown> }[]
let user: ReturnType<typeof userFixture>

function snapshot(state: State) {
  return { exists: () => state.exists, data: () => (state.exists ? state.data : undefined) }
}

function userFixture(overrides: Record<string, unknown> = {}) {
  return {
    uid: 'user-1',
    email: 'dewi@example.com',
    displayName: 'Dewi',
    emailVerified: true,
    isAnonymous: false,
    getIdTokenResult: vi.fn(async () => ({
      issuedAtTime: new Date(nowMs).toISOString(),
      expirationTime: new Date(nowMs + 3_600_000).toISOString(),
      authTime: new Date(nowMs).toISOString(),
      claims: { email_verified: true },
    })),
    getIdToken: vi.fn(async () => 'token-rahasia'),
    ...overrides,
  }
}

function reportData(overrides: Record<string, unknown> = {}) {
  return {
    reporterKey: REPORTER_KEY,
    userName: 'Rani(sensor)',
    category: 'phishing',
    reason: 'Formulir meminta kata sandi bank.',
    createdAt: new mocks.FakeTimestamp(NOW - 60_000),
    updatedAt: new mocks.FakeTimestamp(NOW - 60_000),
    ...overrides,
  }
}

function scanEntry(id: string, overrides: Record<string, unknown> = {}) {
  return { id, data: reportData(overrides) }
}

function latestEntryData(overrides: Record<string, unknown> = {}) {
  return {
    reporterKey: REPORTER_KEY,
    userName: 'Rani(sensor)',
    reportedUrl: 'https://contoh.id/login',
    hostname: 'contoh.id',
    category: 'phishing',
    reason: 'Formulir meminta kata sandi bank lewat halaman palsu.',
    createdAt: new mocks.FakeTimestamp(NOW - 3_600_000),
    ...overrides,
  }
}

function dailyEntryData(overrides: Record<string, unknown> = {}) {
  return {
    userName: 'Rani(sensor)',
    reportedUrl: 'https://contoh.id/login',
    hostname: 'contoh.id',
    category: 'phishing',
    reason: 'Formulir meminta kata sandi bank lewat halaman palsu.',
    createdAt: new mocks.FakeTimestamp(NOW - 3_600_000),
    ...overrides,
  }
}

function dailyEntry(id: string, overrides: Record<string, unknown> = {}) {
  return { id, data: dailyEntryData(overrides) }
}

function stateFor(ref: Ref): State {
  if (ref.kind === 'key') return keyState
  if (ref.kind === 'marker') return markerState
  if (ref.kind === 'report') return reportState
  if (ref.kind === 'profile') return profileState
  if (ref.kind === 'feedHead') return feedHeadState
  if (ref.kind === 'feedEntry') {
    return feedEntryStates.get(ref.segments[3]) ?? { exists: false }
  }
  return { exists: false }
}

function makeRef(segments: string[]): Ref {
  let kind: Ref['kind'] = 'other'
  if (segments.includes('communityLatestReports') && segments.includes('entries')) {
    kind = 'feedEntry'
  } else if (segments[0] === 'communityLatestReports' && segments[1] === 'global') {
    kind = 'feedHead'
  } else if (segments[0] === 'communityDailyReports' && segments.length === 4) {
    kind = 'dailyEntry'
  } else if (segments[0] === 'communityDailyReports' && segments.length === 3) {
    kind = 'dailyReports'
  } else if (segments.includes('communityReports') && segments.includes('reports')) {
    kind = 'report'
  } else if (segments.includes('communityReporterKeys')) {
    kind = 'key'
  } else if (segments.includes('communityReportDays')) {
    kind = 'marker'
  } else if (segments.length === 2 && segments[0] === 'users') {
    kind = 'profile'
  }
  return { kind, path: segments.join('/'), segments }
}

function deferred<T>() {
  let resolve: (value: T) => void = () => undefined
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve
  })
  return { promise, resolve }
}

beforeEach(() => {
  vi.clearAllMocks()
  resetCommunityCacheForTests()
  nowMs = NOW
  vi.spyOn(Date, 'now').mockImplementation(() => nowMs)

  count = 0
  profileState = { exists: true, data: { displayName: 'Dewi' } }
  keyState = { exists: false }
  markerState = { exists: false }
  reportState = { exists: false }
  feedHeadState = { exists: false }
  feedEntryStates = new Map()
  scanDocs = []
  dailyDocs = []
  sets = []
  user = userFixture()

  mocks.getFirebaseClient.mockReturnValue({ db: {}, auth: { currentUser: user } })
  mocks.collection.mockImplementation((_db: unknown, ...segments: string[]) =>
    makeRef(segments),
  )
  mocks.doc.mockImplementation((_db: unknown, ...segments: string[]) => makeRef(segments))
  mocks.getDoc.mockImplementation(async (ref: Ref) => snapshot(stateFor(ref)))
  mocks.getCountFromServer.mockImplementation(async () => ({ data: () => ({ count }) }))
  mocks.query.mockImplementation((base: Ref, ...constraints: unknown[]) => ({
    base,
    constraints,
  }))
  mocks.getDocs.mockImplementation(async (value: { base?: Ref } | Ref) => {
    const base = value && 'base' in value ? value.base : (value as Ref)
    const segments = base?.segments ?? []
    const documents = segments[0] === 'communityDailyReports' ? dailyDocs : scanDocs
    return {
      docs: documents.map((doc) => ({ id: doc.id, data: () => doc.data })),
    }
  })
  mocks.runTransaction.mockImplementation(
    async (_db: unknown, callback: (transaction: unknown) => unknown) =>
      callback({
        get: async (ref: Ref) => snapshot(stateFor(ref)),
        set: (ref: Ref, data: Record<string, unknown>) => {
          sets.push({ ref, data })
        },
      }),
  )
  mocks.syncUserProfile.mockResolvedValue({
    uid: 'user-1',
    email: 'dewi@example.com',
    displayName: 'Dewi',
    createdAt: new Date(NOW).toISOString(),
    lastLoginAt: new Date(NOW).toISOString(),
  })
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('gerbang akun untuk jalur Firestore', () => {
  it('menolak sesi tanpa akun tanpa membaca koleksi', async () => {
    mocks.getFirebaseClient.mockReturnValue({ db: {}, auth: { currentUser: null } })

    const error = (await getCommunityContext(TARGET_URL).catch((caught) => caught)) as CommunityServiceError

    expect(error).toBeInstanceOf(CommunityServiceError)
    expect(error.code).toBe('unauthenticated')
    await expect(listLatestCommunityReports()).rejects.toMatchObject({
      code: 'unauthenticated',
    })
    expect(mocks.getCountFromServer).not.toHaveBeenCalled()
    expect(mocks.getDocs).not.toHaveBeenCalled()
    expect(mocks.getDoc).not.toHaveBeenCalled()
  })

  it('menolak akun anonim tanpa membaca atau menulis koleksi', async () => {
    user = userFixture({ isAnonymous: true, emailVerified: false })
    mocks.getFirebaseClient.mockReturnValue({ db: {}, auth: { currentUser: user } })

    const error = (await getCommunityContext(TARGET_URL).catch((caught) => caught)) as CommunityServiceError

    expect(error.code).toBe('unauthenticated')
    await expect(submitCommunityReport(INPUT)).rejects.toMatchObject({
      code: 'unauthenticated',
    })
    await expect(listLatestCommunityReports()).rejects.toMatchObject({
      code: 'unauthenticated',
    })
    expect(mocks.getCountFromServer).not.toHaveBeenCalled()
    expect(mocks.getDoc).not.toHaveBeenCalled()
    expect(mocks.runTransaction).not.toHaveBeenCalled()
  })

  it('menolak akun yang belum memverifikasi email tanpa membaca koleksi', async () => {
    user = userFixture({ emailVerified: false })
    mocks.getFirebaseClient.mockReturnValue({ db: {}, auth: { currentUser: user } })

    const error = (await getCommunityContext(TARGET_URL).catch((caught) => caught)) as CommunityServiceError

    expect(error.code).toBe('email-not-verified')
    await expect(listLatestCommunityReports()).rejects.toMatchObject({
      code: 'email-not-verified',
    })
    expect(mocks.getCountFromServer).not.toHaveBeenCalled()
    expect(mocks.getDoc).not.toHaveBeenCalled()
  })

  it('menolak pengiriman sebelum menulis apa pun bila email belum terverifikasi', async () => {
    user = userFixture({ emailVerified: false })
    mocks.getFirebaseClient.mockReturnValue({ db: {}, auth: { currentUser: user } })

    await expect(submitCommunityReport(INPUT)).rejects.toMatchObject({
      code: 'email-not-verified',
    })
    expect(mocks.runTransaction).not.toHaveBeenCalled()
    expect(mocks.serverTimestamp).not.toHaveBeenCalled()
  })
})

describe('konteks URL-scoped dan agregat jujur', () => {
  it('membaca count, scan terbatas, dan kunci pseudonim privat untuk URL ini saja', async () => {
    const hash = await communityUrlHash(TARGET_URL)
    count = 2
    scanDocs = [
      scanEntry('1'.repeat(32), {
        reporterKey: OTHER_REPORTER_KEY,
        userName: 'Rani(sensor)',
        createdAt: new mocks.FakeTimestamp(NOW - 86_400_000),
      }),
      scanEntry('2'.repeat(32), {
        reporterKey: REPORTER_KEY,
        userName: 'Dewi(sensor)',
        createdAt: new mocks.FakeTimestamp(NOW - 172_800_000),
      }),
    ]
    keyState = {
      exists: true,
      data: { ownerId: 'user-1', reporterKey: REPORTER_KEY, createdAt: new mocks.FakeTimestamp(NOW) },
    }

    const context = await getCommunityContext(TARGET_URL)

    expect(context.summary).toMatchObject({
      hostname: 'contoh.id',
      reportCount: 2,
      reporterCount: 2,
      categoryCounts: { phishing: 2 },
      moderationStatus: 'community_reported',
      aggregatesComplete: true,
    })
    expect(context.report?.userName).toBe('Dewi(sensor)')
    expect(context.reports.map((entry) => entry.id)).toEqual([
      '1'.repeat(32),
      '2'.repeat(32),
    ])
    expect(context.reports.map((entry) => entry.userName)).toEqual([
      'Rani(sensor)',
      'Dewi(sensor)',
    ])
    expect(context.reports[0].hostname).toBe('contoh.id')
    expect(mocks.collection).toHaveBeenCalledWith({}, 'communityReports', hash, 'reports')
    expect(mocks.doc).toHaveBeenCalledWith(
      {},
      'users',
      'user-1',
      'communityReporterKeys',
      hash,
    )
    expect(mocks.orderBy).toHaveBeenCalledWith('createdAt', 'desc')
    expect(mocks.limit).toHaveBeenCalledWith(COMMUNITY_CONTEXT_SCAN_LIMIT)
  })

  it('tidak membaca scan atau kunci pribadi ketika count nol', async () => {
    count = 0

    const context = await getCommunityContext(TARGET_URL)

    expect(context).toEqual({ summary: null, report: null, reports: [] })
    expect(mocks.getCountFromServer).toHaveBeenCalledTimes(1)
    expect(mocks.getDocs).not.toHaveBeenCalled()
    expect(mocks.getDoc).not.toHaveBeenCalled()
  })

  it('menandai agregat tidak lengkap ketika total melebihi batas scan', async () => {
    count = 500
    scanDocs = Array.from({ length: 3 }, (_unused, index) =>
      scanEntry(String(index).repeat(32), {
        reporterKey: index === 0 ? REPORTER_KEY : OTHER_REPORTER_KEY,
        userName: `Pelapor ${index}(sensor)`,
        createdAt: new mocks.FakeTimestamp(NOW - (index + 1) * 60_000),
      }),
    )
    keyState = {
      exists: true,
      data: { ownerId: 'user-1', reporterKey: REPORTER_KEY, createdAt: new mocks.FakeTimestamp(NOW) },
    }

    const context = await getCommunityContext(TARGET_URL)

    expect(context.summary).toMatchObject({
      reportCount: 500,
      reporterCount: 0,
      categoryCounts: {},
      firstReportedAt: null,
      aggregatesComplete: false,
    })
    expect(context.summary?.lastReportedAt).toBe(new Date(NOW - 60_000).toISOString())
    expect(context.report?.userName).toBe('Pelapor 0(sensor)')
    expect(context.reports).toHaveLength(3)
  })

  it('menandai agregat tidak lengkap bila ada dokumen dengan skema rusak', async () => {
    count = 2
    scanDocs = [
      scanEntry('1'.repeat(32)),
      scanEntry('2'.repeat(32), { reporterKey: 'bukan-hex', category: 'palsu' }),
    ]

    const context = await getCommunityContext(TARGET_URL)

    expect(context.summary).toMatchObject({
      reportCount: 2,
      reporterCount: 0,
      categoryCounts: {},
      aggregatesComplete: false,
    })
  })

  it('tidak mencampur laporan atau kunci akun lain saat URL berbeda dibaca', async () => {
    const firstHash = await communityUrlHash(TARGET_URL)
    const secondHash = await communityUrlHash(OTHER_URL)
    count = 0

    await getCommunityContext(TARGET_URL)
    await getCommunityContext(OTHER_URL)

    expect(firstHash).not.toBe(secondHash)
    expect(mocks.collection).toHaveBeenCalledWith({}, 'communityReports', firstHash, 'reports')
    expect(mocks.collection).toHaveBeenCalledWith({}, 'communityReports', secondHash, 'reports')
    expect(mocks.doc).toHaveBeenCalledWith(
      {},
      'users',
      'user-1',
      'communityReporterKeys',
      firstHash,
    )
    expect(mocks.doc).toHaveBeenCalledWith(
      {},
      'users',
      'user-1',
      'communityReporterKeys',
      secondHash,
    )
  })
})

describe('cache singkat dan deduplikasi', () => {
  it('memakai hasil cache untuk permintaan berulang, lalu memaksa baca baru saat diminta', async () => {
    await getCommunityContext(TARGET_URL)
    await getCommunityContext(TARGET_URL)

    expect(mocks.getCountFromServer).toHaveBeenCalledTimes(1)

    await getCommunityContext(TARGET_URL, { forceRefresh: true })

    expect(mocks.getCountFromServer).toHaveBeenCalledTimes(2)
  })

  it('menggabungkan dua permintaan yang berjalan bersamaan menjadi satu pembacaan', async () => {
    const pending = deferred<{ data: () => { count: number } }>()
    mocks.getCountFromServer.mockReturnValueOnce(pending.promise)

    const first = getCommunityContext(TARGET_URL)
    const second = getCommunityContext(TARGET_URL)
    pending.resolve({ data: () => ({ count: 0 }) })

    await Promise.all([first, second])

    expect(mocks.getCountFromServer).toHaveBeenCalledTimes(1)
  })

  it('kedaluwarsa setelah 30 detik sehingga data tidak dianggap selamanya segar', async () => {
    await getCommunityContext(TARGET_URL)
    nowMs = NOW + 30_001

    await getCommunityContext(TARGET_URL)

    expect(mocks.getCountFromServer).toHaveBeenCalledTimes(2)
  })
})

describe('umpan laporan terbaru harian (WITA)', () => {
  it('membaca partisi hari WITA dengan jendela createdAt penuh dan urutan terbaru', async () => {
    const dayId = communityDailyFeedDayId(NOW)
    const olderId = '1'.repeat(32)
    const newerId = '2'.repeat(32)
    dailyDocs = [
      dailyEntry(olderId, {
        userName: 'Bima(sensor)',
        category: 'marketplace',
        reason: 'Penjual tidak mengirim barang setelah pembayaran lunas.',
        createdAt: new mocks.FakeTimestamp(NOW - 7_200_000),
      }),
      dailyEntry(newerId, {
        createdAt: new mocks.FakeTimestamp(NOW - 3_600_000),
      }),
    ]

    const reports = await listLatestCommunityReports()

    expect(reports.map((entry) => entry.id)).toEqual([newerId, olderId])
    expect(reports[0]).toEqual({
      id: newerId,
      userName: 'Rani(sensor)',
      reportText: 'Formulir meminta kata sandi bank lewat halaman palsu.',
      category: 'phishing',
      reportedUrl: 'https://contoh.id/login',
      hostname: 'contoh.id',
      createdAt: new Date(NOW - 3_600_000).toISOString(),
    })
    expect(reports[0]).not.toHaveProperty('reporterKey')
    expect(reports[0]).not.toHaveProperty('ownerId')
    expect(reports[0]).not.toHaveProperty('urlHash')
    expect(reports[0]).not.toHaveProperty('updatedAt')
    expect(mocks.collection).toHaveBeenCalledWith(
      {},
      'communityDailyReports',
      dayId,
      'reports',
    )
    expect(mocks.orderBy).toHaveBeenCalledWith('createdAt', 'desc')
    expect(mocks.limit).toHaveBeenCalledWith(COMMUNITY_DAILY_FEED_LIMIT)
    const ranges = mocks.where.mock.calls.filter((call) => call[0] === 'createdAt')
    expect(ranges).toHaveLength(2)
    expect(ranges[0][1]).toBe('>=')
    expect(ranges[1][1]).toBe('<')
    expect(ranges[0][2].toMillis()).toBe(communityDailyFeedDayStartMs(NOW))
    expect(ranges[1][2].toMillis()).toBe(communityDailyFeedDayEndMs(NOW))
    expect(mocks.getDoc).not.toHaveBeenCalled()
  })

  it('menampilkan dua laporan hari ini dan tidak mencampur laporan kemarin', async () => {
    const todayNewer = '1'.repeat(32)
    const todayOlder = '2'.repeat(32)
    const yesterday = '3'.repeat(32)
    dailyDocs = [
      dailyEntry(todayNewer, { createdAt: new mocks.FakeTimestamp(NOW - 60_000) }),
      dailyEntry(yesterday, { createdAt: new mocks.FakeTimestamp(NOW - 79_200_000) }),
      dailyEntry(todayOlder, { createdAt: new mocks.FakeTimestamp(NOW - 7_200_000) }),
    ]

    const reports = await listLatestCommunityReports()

    expect(reports.map((entry) => entry.id)).toEqual([todayNewer, todayOlder])
  })

  it('menangani pergantian bulan dan tahun pada tengah malam WITA', async () => {
    const newYearNow = Date.parse('2026-12-31T17:30:00Z') // 1 Jan 2027, 01:30 WITA
    nowMs = newYearNow
    const lastSecond = Date.parse('2026-12-31T15:59:59.999Z') // 23:59:59 WITA
    const firstSecond = Date.parse('2026-12-31T16:00:00.000Z') // 00:00:00 WITA
    dailyDocs = [
      dailyEntry('4'.repeat(32), {
        createdAt: new mocks.FakeTimestamp(lastSecond),
      }),
      dailyEntry('5'.repeat(32), {
        createdAt: new mocks.FakeTimestamp(firstSecond),
      }),
    ]

    const reports = await listLatestCommunityReports()

    expect(reports.map((entry) => entry.id)).toEqual(['5'.repeat(32)])
    expect(mocks.collection).toHaveBeenCalledWith(
      {},
      'communityDailyReports',
      communityDailyFeedDayId(newYearNow),
      'reports',
    )
    expect(communityDailyFeedDayStartMs(newYearNow)).toBe(firstSecond)
  })

  it('membatasi hasil pada item terbaru saat laporan melebihi kapasitas panel', async () => {
    const ids = Array.from({ length: COMMUNITY_DAILY_FEED_LIMIT + 2 }, (_unused, index) =>
      (index + 1).toString(16).padStart(32, '0'),
    )
    dailyDocs = ids.map((id, index) =>
      dailyEntry(id, {
        createdAt: new mocks.FakeTimestamp(NOW - index * 60_000),
      }),
    )

    const reports = await listLatestCommunityReports()

    expect(reports).toHaveLength(COMMUNITY_DAILY_FEED_LIMIT)
    expect(reports.map((entry) => entry.id)).toEqual(
      ids.slice(0, COMMUNITY_DAILY_FEED_LIMIT),
    )
    expect(mocks.limit).toHaveBeenCalledWith(COMMUNITY_DAILY_FEED_LIMIT)
  })

  it('mengembalikan kosong hanya setelah query harian berhasil dan kepala juga kosong', async () => {
    dailyDocs = []
    feedHeadState = { exists: false }

    const reports = await listLatestCommunityReports()

    expect(reports).toEqual([])
    expect(mocks.getDocs).toHaveBeenCalledTimes(1)
    expect(mocks.doc).toHaveBeenCalledWith({}, 'communityLatestReports', 'global')
    expect(mocks.getDoc).toHaveBeenCalledTimes(1)
  })

  it('memakai kepala lama sebagai jaring transisi hanya saat partisi harian kosong', async () => {
    const todayId = '7'.repeat(32)
    const yesterdayId = '8'.repeat(32)
    dailyDocs = []
    feedHeadState = {
      exists: true,
      data: {
        entries: [todayId, yesterdayId],
        updatedAt: new mocks.FakeTimestamp(NOW),
      },
    }
    feedEntryStates.set(todayId, {
      exists: true,
      data: latestEntryData({ createdAt: new mocks.FakeTimestamp(NOW - 3_600_000) }),
    })
    feedEntryStates.set(yesterdayId, {
      exists: true,
      data: latestEntryData({ createdAt: new mocks.FakeTimestamp(NOW - 79_200_000) }),
    })

    const reports = await listLatestCommunityReports()

    expect(reports.map((entry) => entry.id)).toEqual([todayId])
    expect(mocks.getDocs).toHaveBeenCalledTimes(1)
  })

  it('melewati entri harian yang hilang atau rusak tanpa mengarang laporan', async () => {
    const validId = '9'.repeat(32)
    dailyDocs = [
      dailyEntry(validId),
      {
        id: 'a'.repeat(32),
        data: { userName: 'Rusak(sensor)', category: 'palsu', reason: '' },
      },
    ]

    const reports = await listLatestCommunityReports()

    expect(reports.map((entry) => entry.id)).toEqual([validId])
    expect(mocks.getDoc).not.toHaveBeenCalled()
  })

  it('memakai null untuk URL/hostname lama atau tidak aman tanpa menyembunyikan laporan', async () => {
    const legacyId = 'e'.repeat(32)
    const invalidId = 'f'.repeat(32)
    const validId = 'a'.repeat(32)
    dailyDocs = [
      dailyEntry(legacyId, {
        reportedUrl: undefined,
        hostname: undefined,
        createdAt: new mocks.FakeTimestamp(NOW - 60_000),
      }),
      dailyEntry(invalidId, {
        reportedUrl: 'https://user:rahasia@contoh.id/path',
        hostname: 'https://contoh.id/path',
        createdAt: new mocks.FakeTimestamp(NOW - 120_000),
      }),
      dailyEntry(validId, {
        reportedUrl: 'https://sub.contoh.id/halaman?utm_source=promo#bagian',
        hostname: 'sub.contoh.id',
        createdAt: new mocks.FakeTimestamp(NOW - 180_000),
      }),
    ]

    const reports = await listLatestCommunityReports()

    expect(
      reports.map(({ id, reportedUrl, hostname }) => ({ id, reportedUrl, hostname })),
    ).toEqual([
      { id: legacyId, reportedUrl: null, hostname: null },
      { id: invalidId, reportedUrl: null, hostname: null },
      { id: validId, reportedUrl: 'https://sub.contoh.id/halaman', hostname: 'sub.contoh.id' },
    ])
  })

  it('membaca URL tersimpan dan membuang query/fragment saat menampilkan feed', async () => {
    const urlId = 'b'.repeat(32)
    dailyDocs = [
      dailyEntry(urlId, {
        reportedUrl: 'https://forms.gle/sfUqkbdPrC9uyh3b8?token=rahasia#bagian',
        hostname: 'forms.gle',
      }),
    ]

    const reports = await listLatestCommunityReports()

    expect(reports[0]).toMatchObject({
      reportedUrl: 'https://forms.gle/sfUqkbdPrC9uyh3b8',
      hostname: 'forms.gle',
    })
  })

  it('membuang label hostname yang bukan authority dari URL laporannya', async () => {
    const forgedId = 'c'.repeat(32)
    const legitId = 'd'.repeat(32)
    dailyDocs = [
      dailyEntry(forgedId, {
        reportedUrl: 'https://penipu.example/login',
        hostname: 'bank-resmi.example',
      }),
      dailyEntry(legitId, {
        reportedUrl: 'https://bank-resmi.example.evil.test/x',
        hostname: 'bank-resmi.example.evil.test',
      }),
    ]

    const reports = await listLatestCommunityReports()

    expect(
      reports.map(({ id, reportedUrl, hostname }) => ({ id, reportedUrl, hostname })),
    ).toEqual([
      { id: forgedId, reportedUrl: 'https://penipu.example/login', hostname: null },
      {
        id: legitId,
        reportedUrl: 'https://bank-resmi.example.evil.test/x',
        hostname: 'bank-resmi.example.evil.test',
      },
    ])
  })

  it('menolak kepala transisi yang rusak, bukan menampilkan keadaan kosong', async () => {
    dailyDocs = []
    feedHeadState = {
      exists: true,
      data: { entries: ['bukan-id'], updatedAt: new mocks.FakeTimestamp(NOW) },
    }

    await expect(listLatestCommunityReports()).rejects.toMatchObject({
      code: 'failed-precondition',
    })
    expect(mocks.getDocs).toHaveBeenCalledTimes(1)
    expect(mocks.getDoc).toHaveBeenCalledTimes(1)
  })

  it('memakai cache per hari WITA dan tidak menggandakan permintaan yang berjalan', async () => {
    dailyDocs = [dailyEntry('b'.repeat(32))]
    await listLatestCommunityReports()
    await listLatestCommunityReports()
    expect(mocks.getDocs).toHaveBeenCalledTimes(1)

    await listLatestCommunityReports({ forceRefresh: true })
    expect(mocks.getDocs).toHaveBeenCalledTimes(2)

    resetCommunityCacheForTests()
    mocks.getDocs.mockClear()
    mocks.getDoc.mockClear()
    const pending = deferred<{ docs: { id: string; data: () => unknown }[] }>()
    mocks.getDocs.mockReturnValueOnce(pending.promise)

    const first = listLatestCommunityReports()
    const second = listLatestCommunityReports({ forceRefresh: true })
    pending.resolve({ docs: [] })

    await expect(Promise.all([first, second])).resolves.toEqual([[], []])
    expect(mocks.getDocs).toHaveBeenCalledTimes(1)
    expect(mocks.getDoc).toHaveBeenCalledTimes(1)
  })

  it('memakai kunci cache baru setelah tanggal WITA berganti', async () => {
    const firstId = 'c'.repeat(32)
    const secondId = 'd'.repeat(32)
    dailyDocs = [
      dailyEntry(firstId, { createdAt: new mocks.FakeTimestamp(NOW - 3_600_000) }),
    ]

    await listLatestCommunityReports()

    nowMs = NOW + 86_400_000
    dailyDocs = [
      dailyEntry(secondId, { createdAt: new mocks.FakeTimestamp(nowMs - 3_600_000) }),
    ]
    const reports = await listLatestCommunityReports()

    expect(reports.map((entry) => entry.id)).toEqual([secondId])
    expect(mocks.getDocs).toHaveBeenCalledTimes(2)
    expect(mocks.collection).toHaveBeenCalledWith(
      {},
      'communityDailyReports',
      communityDailyFeedDayId(NOW),
      'reports',
    )
    expect(mocks.collection).toHaveBeenCalledWith(
      {},
      'communityDailyReports',
      communityDailyFeedDayId(nowMs),
      'reports',
    )
  })

  it('menjadikan penolakan akses query harian sebagai error, bukan keadaan kosong', async () => {
    mocks.getDocs.mockRejectedValue(
      Object.assign(new Error('denied'), { code: 'permission-denied' }),
    )

    const error = (await listLatestCommunityReports().catch(
      (caught) => caught,
    )) as CommunityServiceError

    expect(error.code).toBe('permission-denied')
    expect(error.details).toMatchObject({ cause: 'permission-denied', stage: 'daily-list' })
    expect(user.getIdToken).toHaveBeenCalledWith(true)
    expect(mocks.getDocs).toHaveBeenCalledTimes(2)
    expect(mocks.getDoc).not.toHaveBeenCalled()
  })

  it('memisahkan gangguan jaringan query harian tanpa mencoba ulang', async () => {
    mocks.getDocs.mockRejectedValue(
      Object.assign(new Error('offline'), { code: 'unavailable' }),
    )

    const error = (await listLatestCommunityReports().catch(
      (caught) => caught,
    )) as CommunityServiceError

    expect(error.code).toBe('unavailable')
    expect(user.getIdToken).not.toHaveBeenCalled()
    expect(mocks.getDocs).toHaveBeenCalledTimes(1)
  })
})

describe('pengiriman satu laporan per hari dengan pengikatan transaksi', () => {
  it('menolak bila penanda hari sudah ada tanpa menulis apa pun', async () => {
    markerState = {
      exists: true,
      data: {
        ownerId: 'user-1',
        reportId: '1'.repeat(32),
        urlHash: 'c'.repeat(64),
        reporterKey: REPORTER_KEY,
        category: 'phishing',
        createdAt: new mocks.FakeTimestamp(NOW),
      },
    }

    const error = (await submitCommunityReport(INPUT).catch((caught) => caught)) as CommunityServiceError

    expect(error).toBeInstanceOf(CommunityServiceError)
    expect(error.dailyLimitReached).toBe(true)
    expect(error.code).toBe('resource-exhausted')
    expect(error.message).toBe(COMMUNITY_DAILY_LIMIT_MESSAGE)
    expect(sets).toHaveLength(0)
  })

  it('membuat penanda, pseudonim baru, dan laporan publik yang saling terikat', async () => {
    const expectedDay = String(communityDayId(NOW))
    const expectedFeedDay = communityDailyFeedDayId(NOW)
    const expectedHash = await communityUrlHash(TARGET_URL)

    const result = await submitCommunityReport(INPUT)

    expect(result.created).toBe(true)
    expect(sets).toHaveLength(6)

    const keySet = sets.find((entry) => entry.ref.kind === 'key')
    const markerSet = sets.find((entry) => entry.ref.kind === 'marker')
    const reportSet = sets.find((entry) => entry.ref.kind === 'report')
    const entrySet = sets.find((entry) => entry.ref.kind === 'feedEntry')
    const dailySet = sets.find((entry) => entry.ref.kind === 'dailyEntry')
    const headSet = sets.find((entry) => entry.ref.kind === 'feedHead')
    expect(keySet?.ref.path).toBe(`users/user-1/communityReporterKeys/${expectedHash}`)
    expect(keySet?.data).toMatchObject({
      ownerId: 'user-1',
      reporterKey: expect.stringMatching(/^[0-9a-f]{64}$/),
      createdAt: { __serverTimestamp: true },
    })
    expect(markerSet?.ref.path).toBe(`users/user-1/communityReportDays/${expectedDay}`)
    expect(markerSet?.data).toMatchObject({
      ownerId: 'user-1',
      urlHash: expectedHash,
      reporterKey: keySet?.data.reporterKey,
      category: 'phishing',
      createdAt: { __serverTimestamp: true },
      reportId: expect.stringMatching(/^[0-9a-f]{32}$/),
    })
    expect(reportSet?.ref.path).toBe(
      `communityReports/${expectedHash}/reports/${String(markerSet?.data.reportId)}`,
    )
    expect(reportSet?.data).toEqual({
      reporterKey: keySet?.data.reporterKey,
      userName: maskReporterName('Dewi'),
      reportedUrl: 'https://contoh.id/login',
      hostname: 'contoh.id',
      category: 'phishing',
      reason: INPUT.reason,
      createdAt: { __serverTimestamp: true },
      updatedAt: { __serverTimestamp: true },
    })
    expect(reportSet?.data).not.toHaveProperty('ownerId')
    expect(reportSet?.data).not.toHaveProperty('urlHash')

    const reportId = String(markerSet?.data.reportId)
    expect(entrySet?.ref.path).toBe(
      `communityLatestReports/global/entries/${reportId}`,
    )
    expect(entrySet?.data).toEqual({
      reporterKey: keySet?.data.reporterKey,
      userName: maskReporterName('Dewi'),
      reportedUrl: 'https://contoh.id/login',
      hostname: 'contoh.id',
      category: 'phishing',
      reason: INPUT.reason,
      createdAt: { __serverTimestamp: true },
    })
    expect(entrySet?.data).not.toHaveProperty('ownerId')
    expect(entrySet?.data).not.toHaveProperty('urlHash')
    expect(entrySet?.data).not.toHaveProperty('updatedAt')
    expect(dailySet?.ref.path).toBe(
      `communityDailyReports/${expectedFeedDay}/reports/${reportId}`,
    )
    expect(dailySet?.data).toEqual({
      userName: maskReporterName('Dewi'),
      reportedUrl: 'https://contoh.id/login',
      hostname: 'contoh.id',
      category: 'phishing',
      reason: INPUT.reason,
      createdAt: { __serverTimestamp: true },
    })
    expect(dailySet?.data).not.toHaveProperty('reporterKey')
    expect(dailySet?.data).not.toHaveProperty('ownerId')
    expect(dailySet?.data).not.toHaveProperty('urlHash')
    expect(dailySet?.data).not.toHaveProperty('updatedAt')
    expect(entrySet?.data.hostname).toBe(reportSet?.data.hostname)
    expect(dailySet?.data.hostname).toBe(reportSet?.data.hostname)
    expect(entrySet?.data.reportedUrl).toBe(reportSet?.data.reportedUrl)
    expect(dailySet?.data.reportedUrl).toBe(reportSet?.data.reportedUrl)
    expect(headSet?.ref.path).toBe('communityLatestReports/global')
    expect(headSet?.data).toEqual({
      entries: [reportId],
      updatedAt: { __serverTimestamp: true },
    })
    expect(mocks.syncUserProfile).not.toHaveBeenCalled()
  })

  it('menyimpan URL tampilan forms.gle tanpa query/fragment dan hostname terpisah', async () => {
    await submitCommunityReport({
      ...INPUT,
      url: 'https://forms.gle/sfUqkbdPrC9uyh3b8?token=rahasia#bagian',
    })

    const written = sets.filter((entry) =>
      ['report', 'feedEntry', 'dailyEntry'].includes(entry.ref.kind),
    )
    expect(written).toHaveLength(3)
    for (const { data } of written) {
      expect(data.reportedUrl).toBe('https://forms.gle/sfUqkbdPrC9uyh3b8')
      expect(data.hostname).toBe('forms.gle')
      expect(String(data.reportedUrl)).not.toMatch(/[?#@\s]/)
      expect(String(data.hostname)).not.toMatch(/[:/?#@\s]/)
    }
  })

  it('mempertahankan path aman dan membuang port default serta query pelacak', async () => {
    await submitCommunityReport({
      ...INPUT,
      url: 'https://Sub.Contoh.ID:443/halaman/2026?utm_source=sms&token=rahasia#bagian',
    })

    const written = sets.filter((entry) =>
      ['report', 'feedEntry', 'dailyEntry'].includes(entry.ref.kind),
    )
    expect(written).toHaveLength(3)
    for (const { data } of written) {
      expect(data.reportedUrl).toBe('https://sub.contoh.id/halaman/2026')
      expect(data.hostname).toBe('sub.contoh.id')
    }
  })

  it('menolak URL berkredensial sebelum menulis apa pun', async () => {
    const error = (await submitCommunityReport({
      ...INPUT,
      url: 'https://user:rahasia@contoh.id/login',
    }).catch((caught) => caught)) as CommunityServiceError

    expect(error.code).toBe('invalid-argument')
    expect(error.message).toMatch(/kata sandi|kredensial/i)
    expect(mocks.runTransaction).not.toHaveBeenCalled()
    expect(sets).toHaveLength(0)
  })

  it('menolak hostname yang tidak berbentuk aman sebelum menulis apa pun', async () => {
    const error = (await submitCommunityReport({
      ...INPUT,
      url: 'https://contoh..id/login',
    }).catch((caught) => caught)) as CommunityServiceError

    expect(error.code).toBe('invalid-argument')
    expect(error.message).toMatch(/hostname/i)
    expect(mocks.runTransaction).not.toHaveBeenCalled()
  })

  it('memakai pseudonim yang sudah ada dan tidak menulis kunci kedua', async () => {
    keyState = {
      exists: true,
      data: {
        ownerId: 'user-1',
        reporterKey: OTHER_REPORTER_KEY,
        createdAt: new mocks.FakeTimestamp(NOW - 100_000),
      },
    }

    await submitCommunityReport(INPUT)

    expect(sets).toHaveLength(5)
    expect(sets.some((entry) => entry.ref.kind === 'key')).toBe(false)
    const reportSet = sets.find((entry) => entry.ref.kind === 'report')
    expect(reportSet?.data.reporterKey).toBe(OTHER_REPORTER_KEY)
    const entrySet = sets.find((entry) => entry.ref.kind === 'feedEntry')
    expect(entrySet?.data.reporterKey).toBe(OTHER_REPORTER_KEY)
    const dailySet = sets.find((entry) => entry.ref.kind === 'dailyEntry')
    expect(dailySet?.ref.path).toContain(
      `communityDailyReports/${communityDailyFeedDayId(NOW)}/reports/`,
    )
  })

  it('menggeser kepala umpan dan mengeluarkan laporan tertua tanpa menghapus dokumennya', async () => {
    const oldIds = Array.from({ length: COMMUNITY_LATEST_LIMIT }, (_unused, index) =>
      (index + 1).toString(16).padStart(32, '0'),
    )
    const oldestId = oldIds[oldIds.length - 1]
    keyState = {
      exists: true,
      data: {
        ownerId: 'user-1',
        reporterKey: OTHER_REPORTER_KEY,
        createdAt: new mocks.FakeTimestamp(NOW - 100_000),
      },
    }
    feedHeadState = {
      exists: true,
      data: { entries: oldIds, updatedAt: new mocks.FakeTimestamp(NOW - 1_000) },
    }
    feedEntryStates.set(oldestId, { exists: true, data: latestEntryData() })

    await submitCommunityReport(INPUT)

    const markerSet = sets.find((entry) => entry.ref.kind === 'marker')
    const reportId = String(markerSet?.data.reportId)
    const headSet = sets.find((entry) => entry.ref.kind === 'feedHead')
    expect(headSet?.data.entries).toEqual([reportId, ...oldIds.slice(0, -1)])
    expect(headSet?.data.entries).toHaveLength(COMMUNITY_LATEST_LIMIT)
    expect(headSet?.data.entries).not.toContain(oldestId)
    expect(sets.some((entry) => entry.ref.path.endsWith(`/entries/${oldestId}`))).toBe(false)
    expect(sets.some((entry) => entry.ref.kind === 'report' && entry.ref.path.includes(oldestId))).toBe(
      false,
    )
    expect(feedEntryStates.get(oldestId)?.exists).toBe(true)
  })

  it('menolak kunci pseudonim privat yang rusak tanpa menulis laporan', async () => {
    keyState = {
      exists: true,
      data: {
        ownerId: 'user-1',
        reporterKey: 'bukan-kunci',
        createdAt: new mocks.FakeTimestamp(NOW - 100_000),
      },
    }

    await expect(submitCommunityReport(INPUT)).rejects.toMatchObject({
      code: 'failed-precondition',
    })
    expect(sets).toHaveLength(0)
  })

  it('membedakan kegagalan transaksi setelah penanda tersimpan', async () => {
    markerState = {
      exists: true,
      data: { ownerId: 'user-1', reportId: '1'.repeat(32) },
    }
    const transaction = {
      get: async (ref: Ref) =>
        ref.kind === 'marker' ? { exists: () => false } : snapshot(stateFor(ref)),
      set: vi.fn(),
    }
    mocks.runTransaction.mockImplementationOnce(
      async (_db: unknown, callback: (value: typeof transaction) => unknown) => {
        await callback(transaction)
        throw Object.assign(new Error('conflict'), { code: 'aborted' })
      },
    )

    const error = (await submitCommunityReport(INPUT).catch((caught) => caught)) as CommunityServiceError

    expect(error.dailyLimitReached).toBe(true)
    expect(error.message).toBe(COMMUNITY_DAILY_LIMIT_MESSAGE)
  })

  it('tidak menyamarkan penolakan izin tulis sebagai batas harian', async () => {
    mocks.runTransaction.mockRejectedValueOnce(
      Object.assign(new Error('denied'), { code: 'permission-denied' }),
    )

    const error = (await submitCommunityReport(INPUT).catch((caught) => caught)) as CommunityServiceError

    expect(error.code).toBe('permission-denied')
    expect(error.dailyLimitReached).toBe(false)
    expect(error.message).toMatch(/tidak memiliki izin/i)
    expect(error.details).toMatchObject({ cause: 'permission-denied' })
    expect(sets).toHaveLength(0)
  })

  it('menyiapkan profil yang hilang sebelum menulis laporan', async () => {
    profileState = { exists: false }
    mocks.syncUserProfile.mockImplementation(async () => {
      profileState = { exists: true, data: { displayName: 'Dewi' } }
      return {
        uid: 'user-1',
        email: 'dewi@example.com',
        displayName: 'Dewi',
        createdAt: new Date(NOW).toISOString(),
        lastLoginAt: new Date(NOW).toISOString(),
      }
    })

    const result = await submitCommunityReport(INPUT)

    expect(mocks.syncUserProfile).toHaveBeenCalledWith({
      uid: 'user-1',
      email: 'dewi@example.com',
      displayName: 'Dewi',
    })
    expect(result.created).toBe(true)
    expect(result.summary).toBeNull()
  })

  it('mencoba ulang sekali dengan hari baru setelah penolakan di batas tengah malam', async () => {
    const newDay = String(communityDayId(NOW) + 1)
    const newFeedDay = communityDailyFeedDayId(NOW + 86_400_000)
    user.getIdTokenResult
      .mockResolvedValueOnce({
        issuedAtTime: new Date(nowMs).toISOString(),
        expirationTime: new Date(nowMs + 3_600_000).toISOString(),
        authTime: new Date(nowMs).toISOString(),
        claims: { email_verified: true },
      })
      .mockResolvedValueOnce({
        issuedAtTime: new Date(nowMs + 86_400_000).toISOString(),
        expirationTime: new Date(nowMs + 90_000_000).toISOString(),
        authTime: new Date(nowMs + 86_400_000).toISOString(),
        claims: { email_verified: true },
      })

    let attempts = 0
    mocks.runTransaction.mockImplementation(
      async (_db: unknown, callback: (transaction: unknown) => unknown) => {
        attempts += 1
        if (attempts === 1) {
          throw Object.assign(new Error('denied at midnight'), { code: 'permission-denied' })
        }
        return callback({
          get: async (ref: Ref) => snapshot(stateFor(ref)),
          set: (ref: Ref, data: Record<string, unknown>) => {
            sets.push({ ref, data })
          },
        })
      },
    )

    const result = await submitCommunityReport(INPUT)

    expect(result.created).toBe(true)
    expect(mocks.runTransaction).toHaveBeenCalledTimes(2)
    const markerSet = sets.find((entry) => entry.ref.kind === 'marker')
    const dailySet = sets.find((entry) => entry.ref.kind === 'dailyEntry')
    expect(markerSet?.ref.path).toBe(`users/user-1/communityReportDays/${newDay}`)
    expect(dailySet?.ref.path).toContain(
      `communityDailyReports/${newFeedDay}/reports/`,
    )
  })

  it('mencoba ulang saat hanya partisi WITA yang berganti, tanpa mengubah batas WIB', async () => {
    // 22:30 WIB / 23:30 WITA; satu jam kemudian WIB masih hari yang sama,
    // sedangkan WITA sudah masuk hari berikutnya.
    const beforeWitaMidnight = Date.parse('2026-10-25T15:30:00Z')
    nowMs = beforeWitaMidnight
    const firstQuotaDay = communityDayId(beforeWitaMidnight)
    const firstFeedDay = communityDailyFeedDayId(beforeWitaMidnight)
    const secondQuotaDay = communityDayId(beforeWitaMidnight + 3_600_000)
    const secondFeedDay = communityDailyFeedDayId(beforeWitaMidnight + 3_600_000)
    expect(secondQuotaDay).toBe(firstQuotaDay)
    expect(secondFeedDay).not.toBe(firstFeedDay)

    user.getIdTokenResult
      .mockResolvedValueOnce({
        issuedAtTime: new Date(beforeWitaMidnight).toISOString(),
        expirationTime: new Date(beforeWitaMidnight + 3_600_000).toISOString(),
        authTime: new Date(beforeWitaMidnight).toISOString(),
        claims: { email_verified: true },
      })
      .mockResolvedValueOnce({
        issuedAtTime: new Date(beforeWitaMidnight + 3_600_000).toISOString(),
        expirationTime: new Date(beforeWitaMidnight + 7_200_000).toISOString(),
        authTime: new Date(beforeWitaMidnight + 3_600_000).toISOString(),
        claims: { email_verified: true },
      })

    let attempts = 0
    mocks.runTransaction.mockImplementation(
      async (_db: unknown, callback: (transaction: unknown) => unknown) => {
        attempts += 1
        if (attempts === 1) {
          throw Object.assign(new Error('denied at WITA midnight'), {
            code: 'permission-denied',
          })
        }
        return callback({
          get: async (ref: Ref) => snapshot(stateFor(ref)),
          set: (ref: Ref, data: Record<string, unknown>) => {
            sets.push({ ref, data })
          },
        })
      },
    )

    const result = await submitCommunityReport(INPUT)

    expect(result.created).toBe(true)
    expect(mocks.runTransaction).toHaveBeenCalledTimes(2)
    const markerSet = sets.find((entry) => entry.ref.kind === 'marker')
    const dailySet = sets.find((entry) => entry.ref.kind === 'dailyEntry')
    expect(markerSet?.ref.path).toBe(
      `users/user-1/communityReportDays/${secondQuotaDay}`,
    )
    expect(dailySet?.ref.path).toContain(
      `communityDailyReports/${secondFeedDay}/reports/`,
    )
  })

  it('membuang cache umpan lama setelah laporan tersimpan', async () => {
    dailyDocs = [dailyEntry('e'.repeat(32))]
    await listLatestCommunityReports()
    await listLatestCommunityReports()
    expect(mocks.getDocs).toHaveBeenCalledTimes(1)

    await submitCommunityReport(INPUT)
    mocks.getDocs.mockClear()
    await listLatestCommunityReports()

    expect(mocks.getDocs).toHaveBeenCalledTimes(1)
  })
})

describe('pemetaan kegagalan layanan', () => {
  it('memperbarui token lalu mencoba sekali lagi saat rules menolak token lama', async () => {
    const denied = Object.assign(new Error('denied'), { code: 'permission-denied' })
    mocks.getCountFromServer.mockRejectedValueOnce(denied)

    const context = await getCommunityContext(TARGET_URL)

    expect(context.summary).toBeNull()
    expect(user.getIdToken).toHaveBeenCalledWith(true)
    expect(mocks.getCountFromServer).toHaveBeenCalledTimes(2)
  })

  it('menampilkan error akses, bukan keadaan kosong, bila penolakan tetap terjadi', async () => {
    mocks.getCountFromServer.mockRejectedValue(
      Object.assign(new Error('denied'), { code: 'permission-denied' }),
    )

    const error = (await getCommunityContext(TARGET_URL).catch((caught) => caught)) as CommunityServiceError

    expect(error.code).toBe('permission-denied')
    expect(error.message).toMatch(/tidak memiliki izin/i)
    expect(error.message).not.toMatch(/deploy|aturan Firestore/i)
    expect(user.getIdToken).toHaveBeenCalledWith(true)
    expect(mocks.getCountFromServer).toHaveBeenCalledTimes(2)
  })

  it('membedakan email belum terverifikasi dari penolakan akses lain', async () => {
    mocks.getCountFromServer.mockRejectedValue(
      Object.assign(new Error('denied'), { code: 'permission-denied' }),
    )
    user.getIdToken.mockImplementation(async () => {
      user.emailVerified = false
      return 'token-baru'
    })

    const error = (await getCommunityContext(TARGET_URL).catch((caught) => caught)) as CommunityServiceError

    expect(error.code).toBe('email-not-verified')
    expect(error.message).toMatch(/verifikasi email/i)
    expect(mocks.getCountFromServer).toHaveBeenCalledTimes(2)
  })

  it('memisahkan gangguan jaringan dari penolakan akses tanpa mencoba ulang', async () => {
    mocks.getCountFromServer.mockRejectedValue(
      Object.assign(new Error('offline'), { code: 'unavailable' }),
    )

    const error = (await getCommunityContext(TARGET_URL).catch((caught) => caught)) as CommunityServiceError

    expect(error.code).toBe('unavailable')
    expect(error.message).toMatch(/tidak dapat dihubungi/i)
    expect(user.getIdToken).not.toHaveBeenCalled()
    expect(mocks.getCountFromServer).toHaveBeenCalledTimes(1)
  })

  it('memisahkan kuota dari penolakan akses dan batas harian', async () => {
    mocks.getCountFromServer.mockRejectedValue(
      Object.assign(new Error('quota'), { code: 'resource-exhausted' }),
    )

    const error = (await getCommunityContext(TARGET_URL).catch((caught) => caught)) as CommunityServiceError

    expect(error.code).toBe('resource-exhausted')
    expect(error.dailyLimitReached).toBe(false)
    expect(error.message).toMatch(/kuota/i)
  })

  it('tidak melaporkan kegagalan konfigurasi sebagai kegagalan email atau akses', async () => {
    mocks.getCountFromServer.mockRejectedValue(
      Object.assign(
        new Error(
          'The query requires an index. You can create it here: https://console.firebase.google.com/project/demo/indexes',
        ),
        { code: 'failed-precondition' },
      ),
    )

    const error = (await getCommunityContext(TARGET_URL).catch((caught) => caught)) as CommunityServiceError

    expect(error.code).toBe('failed-precondition')
    expect(error.message).toMatch(/belum siap/i)
    expect(error.message).not.toMatch(/verifikasi email|tidak memiliki izin/i)
    expect(error.message).not.toContain('console.firebase.google.com')
  })

  it('penolakan saat menulis memakai pesan izin tulis, bukan izin baca', async () => {
    mocks.runTransaction.mockRejectedValueOnce(
      Object.assign(new Error('denied'), { code: 'permission-denied' }),
    )

    const error = (await submitCommunityReport(INPUT).catch((caught) => caught)) as CommunityServiceError

    expect(error.code).toBe('permission-denied')
    expect(error.message).toMatch(/tidak dapat disimpan/i)
    expect(error.message).not.toMatch(/tidak dapat dibaca/i)
  })

  it('mencatat operasi dan kode saja tanpa email, UID, token, atau isi laporan', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    mocks.getCountFromServer.mockRejectedValue(
      Object.assign(new Error(`denied for dewi@example.com user-1 ${INPUT.reason}`), {
        code: 'permission-denied',
      }),
    )

    await getCommunityContext(TARGET_URL).catch(() => undefined)

    expect(warn).toHaveBeenCalledWith('[community] context failed: permission-denied')
    const logged = warn.mock.calls.flat().join(' ')
    expect(logged).not.toContain('dewi@example.com')
    expect(logged).not.toContain('user-1')
    expect(logged).not.toContain('token-rahasia')
    expect(logged).not.toContain(INPUT.reason)
  })

  it('mencatat tahap query harian yang ditolak tanpa data sensitif', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    mocks.getDocs.mockRejectedValue(
      Object.assign(new Error('denied for dewi@example.com user-1'), {
        code: 'permission-denied',
      }),
    )

    const error = (await listLatestCommunityReports().catch(
      (caught) => caught,
    )) as CommunityServiceError

    expect(error.code).toBe('permission-denied')
    expect(error.details).toMatchObject({ cause: 'permission-denied', stage: 'daily-list' })
    expect(warn).toHaveBeenCalledWith(
      '[community] latest failed: permission-denied (daily-list)',
    )
    const logged = warn.mock.calls.flat().join(' ')
    expect(logged).not.toContain('dewi@example.com')
    expect(logged).not.toContain('user-1')
  })

  it('membedakan penolakan saat membaca entri dari kepala transisi', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const entryId = 'f'.repeat(32)
    dailyDocs = []
    feedHeadState = {
      exists: true,
      data: { entries: [entryId], updatedAt: new mocks.FakeTimestamp(NOW) },
    }
    mocks.getDoc.mockImplementation(async (ref: Ref) => {
      if (ref.kind === 'feedHead') return snapshot(feedHeadState)
      if (ref.kind === 'feedEntry') {
        throw Object.assign(new Error('denied'), { code: 'permission-denied' })
      }
      return snapshot(stateFor(ref))
    })

    const error = (await listLatestCommunityReports().catch(
      (caught) => caught,
    )) as CommunityServiceError

    expect(error.code).toBe('permission-denied')
    expect(error.details).toMatchObject({ cause: 'permission-denied', stage: 'fallback-entry' })
    expect(warn).toHaveBeenCalledWith(
      '[community] latest failed: permission-denied (fallback-entry)',
    )
  })
})

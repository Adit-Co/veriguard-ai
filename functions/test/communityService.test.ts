import { createHash } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { FakeFirestore } from './helpers/fakeFirestore.js'

const context = vi.hoisted(() => ({
  fake: null as unknown as import('./helpers/fakeFirestore.js').FakeFirestore,
}))

vi.mock('firebase-admin/app', () => ({
  getApps: () => [{ name: '[DEFAULT]' }],
  initializeApp: () => undefined,
}))

vi.mock('firebase-admin/firestore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('firebase-admin/firestore')>()
  return { ...actual, getFirestore: () => context.fake }
})

// getFirestore() dipanggil saat modul layanan dimuat, jadi instance palsu harus siap
// sebelum import dinamis ini berjalan.
context.fake = new FakeFirestore()

const { Timestamp } = await import('firebase-admin/firestore')
const service = await import('../src/community/service.js')
const callable = await import('../src/community/index.js')

const BASE_UTC = Date.parse('2026-10-20T05:00:00Z')
const LATE_SAME_DAY_UTC = Date.parse('2026-10-20T16:00:00Z')
const NEXT_UTC_DAY = Date.parse('2026-10-21T00:30:00Z')

const REASON = 'Halaman ini meminta kata sandi lewat formulir yang menyerupai bank.'
const REPORT_INPUT = { url: 'https://contoh-bank-palsu.id/login', category: 'phishing', reason: REASON }

function hashUrl(url: string): string {
  return createHash('sha256').update(url).digest('hex')
}

function summaryPath(url: string): string {
  return `communitySummaries/${hashUrl(url)}`
}

type StoredReport = { path: string; data: Record<string, unknown> }

/** Laporan kini append-only dengan ID otomatis, jadi jumlahnya dihitung dari path nyata. */
function storedReports(uid: string): StoredReport[] {
  return context.fake
    .paths()
    .filter((path) => path.startsWith(`users/${uid}/communityReports/`))
    .map((path) => ({ path, data: context.fake.peek(path)! }))
}

function seedReport(uid: string, url: string, data: Record<string, unknown>): string {
  const path = `users/${uid}/communityReports/laporan-${uid}-${context.fake.paths().length}`
  context.fake.seed(path, {
    ownerId: uid,
    userName: `Pelapor ${uid}`,
    urlHash: hashUrl(url),
    url,
    hostname: new URL(url).hostname,
    category: 'other',
    reason: 'Alasan yang cukup panjang untuk lolos validasi proyek ini.',
    createdAt: Timestamp.fromMillis(BASE_UTC),
    updatedAt: Timestamp.fromMillis(BASE_UTC),
    ...data,
  })
  return path
}

function fakeNow(millis: number): void {
  vi.spyOn(Date, 'now').mockReturnValue(millis)
}

async function expectHttpsError(
  code: string,
  action: () => Promise<unknown>,
): Promise<{ message: string; details?: { reason?: string } }> {
  const error = await action().then(
    () => null,
    (caught: unknown) => caught as { code?: string; message: string; details?: { reason?: string } },
  )

  if (!error) throw new Error('Backend seharusnya menolak permintaan ini.')
  expect(error.code).toBe(code)
  return error
}

type CallableRequest = { auth?: { uid: string; token: Record<string, unknown> } | null }

function capture(
  guard: (request: CallableRequest) => unknown,
  request: CallableRequest,
): { code?: string; message: string } {
  try {
    guard(request)
  } catch (caught) {
    return caught as { code?: string; message: string }
  }
  throw new Error('Gerbang autentikasi seharusnya menolak permintaan ini.')
}

beforeEach(() => {
  context.fake.reset()
  fakeNow(BASE_UTC)
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('gerbang autentikasi laporan komunitas', () => {
  it('menolak permintaan tanpa sesi login', () => {
    const error = capture(callable.requireAccount, { auth: null })
    expect(error.code).toBe('unauthenticated')
  })

  it('menolak sesi anonim karena sesi tamu dipakai untuk scan tanpa akun', () => {
    const error = capture(callable.requireAccount, {
      auth: { uid: 'guest-1', token: { firebase: { sign_in_provider: 'anonymous' } } },
    })

    expect(error.code).toBe('permission-denied')
  })

  it('menolak token tanpa klaim email terverifikasi', () => {
    const error = capture(callable.requireAccount, {
      auth: {
        uid: 'uid-belum-verify',
        token: { firebase: { sign_in_provider: 'password' }, email_verified: false },
      },
    })

    expect(error.code).toBe('permission-denied')
  })

  it('mengambil identitas dari token, bukan dari isi permintaan', () => {
    const submitter = callable.requireAccount({
      auth: {
        uid: 'uid-airin',
        token: { name: 'Airin Nazua', uid: 'uid-penyerang', email_verified: true },
      },
    })

    expect(submitter).toEqual({ uid: 'uid-airin', name: 'Airin Nazua' })
  })
})

describe('gerbang callable untuk jalur baca data komunitas', () => {
  const verifiedCall = (data: unknown) => ({
    auth: { uid: 'uid-a', token: { name: 'Andi', email_verified: true } },
    data,
  })

  function spyOnReads() {
    return [vi.spyOn(context.fake, 'collection'), vi.spyOn(context.fake, 'collectionGroup')] as const
  }

  it('getCommunityContext menolak tanpa sesi tanpa membaca Firestore', async () => {
    const [collectionSpy, groupSpy] = spyOnReads()

    await expectHttpsError('unauthenticated', () =>
      callable.getCommunityContextHandler({ auth: null, data: { url: REPORT_INPUT.url } }),
    )

    expect(collectionSpy).not.toHaveBeenCalled()
    expect(groupSpy).not.toHaveBeenCalled()
  })

  it('getCommunityContext menolak sesi anonim dan akun yang belum verifikasi email', async () => {
    const [, groupSpy] = spyOnReads()

    await expectHttpsError('permission-denied', () =>
      callable.getCommunityContextHandler({
        auth: { uid: 'guest-1', token: { firebase: { sign_in_provider: 'anonymous' } } },
        data: { url: REPORT_INPUT.url },
      }),
    )
    await expectHttpsError('permission-denied', () =>
      callable.getCommunityContextHandler({
        auth: { uid: 'uid-belum-verify', token: { email_verified: false } },
        data: { url: REPORT_INPUT.url },
      }),
    )

    expect(groupSpy).not.toHaveBeenCalled()
  })

  it('getCommunityContext memakai uid dari token untuk riwayat milik pemanggil', async () => {
    context.fake.seed('users/uid-a', { displayName: 'Andi' })
    await service.submitCommunityReport({ uid: 'uid-a', name: null }, REPORT_INPUT)
    seedReport('uid-b', REPORT_INPUT.url, { userName: 'Bunga' })

    // uid di isi permintaan sengaja milik akun lain: riwayat yang dikembalikan tetap punya uid-a.
    const result = await callable.getCommunityContextHandler(
      verifiedCall({ url: REPORT_INPUT.url, uid: 'uid-b' }),
    )

    expect(result.report?.userName).toBe('Andi')
    expect(result.reports.map((entry) => entry.userName).sort()).toEqual(['Andi', 'Bunga'])
  })

  it('listCommunityReports menolak pembaca tanpa akun terverifikasi', async () => {
    const [, groupSpy] = spyOnReads()
    seedReport('uid-x', 'https://situs-segar.id/promo', { userName: 'Xenia' })

    await expectHttpsError('unauthenticated', () =>
      callable.listCommunityReportsHandler({ auth: null, data: {} }),
    )
    await expectHttpsError('permission-denied', () =>
      callable.listCommunityReportsHandler({
        auth: { uid: 'guest-2', token: { firebase: { sign_in_provider: 'anonymous' } } },
        data: {},
      }),
    )

    expect(groupSpy).not.toHaveBeenCalled()
  })

  it('listCommunityReports melayani akun terverifikasi', async () => {
    seedReport('uid-x', 'https://situs-segar.id/promo', {
      userName: 'Xenia',
      createdAt: Timestamp.fromMillis(BASE_UTC - 60_000),
      updatedAt: Timestamp.fromMillis(BASE_UTC - 60_000),
    })

    const result = await callable.listCommunityReportsHandler(verifiedCall({ limit: 20 }))

    expect(result.reports.map((entry) => entry.userName)).toEqual(['Xenia'])
  })

  it('reviewCommunityReport menolak sesi tanpa klaim admin sebelum membaca data', async () => {
    const [collectionSpy, groupSpy] = spyOnReads()

    await expectHttpsError('permission-denied', () =>
      callable.reviewCommunityReportHandler({
        auth: { uid: 'uid-a', token: { email_verified: true } },
        data: REPORT_INPUT,
      }),
    )
    await expectHttpsError('unauthenticated', () =>
      callable.reviewCommunityReportHandler({ auth: null, data: REPORT_INPUT }),
    )

    expect(collectionSpy).not.toHaveBeenCalled()
    expect(groupSpy).not.toHaveBeenCalled()
  })

  // Jalur SUKSES moderasi. Yang diuji adalah sumber kewenangannya: klaim `admin` dibaca dari
  // token ID yang sudah diverifikasi Firebase (reviewCommunityReportHandler memeriksa
  // auth.token.admin), BUKAN dari isi permintaan. Karena itu satu-satunya cara frontend
  // "mengklaim admin" adalah lewat token, dan token palsu tidak dapat dibuat klien.
  it('reviewCommunityReport melayani token admin dan hanya itu yang mengubah status', async () => {
    context.fake.seed('users/uid-pelapor', { displayName: 'Pelapor Satu' })
    await service.submitCommunityReport(
      { uid: 'uid-pelapor', name: 'Pelapor Satu' },
      REPORT_INPUT,
    )

    const sebelum = context.fake.peek(summaryPath(REPORT_INPUT.url))
    expect(sebelum?.moderationStatus).toBe('community_reported')

    const hasil = await callable.reviewCommunityReportHandler({
      auth: { uid: 'uid-admin', token: { email_verified: true, admin: true } },
      data: {
        url: REPORT_INPUT.url,
        status: 'verified_malicious',
        verificationSource: 'phish_tank',
        note: 'Dikonfirmasi dari sumber verifikasi eksternal.',
      },
    })

    expect(hasil.moderationStatus).toBe('verified_malicious')
    expect(hasil.reviewRequired).toBe(false)
    expect(hasil.verificationSource).toBe('phish_tank')
    expect(hasil.verifiedAt).toBeTypeOf('string')

    // Perubahan status benar-benar tertulis di sisi server, bukan hanya di respons.
    const sesudah = context.fake.peek(summaryPath(REPORT_INPUT.url))
    expect(sesudah?.moderationStatus).toBe('verified_malicious')

    // Jejak audit memakai uid dari token, bukan identitas yang dikirim pemanggil.
    const auditPaths = context.fake
      .paths()
      .filter((path) => path.startsWith('communityModerationAudit/'))
    expect(auditPaths).toHaveLength(1)
    expect(context.fake.peek(auditPaths[0])?.adminUid).toBe('uid-admin')
    expect(context.fake.peek(auditPaths[0])?.previousStatus).toBe('community_reported')

    // Akun biasa yang menyertakan `admin: true` di isi permintaan tetap ditolak dan tidak ada
    // satu pun tulis tambahan terjadi; klaim dari frontend tidak pernah dipercaya.
    await expectHttpsError('permission-denied', () =>
      callable.reviewCommunityReportHandler({
        auth: { uid: 'uid-pelapor', token: { email_verified: true } },
        data: {
          url: REPORT_INPUT.url,
          status: 'cleared',
          admin: true,
          isAdmin: true,
          role: 'admin',
        },
      }),
    )

    expect(context.fake.peek(summaryPath(REPORT_INPUT.url))?.moderationStatus).toBe(
      'verified_malicious',
    )
    expect(
      context.fake.paths().filter((path) => path.startsWith('communityModerationAudit/')),
    ).toHaveLength(1)
  })

  it('token admin tanpa sesi sama sekali tetap ditolak sebelum Firestore disentuh', async () => {
    const [collectionSpy, groupSpy] = spyOnReads()

    await expectHttpsError('unauthenticated', () =>
      callable.reviewCommunityReportHandler({
        auth: null,
        data: { url: REPORT_INPUT.url, status: 'cleared', admin: true },
      }),
    )

    expect(collectionSpy).not.toHaveBeenCalled()
    expect(groupSpy).not.toHaveBeenCalled()
  })
})

describe('batas satu laporan per akun per hari kalender', () => {
  it('menyimpan laporan pertama dengan nama dari profil akun', async () => {
    context.fake.seed('users/uid-bima', { displayName: 'Bima Santosa' })

    const result = await service.submitCommunityReport(
      { uid: 'uid-bima', name: 'Bima (token)' },
      REPORT_INPUT,
    )

    const reports = storedReports('uid-bima')
    const stored = reports[0]?.data
    expect(result.created).toBe(true)
    expect(reports).toHaveLength(1)
    expect(reports[0].path).toMatch(/^users\/uid-bima\/communityReports\/[^/]+$/)
    expect(stored?.userName).toBe('Bima Santosa')
    expect(stored?.reason).toBe(REASON)
    expect(stored?.url).toBe(REPORT_INPUT.url)
    expect(stored?.createdAt).toBeInstanceOf(Timestamp)
    const summary = context.fake.peek(summaryPath(REPORT_INPUT.url))
    expect(summary?.reportCount).toBe(1)
    expect(summary?.reporterCount).toBe(1)
    expect(context.fake.peek(`communityRateLimits/uid-bima`)?.dailyPeriod).toBe('2026-10-20')
  })

  it('abaikan nama yang dikirim klien agar identitas tidak dapat dipalsukan', async () => {
    context.fake.seed('users/uid-bima', { displayName: 'Bima Santosa' })

    await service.submitCommunityReport({ uid: 'uid-bima', name: null }, {
      ...REPORT_INPUT,
      userName: 'Admin Veriguard',
      ownerId: 'orang-lain',
    } as unknown as Record<string, unknown>)

    const stored = storedReports('uid-bima')[0]?.data
    expect(stored?.userName).toBe('Bima Santosa')
    expect(stored?.ownerId).toBe('uid-bima')
  })

  it('menolak laporan kedua pada hari yang sama dengan pesan status yang diminta', async () => {
    context.fake.seed('users/uid-rani', { displayName: 'Rani Halim' })
    await service.submitCommunityReport({ uid: 'uid-rani', name: null }, REPORT_INPUT)

    const before = storedReports('uid-rani')
    const beforeSummary = context.fake.peek(summaryPath(REPORT_INPUT.url))

    fakeNow(LATE_SAME_DAY_UTC)
    const otherUrl = { ...REPORT_INPUT, url: 'https://toko-aneh.id/promo' }
    const error = await expectHttpsError('resource-exhausted', () =>
      service.submitCommunityReport({ uid: 'uid-rani', name: null }, otherUrl),
    )

    expect(error.message).toBe('Laporan Anda untuk sesi ini sudah diberikan.')
    expect(error.details?.reason).toBe('daily_limit_reached')
    expect(error.message).not.toMatch(/ditolak/i)

    // Laporan lama tidak diubah, dan tidak ada dokumen baru untuk URL kedua.
    expect(storedReports('uid-rani')).toEqual(before)
    expect(context.fake.peek(summaryPath(REPORT_INPUT.url))).toEqual(beforeSummary)
    expect(context.fake.has(summaryPath(otherUrl.url))).toBe(false)
  })

  it('membuka peluang baru pada hari kalender berikutnya tanpa menimpa laporan lama', async () => {
    context.fake.seed('users/uid-rani', { displayName: 'Rani Halim' })
    await service.submitCommunityReport({ uid: 'uid-rani', name: null }, REPORT_INPUT)
    const [first] = storedReports('uid-rani')

    // Baku tanpa konfigurasi adalah UTC; peluang baru terbuka pada 00:00 UTC berikutnya.
    expect(service.communityTimezone('')).toBe('UTC')
    expect(service.dailyPeriod(NEXT_UTC_DAY, 'UTC')).toBe('2026-10-21')
    fakeNow(NEXT_UTC_DAY)

    const result = await service.submitCommunityReport(
      { uid: 'uid-rani', name: null },
      { ...REPORT_INPUT, reason: 'Hari berikutnya situs yang sama masih mencurigakan.' },
    )

    const reports = storedReports('uid-rani')
    expect(result.created).toBe(true)
    expect(reports).toHaveLength(2)
    expect(reports.map((entry) => entry.path)).toContain(first.path)
    expect(context.fake.peek(first.path)).toEqual(first.data)
    expect(result.summary.reportCount).toBe(2)
    expect(result.summary.reporterCount).toBe(1)
    expect(context.fake.peek(`communityRateLimits/uid-rani`)?.dailyPeriod).toBe('2026-10-21')
  })

  it('memakai zona waktu configured dan jatuh ke UTC bila nilainya tidak dikenal', () => {
    expect(service.communityTimezone('')).toBe('UTC')
    expect(service.communityTimezone('Asia/Jakarta')).toBe('Asia/Jakarta')
    expect(service.communityTimezone('Zone/Buatan')).toBe('UTC')
    expect(service.dailyPeriod(Date.parse('2026-06-01T17:30:00Z'), 'UTC')).toBe('2026-06-01')
    expect(service.dailyPeriod(Date.parse('2026-06-01T17:30:00Z'), 'Asia/Jakarta')).toBe(
      '2026-06-02',
    )
  })

  it('batas harian berlaku per akun, bukan satu kuota global', async () => {
    context.fake.seed('users/uid-a', { displayName: 'Andi' })
    context.fake.seed('users/uid-b', { displayName: 'Bunga' })
    await service.submitCommunityReport({ uid: 'uid-a', name: null }, REPORT_INPUT)

    const result = await service.submitCommunityReport({ uid: 'uid-b', name: null }, REPORT_INPUT)

    expect(result.summary.reportCount).toBe(2)
    expect(result.summary.reporterCount).toBe(2)
    expect(result.created).toBe(true)
  })

  it('dua permintaan concurrent tidak dapat menembus batas harian', async () => {
    context.fake.seed('users/uid-putri', { displayName: 'Putri Ini' })

    const attempts = await Promise.allSettled([
      service.submitCommunityReport({ uid: 'uid-putri', name: null }, REPORT_INPUT),
      service.submitCommunityReport({ uid: 'uid-putri', name: null }, REPORT_INPUT),
    ])

    const succeeded = attempts.filter((entry) => entry.status === 'fulfilled')
    const failed = attempts.filter((entry) => entry.status === 'rejected')
    expect(succeeded).toHaveLength(1)
    expect(failed).toHaveLength(1)

    const reason = failed[0] as { reason: { code?: string; message?: string } }
    expect(reason.reason.code).toBe('resource-exhausted')
    expect(reason.reason.message).toBe('Laporan Anda untuk sesi ini sudah diberikan.')

    expect(context.fake.paths().filter((path) => path.includes('/communityReports/'))).toHaveLength(1)
    expect(context.fake.peek(summaryPath(REPORT_INPUT.url))?.reportCount).toBe(1)
    expect(context.fake.peek(summaryPath(REPORT_INPUT.url))?.reporterCount).toBe(1)
    expect(context.fake.events.filter((event) => event === 'transaction-aborted-retry')).toHaveLength(
      1,
    )
  })
})

describe('konteks komunitas per URL ternormalisasi', () => {
  it('menampilkan nama dan isi laporan dari akun yang melapor untuk URL yang sama', async () => {
    context.fake.seed('users/uid-a', { displayName: 'Andi' })
    context.fake.seed('users/uid-b', { displayName: 'Bunga' })
    await service.submitCommunityReport(
      { uid: 'uid-a', name: null },
      { ...REPORT_INPUT, url: 'https://contoh-bank-palsu.id/login?utm_source=sms' },
    )
    // Kedua akun punya kuota hariannya masing-masing, jadi laporan kedua tetap masuk.
    await service.submitCommunityReport(
      { uid: 'uid-b', name: null },
      {
        ...REPORT_INPUT,
        category: 'impersonation',
        reason: 'Formulirnya mengaku bank dan meminta OTP.',
      },
    )

    const contextResult = await service.getCommunityContext('uid-a', {
      url: 'https://Contoh-Bank-Palsu.id:443/login#form',
    })

    expect(contextResult.summary?.reportCount).toBe(2)
    expect(contextResult.summary?.reporterCount).toBe(2)
    expect(contextResult.reports).toHaveLength(2)
    expect(contextResult.reports.map((entry) => entry.userName).sort()).toEqual(['Andi', 'Bunga'])
    expect(contextResult.report?.userName).toBe('Andi')
  })

  it('menampilkan laporan terbaru milik akun saat URL yang sama dilaporkan lagi', async () => {
    context.fake.seed('users/uid-rani', { displayName: 'Rani Halim' })
    await service.submitCommunityReport({ uid: 'uid-rani', name: null }, REPORT_INPUT)
    fakeNow(NEXT_UTC_DAY)
    await service.submitCommunityReport(
      { uid: 'uid-rani', name: null },
      { ...REPORT_INPUT, reason: 'Laporan kedua pada hari berikutnya untuk URL yang sama.' },
    )

    const contextResult = await service.getCommunityContext('uid-rani', {
      url: REPORT_INPUT.url,
    })

    expect(contextResult.reports).toHaveLength(2)
    expect(contextResult.summary?.reportCount).toBe(2)
    expect(contextResult.summary?.reporterCount).toBe(1)
    expect(contextResult.report?.reason).toContain('Laporan kedua')
    expect(contextResult.reports[0].reportText).toContain('Laporan kedua')
  })

  it('tetap memilih laporan terbaru milik akun saat riwayatnya melebihi batas tampilan', async () => {
    context.fake.seed('users/uid-rani', { displayName: 'Rani Halim' })
    const dayMs = 24 * 60 * 60 * 1000

    for (let index = 0; index < 21; index += 1) {
      fakeNow(BASE_UTC + index * dayMs)
      await service.submitCommunityReport(
        { uid: 'uid-rani', name: null },
        { ...REPORT_INPUT, reason: `Laporan hari ke-${index + 1} untuk URL yang sama.` },
      )
    }

    const contextResult = await service.getCommunityContext('uid-rani', {
      url: REPORT_INPUT.url,
    })

    expect(contextResult.report?.reason).toContain('hari ke-21')
    expect(contextResult.summary?.reportCount).toBe(21)
    expect(contextResult.summary?.reporterCount).toBe(1)
  })

  it('tidak membocorkan laporan untuk URL lain', async () => {
    context.fake.seed('users/uid-a', { displayName: 'Andi' })
    await service.submitCommunityReport({ uid: 'uid-a', name: null }, REPORT_INPUT)

    const other = await service.getCommunityContext('uid-a', {
      url: 'https://situs-lain.id/berita',
    })

    expect(other.reports).toEqual([])
    expect(other.summary).toBeNull()
    expect(other.report).toBeNull()
  })

  it('kegagalan pengambilan tampil sebagai error, bukan dianggap tanpa laporan', async () => {
    const broken = new Error('Firestore tidak dapat dihubungi.')
    vi.spyOn(context.fake, 'collectionGroup').mockImplementation(() => {
      throw broken
    })

    await expect(service.getCommunityContext('uid-a', { url: REPORT_INPUT.url })).rejects.toThrow(
      broken,
    )
    await expect(service.listCommunityReports({})).rejects.toThrow(broken)
  })
})

describe('daftar laporan 24 jam terakhir', () => {
  it('memakai stempel waktu server dan membuang laporan di luar jendela rolling 24 jam', async () => {
    const fresh = 'https://situs-segar.id/promo'
    const stale = 'https://situs-lama.id/promo'
    seedReport('uid-x', fresh, {
      userName: 'Xenia',
      hostname: 'situs-segar.id',
      category: 'giveaway',
      reason: 'Undian palsu yang meminta biaya administrasi di awal.',
      createdAt: Timestamp.fromMillis(BASE_UTC - 60_000),
      updatedAt: Timestamp.fromMillis(BASE_UTC - 60_000),
    })
    const stalePath = seedReport('uid-y', stale, {
      userName: 'Yoga',
      hostname: 'situs-lama.id',
      category: 'marketplace',
      reason: 'Penjual tidak mengirim barang setelah pembayaran lunas.',
      createdAt: Timestamp.fromMillis(BASE_UTC - 30 * 24 * 60 * 60 * 1000),
      updatedAt: Timestamp.fromMillis(BASE_UTC - 30 * 24 * 60 * 60 * 1000),
    })

    const reports = await service.listCommunityReports({ limit: 20 })

    expect(reports.map((entry) => entry.userName)).toEqual(['Xenia'])
    expect(reports[0].reportText).toContain('Undian palsu')
    expect(context.fake.has(stalePath)).toBe(true)
  })

  it('mengurutkan laporan terbaru lebih dulu berdasarkan waktu dibuat', async () => {
    for (const [index, host] of ['satu.id', 'dua.id', 'tiga.id'].entries()) {
      const url = `https://${host}/page`
      seedReport(`uid-${index}`, url, {
        userName: `Pelapor ${index}`,
        hostname: host,
        category: 'other',
        createdAt: Timestamp.fromMillis(BASE_UTC + index * 1000),
        updatedAt: Timestamp.fromMillis(BASE_UTC - index * 1000),
      })
    }

    const reports = await service.listCommunityReports({})

    expect(reports.map((entry) => entry.userName)).toEqual([
      'Pelapor 2',
      'Pelapor 1',
      'Pelapor 0',
    ])
  })

  it('hasil kosong hanya untuk keadaan benar-benar kosong', async () => {
    await expect(service.listCommunityReports({})).resolves.toEqual([])
  })
})

import { createHash } from 'node:crypto'
import { getApps, initializeApp } from 'firebase-admin/app'
import {
  Timestamp,
  getFirestore,
  type DocumentData,
  type DocumentReference,
  type Transaction,
} from 'firebase-admin/firestore'
import { HttpsError } from 'firebase-functions/v2/https'
import {
  COMMUNITY_CATEGORIES,
  COMMUNITY_COLLECTIONS,
  COMMUNITY_DAILY_LIMIT_MESSAGE,
  COMMUNITY_DAILY_LIMIT_REASON,
  COMMUNITY_FALLBACK_USER_NAME,
  COMMUNITY_MODERATION_STATUSES,
  COMMUNITY_POLICY,
  COMMUNITY_TIMEZONE_DEFAULT,
  type CommunityCategory,
  type CommunityContextResponse,
  type CommunityModerationStatus,
  type CommunityReportEntry,
  type CommunityReportResponse,
  type CommunitySubmitter,
  type CommunitySummaryResponse,
  type ReviewCommunityReportInput,
  type SubmitCommunityReportInput,
  type SubmitResult,
} from './types.js'
import { parseListLimit, parseReviewInput, parseSubmitInput, parseUrlPayload } from './validation.js'

const CATEGORY_IDS = new Set<string>(COMMUNITY_CATEGORIES)
const MODERATION_IDS = new Set<string>(COMMUNITY_MODERATION_STATUSES)

if (getApps().length === 0) {
  initializeApp()
}

const db = getFirestore()

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function hashUrl(url: string): string {
  return createHash('sha256').update(url).digest('hex')
}

function toTimestamp(value: unknown): Timestamp | null {
  if (value instanceof Timestamp) return value
  if (value instanceof Date) return Timestamp.fromDate(value)
  return null
}

function toIso(value: unknown): string | null {
  return toTimestamp(value)?.toDate().toISOString() ?? null
}

function readCount(value: unknown): number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : 0
}

/**
 * Ringkasan lama (V4) hanya punya reportCount yang sekaligus berarti jumlah akun unik.
 * Nilai itu dipakai sebagai fallback supaya data komunitas yang sudah ada tetap terbaca.
 */
function readReporterCount(data: DocumentData): number {
  return typeof data.reporterCount === 'number'
    ? readCount(data.reporterCount)
    : readCount(data.reportCount)
}

function readCategory(value: unknown): CommunityCategory | null {
  return typeof value === 'string' && CATEGORY_IDS.has(value)
    ? (value as CommunityCategory)
    : null
}

function readStatus(value: unknown): CommunityModerationStatus | null {
  return typeof value === 'string' && MODERATION_IDS.has(value)
    ? (value as CommunityModerationStatus)
    : null
}

function readOptionalString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null
}

/**
 * Nama pelapor selalu diambil dari data yang ditulis backend (profil akun), bukan dari
 * isi permintaan. Dokumen lama tanpa nama ditampilkan sebagai label netral, bukan nama
 * yang dikarang.
 */
function readUserName(value: unknown): string {
  const name = readOptionalString(value)
  if (!name) return COMMUNITY_FALLBACK_USER_NAME
  return name.slice(0, COMMUNITY_POLICY.maxUserNameLength)
}

function readCategoryCounts(value: unknown): Partial<Record<CommunityCategory, number>> {
  if (!isRecord(value)) return {}

  const counts: Partial<Record<CommunityCategory, number>> = {}
  for (const [key, rawCount] of Object.entries(value)) {
    const category = readCategory(key)
    if (category && typeof rawCount === 'number' && Number.isInteger(rawCount) && rawCount > 0) {
      counts[category] = rawCount
    }
  }
  return counts
}

function summaryResponse(data: DocumentData): CommunitySummaryResponse {
  return {
    hostname: typeof data.hostname === 'string' ? data.hostname : '',
    reportCount: readCount(data.reportCount),
    reporterCount: readReporterCount(data),
    categoryCounts: readCategoryCounts(data.categoryCounts),
    firstReportedAt: toIso(data.firstReportedAt),
    lastReportedAt: toIso(data.lastReportedAt),
    lastActivityAt: toIso(data.lastActivityAt),
    moderationStatus: readStatus(data.moderationStatus) ?? 'community_reported',
    reviewRequired: data.reviewRequired === true,
    reviewReason: readOptionalString(data.reviewReason),
    verificationSource: readOptionalString(data.verificationSource),
    verifiedAt: toIso(data.verifiedAt),
  }
}

function reportResponse(data: DocumentData): CommunityReportResponse {
  return {
    userName: readUserName(data.userName),
    category: readCategory(data.category) ?? 'other',
    reason: typeof data.reason === 'string' ? data.reason : '',
    createdAt: toIso(data.createdAt) ?? new Date(0).toISOString(),
    updatedAt: toIso(data.updatedAt) ?? new Date(0).toISOString(),
  }
}

function timestampsWithin(value: unknown, cutoffMs: number): Timestamp[] {
  if (!Array.isArray(value)) return []
  return value
    .filter((item): item is Timestamp => item instanceof Timestamp)
    .filter((item) => item.toMillis() >= cutoffMs)
}

/**
 * Zona waktu hari kalender untuk batas harian. Proyek belum punya konfigurasi zona waktu
 * tersendiri, jadi bakuannya UTC sesuai kontrak. Deploy dapat mengisi COMMUNITY_TIMEZONE
 * (mis. Asia/Jakarta); nilai yang tidak dikenal jatuh ke UTC agar perhitungan tetap konsisten
 * di sisi backend yang tepercaya.
 */
export function communityTimezone(
  configured: string | undefined = process.env.COMMUNITY_TIMEZONE,
): string {
  const value = configured?.trim()
  if (!value) return COMMUNITY_TIMEZONE_DEFAULT

  try {
    new Intl.DateTimeFormat('en-CA', { timeZone: value }).format(new Date(0))
    return value
  } catch {
    return 'UTC'
  }
}

const dayFormatterCache = new Map<string, Intl.DateTimeFormat>()

/** Periode harian versi server: YYYY-MM-DD menurut zona waktu yang konfigurasi pakai. */
export function dailyPeriod(millis: number, timeZone: string): string {
  let formatter = dayFormatterCache.get(timeZone)
  if (!formatter) {
    formatter = new Intl.DateTimeFormat('en-CA', {
      timeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    })
    dayFormatterCache.set(timeZone, formatter)
  }
  return formatter.format(new Date(millis))
}

/**
 * Gerbang satu laporan per akun per hari kalender. Dibaca dan ditulis di dalam transaksi
 * yang sama dengan laporan, jadi permintaan concurrent tidak bisa lolos: transaksi yang
 * membaca dokumen batas yang kemudian diubah permintaan lain akan diulang, dan pada
 * pengulangan itu periode hari ini sudah terisi.
 */
function assertDailyAllowance(data: DocumentData | undefined, now: Timestamp, period: string): void {
  const usedPeriod = readOptionalString(data?.dailyPeriod)
  if (usedPeriod !== period) return

  throw new HttpsError('resource-exhausted', COMMUNITY_DAILY_LIMIT_MESSAGE, {
    reason: COMMUNITY_DAILY_LIMIT_REASON,
  })
}

function updateDailyAllowance(
  transaction: Transaction,
  ref: DocumentReference,
  now: Timestamp,
  period: string,
): void {
  transaction.set(
    ref,
    {
      dailyPeriod: period,
      lastWriteAt: now,
      updatedAt: now,
    },
    { merge: true },
  )
}

function incrementCategory(
  counts: Partial<Record<CommunityCategory, number>>,
  category: CommunityCategory,
  delta: 1 | -1,
): void {
  const current = counts[category] ?? 0
  const next = current + delta
  if (next > 0) {
    counts[category] = next
  } else {
    delete counts[category]
  }
}

function trustedUserName(submitter: CommunitySubmitter, profile: DocumentData | undefined): string {
  // Nama hanya dari profil akun hasil tulis backend, lalu token login. Nama yang dikirim
  // penyusun permintaan tidak pernah dipakai, jadi identitas tidak dapat dipalsukan.
  const profileName = readOptionalString(profile?.displayName)
  const tokenName = readOptionalString(submitter.name)
  return readUserName(profileName ?? tokenName)
}

export async function submitCommunityReport(
  submitter: CommunitySubmitter,
  data: unknown,
): Promise<SubmitResult> {
  const input: SubmitCommunityReportInput = parseSubmitInput(data)
  return submitCommunityReportImpl(submitter, input)
}

async function submitCommunityReportImpl(
  submitter: CommunitySubmitter,
  input: SubmitCommunityReportInput,
): Promise<SubmitResult> {
  const uid = submitter.uid
  const url = input.url
  const hostname = new URL(url).hostname
  const urlHash = hashUrl(url)
  const summaryRef = db.collection(COMMUNITY_COLLECTIONS.summaries).doc(urlHash)
  const reportsRef = db
    .collection('users')
    .doc(uid)
    .collection(COMMUNITY_COLLECTIONS.reports)
  // Setiap pengiriman menghasilkan dokumen baru. Dokumen ini tidak pernah menimpa laporan
  // sebelumnya, termasuk saat akun yang sama melapor URL yang sama pada hari berikutnya.
  const reportRef = reportsRef.doc()
  const ownReportsQuery = reportsRef.where('urlHash', '==', urlHash).limit(1)
  const rateRef = db.collection(COMMUNITY_COLLECTIONS.rateLimits).doc(uid)
  const profileRef = db.collection('users').doc(uid)
  const now = Timestamp.now()
  const period = dailyPeriod(now.toMillis(), communityTimezone())

  return db.runTransaction(async (transaction) => {
    // Semua pembacaan harus selesai sebelum penulisan, sesuai aturan transaksi Firestore.
    const [rateSnapshot, summarySnapshot, profileSnapshot, ownReportsSnapshot] =
      await Promise.all([
        transaction.get(rateRef),
        transaction.get(summaryRef),
        transaction.get(profileRef),
        transaction.get(ownReportsQuery),
      ])

    assertDailyAllowance(rateSnapshot.data(), now, period)
    const userName = trustedUserName(submitter, profileSnapshot.data())
    const summary = summarySnapshot.exists ? summarySnapshot.data() : undefined
    const firstReportForAccount = ownReportsSnapshot.docs.length === 0
    const reportCount = (summary ? readCount(summary.reportCount) : 0) + 1
    const reporterCount =
      (summary ? readReporterCount(summary) : 0) + (firstReportForAccount ? 1 : 0)

    const counts = readCategoryCounts(summary?.categoryCounts)
    incrementCategory(counts, input.category, 1)
    const recentReportAt = timestampsWithin(
      summary?.recentReportAt,
      now.toMillis() - COMMUNITY_POLICY.spikeWindowMs,
    )
    recentReportAt.push(now)

    let moderationStatus = readStatus(summary?.moderationStatus) ?? 'community_reported'
    let reviewReason = readOptionalString(summary?.reviewReason)
    let verificationSource = readOptionalString(summary?.verificationSource)
    let verifiedAt = toTimestamp(summary?.verifiedAt)

    if (moderationStatus === 'cleared') {
      moderationStatus = 'community_reported'
      reviewReason = null
    }

    if (
      moderationStatus === 'community_reported' &&
      recentReportAt.length >= COMMUNITY_POLICY.spikeReportCount
    ) {
      moderationStatus = 'under_review'
      reviewReason = 'report_spike'
    }

    if (moderationStatus !== 'under_review') {
      reviewReason = null
    } else if (!reviewReason) {
      reviewReason = 'manual_review'
    }

    if (moderationStatus !== 'verified_malicious') {
      verificationSource = null
      verifiedAt = null
    }

    const summaryCreatedAt = toTimestamp(summary?.createdAt) ?? now
    const firstReportedAt = toTimestamp(summary?.firstReportedAt) ?? now

    const reportData = {
      ownerId: uid,
      userName,
      urlHash,
      // `url` adalah URL ternormalisasi; konvensi nama kolom proyek dipertahankan.
      url,
      hostname,
      category: input.category,
      reason: input.reason,
      createdAt: now,
      updatedAt: now,
    }

    const summaryData = {
      url,
      hostname,
      urlHash,
      reportCount,
      reporterCount,
      categoryCounts: counts,
      firstReportedAt,
      lastReportedAt: now,
      lastActivityAt: now,
      recentReportAt,
      moderationStatus,
      reviewRequired: moderationStatus === 'under_review',
      reviewReason,
      verificationSource,
      verifiedAt,
      createdAt: summaryCreatedAt,
      updatedAt: now,
    }

    transaction.set(reportRef, reportData)
    transaction.set(summaryRef, summaryData)
    updateDailyAllowance(transaction, rateRef, now, period)

    return {
      created: true,
      summary: summaryResponse(summaryData as DocumentData),
      report: reportResponse(reportData as DocumentData),
    }
  })
}

function reportEntry(data: DocumentData): CommunityReportEntry {
  return {
    userName: readUserName(data.userName),
    reportText: typeof data.reason === 'string' ? data.reason : '',
    category: readCategory(data.category) ?? 'other',
    hostname: typeof data.hostname === 'string' ? data.hostname : '',
    createdAt: toIso(data.createdAt) ?? new Date(0).toISOString(),
    updatedAt: toIso(data.updatedAt) ?? new Date(0).toISOString(),
  }
}

export async function getCommunityContext(
  uid: string | undefined,
  data: unknown,
): Promise<CommunityContextResponse> {
  const url = parseUrlPayload(data)
  const urlHash = hashUrl(url)
  const summaryRef = db.collection(COMMUNITY_COLLECTIONS.summaries).doc(urlHash)
  // Riwayat satu akun untuk satu URL dibatasi kuota harian dan retensi, jadi dibaca penuh
  // agar laporan terbaru tidak terpotong oleh limit tampilan.
  const ownReportsQuery = uid
    ? db
        .collection('users')
        .doc(uid)
        .collection(COMMUNITY_COLLECTIONS.reports)
        .where('urlHash', '==', urlHash)
    : null

  // Laporan disimpan per akun, jadi pencarian lintas akun untuk URL yang sama memakai
  // collection group. Kegagalan query ini harus tampil sebagai error, bukan "tanpa laporan".
  const [summarySnapshot, ownSnapshot, reportsSnapshot] = await Promise.all([
    summaryRef.get(),
    ownReportsQuery ? ownReportsQuery.get() : Promise.resolve(null),
    db
      .collectionGroup(COMMUNITY_COLLECTIONS.reports)
      .where('urlHash', '==', urlHash)
      .orderBy('createdAt', 'desc')
      .limit(COMMUNITY_POLICY.contextReportLimit)
      .get(),
  ])

  const ownReports = (ownSnapshot?.docs ?? [])
    .map((doc) => doc.data())
    .filter((value): value is DocumentData => value !== undefined)
    .sort(
      (left, right) =>
        (toTimestamp(right.createdAt)?.toMillis() ?? 0) -
        (toTimestamp(left.createdAt)?.toMillis() ?? 0),
    )

  return {
    summary: summarySnapshot.exists ? summaryResponse(summarySnapshot.data()!) : null,
    report: ownReports.length > 0 ? reportResponse(ownReports[0]) : null,
    reports: reportsSnapshot.docs
      .map((doc) => doc.data())
      .filter((value): value is DocumentData => value !== undefined)
      .map(reportEntry),
  }
}

/**
 * Laporan yang benar-benar dikirim dalam 24 jam terakhir, terbaru lebih dulu. Ini tampilan
 * waktu saja: dokumen tidak pernah dihapus karena keluar dari jendela ini.
 */
export async function listCommunityReports(data: unknown): Promise<CommunityReportEntry[]> {
  const limit = parseListLimit(data)
  const cutoff = Timestamp.fromMillis(Date.now() - COMMUNITY_POLICY.recentWindowMs)
  const snapshot = await db
    .collectionGroup(COMMUNITY_COLLECTIONS.reports)
    .where('createdAt', '>=', cutoff)
    .orderBy('createdAt', 'desc')
    .limit(limit)
    .get()

  return snapshot.docs
    .map((doc) => doc.data())
    .filter((value): value is DocumentData => value !== undefined)
    .map(reportEntry)
}

export async function reviewCommunityReport(
  adminUid: string,
  data: unknown,
): Promise<CommunitySummaryResponse> {
  const input: ReviewCommunityReportInput = parseReviewInput(data)
  const urlHash = hashUrl(input.url)
  const summaryRef = db.collection(COMMUNITY_COLLECTIONS.summaries).doc(urlHash)
  const auditRef = db.collection(COMMUNITY_COLLECTIONS.moderationAudit).doc()
  const now = Timestamp.now()

  await db.runTransaction(async (transaction) => {
    const snapshot = await transaction.get(summaryRef)
    if (!snapshot.exists) {
      throw new HttpsError('not-found', 'Ringkasan komunitas untuk URL ini tidak ditemukan.')
    }

    const current = snapshot.data()!
    const previousStatus = readStatus(current.moderationStatus) ?? 'community_reported'
    const reportCount = readCount(current.reportCount)

    if (reportCount < 1) {
      throw new HttpsError(
        'failed-precondition',
        'Tidak ada laporan aktif yang dapat dimoderasi untuk URL ini.',
      )
    }

    const verified = input.status === 'verified_malicious'
    const underReview = input.status === 'under_review'

    transaction.set(
      summaryRef,
      {
        moderationStatus: input.status,
        reviewRequired: underReview,
        reviewReason: underReview ? 'manual_review' : null,
        verificationSource: verified ? input.verificationSource : null,
        verifiedAt: verified ? now : null,
        recentReportAt: input.status === 'cleared' ? [] : current.recentReportAt ?? [],
        updatedAt: now,
      },
      { merge: true },
    )

    transaction.set(auditRef, {
      urlHash,
      url: input.url,
      previousStatus,
      newStatus: input.status,
      adminUid,
      note: input.note,
      createdAt: now,
    })
  })

  const updated = await summaryRef.get()
  if (!updated.exists) {
    throw new HttpsError('internal', 'Ringkasan komunitas tidak dapat dimuat setelah moderasi.')
  }

  return summaryResponse(updated.data()!)
}

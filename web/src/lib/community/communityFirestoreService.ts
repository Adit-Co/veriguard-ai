import type { User } from 'firebase/auth'
import {
  Timestamp,
  collection,
  doc,
  getCountFromServer,
  getDoc,
  getDocs,
  limit,
  orderBy,
  query,
  runTransaction,
  serverTimestamp,
  where,
  type DocumentData,
} from 'firebase/firestore'
import type { UserProfileIdentity } from '../firebase/profileDocuments'
import { syncUserProfile } from '../firebase/profile'
import { getFirebaseClient } from '../firebase/client'
import { isFirebaseConfigured } from '../firebase/config'
import { getFirebaseErrorCode } from '../firebase/errors'
import { CommunityServiceError, dailyLimitError } from './communityErrors'
import { maskReporterName } from './reporterName'
import {
  COMMUNITY_CACHE_MAX_ENTRIES,
  COMMUNITY_CACHE_TTL_MS,
  COMMUNITY_CONTEXT_REPORT_LIMIT,
  COMMUNITY_CONTEXT_SCAN_LIMIT,
  COMMUNITY_DAILY_FEED_LIMIT,
  COMMUNITY_LATEST_LIMIT,
  COMMUNITY_REPORTER_KEY_PATTERN,
  COMMUNITY_REPORT_ID_PATTERN,
  communityDailyFeedDayEndMs,
  communityDailyFeedDayId,
  communityDailyFeedDayIdFromIso,
  communityDailyFeedDayStartMs,
  communityDayId,
  communityDayIdFromIso,
  communityUrlHash,
  createReportId,
  createReporterKey,
} from './sparkProtocol'
import {
  COMMUNITY_CATEGORY_IDS,
  MAX_REPORT_REASON_LENGTH,
  MIN_REPORT_REASON_LENGTH,
  type CommunityCategory,
  type CommunityContext,
  type CommunityLatestReportEntry,
  type CommunityReport,
  type CommunityReportEntry,
  type CommunitySummary,
  type SubmitCommunityReportInput,
  type SubmitCommunityReportResult,
} from './types'
import {
  hostnameFromCommunityUrl,
  isCommunityHostname,
  normalizeCommunityUrl,
  sanitizeCommunityUrlForDisplay,
} from './url'

const USERS_COLLECTION = 'users'
const REPORTS_ROOT = 'communityReports'
const REPORTS_SUBCOLLECTION = 'reports'
const DAY_MARKERS = 'communityReportDays'
const REPORTER_KEYS = 'communityReporterKeys'

// Umpan global adalah satu dokumen kepala berisi maksimal COMMUNITY_LATEST_LIMIT
// ID laporan, ditambah satu dokumen entri publik per laporan. Klien tidak pernah
// menanyakan seluruh koleksi; pembacaan hanya get() pada jalur yang diketahui.
const LATEST_FEED_ROOT = 'communityLatestReports'
const LATEST_FEED_HEAD_ID = 'global'
const LATEST_FEED_ENTRIES = 'entries'

// Umpan harian adalah partisi terpisah per hari WITA. Query hanya menyentuh
// partisi hari ini dan memakai createdAt dari server, sehingga laporan kemarin
// tidak pernah ikut terbaca dan tidak ada collection-group query.
const DAILY_FEED_ROOT = 'communityDailyReports'
const DAILY_FEED_REPORTS = 'reports'

const FALLBACK_USER_NAME = 'Pengguna'
const MAX_USER_NAME_LENGTH = 80

type CommunityOperation = 'context' | 'latest' | 'submit' | 'profile' | 'token'

type CommunityRequestOptions = {
  /** Hanya untuk tombol muat ulang; pembacaan normal memakai cache singkat. */
  forceRefresh?: boolean
}

type ParsedReportDoc = {
  id: string
  reporterKey: string
  userName: string
  category: CommunityCategory | null
  reason: string
  createdAt: Timestamp | null
  updatedAt: Timestamp | null
}

type ParsedLatestEntry = {
  id: string
  userName: string
  category: CommunityCategory
  reason: string
  /** Null untuk dokumen lama atau URL yang tidak dapat disanitasi dengan aman. */
  reportedUrl: string | null
  /** Null untuk dokumen lama atau nilai yang bentuknya tidak aman. */
  hostname: string | null
  createdAt: Timestamp
}

function logCommunityFailure(operation: CommunityOperation, code: string): void {
  // Hanya operasi dan kode: tanpa email, UID, token, pesan server, atau isi laporan.
  console.warn(`[community] ${operation} failed: ${code}`)
}

function readOptionalString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null
}

function readUserName(value: unknown): string {
  const name = readOptionalString(value)?.trim()
  if (!name) return FALLBACK_USER_NAME
  return name.slice(0, MAX_USER_NAME_LENGTH)
}

function readReporterKey(value: unknown): string | null {
  return typeof value === 'string' && COMMUNITY_REPORTER_KEY_PATTERN.test(value) ? value : null
}

function readCategory(value: unknown): CommunityCategory | null {
  return typeof value === 'string' && COMMUNITY_CATEGORY_IDS.has(value)
    ? (value as CommunityCategory)
    : null
}

function readTimestamp(value: unknown): Timestamp | null {
  return value instanceof Timestamp ? value : null
}

function toIso(value: Timestamp | null): string | null {
  return value ? value.toDate().toISOString() : null
}

function parseReportDoc(id: string, data: DocumentData | undefined): ParsedReportDoc {
  if (!data) {
    return {
      id,
      reporterKey: '',
      userName: FALLBACK_USER_NAME,
      category: null,
      reason: '',
      createdAt: null,
      updatedAt: null,
    }
  }

  return {
    id,
    reporterKey: readReporterKey(data.reporterKey) ?? '',
    userName: readUserName(data.userName),
    category: readCategory(data.category),
    reason: typeof data.reason === 'string' ? data.reason : '',
    createdAt: readTimestamp(data.createdAt),
    updatedAt: readTimestamp(data.updatedAt),
  }
}

function newestFirst(docs: ParsedReportDoc[]): ParsedReportDoc[] {
  return [...docs].sort(
    (left, right) => (right.createdAt?.toMillis() ?? 0) - (left.createdAt?.toMillis() ?? 0),
  )
}

function parseLatestEntryDoc(
  id: string,
  data: DocumentData | undefined,
): ParsedLatestEntry | null {
  if (!data) return null
  const category = readCategory(data.category)
  const createdAt = readTimestamp(data.createdAt)
  const reason = typeof data.reason === 'string' ? data.reason.trim() : ''
  if (!category || !createdAt || !reason) return null

  const reportedUrl = sanitizeCommunityUrlForDisplay(data.reportedUrl)

  return {
    id,
    userName: readUserName(data.userName),
    category,
    reason,
    // Sanitasi ulang saat membaca agar dokumen lama atau rusak tidak pernah
    // menampilkan query, fragment, atau kredensial yang tersimpan tanpa sengaja.
    reportedUrl,
    // Host yang dideklarasikan harus authority dari URL yang sama. Aturan Firestore
    // tidak dapat menghitung SHA-256, jadi label brand-only inilah yang masih bisa
    // dipalsukan untuk menempelkan laporan pada nama situs lain; bila tidak cocok,
    // labelnya dibuang dan URL-nya tetap tampil.
    hostname: hostnameMatchesUrl(data.hostname, reportedUrl),
    createdAt,
  }
}

function hostnameMatchesUrl(
  value: unknown,
  reportedUrl: string | null,
): string | null {
  if (!isCommunityHostname(value)) return null
  if (!reportedUrl) return value

  try {
    return new URL(reportedUrl).hostname === value ? value : null
  } catch {
    return null
  }
}

/**
 * Kepala umpan adalah daftar ID berurutan, bukan kueri. Bentuk yang tidak dikenal
 * dianggap rusak, bukan keadaan kosong: laporan yang ada tidak boleh tampak hilang
 * hanya karena dokumen kepala tidak dapat dipercaya.
 */
function readLatestHeadIds(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length > COMMUNITY_LATEST_LIMIT) return null

  const ids: string[] = []
  const seen = new Set<string>()
  for (const id of value) {
    if (
      typeof id !== 'string' ||
      !COMMUNITY_REPORT_ID_PATTERN.test(id) ||
      seen.has(id)
    ) {
      return null
    }
    seen.add(id)
    ids.push(id)
  }
  return ids
}

function latestEntryFromParsed(entry: ParsedLatestEntry): CommunityLatestReportEntry {
  return {
    id: entry.id,
    userName: entry.userName,
    reportText: entry.reason,
    category: entry.category,
    reportedUrl: entry.reportedUrl,
    hostname: entry.hostname,
    createdAt: entry.createdAt.toDate().toISOString(),
  }
}

function entryFromDoc(doc: ParsedReportDoc, fallbackHostname: string): CommunityReportEntry {
  const createdAt = toIso(doc.createdAt)
  return {
    id: doc.id,
    userName: doc.userName,
    reportText: doc.reason,
    category: doc.category ?? 'other',
    hostname: fallbackHostname,
    createdAt: createdAt ?? '',
    updatedAt: toIso(doc.updatedAt) ?? createdAt ?? '',
  }
}

function reportFromDoc(doc: ParsedReportDoc): CommunityReport | null {
  const createdAt = toIso(doc.createdAt)
  if (!createdAt) return null
  return {
    userName: doc.userName,
    category: doc.category ?? 'other',
    reason: doc.reason,
    createdAt,
    updatedAt: toIso(doc.updatedAt) ?? createdAt,
  }
}

function buildSummary(
  hostname: string,
  reportCount: number,
  scan: ParsedReportDoc[],
): CommunitySummary | null {
  if (reportCount <= 0) return null

  const timed = newestFirst(scan.filter((entry) => entry.createdAt !== null))
  const newest = timed[0]?.createdAt ?? null
  const oldest = timed[timed.length - 1]?.createdAt ?? null

  // Agregat hanya disebut lengkap bila seluruh dokumen partisi URL ini benar-benar
  // terpindai dan setiap dokumen punya pseudonim, kategori, dan waktu yang valid.
  const complete =
    reportCount <= COMMUNITY_CONTEXT_SCAN_LIMIT &&
    scan.length === reportCount &&
    scan.every(
      (entry) =>
        entry.reporterKey !== '' && entry.category !== null && entry.createdAt !== null,
    )

  let reporterCount = 0
  let categoryCounts: Partial<Record<CommunityCategory, number>> = {}
  let firstReportedAt: string | null = null

  if (complete) {
    reporterCount = new Set(scan.map((entry) => entry.reporterKey)).size
    categoryCounts = {}
    for (const entry of scan) {
      const category = entry.category as CommunityCategory
      categoryCounts[category] = (categoryCounts[category] ?? 0) + 1
    }
    firstReportedAt = toIso(oldest)
  }

  return {
    hostname,
    reportCount,
    reporterCount,
    categoryCounts,
    firstReportedAt,
    lastReportedAt: toIso(newest),
    lastActivityAt: toIso(newest),
    moderationStatus: 'community_reported',
    reviewRequired: false,
    reviewReason: null,
    verificationSource: null,
    verifiedAt: null,
    aggregatesComplete: complete,
  }
}

function isPermissionDenied(error: unknown): boolean {
  return getFirebaseErrorCode(error) === 'permission-denied'
}

type StagedError = Error & {
  code?: string
  communityStage?: string
  cause?: unknown
}

// Tahap bacaan ditambahkan tanpa mengubah kode Firebase, sehingga retry token dan
// pemetaan error tetap bekerja. Tahap hanya berisi nama jalur internal, bukan URL,
// ID laporan, email, atau UID.
function withReadStage(error: unknown, stage: string): unknown {
  const code = getFirebaseErrorCode(error)
  if (!code) return error

  const staged = new Error('community read failed') as StagedError
  staged.code = code
  staged.communityStage = stage
  staged.cause = error
  return staged
}

function readStageOf(error: unknown): string | null {
  if (!error || typeof error !== 'object' || !('communityStage' in error)) return null
  const stage = (error as { communityStage?: unknown }).communityStage
  return typeof stage === 'string' && /^[a-z-]{1,32}$/.test(stage) ? stage : null
}

function accessDeniedMessage(operation: CommunityOperation): string {
  return operation === 'submit'
    ? 'Laporan tidak dapat disimpan karena akun ini tidak memiliki izin menulis. Sesi sudah diperbarui, tetapi akses tetap ditolak. Coba masuk kembali; bila masih gagal, hubungi pengelola layanan.'
    : 'Laporan komunitas tidak dapat dibaca karena akun ini tidak memiliki izin. Sesi sudah diperbarui, tetapi akses tetap ditolak. Coba masuk kembali; bila masih gagal, hubungi pengelola layanan.'
}

function toFirestoreServiceError(
  error: unknown,
  operation: CommunityOperation,
  user?: User | null,
): CommunityServiceError {
  if (error instanceof CommunityServiceError) return error

  const code = getFirebaseErrorCode(error) ?? 'unknown'
  const stage = readStageOf(error)
  logCommunityFailure(operation, stage ? `${code} (${stage})` : code)
  const details = stage ? { cause: code, stage } : { cause: code }

  if (code === 'permission-denied') {
    if (user?.isAnonymous) {
      return new CommunityServiceError(
        'unauthenticated',
        'Masuk dengan akun untuk menggunakan Community Reports.',
        details,
      )
    }
    if (user && !user.emailVerified) {
      return new CommunityServiceError(
        'email-not-verified',
        'Verifikasi email akun terlebih dahulu, lalu muat ulang halaman. Akses Community Reports masih ditolak untuk email yang belum terverifikasi.',
        details,
      )
    }
    return new CommunityServiceError(code, accessDeniedMessage(operation), details)
  }
  if (code === 'unauthenticated' || code.startsWith('auth/')) {
    return new CommunityServiceError(
      code === 'auth/network-request-failed' ? 'unavailable' : code,
      code === 'auth/network-request-failed'
        ? 'Tidak dapat menghubungi layanan akun. Periksa koneksi lalu coba lagi.'
        : 'Sesi akun sudah berakhir. Masuk kembali lalu coba lagi.',
      details,
    )
  }
  if (code === 'unavailable' || code === 'deadline-exceeded') {
    return new CommunityServiceError(
      'unavailable',
      'Layanan Community Reports tidak dapat dihubungi. Coba lagi nanti.',
      details,
    )
  }
  if (code === 'failed-precondition') {
    return new CommunityServiceError(
      code,
      'Layanan Community Reports belum siap untuk permintaan ini. Coba lagi nanti.',
      details,
    )
  }
  if (code === 'resource-exhausted') {
    return new CommunityServiceError(
      code,
      'Kuota Community Reports untuk operasi ini sudah tercapai. Coba lagi nanti.',
      details,
    )
  }
  if (code === 'invalid-argument') {
    return new CommunityServiceError(
      code,
      'Permintaan Community Reports tidak valid. Muat ulang halaman lalu coba lagi.',
      details,
    )
  }
  if (code === 'aborted' || code === 'already-exists') {
    return new CommunityServiceError(
      code,
      'Permintaan bentrok dengan pengiriman lain. Coba lagi sebentar lagi.',
      details,
    )
  }

  return new CommunityServiceError(
    code,
    'Layanan Community Reports tidak dapat digunakan saat ini.',
    details,
  )
}

function assertConfigured(): void {
  if (!isFirebaseConfigured) {
    throw new CommunityServiceError(
      'not-configured',
      'Layanan akun belum tersedia pada versi ini, jadi Community Reports belum dapat digunakan.',
    )
  }
}

function requireVerifiedUser(): User {
  assertConfigured()
  const { auth } = getFirebaseClient()
  const user = auth.currentUser

  if (!user || user.isAnonymous) {
    throw new CommunityServiceError(
      'unauthenticated',
      'Masuk dengan akun untuk menggunakan Community Reports.',
    )
  }
  if (!user.emailVerified) {
    throw new CommunityServiceError(
      'email-not-verified',
      'Verifikasi email akun terlebih dahulu untuk membuka Community Reports.',
    )
  }

  return user
}

/**
 * Token yang baru diterbitkan membawa klaim email_verified terbaru. Bila rules sempat
 * menolak karena token lama, satu pembaruan token lalu percobaan ulang memulihkan sesi
 * tanpa berpura-pura bahwa kegagalan akses adalah keadaan kosong.
 */
async function readWithRetry<T>(
  user: User,
  operationName: CommunityOperation,
  operation: () => Promise<T>,
): Promise<T> {
  try {
    return await operation()
  } catch (error) {
    if (!isPermissionDenied(error)) {
      throw toFirestoreServiceError(error, operationName, user)
    }
    try {
      await user.getIdToken(true)
    } catch {
      throw toFirestoreServiceError(error, operationName, user)
    }
    try {
      return await operation()
    } catch (retryError) {
      throw toFirestoreServiceError(retryError, operationName, user)
    }
  }
}

type CacheEntry = {
  value: unknown
  expiresAt: number
}

const resultCache = new Map<string, CacheEntry>()
const inFlightRequests = new Map<string, Promise<unknown>>()

function cacheKey(kind: 'context' | 'latest', userId: string, detail: string): string {
  return `${kind}:${userId}:${detail}`
}

function readCache<T>(key: string): T | null {
  const entry = resultCache.get(key)
  if (!entry) return null
  if (entry.expiresAt <= Date.now()) {
    resultCache.delete(key)
    return null
  }
  return entry.value as T
}

function writeCache(key: string, value: unknown): void {
  if (resultCache.size >= COMMUNITY_CACHE_MAX_ENTRIES) {
    const oldestKey = resultCache.keys().next().value
    if (oldestKey !== undefined) resultCache.delete(oldestKey)
  }
  resultCache.set(key, { value, expiresAt: Date.now() + COMMUNITY_CACHE_TTL_MS })
}

/**
 * Cache singkat + deduplikasi permintaan yang sedang berjalan. Permintaan yang
 * sedang berjalan selalu digabung, termasuk saat tombol meminta muat ulang, agar
 * klik berulang tidak menggandakan pembacaan Firestore. Data kedaluwarsa setelah
 * 30 detik dan tidak disimpan ke disk.
 */
async function cachedRequest<T>(
  key: string,
  forceRefresh: boolean,
  loader: () => Promise<T>,
): Promise<T> {
  const pending = inFlightRequests.get(key)
  if (pending) return pending as Promise<T>

  if (!forceRefresh) {
    const cached = readCache<T>(key)
    if (cached !== null) return cached
  }

  let promise: Promise<T>
  promise = loader()
    .then((value) => {
      if (inFlightRequests.get(key) === promise) writeCache(key, value)
      return value
    })
    .finally(() => {
      if (inFlightRequests.get(key) === promise) inFlightRequests.delete(key)
    })
  inFlightRequests.set(key, promise)
  return promise
}

function invalidateUserCache(userId: string, urlHash: string): void {
  resultCache.delete(cacheKey('context', userId, urlHash))
  // Kunci umpan menyertakan tanggal WITA, jadi seluruh kunci umpan milik akun
  // dibuang agar pergantian hari tidak menyisakan entri cache hari sebelumnya.
  for (const key of resultCache.keys()) {
    if (key.startsWith(`latest:${userId}:`)) resultCache.delete(key)
  }
  for (const key of inFlightRequests.keys()) {
    if (key.startsWith(`latest:${userId}:`)) inFlightRequests.delete(key)
  }
  // Permintaan yang dimulai sebelum penulisan tidak boleh dijadikan hasil muat ulang,
  // karena isinya belum tentu memuat laporan yang baru saja tersimpan.
  inFlightRequests.delete(cacheKey('context', userId, urlHash))
}

export function resetCommunityCacheForTests(): void {
  resultCache.clear()
  inFlightRequests.clear()
}

async function loadContext(
  urlHash: string,
  hostname: string,
  user: User,
): Promise<CommunityContext> {
  const { db } = getFirebaseClient()
  const reportsRef = collection(db, REPORTS_ROOT, urlHash, REPORTS_SUBCOLLECTION)
  const keyRef = doc(db, USERS_COLLECTION, user.uid, REPORTER_KEYS, urlHash)

  // Count lebih dulu: keadaan kosong hanya perlu satu pembacaan. Setelah ada laporan,
  // scan 300 dokumen dan kunci pseudonim privat diambil paralel.
  const countSnapshot = await getCountFromServer(reportsRef)
  const reportCount = countSnapshot.data().count
  if (reportCount === 0) {
    return { summary: null, report: null, reports: [] }
  }

  const [scanSnapshot, keySnapshot] = await Promise.all([
    getDocs(
      query(
        reportsRef,
        orderBy('createdAt', 'desc'),
        limit(COMMUNITY_CONTEXT_SCAN_LIMIT),
      ),
    ),
    getDoc(keyRef),
  ])

  const scanDocs = scanSnapshot.docs.map((snapshot) =>
    parseReportDoc(snapshot.id, snapshot.data()),
  )
  const ownReporterKey = keySnapshot.exists()
    ? readReporterKey(keySnapshot.data()?.reporterKey)
    : null
  const ownDoc =
    ownReporterKey === null
      ? null
      : scanDocs.find(
          (entry) => entry.reporterKey === ownReporterKey && entry.createdAt !== null,
        ) ?? null

  return {
    summary: buildSummary(hostname, reportCount, scanDocs),
    report: ownDoc ? reportFromDoc(ownDoc) : null,
    reports: scanDocs
      .filter((entry) => entry.createdAt !== null)
      .slice(0, COMMUNITY_CONTEXT_REPORT_LIMIT)
      .map((entry) => entryFromDoc(entry, hostname)),
  }
}

/**
 * Jaring transisi untuk laporan yang dibuat klien lama sebelum partisi harian
 * tersedia. Hanya dijalankan bila query harian berhasil tetapi kosong; kepala
 * lama dibaca maksimal satu kali dan entri hanya diambil bila waktunya hari ini.
 * Sumber utama tetap partisi harian; fallback ini tidak dapat menggantikan query
 * tanggal dan tidak pernah dipakai untuk menyembunyikan kegagalan query.
 */
async function loadLegacyTodayReports(
  dayStartMs: number,
  dayEndMs: number,
): Promise<ParsedLatestEntry[]> {
  const { db } = getFirebaseClient()
  const headRef = doc(db, LATEST_FEED_ROOT, LATEST_FEED_HEAD_ID)
  let headSnapshot
  try {
    headSnapshot = await getDoc(headRef)
  } catch (error) {
    throw withReadStage(error, 'fallback-head')
  }
  if (!headSnapshot.exists()) return []

  const updatedAt = readTimestamp(headSnapshot.data()?.updatedAt)
  if (updatedAt && (updatedAt.toMillis() < dayStartMs || updatedAt.toMillis() >= dayEndMs)) {
    return []
  }

  const ids = readLatestHeadIds(headSnapshot.data()?.entries)
  if (ids === null) {
    throw new CommunityServiceError(
      'failed-precondition',
      'Daftar laporan komunitas belum dapat dibaca dengan benar. Coba lagi nanti.',
    )
  }

  const entries = await Promise.all(
    ids.map(async (id) => {
      const entryRef = doc(
        db,
        LATEST_FEED_ROOT,
        LATEST_FEED_HEAD_ID,
        LATEST_FEED_ENTRIES,
        id,
      )
      let snapshot
      try {
        snapshot = await getDoc(entryRef)
      } catch (error) {
        throw withReadStage(error, 'fallback-entry')
      }
      return snapshot.exists() ? parseLatestEntryDoc(id, snapshot.data()) : null
    }),
  )

  return entries
    .filter((entry): entry is ParsedLatestEntry => entry !== null)
    .filter((entry) => {
      const millis = entry.createdAt.toMillis()
      return millis >= dayStartMs && millis < dayEndMs
    })
    .sort(
      (left, right) =>
        right.createdAt.toMillis() - left.createdAt.toMillis(),
    )
    .slice(0, COMMUNITY_DAILY_FEED_LIMIT)
}

async function loadLatestReports(
  dayId: string,
  nowMs: number,
): Promise<CommunityLatestReportEntry[]> {
  const { db } = getFirebaseClient()
  const dayStartMs = communityDailyFeedDayStartMs(nowMs)
  const dayEndMs = communityDailyFeedDayEndMs(nowMs)
  const dailyRef = collection(db, DAILY_FEED_ROOT, dayId, DAILY_FEED_REPORTS)

  let snapshot
  try {
    snapshot = await getDocs(
      query(
        dailyRef,
        where('createdAt', '>=', Timestamp.fromMillis(dayStartMs)),
        where('createdAt', '<', Timestamp.fromMillis(dayEndMs)),
        orderBy('createdAt', 'desc'),
        limit(COMMUNITY_DAILY_FEED_LIMIT),
      ),
    )
  } catch (error) {
    throw withReadStage(error, 'daily-list')
  }

  // Query sudah menyaring tanggal penuh (hari, bulan, tahun) dan mengurutkan
  // terbaru. Penyaringan ulang menjaga data lama/rusak tidak pernah tampil.
  const entries = snapshot.docs
    .map((entryDoc) => parseLatestEntryDoc(entryDoc.id, entryDoc.data()))
    .filter((entry): entry is ParsedLatestEntry => entry !== null)
    .filter((entry) => {
      const millis = entry.createdAt.toMillis()
      return millis >= dayStartMs && millis < dayEndMs
    })
    .sort(
      (left, right) =>
        right.createdAt.toMillis() - left.createdAt.toMillis(),
    )
    .slice(0, COMMUNITY_DAILY_FEED_LIMIT)

  if (entries.length > 0) return entries.map(latestEntryFromParsed)

  const legacy = await loadLegacyTodayReports(dayStartMs, dayEndMs)
  return legacy.map(latestEntryFromParsed)
}

async function ensureProfile(user: User): Promise<string> {
  const { db } = getFirebaseClient()
  const profileRef = doc(db, USERS_COLLECTION, user.uid)
  const snapshot = await getDoc(profileRef)
  const displayName = snapshot.exists() ? snapshot.data()?.displayName : null

  if (
    typeof displayName === 'string' &&
    displayName.trim() &&
    displayName.length <= MAX_USER_NAME_LENGTH
  ) {
    return displayName.trim()
  }

  const identity: UserProfileIdentity = {
    uid: user.uid,
    email: user.email,
    displayName: user.displayName,
  }
  const profile = await syncUserProfile(identity)
  const syncedName = profile.displayName?.trim()
  if (!syncedName) {
    throw new CommunityServiceError(
      'failed-precondition',
      'Profil akun belum siap untuk mencatat laporan. Muat ulang halaman lalu coba lagi.',
    )
  }
  return syncedName.slice(0, MAX_USER_NAME_LENGTH)
}

type DayIds = {
  /** Penanda batas kirim harian (WIB, kompatibel dengan dokumen lama). */
  quotaDayId: number
  /** Partisi umpan Laporan terbaru (WITA). */
  feedDayId: string
}

async function freshDayIds(user: User): Promise<DayIds> {
  try {
    const token = await user.getIdTokenResult(true)
    return {
      quotaDayId:
        communityDayIdFromIso(token.issuedAtTime) ?? communityDayId(),
      feedDayId:
        communityDailyFeedDayIdFromIso(token.issuedAtTime) ??
        communityDailyFeedDayId(),
    }
  } catch (error) {
    throw toFirestoreServiceError(error, 'token', user)
  }
}

function newIdentifier(factory: () => string, label: string): string {
  try {
    return factory()
  } catch {
    throw new CommunityServiceError(
      'failed-precondition',
      `Browser ini tidak dapat membuat ${label}. Gunakan browser modern lalu coba lagi.`,
    )
  }
}

async function createReportDocuments(
  user: User,
  urlHash: string,
  reportedUrl: string,
  hostname: string,
  dayId: number,
  feedDayId: string,
  displayName: string,
  category: CommunityCategory,
  reason: string,
): Promise<void> {
  const { db } = getFirebaseClient()
  const markerRef = doc(db, USERS_COLLECTION, user.uid, DAY_MARKERS, String(dayId))
  const keyRef = doc(db, USERS_COLLECTION, user.uid, REPORTER_KEYS, urlHash)
  const headRef = doc(db, LATEST_FEED_ROOT, LATEST_FEED_HEAD_ID)
  const maskedName = maskReporterName(displayName)

  try {
    await runTransaction(db, async (transaction) => {
      const markerSnapshot = await transaction.get(markerRef)
      if (markerSnapshot.exists()) throw dailyLimitError()

      const keySnapshot = await transaction.get(keyRef)
      const existingKey = keySnapshot.exists()
        ? readReporterKey(keySnapshot.data()?.reporterKey)
        : null
      if (keySnapshot.exists() && existingKey === null) {
        throw new CommunityServiceError(
          'failed-precondition',
          'Identitas pelapor untuk URL ini tidak valid. Muat ulang halaman lalu coba lagi.',
        )
      }

      const headSnapshot = await transaction.get(headRef)
      const previousEntries = headSnapshot.exists()
        ? readLatestHeadIds(headSnapshot.data()?.entries)
        : []
      if (previousEntries === null) {
        throw new CommunityServiceError(
          'failed-precondition',
          'Daftar laporan komunitas belum dapat diperbarui. Coba lagi nanti.',
        )
      }

      let reportId = newIdentifier(createReportId, 'identitas laporan')
      while (previousEntries.includes(reportId)) {
        reportId = newIdentifier(createReportId, 'identitas laporan')
      }

      const reporterKey =
        existingKey ?? newIdentifier(createReporterKey, 'pseudonim pelapor')
      const reportRef = doc(
        db,
        REPORTS_ROOT,
        urlHash,
        REPORTS_SUBCOLLECTION,
        reportId,
      )
      const entryRef = doc(
        db,
        LATEST_FEED_ROOT,
        LATEST_FEED_HEAD_ID,
        LATEST_FEED_ENTRIES,
        reportId,
      )
      const dailyRef = doc(
        db,
        DAILY_FEED_ROOT,
        feedDayId,
        DAILY_FEED_REPORTS,
        reportId,
      )
      const nextEntries = [reportId, ...previousEntries].slice(
        0,
        COMMUNITY_LATEST_LIMIT,
      )

      if (!existingKey) {
        transaction.set(keyRef, {
          ownerId: user.uid,
          reporterKey,
          createdAt: serverTimestamp(),
        })
      }
      transaction.set(markerRef, {
        ownerId: user.uid,
        reportId,
        urlHash,
        reporterKey,
        category,
        createdAt: serverTimestamp(),
      })
      // URL tampilan dan hostname dari URL ternormalisasi disalin ke ketiga
      // dokumen. URL sudah tanpa kredensial, query, atau fragment; aturan Firestore
      // memeriksa bentuk dan kesamaan nilainya antar-dokumen.
      transaction.set(reportRef, {
        reporterKey,
        userName: maskedName,
        reportedUrl,
        hostname,
        category,
        reason,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      })
      // Entri umpan hanya memuat field publik minimum. Laporan lama yang keluar
      // dari daftar berurutan tetap tersimpan di partisi URL masing-masing.
      transaction.set(entryRef, {
        reporterKey,
        userName: maskedName,
        reportedUrl,
        hostname,
        category,
        reason,
        createdAt: serverTimestamp(),
      })
      // Partisi harian WITA memakai field publik yang sama tanpa pseudonim. ID
      // dokumennya acak dan tanggalnya ditentukan server, sehingga umpan dapat
      // di-query per hari tanpa membaca URL hash atau identitas pelapor.
      transaction.set(dailyRef, {
        userName: maskedName,
        reportedUrl,
        hostname,
        category,
        reason,
        createdAt: serverTimestamp(),
      })
      transaction.set(headRef, {
        entries: nextEntries,
        updatedAt: serverTimestamp(),
      })
    })
  } catch (error) {
    if (error instanceof CommunityServiceError) throw error

    // Transaksi bisa gagal setelah dokumen sebenarnya tersimpan (mis. koneksi terputus
    // atau dua pengiriman bersamaan). Penanda hari yang ada membuktikan batas harian,
    // bukan kegagalan layanan.
    let alreadyCreated = false
    try {
      alreadyCreated = (await getDoc(markerRef)).exists()
    } catch {
      alreadyCreated = false
    }
    if (alreadyCreated) throw dailyLimitError()

    throw error
  }
}

export async function getCommunityContext(
  url: string,
  options: CommunityRequestOptions = {},
): Promise<CommunityContext> {
  const user = requireVerifiedUser()

  let normalizedUrl: string
  try {
    normalizedUrl = normalizeCommunityUrl(url)
  } catch (error) {
    throw new CommunityServiceError(
      'invalid-argument',
      error instanceof Error ? error.message : 'URL tidak valid.',
    )
  }

  const urlHash = await communityUrlHash(normalizedUrl)
  const hostname = hostnameFromCommunityUrl(normalizedUrl)
  const key = cacheKey('context', user.uid, urlHash)

  return cachedRequest(key, options.forceRefresh === true, () =>
    readWithRetry(user, 'context', () => loadContext(urlHash, hostname, user)),
  )
}

export async function listLatestCommunityReports(
  options: CommunityRequestOptions = {},
): Promise<CommunityLatestReportEntry[]> {
  const user = requireVerifiedUser()
  const nowMs = Date.now()
  const dayId = communityDailyFeedDayId(nowMs)
  const key = cacheKey('latest', user.uid, dayId)

  return cachedRequest(key, options.forceRefresh === true, () =>
    readWithRetry(user, 'latest', () => loadLatestReports(dayId, nowMs)),
  )
}

export async function submitCommunityReport(
  input: SubmitCommunityReportInput,
): Promise<SubmitCommunityReportResult> {
  const user = requireVerifiedUser()

  let normalizedUrl: string
  let reportedUrl: string | null
  let hostname: string
  try {
    normalizedUrl = normalizeCommunityUrl(input.url)
    reportedUrl = sanitizeCommunityUrlForDisplay(normalizedUrl)
    hostname = hostnameFromCommunityUrl(normalizedUrl)
  } catch (error) {
    throw new CommunityServiceError(
      'invalid-argument',
      error instanceof Error ? error.message : 'URL tidak valid.',
    )
  }
  if (!isCommunityHostname(hostname)) {
    throw new CommunityServiceError(
      'invalid-argument',
      'Hostname URL tidak dapat ditampilkan dengan aman. Gunakan alamat domain biasa.',
    )
  }
  if (!reportedUrl) {
    throw new CommunityServiceError(
      'invalid-argument',
      'URL laporan tidak dapat ditampilkan dengan aman. Gunakan alamat http atau https tanpa data masuk.',
    )
  }

  if (!COMMUNITY_CATEGORY_IDS.has(input.category)) {
    throw new CommunityServiceError('invalid-argument', 'Kategori laporan tidak valid.')
  }

  const reason = input.reason.trim()
  if (reason.length < MIN_REPORT_REASON_LENGTH) {
    throw new CommunityServiceError(
      'invalid-argument',
      `Alasan minimal ${MIN_REPORT_REASON_LENGTH} karakter.`,
    )
  }
  if (reason.length > MAX_REPORT_REASON_LENGTH) {
    throw new CommunityServiceError(
      'invalid-argument',
      `Alasan maksimal ${MAX_REPORT_REASON_LENGTH} karakter.`,
    )
  }

  let displayName: string
  try {
    displayName = await ensureProfile(user)
  } catch (error) {
    throw toFirestoreServiceError(error, 'profile', user)
  }

  const urlHash = await communityUrlHash(normalizedUrl)
  let dayIds = await freshDayIds(user)

  try {
    await createReportDocuments(
      user,
      urlHash,
      reportedUrl,
      hostname,
      dayIds.quotaDayId,
      dayIds.feedDayId,
      displayName,
      input.category,
      reason,
    )
  } catch (error) {
    if (error instanceof CommunityServiceError) throw error
    if (!isPermissionDenied(error)) throw toFirestoreServiceError(error, 'submit', user)

    // Lewat tengah malam WIB/WITA, ID hari dari token pertama bisa sudah bukan
    // "hari ini" menurut request.time. Token baru menentukan hari yang benar;
    // jika keduanya sama, ini penolakan nyata.
    const retryDayIds = await freshDayIds(user).catch(() => null)
    if (
      retryDayIds === null ||
      (retryDayIds.quotaDayId === dayIds.quotaDayId &&
        retryDayIds.feedDayId === dayIds.feedDayId)
    ) {
      throw toFirestoreServiceError(error, 'submit', user)
    }

    dayIds = retryDayIds
    try {
      await createReportDocuments(
        user,
        urlHash,
        reportedUrl,
        hostname,
        dayIds.quotaDayId,
        dayIds.feedDayId,
        displayName,
        input.category,
        reason,
      )
    } catch (retryError) {
      throw toFirestoreServiceError(retryError, 'submit', user)
    }
  }

  invalidateUserCache(user.uid, urlHash)

  // Ringkasan setelah penulisan bersifat pelengkap. Kegagalan membacanya tidak boleh
  // mengubah laporan yang sudah tersimpan menjadi "gagal", dan angka tidak dikarang.
  const context = await getCommunityContext(normalizedUrl, { forceRefresh: true }).catch(
    () => null,
  )

  return {
    created: true,
    summary: context?.summary ?? null,
    report: context?.report ?? null,
  }
}

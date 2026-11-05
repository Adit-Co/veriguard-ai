import type { User } from 'firebase/auth'
import {
  Timestamp,
  collection,
  collectionGroup,
  doc,
  getDoc,
  getDocs,
  limit,
  orderBy,
  query,
  serverTimestamp,
  where,
  writeBatch,
  type DocumentData,
  type DocumentReference,
} from 'firebase/firestore'
import { isCommunityHostname, sanitizeCommunityUrlForDisplay } from '../community/url'
import { getFirebaseClient } from '../firebase/client'
import { getFirebaseErrorCode } from '../firebase/errors'
import {
  COMMUNITY_CATEGORY_IDS,
  type CommunityCategory,
} from '../community/types'
import {
  canTransitionModeration,
  isModerationStatus,
  type AdminModerationReport,
  type ModerationHistoryEntry,
  type ModerationRecord,
  type ModerationStatus,
  type PublicModerationStatus,
} from './types'

const REPORTS_ROOT = 'communityReports'
const MODERATION_COLLECTION = 'communityModeration'
const MODERATION_PUBLIC_COLLECTION = 'communityModerationPublic'
const MAX_QUEUE_DOCUMENTS = 500
const MAX_MODERATION_DOCUMENTS = 500
const MAX_HISTORY_ENTRIES = 50
const MAX_NOTE_LENGTH = 1000
const URL_HASH_PATTERN = /^[0-9a-f]{64}$/
const REPORT_ID_PATTERN = /^[0-9a-f]{32}$/
const REPORTER_KEY_PATTERN = /^[0-9a-f]{64}$/

export type ModerationQueueSnapshot = {
  reports: AdminModerationReport[]
  reportsTruncated: boolean
  moderationTruncated: boolean
}

export type PublicStatusLookup = {
  statuses: Map<string, PublicModerationStatus>
  unavailable: boolean
}

function readTimestampIso(value: unknown): string | null {
  return value instanceof Timestamp ? value.toDate().toISOString() : null
}

function requireModeratorCandidate(): User {
  const { auth } = getFirebaseClient()
  const user = auth.currentUser
  if (!user || user.isAnonymous) {
    throw new Error('Masuk dengan akun untuk membuka data moderasi.')
  }
  if (!user.emailVerified) {
    throw new Error('Verifikasi email akun terlebih dahulu. Daftar admin mensyaratkan email terverifikasi.')
  }
  return user
}

export type ModerationErrorKind =
  | 'permission'
  | 'session'
  | 'connection'
  | 'conflict'
  | 'configuration'
  | 'unknown'

export type ModerationErrorInfo = {
  kind: ModerationErrorKind
  code: string | null
  message: string
  detail: string | null
  indexUrl: string | null
}

const MAX_ERROR_DETAIL_LENGTH = 500
const INDEX_CONSOLE_URL_PATTERN = /https:\/\/console\.firebase\.google\.com\/[^\s"'<>]+/

function readErrorDetail(error: unknown): string | null {
  if (!(error instanceof Error)) return null
  const text = error.message.replace(/\s+/g, ' ').trim()
  if (!text) return null
  return text.length > MAX_ERROR_DETAIL_LENGTH
    ? `${text.slice(0, MAX_ERROR_DETAIL_LENGTH)}…`
    : text
}

function readSafeIndexConsoleUrl(detail: string | null): string | null {
  if (!detail) return null
  const match = detail.match(INDEX_CONSOLE_URL_PATTERN)
  if (!match) return null
  try {
    const url = new URL(match[0].replace(/[),.]+$/, ''))
    return url.protocol === 'https:' && url.hostname === 'console.firebase.google.com'
      ? url.toString()
      : null
  } catch {
    return null
  }
}

/**
 * Diagnostik aman: hanya memakai kode dan pesan error Firestore (tanpa isi
 * dokumen). URL indeks ditampilkan hanya bila host-nya konsol Firebase.
 */
export function describeModerationError(error: unknown): ModerationErrorInfo {
  const code = getFirebaseErrorCode(error)
  const detail = readErrorDetail(error)

  if (code === 'permission-denied') {
    return {
      kind: 'permission',
      code,
      message:
        'Tindakan ditolak oleh sistem penyimpanan. Pastikan akun ini tercatat sebagai admin aktif dan aturan akses data versi terbaru sudah aktif. Muat ulang antrean sebelum mencoba lagi.',
      detail: null,
      indexUrl: null,
    }
  }
  if (code === 'unauthenticated' || code?.startsWith('auth/')) {
    return {
      kind: 'session',
      code,
      message: 'Sesi akun sudah berakhir. Masuk kembali lalu coba lagi.',
      detail: null,
      indexUrl: null,
    }
  }
  if (code === 'unavailable' || code === 'deadline-exceeded') {
    return {
      kind: 'connection',
      code,
      message: 'Penyimpanan data tidak dapat dihubungi. Periksa koneksi lalu coba lagi.',
      detail: null,
      indexUrl: null,
    }
  }
  if (code === 'aborted' || code === 'already-exists') {
    return {
      kind: 'conflict',
      code,
      message:
        'Data moderasi berubah bersamaan dengan tindakan ini. Muat ulang antrean lalu tinjau kembali.',
      detail: null,
      indexUrl: null,
    }
  }
  if (code === 'failed-precondition') {
    return {
      kind: 'configuration',
      code,
      message:
        'Sistem penyimpanan menolak operasi ini karena konfigurasi data belum lengkap. Rincian di bawah menunjukkan indeks yang perlu dibuat; ini bukan masalah koneksi atau sesi.',
      detail,
      indexUrl: readSafeIndexConsoleUrl(detail),
    }
  }
  if (detail) {
    return {
      kind: 'unknown',
      code,
      message: detail,
      detail: null,
      indexUrl: null,
    }
  }
  return {
    kind: 'unknown',
    code,
    message: 'Data moderasi tidak dapat diproses saat ini.',
    detail: null,
    indexUrl: null,
  }
}

export function moderationErrorMessage(error: unknown): string {
  return describeModerationError(error).message
}

function parseCategory(value: unknown): CommunityCategory {
  return typeof value === 'string' && COMMUNITY_CATEGORY_IDS.has(value)
    ? (value as CommunityCategory)
    : 'other'
}

function parseModeration(data: DocumentData | undefined): ModerationRecord | null {
  if (!data || !isModerationStatus(data.status)) return null
  return {
    status: data.status,
    note: typeof data.note === 'string' ? data.note.slice(0, MAX_NOTE_LENGTH) : '',
    updatedAt: readTimestampIso(data.updatedAt),
    updatedBy: typeof data.updatedBy === 'string' ? data.updatedBy : '',
  }
}

function reportUrlHash(documentRef: DocumentReference): string | null {
  const reportsCollection = documentRef.parent
  if (!reportsCollection || reportsCollection.parent?.parent?.id !== REPORTS_ROOT) {
    return null
  }
  return reportsCollection.parent.id
}

/**
 * Antrean dibaca dengan collection-group query yang hanya diizinkan aturan untuk
 * admin. Filter reporterKey mengecualikan partisi umpan harian yang memakai nama
 * koleksi "reports" juga. Batas 500 dokumen menjaga biaya Spark; UI menyatakan
 * secara eksplisit bila data terpotong.
 */
export async function loadModerationQueue(): Promise<ModerationQueueSnapshot> {
  requireModeratorCandidate()
  const { db } = getFirebaseClient()

  const [reportsSnapshot, moderationSnapshot] = await Promise.all([
    getDocs(
      query(
        collectionGroup(db, 'reports'),
        where('reporterKey', '>', ''),
        limit(MAX_QUEUE_DOCUMENTS),
      ),
    ),
    getDocs(query(collection(db, MODERATION_COLLECTION), limit(MAX_MODERATION_DOCUMENTS))),
  ])

  const moderationById = new Map<string, ModerationRecord>()
  for (const moderationDoc of moderationSnapshot.docs) {
    const parsed = parseModeration(moderationDoc.data())
    if (parsed) moderationById.set(moderationDoc.id, parsed)
  }

  const reports: AdminModerationReport[] = []
  for (const reportDoc of reportsSnapshot.docs) {
    const data = reportDoc.data()
    const urlHash = reportUrlHash(reportDoc.ref)
    if (
      !urlHash ||
      !URL_HASH_PATTERN.test(urlHash) ||
      !REPORT_ID_PATTERN.test(reportDoc.id) ||
      typeof data.reporterKey !== 'string' ||
      !REPORTER_KEY_PATTERN.test(data.reporterKey)
    ) {
      continue
    }

    reports.push({
      id: reportDoc.id,
      urlHash,
      userName:
        typeof data.userName === 'string' && data.userName.trim()
          ? data.userName.trim().slice(0, 80)
          : 'Pengguna',
      reportText: typeof data.reason === 'string' ? data.reason.trim() : '',
      category: parseCategory(data.category),
      reportedUrl: sanitizeCommunityUrlForDisplay(data.reportedUrl),
      hostname: isCommunityHostname(data.hostname) ? data.hostname : null,
      createdAt: readTimestampIso(data.createdAt),
      moderation: moderationById.get(reportDoc.id) ?? null,
    })
  }

  reports.sort((left, right) => {
    const leftTime = left.createdAt ? Date.parse(left.createdAt) : 0
    const rightTime = right.createdAt ? Date.parse(right.createdAt) : 0
    return rightTime - leftTime
  })

  return {
    reports,
    reportsTruncated: reportsSnapshot.size >= MAX_QUEUE_DOCUMENTS,
    moderationTruncated: moderationSnapshot.size >= MAX_MODERATION_DOCUMENTS,
  }
}

export async function loadModerationHistory(
  reportId: string,
): Promise<ModerationHistoryEntry[]> {
  requireModeratorCandidate()
  if (!REPORT_ID_PATTERN.test(reportId)) {
    throw new Error('ID laporan tidak valid.')
  }
  const { db } = getFirebaseClient()
  const snapshot = await getDocs(
    query(
      collection(db, MODERATION_COLLECTION, reportId, 'history'),
      orderBy('createdAt', 'desc'),
      limit(MAX_HISTORY_ENTRIES),
    ),
  )

  return snapshot.docs.flatMap((entryDoc) => {
    const data = entryDoc.data()
    if (
      (data.action !== 'created' && data.action !== 'status_changed') ||
      !isModerationStatus(data.toStatus)
    ) {
      return []
    }
    const fromStatus =
      typeof data.fromStatus === 'string' && isModerationStatus(data.fromStatus)
        ? data.fromStatus
        : null
    return [
      {
        id: entryDoc.id,
        action: data.action,
        fromStatus,
        toStatus: data.toStatus,
        note: typeof data.note === 'string' ? data.note.slice(0, MAX_NOTE_LENGTH) : '',
        actorUid: typeof data.actorUid === 'string' ? data.actorUid : '',
        createdAt: readTimestampIso(data.createdAt),
      },
    ]
  })
}

export type ApplyModerationDecisionInput = {
  reportId: string
  urlHash: string
  currentStatus: ModerationStatus | null
  nextStatus: ModerationStatus
  note: string
}

/**
 * Satu batch berisi catatan privat, proyeksi status publik minimum, dan audit.
 * Rules menolak batch yang tidak lengkap atau tidak konsisten, sehingga status
 * publik tidak dapat menyimpang dari keputusan moderator.
 */
export async function applyModerationDecision(
  input: ApplyModerationDecisionInput,
): Promise<void> {
  const user = requireModeratorCandidate()
  if (!REPORT_ID_PATTERN.test(input.reportId) || !URL_HASH_PATTERN.test(input.urlHash)) {
    throw new Error('Referensi laporan tidak valid.')
  }
  if (!isModerationStatus(input.nextStatus)) {
    throw new Error('Status moderasi tidak valid.')
  }
  if (!canTransitionModeration(input.currentStatus, input.nextStatus)) {
    throw new Error('Perubahan status ini tidak diizinkan. Muat ulang antrean.')
  }

  const note = input.note.trim()
  if (note.length > MAX_NOTE_LENGTH) {
    throw new Error(`Catatan internal maksimal ${MAX_NOTE_LENGTH} karakter.`)
  }

  const { db } = getFirebaseClient()
  const privateRef = doc(db, MODERATION_COLLECTION, input.reportId)
  const publicRef = doc(db, MODERATION_PUBLIC_COLLECTION, input.reportId)
  const eventId =
    input.currentStatus === null
      ? `created_${input.nextStatus}`
      : `from_${input.currentStatus}_to_${input.nextStatus}`
  const historyRef = doc(db, MODERATION_COLLECTION, input.reportId, 'history', eventId)
  const batch = writeBatch(db)

  if (input.currentStatus === null) {
    batch.set(privateRef, {
      urlHash: input.urlHash,
      reportId: input.reportId,
      status: input.nextStatus,
      note,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
      updatedBy: user.uid,
    })
  } else {
    batch.update(privateRef, {
      status: input.nextStatus,
      note,
      updatedAt: serverTimestamp(),
      updatedBy: user.uid,
    })
  }

  batch.set(publicRef, {
    status: input.nextStatus,
    updatedAt: serverTimestamp(),
  })
  batch.set(historyRef, {
    reportId: input.reportId,
    action: input.currentStatus === null ? 'created' : 'status_changed',
    fromStatus: input.currentStatus ?? '',
    toStatus: input.nextStatus,
    actorUid: user.uid,
    note,
    createdAt: serverTimestamp(),
  })

  await batch.commit()
}

/**
 * Status publik dibaca per ID dari feed, bukan dengan list, supaya pengguna biasa
 * tidak dapat menghitung atau menelusuri seluruh arsip moderasi. Kegagalan satu
 * dokumen ditandai "tidak tersedia", bukan dianggap belum diverifikasi.
 */
export async function loadPublicModerationStatuses(
  reportIds: string[],
): Promise<PublicStatusLookup> {
  const { auth, db } = getFirebaseClient()
  const user = auth.currentUser
  const statuses = new Map<string, PublicModerationStatus>()
  if (!user || !user.emailVerified || user.isAnonymous) {
    return { statuses, unavailable: true }
  }

  const uniqueIds = [...new Set(reportIds.filter((id) => REPORT_ID_PATTERN.test(id)))]
  if (uniqueIds.length === 0) return { statuses, unavailable: false }

  const results = await Promise.allSettled(
    uniqueIds.map((id) => getDoc(doc(db, MODERATION_PUBLIC_COLLECTION, id))),
  )

  let unavailable = false
  results.forEach((result, index) => {
    if (result.status === 'rejected') {
      unavailable = true
      return
    }
    const snapshot = result.value
    if (!snapshot.exists()) return
    const data = snapshot.data()
    if (!isModerationStatus(data.status)) {
      unavailable = true
      return
    }
    statuses.set(uniqueIds[index], {
      status: data.status,
      updatedAt: readTimestampIso(data.updatedAt),
    })
  })

  return { statuses, unavailable }
}

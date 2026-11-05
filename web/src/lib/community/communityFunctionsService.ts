import { httpsCallable } from 'firebase/functions'
import { getFirebaseClient } from '../firebase/client'
import { isFirebaseConfigured } from '../firebase/config'
import { getFirebaseErrorCode } from '../firebase/errors'
import { userFacingText } from '../uiText'
import { CommunityServiceError } from './communityErrors'
import {
  COMMUNITY_CATEGORY_IDS,
  COMMUNITY_DAILY_LIMIT_MESSAGE,
  type CommunityCategory,
  type CommunityContext,
  type CommunityModerationStatus,
  type CommunityReport,
  type CommunityReportEntry,
  type CommunitySummary,
  type SubmitCommunityReportInput,
  type SubmitCommunityReportResult,
} from './types'

const LIST_LIMIT = 20
const MODERATION_STATUSES = new Set<CommunityModerationStatus>([
  'community_reported',
  'under_review',
  'cleared',
  'verified_malicious',
])

const DAILY_LIMIT_REASON = 'daily_limit_reached'

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function optionalIso(value: unknown): string | null {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value)) ? value : null
}

function parseCategory(value: unknown): CommunityCategory {
  if (typeof value !== 'string' || !COMMUNITY_CATEGORY_IDS.has(value)) {
    throw new CommunityServiceError('invalid-response', 'Kategori laporan dari layanan tidak valid.')
  }
  return value as CommunityCategory
}

function parseCategoryCounts(value: unknown): Partial<Record<CommunityCategory, number>> {
  if (!isRecord(value)) return {}

  const counts: Partial<Record<CommunityCategory, number>> = {}
  for (const [key, raw] of Object.entries(value)) {
    if (COMMUNITY_CATEGORY_IDS.has(key) && typeof raw === 'number' && Number.isInteger(raw) && raw >= 0) {
      counts[key as CommunityCategory] = raw
    }
  }
  return counts
}

function parseSummary(value: unknown): CommunitySummary {
  if (!isRecord(value)) {
    throw new CommunityServiceError('invalid-response', 'Ringkasan komunitas dari layanan tidak valid.')
  }

  const status = value.moderationStatus
  if (
    typeof value.hostname !== 'string' ||
    typeof value.reportCount !== 'number' ||
    !Number.isInteger(value.reportCount) ||
    value.reportCount < 0 ||
    typeof status !== 'string' ||
    !MODERATION_STATUSES.has(status as CommunityModerationStatus)
  ) {
    throw new CommunityServiceError('invalid-response', 'Ringkasan komunitas dari layanan tidak valid.')
  }

  // Backend versi sebelumnya belum mengirim reporterCount. Laporan saat itu satu per akun,
  // jadi reportCount adalah nilai akun unik yang aman dipakai sebagai fallback.
  const reporterCount =
    typeof value.reporterCount === 'number' &&
    Number.isInteger(value.reporterCount) &&
    value.reporterCount >= 0
      ? value.reporterCount
      : value.reportCount

  return {
    hostname: value.hostname,
    reportCount: value.reportCount,
    reporterCount,
    categoryCounts: parseCategoryCounts(value.categoryCounts),
    firstReportedAt: optionalIso(value.firstReportedAt),
    lastReportedAt: optionalIso(value.lastReportedAt),
    lastActivityAt: optionalIso(value.lastActivityAt),
    moderationStatus: status as CommunityModerationStatus,
    reviewRequired: value.reviewRequired === true,
    reviewReason: typeof value.reviewReason === 'string' ? value.reviewReason : null,
    verificationSource:
      typeof value.verificationSource === 'string' ? value.verificationSource : null,
    verifiedAt: optionalIso(value.verifiedAt),
    // Backend tepercaya menghitung agregat penuh; nilai false hanya dihormati bila
    // suatu saat respons eksplisit menyatakan sebaliknya.
    aggregatesComplete: value.aggregatesComplete !== false,
  }
}

function parseReport(value: unknown): CommunityReport {
  if (
    !isRecord(value) ||
    typeof value.reason !== 'string' ||
    typeof value.createdAt !== 'string' ||
    typeof value.updatedAt !== 'string' ||
    Number.isNaN(Date.parse(value.createdAt)) ||
    Number.isNaN(Date.parse(value.updatedAt))
  ) {
    throw new CommunityServiceError('invalid-response', 'Laporan dari layanan tidak valid.')
  }

  return {
    userName: parseUserName(value.userName),
    category: parseCategory(value.category),
    reason: value.reason,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
  }
}

function parseUserName(value: unknown): string {
  if (typeof value !== 'string') return 'Pengguna'
  const name = value.trim()
  return name ? name.slice(0, 80) : 'Pengguna'
}

/**
 * Entri laporan nyata untuk daftar komunitas. Dokumen lama sebelum versi ini tidak punya
 * nama, jadi label netral dipakai alih-alih mengarang identitas.
 */
function parseReportEntry(value: unknown, index: number): CommunityReportEntry {
  if (
    !isRecord(value) ||
    typeof value.reportText !== 'string' ||
    typeof value.createdAt !== 'string' ||
    typeof value.updatedAt !== 'string' ||
    Number.isNaN(Date.parse(value.createdAt)) ||
    Number.isNaN(Date.parse(value.updatedAt))
  ) {
    throw new CommunityServiceError('invalid-response', 'Laporan komunitas dari layanan tidak valid.')
  }

  return {
    id:
      typeof value.id === 'string' && value.id.trim()
        ? value.id.trim().slice(0, 128)
        : `legacy-${index}`,
    userName: parseUserName(value.userName),
    reportText: value.reportText,
    category: parseCategory(value.category),
    hostname: typeof value.hostname === 'string' ? value.hostname : '',
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
  }
}

function parseReportEntries(value: unknown): CommunityReportEntry[] {
  if (!Array.isArray(value)) {
    throw new CommunityServiceError('invalid-response', 'Daftar laporan komunitas tidak valid.')
  }
  return value.map((entry, index) => parseReportEntry(entry, index))
}

function parseNullableReport(value: unknown): CommunityReport | null {
  return value === null || value === undefined ? null : parseReport(value)
}

function parseNullableSummary(value: unknown): CommunitySummary | null {
  return value === null || value === undefined ? null : parseSummary(value)
}

function serverMessage(error: unknown): string | null {
  if (!(error instanceof Error)) return null
  const message = error.message.trim()
  if (!message || message.length > 500) return null
  return userFacingText(message)
}

function toServiceError(error: unknown): CommunityServiceError {
  if (error instanceof CommunityServiceError) return error

  const rawCode = getFirebaseErrorCode(error) ?? ''
  const code = rawCode.replace(/^functions\//, '')
  const message = serverMessage(error)
  const details =
    error && typeof error === 'object' ? (error as { details?: unknown }).details : undefined

  if (code === 'resource-exhausted') {
    // Batas harian akun adalah status biasa, bukan kegagalan. Penanda dari backend yang
    // dipakai, jadi pesan ini tidak mungkin muncul ketika masalah sebenarnya adalah database.
    if (isDailyLimitDetail(details)) {
      return new CommunityServiceError(code, COMMUNITY_DAILY_LIMIT_MESSAGE, details)
    }
    return new CommunityServiceError(
      code,
      message ?? 'Terlalu banyak laporan dalam waktu singkat. Tunggu sebelum mencoba lagi.',
      details,
    )
  }

  if (code === 'unauthenticated') {
    return new CommunityServiceError(code, 'Masuk ke akun untuk mengirim laporan.', details)
  }
  if (code === 'permission-denied') {
    return new CommunityServiceError(
      code,
      message ?? 'Tindakan ini tidak diizinkan untuk akun tersebut.',
      details,
    )
  }
  if (code === 'invalid-argument') {
    return new CommunityServiceError(code, message ?? 'Data laporan tidak valid.', details)
  }
  if (code === 'not-found') {
    return new CommunityServiceError(
      code,
      'Layanan Community Reports belum tersedia atau belum di-deploy.',
      details,
    )
  }
  if (code === 'unavailable' || code === 'deadline-exceeded') {
    return new CommunityServiceError(
      code,
      'Layanan Community Reports tidak dapat dihubungi. Coba lagi nanti.',
      details,
    )
  }
  if (code === 'failed-precondition') {
    return new CommunityServiceError(
      code,
      message ?? 'Layanan Community Reports belum siap digunakan.',
      details,
    )
  }
  if (code === 'internal') {
    return new CommunityServiceError(
      code,
      'Layanan Community Reports gagal memproses permintaan. Coba lagi nanti.',
      details,
    )
  }

  return new CommunityServiceError(
    code || 'unknown',
    'Layanan Community Reports tidak dapat digunakan saat ini.',
    details,
  )
}

function isDailyLimitDetail(details: unknown): boolean {
  if (!details || typeof details !== 'object' || Array.isArray(details)) return false
  return (details as { reason?: unknown }).reason === DAILY_LIMIT_REASON
}

function assertConfigured(): void {
  if (!isFirebaseConfigured) {
    throw new CommunityServiceError(
      'not-configured',
      'Layanan akun belum tersedia pada versi ini, jadi Community Reports belum dapat digunakan.',
    )
  }
}

async function call<TResult>(name: string, data?: unknown): Promise<TResult> {
  assertConfigured()
  const { functions } = getFirebaseClient()
  const callable = httpsCallable<unknown, TResult>(functions, name)
  try {
    const response = await callable(data)
    return response.data
  } catch (error) {
    throw toServiceError(error)
  }
}

/** Laporan nyata 24 jam terakhir, terbaru lebih dulu, diambil dari database online. */
export async function listCommunityReports(): Promise<CommunityReportEntry[]> {
  const response = await call<{ reports?: unknown; region?: unknown }>(
    'listCommunityReports',
    { limit: LIST_LIMIT },
  )

  return parseReportEntries(response.reports)
}

export async function getCommunityContext(url: string): Promise<CommunityContext> {
  const response = await call<{ summary?: unknown; report?: unknown; reports?: unknown }>(
    'getCommunityContext',
    { url },
  )

  return {
    summary: parseNullableSummary(response.summary),
    report: parseNullableReport(response.report),
    reports: parseReportEntries(response.reports),
  }
}

export async function submitCommunityReport(
  input: SubmitCommunityReportInput,
): Promise<SubmitCommunityReportResult> {
  const response = await call<{ created?: unknown; summary?: unknown; report?: unknown }>(
    'submitCommunityReport',
    input,
  )

  if (typeof response.created !== 'boolean') {
    throw new CommunityServiceError('invalid-response', 'Respons pengiriman laporan tidak valid.')
  }

  return {
    created: response.created,
    summary: parseSummary(response.summary),
    report: parseReport(response.report),
  }
}

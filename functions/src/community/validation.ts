import { HttpsError } from 'firebase-functions/v2/https'
import {
  COMMUNITY_CATEGORIES,
  COMMUNITY_MODERATION_STATUSES,
  COMMUNITY_POLICY,
  type CommunityCategory,
  type CommunityModerationStatus,
  type ReviewCommunityReportInput,
  type SubmitCommunityReportInput,
} from './types.js'
import { CommunityUrlError, normalizeCommunityUrl } from './url.js'

const CATEGORY_IDS = new Set<string>(COMMUNITY_CATEGORIES)
const MODERATION_IDS = new Set<string>(COMMUNITY_MODERATION_STATUSES)

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function requiredString(value: unknown, message: string): string {
  if (typeof value !== 'string') {
    throw new HttpsError('invalid-argument', message)
  }
  return value
}

function parseCategory(value: unknown): CommunityCategory {
  if (typeof value !== 'string' || !CATEGORY_IDS.has(value)) {
    throw new HttpsError('invalid-argument', 'Kategori laporan tidak valid.')
  }
  return value as CommunityCategory
}

function parseModerationStatus(value: unknown): CommunityModerationStatus {
  if (typeof value !== 'string' || !MODERATION_IDS.has(value)) {
    throw new HttpsError('invalid-argument', 'Status moderasi tidak valid.')
  }
  return value as CommunityModerationStatus
}

function normalizeUrlInput(value: unknown): string {
  const raw = requiredString(value, 'URL harus berupa teks.')
  try {
    return normalizeCommunityUrl(raw)
  } catch (error) {
    if (error instanceof CommunityUrlError) {
      throw new HttpsError('invalid-argument', error.message)
    }
    throw new HttpsError('invalid-argument', 'URL tidak valid.')
  }
}

export function parseSubmitInput(data: unknown): SubmitCommunityReportInput {
  if (!isRecord(data)) {
    throw new HttpsError('invalid-argument', 'Data laporan tidak valid.')
  }

  const url = normalizeUrlInput(data.url)
  const category = parseCategory(data.category)
  const reason = requiredString(data.reason, 'Alasan laporan harus berupa teks.')
    .trim()
    .replace(/\r\n/g, '\n')

  if (reason.length < COMMUNITY_POLICY.minReasonLength) {
    throw new HttpsError(
      'invalid-argument',
      `Alasan minimal ${COMMUNITY_POLICY.minReasonLength} karakter.`,
    )
  }

  if (reason.length > COMMUNITY_POLICY.maxReasonLength) {
    throw new HttpsError(
      'invalid-argument',
      `Alasan maksimal ${COMMUNITY_POLICY.maxReasonLength} karakter.`,
    )
  }

  if (reason.includes('\u0000')) {
    throw new HttpsError('invalid-argument', 'Alasan laporan mengandung karakter yang tidak valid.')
  }

  return { url, category, reason }
}

export function parseReviewInput(data: unknown): ReviewCommunityReportInput {
  if (!isRecord(data)) {
    throw new HttpsError('invalid-argument', 'Data moderasi tidak valid.')
  }

  const url = normalizeUrlInput(data.url)
  const status = parseModerationStatus(data.status)

  let verificationSource: string | null = null
  if (data.verificationSource !== undefined && data.verificationSource !== null) {
    const rawSource = requiredString(
      data.verificationSource,
      'Sumber verifikasi harus berupa teks.',
    ).trim()
    if (rawSource.length > COMMUNITY_POLICY.maxVerificationSourceLength) {
      throw new HttpsError('invalid-argument', 'Sumber verifikasi terlalu panjang.')
    }
    verificationSource = rawSource || null
  }

  if (status === 'verified_malicious' && !verificationSource) {
    throw new HttpsError(
      'invalid-argument',
      'Status verified_malicious memerlukan sumber verifikasi.',
    )
  }

  let note: string | null = null
  if (data.note !== undefined && data.note !== null) {
    const rawNote = requiredString(data.note, 'Catatan moderasi harus berupa teks.').trim()
    if (rawNote.length > COMMUNITY_POLICY.maxModerationNoteLength) {
      throw new HttpsError('invalid-argument', 'Catatan moderasi terlalu panjang.')
    }
    if (rawNote.includes('\u0000')) {
      throw new HttpsError('invalid-argument', 'Catatan moderasi mengandung karakter tidak valid.')
    }
    note = rawNote || null
  }

  return { url, status, verificationSource, note }
}

export function parseListLimit(data: unknown): number {
  if (!isRecord(data) || data.limit === undefined) {
    return COMMUNITY_POLICY.listDefaultLimit
  }

  if (
    typeof data.limit !== 'number' ||
    !Number.isInteger(data.limit) ||
    data.limit < 1 ||
    data.limit > COMMUNITY_POLICY.listMaxLimit
  ) {
    throw new HttpsError(
      'invalid-argument',
      `Batas daftar harus bilangan bulat 1-${COMMUNITY_POLICY.listMaxLimit}.`,
    )
  }

  return data.limit
}

export function parseUrlPayload(data: unknown): string {
  if (!isRecord(data)) {
    throw new HttpsError('invalid-argument', 'Permintaan konteks komunitas tidak valid.')
  }
  return normalizeUrlInput(data.url)
}

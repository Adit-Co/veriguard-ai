import { COMMUNITY_DAILY_LIMIT_MESSAGE } from './types'

const DAILY_LIMIT_REASON = 'daily_limit_reached'

export class CommunityServiceError extends Error {
  readonly code: string
  readonly details: unknown
  /** Kondisi batas harian, bukan gangguan layanan: pesan bakunya dipakai di UI. */
  readonly dailyLimitReached: boolean

  constructor(code: string, message: string, details?: unknown) {
    super(message)
    this.name = 'CommunityServiceError'
    this.code = code
    this.details = details
    const reason =
      details && typeof details === 'object' && !Array.isArray(details)
        ? (details as { reason?: unknown }).reason
        : undefined
    this.dailyLimitReached = code === 'resource-exhausted' && reason === DAILY_LIMIT_REASON
  }
}

export function dailyLimitError(): CommunityServiceError {
  return new CommunityServiceError('resource-exhausted', COMMUNITY_DAILY_LIMIT_MESSAGE, {
    reason: DAILY_LIMIT_REASON,
  })
}

export function communityErrorMessage(error: unknown): string {
  if (error instanceof CommunityServiceError) return error.message
  return 'Layanan Community Reports tidak dapat digunakan saat ini.'
}

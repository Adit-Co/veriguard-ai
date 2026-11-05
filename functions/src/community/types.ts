export const COMMUNITY_COLLECTIONS = {
  summaries: 'communitySummaries',
  rateLimits: 'communityRateLimits',
  moderationAudit: 'communityModerationAudit',
  reports: 'communityReports',
} as const

export const COMMUNITY_CATEGORIES = [
  'phishing',
  'giveaway',
  'marketplace',
  'impersonation',
  'malware',
  'investment_job',
  'other',
] as const

export type CommunityCategory = (typeof COMMUNITY_CATEGORIES)[number]

export const COMMUNITY_MODERATION_STATUSES = [
  'community_reported',
  'under_review',
  'cleared',
  'verified_malicious',
] as const

export type CommunityModerationStatus = (typeof COMMUNITY_MODERATION_STATUSES)[number]

export const COMMUNITY_POLICY = {
  minReasonLength: 20,
  maxReasonLength: 500,
  maxRawUrlLength: 4096,
  maxNormalizedUrlLength: 2048,
  listDefaultLimit: 20,
  listMaxLimit: 50,
  maxUserNameLength: 80,
  recentWindowMs: 24 * 60 * 60 * 1000,
  contextReportLimit: 20,
  spikeWindowMs: 24 * 60 * 60 * 1000,
  spikeReportCount: 8,
  maxVerificationSourceLength: 120,
  maxModerationNoteLength: 500,
  retentionDaysDefault: 90,
  retentionDaysMin: 30,
  retentionDaysMax: 90,
  retentionBatchSize: 25,
  // Bukti tidakaktif harus berulang dan berjeda; satu kegagalan jaringan bukan bukti.
  retentionRequiredChecks: 2,
  retentionCheckGapMs: 7 * 24 * 60 * 60 * 1000,
} as const

/** Zona waktu hari kalender untuk batas harian, dihitung di sisi backend yang tepercaya. */
export const COMMUNITY_TIMEZONE_DEFAULT = 'UTC'

/**
 * Pesan yang harus tampil apa adanya saat peluang kirim harian akun sudah terpakai.
 * Ini status ramah, bukan error generik, jadi kata "Ditolak" tidak dipakai.
 */
export const COMMUNITY_DAILY_LIMIT_MESSAGE = 'Laporan Anda untuk sesi ini sudah diberikan.'

/** Penanda mesin supaya klien bisa membedakan batas harian dari gangguan layanan. */
export const COMMUNITY_DAILY_LIMIT_REASON = 'daily_limit_reached' as const

export const COMMUNITY_FALLBACK_USER_NAME = 'Pengguna'

export type CommunitySubmitter = {
  uid: string
  name: string | null
}

/**
 * Setiap pengiriman yang berhasil menjadi dokumen laporan baru. Riwayat laporan lama tidak
 * ditimpa; batas harian hanya mencegah pengiriman berikutnya pada hari yang sama.
 */
export type CommunityReportEntry = {
  userName: string
  reportText: string
  category: CommunityCategory
  hostname: string
  createdAt: string
  updatedAt: string
}

export type RetentionOutcome = {
  scanned: number
  deleted: number
  retained: number
  retentionDays: number
  detail: string | null
}

export type CommunitySummaryData = {
  url: string
  hostname: string
  urlHash: string
  reportCount: number
  /** Akun unik yang memiliki laporan aktif untuk URL ini. */
  reporterCount: number
  categoryCounts: Partial<Record<CommunityCategory, number>>
  firstReportedAt: unknown
  lastReportedAt: unknown
  lastActivityAt: unknown
  moderationStatus: CommunityModerationStatus
  reviewRequired: boolean
  reviewReason: string | null
  verificationSource: string | null
  verifiedAt: unknown
  createdAt: unknown
  updatedAt: unknown
}

export type CommunitySummaryResponse = {
  hostname: string
  reportCount: number
  reporterCount: number
  categoryCounts: Partial<Record<CommunityCategory, number>>
  firstReportedAt: string | null
  lastReportedAt: string | null
  lastActivityAt: string | null
  moderationStatus: CommunityModerationStatus
  reviewRequired: boolean
  reviewReason: string | null
  verificationSource: string | null
  verifiedAt: string | null
}

export type CommunityReportResponse = {
  userName: string
  category: CommunityCategory
  reason: string
  createdAt: string
  updatedAt: string
}

export type CommunityContextResponse = {
  summary: CommunitySummaryResponse | null
  report: CommunityReportResponse | null
  reports: CommunityReportEntry[]
}

export type SubmitCommunityReportInput = {
  url: string
  category: CommunityCategory
  reason: string
}

export type SubmitResult = {
  created: boolean
  summary: CommunitySummaryResponse
  report: CommunityReportResponse
}

export type ReviewCommunityReportInput = {
  url: string
  status: CommunityModerationStatus
  verificationSource: string | null
  note: string | null
}

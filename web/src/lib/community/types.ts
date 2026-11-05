export const COMMUNITY_CATEGORIES = [
  { id: 'phishing', label: 'Phishing atau login palsu' },
  { id: 'giveaway', label: 'Hadiah atau undian' },
  { id: 'marketplace', label: 'Jual beli atau kurir' },
  { id: 'impersonation', label: 'Penyamaran institusi' },
  { id: 'malware', label: 'Malware atau unduhan' },
  { id: 'investment_job', label: 'Investasi atau lowongan kerja' },
  { id: 'other', label: 'Lainnya' },
] as const

export type CommunityCategory = (typeof COMMUNITY_CATEGORIES)[number]['id']

export type CommunityModerationStatus =
  | 'community_reported'
  | 'under_review'
  | 'cleared'
  | 'verified_malicious'

export type CommunitySummary = {
  hostname: string
  reportCount: number
  /**
   * Pseudonim unik per URL yang punya laporan aktif; dasar Skor Reputasi.
   * Bukan bukti identitas unik: pseudonim dibuat klien dan dapat disalin akun lain.
   */
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
  /**
   * True hanya bila seluruh laporan untuk URL ini ikut dihitung dalam agregat.
   * Bila false, reportCount tetap tepat tetapi reporterCount/categoryCounts belum lengkap.
   */
  aggregatesComplete: boolean
}

export type CommunityReport = {
  userName: string
  category: CommunityCategory
  reason: string
  createdAt: string
  updatedAt: string
}

/**
 * Satu laporan publik untuk URL yang sedang dibaca. `userName` sudah tersamar dan
 * `id` adalah nama dokumen acak; tidak ada UID, email, atau URL mentah di sini.
 */
export type CommunityReportEntry = {
  id: string
  userName: string
  reportText: string
  category: CommunityCategory
  hostname: string
  createdAt: string
  updatedAt: string
}

export type CommunityContext = {
  summary: CommunitySummary | null
  report: CommunityReport | null
  reports: CommunityReportEntry[]
}

/**
 * Satu laporan pada umpan komunitas global. Hanya berisi field publik minimum:
 * URL yang sudah disanitasi (tanpa kredensial, query, atau fragment) dan hostname,
 * tanpa UID, email, atau data moderasi privat. Keduanya dideklarasikan klien dan
 * hanya diperiksa bentuk serta konsistensinya, jadi bukan bukti bahwa situs itu
 * benar-benar milik laporan. Nilai null berarti dokumen lama tidak menyimpan field
 * tersebut.
 */
export type CommunityLatestReportEntry = {
  id: string
  userName: string
  reportText: string
  category: CommunityCategory
  reportedUrl: string | null
  hostname: string | null
  createdAt: string
}

/**
 * Pesan baku untuk kondisi peluang kirim harian sudah terpakai. Kalimat status ramah,
 * bukan penolakan teknis, dan kata "Ditolak" tidak dipakai.
 */
export const COMMUNITY_DAILY_LIMIT_MESSAGE = 'Laporan Anda untuk hari ini sudah tercatat.'

/** Pesan baku ketika belum ada laporan pada hari WITA berjalan. */
export const COMMUNITY_LATEST_EMPTY_MESSAGE = 'Belum ada laporan komunitas hari ini'

export type SubmitCommunityReportInput = {
  url: string
  category: CommunityCategory
  reason: string
}

export type SubmitCommunityReportResult = {
  created: boolean
  /** Null bila ringkasan tidak dapat dibaca setelah laporan tersimpan; tidak dikarang. */
  summary: CommunitySummary | null
  report: CommunityReport | null
}

export const COMMUNITY_CATEGORY_IDS = new Set<string>(
  COMMUNITY_CATEGORIES.map((category) => category.id),
)

export const COMMUNITY_CATEGORY_LABELS = Object.fromEntries(
  COMMUNITY_CATEGORIES.map((category) => [category.id, category.label]),
) as Record<CommunityCategory, string>

export const MIN_REPORT_REASON_LENGTH = 20
export const MAX_REPORT_REASON_LENGTH = 500

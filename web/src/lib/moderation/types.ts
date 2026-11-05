import type { CommunityCategory } from '../community/types'

export const MODERATION_STATUSES = [
  'pending',
  'review',
  'confirmed_malicious',
  'inconclusive',
  'rejected',
] as const

export type ModerationStatus = (typeof MODERATION_STATUSES)[number]

export type ModerationTone = 'neutral' | 'accent' | 'low' | 'medium' | 'high' | 'info'

type ModerationStatusMeta = {
  label: string
  description: string
  tone: ModerationTone
  terminal: boolean
}

export const MODERATION_STATUS_META: Record<ModerationStatus, ModerationStatusMeta> = {
  pending: {
    label: 'Menunggu peninjauan',
    description: 'Laporan masuk antrean moderator dan belum diperiksa.',
    tone: 'neutral',
    terminal: false,
  },
  review: {
    label: 'Sedang ditinjau',
    description: 'Moderator sedang memeriksa laporan ini.',
    tone: 'info',
    terminal: false,
  },
  confirmed_malicious: {
    label: 'Terverifikasi berbahaya',
    description:
      'Moderator sudah menetapkan laporan ini berbahaya berdasarkan laporan pengguna. Tetap berhati-hati.',
    tone: 'high',
    terminal: true,
  },
  inconclusive: {
    label: 'Belum cukup bukti',
    description:
      'Moderator tidak menemukan cukup bukti. Status ini bukan jaminan bahwa tautan aman.',
    tone: 'medium',
    terminal: true,
  },
  rejected: {
    label: 'Ditolak',
    description:
      'Laporan tidak dikonfirmasi oleh moderator. Status ini bukan jaminan bahwa tautan aman.',
    tone: 'neutral',
    terminal: true,
  },
}

export const MODERATION_UNREVIEWED_LABEL = 'Belum diverifikasi'
export const MODERATION_UNREVIEWED_DESCRIPTION =
  'Belum ada keputusan moderator untuk laporan ini. Ini bukan penilaian bahwa tautan aman.'

export const MODERATION_STATUS_SET = new Set<string>(MODERATION_STATUSES)

export const MODERATION_PUBLIC_CAVEAT =
  'Status moderasi berasal dari keputusan manual moderator. Selain “Terverifikasi berbahaya”, status bukan jaminan bahwa tautan aman.'

export function isModerationStatus(value: unknown): value is ModerationStatus {
  return typeof value === 'string' && MODERATION_STATUS_SET.has(value)
}

export type PublicModerationStatus = {
  status: ModerationStatus
  updatedAt: string | null
}

export type ModerationRecord = {
  status: ModerationStatus
  note: string
  updatedAt: string | null
  updatedBy: string
}

export type AdminModerationReport = {
  id: string
  urlHash: string
  userName: string
  reportText: string
  category: CommunityCategory
  reportedUrl: string | null
  hostname: string | null
  createdAt: string | null
  moderation: ModerationRecord | null
}

export type ModerationHistoryEntry = {
  id: string
  action: 'created' | 'status_changed'
  fromStatus: ModerationStatus | null
  toStatus: ModerationStatus
  note: string
  actorUid: string
  createdAt: string | null
}

export type ModerationAction = {
  to: ModerationStatus
  label: string
  description: string
  destructive: boolean
}

const TERMINAL_ACTIONS: ModeratorDecisionTarget[] = [
  {
    to: 'confirmed_malicious',
    label: 'Tandai terverifikasi berbahaya',
    description:
      'Status ini akan tampil di umpan publik sebagai “Terverifikasi berbahaya”. Pastikan bukti laporan sudah kamu tinjau.',
    destructive: true,
  },
  {
    to: 'inconclusive',
    label: 'Belum cukup bukti',
    description:
      'Laporan ditutup tanpa konfirmasi. Status publik akan menyatakan bukti belum cukup, bukan bahwa tautan aman.',
    destructive: false,
  },
  {
    to: 'rejected',
    label: 'Tolak laporan',
    description:
      'Laporan ditutup sebagai tidak dikonfirmasi. Status publik tidak boleh dibaca sebagai jaminan keamanan.',
    destructive: true,
  },
]

type ModeratorDecisionTarget = ModerationAction

/**
 * Aksi yang tersedia mengikuti transisi yang sama dengan Firestore Rules.
 * Status akhir tidak dapat dibuka kembali dari UI.
 */
export function allowedModerationActions(
  currentStatus: ModerationStatus | null,
): ModerationAction[] {
  if (currentStatus === null || currentStatus === 'pending') {
    return [
      {
        to: 'review',
        label: 'Mulai tinjau',
        description:
          'Tandai bahwa laporan sedang kamu periksa. Status ini terlihat publik sebagai “Sedang ditinjau”.',
        destructive: false,
      },
      ...TERMINAL_ACTIONS,
    ]
  }

  if (currentStatus === 'review') {
    return TERMINAL_ACTIONS
  }

  return []
}

export function canTransitionModeration(
  currentStatus: ModerationStatus | null,
  nextStatus: ModerationStatus,
): boolean {
  return allowedModerationActions(currentStatus).some((action) => action.to === nextStatus)
}

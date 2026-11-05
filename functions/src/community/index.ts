import { HttpsError, onCall } from 'firebase-functions/v2/https'
import { onSchedule } from 'firebase-functions/v2/scheduler'
import {
  communityTimezone,
  getCommunityContext as getCommunityContextService,
  listCommunityReports as listCommunityReportsService,
  reviewCommunityReport as reviewCommunityReportService,
  submitCommunityReport as submitCommunityReportService,
} from './service.js'
import {
  enforceCommunityReportRetention,
  formatRetentionLog,
  resolveRetentionDays,
} from './retention.js'
import type { CommunitySubmitter } from './types.js'

const REGION = 'asia-southeast2'

const CALLABLE_OPTIONS = {
  region: REGION,
  timeoutSeconds: 15,
  maxInstances: 20,
} as const

/**
 * Sesi anonim dipakai untuk scan tamu, jadi keberadaannya saja tidak cukup untuk menyentuh
 * data komunitas. Identitas diambil dari token yang diverifikasi Firebase; uid atau nama
 * kiriman klien tidak pernah dipakai.
 *
 * Gerbang ini dipakai jalur tulis DAN jalur baca. Bacaan laporan komunitas dijalankan dengan
 * Admin SDK, yang melewati Firestore rules, sedangkan rules menutup `communityReports` dan
 * `communitySummaries` untuk klien. Tanpa gerbang yang sama di sisi server, siapa pun tanpa
 * akun bisa memanggil callable dan membaca identitas pelapor.
 */
export function requireAccount(request: {
  auth?: { uid: string; token: Record<string, unknown> } | null
}): CommunitySubmitter {
  const auth = request.auth
  if (!auth) {
    throw new HttpsError('unauthenticated', 'Masuk ke akun Firebase untuk mengakses data komunitas.')
  }

  const firebase = auth.token.firebase as { sign_in_provider?: string } | undefined
  if (firebase?.sign_in_provider === 'anonymous') {
    throw new HttpsError(
      'permission-denied',
      'Data komunitas hanya dapat diakses dari akun yang masuk. Masuk dengan email untuk lanjut.',
    )
  }

  // Klaim email_verified dibaca dari token yang diverifikasi Firebase, bukan dari
  // isi permintaan, sehingga akun tanpa konfirmasi email ditolak di sisi server.
  if (auth.token.email_verified !== true) {
    throw new HttpsError(
      'permission-denied',
      'Verifikasi email akun terlebih dahulu untuk mengakses data komunitas.',
    )
  }

  const name = auth.token.name
  return { uid: auth.uid, name: typeof name === 'string' ? name : null }
}

/**
 * Bentuk permintaan yang dibaca gerbang di bawah. Handler onCall membawa properti tambahan
 * (rawRequest, headers, dll.), jadi tipe struktural yang lebih sempit tetap menerima request
 * aslinya. Handler diekstrak sebagai fungsi biasa supaya gerbang otorisasi bisa diuji tanpa
 * memanggil callable yang ter-deploy.
 */
type GuardedCall = {
  auth?: { uid: string; token: Record<string, unknown> } | null
  data: unknown
}

export async function getCommunityContextHandler(request: GuardedCall) {
  // requireAccount dieksekusi sebelum Admin SDK membaca agregat maupun laporan lintas akun,
  // sehingga riwayat milik pemanggil diambil dari uid token, bukan dari isi permintaan.
  const account = requireAccount(request)
  return getCommunityContextService(account.uid, request.data)
}

export async function listCommunityReportsHandler(request: GuardedCall) {
  // Daftar 24 jam terakhir memuat nama pelapor; jalur baca ini memakai gerbang yang sama
  // dengan jalur tulis supaya tidak ada pintu yang lebih longgar ke data yang sama.
  requireAccount(request)
  const reports = await listCommunityReportsService(request.data)
  return { reports }
}

export async function reviewCommunityReportHandler(request: GuardedCall) {
  if (!request.auth) {
    throw new HttpsError('unauthenticated', 'Autentikasi admin diperlukan.')
  }

  if (request.auth.token.admin !== true) {
    throw new HttpsError('permission-denied', 'Hanya admin yang dapat memoderasi laporan.')
  }

  return reviewCommunityReportService(request.auth.uid, request.data)
}

export const submitCommunityReport = onCall(CALLABLE_OPTIONS, async (request) => {
  return submitCommunityReportService(requireAccount(request), request.data)
})

export const getCommunityContext = onCall(CALLABLE_OPTIONS, (request) =>
  getCommunityContextHandler(request),
)

export const listCommunityReports = onCall(CALLABLE_OPTIONS, (request) =>
  listCommunityReportsHandler(request),
)

export const reviewCommunityReport = onCall(
  { ...CALLABLE_OPTIONS, maxInstances: 5 },
  (request) => reviewCommunityReportHandler(request),
)

/**
 * Pekerjaan terjadwal pembersihan retensi. Syarat jalannya: Cloud Scheduler aktif dan
 * proyek berjalan pada paket yang mendukung Cloud Functions 2nd gen. Tanpa itu fungsi ini
 * tidak pernah dipanggil; laporan tetap tersimpan dan tidak ada data yang hilang.
 */
export const communityReportRetentionCleanup = onSchedule(
  {
    region: REGION,
    schedule: '15 3 * * *',
    timeZone: communityTimezone(),
    timeoutSeconds: 300,
    memory: '256MiB',
  },
  async () => {
    try {
      const outcome = await enforceCommunityReportRetention({
        retentionDays: resolveRetentionDays(process.env.COMMUNITY_RETENTION_DAYS),
      })
      // Log hanya memuat angka; isi laporan, URL, dan nama pelapor tidak ditulis ke log.
      console.log(formatRetentionLog(outcome))
    } catch (error) {
      const code =
        error && typeof error === 'object' && 'code' in error
          ? String((error as { code?: unknown }).code).slice(0, 80)
          : 'unknown'
      // Jangan menulis pesan error mentah: pesan Firestore dapat memuat path dokumen.
      console.error(
        JSON.stringify({
          event: 'community_report_retention',
          status: 'error',
          code,
        }),
      )
      throw new Error('community_report_retention_failed')
    }
  },
)

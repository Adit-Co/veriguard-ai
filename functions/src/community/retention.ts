import { promises as dns } from 'node:dns'
import { Timestamp, getFirestore, type DocumentData, type Firestore } from 'firebase-admin/firestore'
import {
  COMMUNITY_COLLECTIONS,
  COMMUNITY_POLICY,
  type RetentionOutcome,
} from './types.js'

export type InactivityVerdict = 'inactive' | 'reachable' | 'inconclusive'
export type InactivityVerifier = (hostname: string) => Promise<InactivityVerdict>

export type RetentionDependencies = {
  db: Firestore
  verifyInactivity: InactivityVerifier
  now: () => number
  retentionDays: number
  batchSize: number
}

/**
 * Konfigurasi masa retensi selalu dipaksa ke rentang 30-90 hari yang diminta, sehingga
 * nilai lingkungan yang keliru tidak dapat menghapus riwayat terlalu cepat.
 */
export function resolveRetentionDays(configured?: string): number {
  const value = Number.parseInt(configured?.trim() ?? '', 10)
  if (!Number.isFinite(value)) return COMMUNITY_POLICY.retentionDaysDefault
  return Math.min(
    COMMUNITY_POLICY.retentionDaysMax,
    Math.max(COMMUNITY_POLICY.retentionDaysMin, value),
  )
}

/**
 * Satu-satunya bukti "URL sudah benar-benar mati" yang dianggap andal adalah NXDOMAIN:
 * nama domainnya tidak terdaftar lagi. Timeout, SERVFAIL, EAI_AGAIN, dan ENODATA adalah
 * kondisi sementara atau perbedaan tipe record, jadi diklasifikasikan tidak conclusif dan
 * laporan dipertahankan.
 */
const HARD_NXDOMAIN_CODES = new Set(['ENOTFOUND'])

function isNxDomain(error: unknown): boolean {
  const code = (error as { code?: string })?.code
  return typeof code === 'string' && HARD_NXDOMAIN_CODES.has(code)
}

/**
 * Resolver mengembalikan ENOTFOUND untuk literal IP karena yang diminta adalah record DNS,
 * bukan alamat host. Itu bukan bukti host mati, jadi laporan dengan host IP tidak pernah
 * dihapus otomatis oleh pemeriksaan DNS ini.
 */
function isIpLiteral(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '')
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(':')
}

export async function dnsVerdict(hostname: string): Promise<InactivityVerdict> {
  if (isIpLiteral(hostname)) return 'inconclusive'

  const lookups = await Promise.allSettled([dns.resolve4(hostname), dns.resolve6(hostname)])

  const resolved = lookups.some(
    (entry) => entry.status === 'fulfilled' && Array.isArray(entry.value) && entry.value.length > 0,
  )
  if (resolved) return 'reachable'

  const rejected = lookups.filter((entry) => entry.status === 'rejected')
  if (rejected.length === lookups.length && rejected.every((entry) => isNxDomain(entry.reason))) {
    return 'inactive'
  }

  return 'inconclusive'
}

function readTimestamp(value: unknown): Timestamp | null {
  return value instanceof Timestamp ? value : null
}

function readCount(value: unknown): number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : 0
}

function readString(value: unknown): string | null {
  return typeof value === 'string' && value ? value : null
}

function readReporterCount(data: DocumentData): number {
  return typeof data.reporterCount === 'number'
    ? readCount(data.reporterCount)
    : readCount(data.reportCount)
}

/** Path laporan harus tetap di bawah pemiliknya; data laporan tidak menentukan pemilik baru. */
function ownerFromReportPath(path: string): string | null {
  const segments = path.split('/')
  if (
    segments.length !== 4 ||
    segments[0] !== 'users' ||
    segments[2] !== COMMUNITY_COLLECTIONS.reports
  ) {
    return null
  }
  return readString(segments[1])
}

function readCategoryCounts(value: unknown): Partial<Record<string, number>> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  const counts: Partial<Record<string, number>> = {}
  for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
    if (typeof raw === 'number' && Number.isInteger(raw) && raw > 0) counts[key] = raw
  }
  return counts
}

function hostnameOf(data: DocumentData): string {
  return typeof data.hostname === 'string' ? data.hostname : ''
}

/**
 * Membersihkan hanya laporan yang memenuhi DUA syarat sekaligus: lebih tua dari ambang
 * retensi DAN ketidakhidupannya terkonfirmasi berulang dengan jeda. Bukti ditulis
 * berdampingan dengan laporan agar tidak ada penghapusan berdasarkan satu pemeriksaan.
 */
export async function enforceCommunityReportRetention(
  dependencies: Partial<RetentionDependencies> = {},
): Promise<RetentionOutcome> {
  const db = dependencies.db ?? getFirestore()
  const verifyInactivity = dependencies.verifyInactivity ?? dnsVerdict
  const nowMs = dependencies.now?.() ?? Date.now()
  const retentionDays = dependencies.retentionDays ?? resolveRetentionDays()
  const batchSize = Math.max(
    1,
    Math.min(dependencies.batchSize ?? COMMUNITY_POLICY.retentionBatchSize, 100),
  )

  const cutoff = Timestamp.fromMillis(nowMs - retentionDays * 24 * 60 * 60 * 1000)
  const snapshot = await db
    .collectionGroup(COMMUNITY_COLLECTIONS.reports)
    .where('createdAt', '<', cutoff)
    .orderBy('createdAt', 'asc')
    .limit(batchSize)
    .get()

  let deleted = 0
  let retained = 0
  let verifierErrors = 0

  for (const doc of snapshot.docs) {
    const data = doc.data()
    const hostname = hostnameOf(data)
    const ownerId = ownerFromReportPath(doc.ref.path)
    const urlHash = readString(data.urlHash)
    const createdAt = readTimestamp(data.createdAt)

    // Tanpa umur, pemilik, atau identitas URL yang pasti, laporan tidak pernah dihapus.
    if (!hostname || !ownerId || !urlHash || !createdAt) {
      retained += 1
      continue
    }

    const reportRef = doc.ref

    let verdict: InactivityVerdict
    try {
      verdict = await verifyInactivity(hostname)
    } catch {
      // Kegagalan pemeriksaan itu sendiri bukan bukti tidakaktif: laporan tetap
      // dipertahankan dan dokumen berikutnya tetap diperiksa.
      verdict = 'inconclusive'
      verifierErrors += 1
    }

    if (verdict !== 'inactive') {
      // URL hidup kembali: bukti lama dibatalkan. Hasil yang belum pasti tidak mengubah
      // bukti, supaya pemeriksaan berikutnya masih dapat mengonfirmasi.
      if (verdict === 'reachable' && readCount(data.retentionChecks) > 0) {
        await reportRef.update({
          retentionChecks: 0,
          lastRetentionCheckAt: Timestamp.fromMillis(nowMs),
        })
      }
      retained += 1
      continue
    }

    const previousChecks = readCount(data.retentionChecks)
    const previousCheckAt = readTimestamp(data.lastRetentionCheckAt)

    if (previousChecks < 1 || !previousCheckAt) {
      await reportRef.update({
        retentionChecks: 1,
        lastRetentionCheckAt: Timestamp.fromMillis(nowMs),
      })
      retained += 1
      continue
    }

    const gapMs = nowMs - previousCheckAt.toMillis()
    const totalChecks = previousChecks + 1
    // Jangan pernah memindahkan lastRetentionCheckAt saat jeda belum cukup: pekerjaan ini
    // berjalan harian, dan memindahkannya akan membuat ambang 7 hari tidak pernah tercapai.
    const confirmation =
      totalChecks >= COMMUNITY_POLICY.retentionRequiredChecks &&
      gapMs >= COMMUNITY_POLICY.retentionCheckGapMs

    if (!confirmation) {
      retained += 1
      continue
    }

    const removed = await db.runTransaction<boolean>(async (transaction) => {
      // Semua pembacaan transaksi dilakukan sebelum penulisan apa pun.
      const fresh = await transaction.get(reportRef)
      if (!fresh.exists) return false

      const freshData = fresh.data()
      const summaryRef = db.collection(COMMUNITY_COLLECTIONS.summaries).doc(urlHash)
      const summarySnap = await transaction.get(summaryRef)
      const ownReportsQuery = db
        .collection('users')
        .doc(ownerId)
        .collection(COMMUNITY_COLLECTIONS.reports)
        .where('urlHash', '==', urlHash)
        .limit(2)
      const ownReportsSnap = await transaction.get(ownReportsQuery)

      const freshCreatedAt = readTimestamp(freshData?.createdAt)
      const freshCheckAt = readTimestamp(freshData?.lastRetentionCheckAt)
      const stillEligible =
        Boolean(freshCreatedAt) &&
        (freshCreatedAt as Timestamp).toMillis() < cutoff.toMillis() &&
        readCount(freshData?.retentionChecks) >= 1 &&
        Boolean(freshCheckAt) &&
        nowMs - (freshCheckAt as Timestamp).toMillis() >= COMMUNITY_POLICY.retentionCheckGapMs
      if (!stillEligible) return false

      const hasOtherReportByOwner = ownReportsSnap.docs.some(
        (entry) => entry.ref.path !== reportRef.path,
      )

      transaction.delete(reportRef)

      if (summarySnap.exists) {
        const summaryData = summarySnap.data()!
        const counts = readCategoryCounts(summaryData.categoryCounts)
        const category = typeof freshData?.category === 'string' ? freshData.category : null
        if (category && counts[category]) {
          counts[category] -= 1
          if (counts[category] <= 0) delete counts[category]
        }

        const remainingReports = Math.max(0, readCount(summaryData.reportCount) - 1)
        const remainingReporters = Math.max(
          0,
          readReporterCount(summaryData) - (hasOtherReportByOwner ? 0 : 1),
        )

        transaction.set(
          summaryRef,
          {
            reportCount: remainingReports,
            reporterCount: remainingReporters,
            categoryCounts: counts,
            updatedAt: Timestamp.fromMillis(nowMs),
          },
          { merge: true },
        )
      }

      return true
    })

    if (removed) {
      deleted += 1
    } else {
      retained += 1
    }
  }

  return {
    scanned: snapshot.docs.length,
    deleted,
    retained,
    retentionDays,
    detail: describeOutcome(snapshot.docs.length, verifierErrors),
  }
}

/** Log hanya memuat kode singkat; tidak ada isi laporan, URL, atau nama pelapor. */
function describeOutcome(scanned: number, verifierErrors: number): string | null {
  if (scanned === 0) return 'empty'
  if (verifierErrors > 0) return `verifier-inconclusive:${verifierErrors}`
  return null
}

export function formatRetentionLog(outcome: RetentionOutcome): string {
  // Tidak ada isi laporan, URL, atau nama pengguna di baris log.
  return JSON.stringify({
    event: 'community_report_retention',
    scanned: outcome.scanned,
    deleted: outcome.deleted,
    retained: outcome.retained,
    retentionDays: outcome.retentionDays,
    detail: outcome.detail,
  })
}

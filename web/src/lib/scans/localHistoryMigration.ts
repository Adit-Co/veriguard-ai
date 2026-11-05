import { describeFirestoreError } from '../firebase/errors'
import { pruneCloudScans, saveCloudScan } from '../firebase/scans'
import {
  MAX_SAVED_SCANS,
  deleteScan,
  getScan,
  listScans,
  toStoredScan,
} from '../storage/scanStore'
import {
  forgetPendingScan,
  pendingScanIds,
  rememberPendingScan,
} from './pendingSyncStore'

export type LocalHistoryMergeResult = {
  uploaded: number
  failed: number
  message: string | null
}

const EMPTY: LocalHistoryMergeResult = { uploaded: 0, failed: 0, message: null }

// Satu jalan per UID per sesi aplikasi: tiga halaman memakai hook yang sama, tanpa antrean ini
// riwayat perangkat akan dikirim berkali-kali pada setiap perpindahan halaman.
const passes = new Map<string, Promise<LocalHistoryMergeResult>>()
const retentionPasses = new Set<string>()

function candidateIds(uid: string): string[] {
  return [...new Set([...pendingScanIds(uid), ...listScans().map((scan) => scan.id)])].slice(
    0,
    MAX_SAVED_SCANS,
  )
}

async function runMerge(uid: string): Promise<LocalHistoryMergeResult> {
  const ids = candidateIds(uid)
  if (ids.length === 0) return EMPTY

  let uploaded = 0
  let failed = 0
  let lastError: unknown = null

  for (const id of ids) {
    const scan = getScan(id)
    // Entri yang sudah tidak ada di perangkat (dihapus pengguna atau dipotong retensi 90 hari)
    // tidak boleh ditulis ulang ke akun dari ingatan lama.
    if (!scan) {
      forgetPendingScan(uid, id)
      continue
    }

    try {
      await saveCloudScan(uid, toStoredScan(scan))
      // Riwayat lokal baru dibuang setelah Firestore mengonfirmasi dokumen milik akun ini.
      deleteScan(id)
      forgetPendingScan(uid, id)
      uploaded += 1
    } catch (cause) {
      rememberPendingScan(uid, id)
      failed += 1
      lastError = cause
    }
  }

  if (uploaded > 0) {
    scheduleRetentionPass(uid)
  }

  return {
    uploaded,
    failed,
    message: failed > 0 ? describeFirestoreError(lastError).message : null,
  }
}

/**
 * VGL-17: mengirim riwayat yang masih tertinggal di perangkat (pemeriksaan tamu, hasil yang
 * gagal tersinkronisasi, atau entri dari sebelum email terverifikasi) ke `users/{uid}/scans`.
 * Dokumen ditulis dengan id yang sama seperti di perangkat sehingga referensi `/hasil/:id`
 * tetap sah, dan `setDoc` membuat jalan ini aman dijalankan berulang tanpa dokumen kembar.
 * Fungsi ini tidak pernah melempar: kegagalan dikembalikan sebagai status agar halaman tidak
 * kehilangan hasil yang sedang dilihat pengguna.
 */
export function mergeLocalScansIntoAccount(uid: string): Promise<LocalHistoryMergeResult> {
  if (!uid) return Promise.resolve(EMPTY)

  const inFlight = passes.get(uid)
  if (inFlight) return inFlight

  const pass = runMerge(uid).catch((cause): LocalHistoryMergeResult => {
    return {
      uploaded: 0,
      failed: 0,
      message: describeFirestoreError(cause).message,
    }
  })

  passes.set(uid, pass)

  // Jalan yang masih menyisakan kegagalan dibuang dari ingatan agar mount berikutnya mencoba
  // lagi; yang bersih dibiarkan supaya panggilan selanjutnya menjadi no-op.
  void pass.then((result) => {
    if (result.failed > 0 || (result.uploaded === 0 && result.message !== null)) {
      passes.delete(uid)
    }
  })

  return pass
}

/** Dibutuhkan pengujian: membebaskan ingatan "satu jalan per sesi" untuk kedua pekerjaan. */
export function resetLocalHistoryMergePasses(): void {
  passes.clear()
  retentionPasses.clear()
}

/**
 * VGL-17: menjalankan pemangkasan retensi riwayat akun (90 hari dan maksimal
 * MAX_SAVED_SCANS dokumen — kebijakan yang sama dengan penyimpanan lokal) paling banyak satu
 * kali per UID per sesi aplikasi. Hasilnya sengaja tidak ditunggu: dokumentasi retensi tidak
 * boleh menahan tampilan hasil pemeriksaan, dan kegagalan pangkasan tidak boleh membuat
 * pengguna mengira riwayatnya hilang.
 */
export function scheduleRetentionPass(uid: string): void {
  if (!uid || retentionPasses.has(uid)) return

  retentionPasses.add(uid)
  void pruneCloudScans(uid).catch(() => undefined)
}

/** Ulang jalan migrasi setelah pengguna memilih mencoba lagi; hanya UID itu yang dibebaskan. */
export async function retryMergeLocalScans(
  uid: string,
): Promise<LocalHistoryMergeResult> {
  passes.delete(uid)
  return mergeLocalScansIntoAccount(uid)
}

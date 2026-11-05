import type { ScanDraft, ScanResult } from '../analysis/types'
import { describeFirestoreError } from '../firebase/errors'
import { saveCloudScan } from '../firebase/scans'
import {
  listScans,
  persistPreparedScan,
  prepareScan,
  toStoredScan,
  type SaveScanOptions,
} from '../storage/scanStore'
import { scheduleRetentionPass } from './localHistoryMigration'
import { rememberPendingScan, retainPendingScans } from './pendingSyncStore'
import type { ScanSource } from './useScanHistory'

export type SaveScanOutcome = {
  scan: ScanResult
  /** Tempat salinan hasil ini berada setelah fungsi selesai. */
  source: ScanSource
  /** Pesan yang siap ditampilkan saat sinkronisasi akun gagal; `null` saat tersimpan di akun. */
  syncError: string | null
}

export async function saveScanForUser(
  draft: ScanDraft,
  options: SaveScanOptions,
  uid: string | null,
): Promise<SaveScanOutcome> {
  const scan = prepareScan(draft, options)

  if (!uid) {
    persistPreparedScan(scan)
    return { scan, source: 'local', syncError: null }
  }

  // Yang dikirim ke Firestore adalah salinan yang sudah aman; objek yang dipakai sesi
  // berjalan ini tetap memegang teks asli.
  try {
    await saveCloudScan(uid, toStoredScan(scan))
    scheduleRetentionPass(uid)
    return { scan, source: 'cloud', syncError: null }
  } catch (cause) {
    // VGL-17: kegagalan riwayat tidak boleh menghapus hasil pemeriksaan. Salinan aman
    // ditahan di perangkat dan diantrekan untuk dikirim ulang; panggilan diberi tahu bahwa
    // sinkronisasi gagal, bukan bahwa hasilnya tersimpan di akun.
    persistPreparedScan(scan)
    retainPendingScans(
      uid,
      listScans().map((item) => item.id),
    )
    rememberPendingScan(uid, scan.id)
    return { scan, source: 'local', syncError: describeFirestoreError(cause).message }
  }
}

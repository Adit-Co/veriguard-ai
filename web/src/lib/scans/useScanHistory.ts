import { useCallback, useEffect, useRef, useState } from 'react'
import type { ScanResult } from '../analysis/types'
import { useAuth } from '../auth/useAuth'
import { isVerifiedAccount } from '../auth/verification'
import {
  describeFirestoreError,
  type FirestoreErrorKind,
} from '../firebase/errors'
import {
  clearCloudScans,
  deleteCloudScan,
  listCloudScans,
  redactCloudMessageContents,
} from '../firebase/scans'
import { clearScanReports, deleteScanReport } from '../scanners/reportStore'
import {
  mergeLocalScansIntoAccount,
  retryMergeLocalScans,
  type LocalHistoryMergeResult,
} from './localHistoryMigration'
import {
  clearPendingSync,
  forgetPendingScan,
  pendingScanIds,
} from './pendingSyncStore'
import { clearSiteAnalyses, deleteSiteAnalysis } from '../website/analysisStore'
import {
  clearScans,
  deleteScan,
  listScans,
  redactAllMessageContents,
} from '../storage/scanStore'

type ScanHistoryState = {
  ownerKey: string
  scans: ScanResult[]
  loading: boolean
  error: string | null
  errorKind: FirestoreErrorKind | null
  pendingLocalCount: number
  syncMessage: string | null
}

export type ScanSource = 'cloud' | 'local'

function scanOwnerKey(cloud: boolean, uid: string | null): string {
  return cloud && uid ? `user:${uid}` : 'local'
}

export function useScanHistory() {
  const { mode, status, user } = useAuth()
  const cloud = mode === 'firebase' && isVerifiedAccount(user)
  const waitingForAuth = mode === 'firebase' && status === 'loading'
  const uid = user?.uid ?? null
  const ownerKey = scanOwnerKey(cloud, uid)
  const [state, setState] = useState<ScanHistoryState>(() => ({
    ownerKey,
    scans: waitingForAuth || cloud ? [] : listScans(),
    loading: waitingForAuth || cloud,
    error: null,
    errorKind: null,
    pendingLocalCount: 0,
    syncMessage: null,
  }))
  const requestId = useRef(0)
  const stateOwnerRef = useRef(ownerKey)

  const load = useCallback(async () => {
    if (waitingForAuth) return

    const request = requestId.current + 1
    requestId.current = request
    await Promise.resolve()

    const targetOwner = scanOwnerKey(cloud, uid)
    const switchingOwner = stateOwnerRef.current !== targetOwner
    stateOwnerRef.current = targetOwner

    if (!cloud || !uid) {
      const scans = listScans()
      if (requestId.current === request) {
        setState({
          ownerKey: targetOwner,
          scans,
          loading: false,
          error: null,
          errorKind: null,
          pendingLocalCount: 0,
          syncMessage: null,
        })
      }
      return
    }

    setState((current) => ({
      ...current,
      ownerKey: targetOwner,
      scans: switchingOwner ? [] : current.scans,
      loading: true,
      error: null,
      errorKind: null,
    }))

    // Riwayat yang masih tertinggal di perangkat (pemeriksaan tamu, hasil yang gagal
    // tersinkronisasi) dikirim lebih dulu, supaya daftar yang dibaca pengguna setelahnya
    // adalah daftar akun yang sudah lengkap.
    const merge: LocalHistoryMergeResult = await mergeLocalScansIntoAccount(uid)

    try {
      const scans = await listCloudScans(uid)
      if (requestId.current === request) {
        setState({
          ownerKey: targetOwner,
          scans,
          loading: false,
          error: null,
          errorKind: null,
          pendingLocalCount: pendingScanIds(uid).length,
          syncMessage: merge.message,
        })
      }
    } catch (error) {
      if (requestId.current === request) {
        const info = describeFirestoreError(error)
        setState((current) => ({
          ...current,
          ownerKey: targetOwner,
          loading: false,
          error: info.message,
          errorKind: info.kind,
          pendingLocalCount: pendingScanIds(uid).length,
          syncMessage: merge.message ?? info.message,
        }))
      }
    }
  }, [cloud, uid, waitingForAuth])

  useEffect(() => {
    // oxlint-disable-next-line react/set-state-in-effect -- sinkronisasi data Firebase/localStorage
    void load()
  }, [load])

  const remove = useCallback(
    async (id: string) => {
      // Salinan perangkat selalu ikut dihapus. Hasil yang masih mengantre untuk dikirim tidak
      // boleh muncul kembali di akun setelah pengguna menghapusnya dari riwayat.
      deleteScan(id)

      if (cloud && uid) {
        forgetPendingScan(uid, id)
        await deleteCloudScan(uid, id)
      }

      deleteScanReport(id)
      deleteSiteAnalysis(id)

      setState((current) => ({
        ...current,
        scans: current.scans.filter((scan) => scan.id !== id),
      }))
    },
    [cloud, uid],
  )

  const clear = useCallback(async () => {
    // Penghapusan lokal dijalankan lebih dulu dan tanpa syarat: janji tombol tidak boleh
    // bergantung pada status login, sumber riwayat, atau keberhasilan jaringan.
    clearScans()
    clearPendingSync()
    clearScanReports()
    clearSiteAnalyses()

    if (cloud && uid) {
      await clearCloudScans(uid)
    }

    setState((current) => ({
      ...current,
      scans: [],
      error: null,
      errorKind: null,
      pendingLocalCount: 0,
      syncMessage: null,
    }))
  }, [cloud, uid])

  const syncLocalHistory = useCallback(async (): Promise<LocalHistoryMergeResult> => {
    if (!cloud || !uid) {
      return { uploaded: 0, failed: 0, message: null }
    }

    const result = await retryMergeLocalScans(uid)
    await load()
    return result
  }, [cloud, load, uid])

  const redactAll = useCallback(async () => {
    if (cloud && uid) {
      const count = await redactCloudMessageContents(uid)
      await load()
      return count
    }

    const count = redactAllMessageContents()
    setState((current) => ({ ...current, scans: listScans() }))
    return count
  }, [cloud, load, uid])

  const visible = state.ownerKey === ownerKey

  return {
    scans: visible ? state.scans : [],
    loading: visible ? state.loading : true,
    error: visible ? state.error : null,
    errorKind: visible ? state.errorKind : null,
    pendingLocalCount: visible ? state.pendingLocalCount : 0,
    syncMessage: visible ? state.syncMessage : null,
    source: (cloud ? 'cloud' : 'local') as ScanSource,
    refresh: load,
    remove,
    clear,
    redactAll,
    syncLocalHistory,
  }
}

import { useCallback, useEffect, useRef, useState } from 'react'
import type { ScanResult } from '../analysis/types'
import { useAuth } from '../auth/useAuth'
import { isVerifiedAccount } from '../auth/verification'
import { describeFirestoreError } from '../firebase/errors'
import { getCloudScan } from '../firebase/scans'
import { pendingScanIds } from './pendingSyncStore'
import { getScan } from '../storage/scanStore'
import type { ScanSource } from './useScanHistory'

type ScanState = {
  ownerKey: string
  scan: ScanResult | null
  loading: boolean
  error: string | null
}

function scanOwnerKey(cloud: boolean, uid: string | null, id: string | undefined): string {
  return `${cloud && uid ? `user:${uid}` : 'local'}:${id ?? ''}`
}

/**
 * VGL-17: satu-satunya keadaan ketika akun terverifikasi membaca perangkat. Hasil yang
 * antrean sinkronisasinya masih menunggu untuk UID ini memang belum ada di Firestore, jadi
 * halaman hasil tetap bisa dibuka alih-alih melaporkan hasil yang baru saja dibuat sebagai
 * tidak ditemukan. Pemeriksaan lain tetap hanya dari akun.
 */
function pendingLocalScan(uid: string, id: string): ScanResult | null {
  if (!pendingScanIds(uid).includes(id)) return null

  return getScan(id)
}

export function useScan(id: string | undefined) {
  const { mode, status, user } = useAuth()
  const cloud = mode === 'firebase' && isVerifiedAccount(user)
  const waitingForAuth = mode === 'firebase' && status === 'loading'
  const uid = user?.uid ?? null
  const ownerKey = scanOwnerKey(cloud, uid, id)
  const [state, setState] = useState<ScanState>(() => ({
    ownerKey,
    scan: !waitingForAuth && !cloud && id ? getScan(id) : null,
    loading: Boolean(id) && (waitingForAuth || cloud),
    error: null,
  }))
  const requestId = useRef(0)
  const stateOwnerRef = useRef(ownerKey)

  const load = useCallback(async () => {
    if (!id || waitingForAuth) return

    const request = requestId.current + 1
    requestId.current = request
    await Promise.resolve()

    const targetOwner = scanOwnerKey(cloud, uid, id)
    const switchingOwner = stateOwnerRef.current !== targetOwner
    stateOwnerRef.current = targetOwner

    if (!cloud || !uid) {
      setState({
        ownerKey: targetOwner,
        scan: getScan(id),
        loading: false,
        error: null,
      })
      return
    }

    setState((current) => ({
      ownerKey: targetOwner,
      scan: switchingOwner ? null : current.scan,
      loading: true,
      error: null,
    }))

    try {
      const scan = (await getCloudScan(uid, id)) ?? pendingLocalScan(uid, id)
      if (requestId.current === request) {
        setState({ ownerKey: targetOwner, scan, loading: false, error: null })
      }
    } catch (error) {
      if (requestId.current === request) {
        setState({
          ownerKey: targetOwner,
          scan: null,
          loading: false,
          error: describeFirestoreError(error).message,
        })
      }
    }
  }, [cloud, id, uid, waitingForAuth])

  useEffect(() => {
    // oxlint-disable-next-line react/set-state-in-effect -- sinkronisasi data Firebase/localStorage
    void load()
  }, [load])

  const visible = state.ownerKey === ownerKey

  return {
    scan: visible ? state.scan : null,
    loading: visible ? state.loading : Boolean(id),
    error: visible ? state.error : null,
    source: (cloud ? 'cloud' : 'local') as ScanSource,
    retry: load,
  }
}

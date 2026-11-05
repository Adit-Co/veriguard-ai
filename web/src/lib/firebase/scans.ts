import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  limit,
  orderBy,
  query,
  setDoc,
  writeBatch,
} from 'firebase/firestore'
import type { ScanResult } from '../analysis/types'
import {
  MAX_SAVED_SCANS,
  SCAN_RETENTION_MS,
  redactMessageScan,
} from '../storage/scanStore'
import { getFirebaseClient } from './client'
import { fromCloudScanDocument, toCloudScanDocument } from './scanDocuments'

const BATCH_SIZE = 450

function scansCollection(uid: string) {
  const { db } = getFirebaseClient()
  return collection(db, 'users', uid, 'scans')
}

function scanDocument(uid: string, scanId: string) {
  const { db } = getFirebaseClient()
  return doc(db, 'users', uid, 'scans', scanId)
}

function assertScanId(scanId: string): void {
  if (!scanId || scanId.includes('/')) {
    throw new Error('ID pemeriksaan tidak valid untuk disimpan ke penyimpanan akun.')
  }
}

export async function listCloudScans(uid: string): Promise<ScanResult[]> {
  const snapshot = await getDocs(
    query(scansCollection(uid), orderBy('createdAt', 'desc'), limit(MAX_SAVED_SCANS)),
  )

  return snapshot.docs
    .map((item) => fromCloudScanDocument(item.id, item.data(), uid))
    .filter((item): item is ScanResult => item !== null)
}

export async function getCloudScan(uid: string, scanId: string): Promise<ScanResult | null> {
  const snapshot = await getDoc(scanDocument(uid, scanId))
  if (!snapshot.exists()) return null
  return fromCloudScanDocument(snapshot.id, snapshot.data(), uid)
}

export async function saveCloudScan(uid: string, scan: ScanResult): Promise<void> {
  assertScanId(scan.id)
  await setDoc(scanDocument(uid, scan.id), toCloudScanDocument(scan, uid))
}

export async function deleteCloudScan(uid: string, scanId: string): Promise<void> {
  await deleteDoc(scanDocument(uid, scanId))
}

export async function clearCloudScans(uid: string): Promise<void> {
  const snapshot = await getDocs(scansCollection(uid))
  const { db } = getFirebaseClient()

  for (let index = 0; index < snapshot.docs.length; index += BATCH_SIZE) {
    const batch = writeBatch(db)
    for (const item of snapshot.docs.slice(index, index + BATCH_SIZE)) {
      batch.delete(item.ref)
    }
    await batch.commit()
  }
}

/**
 * VGL-17: retensi riwayat akun memakai kebijakan yang sama seperti penyimpanan lokal — hanya
 * MAX_SAVED_SCANS pemeriksaan terbaru yang bertahan dan tidak lebih tua dari SCAN_RETENTION_MS.
 * Batas jumlah pada `listCloudScans` bukan mekanisme penghapusan: tanpanya dokumen lama tetap
 * menumpuk di Firestore meski tidak lagi ditampilkan. Pemanggil tidak menunggu hasilnya supaya
 * hasil pemeriksaan pengguna tidak tertahan oleh pekerjaan rumah tangga.
 */
export async function pruneCloudScans(uid: string, now = Date.now()): Promise<number> {
  const snapshot = await getDocs(query(scansCollection(uid), orderBy('createdAt', 'desc')))
  const cutoff = now - SCAN_RETENTION_MS
  const stale = snapshot.docs.filter((item, index) => {
    if (index >= MAX_SAVED_SCANS) return true

    const createdAt = Date.parse(String(item.data().createdAt ?? ''))
    return !Number.isNaN(createdAt) && createdAt < cutoff
  })

  if (stale.length === 0) return 0

  const { db } = getFirebaseClient()
  for (let index = 0; index < stale.length; index += BATCH_SIZE) {
    const batch = writeBatch(db)
    for (const item of stale.slice(index, index + BATCH_SIZE)) {
      batch.delete(item.ref)
    }
    await batch.commit()
  }

  return stale.length
}

export async function redactCloudMessageContents(uid: string): Promise<number> {
  const snapshot = await getDocs(query(scansCollection(uid), limit(MAX_SAVED_SCANS)))
  const { db } = getFirebaseClient()
  const updates: Array<{ id: string; scan: ScanResult }> = []

  for (const item of snapshot.docs) {
    const scan = fromCloudScanDocument(item.id, item.data(), uid)
    if (scan?.mode === 'message' && scan.meta.inputStored !== 'redacted') {
      updates.push({ id: item.id, scan: redactMessageScan(scan) })
    }
  }

  for (let index = 0; index < updates.length; index += BATCH_SIZE) {
    const batch = writeBatch(db)
    for (const update of updates.slice(index, index + BATCH_SIZE)) {
      batch.set(scanDocument(uid, update.id), toCloudScanDocument(update.scan, uid))
    }
    await batch.commit()
  }

  return updates.length
}

import { MAX_SAVED_SCANS } from '../storage/scanStore'

export const PENDING_SYNC_STORAGE_KEY = 'veriguard.pendingSync.v1'

export type PendingSyncQueue = {
  uid: string
  scanIds: string[]
}

let memoryQueue: PendingSyncQueue | null = null

function getStorage(): Storage | null {
  if (typeof window === 'undefined') return null

  try {
    const storage = window.localStorage
    const probe = '__veriguard_pending_sync_probe__'
    storage.setItem(probe, '1')
    storage.removeItem(probe)
    return storage
  } catch {
    return null
  }
}

function isPendingSyncQueue(value: unknown): value is PendingSyncQueue {
  if (!value || typeof value !== 'object') return false

  const candidate = value as Record<string, unknown>
  return (
    typeof candidate.uid === 'string' &&
    candidate.uid.length > 0 &&
    Array.isArray(candidate.scanIds) &&
    candidate.scanIds.every((id) => typeof id === 'string' && id.length > 0)
  )
}

function read(): PendingSyncQueue | null {
  const storage = getStorage()
  if (!storage) return memoryQueue

  try {
    const raw = storage.getItem(PENDING_SYNC_STORAGE_KEY)
    if (!raw) return null

    const parsed: unknown = JSON.parse(raw)
    if (!isPendingSyncQueue(parsed)) return null

    memoryQueue = parsed
    return parsed
  } catch {
    return memoryQueue
  }
}

function write(queue: PendingSyncQueue | null): void {
  memoryQueue = queue

  const storage = getStorage()
  if (!storage) return

  try {
    if (!queue || queue.scanIds.length === 0) {
      storage.removeItem(PENDING_SYNC_STORAGE_KEY)
      return
    }
    storage.setItem(PENDING_SYNC_STORAGE_KEY, JSON.stringify(queue))
  } catch {
    // Antrean tetap tersedia di memori sesi ini bila penyimpanan ditolak.
  }
}

/**
 * Antrean milik satu akun saja. Saat UID yang tersimpan bukan UID yang sedang masuk,
 * antreannya dibuang: pemeriksaan yang masih ada di localStorage akan diantrekan ulang
 * oleh migrasi, dan tidak ada riwayat yang pernah dikirim ke akun lain.
 */
export function pendingScanIds(uid: string): string[] {
  const queue = read()
  if (!queue) return []

  if (queue.uid !== uid) {
    write(null)
    return []
  }

  return [...queue.scanIds]
}

export function rememberPendingScan(uid: string, scanId: string): void {
  if (!uid || !scanId) return

  const queue = read()
  const current = queue && queue.uid === uid ? queue.scanIds : []
  // Batas yang sama dengan penyimpanan riwayat: entri yang terdorong keluar tetap tinggal di
  // localStorage dan akan diantrekan ulang oleh migrasi berikutnya.
  const next = [scanId, ...current.filter((id) => id !== scanId)].slice(0, MAX_SAVED_SCANS)

  write({ uid, scanIds: next })
}

export function forgetPendingScan(uid: string, scanId: string): void {
  const queue = read()
  if (!queue || queue.uid !== uid) return

  const next = queue.scanIds.filter((id) => id !== scanId)
  write(next.length > 0 ? { uid, scanIds: next } : null)
}

/**
 * Buang id yang sudah tidak ada di penyimpanan riwayat. Pemeriksaan dengan URL yang sama
 * menggantikan entri lamanya, dan entri bisa saja dihapus pengguna atau dipotong retensi;
 * tanpa langkah ini antrean akan terus menyimpan id yang tidak lagi punya salinan perangkat.
 */
export function retainPendingScans(uid: string, existingIds: string[]): void {
  const queue = read()
  if (!queue || queue.uid !== uid) return

  const remaining = new Set(existingIds)
  const next = queue.scanIds.filter((id) => remaining.has(id))
  write(next.length > 0 ? { uid, scanIds: next } : null)
}

export function clearPendingSync(): void {
  write(null)
}

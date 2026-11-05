export type LocalDemoSession = {
  kind: 'local-demo'
  displayName: string
  startedAt: string
}

export const SESSION_STORAGE_KEY = 'veriguard.local-session.v1'
export const DEFAULT_DISPLAY_NAME = 'Pengguna demo'
export const MAX_DISPLAY_NAME_LENGTH = 40

let memorySession: LocalDemoSession | null = null

function getStorage(): Storage | null {
  if (typeof window === 'undefined') return null

  try {
    const storage = window.localStorage
    const probe = '__veriguard_session_probe__'
    storage.setItem(probe, '1')
    storage.removeItem(probe)
    return storage
  } catch {
    return null
  }
}

function isLocalDemoSession(value: unknown): value is LocalDemoSession {
  if (!value || typeof value !== 'object') return false

  const session = value as Record<string, unknown>
  return (
    session.kind === 'local-demo' &&
    typeof session.displayName === 'string' &&
    session.displayName.length > 0 &&
    typeof session.startedAt === 'string' &&
    !Number.isNaN(Date.parse(session.startedAt))
  )
}

export function getLocalDemoSession(): LocalDemoSession | null {
  const storage = getStorage()
  if (!storage) return memorySession

  try {
    const raw = storage.getItem(SESSION_STORAGE_KEY)
    if (!raw) return null

    const parsed: unknown = JSON.parse(raw)
    if (!isLocalDemoSession(parsed)) return null

    memorySession = parsed
    return { ...parsed }
  } catch {
    return memorySession
  }
}

export function startLocalDemoSession(displayName: string): LocalDemoSession {
  const normalizedName =
    displayName.trim().slice(0, MAX_DISPLAY_NAME_LENGTH) || DEFAULT_DISPLAY_NAME

  const session: LocalDemoSession = {
    kind: 'local-demo',
    displayName: normalizedName,
    startedAt: new Date().toISOString(),
  }

  memorySession = session

  const storage = getStorage()
  if (storage) {
    try {
      storage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session))
    } catch {
      // Sesi demo tetap tersedia di memori selama tab ini terbuka.
    }
  }

  return { ...session }
}

export function endLocalDemoSession(): void {
  memorySession = null

  const storage = getStorage()
  if (storage) {
    try {
      storage.removeItem(SESSION_STORAGE_KEY)
    } catch {
      // Abaikan; sesi memori sudah diakhiri.
    }
  }
}

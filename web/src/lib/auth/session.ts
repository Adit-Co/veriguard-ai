import { getApp, getApps } from 'firebase/app'
import { getAuth, getIdToken } from 'firebase/auth'
import type { Auth, User } from 'firebase/auth'

// P1-2: backend VERIGUARD sendiri boleh mengenali akun yang sedang masuk, tetapi tidak boleh
// memaksa login. Karena itu header disisipkan HANYA bila ada sesi aktif; tanpa sesi permintaan
// berjalan sebagai tamu. Token dibaca segar dari SDK Auth (yang menangani refresh) dan tidak
// pernah disimpan di state UI, localStorage, maupun log.

export type AuthorizationDeps = {
  resolveAuth?: () => Auth | null
  readToken?: (user: User, forceRefresh: boolean) => Promise<string | null>
}

function currentAuth(): Auth | null {
  try {
    if (getApps().length === 0) return null
    return getAuth(getApp())
  } catch {
    // Konfigurasi belum lengkap (deployment tanpa kredensial): tanpa identitas.
    return null
  }
}

export async function authorizationHeader(
  deps: AuthorizationDeps = {},
  forceRefresh = false,
): Promise<Record<string, string>> {
  const auth = (deps.resolveAuth ?? currentAuth)()
  const user = auth?.currentUser
  if (!user) return {}

  const readToken = deps.readToken ?? ((target: User, refresh: boolean) => getIdToken(target, refresh))
  try {
    const token = await readToken(user, forceRefresh)
    if (!token) return {}
    return { Authorization: `Bearer ${token}` }
  } catch {
    return {}
  }
}

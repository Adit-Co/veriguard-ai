import { signInWithCustomToken, type User } from 'firebase/auth'
import { getFirebaseClient } from '../firebase/client'
import { authEmulatorUrl, firebaseConfigState, useFirebaseEmulators } from '../firebase/config'
import { getFirebaseErrorCode } from '../firebase/errors'

/**
 * Login demo LOKAL. Jalur ini hanya ada pada dev server dengan Emulator Firebase.
 * Kunci akun ('admin' | 'user') adalah satu-satunya yang dikirim ke server: alamat email
 * dan peran ditetapkan di sisi server (web/config/demoAccounts.ts + demoSessionPlugin.ts),
 * dan peran yang dipakai aplikasi dibaca kembali dari token yang diterbitkan layanan akun
 * serta dokumen allowlist di Firestore — tidak pernah dari klaim frontend.
 *
 * Berkas ini sengaja TIDAK mengimpor konfigurasi Node (web/config/demoAccounts.ts) supaya peta
 * akun demo tidak ikut terbundel ke peramban.
 */

export type DemoAccountKey = 'admin' | 'user'

export const DEMO_SESSION_ENDPOINT = '/__veriguard-demo/session'

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0'])

function isLoopbackEmulator(value: string): boolean {
  if (!value) return false
  try {
    const url = new URL(value)
    if (url.protocol !== 'http:') return false
    const host = url.hostname.toLowerCase()
    return (
      LOOPBACK_HOSTS.has(host) ||
      host.endsWith('.localhost') ||
      host.startsWith('127.')
    )
  } catch {
    return false
  }
}

export type DemoLoginAvailability = {
  available: boolean
  reason: string | null
}

/**
 * Default nonaktif. Tiga syarat teknis harus terpenuhi sekaligus: build pengembangan
 * (`import.meta.env.DEV` bernilai false pada build produksi), bendera dinyalakan eksplisit,
 * dan layanan akun benar-benar terhubung ke emulator loopback dengan konfigurasi lengkap.
 */
export function demoLoginAvailability(): DemoLoginAvailability {
  if (!import.meta.env.DEV) {
    return { available: false, reason: 'Build produksi tidak menyertakan login demo.' }
  }

  const flag = import.meta.env.VITE_ENABLE_DEMO_LOGIN?.toString().trim().toLowerCase()
  if (flag !== '1' && flag !== 'true') {
    return { available: false, reason: 'Login demo tidak diaktifkan.' }
  }

  if (!firebaseConfigState.configured) {
    return { available: false, reason: 'Konfigurasi layanan akun belum lengkap.' }
  }

  if (!useFirebaseEmulators || !isLoopbackEmulator(authEmulatorUrl)) {
    return {
      available: false,
      reason: 'Login demo hanya berjalan dengan Emulator Firebase pada host lokal.',
    }
  }

  return { available: true, reason: null }
}

export type DemoSessionResult = {
  user: User
  /** Klaim `admin` dibaca dari ID token yang diterbitkan server akun, bukan dari respons HTTP. */
  adminClaim: boolean
}

export class DemoLoginError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'DemoLoginError'
  }
}

async function requestDemoToken(account: DemoAccountKey): Promise<string> {
  let response: Response
  try {
    response = await fetch(DEMO_SESSION_ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ account }),
    })
  } catch {
    throw new DemoLoginError(
      'Layanan sesi demo tidak terjangkau. Jalankan dev server dan firebase emulators:start.',
    )
  }

  if (response.status === 404) {
    throw new DemoLoginError('Login demo tidak aktif pada lingkungan ini.')
  }

  let payload: unknown
  try {
    payload = (await response.json()) as unknown
  } catch {
    throw new DemoLoginError('Sesi demo gagal disiapkan.')
  }

  const record = (payload ?? {}) as Record<string, unknown>
  if (!response.ok) {
    throw new DemoLoginError(
      typeof record.error === 'string' ? record.error : 'Sesi demo gagal disiapkan.',
    )
  }

  if (typeof record.token !== 'string' || !record.token) {
    throw new DemoLoginError('Sesi demo tidak menerima token dari server.')
  }

  return record.token
}

function describeSignInFailure(error: unknown): string {
  const code = getFirebaseErrorCode(error)
  if (code === 'auth/invalid-custom-token' || code === 'auth/custom-token-mismatch') {
    return 'Token demo ditolak layanan akun. Pastikan emulator Firebase sedang berjalan.'
  }
  if (code === 'auth/network-request-failed') {
    return 'Emulator Firebase tidak dapat dihubungi dari peramban.'
  }
  return 'Login demo gagal. Peran tidak diberikan tanpa verifikasi server.'
}

/**
 * Masuk lewat token custom yang dicetak server. Peran dibaca dari klaim ID token yang baru
 * saja diterbitkan (hasil penukaran token di server akun), bukan dari respons HTTP.
 */
export async function signInWithDemoAccount(account: DemoAccountKey): Promise<DemoSessionResult> {
  const availability = demoLoginAvailability()
  if (!availability.available) {
    throw new DemoLoginError(availability.reason ?? 'Login demo tidak tersedia.')
  }

  const token = await requestDemoToken(account)
  const { auth } = getFirebaseClient()

  let credential: Awaited<ReturnType<typeof signInWithCustomToken>>
  try {
    credential = await signInWithCustomToken(auth, token)
  } catch (error) {
    throw new DemoLoginError(describeSignInFailure(error))
  }

  const user = credential.user
  await user.getIdToken(true)
  const claims = (await user.getIdTokenResult()).claims as Record<string, unknown>

  return { user, adminClaim: claims.admin === true }
}

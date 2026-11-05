import type { AuthContextValue } from './context'

export const VERIFICATION_EMAIL_PATH = '/verifikasi-email'
export const VERIFICATION_RESEND_COOLDOWN_SECONDS = 60
const MAX_ACTION_CODE_LENGTH = 2048

export const EMAIL_STATE_LABELS = {
  verified: 'Terverifikasi',
  unverified: 'Belum verifikasi email',
} as const

type VerificationAccount = {
  emailVerified: boolean
  isAnonymous: boolean
} | null

// Satu-satunya tafsir "akun penuh": sesi Firebase nyata yang email-nya sudah dikonfirmasi.
// Sesi anonim dan sesi demo lokal sengaja tidak dihitung.
export function isVerifiedAccount(user: VerificationAccount): boolean {
  return Boolean(user && !user.isAnonymous && user.emailVerified)
}

export function emailStateLabel(user: VerificationAccount): string {
  return user?.emailVerified ? EMAIL_STATE_LABELS.verified : EMAIL_STATE_LABELS.unverified
}

export type VerificationGate = 'allow' | 'redirect'

type GateInput = Pick<AuthContextValue, 'mode' | 'status' | 'user'>

// Keputusan gerbang dipisah dari komponen supaya bisa diuji tanpa merender halaman.
// Sumber kebenarannya emailVerified dari user Firebase Auth, bukan ada/tidaknya user
// dan bukan status yang dikirim klien.
export function verificationGate(auth: GateInput): VerificationGate {
  if (auth.mode !== 'firebase') return 'allow'
  if (auth.status === 'loading') return 'allow'

  const user = auth.user
  // Tamu (belum masuk atau sesi anonim) memang tidak punya email untuk diverifikasi,
  // jadi jalur publik tidak pernah dibendung di sini.
  if (!user || user.isAnonymous) return 'allow'

  // P2: kegagalan inisialisasi auth membuat emailVerified tidak dapat dipercaya lagi
  // (mis. token sesi dicabut atau onAuthStateChanged gagal). Selama masih ada akun,
  // gerbang menutup alih-alih memakai klaim verifikasi terakhir yang mungkin basi.
  if (auth.status !== 'ready') return 'redirect'

  return user.emailVerified ? 'allow' : 'redirect'
}

export type VerificationAction = {
  mode: string | null
  oobCode: string | null
  canApply: boolean
}

export function parseVerificationAction(search: string): VerificationAction {
  const params = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search)
  const mode = params.get('mode')
  const rawCode = params.get('oobCode')
  const oobCode = rawCode?.trim() || null
  const canApply =
    mode === 'verifyEmail' &&
    Boolean(oobCode) &&
    (oobCode?.length ?? 0) <= MAX_ACTION_CODE_LENGTH

  return { mode, oobCode, canApply }
}

export function remainingCooldownSeconds(availableAt: number, now = Date.now()): number {
  if (!Number.isFinite(availableAt) || availableAt <= now) return 0
  return Math.ceil((availableAt - now) / 1000)
}

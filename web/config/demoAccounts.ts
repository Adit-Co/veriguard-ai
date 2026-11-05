/**
 * Definisi akun demo LOKAL. Berkas ini hanya boleh dipakai oleh plugin dev-server
 * (sisi Node); tidak boleh diimpor dari kode yang ikut dibundel ke browser, karena
 * alamat email akun demo tidak boleh ada di artefak produksi.
 */

export type DemoAccountKey = 'admin' | 'user'

export type DemoAccount = {
  key: DemoAccountKey
  email: string
  displayName: string
  /** Peran ditetapkan di sini (sisi server), tidak pernah dibaca dari permintaan klien. */
  role: 'admin' | 'user'
}

export const DEMO_SESSION_PATH = '/__veriguard-demo/session'
/** Jalur baca untuk daftar identifikasi akun demo (digest, bukan alamat email). VGL-41E. */
export const DEMO_IDENTITIES_PATH = '/__veriguard-demo/identities'
export const DEMO_LOGIN_ENV_FLAG = 'VITE_ENABLE_DEMO_LOGIN'

/**
 * Bentuk pencocokan identitas akun demo. Sisi dev-server dan sisi peramban HARUS menormalkan
 * dengan cara yang sama; yang dibandingkan adalah digest-nya, jadi alamat email tidak pernah
 * keluar dari dev-server maupun masuk ke bundel.
 */
export function normalizeDemoEmail(email: string): string {
  return email.trim().toLowerCase()
}

export const DEMO_ACCOUNTS: Record<DemoAccountKey, DemoAccount> = {
  admin: {
    key: 'admin',
    email: 'aleksatya4@gmail.com',
    displayName: 'Admin Demo',
    role: 'admin',
  },
  user: {
    key: 'user',
    email: 'akusipemain@gmail.com',
    displayName: 'Pengguna Demo',
    role: 'user',
  },
}

/** Batas ukuran badan permintaan sesi demo; dipakai juga oleh middleware dev server. */
export const MAX_DEMO_REQUEST_BYTES = 2_048

export function demoAccountFor(value: unknown): DemoAccount | null {
  return value === 'admin' || value === 'user' ? DEMO_ACCOUNTS[value] : null
}

export type ParsedDemoRequest =
  | { account: DemoAccount }
  | { error: 'too-large' | 'invalid-json' | 'unknown-account' | 'unexpected-field' }

/**
 * Isi permintaan dibaca sebagai teks mentah supaya batas ukuran berlaku sebelum parsing,
 * dan satu-satunya bidang yang diterima adalah kunci akun. Email/peran dari klien tidak
 * pernah dipercaya, jadi mengirim `{ email: 'aleksatya4@gmail.com' }` tidak menghasilkan
 * akses admin apa pun.
 */
export function parseDemoSessionRequest(text: string): ParsedDemoRequest {
  if (text.length > MAX_DEMO_REQUEST_BYTES) return { error: 'too-large' }

  let payload: unknown
  try {
    payload = JSON.parse(text) as unknown
  } catch {
    return { error: 'invalid-json' }
  }

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { error: 'invalid-json' }
  }

  const fields = Object.keys(payload as Record<string, unknown>)
  if (fields.length !== 1 || fields[0] !== 'account') return { error: 'unexpected-field' }

  const account = demoAccountFor((payload as { account?: unknown }).account)
  return account ? { account } : { error: 'unknown-account' }
}

export type DemoRequestError = Extract<
  ParsedDemoRequest,
  { error: unknown }
>['error']

export function demoRequestErrorText(error: DemoRequestError): string {
  switch (error) {
    case 'too-large':
      return 'Permintaan sesi demo terlalu besar.'
    case 'invalid-json':
      return 'Permintaan sesi demo tidak dapat dibaca.'
    case 'unknown-account':
      return 'Akun demo tidak dikenal.'
    default:
      return 'Permintaan sesi demo hanya boleh berisi kunci akun.'
  }
}

/** Hanya URL loopback yang boleh dipakai sebagai alamat emulator di jalur demo. */
export function isLoopbackEmulatorUrl(value: string): boolean {
  if (!value) return false

  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    return false
  }

  if (parsed.protocol !== 'http:') return false
  const host = parsed.hostname.toLowerCase()
  return (
    host === 'localhost' ||
    host === '::1' ||
    host === '[::1]' ||
    host.endsWith('.localhost') ||
    host.startsWith('127.')
  )
}

/**
 * Token custom untuk EMULATOR Auth saja: emulator menerima JSON tegas berisi uid
 * (firebase-tools, auth/operations.js:1008-1040). Peran TIDAK ada di token ini; ia dibaca
 * emulator dari customAttributes akun yang ditulis lewat jalur istimewa, sehingga klaim
 * admin berasal dari keadaan akun di server, bukan dari yang dikirim klien.
 * Token semacam ini tidak akan pernah diterima produksi, yang mewajibkan JWT bertanda
 * tangan service account proyek.
 */
export function emulatorCustomToken(uid: string): string {
  return JSON.stringify({ uid })
}

export type DemoLoginGate = {
  available: boolean
  reasons: string[]
}

/**
 * Pagar login demo. Semua syarat harus terpenuhi; default-nya NONAKTIF. Pemeriksaan
 * NODE_ENV=production membuat fitur ini mustahil aktif pada build produksi meskipun
 * bendera env ikut ter-set.
 */
export function demoLoginAvailability(
  env: Record<string, string | undefined>,
  nodeEnv: string | undefined = process.env.NODE_ENV,
): DemoLoginGate {
  const reasons: string[] = []

  const flag = env[DEMO_LOGIN_ENV_FLAG]?.trim().toLowerCase()
  if (flag !== '1' && flag !== 'true') {
    reasons.push(`${DEMO_LOGIN_ENV_FLAG} tidak diaktifkan (default nonaktif).`)
  }

  if (nodeEnv === 'production' || env.NODE_ENV?.trim() === 'production') {
    reasons.push('Login demo tidak diizinkan pada NODE_ENV=production.')
  }

  const emulators = env.VITE_USE_EMULATORS?.trim().toLowerCase()
  if (emulators !== 'true') {
    reasons.push('Emulator Firebase tidak diaktifkan (VITE_USE_EMULATORS).')
  }

  if (!isLoopbackEmulatorUrl(env.VITE_AUTH_EMULATOR_URL?.trim() ?? '')) {
    reasons.push('VITE_AUTH_EMULATOR_URL harus URL http pada host loopback.')
  }

  if (!env.VITE_FIRESTORE_EMULATOR_HOST?.trim()) {
    reasons.push('VITE_FIRESTORE_EMULATOR_HOST belum diisi.')
  }

  if (!env.VITE_FIREBASE_PROJECT_ID?.trim()) {
    reasons.push('VITE_FIREBASE_PROJECT_ID belum diisi.')
  }

  if (!env.VITE_FIREBASE_API_KEY?.trim()) {
    reasons.push('VITE_FIREBASE_API_KEY belum diisi.')
  }

  return { available: reasons.length === 0, reasons }
}

import { getFirebaseErrorCode } from '../firebase/errors'
import { configuredApiBase } from '../scanners/client'

// VGL-38 — klien gerbang cooldown login.
// VGL-39A — setiap tingkat memberi tepat 3 kesempatan; kegagalan ke-1 dan ke-2 hanya
// mengurangi kesempatan, kegagalan ke-3 yang mengaktifkan cooldown.
//
// APA YANG DITEGAKKAN DARI SINI
// Keputusan cooldown diminta ke gerbang SEBELUM kredensial dikirim ke Firebase, dan hasilnya
// dilaporkan setelah Firebase menjawab. Ketika server lokal reachable, SERVER yang menentukan
// (jam server + penyimpanan persisten). Ketika tidak reachable, keadaan lokal dipakai sebagai
// cermin agar UI tetap mengunci sumber ini. Cermin localStorage BUKAN sumber kebenaran: ia hanya
// lapisan cadangan, dan permintaan berikutnya tetap ditolak oleh gerbang begitu server hidup
// lagi. Klien ini tidak bisa menghentikan panggilan langsung ke identitytoolkit.googleapis.com
// karena aplikasi memakai Firebase Auth dari browser; celah itu dilaporkan terpisah.

export const LOGIN_CLIENT_ID_STORAGE_KEY = 'veriguard.login-client.v1'
// .v2 (VGL-39A): bentuk cermin berubah — `failures` sekarang hitungan dalam siklus berjalan,
// bukan lagi jumlah kegagalan total. Cermin lama dibuang, tidak ditafsirkan ulang.
export const LOGIN_COOLDOWN_STORAGE_KEY = 'veriguard.login-cooldown.v2'

/** Sama seperti LOGIN_GUARD_ATTEMPTS_PER_LEVEL di gerbang server. */
export const LOGIN_GUARD_ATTEMPTS_PER_LEVEL = 3

export type LoginGuardOutcome = 'credential-failure' | 'success' | 'network' | 'rate-limited'

export type LoginGuardCooldown = {
  active: boolean
  retryAfterMs: number
  level: number
  failures: number
  /** Kesempatan yang masih ada pada tingkat berjalan (0 saat cooldown aktif). */
  attemptsLeft: number
  attemptsPerLevel: number
  // Sumber keputusan: 'server' = gerbang lokal menjawab, 'local' = cermin saat server tidak
  // terjangkau, 'none' = tidak ada keadaan cooldown.
  authority: 'server' | 'local' | 'none'
}

export type LoginGuardHandle = {
  // Token reservasi dari server. Null bila keputusan datang dari cermin lokal.
  token: string | null
}

/**
 * Dilempar ketika gerbang menolak. Kelasnya dipakai LoginPage untuk menampilkan panel cooldown
 * tanpa menganggap penolakan itu sebagai "email atau kata sandi salah".
 */
export class LoginCooldownError extends Error {
  readonly retryAfterMs: number
  readonly level: number

  constructor(retryAfterMs: number, level: number) {
    super('Terlalu banyak percobaan login dari sumber ini. Silakan tunggu sebelum mencoba kembali.')
    this.name = 'LoginCooldownError'
    this.retryAfterMs = retryAfterMs
    this.level = level
  }
}

type GateDecisionBody = {
  allowed?: boolean
  active?: boolean
  reason?: string
  retryAfterMs?: number
  level?: number
  failures?: number
  attemptsLeft?: number
  attemptsPerLevel?: number
  serverTime?: number
  token?: string | null
}

const IDLE_COOLDOWN: LoginGuardCooldown = {
  active: false,
  retryAfterMs: 0,
  level: 0,
  failures: 0,
  attemptsLeft: LOGIN_GUARD_ATTEMPTS_PER_LEVEL,
  attemptsPerLevel: LOGIN_GUARD_ATTEMPTS_PER_LEVEL,
  authority: 'none',
}

const GATE_TIMEOUT_MS = 2_500
// Status yang berarti "endpoint gerbang tidak ada/tidak dapat dipakai pada deployment ini".
const ABSENT_GATE_STATUS = new Set([404, 405, 410, 500, 502, 503, 504])
// Tingkat maksimum tangga adalah 24 jam; nilai yang jauh lebih besar berarti cermin tidak bisa
// dipercaya (jam lokal melompat atau berkas dirusak) dan lebih baik dibuang.
const MIRROR_MAX_WINDOW_MS = 36 * 60 * 60_000
// Sama seperti LOGIN_GUARD_HISTORY_TTL_MS di gerbang: riwayat kegagalan tidak tersimpan selamanya,
// tetapi tetap diingat sampai cooldown-nya tuntas agar tangga tidak jatuh ke tingkat 1.
export const LOGIN_GUARD_MIRROR_HISTORY_MS = 24 * 60 * 60_000
const CLIENT_ID_PATTERN = /^[A-Za-z0-9_-]{8,64}$/

type Mirror = {
  endsAt: number
  writtenAt: number
  level: number
  failures: number
}

/**
 * VGL-41C: sama seperti gerbang server, kesempatan 0 hanya ada selama cooldown berjalan.
 * Kegagalan ke-3 pada cermin selalu ditutup cooldown lalu direset, jadi angka >= 3 pada keadaan
 * bebas berasal dari cermin versi lama dan tidak boleh ditampilkan sebagai "kesempatan habis".
 */
function attemptsLeftFrom(failures: number): number {
  if (failures >= LOGIN_GUARD_ATTEMPTS_PER_LEVEL) return LOGIN_GUARD_ATTEMPTS_PER_LEVEL
  return Math.max(1, LOGIN_GUARD_ATTEMPTS_PER_LEVEL - failures)
}

function storage(): Storage | null {
  if (typeof window === 'undefined') return null
  try {
    const store = window.localStorage
    const probe = '__veriguard_login_guard_probe__'
    store.setItem(probe, '1')
    store.removeItem(probe)
    return store
  } catch {
    return null
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function finite(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : fallback
}

/**
 * Pengenal sumber per perangkat. Bukan bukti identitas: bisa dipalsukan atau dihapus, karena itu
 * gerbang selalu menggabungkannya dengan IP dan tetap membatasi klien tanpa pengenal.
 */
export function loginClientId(): string {
  const store = storage()
  const existing = store?.getItem(LOGIN_CLIENT_ID_STORAGE_KEY)
  if (existing && CLIENT_ID_PATTERN.test(existing)) return existing

  const bytes = new Uint8Array(16)
  if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(bytes)
  else for (let index = 0; index < bytes.length; index += 1) bytes[index] = Math.floor(Math.random() * 256)

  const generated = `web-${Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')}`
  store?.setItem(LOGIN_CLIENT_ID_STORAGE_KEY, generated)
  return generated
}

function readMirror(now: number): Mirror | null {
  const raw = storage()?.getItem(LOGIN_COOLDOWN_STORAGE_KEY)
  if (!raw) return null

  try {
    const parsed: unknown = JSON.parse(raw)
    if (!isRecord(parsed)) return null
    const mirror: Mirror = {
      endsAt: finite(parsed.endsAt),
      writtenAt: finite(parsed.writtenAt),
      level: finite(parsed.level),
      failures: finite(parsed.failures),
    }
    if (!mirror.writtenAt || mirror.endsAt - now > MIRROR_MAX_WINDOW_MS) {
      // writtenAt saja yang wajib ada: cermin juga menyimpan sisa kesempatan TANPA cooldown
      // aktif (endsAt = waktu tulisan), dan itu keadaan yang sah.
      storage()?.removeItem(LOGIN_COOLDOWN_STORAGE_KEY)
      return null
    }
    // Riwayat dibuang setelah cooldown tuntas DAN tidak ada aktivitas selama MIRROR_HISTORY_MS.
    // Selama cooldown masih berjalan, angka kegagalan harus bertahan.
    const lastEvent = Math.max(mirror.writtenAt, mirror.endsAt)
    if (mirror.endsAt <= now && lastEvent + LOGIN_GUARD_MIRROR_HISTORY_MS <= now) {
      storage()?.removeItem(LOGIN_COOLDOWN_STORAGE_KEY)
      return null
    }
    return mirror
  } catch {
    storage()?.removeItem(LOGIN_COOLDOWN_STORAGE_KEY)
    return null
  }
}

/**
 * Sisa waktu cermin. Cermin disimpan sebagai "berakhir pada jam server", jadi memundurkan jam
 * lokal hanya membuat cooldown terlihat lebih panjang, tidak pernah lebih pendek. Maju jauh hanya
 * berpengaruh pada lapisan cadangan; gerbang server tetap penentu begitu reachable.
 */
function mirrorCooldown(now: number): LoginGuardCooldown {
  const mirror = readMirror(now)
  if (!mirror) return { ...IDLE_COOLDOWN, authority: 'local' }

  const remaining = mirror.endsAt - now
  if (remaining <= 0) {
    // Cooldown selesai tapi riwayat masih dikenal: sumber bebas mencoba lagi dengan 3 kesempatan
    // baru, dan kegagalan berikutnya melanjutkan tangga, bukan mulai dari nol.
    return {
      ...IDLE_COOLDOWN,
      level: mirror.level,
      failures: mirror.failures,
      attemptsLeft: attemptsLeftFrom(mirror.failures),
      authority: 'local',
    }
  }

  return {
    active: true,
    retryAfterMs: remaining,
    level: mirror.level,
    failures: mirror.failures,
    attemptsLeft: 0,
    attemptsPerLevel: LOGIN_GUARD_ATTEMPTS_PER_LEVEL,
    authority: 'local',
  }
}

function writeMirror(
  input: {
    retryAfterMs: number
    level: number
    failures: number
    serverTime?: number
  },
  now: number,
): void {
  const serverTime = finite(input.serverTime)
  const anchor = serverTime > 0 ? serverTime : now
  if (input.retryAfterMs <= 0 && input.level === 0 && input.failures === 0) {
    // Keadaan benar-benar bersih: tidak ada yang perlu dicadangkan.
    storage()?.removeItem(LOGIN_COOLDOWN_STORAGE_KEY)
    return
  }
  const mirror: Mirror = {
    endsAt: anchor + Math.max(0, input.retryAfterMs),
    writtenAt: anchor,
    level: input.level,
    failures: input.failures,
  }
  try {
    storage()?.setItem(LOGIN_COOLDOWN_STORAGE_KEY, JSON.stringify(mirror))
  } catch {
    // Penyimpanan penuh/diblokir: lapisan cadangan hilang, gerbang server tetap bekerja.
  }
}

export function clearLoginGuardLocalState(): void {
  const store = storage()
  if (!store) return
  store.removeItem(LOGIN_COOLDOWN_STORAGE_KEY)
  store.removeItem(LOGIN_CLIENT_ID_STORAGE_KEY)
}

export type LoginGuardOptions = {
  apiBase?: string
  now?: () => number
  fetchImpl?: typeof fetch
}

type ResolvedOptions = {
  apiBase: string | undefined
  now: () => number
  fetchImpl: typeof fetch
}

function resolveOptions(options: LoginGuardOptions): ResolvedOptions {
  return {
    apiBase: options.apiBase ?? configuredApiBase(),
    now: options.now ?? Date.now,
    fetchImpl: options.fetchImpl ?? fetch,
  }
}

function gateEndpoint(apiBase: string, name: 'acquire' | 'report' | 'status'): string {
  const trimmed = apiBase.trim().replace(/\/+$/, '')
  return `${trimmed}/auth/login/gate/${name}`
}

function postGate(
  fetchImpl: typeof fetch,
  apiBase: string,
  name: 'acquire' | 'report',
  payload: Record<string, unknown>,
  signal?: AbortSignal,
): Promise<Response> {
  return fetchImpl(gateEndpoint(apiBase, name), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
    ...(signal ? { signal } : {}),
  })
}

function decisionCooldown(body: GateDecisionBody): LoginGuardCooldown {
  const retryAfterMs = finite(body.retryAfterMs)
  const failures = finite(body.failures)
  return {
    active: retryAfterMs > 0,
    retryAfterMs,
    level: finite(body.level),
    failures,
    // Jawaban server yang berisi `attemptsLeft` dipakai apa adanya; bila gerbang lebih tua dan
    // tidak mengirimnya, hitung dari sisa kesempatan tingkat berjalan.
    attemptsLeft: retryAfterMs > 0 ? 0 : finite(body.attemptsLeft, attemptsLeftFrom(failures)),
    attemptsPerLevel: finite(body.attemptsPerLevel, LOGIN_GUARD_ATTEMPTS_PER_LEVEL),
    authority: 'server',
  }
}

/**
 * Sebelum kredensial dikirim: minta izin ke gerbang. Jawaban server selalu menimpa cermin lokal.
 * Bila gerbang tidak terjangkau, keputusan diambil dari cermin (fallback) dan percobaan tetap
 * boleh dilanjutkan — kegagalan memanggil gerbang bukan kegagalan autentikasi.
 */
export async function acquireLoginAttempt(
  email: string,
  options: LoginGuardOptions = {},
): Promise<{ handle: LoginGuardHandle; cooldown: LoginGuardCooldown }> {
  const { apiBase, now, fetchImpl } = resolveOptions(options)
  const clientId = loginClientId()

  if (!apiBase) {
    const cooldown = mirrorCooldown(now())
    return { handle: { token: null }, cooldown }
  }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), GATE_TIMEOUT_MS)
  try {
    const response = await postGate(
      fetchImpl,
      apiBase,
      'acquire',
      { clientId, ...(email.trim() ? { email: email.trim() } : {}) },
      controller.signal,
    )
    const body = (await response.json().catch(() => null)) as GateDecisionBody | null

    if (response.status === 429 && isRecord(body)) {
      const cooldown = decisionCooldown(body)
      writeMirror(
        {
          retryAfterMs: cooldown.retryAfterMs,
          level: cooldown.level,
          failures: cooldown.failures,
          serverTime: finite(body.serverTime),
        },
        now(),
      )
      return { handle: { token: null }, cooldown }
    }

    if (response.ok && isRecord(body) && body.allowed === true) {
      // Server menyatakan sumber ini boleh mencoba: cermin mengikuti keadaan sumber itu,
      // termasuk sisa kesempatan pada tingkat berjalan.
      const cooldown = decisionCooldown(body)
      writeMirror(
        {
          retryAfterMs: 0,
          level: cooldown.level,
          failures: cooldown.failures,
          serverTime: finite(body.serverTime),
        },
        now(),
      )
      return {
        handle: { token: typeof body.token === 'string' ? body.token : null },
        cooldown: { ...cooldown, active: false, retryAfterMs: 0 },
      }
    }

    const cooldown = mirrorCooldown(now())
    return { handle: { token: null }, cooldown }
  } catch {
    const cooldown = mirrorCooldown(now())
    return { handle: { token: null }, cooldown }
  } finally {
    clearTimeout(timer)
  }
}

/** Laporkan hasil ke gerbang. Kegagalan laporan tidak boleh menggagalkan alur login di UI. */
export async function reportLoginAttempt(
  handle: LoginGuardHandle,
  email: string,
  outcome: LoginGuardOutcome,
  options: LoginGuardOptions = {},
): Promise<void> {
  const { apiBase, now, fetchImpl } = resolveOptions(options)

  // Cermin dipakai ketika gerbang benar-benar tidak menjawab: tanpa pengenal API, permintaan
  // gagal di lapisan jaringan, atau endpoint tidak ada pada deployment yang lebih tua.
  const applyLocalFallback = (): void => {
    if (outcome === 'credential-failure') {
      const next = bumpLocalMirror(now())
      writeMirror({ retryAfterMs: next.retryAfterMs, level: next.level, failures: next.failures }, now())
    } else if (outcome === 'success') {
      writeMirror({ retryAfterMs: 0, level: 0, failures: 0 }, now())
    }
  }

  if (!apiBase) {
    applyLocalFallback()
    return
  }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), GATE_TIMEOUT_MS)
  try {
    const response = await postGate(
      fetchImpl,
      apiBase,
      'report',
      {
        clientId: loginClientId(),
        ...(email.trim() ? { email: email.trim() } : {}),
        outcome,
        ...(handle.token ? { token: handle.token } : {}),
      },
      controller.signal,
    )
    if (!response.ok) {
      // 404/405/410 = endpoint gerbang tidak ada di deployment ini; 5xx = gerbang tidak
      // dapat dipakai. Tanpa cabang ini, kegagalan kredensial di deployment semacam itu
      // tidak pernah menaikkan tingkat sama sekali (bukan di server, bukan di cermin).
      // 400/403/413/415 dibiarkan: gerbang ada dan menolak permintaan itu, jadi cermin
      // tidak boleh mengarang keadaan.
      if (ABSENT_GATE_STATUS.has(response.status)) applyLocalFallback()
      return
    }
    const body = (await response.json().catch(() => null)) as GateDecisionBody | null
    if (!isRecord(body)) return

    const cooldown = decisionCooldown(body)
    if (outcome === 'credential-failure') {
      // Cermin selalu disinkronkan dengan keadaan sumber yang dilaporkan server, termasuk saat
      // belum ada cooldown (kesempatan berkurang). Tanpa ini, refresh saat gerbang hilang akan
      // mengembalikan 3 kesempatan penuh.
      writeMirror(
        {
          retryAfterMs: cooldown.retryAfterMs,
          level: cooldown.level,
          failures: cooldown.failures,
          serverTime: finite(body.serverTime),
        },
        now(),
      )
    } else if (outcome === 'success') {
      // Login berhasil: bersihkan cermin sumber ini.
      writeMirror({ retryAfterMs: 0, level: 0, failures: 0 }, now())
    }
  } catch {
    // Server menyimpan cooldown-nya sendiri; cermin hanya cadangan.
  } finally {
    clearTimeout(timer)
  }
}

// Tangga yang sama dengan gerbang server, dipakai hanya ketika server tidak terjangkau sehingga
// cermin tidak mulai dari nol setiap kegagalan. Indeks = tingkat (0 = "Awal" 2 menit).
const LOCAL_STEPS_MS = [120_000, 3_600_000, 10_800_000, 21_600_000, 43_200_000, 86_400_000]

/**
 * VGL-39A pada lapisan cadangan: sama seperti gerbang, kegagalan ke-1 dan ke-2 hanya mengurangi
 * kesempatan; hanya kegagalan ke-3 yang mengaktifkan cooldown tingkat itu lalu menaikkan tingkat.
 */
function bumpLocalMirror(now: number): {
  retryAfterMs: number
  level: number
  failures: number
} {
  const current = readMirror(now)
  const level = current?.level ?? 0
  const failures = (current?.failures ?? 0) + 1

  if (failures < LOGIN_GUARD_ATTEMPTS_PER_LEVEL) {
    return { retryAfterMs: 0, level, failures }
  }

  const step = LOCAL_STEPS_MS[Math.min(level, LOCAL_STEPS_MS.length - 1)]
  return { retryAfterMs: step, level: level + 1, failures: 0 }
}


/**
 * Cooldown aktif untuk UI. Sumber kebenaran: gerbang bila reachable, cermin bila tidak.
 * Jawaban "tidak aktif" dari server menggantikan cermin dengan keadaan sumber yang sebenarnya
 * (termasuk sisa kesempatan), jadi tombol aktif lagi tepat setelah cooldown server selesai.
 */
export async function readLoginCooldown(
  options: LoginGuardOptions = {},
): Promise<LoginGuardCooldown> {
  const { apiBase, now, fetchImpl } = resolveOptions(options)
  const local = mirrorCooldown(now())

  if (!apiBase) return local

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), GATE_TIMEOUT_MS)
  try {
    const response = await fetchImpl(
      `${gateEndpoint(apiBase, 'status')}?clientId=${encodeURIComponent(loginClientId())}`,
      { method: 'GET', signal: controller.signal },
    )
    if (!response.ok) return local
    const body = (await response.json().catch(() => null)) as GateDecisionBody | null
    if (!isRecord(body)) return local

    const retryAfterMs = finite(body.retryAfterMs)
    if (body.active === true && retryAfterMs > 0) {
      writeMirror(
        {
          retryAfterMs,
          level: finite(body.level),
          failures: finite(body.failures),
          serverTime: finite(body.serverTime),
        },
        now(),
      )
      return decisionCooldown(body)
    }

    // Server tidak menahan sumber ini: cermin mengikuti angka server, bukan menahan sendiri.
    const cooldown = decisionCooldown({ ...body, retryAfterMs: 0 })
    writeMirror(
      { retryAfterMs: 0, level: cooldown.level, failures: cooldown.failures, serverTime: finite(body.serverTime) },
      now(),
    )
    return cooldown
  } catch {
    return local
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Klasifikasi error Firebase menjadi outcome gerbang. Validasi bentuk dan gangguan layanan TIDAK
 * dihitung sebagai password salah; hanya kegagalan kredensial yang menaikkan tingkat cooldown.
 */
const CREDENTIAL_CODES = new Set([
  'auth/invalid-credential',
  'auth/user-not-found',
  'auth/wrong-password',
  'auth/invalid-login-credentials',
])

const NETWORK_CODES = new Set([
  'auth/network-request-failed',
  'auth/admin-restricted-operation',
  'auth/operation-not-allowed',
  'auth/user-disabled',
  'auth/internal-error',
  'auth/unexpected-response',
  'auth/argument-error',
])

export function classifyLoginError(error: unknown): LoginGuardOutcome {
  const code = getFirebaseErrorCode(error)
  if (code && CREDENTIAL_CODES.has(code)) return 'credential-failure'
  if (code === 'auth/too-many-requests') return 'rate-limited'
  if (code && NETWORK_CODES.has(code)) return 'network'
  // Tanpa kode: gangguan layanan/unknown. Lebih aman tidak menghitungnya sebagai password salah;
  // penyerang yang mengulang kegagalan semacam ini tidak pernah naik tingkat.
  return 'network'
}

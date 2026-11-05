import { createHmac, randomBytes } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'

// VGL-38 — gerbang cooldown login progresif.
// VGL-39A — setiap tingkat memberi TEPAT 3 kesempatan: kegagalan ke-1 dan ke-2 hanya
// mengurangi kesempatan; kegagalan ke-3 baru mengaktifkan cooldown tingkat itu.
//
// TEMPAT GERBANG INI BERADA DAN BATAS JUJURNYA
// Aplikasi memanggil Firebase Auth LANGSUNG dari browser
// (web/src/lib/firebase/auth.ts -> signInWithEmailAndPassword), jadi tidak ada backend
// VERIGUARD yang berada di jalur autentikasi sebenarnya. Gerbang di berkas ini adalah otoritas
// cooldown yang dapat ditegakkan secara lokal: jam server, penyimpanan persisten, dan keputusan
// yang diambil SEBELUM percobaan dikirim. Gerbang ini membatasi klien yang memakai aplikasi dan
// permintaan langsung ke endpoint ini, tetapi TIDAK dapat menghentikan penyerang yang memanggil
// identitytoolkit.googleapis.com dengan API key publik. Celah itu butuh perubahan batas
// autentikasi (verifikasi kredensial di server) dan sengaja tidak disimulasikan di sini.
//
// KEBIJAKAN (VGL-39A)
//   3 kegagalan pada tingkat N -> cooldown steps[N], lalu tingkat naik
//   Awal 2 menit · T1 1 jam · T2 3 jam · T3 6 jam · T4 12 jam · T5 dan seterusnya 24 jam
// Setelah cooldown berakhir sumber memperoleh 3 kesempatan BARU tanpa menghapus tingkat.
// Login berhasil mengembalikan tingkat ke awal. Percobaan saat cooldown berlangsung ditolak
// tanpa mengurangi kesempatan dan tanpa menaikkan tingkat.
// Riwayat kegagalan kedaluwarsa setelah HISTORY_TTL_MS tanpa aktivitas, sehingga keadaan tidak
// menumpuk selamanya.

export const LOGIN_COOLDOWN_STEPS_MS = [
  2 * 60_000, // 2 menit
  60 * 60_000, // 1 jam
  3 * 60 * 60_000, // 3 jam
  6 * 60 * 60_000, // 6 jam
  12 * 60 * 60_000, // 12 jam
  24 * 60 * 60_000, // 24 jam (maksimum)
] as const

/** VGL-39A — kesempatan login per tingkat sebelum cooldown tingkat itu berlaku. */
export const LOGIN_GUARD_ATTEMPTS_PER_LEVEL = 3

/** Riwayat kegagalan dibuang bila tidak ada aktivitas selama ini DAN cooldown sudah habis. */
export const LOGIN_GUARD_HISTORY_TTL_MS = 24 * 60 * 60_000

/**
 * Lapisan jaringan (per IP) sengaja TIDAK memakai tangga penuh untuk klien ber-identifier.
 * Satu IP bersama (kafe, asrama, CGNAT) dipakai banyak pengguna sah; tanpa batas proporsional,
 * satu penyerang mengunci seluruh jaringan. Lapisan ini baru bergerak setelah IP_THRESHOLD
 * kegagalan dan durasinya dibatasi IP_COOLDOWN_MS.
 */
export const LOGIN_GUARD_IP_THRESHOLD = 8
export const LOGIN_GUARD_IP_COOLDOWN_MS = 2 * 60_000

/** Percobaan paralel per sumber: mencegah satu sumber mengirim banyak percobaan sekaligus. */
export const LOGIN_GUARD_MAX_INFLIGHT = 2
export const LOGIN_GUARD_RESERVATION_TTL_MS = 30_000

/** Sama seperti struktur keadaan lain di proyek: tabel penuh menolak kunci BARU, bukan mengusir entri hidup. */
export const LOGIN_GUARD_MAX_BUCKETS = 5_000

export const LOGIN_GUARD_MAX_BODY_BYTES = 8_192

export const LOGIN_GUARD_ACQUIRE_PATH = '/auth/login/gate/acquire'
export const LOGIN_GUARD_REPORT_PATH = '/auth/login/gate/report'
export const LOGIN_GUARD_STATUS_PATH = '/auth/login/gate/status'

const LOGIN_GUARD_PATHS = new Set([
  LOGIN_GUARD_ACQUIRE_PATH,
  LOGIN_GUARD_REPORT_PATH,
  LOGIN_GUARD_STATUS_PATH,
])

export type LoginGuardOutcome = 'credential-failure' | 'success' | 'network' | 'rate-limited'

export type LoginGuardSource = {
  ip: string
  clientId: string | null
  email: string | null
}

export type LoginGuardDecision = {
  allowed: boolean
  reason: 'granted' | 'cooldown' | 'network-cooldown' | 'busy' | 'full'
  retryAfterMs: number
  level: number
  failures: number
  attemptsLeft: number
  attemptsPerLevel: number
  serverTime: number
  token: string | null
}

export type LoginGuardReport = {
  counted: boolean
  level: number
  failures: number
  attemptsLeft: number
  attemptsPerLevel: number
  retryAfterMs: number
  serverTime: number
}

export type LoginGuardStatus = {
  active: boolean
  retryAfterMs: number
  level: number
  failures: number
  attemptsLeft: number
  attemptsPerLevel: number
  serverTime: number
}

/** Bentuk yang sama dipakai untuk bucket sumber maupun bucket IP, agar satu referensi cukup. */
type Bucket = {
  /** VGL-39A — tingkat cooldown saat ini (0 = awal). Hanya naik setelah 3 kegagalan. */
  level: number
  /** Kegagalan pada tingkat berjalan (0..ATTEMPTS_PER_LEVEL). Ini yang mengurangi kesempatan. */
  failures: number
  /** Jumlah kegagalan sejak riwayat terbentuk; dipakai ambang IP yang harus tetap monotonic. */
  total: number
  cooldownUntil: number
  updatedAt: number
  inflight: number
}

/**
 * Deteksi serangan terarah. SENGAJA tidak pernah menolak berdasarkan kunci ini: menolak
 * berdasarkan email = mengunci akun korban secara global, dan itu dilarang VGL-38.
 */
type AccountState = {
  failures: number
  sources: string[]
  updatedAt: number
}

type Reservation = { bucketKey: string; expiresAt: number }

export type LoginGuardStore = {
  acquire(source: Partial<LoginGuardSource>, now?: number): LoginGuardDecision
  report(
    source: Partial<LoginGuardSource>,
    outcome: LoginGuardOutcome,
    token: string | null,
    now?: number,
  ): LoginGuardReport
  status(source: Partial<LoginGuardSource>, now?: number): LoginGuardStatus
  stats(): { sources: number; ips: number; accounts: number }
  reset(): void
}

/**
 * Durasi cooldown untuk tingkat `level`. `level` adalah indeks 0-based pada tangga: 0 = "Awal"
 * (2 menit), 1 = tingkat 1 (1 jam), dan seterusnya. Tingkat di atas ujung tangga dipatok 24 jam.
 * VGL-39A: tingkat hanya naik setelah TEPAT {@link LOGIN_GUARD_ATTEMPTS_PER_LEVEL} kegagalan.
 */
export function cooldownMsForLevel(level: number): number {
  const index = Math.min(Math.max(Math.trunc(level), 0), LOGIN_COOLDOWN_STEPS_MS.length - 1)
  return LOGIN_COOLDOWN_STEPS_MS[index]
}

/**
 * Sisa kesempatan tingkat berjalan. Sumber yang sedang terkunci tidak punya kesempatan.
 *
 * VGL-41C: angka 0 hanya sah bila cooldown masih berjalan. Kegagalan ke-3 selalu menutup
 * siklus dengan cooldown dan mereset `failures`, jadi "0 kesempatan tanpa cooldown" bukan
 * keadaan yang bisa dihasilkan kebijakan ini — bila terbaca begitu (berkas lama/tercemar),
 * sumber itu diperlakukan masih punya satu kesempatan agar angka UI tidak bertentangan dengan
 * gerbang yang justru mengizinkan percobaan berikutnya.
 */
function attemptsLeftFor(bucket: Bucket | null | undefined, now: number): number {
  if (!bucket) return LOGIN_GUARD_ATTEMPTS_PER_LEVEL
  if (bucket.cooldownUntil > now) return 0
  return Math.min(LOGIN_GUARD_ATTEMPTS_PER_LEVEL, Math.max(1, LOGIN_GUARD_ATTEMPTS_PER_LEVEL - bucket.failures))
}

function reportedLevel(bucket: Bucket | null | undefined): number {
  return Math.min(Math.max(bucket?.level ?? 0, 0), LOGIN_COOLDOWN_STEPS_MS.length)
}

function normalizeEmail(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim().toLowerCase()
  if (!trimmed || trimmed.length > 320 || !trimmed.includes('@')) return null
  return trimmed
}

function normalizeClientId(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(trimmed)) return null
  return trimmed
}

function normalizeIp(value: unknown): string {
  if (typeof value !== 'string') return 'unknown'
  const trimmed = value.trim()
  return trimmed || 'unknown'
}

function sanitizeNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? Math.max(0, Math.trunc(value)) : fallback
}

export type LoginGuardStoreOptions = {
  /** Berkas keadaan. `null` = hanya di memori (dipakai unit test). */
  stateFile?: string | null
  now?: () => number
}

const FILE_VERSION = 2

/** Versi berkas yang masih boleh dibaca. v1 = VGL-38 (1 kegagalan = 1 tingkat). */
const SUPPORTED_FILE_VERSIONS = new Set([1, FILE_VERSION])

type PersistedFile = {
  version: number
  secret: string
  sources: Record<string, unknown>
  ips: Record<string, unknown>
  accounts: Record<string, unknown>
}

function emptyFile(secret: string): PersistedFile {
  return { version: FILE_VERSION, secret, sources: {}, ips: {}, accounts: {} }
}

function readStateFile(file: string): PersistedFile | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as unknown
    if (!isRecord(parsed)) return null
    if (!SUPPORTED_FILE_VERSIONS.has(Number(parsed.version)) || typeof parsed.secret !== 'string') return null
    return {
      version: Number(parsed.version),
      secret: parsed.secret,
      sources: isRecord(parsed.sources) ? parsed.sources : {},
      ips: isRecord(parsed.ips) ? parsed.ips : {},
      accounts: isRecord(parsed.accounts) ? parsed.accounts : {},
    }
  } catch {
    return null
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

/**
 * v1 -> v2 (VGL-39B). Berkas v1 ditulis kebijakan lama "1 kegagalan = 1 tingkat", jadi angkanya
 * adalah tingkat, bukan kegagalan dalam satu siklus, dan cooldown yang menyertainya bisa berupa
 * durasi yang tidak pernah lagi diizinkan kebijakan sekarang (misalnya 3 jam dari 3 kegagalan,
 * padahal 3 kegagalan baru naik dari tingkat 0 ke tingkat 1).
 *
 * Pemetaan dilakukan terhadap SEMANTIK baru: setiap 3 kegagalan lama dihitung sebagai satu siklus
 * selesai (tingkat naik satu, sisa kegagalan dibawa sebagai kegagalan siklus berjalan), `total`
 * dipertahankan supaya ambang lapisan IP (8 kegagalan) tidak hilang saat upgrade, dan cooldown
 * warisan dibuang karena durasinya tidak akan pernah diizinkan kebijakan aktif untuk jumlah
 * kegagalan yang sama.
 */
function toBucket(value: unknown, fileVersion = FILE_VERSION): Bucket {
  const record = isRecord(value) ? value : {}
  const failures = sanitizeNumber(record.failures)
  const legacyCycles = Math.floor(failures / LOGIN_GUARD_ATTEMPTS_PER_LEVEL)
  const legacyResidual = failures % LOGIN_GUARD_ATTEMPTS_PER_LEVEL
  const level = fileVersion >= 2 ? sanitizeNumber(record.level) : legacyCycles
  const total = fileVersion >= 2 ? sanitizeNumber(record.total, failures) : failures
  return {
    level: Math.min(level, LOGIN_COOLDOWN_STEPS_MS.length),
    // VGL-41C: `failures` pada satu siklus sumber hanya bisa 0..ATTEMPTS-1 (kegagalan ke-3
    // langsung ditutup cooldown dan direset). Angka di atasnya berasal dari berkas yang ditulis
    // kebijakan lama atau dari penumpukan lintas klien, dan tidak boleh diwarisi sebagai
    // "kesempatan habis". `total` tetap utuh supaya ambang proporsional lapisan IP tidak hilang.
    failures:
      fileVersion >= 2
        ? failures >= LOGIN_GUARD_ATTEMPTS_PER_LEVEL
          ? 0
          : failures
        : legacyResidual,
    total,
    cooldownUntil: fileVersion >= 2 ? sanitizeNumber(record.cooldownUntil) : 0,
    updatedAt: sanitizeNumber(record.updatedAt),
    // Reservasi tidak bertahan melewati restart, jadi sisa hitungan in-flight dari proses lama
    // selalu dinolkan.
    inflight: 0,
  }
}

/**
 * Tulis lewat berkas sementara lalu rename. Rename atomik pada volume yang sama, sehingga proses
 * yang mati di tengah tulis tidak pernah meninggalkan JSON setengah jadi.
 */
function writeStateFile(file: string, state: PersistedFile): void {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  const temporary = `${file}.${process.pid}.tmp`
  fs.writeFileSync(temporary, `${JSON.stringify(state)}\n`, 'utf8')
  fs.renameSync(temporary, file)
}

export function defaultLoginGuardStateFile(cwd: string = process.cwd()): string {
  return path.join(cwd, '.data', 'login-guard.json')
}

/**
 * Penyimpanan cooldown.
 *
 * SINKRON oleh desain: tidak ada `await` di dalam read-modify-write, sehingga dua permintaan
 * yang datang bersamaan tidak pernah membaca keadaan lama lalu sama-sama menulis (persaingan
 * yang akan meloloskan dua percobaan melewati satu batas). Node menjalankan modul ini pada satu
 * thread, jadi sifat itu sudah berfungsi sebagai mutex.
 */
export function createLoginGuardStore(options: LoginGuardStoreOptions = {}): LoginGuardStore {
  const stateFile = options.stateFile === undefined ? defaultLoginGuardStateFile() : options.stateFile
  const clock = options.now ?? Date.now

  const loaded = stateFile ? readStateFile(stateFile) : null
  const state: PersistedFile = loaded ?? emptyFile(randomBytes(32).toString('hex'))
  const fileVersion = loaded?.version ?? FILE_VERSION

  const sources = new Map<string, Bucket>()
  for (const [key, value] of Object.entries(state.sources)) sources.set(key, toBucket(value, fileVersion))

  const ips = new Map<string, Bucket>()
  for (const [key, value] of Object.entries(state.ips)) ips.set(key, toBucket(value, fileVersion))

  const accounts = new Map<string, AccountState>()
  for (const [key, value] of Object.entries(state.accounts)) {
    const record: Record<string, unknown> = isRecord(value) ? value : {}
    const listed = Array.isArray(record.sources)
      ? record.sources.filter((item): item is string => typeof item === 'string')
      : []
    accounts.set(key, {
      failures: sanitizeNumber(record.failures),
      sources: listed.slice(0, 16),
      updatedAt: sanitizeNumber(record.updatedAt),
    })
  }

  const reservations = new Map<string, Reservation>()

  const sign = (value: string): string => createHmac('sha256', state.secret).update(value).digest('hex')

  const persist = (): void => {
    if (!stateFile) return
    writeStateFile(stateFile, {
      version: FILE_VERSION,
      secret: state.secret,
      sources: Object.fromEntries(sources),
      ips: Object.fromEntries(ips),
      accounts: Object.fromEntries(accounts),
    })
  }

  const prune = (now: number): void => {
    // Kedaluwarsa dihitung dari kejadian TERAKHIR: kegagalan terakhir ATAU berakhirnya
    // cooldown terakhir. Kalau hanya kegagalan yang dihitung, orang yang patuh menunggu
    // cooldown 24 jam justru kehilangan seluruh riwayatnya dan kembali ke tingkat 1.
    const expired = (bucket: Bucket): boolean =>
      bucket.cooldownUntil <= now && Math.max(bucket.updatedAt, bucket.cooldownUntil) + LOGIN_GUARD_HISTORY_TTL_MS <= now

    for (const [key, bucket] of sources) {
      if (expired(bucket)) sources.delete(key)
    }
    for (const [key, bucket] of ips) {
      if (expired(bucket)) ips.delete(key)
    }
    for (const [key, account] of accounts) {
      if (account.updatedAt + LOGIN_GUARD_HISTORY_TTL_MS <= now) accounts.delete(key)
    }
    for (const [token, reservation] of reservations) {
      // Reservasi yang jatuh tempo harus melepas slot in-flight-nya. Tanpa ini, klien yang
      // crash sebelum melaporkan hasil membuat sumber terkunci "busy" selamanya.
      if (reservation.expiresAt <= now) {
        reservations.delete(token)
        const bucket = sources.get(reservation.bucketKey) ?? ips.get(reservation.bucketKey)
        if (bucket && bucket.inflight > 0) bucket.inflight -= 1
      }
    }
  }

  /**
   * Kunci yang dipakai sebagai tempat perhitungan kegagalan utama. Dengan identifier peramban,
   * kunci gabungan ip+clientId (lapisan sumber, tangga penuh). Tanpa identifier tidak ada dimensi
   * sumber yang bisa dibedakan, sehingga kunci IP memakai tangga penuh.
   */
  const resolve = (raw: Partial<LoginGuardSource>) => {
    const ip = normalizeIp(raw.ip)
    const clientId = normalizeClientId(raw.clientId)
    const email = normalizeEmail(raw.email)
    const ipKey = `i:${sign(ip)}`
    const combinedKey = clientId ? `s:${sign(`${ip}|${clientId}`)}` : null
    const bucketKey = combinedKey ?? ipKey
    const table = combinedKey ? sources : ips
    return { ip, clientId, email, ipKey, combinedKey, bucketKey, table }
  }

  const releaseReservation = (token: string | null): void => {
    if (!token) return
    const reservation = reservations.get(token)
    if (!reservation) return
    reservations.delete(token)
    const bucket = sources.get(reservation.bucketKey) ?? ips.get(reservation.bucketKey)
    if (bucket && bucket.inflight > 0) bucket.inflight -= 1
  }

  const deny = (
    reason: LoginGuardDecision['reason'],
    bucket: Bucket | undefined,
    now: number,
    retryAfterMs: number,
  ): LoginGuardDecision => ({
    allowed: false,
    reason,
    retryAfterMs: Math.max(0, retryAfterMs),
    level: reportedLevel(bucket),
    failures: bucket?.failures ?? 0,
    attemptsLeft: attemptsLeftFor(bucket, now),
    attemptsPerLevel: LOGIN_GUARD_ATTEMPTS_PER_LEVEL,
    serverTime: now,
    token: null,
  })

  return {
    acquire(raw, nowOverride) {
      const now = nowOverride ?? clock()
      prune(now)
      const target = resolve(raw)
      const ipBucket = ips.get(target.ipKey)
      const bucket = target.table.get(target.bucketKey)

      if (bucket && bucket.cooldownUntil > now) {
        // Ditolak saat cooldown berlangsung: kesempatan TIDAK dikurangi dan tingkat TIDAK naik.
        return deny('cooldown', bucket, now, bucket.cooldownUntil - now)
      }

      // Lapisan jaringan hanya menghukum klien ber-identifier bila IP itu sendiri sudah
      // melewati ambang proporsionalnya.
      if (target.combinedKey && ipBucket && ipBucket.cooldownUntil > now) {
        return deny('network-cooldown', bucket, now, ipBucket.cooldownUntil - now)
      }

      if (bucket && bucket.inflight >= LOGIN_GUARD_MAX_INFLIGHT) {
        return deny('busy', bucket, now, LOGIN_GUARD_RESERVATION_TTL_MS)
      }

      const live = bucket ?? null
      if (!live) {
        if (target.table.size >= LOGIN_GUARD_MAX_BUCKETS) {
          // Tabel penuh: kunci baru ditolak. Mengusir entri hidup akan membuka jalur bypass
          // (penyerang memaksa eviction lalu mendapat kuota baru).
          return deny('full', undefined, now, LOGIN_GUARD_IP_COOLDOWN_MS)
        }
      }

      const granted: Bucket =
        live ?? { level: 0, failures: 0, total: 0, cooldownUntil: 0, updatedAt: now, inflight: 0 }
      if (!live) target.table.set(target.bucketKey, granted)
      granted.inflight += 1
      granted.updatedAt = now

      const token = randomBytes(16).toString('hex')
      reservations.set(token, { bucketKey: target.bucketKey, expiresAt: now + LOGIN_GUARD_RESERVATION_TTL_MS })
      persist()

      return {
        allowed: true,
        reason: 'granted',
        retryAfterMs: 0,
        level: reportedLevel(granted),
        failures: granted.failures,
        attemptsLeft: attemptsLeftFor(granted, now),
        attemptsPerLevel: LOGIN_GUARD_ATTEMPTS_PER_LEVEL,
        serverTime: now,
        token,
      }
    },

    report(raw, outcome, token, nowOverride) {
      const now = nowOverride ?? clock()
      prune(now)
      const target = resolve(raw)

      // Bucket selalu diambil/dibuat lewat table yang sama dengan acquire, sehingga laporan
      // tanpa acquire (permintaan langsung) tetap tercatat dan tidak bisa lolos.
      // Token acquire SENGAJA tidak dijadikan syarat perhitungan: kunci eskalasi adalah
      // ip+clientId (lihat resolve()), bukan email, sehingga melaporkan kegagalan kredensial
      // untuk email korban tidak mengunci siapa pun. Syarat token justru membuang pencatatan
      // untuk klien yang acquire-nya gagal — jalur yang sengaja ditangani cermin klien.
      const bucket = target.table.get(target.bucketKey) ?? null
      const live =
        bucket ??
        (() => {
          if (target.table.size >= LOGIN_GUARD_MAX_BUCKETS) return null
          const created: Bucket = { level: 0, failures: 0, total: 0, cooldownUntil: 0, updatedAt: now, inflight: 0 }
          target.table.set(target.bucketKey, created)
          return created
        })()

      const ipBucket = (() => {
        const existing = ips.get(target.ipKey)
        if (existing) return existing
        if (ips.size >= LOGIN_GUARD_MAX_BUCKETS) return null
        const created: Bucket = { level: 0, failures: 0, total: 0, cooldownUntil: 0, updatedAt: now, inflight: 0 }
        ips.set(target.ipKey, created)
        return created
      })()

      releaseReservation(token)

      const view = (state: Bucket | null): Omit<LoginGuardReport, 'counted' | 'retryAfterMs'> => ({
        level: reportedLevel(state),
        failures: state?.failures ?? 0,
        attemptsLeft: attemptsLeftFor(state, now),
        attemptsPerLevel: LOGIN_GUARD_ATTEMPTS_PER_LEVEL,
        serverTime: now,
      })

      if (outcome === 'network' || outcome === 'rate-limited') {
        // Gangguan jaringan bukan password salah; rate limit pihak layanan juga bukan bukti
        // kredensial. Keduanya tidak menambah riwayat kegagalan dan tidak mengurangi kesempatan.
        persist()
        return {
          counted: false,
          ...view(live),
          retryAfterMs: Math.max(0, (live?.cooldownUntil ?? 0) - now),
        }
      }

      if (outcome === 'success') {
        // Login berhasil mereset SUMBER ini sepenuhnya: kesempatan penuh dan tingkat kembali ke
        // awal. Riwayat IP dibiarkan meluruh sendiri: kalau tidak, penyerang bisa membersihkan
        // lapisan IP dengan akun miliknya.
        if (live) {
          live.level = 0
          live.failures = 0
          live.total = 0
          live.cooldownUntil = 0
          live.inflight = 0
          live.updatedAt = now
        }
        persist()
        return { counted: false, level: 0, failures: 0, attemptsLeft: LOGIN_GUARD_ATTEMPTS_PER_LEVEL, attemptsPerLevel: LOGIN_GUARD_ATTEMPTS_PER_LEVEL, retryAfterMs: 0, serverTime: now }
      }

      // credential-failure
      if (live && live.cooldownUntil > now) {
        // Kegagalan selama cooldown berlangsung TIDAK mereset, tidak memperpendek cooldown,
        // tidak mengurangi kesempatan, dan tidak menaikkan tingkat.
        persist()
        return {
          counted: false,
          ...view(live),
          retryAfterMs: live.cooldownUntil - now,
        }
      }

      if (live) {
        // VGL-39A — kegagalan ke-1 dan ke-2 hanya mengurangi kesempatan. Hanya kegagalan ke-3
        // pada tingkat berjalan yang mengaktifkan cooldown, lalu tingkat naik dan siklus
        // kesempatan dimulai ulang dari 3.
        live.failures += 1
        live.total += 1
        live.updatedAt = now
        if (live.failures >= LOGIN_GUARD_ATTEMPTS_PER_LEVEL) {
          live.cooldownUntil = now + cooldownMsForLevel(live.level)
          live.level += 1
          live.failures = 0
        }
      }

      // Lapisan IP hanya berlaku bila kegagalan sudah tercatat pada bucket sumber. Untuk klien
      // tanpa identifier, bucket sumber adalah bucket IP itu sendiri: menambahnya dua kali
      // akan menaikkan tingkat dua langkah sekaligus untuk satu percobaan.
      //
      // VGL-41C: lapisan IP hanya mencatat `total` (ambang proporsional 8 kegagalan) dan
      // cooldown-nya sendiri, TIDAK mencatat `failures` siklus berjalan. Angka itu hanya punya
      // arti bagi bucket sumber: bila ditumpuk dari semua klien ber-identifier di IP yang sama,
      // satu browser tanpa pengenal (mode privat, pengenal dihapus, permintaan langsung)
      // mewarisi kegagalan orang lain dan melaporkan "kesempatan habis" padahal tidak ada
      // cooldown — lalu satu password salah langsung dihukum tangga penuh.
      if (target.combinedKey && ipBucket) {
        ipBucket.total += 1
        ipBucket.updatedAt = now
        if (ipBucket.total >= LOGIN_GUARD_IP_THRESHOLD && ipBucket.cooldownUntil <= now) {
          ipBucket.cooldownUntil = now + LOGIN_GUARD_IP_COOLDOWN_MS
        }
      }

      if (target.email) {
        const accountKey = `a:${sign(target.email)}`
        const existing = accounts.get(accountKey)
        const account: AccountState = existing ?? { failures: 0, sources: [], updatedAt: now }
        account.failures += 1
        account.updatedAt = now
        if (!account.sources.includes(target.bucketKey) && account.sources.length < 16) {
          account.sources.push(target.bucketKey)
        }
        if (existing || accounts.size < LOGIN_GUARD_MAX_BUCKETS) accounts.set(accountKey, account)
      }

      persist()

      return {
        counted: Boolean(live),
        ...view(live),
        retryAfterMs: live && live.cooldownUntil > now ? live.cooldownUntil - now : 0,
      }
    },

    status(raw, nowOverride) {
      const now = nowOverride ?? clock()
      prune(now)
      const target = resolve(raw)
      const bucket = target.table.get(target.bucketKey)
      const ipBucket = ips.get(target.ipKey)
      const cooldownUntil = Math.max(bucket?.cooldownUntil ?? 0, ipBucket?.cooldownUntil ?? 0)
      const remaining = cooldownUntil > now ? cooldownUntil - now : 0

      return {
        active: remaining > 0,
        retryAfterMs: remaining,
        level: reportedLevel(bucket),
        failures: bucket?.failures ?? 0,
        attemptsLeft: remaining > 0 ? 0 : attemptsLeftFor(bucket, now),
        attemptsPerLevel: LOGIN_GUARD_ATTEMPTS_PER_LEVEL,
        serverTime: now,
      }
    },

    stats() {
      return { sources: sources.size, ips: ips.size, accounts: accounts.size }
    },

    reset() {
      sources.clear()
      ips.clear()
      accounts.clear()
      reservations.clear()
    },
  }
}

// ── Lapisan HTTP ──────────────────────────────────────────────────────────────

export type LoginGuardHttpOptions = {
  store: LoginGuardStore
  allowedOrigins?: string | undefined
  now?: () => number
  maxBodyBytes?: number
}

const BASE_HEADERS: Record<string, string> = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
}

function buildResponse(
  status: number,
  body: string | null,
  extra: Headers,
  contentType = 'application/json; charset=utf-8',
): Response {
  const headers = new Headers(BASE_HEADERS)
  headers.set('content-type', contentType)
  extra.forEach((value, key) => headers.set(key, value))
  return new Response(body, { status, headers })
}

function corsHeaders(origin: string | null, allowed: Set<string>): Headers {
  const headers = new Headers()
  if (origin && allowed.has(origin)) {
    headers.set('access-control-allow-origin', origin)
    headers.set('vary', 'origin')
    headers.set('access-control-allow-headers', 'content-type')
    headers.set('access-control-allow-methods', 'POST, GET, OPTIONS')
    headers.set('access-control-max-age', '600')
  }
  return headers
}

const OUTCOMES = new Set<LoginGuardOutcome>([
  'credential-failure',
  'success',
  'network',
  'rate-limited',
])

export function createLoginGuardHandler(
  options: LoginGuardHttpOptions,
): (request: Request) => Promise<Response | null> {
  const allowedOrigins = new Set(
    (options.allowedOrigins ?? '')
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean),
  )
  const maxBodyBytes = options.maxBodyBytes ?? LOGIN_GUARD_MAX_BODY_BYTES

  return async function handleLoginGuard(request) {
    let url: URL
    try {
      url = new URL(request.url)
    } catch {
      return null
    }
    if (!LOGIN_GUARD_PATHS.has(url.pathname)) return null

    const origin = request.headers.get('origin')
    const cors = corsHeaders(origin, allowedOrigins)

    if (request.method === 'OPTIONS') {
      if (origin && allowedOrigins.size > 0 && !allowedOrigins.has(origin)) {
        return buildResponse(403, JSON.stringify({ error: { code: 'origin_not_allowed', message: 'Origin tidak diizinkan.' } }), cors)
      }
      return buildResponse(204, null, cors, 'text/plain; charset=utf-8')
    }

    if (origin && allowedOrigins.size > 0 && !allowedOrigins.has(origin)) {
      return buildResponse(403, JSON.stringify({ error: { code: 'origin_not_allowed', message: 'Origin tidak diizinkan.' } }), cors)
    }

    const source = {
      ip: normalizeIp(request.headers.get('cf-connecting-ip')),
      clientId: url.searchParams.get('clientId'),
      email: null as string | null,
    }

    if (url.pathname === LOGIN_GUARD_STATUS_PATH) {
      if (request.method !== 'GET' && request.method !== 'POST') {
        return buildResponse(405, JSON.stringify({ error: { code: 'method_not_allowed', message: 'Metode tidak diizinkan.' } }), cors)
      }
      return buildResponse(200, JSON.stringify(options.store.status(source)), cors)
    }

    if (request.method !== 'POST') {
      return buildResponse(405, JSON.stringify({ error: { code: 'method_not_allowed', message: 'Metode tidak diizinkan.' } }), cors)
    }

    if (!/application\/json/i.test(request.headers.get('content-type') ?? '')) {
      return buildResponse(415, JSON.stringify({ error: { code: 'unsupported_media_type', message: 'Tipe konten tidak didukung.' } }), cors)
    }

    const declared = Number(request.headers.get('content-length') ?? '0')
    if (Number.isFinite(declared) && declared > maxBodyBytes) {
      return buildResponse(413, JSON.stringify({ error: { code: 'payload_too_large', message: 'Permintaan terlalu besar.' } }), cors)
    }

    let text = ''
    try {
      text = await request.text()
    } catch {
      return buildResponse(400, JSON.stringify({ error: { code: 'invalid_request', message: 'Permintaan tidak valid.' } }), cors)
    }
    if (text.length > maxBodyBytes) {
      return buildResponse(413, JSON.stringify({ error: { code: 'payload_too_large', message: 'Permintaan terlalu besar.' } }), cors)
    }

    let payload: unknown
    try {
      payload = JSON.parse(text)
    } catch {
      return buildResponse(400, JSON.stringify({ error: { code: 'invalid_request', message: 'Permintaan tidak valid.' } }), cors)
    }
    if (!isRecord(payload)) {
      return buildResponse(400, JSON.stringify({ error: { code: 'invalid_request', message: 'Permintaan tidak valid.' } }), cors)
    }

    source.clientId = typeof payload.clientId === 'string' ? payload.clientId : source.clientId
    source.email = typeof payload.email === 'string' ? payload.email : null

    if (url.pathname === LOGIN_GUARD_ACQUIRE_PATH) {
      const decision = options.store.acquire(source)
      if (!decision.allowed) {
        cors.set('retry-after', String(Math.max(1, Math.ceil(decision.retryAfterMs / 1_000))))
        return buildResponse(429, JSON.stringify(decision), cors)
      }
      return buildResponse(200, JSON.stringify(decision), cors)
    }

    const outcome = payload.outcome
    if (typeof outcome !== 'string' || !OUTCOMES.has(outcome as LoginGuardOutcome)) {
      return buildResponse(400, JSON.stringify({ error: { code: 'invalid_request', message: 'Permintaan tidak valid.' } }), cors)
    }

    const token = typeof payload.token === 'string' ? payload.token : null
    return buildResponse(200, JSON.stringify(options.store.report(source, outcome as LoginGuardOutcome, token)), cors)
  }
}

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  LOGIN_COOLDOWN_STEPS_MS,
  LOGIN_GUARD_ATTEMPTS_PER_LEVEL,
  LOGIN_GUARD_HISTORY_TTL_MS,
  LOGIN_GUARD_IP_COOLDOWN_MS,
  LOGIN_GUARD_IP_THRESHOLD,
  LOGIN_GUARD_MAX_INFLIGHT,
  LOGIN_GUARD_ACQUIRE_PATH,
  LOGIN_GUARD_REPORT_PATH,
  LOGIN_GUARD_STATUS_PATH,
  cooldownMsForLevel,
  createLoginGuardHandler,
  createLoginGuardStore,
  type LoginGuardOutcome,
  type LoginGuardSource,
  type LoginGuardStore,
} from '../src/loginGuard.js'

const T0 = 1_780_000_000_000
const ATTEMPTS = LOGIN_GUARD_ATTEMPTS_PER_LEVEL
const STEPS = [120_000, 3_600_000, 10_800_000, 21_600_000, 43_200_000, 86_400_000]

const SOURCE_X = { ip: '203.0.113.10', clientId: 'client-xxxx-0001', email: 'sasaran@contoh.com' }
const SOURCE_Y = { ip: '203.0.113.10', clientId: 'client-yyyy-0002', email: 'sasaran@contoh.com' }
const SOURCE_Z = { ip: '198.51.100.7', clientId: 'client-zzzz-0003', email: 'sasaran@contoh.com' }

// Uji tangga penuh (>= 8 kegagalan) memakai klien TANPA identifier. Alasannya bukan teknis:
// begitu satu IP melewati LOGIN_GUARD_IP_THRESHOLD, lapisan jaringan ikut menahan 2 menit di
// antara kesempatan, sehingga tangga tidak bisa dibaca bersih. Jalur ber-identifier diuji pada
// siklus pendek (<= 6 kegagalan) di bawah, dan interaksi lapisan IP diuji terpisah.
const LADDER = { ip: '203.0.113.40', clientId: null, email: 'sasaran@contoh.com' }
const RESET = { ip: '203.0.113.41', clientId: null, email: 'sasaran@contoh.com' }

function withClock() {
  let now = T0
  const store = createLoginGuardStore({ stateFile: null, now: () => now })
  return { store, now: () => now, advance: (ms: number) => (now += ms), set: (value: number) => (now = value) }
}

/** Alur nyata satu percobaan: akuisisi dulu (sebelum kredensial dikirim), lalu laporkan hasilnya. */
function attempt(
  store: LoginGuardStore,
  source: Partial<LoginGuardSource>,
  outcome: LoginGuardOutcome,
  now: number,
) {
  const gate = store.acquire(source, now)
  if (!gate.allowed) return { gate, report: null }
  return { gate, report: store.report(source, outcome, gate.token, now) }
}

/** `n` kegagalan kredensial berurutan, masing-masing dengan akuisisi yang diizinkan. */
function failTimes(store: LoginGuardStore, source: Partial<LoginGuardSource>, now: number, n = ATTEMPTS) {
  const results = []
  for (let index = 0; index < n; index += 1) {
    const result = attempt(store, source, 'credential-failure', now)
    expect(result.gate.allowed, `percobaan ke-${index + 1} seharusnya diizinkan`).toBe(true)
    results.push(result.report)
  }
  return results
}

describe('VGL-39A — tangga cooldown progresif dengan 3 kesempatan per tingkat', () => {
  it('setiap tingkat memakai durasi kebijakan: 2m, 1h, 3h, 6h, 12h, 24h', () => {
    expect([...LOGIN_COOLDOWN_STEPS_MS]).toEqual(STEPS)
    // `level` adalah indeks 0-based tangga: 0 = "Awal", 1 = tingkat 1, dst.
    expect(cooldownMsForLevel(0)).toBe(2 * 60_000)
    expect(cooldownMsForLevel(1)).toBe(60 * 60_000)
    expect(cooldownMsForLevel(2)).toBe(3 * 60 * 60_000)
    expect(cooldownMsForLevel(3)).toBe(6 * 60 * 60_000)
    expect(cooldownMsForLevel(4)).toBe(12 * 60 * 60_000)
    expect(cooldownMsForLevel(5)).toBe(24 * 60 * 60_000)
  })

  it('tingkat keenam dan seterusnya tidak pernah melebihi 24 jam', () => {
    expect(cooldownMsForLevel(6)).toBe(24 * 60 * 60_000)
    expect(cooldownMsForLevel(999)).toBe(24 * 60 * 60_000)
  })

  it('kegagalan ke-1 dan ke-2 hanya mengurangi kesempatan, belum ada cooldown', () => {
    const clock = withClock()
    const { store } = clock

    const before = store.acquire(SOURCE_X, clock.now())
    expect(before.allowed).toBe(true)
    expect(before.attemptsLeft).toBe(3)
    expect(before.attemptsPerLevel).toBe(3)

    const first = store.report(SOURCE_X, 'credential-failure', before.token, clock.now())
    expect(first.counted).toBe(true)
    expect(first.failures).toBe(1)
    expect(first.attemptsLeft).toBe(2)
    expect(first.level).toBe(0)
    expect(first.retryAfterMs).toBe(0)
    // Tidak ada cooldown: sumber masih boleh mencoba lagi sekarang.
    expect(store.acquire(SOURCE_X, clock.now()).allowed).toBe(true)

    const second = store.report(SOURCE_X, 'credential-failure', null, clock.now())
    expect(second.failures).toBe(2)
    expect(second.attemptsLeft).toBe(1)
    expect(second.level).toBe(0)
    expect(second.retryAfterMs).toBe(0)
    expect(store.status(SOURCE_X, clock.now()).active).toBe(false)
  })

  it('tepat 3 kegagalan mengaktifkan cooldown tingkat itu, lalu kesempatan kembali 3 dan tingkat naik', () => {
    const clock = withClock()
    const { store } = clock

    const [one, two, three] = failTimes(store, LADDER, clock.now())
    expect(one?.retryAfterMs).toBe(0)
    expect(two?.retryAfterMs).toBe(0)
    expect(three?.failures).toBe(0)
    expect(three?.attemptsLeft).toBe(0)
    expect(three?.level).toBe(1)
    expect(three?.retryAfterMs).toBe(2 * 60_000)
    expect(store.status(LADDER, clock.now()).active).toBe(true)

    // Setelah cooldown "Awal" habis: 3 kesempatan BARU, tingkat TIDAK dihapus.
    clock.advance(2 * 60_000)
    const reopened = store.status(LADDER, clock.now())
    expect(reopened.active).toBe(false)
    expect(reopened.attemptsLeft).toBe(3)
    expect(reopened.level).toBe(1)

    const next = failTimes(store, LADDER, clock.now())
    expect(next[2]?.retryAfterMs).toBe(60 * 60_000)
    expect(next[2]?.level).toBe(2)

    clock.advance(60 * 60_000)
    expect(failTimes(store, LADDER, clock.now())[2]?.retryAfterMs).toBe(3 * 60 * 60_000)
    clock.advance(3 * 60 * 60_000)
    expect(failTimes(store, LADDER, clock.now())[2]?.retryAfterMs).toBe(6 * 60 * 60_000)
    clock.advance(6 * 60 * 60_000)
    expect(failTimes(store, LADDER, clock.now())[2]?.retryAfterMs).toBe(12 * 60 * 60_000)
    clock.advance(12 * 60 * 60_000)
    expect(failTimes(store, LADDER, clock.now())[2]?.retryAfterMs).toBe(24 * 60 * 60_000)
    clock.advance(24 * 60 * 60_000)
    // Puncak tangga: tetap 24 jam, tidak ada tingkat yang lebih tinggi dari itu.
    const top = failTimes(store, LADDER, clock.now())
    expect(top[2]?.retryAfterMs).toBe(24 * 60 * 60_000)
    expect(top[2]?.level).toBe(6)
    clock.advance(24 * 60 * 60_000)
    expect(failTimes(store, LADDER, clock.now())[2]?.retryAfterMs).toBe(24 * 60 * 60_000)
  })

  it('percobaan selama cooldown berlangsung ditolak tanpa mengurangi kesempatan', () => {
    const clock = withClock()
    const { store } = clock

    failTimes(store, SOURCE_X, clock.now())
    clock.advance(60_000)

    const denied = store.acquire(SOURCE_X, clock.now())
    expect(denied.allowed).toBe(false)
    expect(denied.reason).toBe('cooldown')
    expect(denied.retryAfterMs).toBe(60_000)
    expect(denied.level).toBe(1)
    expect(denied.failures).toBe(0)
    expect(denied.attemptsLeft).toBe(0)

    // 20 percobaan saat cooldown tidak mengubah tingkat maupun riwayat.
    for (let index = 0; index < 20; index += 1) store.acquire(SOURCE_X, clock.now())
    const status = store.status(SOURCE_X, clock.now())
    expect(status.level).toBe(1)
    expect(status.failures).toBe(0)
    expect(status.retryAfterMs).toBe(60_000)
  })
})

describe('VGL-39A — aturan perhitungan kesempatan', () => {
  it('kesempatan yang sudah terpakai bertahan sampai masa riwayat habis', () => {
    const clock = withClock()
    const { store } = clock

    attempt(store, SOURCE_X, 'credential-failure', clock.now())
    attempt(store, SOURCE_X, 'credential-failure', clock.now())
    expect(store.status(SOURCE_X, clock.now()).attemptsLeft).toBe(1)

    // Sumber itu berhenti (mis. menutup tab) lalu kembali setelah masa riwayat habis.
    clock.advance(LOGIN_GUARD_HISTORY_TTL_MS + 1)
    const back = store.status(SOURCE_X, clock.now())
    expect(back.attemptsLeft).toBe(ATTEMPTS)
    expect(back.failures).toBe(0)
  })

  it('kegagalan selama cooldown berlangsung tidak mereset, tidak memperpendek, dan tidak menambah tingkat', () => {
    const clock = withClock()
    const { store } = clock

    failTimes(store, SOURCE_X, clock.now())
    const until = store.status(SOURCE_X, clock.now()).retryAfterMs
    expect(until).toBe(2 * 60_000)

    clock.advance(10_000)
    // Klien nakal mengirim laporan gagal berulang kali selama cooldown.
    for (let index = 0; index < 5; index += 1) {
      const late = store.report(SOURCE_X, 'credential-failure', null, clock.now())
      expect(late.counted).toBe(false)
      expect(late.attemptsLeft).toBe(0)
    }

    const status = store.status(SOURCE_X, clock.now())
    expect(status.failures).toBe(0)
    expect(status.level).toBe(1)
    expect(status.retryAfterMs).toBe(until - 10_000)
  })

  it('login berhasil mereset kesempatan DAN mengembalikan tingkat ke awal', () => {
    const clock = withClock()
    const { store } = clock

    // Dua siklus penuh: tingkat naik 0 -> 1 -> 2.
    failTimes(store, RESET, clock.now())
    expect(store.status(RESET, clock.now()).level).toBe(1)
    clock.advance(2 * 60_000)
    failTimes(store, RESET, clock.now())
    clock.advance(60 * 60_000)
    expect(store.status(RESET, clock.now()).level).toBe(2)

    // 2 kegagalan lagi, lalu pemilik sah login dengan benar.
    attempt(store, RESET, 'credential-failure', clock.now())
    attempt(store, RESET, 'credential-failure', clock.now())
    expect(store.status(RESET, clock.now()).attemptsLeft).toBe(1)

    const ok = attempt(store, RESET, 'success', clock.now())
    expect(ok.report?.level).toBe(0)
    expect(ok.report?.attemptsLeft).toBe(ATTEMPTS)

    const after = store.status(RESET, clock.now())
    expect(after.failures).toBe(0)
    expect(after.level).toBe(0)
    expect(after.attemptsLeft).toBe(ATTEMPTS)
    expect(after.active).toBe(false)

    // Mulai dari awal lagi: 3 kegagalan berikutnya kembali memakai cooldown 2 menit.
    expect(failTimes(store, RESET, clock.now())[2]?.retryAfterMs).toBe(2 * 60_000)
  })

  it('riwayat kegagalan kedaluwarsa, bukan tersimpan selamanya', () => {
    const clock = withClock()
    const { store } = clock

    failTimes(store, SOURCE_X, clock.now())
    expect(store.stats().sources).toBe(1)

    // Masa kedaluwarsa dihitung dari PERISTIWA TERAKHIR, yaitu akhir cooldown 2 menit yang
    // masih berjalan, bukan dari waktu kegagalan itu sendiri. Riwayat yang masih punya
    // cooldown aktif tidak boleh hilang sebelum cooldown itu tuntas.
    clock.advance(LOGIN_GUARD_HISTORY_TTL_MS + 2 * 60_000 + 1)
    const status = store.status(SOURCE_X, clock.now())
    expect(status.failures).toBe(0)
    expect(status.level).toBe(0)
    expect(status.attemptsLeft).toBe(ATTEMPTS)
    expect(store.stats().sources).toBe(0)

    // Kembali ke awal: tiga kegagalan lagi menghasilkan cooldown 2 menit, bukan 1 jam.
    expect(failTimes(store, SOURCE_X, clock.now())[2]?.retryAfterMs).toBe(2 * 60_000)
  })

  it('kegagalan jaringan dan rate limit pihak layanan tidak mengurangi kesempatan', () => {
    const clock = withClock()
    const { store } = clock

    for (const outcome of ['network', 'rate-limited'] as const) {
      const result = attempt(store, SOURCE_X, outcome, clock.now())
      expect(result.report?.counted).toBe(false)
      expect(result.report?.attemptsLeft).toBe(ATTEMPTS)
      expect(result.report?.failures).toBe(0)
    }

    expect(store.status(SOURCE_X, clock.now()).failures).toBe(0)
    expect(store.status(SOURCE_X, clock.now()).active).toBe(false)

    // Baru kegagalan kredensial yang mengurangi kesempatan.
    const first = attempt(store, SOURCE_X, 'credential-failure', clock.now())
    expect(first.report?.attemptsLeft).toBe(2)
  })
})

describe('VGL-38 — isolasi sumber percobaan (tanpa global account lockout)', () => {
  it('sumber yang terkunci tidak mengunci sumber lain pada akun yang sama', () => {
    const clock = withClock()
    const { store } = clock

    failTimes(store, SOURCE_X, clock.now())

    expect(store.acquire(SOURCE_X, clock.now()).allowed).toBe(false)

    // Pemilik akun dari perangkat lain tetap bisa mencoba.
    const other = store.acquire(SOURCE_Y, clock.now())
    expect(other.allowed).toBe(true)
    expect(store.acquire(SOURCE_Z, clock.now()).allowed).toBe(true)
  })

  it('mengganti alamat email target tidak melewati pembatasan sumber', () => {
    const clock = withClock()
    const { store } = clock

    failTimes(store, { ...SOURCE_X, email: 'a@contoh.com' }, clock.now())

    const switched = store.acquire({ ...SOURCE_X, email: 'b@contoh.com' }, clock.now())
    expect(switched.allowed).toBe(false)
    expect(switched.reason).toBe('cooldown')
    expect(switched.level).toBe(1)
  })

  it('sumber yang sama pada IP berbeda tetap punya kuota sumbernya sendiri', () => {
    const clock = withClock()
    const { store } = clock

    failTimes(store, { ...SOURCE_X, ip: '203.0.113.10' }, clock.now())
    const moved = store.acquire({ ...SOURCE_X, ip: '203.0.113.99' }, clock.now())
    expect(moved.allowed).toBe(true)
  })

  it('lapisan IP bersifat proporsional: baru bergerak setelah ambang dan dibatasi 2 menit', () => {
    const clock = withClock()
    const { store } = clock

    // Banyak sumber sah di satu IP bersama, masing-masing satu kegagalan.
    for (let index = 0; index < LOGIN_GUARD_IP_THRESHOLD - 1; index += 1) {
      const source = { ip: '198.51.100.200', clientId: `client-ip-shared-${index}`, email: 'sasaran@contoh.com' }
      attempt(store, source, 'credential-failure', clock.now())
      clock.advance(1)
    }

    // Belum ada pembatasan jaringan: sumber baru masih bebas mencoba.
    const before = store.acquire({ ip: '198.51.100.200', clientId: 'client-pengguna-baru' }, clock.now())
    expect(before.allowed).toBe(true)

    // Satu kegagalan lagi melewati ambang IP -> seluruh IP ditahan, tapi hanya 2 menit.
    attempt(store, { ip: '198.51.100.200', clientId: `client-ip-shared-${LOGIN_GUARD_IP_THRESHOLD - 1}` }, 'credential-failure', clock.now())
    const after = store.acquire({ ip: '198.51.100.200', clientId: 'client-pengguna-baru' }, clock.now())
    expect(after.allowed).toBe(false)
    expect(after.reason).toBe('network-cooldown')
    expect(after.retryAfterMs).toBeLessThanOrEqual(LOGIN_GUARD_IP_COOLDOWN_MS)

    // Kesempatan tingkat ini sendiri masih penuh (3): yang menahan adalah lapisan jaringan,
    // bukan siklus 3 kesempatan sumber.
    expect(after.attemptsLeft).toBe(3)

    // IP lain tidak ikut terpengaruh.
    expect(store.acquire({ ip: '198.51.100.201', clientId: 'client-lain-ip' }, clock.now()).allowed).toBe(true)
  })

  it('klien tanpa identifier juga membutuhkan 3 kegagalan sebelum tangga berlaku pada kunci IP', () => {
    const clock = withClock()
    const { store } = clock
    const source = { ip: '203.0.113.77', clientId: null }

    const first = attempt(store, source, 'credential-failure', clock.now())
    expect(first.gate.allowed).toBe(true)
    expect(first.report?.attemptsLeft).toBe(2)
    expect(first.report?.retryAfterMs).toBe(0)

    const second = attempt(store, source, 'credential-failure', clock.now())
    expect(second.gate.allowed).toBe(true)
    expect(second.report?.attemptsLeft).toBe(1)
    expect(second.report?.retryAfterMs).toBe(0)

    const third = attempt(store, source, 'credential-failure', clock.now())
    expect(third.report?.retryAfterMs).toBe(2 * 60_000)

    const again = store.acquire(source, clock.now())
    expect(again.allowed).toBe(false)
    expect(again.retryAfterMs).toBe(2 * 60_000)
  })

  it('email tidak pernah dipakai sebagai kunci cooldown', () => {
    const clock = withClock()
    const { store } = clock

    failTimes(store, { ip: '203.0.113.5', clientId: 'client-aaaa-1111', email: 'korban@contoh.com' }, clock.now())

    // Sumber lain yang mencoba akun korban yang sama tetap bisa masuk (tidak ada global lockout).
    const victim = store.acquire({ ip: '198.51.100.9', clientId: 'client-victim-2222', email: 'korban@contoh.com' }, clock.now())
    expect(victim.allowed).toBe(true)
  })

  it('VGL-39B — varian penulisan email yang sama tidak membuat record deteksi baru', () => {
    const clock = withClock()
    const { store } = clock

    // Dua sumber berbeda, email sama dengan beda huruf dan spasi: keduanya harus masuk ke record
    // deteksi akun yang SAMA, supaya serangan terarah tidak dipecah menjadi dua record kosong.
    attempt(store, { ip: '203.0.113.21', clientId: 'client-norm-0001', email: 'Sasaran@Contoh.com' }, 'credential-failure', clock.now())
    clock.advance(1)
    attempt(store, { ip: '203.0.113.22', clientId: 'client-norm-0002', email: '  sasaran@CONTOH.com  ' }, 'credential-failure', clock.now())

    expect(store.stats()).toEqual({ sources: 2, ips: 2, accounts: 1 })
  })
})

describe('VGL-38 — ketahanan', () => {
  it('percobaan paralel per sumber dibatasi dan reservasi dilepas setelah laporan', () => {
    const clock = withClock()
    const { store } = clock

    const tokens: Array<string | null> = []
    for (let index = 0; index < LOGIN_GUARD_MAX_INFLIGHT; index += 1) {
      const gate = store.acquire(SOURCE_X, clock.now())
      expect(gate.allowed).toBe(true)
      tokens.push(gate.token)
    }

    const blocked = store.acquire(SOURCE_X, clock.now())
    expect(blocked.allowed).toBe(false)
    expect(blocked.reason).toBe('busy')

    if (tokens[0]) store.report(SOURCE_X, 'network', tokens[0], clock.now())
    expect(store.acquire(SOURCE_X, clock.now()).allowed).toBe(true)
  })

  it('akuisisi paralel tanpa kegagalan nyata tidak mengurangi kesempatan', () => {
    const clock = withClock()
    const { store } = clock

    const parallel = [store.acquire(SOURCE_X, clock.now()), store.acquire(SOURCE_X, clock.now())]
    for (const gate of parallel) if (gate.token) store.report(SOURCE_X, 'network', gate.token, clock.now())
    expect(store.status(SOURCE_X, clock.now()).attemptsLeft).toBe(ATTEMPTS)
  })

  it('reservasi yang tidak pernah dilaporkan kedaluwarsa sendiri', () => {
    const clock = withClock()
    const { store } = clock

    store.acquire(SOURCE_X, clock.now())
    store.acquire(SOURCE_X, clock.now())
    expect(store.acquire(SOURCE_X, clock.now()).reason).toBe('busy')

    clock.advance(31_000)
    expect(store.acquire(SOURCE_X, clock.now()).allowed).toBe(true)
  })

  it('laporan tanpa akuisisi (permintaan langsung ke endpoint) tetap dihitung', () => {
    const clock = withClock()
    const { store } = clock

    for (let index = 1; index <= ATTEMPTS; index += 1) {
      const direct = store.report(SOURCE_X, 'credential-failure', null, clock.now())
      expect(direct.counted).toBe(true)
      expect(direct.failures).toBe(index % ATTEMPTS)
    }
    expect(store.acquire(SOURCE_X, clock.now()).allowed).toBe(false)
  })

  it('identifier yang hilang atau berubah tidak menghapus riwayat pada IP yang sama', () => {
    const clock = withClock()
    const { store } = clock

    attempt(store, { ip: '203.0.113.30', clientId: 'client-lama-000001' }, 'credential-failure', clock.now())
    // Client id baru = sumber baru (sengaja: identifier tidak bisa dipercaya sebagai bukti
    // identitas), tetapi lapisan IP tetap menghitung kegagalan dari IP yang sama.
    for (let index = 0; index < LOGIN_GUARD_IP_THRESHOLD; index += 1) {
      attempt(store, { ip: '203.0.113.30', clientId: `client-baru-${index.toString().padStart(6, '0')}` }, 'credential-failure', clock.now())
      clock.advance(1)
    }
    const status = store.status({ ip: '203.0.113.30', clientId: 'client-baru-999999' }, clock.now())
    expect(status.active).toBe(true)
    expect(status.retryAfterMs).toBeLessThanOrEqual(LOGIN_GUARD_IP_COOLDOWN_MS)
  })
})

describe('VGL-39A — persistensi lintas restart dan migrasi berkas v1', () => {
  let directory = ''

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'vgl39a-guard-'))
  })

  afterEach(() => {
    rmSync(directory, { recursive: true, force: true })
  })

  it('kesempatan yang sudah terpakai bertahan setelah proses dibuat ulang dari berkas yang sama', () => {
    const file = join(directory, 'login-guard.json')
    const first = createLoginGuardStore({ stateFile: file, now: () => T0 })

    attempt(first, SOURCE_X, 'credential-failure', T0)
    expect(first.status(SOURCE_X, T0).attemptsLeft).toBe(2)

    const second = createLoginGuardStore({ stateFile: file, now: () => T0 })
    const reloaded = second.status(SOURCE_X, T0)
    expect(reloaded.attemptsLeft).toBe(2)
    expect(reloaded.failures).toBe(1)

    // Refresh/tab baru tidak memberi kesempatan ekstra, tetapi kegagalan ke-3 tetap menutup.
    expect(second.report(SOURCE_X, 'credential-failure', null, T0).retryAfterMs).toBe(0)
    const third = second.report(SOURCE_X, 'credential-failure', null, T0)
    expect(third.retryAfterMs).toBe(2 * 60_000)
    expect(second.acquire(SOURCE_X, T0).allowed).toBe(false)
  })

  it('cooldown yang masih aktif tetap berlaku setelah restart, dan kesempatan baru terbit setelahnya', () => {
    const file = join(directory, 'login-guard.json')
    const first = createLoginGuardStore({ stateFile: file, now: () => T0 })

    failTimes(first, SOURCE_X, T0)

    const second = createLoginGuardStore({ stateFile: file, now: () => T0 })
    const denied = second.acquire(SOURCE_X, T0)
    expect(denied.allowed).toBe(false)
    expect(denied.reason).toBe('cooldown')
    expect(denied.retryAfterMs).toBe(2 * 60_000)
    expect(denied.attemptsLeft).toBe(0)
    expect(second.status(SOURCE_X, T0).level).toBe(1)

    const third = createLoginGuardStore({ stateFile: file, now: () => T0 + 121_000 })
    const reopened = third.acquire(SOURCE_X, T0 + 121_000)
    expect(reopened.allowed).toBe(true)
    expect(reopened.attemptsLeft).toBe(ATTEMPTS)
    expect(reopened.level).toBe(1)
  })

  it('berkas versi 1 (VGL-38) bermigrasi tanpa mewarisi cooldown kebijakan lama', () => {
    const file = join(directory, 'login-guard.json')
    const seed = createLoginGuardStore({ stateFile: file, now: () => T0 })
    // Satu kegagalan saja: cukup untuk menciptakan bucket pada kunci sumber.
    seed.report(SOURCE_X, 'credential-failure', null, T0)

    // Turunkan berkas ke bentuk v1: `failures` = tingkat, tanpa `level`/`total`.
    const written = JSON.parse(readFileSync(file, 'utf8')) as {
      secret: string
      sources: Record<string, unknown>
      ips: Record<string, unknown>
      accounts: Record<string, unknown>
    }
    writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        secret: written.secret,
        sources: Object.fromEntries(
          Object.keys(written.sources).map((key) => [
            key,
            { failures: 5, cooldownUntil: T0 + 3 * 60 * 60_000, updatedAt: T0, inflight: 3 },
          ]),
        ),
        ips: written.ips,
        accounts: written.accounts,
      }),
      'utf8',
    )

    const migrated = createLoginGuardStore({ stateFile: file, now: () => T0 })
    // v1 mencatat 5 "tingkat" = 5 kegagalan pada kebijakan lama. Kebijakan aktif menghitungnya
    // sebagai 1 siklus penuh (3 kegagalan -> tingkat 1) dengan 2 kegagalan tersisa di siklus
    // berjalan, dan TIDAK mewarisi 3 jam yang tidak pernah dijinkan aturan itu untuk 5 kegagalan.
    const reopened = migrated.acquire(SOURCE_X, T0)
    expect(reopened.allowed).toBe(true)
    expect(reopened.level).toBe(1)
    expect(reopened.failures).toBe(2)
    expect(reopened.attemptsLeft).toBe(1)

    // Kegagalan berikutnya menyelesaikan siklus tingkat 1 -> durasi dari tangga AKTIF (1 jam).
    const closed = attempt(migrated, SOURCE_X, 'credential-failure', T0)
    expect(closed.gate.allowed).toBe(true)
    expect(closed.report?.retryAfterMs).toBe(60 * 60_000)
    expect(closed.report?.level).toBe(2)

    migrated.report(SOURCE_X, 'network', null, T0 + 61 * 60_000)
    const after = JSON.parse(readFileSync(file, 'utf8')) as {
      version: number
      sources: Record<string, { level: number; failures: number; total: number; inflight: number }>
    }
    expect(after.version).toBe(2)
    const bucket = after.sources[Object.keys(after.sources)[0]]
    expect(bucket.level).toBe(2)
    expect(bucket.failures).toBe(0)
    // `total` tetap memakai hitungan kegagalan lama, sehingga ambang lapisan IP tidak menguap.
    expect(bucket.total).toBe(6)
    // in-flight dari proses lama selalu dinolkan; reservasi tidak ikut bermigrasi.
    expect(Object.values(after.sources).every((entry) => entry.inflight === 0)).toBe(true)
  })

  it('kunci warisan kebijakan lama tidak membuat sumber tetap terkunci setelah migrasi', () => {
    // Bentuk persis yang teramati pada berkas dev nyata: 3 kegagalan v1 + cooldown 3 jam, yang
    // di bawah kebijakan aktif tidak pernah dijinkan (3 kegagalan = satu siklus tingkat 0 =
    // 2 menit, bukan 3 jam).
    const file = join(directory, 'login-guard-legacy-lock.json')
    const seed = createLoginGuardStore({ stateFile: file, now: () => T0 })
    seed.report(SOURCE_Y, 'credential-failure', null, T0)
    const written = JSON.parse(readFileSync(file, 'utf8')) as {
      secret: string
      sources: Record<string, unknown>
      ips: Record<string, unknown>
      accounts: Record<string, unknown>
    }
    writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        secret: written.secret,
        sources: Object.fromEntries(
          Object.keys(written.sources).map((key) => [
            key,
            { failures: 3, cooldownUntil: T0 + 3 * 60 * 60_000, updatedAt: T0, inflight: 0 },
          ]),
        ),
        ips: written.ips,
        accounts: written.accounts,
      }),
      'utf8',
    )

    const store = createLoginGuardStore({ stateFile: file, now: () => T0 })
    const status = store.status(SOURCE_Y, T0)
    expect(status.active).toBe(false)
    expect(status.retryAfterMs).toBe(0)
    expect(status.level).toBe(1)
    expect(status.failures).toBe(0)
    expect(status.attemptsLeft).toBe(ATTEMPTS)
    // Riwayat lama tidak dihapus begitu saja: satu kegagalan lagi dari siklus tingkat 1
    // tetap dihitung, dan dua kegagalan tambahan menutup dengan durasi tangga aktif.
    expect(attempt(store, SOURCE_Y, 'credential-failure', T0).report?.failures).toBe(1)
    expect(attempt(store, SOURCE_Y, 'credential-failure', T0).report?.failures).toBe(2)
    expect(attempt(store, SOURCE_Y, 'credential-failure', T0).report?.retryAfterMs).toBe(60 * 60_000)
  })

  it('berkas keadaan tidak pernah memuat email, IP, kata sandi, atau token mentah', () => {
    const file = join(directory, 'login-guard.json')
    const store = createLoginGuardStore({ stateFile: file, now: () => T0 })
    const gate = store.acquire(SOURCE_X, T0)
    failTimes(store, SOURCE_X, T0)

    const raw = readFileSync(file, 'utf8')
    expect(raw).not.toContain(SOURCE_X.email)
    expect(raw).not.toContain(SOURCE_X.ip)
    expect(raw).not.toContain(SOURCE_X.clientId)
    expect(raw).not.toContain(gate.token ?? '___')
    expect(raw).not.toContain('password')
  })

  it('berkas rusak tidak membuat gerbang terbuka; keadaan dimulai dari kosong', () => {
    const file = join(directory, 'login-guard.json')
    const store = createLoginGuardStore({ stateFile: file, now: () => T0 })
    failTimes(store, SOURCE_X, T0)
    // Simulasikan berkas dipotong setengah (proses mati saat tulis).
    writeFileSync(file, readFileSync(file, 'utf8').slice(0, 20), 'utf8')

    const recovered = createLoginGuardStore({ stateFile: file, now: () => T0 })
    expect(recovered.status(SOURCE_X, T0).failures).toBe(0)
    expect(recovered.acquire(SOURCE_X, T0).allowed).toBe(true)
  })
})

describe('VGL-39A — lapisan HTTP gerbang', () => {
  const ORIGIN = 'http://localhost:5173'

  function makeHandler(store: LoginGuardStore) {
    return createLoginGuardHandler({ store, allowedOrigins: ORIGIN })
  }

  function post(pathname: string, body: unknown, options: { origin?: string | null; ip?: string } = {}) {
    return new Request(`http://127.0.0.1:8790${pathname}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(options.origin === null ? {} : { origin: options.origin ?? ORIGIN }),
        'cf-connecting-ip': options.ip ?? SOURCE_X.ip,
      },
      body: JSON.stringify(body),
    })
  }

  type GateBody = {
    allowed?: boolean
    active?: boolean
    token?: string | null
    attemptsLeft?: number
    attemptsPerLevel?: number
    failures?: number
    level?: number
    retryAfterMs?: number
  }

  async function bodyOf(response: Response | null): Promise<GateBody> {
    return (await response?.json()) as GateBody
  }

  it('memberi 3 kesempatan lewat HTTP, baru merespons 429 setelah kegagalan ke-3', async () => {
    const store = createLoginGuardStore({ stateFile: null, now: () => T0 })
    const handler = makeHandler(store)

    for (let index = 1; index <= ATTEMPTS; index += 1) {
      const granted = await handler(post(LOGIN_GUARD_ACQUIRE_PATH, { clientId: SOURCE_X.clientId, email: SOURCE_X.email }))
      expect(granted?.status).toBe(200)
      const body = await bodyOf(granted)
      expect(body.allowed).toBe(true)
      expect(body.attemptsLeft).toBe(ATTEMPTS - (index - 1))
      expect(body.attemptsPerLevel).toBe(ATTEMPTS)

      const reported = await handler(
        post(LOGIN_GUARD_REPORT_PATH, {
          clientId: SOURCE_X.clientId,
          email: SOURCE_X.email,
          outcome: 'credential-failure',
          token: body.token,
        }),
      )
      expect(reported?.status).toBe(200)
      const report = await bodyOf(reported)
      expect(report.attemptsLeft).toBe(ATTEMPTS - index)
      expect(report.retryAfterMs).toBe(index === ATTEMPTS ? 2 * 60_000 : 0)
    }

    const denied = await handler(post(LOGIN_GUARD_ACQUIRE_PATH, { clientId: SOURCE_X.clientId, email: SOURCE_X.email }))
    expect(denied?.status).toBe(429)
    expect(Number(denied?.headers.get('retry-after'))).toBeGreaterThanOrEqual(120)
    const text = await denied?.text()
    expect(text).not.toContain(SOURCE_X.email)
    expect(text).not.toContain(SOURCE_X.ip)
    expect(denied?.headers.get('cache-control')).toBe('no-store')
    expect(denied?.headers.get('x-content-type-options')).toBe('nosniff')
  })

  it('status melaporkan sisa kesempatan dan sisa cooldown dari waktu server', async () => {
    const store = createLoginGuardStore({ stateFile: null, now: () => T0 })
    const handler = makeHandler(store)
    const statusRequest = () =>
      new Request(`http://127.0.0.1:8790${LOGIN_GUARD_STATUS_PATH}?clientId=${SOURCE_X.clientId}`, {
        headers: { origin: ORIGIN, 'cf-connecting-ip': SOURCE_X.ip },
      })

    await handler(post(LOGIN_GUARD_REPORT_PATH, { clientId: SOURCE_X.clientId, outcome: 'credential-failure' }))
    const partial = await bodyOf(await handler(statusRequest()))
    expect(partial.active).toBe(false)
    expect(partial.attemptsLeft).toBe(2)

    await handler(post(LOGIN_GUARD_REPORT_PATH, { clientId: SOURCE_X.clientId, outcome: 'credential-failure' }))
    await handler(post(LOGIN_GUARD_REPORT_PATH, { clientId: SOURCE_X.clientId, outcome: 'credential-failure' }))

    const response = await handler(statusRequest())
    const body = await bodyOf(response)
    expect(response?.status).toBe(200)
    expect(body.active).toBe(true)
    expect(body.retryAfterMs).toBe(2 * 60_000)
    expect(body.attemptsLeft).toBe(0)
    expect(JSON.stringify(body)).not.toContain(SOURCE_X.email)
  })

  it('memvalidasi metode, tipe konten, dan bentuk body', async () => {
    const store = createLoginGuardStore({ stateFile: null, now: () => T0 })
    const handler = makeHandler(store)

    const wrongMethod = await handler(
      new Request(`http://127.0.0.1:8790${LOGIN_GUARD_ACQUIRE_PATH}`, { method: 'GET', headers: { origin: ORIGIN } }),
    )
    expect(wrongMethod?.status).toBe(405)

    const wrongType = await handler(
      new Request(`http://127.0.0.1:8790${LOGIN_GUARD_ACQUIRE_PATH}`, {
        method: 'POST',
        headers: { origin: ORIGIN, 'content-type': 'text/plain' },
        body: '{}',
      }),
    )
    expect(wrongType?.status).toBe(415)

    const badJson = await handler(post(LOGIN_GUARD_ACQUIRE_PATH, 'bukan json' as unknown as Record<string, unknown>))
    expect(badJson?.status).toBe(400)

    const badOutcome = await handler(post(LOGIN_GUARD_REPORT_PATH, { clientId: SOURCE_X.clientId, outcome: 'mungkin-salah' }))
    expect(badOutcome?.status).toBe(400)

    // Outcome yang tidak dikenal tidak boleh mengubah keadaan apa pun.
    const status = store.status(SOURCE_X, T0)
    expect(status.failures).toBe(0)
    expect(status.attemptsLeft).toBe(ATTEMPTS)
  })

  it('menolak origin yang tidak diizinkan dan mengembalikan 204 untuk preflight', async () => {
    const store = createLoginGuardStore({ stateFile: null, now: () => T0 })
    const handler = makeHandler(store)

    const forbidden = await handler(post(LOGIN_GUARD_ACQUIRE_PATH, { clientId: SOURCE_X.clientId }, { origin: 'http://jahat.test' }))
    expect(forbidden?.status).toBe(403)
    expect(forbidden?.headers.get('access-control-allow-origin')).toBeNull()

    const preflight = await handler(
      new Request(`http://127.0.0.1:8790${LOGIN_GUARD_ACQUIRE_PATH}`, { method: 'OPTIONS', headers: { origin: ORIGIN } }),
    )
    expect(preflight?.status).toBe(204)
    expect(preflight?.headers.get('access-control-allow-methods')).toContain('POST')
  })

  it('bukan rute gerbang -> handler mengembalikan null sehingga Worker yang memproses', async () => {
    const store = createLoginGuardStore({ stateFile: null, now: () => T0 })
    const handler = makeHandler(store)
    const other = await handler(
      new Request('http://127.0.0.1:8790/scan', { method: 'POST', headers: { origin: ORIGIN }, body: '{}' }),
    )
    expect(other).toBeNull()
  })
})

describe('VGL-41C — angka kesempatan hanya milik siklus sumbernya sendiri', () => {
  const ANON_ON_X = { ip: SOURCE_X.ip, clientId: null, email: 'sasaran@contoh.com' }

  it('kegagalan klien ber-identifier tidak memakan siklus bucket IP di IP yang sama', () => {
    const { store, now } = withClock()

    // Dua kredensial salah dari browser yang punya pengenal sumber.
    failTimes(store, SOURCE_X, now(), 2)
    expect(store.status(SOURCE_X, now()).attemptsLeft).toBe(1)

    // IP yang sama dipakai klien TANPA pengenal (mode privat, pengenal ditolak, permintaan
    // langsung): siklusnya harus tetap penuh, bukan sisa hasil orang lain.
    const anon = store.status(ANON_ON_X, now())
    expect(anon.failures).toBe(0)
    expect(anon.attemptsLeft).toBe(ATTEMPTS)

    // ...dan benar-benar boleh memakai ketiga kesempatan itu sebelum cooldown berlaku.
    const first = attempt(store, ANON_ON_X, 'credential-failure', now())
    expect(first.gate.attemptsLeft).toBe(ATTEMPTS)
    expect(first.report?.retryAfterMs).toBe(0)
    expect(first.report?.attemptsLeft).toBe(2)

    const second = attempt(store, ANON_ON_X, 'credential-failure', now())
    expect(second.report?.retryAfterMs).toBe(0)
    expect(second.report?.attemptsLeft).toBe(1)

    const third = attempt(store, ANON_ON_X, 'credential-failure', now())
    expect(third.report?.retryAfterMs).toBe(STEPS[0])
    expect(third.report?.attemptsLeft).toBe(0)
  })

  it('keadaan "nol kesempatan tanpa cooldown" tidak pernah dilaporkan dari berkas tercemar', () => {
    const directory = mkdtempSync(join(tmpdir(), 'vgl41c-guard-'))
    const file = join(directory, 'login-guard.json')
    const seed = createLoginGuardStore({ stateFile: file, now: () => T0 })
    failTimes(seed, SOURCE_X, T0, 2)

    try {
      // Bentuk berkas yang pernah ditulis oleh bug ini: bucket IP menampung `failures` dari
      // klien ber-identifier, angka yang tidak mungkin dicapai satu siklus sumber (>= ATTEMPTS).
      const written = JSON.parse(readFileSync(file, 'utf8')) as {
        secret: string
        sources: Record<string, unknown>
        ips: Record<string, unknown>
        accounts: Record<string, unknown>
      }
      const ipKey = Object.keys(written.ips)[0]
      expect(ipKey).toBeTruthy()
      written.ips[ipKey] = { ...(written.ips[ipKey] as object), failures: 5, level: 1, total: 12 }
      writeFileSync(file, JSON.stringify(written), 'utf8')

      const reopened = createLoginGuardStore({ stateFile: file, now: () => T0 })
      const anon = reopened.status(ANON_ON_X, T0)
      expect(anon.failures).toBe(0)
      expect(anon.attemptsLeft).toBe(ATTEMPTS)
      expect(anon.active).toBe(false)
      expect(anon.level).toBe(1)

      // Angka `total` tetap utuh: ambang proporsional lapisan IP (8 kegagalan) tidak hilang.
      const granted = reopened.acquire(ANON_ON_X, T0)
      expect(granted.allowed).toBe(true)
      expect(granted.attemptsLeft).toBe(ATTEMPTS)

      // Satu kegagalan kredensial tidak boleh langsung menghukum: baru kegagalan ke-3 yang menutup.
      const one = reopened.report(ANON_ON_X, 'credential-failure', granted.token, T0)
      expect(one.retryAfterMs).toBe(0)
      expect(one.attemptsLeft).toBe(2)
    } finally {
      rmSync(directory, { recursive: true, force: true })
    }
  })

  it('sumber yang bersih tetap memberi 3 kesempatan penuh setelah cooldown berakhir', () => {
    const { store, now, advance } = withClock()
    failTimes(store, SOURCE_X, now())

    expect(store.acquire(SOURCE_X, now()).allowed).toBe(false)
    advance(STEPS[0] + 1)

    const afterCooldown = store.status(SOURCE_X, now())
    expect(afterCooldown.active).toBe(false)
    expect(afterCooldown.failures).toBe(0)
    expect(afterCooldown.attemptsLeft).toBe(ATTEMPTS)
  })
})

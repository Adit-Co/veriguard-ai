// @vitest-environment jsdom

// VGL-41C — harness siklus kesempatan. Klien gerbang (cermin + UI) dijalankan terhadap
// GERBANG SERVER NYATA (createLoginGuardStore + createLoginGuardHandler) di bawah jam palsu,
// jadi angka yang diuji berasal dari sumber otoritatif, bukan dari stub yang ditulis sepihak.
import { beforeEach, describe, expect, it } from 'vitest'
import {
  createLoginGuardHandler,
  createLoginGuardStore,
  LOGIN_COOLDOWN_STEPS_MS,
  LOGIN_GUARD_ATTEMPTS_PER_LEVEL,
} from '../../../../server/src/loginGuard'
import {
  acquireLoginAttempt,
  clearLoginGuardLocalState,
  LOGIN_COOLDOWN_STORAGE_KEY,
  readLoginCooldown,
  reportLoginAttempt,
  type LoginGuardCooldown,
} from './loginGuard'

const API = 'http://127.0.0.1:8787'
const IP = '203.0.113.7'
const START = 1_780_000_000_000

function fakeClock(start = START) {
  let now = start
  return {
    now: () => now,
    at: () => now,
    advance: (ms: number) => {
      now += ms
    },
  }
}

function setup() {
  const clock = fakeClock()
  const store = createLoginGuardStore({ stateFile: null, now: clock.now })
  const handler = createLoginGuardHandler({ store, allowedOrigins: '', now: clock.now })
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(String(input), init)
    // Lapisan HTTP membaca IP dari header, sama seperti permintaan asli dari jaringan.
    const forwarded = new Request(request, { headers: new Headers({ ...Object.fromEntries(request.headers), 'cf-connecting-ip': IP }) })
    const response = await handler(forwarded)
    if (!response) throw new TypeError('rute gerbang tidak dikenali')
    return response
  }) as unknown as typeof fetch

  const options = { apiBase: API, now: clock.now, fetchImpl }
  return { clock, store, options }
}

function readMirror(): { endsAt: number; writtenAt: number; level: number; failures: number } | null {
  const raw = window.localStorage.getItem(LOGIN_COOLDOWN_STORAGE_KEY)
  return raw ? (JSON.parse(raw) as never) : null
}

beforeEach(() => {
  window.localStorage.clear()
  clearLoginGuardLocalState()
})

describe('VGL-41C — siklus 1: tiga kegagalan menutup sumber dan memberi 3 kesempatan baru sesudah cooldown', () => {
  it('kegagalan 1 dan 2 hanya mengurangi kesempatan (server dan cermin sepakat)', async () => {
    const { options } = setup()

    for (const [index, expectedLeft] of [2, 1].entries()) {
      const { handle, cooldown } = await acquireLoginAttempt('korban@contoh.com', options)
      expect(cooldown.active).toBe(false)
      expect(cooldown.attemptsLeft).toBe(LOGIN_GUARD_ATTEMPTS_PER_LEVEL - index)
      await reportLoginAttempt(handle, 'korban@contoh.com', 'credential-failure', options)
      expect(cooldown.attemptsLeft).toBe(LOGIN_GUARD_ATTEMPTS_PER_LEVEL - index)
      expect(expectedLeft).toBe(LOGIN_GUARD_ATTEMPTS_PER_LEVEL - index - 1)

      const status = await readLoginCooldown(options)
      expect(status.attemptsLeft).toBe(expectedLeft)
      expect(status.active).toBe(false)
      expect(readMirror()?.failures).toBe(index + 1)
    }
  })

  it('kegagalan ke-3 mengaktifkan cooldown tingkat awal selama 2 menit', async () => {
    const { clock, options } = setup()

    for (let index = 0; index < 2; index += 1) {
      const { handle } = await acquireLoginAttempt('korban@contoh.com', options)
      await reportLoginAttempt(handle, 'korban@contoh.com', 'credential-failure', options)
    }

    const third = await acquireLoginAttempt('korban@contoh.com', options)
    await reportLoginAttempt(third.handle, 'korban@contoh.com', 'credential-failure', options)

    const locked = await acquireLoginAttempt('korban@contoh.com', options)
    expect(locked.cooldown.active).toBe(true)
    expect(locked.cooldown.retryAfterMs).toBe(LOGIN_COOLDOWN_STEPS_MS[0])
    expect(locked.cooldown.attemptsLeft).toBe(0)
    expect(locked.handle.token).toBeNull()

    // Jam berjalan menuju akhir cooldown: kesempatan masih nol, bukan nol setengah.
    clock.advance(LOGIN_COOLDOWN_STEPS_MS[0] - 1_000)
    const nearEnd = await readLoginCooldown(options)
    expect(nearEnd.active).toBe(true)
    expect(nearEnd.attemptsLeft).toBe(0)
  })

  it('SESUDAH cooldown berakhir, penghitung kembali nol dan sumber mendapat 3 kesempatan baru', async () => {
    const { clock, options, store } = setup()

    for (let index = 0; index < LOGIN_GUARD_ATTEMPTS_PER_LEVEL; index += 1) {
      const { handle } = await acquireLoginAttempt('korban@contoh.com', options)
      if (handle.token || index < 2) await reportLoginAttempt(handle, 'korban@contoh.com', 'credential-failure', options)
    }

    const mirrorDuringLock = readMirror()
    expect(mirrorDuringLock).not.toBeNull()

    clock.advance(LOGIN_COOLDOWN_STEPS_MS[0] + 1)

    // Sumber otoritatif lebih dulu: status server.
    const status = await readLoginCooldown(options)
    expect(status.active).toBe(false)
    expect(status.attemptsLeft).toBe(LOGIN_GUARD_ATTEMPTS_PER_LEVEL)
    expect(status.failures).toBe(0)
    expect(status.level).toBe(1)

    // Cermin harus ikut pulih, tidak menyimpan sisa siklus lama.
    expect(readMirror()?.failures).toBe(0)

    // Percobaan berikutnya benar-benar diberi 3 kesempatan oleh gerbang.
    const next = await acquireLoginAttempt('korban@contoh.com', options)
    expect(next.cooldown.attemptsLeft).toBe(LOGIN_GUARD_ATTEMPTS_PER_LEVEL)
    expect(next.handle.token).toBeTruthy()

    // ...dan siklus kedua mengulang pola yang sama: 2 kegagalan -> 1 kesempatan.
    await reportLoginAttempt(next.handle, 'korban@contoh.com', 'credential-failure', options)
    const afterOne = await readLoginCooldown(options)
    expect(afterOne.attemptsLeft).toBe(2)
    expect(store.stats().sources).toBeGreaterThan(0)
  })

  it('tingkat naik tiap siklus tetapi kesempatan per siklus tetap tepat 3', async () => {
    const { clock, options } = setup()

    for (let cycle = 0; cycle < 3; cycle += 1) {
      for (let failure = 0; failure < LOGIN_GUARD_ATTEMPTS_PER_LEVEL; failure += 1) {
        const { handle } = await acquireLoginAttempt('korban@contoh.com', options)
        await reportLoginAttempt(handle, 'korban@contoh.com', 'credential-failure', options)
      }
      const locked = await acquireLoginAttempt('korban@contoh.com', options)
      expect(locked.cooldown.active).toBe(true)
      expect(locked.cooldown.retryAfterMs).toBe(LOGIN_COOLDOWN_STEPS_MS[cycle])
      expect(locked.cooldown.level).toBe(cycle + 1)
      expect(locked.cooldown.attemptsLeft).toBe(0)

      clock.advance(LOGIN_COOLDOWN_STEPS_MS[cycle] + 1)
      const freed = await readLoginCooldown(options)
      expect(freed.active).toBe(false)
      expect(freed.attemptsLeft).toBe(LOGIN_GUARD_ATTEMPTS_PER_LEVEL)
      expect(freed.failures).toBe(0)
    }
  })
})

describe('VGL-41C — penolakan non-kredensial tidak boleh menyamar sebagai cooldown', () => {
  it('penolakan paralel (busy) tidak mengurangi kesempatan dan tidak meninggalkan angka basi', async () => {
    const { clock, options } = setup()

    // Dua akuisisi paralel memakai slot in-flight; yang ketiga ditolak "busy".
    const first = await acquireLoginAttempt('korban@contoh.com', options)
    const second = await acquireLoginAttempt('korban@contoh.com', options)
    const third = await acquireLoginAttempt('korban@contoh.com', options)

    expect(first.handle.token).toBeTruthy()
    expect(second.handle.token).toBeTruthy()
    expect(third.cooldown.authority).toBe('server')
    expect(third.cooldown.active).toBe(true)
    expect(third.cooldown.retryAfterMs).toBe(30_000)

    // Kedua percobaan nyata gagal: hanya dua kegagalan yang boleh tercatat.
    await reportLoginAttempt(first.handle, 'korban@contoh.com', 'credential-failure', options)
    await reportLoginAttempt(second.handle, 'korban@contoh.com', 'credential-failure', options)

    clock.advance(30_001)
    const afterBusy = await readLoginCooldown(options)
    expect(afterBusy.active).toBe(false)
    // Dua kredensial salah memang memakai dua kesempatan: sisanya 1, dan itu benar.
    expect(afterBusy.attemptsLeft).toBe(1)

    // Kegagalan ke-3 menutup siklus; setelah cooldown harus 3 lagi.
    const remaining = await acquireLoginAttempt('korban@contoh.com', options)
    await reportLoginAttempt(remaining.handle, 'korban@contoh.com', 'credential-failure', options)
    clock.advance(LOGIN_COOLDOWN_STEPS_MS[0] + 1)
    const freed = await readLoginCooldown(options)
    expect(freed.attemptsLeft).toBe(LOGIN_GUARD_ATTEMPTS_PER_LEVEL)
  })

  it('cermin tidak boleh menahan angka kesempatan dari penolakan yang sudah lewat', async () => {
    const { clock, options } = setup()

    await acquireLoginAttempt('korban@contoh.com', options)
    const parallel = await acquireLoginAttempt('korban@contoh.com', options)
    await acquireLoginAttempt('korban@contoh.com', options)
    // Sumber dilaporkan gagal tanpa cooldown aktif.
    await reportLoginAttempt(parallel.handle, 'korban@contoh.com', 'credential-failure', options)

    const mirror = readMirror()
    expect(mirror?.failures).toBe(1)

    clock.advance(1_000)
    const status = await readLoginCooldown(options)
    expect(status.attemptsLeft).toBe(LOGIN_GUARD_ATTEMPTS_PER_LEVEL - 1)
  })
})

describe('VGL-41C — muat ulang, jam mundur, dan login berhasil', () => {
  it('muat ulang halaman saat cooldown tetap mengunci dari waktu server', async () => {
    const { clock, options } = setup()

    for (let index = 0; index < LOGIN_GUARD_ATTEMPTS_PER_LEVEL; index += 1) {
      const { handle } = await acquireLoginAttempt('korban@contoh.com', options)
      await reportLoginAttempt(handle, 'korban@contoh.com', 'credential-failure', options)
    }

    // "Muat ulang": baca ulang murni dari cermin lalu dari status server.
    const mirrored = await readLoginCooldown({ apiBase: undefined, now: clock.now })
    expect(mirrored.active).toBe(true)
    expect(mirrored.retryAfterMs).toBeGreaterThan(LOGIN_COOLDOWN_STEPS_MS[0] - 5_000)

    const refreshed = await readLoginCooldown(options)
    expect(refreshed.active).toBe(true)
    expect(refreshed.attemptsLeft).toBe(0)

    clock.advance(LOGIN_COOLDOWN_STEPS_MS[0] + 1)
    const afterReload = await readLoginCooldown(options)
    expect(afterReload.active).toBe(false)
    expect(afterReload.attemptsLeft).toBe(LOGIN_GUARD_ATTEMPTS_PER_LEVEL)
  })

  it('jam perangkat dimundurkan tidak memperpendek masa tunggu', async () => {
    const { clock, options } = setup()
    for (let index = 0; index < LOGIN_GUARD_ATTEMPTS_PER_LEVEL; index += 1) {
      const { handle } = await acquireLoginAttempt('korban@contoh.com', options)
      await reportLoginAttempt(handle, 'korban@contoh.com', 'credential-failure', options)
    }

    clock.advance(-60_000)
    const cooldown: LoginGuardCooldown = await readLoginCooldown({ apiBase: undefined, now: clock.now })
    expect(cooldown.active).toBe(true)
    expect(cooldown.retryAfterMs).toBeGreaterThan(LOGIN_COOLDOWN_STEPS_MS[0])
  })

  it('login berhasil mengembalikan 3 kesempatan dan tingkat ke awal walau cooldown belum habis', async () => {
    const { clock, options } = setup()
    for (let index = 0; index < LOGIN_GUARD_ATTEMPTS_PER_LEVEL; index += 1) {
      const { handle } = await acquireLoginAttempt('korban@contoh.com', options)
      await reportLoginAttempt(handle, 'korban@contoh.com', 'credential-failure', options)
    }

    clock.advance(LOGIN_COOLDOWN_STEPS_MS[0] / 2)
    const lockedStill = await readLoginCooldown(options)
    expect(lockedStill.active).toBe(true)

    // Sumber yang sama melapor berhasil (mis. sesi dipulihkan): gerbang melepas kunci sumber.
    const { handle } = await acquireLoginAttempt('korban@contoh.com', options)
    expect(handle.token).toBeNull()
    await reportLoginAttempt(handle, 'korban@contoh.com', 'success', options)

    const afterSuccess = await readLoginCooldown(options)
    expect(afterSuccess.active).toBe(false)
    expect(afterSuccess.level).toBe(0)
    expect(afterSuccess.attemptsLeft).toBe(LOGIN_GUARD_ATTEMPTS_PER_LEVEL)
    expect(readMirror()).toBeNull()
  })
})

describe('VGL-41C — cermin tidak boleh menampilkan kesempatan habis saat sumber tidak terkunci', () => {
  it('cermin berisi angka siklus basi (failures >= 3, tanpa cooldown) dipulihkan ke 3 kesempatan', async () => {
    const clock = fakeClock()
    window.localStorage.setItem(
      LOGIN_COOLDOWN_STORAGE_KEY,
      JSON.stringify({ endsAt: clock.at(), writtenAt: clock.at(), level: 1, failures: 5 }),
    )

    // Tanpa gerbang: lapisan cadangan satu-satunya penentu tampilan.
    const mirrored = await readLoginCooldown({ apiBase: undefined, now: clock.now })
    expect(mirrored.active).toBe(false)
    expect(mirrored.attemptsLeft).toBe(LOGIN_GUARD_ATTEMPTS_PER_LEVEL)
  })

  it('angka server yang sah tetap dipakai apa adanya: 1 kesempatan sisa tidak digubah', async () => {
    const { options } = setup()
    for (let index = 0; index < 2; index += 1) {
      const { handle } = await acquireLoginAttempt('korban@contoh.com', options)
      await reportLoginAttempt(handle, 'korban@contoh.com', 'credential-failure', options)
    }

    const status = await readLoginCooldown(options)
    expect(status.attemptsLeft).toBe(1)
    expect(status.active).toBe(false)
  })
})

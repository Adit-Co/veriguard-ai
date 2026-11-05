// @vitest-environment jsdom

import { beforeEach, describe, expect, it } from 'vitest'
import {
  acquireLoginAttempt,
  LOGIN_GUARD_MIRROR_HISTORY_MS,
  classifyLoginError,
  clearLoginGuardLocalState,
  LOGIN_COOLDOWN_STORAGE_KEY,
  LOGIN_CLIENT_ID_STORAGE_KEY,
  loginClientId,
  readLoginCooldown,
  reportLoginAttempt,
} from './loginGuard'

const API = 'http://127.0.0.1:8787'
const STEPS_MS = [120_000, 3_600_000, 10_800_000, 21_600_000, 43_200_000, 86_400_000]

function fakeClock(start = 1_780_000_000_000) {
  let now = start
  return { now: () => now, at: () => now, advance: (ms: number) => (now += ms), set: (value: number) => (now = value) }
}

type Stub = { status: number; body?: unknown }

function gateFetch(stubs: Stub[]) {
  const calls: { url: string; init?: RequestInit }[] = []
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const stub = stubs.shift() ?? { status: 200, body: { allowed: true, token: 't', retryAfterMs: 0, level: 0, failures: 0, serverTime: 0 } }
    calls.push({ url: String(input), ...(init ? { init } : {}) })
    return new Response(stub.body === undefined ? null : JSON.stringify(stub.body), {
      status: stub.status,
      headers: { 'content-type': 'application/json' },
    })
  }) as unknown as typeof fetch

  return { fetchImpl, calls }
}

beforeEach(() => {
  window.localStorage.clear()
  clearLoginGuardLocalState()
})

describe('VGL-38 — klien gerbang mengikuti keputusan server', () => {
  it('penolakan 429 dari gerbang menahan percobaan dan mencatat cermin', async () => {
    const clock = fakeClock()
    const { fetchImpl } = gateFetch([
      {
        status: 429,
        body: { allowed: false, reason: 'cooldown', retryAfterMs: STEPS_MS[0], level: 1, failures: 1, serverTime: clock.at() },
      },
    ])

    const first = await acquireLoginAttempt('sasaran@contoh.com', { apiBase: API, now: clock.now, fetchImpl })
    expect(first.cooldown.active).toBe(true)
    expect(first.cooldown.retryAfterMs).toBe(STEPS_MS[0])
    expect(first.cooldown.authority).toBe('server')
    expect(first.handle.token).toBeNull()

    const mirror = window.localStorage.getItem(LOGIN_COOLDOWN_STORAGE_KEY)
    expect(mirror).toBeTruthy()
    // Privasi: cermin hanya menyimpan angka, tidak pernah email, kata sandi, atau token.
    expect(mirror).not.toContain('sasaran@contoh.com')
    expect(mirror).not.toContain('password')
  })

  it('jawaban server selalu menimpa cermin, termasuk saat menyatakan sumber ini bebas', async () => {
    const clock = fakeClock()
    window.localStorage.setItem(
      LOGIN_COOLDOWN_STORAGE_KEY,
      JSON.stringify({ endsAt: clock.at() + STEPS_MS[5], level: 6, failures: 6 }),
    )

    const { fetchImpl } = gateFetch([{ status: 200, body: { allowed: true, token: 'abc', retryAfterMs: 0, level: 0, failures: 0, serverTime: clock.at() } }])
    const result = await acquireLoginAttempt('sasaran@contoh.com', { apiBase: API, now: clock.now, fetchImpl })

    expect(result.cooldown.active).toBe(false)
    expect(result.handle.token).toBe('abc')
    expect(window.localStorage.getItem(LOGIN_COOLDOWN_STORAGE_KEY)).toBeNull()
  })

  it('tingkat cooldown yang dilaporkan server dipakai apa adanya (2 menit s/d 24 jam)', async () => {
    for (const [index, step] of STEPS_MS.entries()) {
      const clock = fakeClock()
      const { fetchImpl } = gateFetch([
        { status: 429, body: { allowed: false, retryAfterMs: step, level: index + 1, failures: index + 1, serverTime: clock.at() } },
      ])
      const result = await acquireLoginAttempt('sasaran@contoh.com', { apiBase: API, now: clock.now, fetchImpl })
      expect(result.cooldown.retryAfterMs).toBe(step)
      expect(result.cooldown.level).toBe(index + 1)
    }
  })

  it('gerbang yang tidak terjangkau tidak memblokir login dan tidak mengarang cooldown', async () => {
    const clock = fakeClock()
    const fetchImpl = (async () => {
      throw new TypeError('Failed to fetch')
    }) as unknown as typeof fetch

    const result = await acquireLoginAttempt('sasaran@contoh.com', { apiBase: API, now: clock.now, fetchImpl })
    expect(result.cooldown.active).toBe(false)
    expect(result.cooldown.authority).toBe('local')
  })

  it('status endpoint menjadi sumber countdown setelah halaman dimuat ulang', async () => {
    const clock = fakeClock()
    const { fetchImpl } = gateFetch([
      { status: 200, body: { active: true, retryAfterMs: STEPS_MS[1], level: 2, failures: 2, serverTime: clock.at() } },
    ])

    const cooldown = await readLoginCooldown({ apiBase: API, now: clock.now, fetchImpl })
    expect(cooldown.active).toBe(true)
    expect(cooldown.retryAfterMs).toBe(STEPS_MS[1])
    expect(cooldown.authority).toBe('server')
  })
})

describe('VGL-38 — cermin lokal sebagai lapisan cadangan', () => {
  it('tanpa gerbang, tiga kegagalan kredensial menaikkan satu tingkat pada tangga yang sama', async () => {
    const clock = fakeClock()
    const options = { apiBase: '', now: clock.now }

    for (const [index, step] of STEPS_MS.entries()) {
      // Dua kegagalan pertama hanya mengurangi kesempatan, tidak mengunci.
      for (const expected of [2, 1]) {
        const acquire = await acquireLoginAttempt('sasaran@contoh.com', options)
        expect(acquire.cooldown.active).toBe(false)
        expect(acquire.cooldown.level).toBe(index)
        expect(acquire.cooldown.attemptsLeft).toBe(expected + 1)

        await reportLoginAttempt(acquire.handle, 'sasaran@contoh.com', 'credential-failure', options)

        const stillOpen = await acquireLoginAttempt('sasaran@contoh.com', options)
        expect(stillOpen.cooldown.active).toBe(false)
        expect(stillOpen.cooldown.attemptsLeft).toBe(expected)
      }

      // Kegagalan ketiga mengaktifkan cooldown tingkat ini.
      const acquire = await acquireLoginAttempt('sasaran@contoh.com', options)
      expect(acquire.cooldown.attemptsLeft).toBe(1)
      await reportLoginAttempt(acquire.handle, 'sasaran@contoh.com', 'credential-failure', options)

      const blocked = await acquireLoginAttempt('sasaran@contoh.com', options)
      expect(blocked.cooldown.active).toBe(true)
      expect(blocked.cooldown.level).toBe(index + 1)
      expect(blocked.cooldown.attemptsLeft).toBe(0)
      expect(blocked.cooldown.retryAfterMs).toBe(step)

      clock.advance(step)
    }

    // Tingkat terakhir (24 jam) habis: sumber boleh mencoba lagi, dan kegagalan berikutnya
    // TETAP memakai tangga di tingkat puncak karena riwayatnya belum dibuang.
    const afterTop = await acquireLoginAttempt('sasaran@contoh.com', options)
    expect(afterTop.cooldown.active).toBe(false)
    expect(afterTop.cooldown.level).toBe(STEPS_MS.length)
    for (let index = 0; index < 3; index += 1) {
      const retry = await acquireLoginAttempt('sasaran@contoh.com', options)
      await reportLoginAttempt(retry.handle, 'sasaran@contoh.com', 'credential-failure', options)
    }
    expect((await acquireLoginAttempt('sasaran@contoh.com', options)).cooldown.retryAfterMs).toBe(
      STEPS_MS[STEPS_MS.length - 1],
    )

    // Riwayat punya masa kedaluwarsa: cooldown tuntas + tidak ada aktivitas selama 24 jam.
    clock.advance(STEPS_MS[STEPS_MS.length - 1] + LOGIN_GUARD_MIRROR_HISTORY_MS + 1)
    const fresh = await acquireLoginAttempt('sasaran@contoh.com', options)
    expect(fresh.cooldown.failures).toBe(0)
    expect(fresh.cooldown.attemptsLeft).toBe(3)
    expect(window.localStorage.getItem(LOGIN_COOLDOWN_STORAGE_KEY)).toBeNull()
    await reportLoginAttempt(fresh.handle, 'sasaran@contoh.com', 'credential-failure', options)
    expect((await acquireLoginAttempt('sasaran@contoh.com', options)).cooldown.level).toBe(0)
  })

  it('kegagalan jaringan dan rate limit pihak layanan tidak menaikkan tingkat cermin', async () => {
    const clock = fakeClock()
    const options = { apiBase: '', now: clock.now }

    for (const outcome of ['network', 'rate-limited'] as const) {
      const acquire = await acquireLoginAttempt('sasaran@contoh.com', options)
      await reportLoginAttempt(acquire.handle, 'sasaran@contoh.com', outcome, options)

      const next = await acquireLoginAttempt('sasaran@contoh.com', options)
      expect(next.cooldown.active).toBe(false)
      expect(next.cooldown.level).toBe(0)
    }

    expect(window.localStorage.getItem(LOGIN_COOLDOWN_STORAGE_KEY)).toBeNull()
  })

  it('login berhasil menghapus riwayat dan mengembalikan 3 kesempatan', async () => {
    const clock = fakeClock()
    const options = { apiBase: '', now: clock.now }

    for (let index = 0; index < 2; index += 1) {
      const acquire = await acquireLoginAttempt('sasaran@contoh.com', options)
      await reportLoginAttempt(acquire.handle, 'sasaran@contoh.com', 'credential-failure', options)
    }
    expect((await acquireLoginAttempt('sasaran@contoh.com', options)).cooldown.attemptsLeft).toBe(1)

    const third = await acquireLoginAttempt('sasaran@contoh.com', options)
    await reportLoginAttempt(third.handle, 'sasaran@contoh.com', 'credential-failure', options)
    expect((await acquireLoginAttempt('sasaran@contoh.com', options)).cooldown.active).toBe(true)

    clock.advance(STEPS_MS[0])
    const reset = await acquireLoginAttempt('sasaran@contoh.com', options)
    await reportLoginAttempt(reset.handle, 'sasaran@contoh.com', 'success', options)

    const after = await acquireLoginAttempt('sasaran@contoh.com', options)
    expect(after.cooldown.active).toBe(false)
    expect(after.cooldown.level).toBe(0)
    expect(after.cooldown.attemptsLeft).toBe(3)
    expect(window.localStorage.getItem(LOGIN_COOLDOWN_STORAGE_KEY)).toBeNull()
  })

  it('memundurkan jam perangkat tidak memperpendek sisa cooldown', async () => {
    const clock = fakeClock()
    const { fetchImpl } = gateFetch([
      { status: 429, body: { allowed: false, retryAfterMs: STEPS_MS[0], level: 1, failures: 1, serverTime: clock.at() } },
    ])
    await acquireLoginAttempt('sasaran@contoh.com', { apiBase: API, now: clock.now, fetchImpl })

    clock.advance(60_000)
    const halfway = await readLoginCooldown({ apiBase: '', now: clock.now })
    expect(halfway.retryAfterMs).toBe(STEPS_MS[0] - 60_000)

    clock.set(clock.at() - 3_600_000)
    const rolledBack = await readLoginCooldown({ apiBase: '', now: clock.now })
    expect(rolledBack.retryAfterMs).toBeGreaterThan(halfway.retryAfterMs)
    expect(rolledBack.active).toBe(true)
  })

  it('pengenal sumber dibuat sekali dan dipakai ulang', () => {
    const first = loginClientId()
    expect(first).toMatch(/^web-[0-9a-f]{32}$/)
    expect(loginClientId()).toBe(first)
    expect(window.localStorage.getItem(LOGIN_CLIENT_ID_STORAGE_KEY)).toBe(first)
  })

  it('pengenal yang rusak diganti, bukan dipakai apa adanya', () => {
    window.localStorage.setItem(LOGIN_CLIENT_ID_STORAGE_KEY, '<disuntik>')
    const fresh = loginClientId()
    expect(fresh).toMatch(/^web-[0-9a-f]{32}$/)
    expect(fresh).not.toBe('<disuntik>')
  })

  it('endpoint gerbang yang tidak ada (404) tetap menaikkan cermin, 3 kegagalan per tingkat', async () => {
    const clock = fakeClock()
    const stubs: Array<{ status: number; body?: unknown }> = [
      { status: 200, body: { allowed: true, token: 't1', retryAfterMs: 0, level: 0, failures: 0, attemptsLeft: 3, serverTime: clock.at() } },
      { status: 404, body: { error: { code: 'not_found' } } },
      { status: 200, body: { allowed: true, token: 't1', retryAfterMs: 0, level: 0, failures: 1, attemptsLeft: 2, serverTime: clock.at() } },
      { status: 404, body: { error: { code: 'not_found' } } },
      { status: 200, body: { allowed: true, token: 't1', retryAfterMs: 0, level: 0, failures: 2, attemptsLeft: 1, serverTime: clock.at() } },
      { status: 404, body: { error: { code: 'not_found' } } },
    ]
    const { fetchImpl } = gateFetch(stubs)
    const gateOptions = { apiBase: API, now: clock.now, fetchImpl }

    for (let index = 0; index < 3; index += 1) {
      const acquire = await acquireLoginAttempt('sasaran@contoh.com', gateOptions)
      await reportLoginAttempt(acquire.handle, 'sasaran@contoh.com', 'credential-failure', gateOptions)
    }

    // Deployment tanpa gerbang: cermin adalah satu-satunya lapisan yang bergerak, dan ia
    // baru mengunci setelah kegagalan ketiga.
    const mirror = await readLoginCooldown({ apiBase: '', now: clock.now })
    expect(mirror.active).toBe(true)
    expect(mirror.level).toBe(1)
    expect(mirror.retryAfterMs).toBe(STEPS_MS[0])
    expect(mirror.attemptsLeft).toBe(0)
  })

  it('gerbang 5xx memakai cermin, tetapi penolakan 400 tidak mengarang keadaan', async () => {
    const clock = fakeClock()
    const { fetchImpl: unavailable } = gateFetch([
      { status: 200, body: { allowed: true, token: 't2', retryAfterMs: 0, level: 0, failures: 0, attemptsLeft: 3, serverTime: clock.at() } },
      { status: 503, body: null },
      { status: 200, body: { allowed: true, token: 't2', retryAfterMs: 0, level: 0, failures: 1, attemptsLeft: 2, serverTime: clock.at() } },
      { status: 503, body: null },
      { status: 200, body: { allowed: true, token: 't2', retryAfterMs: 0, level: 0, failures: 2, attemptsLeft: 1, serverTime: clock.at() } },
      { status: 503, body: null },
    ])
    const unavailableOptions = { apiBase: API, now: clock.now, fetchImpl: unavailable }
    for (let index = 0; index < 3; index += 1) {
      const acquire = await acquireLoginAttempt('sasaran@contoh.com', unavailableOptions)
      await reportLoginAttempt(acquire.handle, 'sasaran@contoh.com', 'credential-failure', unavailableOptions)
    }
    const mirrored = await readLoginCooldown({ apiBase: '', now: clock.now })
    expect(mirrored.level).toBe(1)
    expect(mirrored.retryAfterMs).toBe(STEPS_MS[0])

    const second = fakeClock()
    window.localStorage.clear()
    const { fetchImpl: rejected } = gateFetch([
      { status: 200, body: { allowed: true, token: 't3', retryAfterMs: 0, level: 0, failures: 0, attemptsLeft: 3, serverTime: second.at() } },
      { status: 400, body: { error: { code: 'invalid_request' } } },
    ])
    const rejectedOptions = { apiBase: API, now: second.now, fetchImpl: rejected }
    const acquire = await acquireLoginAttempt('sasaran@contoh.com', rejectedOptions)
    await reportLoginAttempt(acquire.handle, 'sasaran@contoh.com', 'credential-failure', rejectedOptions)

    // 400 = gerbang ada dan menolak permintaan ini; cermin tidak boleh naik.
    // (acquire di atas sudah diizinkan server, jadi cermin bersih sebelum laporan ini.)
    const after = await readLoginCooldown({ apiBase: '', now: second.now })
    expect(after.active).toBe(false)
    expect(after.attemptsLeft).toBe(3)
  })
})

describe('VGL-39A — cermin dan jawaban server membawa sisa kesempatan', () => {
  it('jawaban server yang memuat attemptsLeft dipakai apa adanya oleh klien', async () => {
    const clock = fakeClock()
    const { fetchImpl } = gateFetch([
      {
        status: 200,
        body: {
          allowed: true,
          token: 't',
          retryAfterMs: 0,
          level: 2,
          failures: 1,
          attemptsLeft: 2,
          attemptsPerLevel: 3,
          serverTime: clock.at(),
        },
      },
    ])

    const result = await acquireLoginAttempt('sasaran@contoh.com', { apiBase: API, now: clock.now, fetchImpl })
    expect(result.cooldown.attemptsLeft).toBe(2)
    expect(result.cooldown.attemptsPerLevel).toBe(3)
    expect(result.cooldown.level).toBe(2)
    // Cermin mengikuti angka server, bukan mengarang keadaan sendiri.
    expect(JSON.parse(window.localStorage.getItem(LOGIN_COOLDOWN_STORAGE_KEY) ?? '{}')).toMatchObject({
      level: 2,
      failures: 1,
    })
  })

  it('refresh tidak menambah kesempatan pada lapisan cadangan', async () => {
    const clock = fakeClock()
    const options = { apiBase: '', now: clock.now }

    const first = await acquireLoginAttempt('sasaran@contoh.com', options)
    await reportLoginAttempt(first.handle, 'sasaran@contoh.com', 'credential-failure', options)

    // "Muat ulang halaman": baca ulang keadaan, tidak ada kesempatan yang kembali.
    for (let index = 0; index < 5; index += 1) {
      const reread = await readLoginCooldown(options)
      expect(reread.attemptsLeft).toBe(2)
      expect(reread.active).toBe(false)
      const again = await acquireLoginAttempt('sasaran@contoh.com', options)
      expect(again.cooldown.attemptsLeft).toBe(2)
    }

    const second = await acquireLoginAttempt('sasaran@contoh.com', options)
    await reportLoginAttempt(second.handle, 'sasaran@contoh.com', 'credential-failure', options)
    expect((await readLoginCooldown(options)).attemptsLeft).toBe(1)

    const third = await acquireLoginAttempt('sasaran@contoh.com', options)
    await reportLoginAttempt(third.handle, 'sasaran@contoh.com', 'credential-failure', options)
    const locked = await readLoginCooldown(options)
    expect(locked.active).toBe(true)
    expect(locked.attemptsLeft).toBe(0)
    expect(locked.retryAfterMs).toBe(STEPS_MS[0])
  })

  it('percobaan saat cooldown berlangsung tidak menghabiskan kesempatan maupun menaikkan tingkat', async () => {
    const clock = fakeClock()
    const options = { apiBase: '', now: clock.now }

    for (let index = 0; index < 3; index += 1) {
      const acquire = await acquireLoginAttempt('sasaran@contoh.com', options)
      await reportLoginAttempt(acquire.handle, 'sasaran@contoh.com', 'credential-failure', options)
    }

    clock.advance(60_000)
    for (let index = 0; index < 10; index += 1) {
      const denied = await acquireLoginAttempt('sasaran@contoh.com', options)
      expect(denied.cooldown.active).toBe(true)
      expect(denied.handle.token).toBeNull()
    }

    clock.advance(60_000 + 1)
    const reopened = await readLoginCooldown(options)
    expect(reopened.active).toBe(false)
    expect(reopened.attemptsLeft).toBe(3)
    expect(reopened.level).toBe(1)
  })
})

describe('VGL-38 — klasifikasi hasil autentikasi', () => {
  it('hanya kegagalan kredensial yang dihitung sebagai password salah', () => {
    for (const code of ['auth/invalid-credential', 'auth/user-not-found', 'auth/wrong-password']) {
      expect(classifyLoginError(Object.assign(new Error('x'), { code }))).toBe('credential-failure')
    }
  })

  it('gangguan layanan dan rate limit pihak layanan dipisah dari kegagalan kredensial', () => {
    expect(classifyLoginError(Object.assign(new Error('x'), { code: 'auth/network-request-failed' }))).toBe('network')
    expect(classifyLoginError(Object.assign(new Error('x'), { code: 'auth/too-many-requests' }))).toBe('rate-limited')
    expect(classifyLoginError(Object.assign(new Error('x'), { code: 'auth/user-disabled' }))).toBe('network')
    expect(classifyLoginError(new Error('tanpa kode'))).toBe('network')
  })
})

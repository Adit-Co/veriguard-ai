import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { MultiSourceScanResponse } from '../../functions/src/scanners/types.js'
import type { RunMultiSourceScanInput } from '../../functions/src/scanners/service.js'
import type { TurnstileVerifyInput } from '../../functions/src/turnstile/verify.js'
import { createWorker, type Env } from '../src/index.js'
import type { FirebaseIdentity } from '../src/auth/firebaseToken.js'
import { createMemoryStateStore } from '../src/state/store.js'
import type { ScanStateStore } from '../src/state/store.js'
import { resetEdgeRateLimit } from '../src/rateLimit.js'
import { createStateStoreSpy } from './helpers/stateStore.js'
import type { StateStoreSpy } from './helpers/stateStore.js'

const ORIGIN = 'http://localhost:5173'
const NOW = 1_700_000_000_000
const IP = '203.0.113.10'
const SECRET = 'secret-auth-uji'

const ENV: Env = {
  ALLOWED_ORIGINS: ORIGIN,
  RATE_LIMIT_MAX_PER_IP: '30',
  RATE_LIMIT_WINDOW_SECONDS: '60',
  FIREBASE_PROJECT_ID: 'YOUR_FIREBASE_PROJECT_ID',
  TURNSTILE_SECRET_KEY: SECRET,
}

function scanResponse(): MultiSourceScanResponse {
  return {
    providers: [],
    sharedWithProviders: [],
    sensitiveUrl: false,
    privacyReasons: [],
    generatedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 10,
  }
}

type Harness = {
  worker: ExportedHandler<Env>
  runScan: ReturnType<typeof vi.fn>
  verifyFirebaseToken: ReturnType<typeof vi.fn>
  verifyTurnstile: ReturnType<typeof vi.fn>
  spy: StateStoreSpy
}

function makeHarness(options: {
  identity?: FirebaseIdentity
  turnstileOk?: boolean
  used?: number
  // Store bersama boleh disuntikkan agar dua harness berbagi keadaan, seperti dua isolate
  // yang menunjuk satu Durable Object.
  state?: ScanStateStore
} = {}): Harness {
  const runScan = vi.fn(async (_input: RunMultiSourceScanInput) => scanResponse())
  const verifyFirebaseToken = vi.fn(async () =>
    options.identity ?? { ok: true as const, uid: 'uid-sah', email: null, providerId: 'password' },
  )
  const verifyTurnstile = vi.fn(async (_input: TurnstileVerifyInput) =>
    options.turnstileOk === false ? { ok: false as const, reason: 'invalid_token' as const } : { ok: true as const },
  )
  const spy = createStateStoreSpy(options.used === undefined ? {} : { used: options.used })

  const worker = createWorker({
    runScan,
    verifyFirebaseToken,
    verifyTurnstile,
    state: options.state ?? spy.store,
    now: () => NOW,
    siteProbe: null,
  })

  return { worker, runScan, verifyFirebaseToken, verifyTurnstile, spy }
}

function post(body: unknown, headers: Record<string, string> = {}, path = '/scan'): Request {
  return new Request(`https://worker.test${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'CF-Connecting-IP': IP,
      Origin: ORIGIN,
      ...headers,
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}

async function invoke(worker: ExportedHandler<Env>, request: Request, env: Env = ENV) {
  if (!worker.fetch) throw new Error('Worker fetch handler tidak tersedia.')
  return worker.fetch(
    request as unknown as Request<unknown, IncomingRequestCfProperties<unknown>>,
    env,
    {} as ExecutionContext,
  )
}

const scanBody = { url: 'https://contoh.com', consent: true }

beforeEach(() => {
  // Satu kasus uji di bawah memakai store memori nyata, jadi pencacah modul dibersihkan
  // antar kasus agar tidak saling memengaruhi.
  resetEdgeRateLimit()
})

describe('P1-2: identitas pemanggil Worker', () => {
  it('memakai uid terverifikasi untuk pemeriksaan dan tidak meminta login untuk tamu', async () => {
    const tanpaToken = makeHarness()
    const tamu = await invoke(tanpaToken.worker, post(scanBody))
    expect(tamu.status).toBe(200)
    expect(tanpaToken.verifyFirebaseToken).not.toHaveBeenCalled()
    expect(tanpaToken.runScan.mock.calls[0]?.[0]).toMatchObject({ uid: `guest:${IP}` })

    const harness = makeHarness()
    const terisi = await invoke(harness.worker, post(scanBody, { Authorization: 'Bearer jwt-sah' }))
    expect(terisi.status).toBe(200)
    expect(harness.verifyFirebaseToken).toHaveBeenCalledTimes(1)
    expect(harness.verifyFirebaseToken.mock.calls[0]?.[0]).toBe('jwt-sah')
    expect(harness.runScan.mock.calls[0]?.[0]).toMatchObject({ uid: 'uid:uid-sah' })
  })

  it('menolak token yang terbukti tidak sah dengan 401 tanpa menjalankan pemeriksaan', async () => {
    for (const reason of [
      'signature',
      'expired',
      'issuer_mismatch',
      'audience_mismatch',
      'subject_invalid',
      'malformed',
      'unsupported_algorithm',
      'payload_invalid',
      'not_yet_valid',
      'too_large',
    ] as const) {
      const harness = makeHarness({ identity: { ok: false, reason } })
      const response = await invoke(harness.worker, post(scanBody, { Authorization: 'Bearer jwt-palsu' }))

      expect(response.status).toBe(401)
      expect(await response.json()).toMatchObject({ error: { code: 'invalid_token' } })
      expect(harness.runScan).not.toHaveBeenCalled()
    }
  })

  it('melanjutkan sebagai tamu bila kunci penandatangan tidak dapat diambil', async () => {
    const harness = makeHarness({ identity: { ok: false, reason: 'key_unavailable' } })
    const response = await invoke(harness.worker, post(scanBody, { Authorization: 'Bearer jwt-baru' }))

    expect(response.status).toBe(200)
    expect(harness.runScan.mock.calls[0]?.[0]).toMatchObject({ uid: `guest:${IP}` })
  })

  it('VGL-40: meneruskan host Auth Emulator lokal ke verifikasi token', async () => {
    const harness = makeHarness()
    await invoke(
      harness.worker,
      post(scanBody, { Authorization: 'Bearer jwt-emulator' }),
      { ...ENV, FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099' },
    )

    expect(harness.verifyFirebaseToken.mock.calls[0]?.[1]).toMatchObject({
      projectId: 'YOUR_FIREBASE_PROJECT_ID',
      emulatorHost: '127.0.0.1:9099',
    })

    const tanpa = makeHarness()
    await invoke(tanpa.worker, post(scanBody, { Authorization: 'Bearer jwt-emulator' }))
    expect(tanpa.verifyFirebaseToken.mock.calls[0]?.[1]).toMatchObject({ emulatorHost: undefined })
  })

  it('VGL-40: emulator menjawab bukan sesinya → 401; emulator tak terjangkau → tamu', async () => {
    const ditolak = makeHarness({ identity: { ok: false, reason: 'emulator_unverified' } })
    const responsDitolak = await invoke(
      ditolak.worker,
      post(scanBody, { Authorization: 'Bearer jwt-emulator' }),
      { ...ENV, FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099' },
    )
    expect(responsDitolak.status).toBe(401)
    expect(await responsDitolak.json()).toMatchObject({ error: { code: 'invalid_token' } })
    expect(ditolak.runScan).not.toHaveBeenCalled()

    const tidakTerjangkau = makeHarness({ identity: { ok: false, reason: 'emulator_unavailable' } })
    const responsTamu = await invoke(
      tidakTerjangkau.worker,
      post(scanBody, { Authorization: 'Bearer jwt-emulator' }),
      { ...ENV, FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099' },
    )
    expect(responsTamu.status).toBe(200)
    // Arah gagal dibedakan: tidak ada jalur yang memberi hak lebih tinggi dari tamu.
    expect(tidakTerjangkau.runScan.mock.calls[0]?.[0]).toMatchObject({ uid: `guest:${IP}` })
  })

  it('tidak memverifikasi token ketika proyek tidak dikonfigurasi', async () => {
    const harness = makeHarness()
    const response = await invoke(
      harness.worker,
      post(scanBody, { Authorization: 'Bearer jwt-saja' }),
      { ...ENV, FIREBASE_PROJECT_ID: undefined },
    )

    expect(response.status).toBe(200)
    expect(harness.verifyFirebaseToken).not.toHaveBeenCalled()
    expect(harness.runScan.mock.calls[0]?.[0]).toMatchObject({ uid: `guest:${IP}` })
  })

  it('mengabaikan header Authorization yang bukan Bearer sebagai tamu', async () => {
    const harness = makeHarness()
    const response = await invoke(
      harness.worker,
      post(scanBody, { Authorization: 'Basic b3BlbjpwYXNz' }),
    )

    expect(response.status).toBe(200)
    expect(harness.verifyFirebaseToken).not.toHaveBeenCalled()
  })

  it('tidak menulis token ke respons maupun hasil pemeriksaan', async () => {
    const harness = makeHarness()
    const response = await invoke(
      harness.worker,
      post(scanBody, { Authorization: 'Bearer JWT-RAHASIA-JANGAN-DIBOCORKAN' }),
    )
    const body = await response.text()

    expect(response.status).toBe(200)
    expect(body).not.toContain('JWT-RAHASIA-JANGAN-DIBOCORKAN')
    for (const call of harness.verifyFirebaseToken.mock.calls) {
      expect(JSON.stringify(call[1] ?? {})).not.toContain('JWT-RAHASIA-JANGAN-DIBOCORKAN')
    }
  })

  it('menambah batas per-uid untuk pengguna terverifikasi tanpa melepas batas per-IP', async () => {
    const spy = createStateStoreSpy({
      counter: ({ key }) => ({ allowed: key !== 'uid:uid-sah', retryAfterSeconds: 30 }),
    })
    const harness = makeHarness({ state: spy.store })

    const response = await invoke(harness.worker, post(scanBody, { Authorization: 'Bearer jwt-sah' }))

    expect(response.status).toBe(429)
    expect(await response.json()).toMatchObject({ error: { code: 'rate_limited' } })
    expect(response.headers.get('retry-after')).toBe('30')
    // Urutan kunci adalah bukti bahwa batas per-IP tidak dilepas ketika uid dipakai.
    expect(spy.counters.map((call) => call.key)).toEqual([`ip:${IP}`, 'uid:uid-sah'])
    expect(harness.runScan).not.toHaveBeenCalled()
  })

  it('Batas nol per IP menutup gerbang, bukan membukanya tanpa batas', async () => {
    // Store memori nyata dipakai di sini: yang diuji keputusan pencacah terhadap limit <= 0,
    // bukan angka yang dikarang spy. Sebelum P1-3, limit 0 membuat Worker tanpa batas.
    const runScan = vi.fn(async () => scanResponse())
    const worker = createWorker({
      runScan,
      state: createMemoryStateStore(),
      now: () => NOW,
      siteProbe: null,
    })
    const response = await invoke(
      worker,
      post(scanBody),
      { ...ENV, RATE_LIMIT_MAX_PER_IP: '0' },
    )

    expect(response.status).toBe(429)
    expect(await response.json()).toMatchObject({ error: { code: 'rate_limited' } })
    expect(Number(response.headers.get('retry-after'))).toBeGreaterThan(0)
    expect(runScan).not.toHaveBeenCalled()
  })

  it('izin CAPTCHA tersimpan per identitas, bukan hanya per IP', async () => {
    // Satu store dipakai bersama dua harness, meniru dua isolate yang menunjuk satu
    // Durable Object: izin untuk uid tidak boleh berlaku bagi tamu di IP yang sama.
    const shared = createStateStoreSpy({ used: 16 })
    const challenged = makeHarness({ state: shared.store })
    const first = await invoke(
      challenged.worker,
      post({ ...scanBody, captchaToken: 'token-scan' }, { Authorization: 'Bearer jwt-sah' }),
    )
    expect(first.status).toBe(200)
    expect(challenged.verifyTurnstile).toHaveBeenCalledTimes(1)
    expect(shared.clearanceIssues).toEqual([expect.stringContaining('uid:uid-sah')])

    const sameIpOther = makeHarness({ state: shared.store })
    const second = await invoke(sameIpOther.worker, post(scanBody))
    expect(second.status).toBe(428)
    expect(sameIpOther.verifyTurnstile).not.toHaveBeenCalled()
  })

  it('analisis situs memakai bucket uid ketika terverifikasi', async () => {
    const spy = createStateStoreSpy()
    const worker = createWorker({
      verifyFirebaseToken: vi.fn(async () => ({
        ok: true as const,
        uid: 'uid-sah',
        email: null,
        providerId: 'password',
      })),
      state: spy.store,
      now: () => NOW,
      siteProbe: null,
    })

    const response = await invoke(
      worker,
      post({ url: 'https://contoh.com', consent: true }, { Authorization: 'Bearer jwt-sah' }, '/site/analysis'),
    )

    expect(response.status).toBe(200)
    expect(spy.siteWindows.map((call) => call.key)).toEqual(['site:uid:uid-sah'])
  })
})

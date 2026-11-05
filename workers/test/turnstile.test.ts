import { describe, expect, it, vi } from 'vitest'
import type { MultiSourceScanResponse } from '../../functions/src/scanners/types.js'
import type { RunMultiSourceScanInput } from '../../functions/src/scanners/service.js'
import { TURNSTILE_ACTION } from '../../functions/src/turnstile/verify.js'
import type {
  TurnstileVerification,
  TurnstileVerifyInput,
} from '../../functions/src/turnstile/verify.js'
import { createWorker, type Env } from '../src/index.js'
import { createStateStoreSpy } from './helpers/stateStore.js'

const ORIGIN = 'http://localhost:5173'
const NOW = 1_700_000_000_000
const SECRET = 'secret-worker-uji'
const IP = '203.0.113.10'

// Ambang turunan dari RATE_LIMIT_MAX_PER_IP = 30 dengan rasio 0.5 → tantangan mulai di
// permintaan ke-16 dalam satu jendela.
const ENV: Env = {
  ALLOWED_ORIGINS: ORIGIN,
  RATE_LIMIT_MAX_PER_IP: '30',
  RATE_LIMIT_WINDOW_SECONDS: '60',
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
  verifyTurnstile: ReturnType<typeof vi.fn>
  env: Env
}

function makeHarness(
  options: {
    used?: number
    allowed?: boolean
    verification?: TurnstileVerification
    resolve?: (input: TurnstileVerifyInput) => TurnstileVerification
    env?: Env
  } = {},
): Harness {
  const runScan = vi.fn(async (_input: RunMultiSourceScanInput) => scanResponse())
  const verifyTurnstile = vi.fn(async (input: TurnstileVerifyInput) =>
    options.resolve
      ? options.resolve(input)
      : (options.verification ?? { ok: true as const }),
  )

  const state = createStateStoreSpy({
    allow: options.allowed !== false,
    ...(options.used === undefined ? {} : { used: options.used }),
  })

  const worker = createWorker({
    runScan,
    verifyTurnstile,
    state: state.store,
    now: () => NOW,
    siteProbe: null,
  })

  return { worker, runScan, verifyTurnstile, env: options.env ?? ENV }
}

async function invoke(
  worker: ExportedHandler<Env>,
  request: Request,
  env: Env,
): Promise<Response> {
  if (!worker.fetch) throw new Error('Handler worker tidak tersedia.')
  return worker.fetch(
    request as unknown as Request<unknown, IncomingRequestCfProperties<unknown>>,
    env,
    {} as ExecutionContext,
  )
}

function post(
  body: unknown,
  path = '/scan',
): Request {
  return new Request(`https://worker.test${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'CF-Connecting-IP': IP,
      Origin: ORIGIN,
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}

describe('gerbang Turnstile adaptif pada jalur pemeriksaan', () => {
  it('membiarkan pemeriksaan biasa lewat tanpa CAPTCHA dan tanpa siteverify', async () => {
    const harness = makeHarness({ used: 1 })
    const response = await invoke(harness.worker, post({ url: 'https://contoh.com', consent: true }), harness.env)

    expect(response.status).toBe(200)
    expect(harness.runScan).toHaveBeenCalledTimes(1)
    expect(harness.verifyTurnstile).not.toHaveBeenCalled()
  })

  it('meminta CAPTCHA setelah ambang batas lama terlampaui, tanpa menjalankan pemeriksaan', async () => {
    const harness = makeHarness({ used: 16 })
    const response = await invoke(harness.worker, post({ url: 'https://contoh.com', consent: true }), harness.env)

    expect(response.status).toBe(428)
    expect(harness.runScan).not.toHaveBeenCalled()
    expect(harness.verifyTurnstile).not.toHaveBeenCalled()
    const body = await response.json()
    expect(body).toMatchObject({ error: { code: 'captcha_required' } })
    expect(JSON.stringify(body)).not.toContain(SECRET)
  })

  it('melanjutkan ke agen setelah token pemeriksaan terverifikasi server', async () => {
    const harness = makeHarness({ used: 16 })
    const response = await invoke(
      harness.worker,
      post({ url: 'https://contoh.com', consent: true, captchaToken: 'token-pemeriksaan' }),
      harness.env,
    )

    expect(response.status).toBe(200)
    expect(harness.verifyTurnstile).toHaveBeenCalledTimes(1)
    expect(harness.runScan).toHaveBeenCalledTimes(1)
    const input = harness.verifyTurnstile.mock.calls[0]?.[0] as Record<string, unknown>
    expect(input).toMatchObject({
      secretKey: SECRET,
      token: 'token-pemeriksaan',
      expectedAction: TURNSTILE_ACTION.scan,
      remoteIp: IP,
    })
  })

  it('menolak token pemeriksaan yang tidak sah dan tetap tidak menjalankan agen', async () => {
    const harness = makeHarness({ used: 16, verification: { ok: false, reason: 'invalid_token' } })
    const response = await invoke(
      harness.worker,
      post({ url: 'https://contoh.com', consent: true, captchaToken: 'token-palsu' }),
      harness.env,
    )

    expect(response.status).toBe(428)
    expect(harness.runScan).not.toHaveBeenCalled()
    const body = await response.json()
    expect(body).toMatchObject({ error: { code: 'captcha_invalid' } })
    expect(JSON.stringify(body)).not.toContain('token-palsu')
  })

  it('tidak menantang ulang setelah verifikasi berhasil, sehingga tidak ada lingkaran CAPTCHA', async () => {
    const harness = makeHarness({ used: 16 })

    const first = await invoke(
      harness.worker,
      post({ url: 'https://contoh.com', consent: true, captchaToken: 'token-pertama' }),
      harness.env,
    )
    expect(first.status).toBe(200)

    // Permintaan berikutnya dari alamat yang sama: hitungan sudah jauh di atas ambang,
    // tetapi izin pasca-verifikasi membuat pemeriksaan jalan tanpa tantangan baru.
    const second = await invoke(harness.worker, post({ url: 'https://contoh.com', consent: true }), harness.env)
    expect(second.status).toBe(200)
    expect(harness.verifyTurnstile).toHaveBeenCalledTimes(1)
    expect(harness.runScan).toHaveBeenCalledTimes(2)
  })

  it('menantang ulang dengan token baru bila verifikasi sebelumnya gagal', async () => {
    const harness = makeHarness({ used: 16, verification: { ok: false, reason: 'expired_or_reused' } })

    const rejected = await invoke(
      harness.worker,
      post({ url: 'https://contoh.com', consent: true, captchaToken: 'token-kedaluwarsa' }),
      harness.env,
    )
    expect(rejected.status).toBe(428)

    const challenged = await invoke(harness.worker, post({ url: 'https://contoh.com', consent: true }), harness.env)
    expect(challenged.status).toBe(428)
    expect(await challenged.json()).toMatchObject({ error: { code: 'captcha_required' } })
    expect(harness.runScan).not.toHaveBeenCalled()
  })

  it('menuntut CAPTCHA juga di jalur stream, sebelum stream dibuat', async () => {
    const harness = makeHarness({ used: 20 })
    const response = await invoke(
      harness.worker,
      post(
        { url: 'https://contoh.com', consent: true, scanId: 'stream-uji-12345678' },
        '/scan/stream',
      ),
      harness.env,
    )

    expect(response.status).toBe(428)
    expect(response.headers.get('content-type')).toContain('application/json')
    expect(harness.runScan).not.toHaveBeenCalled()
  })

  it('membiarkan jalur stream lewat setelah token diverifikasi', async () => {
    const harness = makeHarness({ used: 20 })
    const response = await invoke(
      harness.worker,
      post(
        {
          url: 'https://contoh.com',
          consent: true,
          scanId: 'stream-uji-12345678',
          captchaToken: 'token-stream',
        },
        '/scan/stream',
      ),
      harness.env,
    )

    expect(response.status).toBe(200)
    expect(response.headers.get('content-type')).toContain('text/event-stream')
    expect(harness.verifyTurnstile).toHaveBeenCalledTimes(1)
  })

  it('tidak mengaktifkan eskalasi ketika kunci rahasia belum dikonfigurasi', async () => {
    const harness = makeHarness({ used: 500, env: { ...ENV, TURNSTILE_SECRET_KEY: undefined } })
    const response = await invoke(harness.worker, post({ url: 'https://contoh.com', consent: true }), harness.env)

    expect(response.status).toBe(200)
    expect(harness.verifyTurnstile).not.toHaveBeenCalled()
  })

  it('memakai daftar hostname yang dikonfigurasi saat memverifikasi token pemeriksaan', async () => {
    const harness = makeHarness({
      used: 16,
      env: {
        ...ENV,
        TURNSTILE_HOSTNAMES: 'app.veriguard.example,app.veriguard.firebaseapp.com',
      },
    })
    const response = await invoke(
      harness.worker,
      post({ url: 'https://contoh.com', consent: true, captchaToken: 'token-host' }),
      harness.env,
    )

    expect(response.status).toBe(200)
    const input = harness.verifyTurnstile.mock.calls[0]?.[0] as Record<string, unknown>
    // VGM-06: kedua hostname publik harus diteruskan; nilai tunggal dulu menolak salah satunya.
    expect(input.allowedHostnames).toEqual([
      'app.veriguard.example',
      'app.veriguard.firebaseapp.com',
    ])
    expect(input).not.toHaveProperty('expectedHostname')
  })

  it('menjaga batas keras yang sudah ada di atas gerbang CAPTCHA', async () => {
    const harness = makeHarness({ used: 30, allowed: false })
    const response = await invoke(harness.worker, post({ url: 'https://contoh.com', consent: true }), harness.env)

    expect(response.status).toBe(429)
    expect(await response.json()).toMatchObject({ error: { code: 'rate_limited' } })
    expect(harness.verifyTurnstile).not.toHaveBeenCalled()
  })

  it('tidak menantang analisis situs', async () => {
    const harness = makeHarness({ used: 16 })
    const response = await invoke(
      harness.worker,
      post({ url: 'https://contoh.com', consent: true }, '/site/analysis'),
      harness.env,
    )

    // Jalur ini tetap menjalankan analisisnya (probe null membuat laporan tidak lengkap),
    // tetapi tidak pernah menghasilkan 428.
    expect(response.status).toBe(200)
    expect(harness.verifyTurnstile).not.toHaveBeenCalled()
  })
})

describe('endpoint verifikasi CAPTCHA untuk pendaftaran', () => {
  it('hanya menerima pendaftaran setelah token diverifikasi server', async () => {
    const harness = makeHarness()
    const response = await invoke(
      harness.worker,
      post({ token: 'token-pendaftaran' }, '/auth/turnstile/verify'),
      harness.env,
    )

    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ verified: true })
    const input = harness.verifyTurnstile.mock.calls[0]?.[0] as Record<string, unknown>
    expect(input).toMatchObject({
      secretKey: SECRET,
      token: 'token-pendaftaran',
      expectedAction: TURNSTILE_ACTION.register,
      remoteIp: IP,
    })
  })

  it('menolak permintaan verifikasi tanpa token, tanpa memerlukan consent dan url', async () => {
    const harness = makeHarness({
      resolve: (input) =>
        typeof input.token === 'string' && input.token.trim()
          ? { ok: true }
          : { ok: false, reason: 'missing_token' },
    })
    const response = await invoke(harness.worker, post({ token: 'token-pendaftaran' }, '/auth/turnstile/verify'), harness.env)
    expect(response.status).toBe(200)

    const missingToken = await invoke(harness.worker, post({}, '/auth/turnstile/verify'), harness.env)
    expect(missingToken.status).toBe(400)
    expect(await missingToken.json()).toMatchObject({ error: { code: 'captcha_verification_failed' } })
  })

  it('menghentikan pendaftaran ketika verifikasi ditolak, tanpa membocorkan rahasia', async () => {
    const harness = makeHarness({ verification: { ok: false, reason: 'invalid_token' } })
    const response = await invoke(
      harness.worker,
      post({ token: 'token-ditolak' }, '/auth/turnstile/verify'),
      harness.env,
    )

    expect(response.status).toBe(400)
    const body = await response.json()
    expect(body).toMatchObject({ error: { code: 'captcha_verification_failed' } })
    expect(JSON.stringify(body)).not.toContain(SECRET)
    expect(JSON.stringify(body)).not.toContain('token-ditolak')
    expect(harness.runScan).not.toHaveBeenCalled()
  })

  it('memberi tahu konfigurasi yang belum lengkap tanpa memanggil Cloudflare', async () => {
    const harness = makeHarness({ env: { ...ENV, TURNSTILE_SECRET_KEY: undefined } })
    const response = await invoke(
      harness.worker,
      post({ token: 'token-pendaftaran' }, '/auth/turnstile/verify'),
      harness.env,
    )

    expect(response.status).toBe(503)
    const body = await response.json()
    expect(body).toMatchObject({ error: { code: 'captcha_not_configured' } })
    expect(JSON.stringify(body)).not.toContain('token-pendaftaran')
    expect(harness.verifyTurnstile).not.toHaveBeenCalled()
  })

  it('tetap menghormati consent untuk jalur pemeriksaan seperti sebelumnya', async () => {
    const harness = makeHarness()
    const response = await invoke(harness.worker, post({ url: 'https://contoh.com' }, '/scan'), harness.env)

    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: { code: 'consent_required' } })
  })
})

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  isTurnstileEnabled,
  requestTurnstileVerification,
  turnstileErrorMessage,
  turnstileSiteKey,
  turnstileVerifyEndpoint,
} from './client'
import { ExternalScanRequestError } from '../scanners/errors'

const API_BASE = 'https://scanner.test'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('klien verifikasi Turnstile', () => {
  beforeEach(() => {
    vi.stubEnv('VITE_TURNSTILE_SITE_KEY', '')
    vi.stubEnv('VITE_API_BASE_URL', API_BASE)
    vi.stubEnv('VITE_SCANNER_WORKER_URL', '')
  })

  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('menganggap kunci situs tersedia hanya bila terisi', () => {
    expect(turnstileSiteKey(undefined)).toBeNull()
    expect(turnstileSiteKey('   ')).toBeNull()
    expect(turnstileSiteKey(' 0x4AAA_SITEKEY ')).toBe('0x4AAA_SITEKEY')
  })

  it('mengaktifkan CAPTCHA hanya bila kunci situs dan endpoint backend sama-sama ada', () => {
    expect(isTurnstileEnabled(null)).toBe(false)
    expect(isTurnstileEnabled('SITEKEY')).toBe(true)

    vi.stubEnv('VITE_API_BASE_URL', '')
    expect(isTurnstileEnabled('SITEKEY')).toBe(false)
    vi.stubEnv('VITE_SCANNER_WORKER_URL', API_BASE)
    expect(isTurnstileEnabled('SITEKEY')).toBe(true)
  })

  it('menurunkan endpoint verifikasi dari basis URL yang sama seperti klien scanner', () => {
    expect(turnstileVerifyEndpoint(API_BASE)).toBe(`${API_BASE}/auth/turnstile/verify`)
    expect(turnstileVerifyEndpoint(`${API_BASE}/`)).toBe(`${API_BASE}/auth/turnstile/verify`)
    expect(turnstileVerifyEndpoint(`${API_BASE}/scanUrlMultiSource`)).toBe(
      `${API_BASE}/auth/turnstile/verify`,
    )
    expect(turnstileVerifyEndpoint(`${API_BASE}/scan/stream`)).toBe(
      `${API_BASE}/auth/turnstile/verify`,
    )
    expect(turnstileVerifyEndpoint(`${API_BASE}/site/analysis`)).toBe(
      `${API_BASE}/auth/turnstile/verify`,
    )
    expect(turnstileVerifyEndpoint(`${API_BASE}/auth/turnstile/verify`)).toBe(
      `${API_BASE}/auth/turnstile/verify`,
    )
  })

  it('mengirim hanya token ke server', async () => {
    const fetchMock = vi.fn(
      async (_url: string, _init?: RequestInit) => jsonResponse({ verified: true }),
    )

    await requestTurnstileVerification('token-hasil', {
      fetchImpl: fetchMock as unknown as typeof fetch,
    })

    const call = fetchMock.mock.calls[0]
    if (!call) throw new Error('Permintaan verifikasi tidak dikirim.')
    const [url, init] = call
    expect(url).toBe(`${API_BASE}/auth/turnstile/verify`)
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({ token: 'token-hasil' })
  })

  it('menyelesaikan tanpa nilai hanya bila server menyatakan sah', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ verified: true }))
    await expect(
      requestTurnstileVerification('token', { fetchImpl: fetchMock as unknown as typeof fetch }),
    ).resolves.toBeUndefined()
  })

  it('melempar error berkode bila server menolak token', async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ error: { code: 'captcha_verification_failed', message: 'Tolak.' } }, 400),
    )

    await expect(
      requestTurnstileVerification('token-tolak', {
        fetchImpl: fetchMock as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(ExternalScanRequestError)

    await expect(
      requestTurnstileVerification('token-tolak', {
        fetchImpl: fetchMock as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ code: 'captcha_verification_failed' })
  })

  it('membedakan layanan belum dikonfigurasi, respons bukan JSON, dan jaringan putus', async () => {
    const notConfigured = vi.fn(async () =>
      jsonResponse({ error: { code: 'captcha_not_configured', message: 'Belum siap.' } }, 503),
    )
    await expect(
      requestTurnstileVerification('token', {
        fetchImpl: notConfigured as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ code: 'captcha_not_configured' })

    const badGateway = vi.fn(async () => new Response('<html>boom</html>', { status: 502 }))
    await expect(
      requestTurnstileVerification('token', { fetchImpl: badGateway as unknown as typeof fetch }),
    ).rejects.toMatchObject({ code: 'captcha_verification_failed' })

    const failing = vi.fn(async () => {
      throw new TypeError('fetch failed')
    })
    await expect(
      requestTurnstileVerification('token', { fetchImpl: failing as unknown as typeof fetch }),
    ).rejects.toMatchObject({ code: 'unavailable' })
  })

  it('menolak memakai endpoint tanpa konfigurasi backend', async () => {
    vi.stubEnv('VITE_API_BASE_URL', '')
    const fetchMock = vi.fn(async () => jsonResponse({ verified: true }))

    await expect(
      requestTurnstileVerification('token', {
        fetchImpl: fetchMock as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ code: 'worker_not_configured' })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('menerjemahkan kode error menjadi pesan yang tidak menyebut token', () => {
    expect(
      turnstileErrorMessage(new ExternalScanRequestError('captcha_not_configured', 'x')),
    ).toContain('belum disiapkan')
    expect(turnstileErrorMessage(new ExternalScanRequestError('rate_limited', 'x'))).toContain(
      'Terlalu banyak permintaan verifikasi',
    )
    const generic = turnstileErrorMessage(
      new ExternalScanRequestError('captcha_verification_failed', 'token-rahasia'),
    )
    expect(generic).toContain('Verifikasi CAPTCHA gagal')
    expect(generic).not.toContain('token-rahasia')
    expect(turnstileErrorMessage(new Error('galat teknis internal'))).toContain(
      'Verifikasi CAPTCHA gagal',
    )
  })
})

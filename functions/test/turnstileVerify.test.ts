import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  TURNSTILE_ACTION,
  TURNSTILE_SITEVERIFY_URL,
  parseTurnstileHostnameAllowlist,
  resetTurnstileTokenRegistry,
  verifyTurnstileToken,
} from '../src/turnstile/verify.js'

const SECRET = 'secret-uji-tidak-dipakai-di-produksi'
const NOW = 1_700_000_000_000

function siteVerifyResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

type FetchCall = { url: string; init: RequestInit }

function formOf(call: FetchCall): URLSearchParams {
  return new URLSearchParams(String(call.init.body))
}

function stubFetch(
  implement: (call: FetchCall) => Promise<Response> | Response,
): {
  fetchImpl: typeof fetch
  calls: FetchCall[]
} {
  const calls: FetchCall[] = []
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const call = { url: String(input), init: init ?? {} }
    calls.push(call)
    return implement(call)
  })
  return { fetchImpl: fetchImpl as unknown as typeof fetch, calls }
}

describe('verifikasi token Cloudflare Turnstile', () => {
  beforeEach(() => {
    resetTurnstileTokenRegistry()
  })

  it('menerima token yang divalidasi Cloudflare dan mengirim kunci lewat badan permintaan', async () => {
    const { fetchImpl, calls } = stubFetch(() =>
      siteVerifyResponse({
        success: true,
        hostname: 'contoh.com',
        action: TURNSTILE_ACTION.scan,
      }),
    )

    const result = await verifyTurnstileToken({
      secretKey: SECRET,
      token: 'token-sah',
      expectedAction: TURNSTILE_ACTION.scan,
      allowedHostnames: ['CONTOH.COM'],
      remoteIp: '203.0.113.10',
      fetchImpl,
      now: () => NOW,
    })

    expect(result).toEqual({ ok: true })
    expect(calls).toHaveLength(1)
    expect(calls[0]?.url).toBe(TURNSTILE_SITEVERIFY_URL)
    expect(calls[0]?.init.method).toBe('POST')
    const form = formOf(calls[0]!)
    expect(form.get('secret')).toBe(SECRET)
    expect(form.get('response')).toBe('token-sah')
    expect(form.get('remoteip')).toBe('203.0.113.10')
  })

  it('menolak tanpa kunci rahasia dan tidak memanggil Cloudflare', async () => {
    const { fetchImpl, calls } = stubFetch(() => siteVerifyResponse({ success: true }))

    const result = await verifyTurnstileToken({
      secretKey: '   ',
      token: 'token-sah',
      fetchImpl,
      now: () => NOW,
    })

    expect(result).toEqual({ ok: false, reason: 'not_configured' })
    expect(calls).toHaveLength(0)
  })

  it('menolak token yang hilang tanpa memanggil Cloudflare', async () => {
    const { fetchImpl, calls } = stubFetch(() => siteVerifyResponse({ success: true }))

    for (const token of [undefined, null, '', '   ', 42, { token: 'x' }]) {
      expect(await verifyTurnstileToken({ secretKey: SECRET, token, fetchImpl })).toEqual({
        ok: false,
        reason: 'missing_token',
      })
    }

    expect(calls).toHaveLength(0)
  })

  it('membedakan token ditolak dan token kedaluwarsa atau terpakai', async () => {
    const rejected = stubFetch(() =>
      siteVerifyResponse({ success: false, 'error-codes': ['invalid-input-response'] }),
    )
    expect(
      await verifyTurnstileToken({
        secretKey: SECRET,
        token: 'token-palsu',
        fetchImpl: rejected.fetchImpl,
      }),
    ).toEqual({ ok: false, reason: 'invalid_token' })

    const expired = stubFetch(() =>
      siteVerifyResponse({ success: false, 'error-codes': ['timeout-or-already-used'] }),
    )
    expect(
      await verifyTurnstileToken({
        secretKey: SECRET,
        token: 'token-kedaluwarsa',
        fetchImpl: expired.fetchImpl,
      }),
    ).toEqual({ ok: false, reason: 'expired_or_reused' })
  })

  it('menolak pemakaian ulang token yang sudah pernah berhasil tanpa meminta Cloudflare lagi', async () => {
    const { fetchImpl, calls } = stubFetch(() =>
      siteVerifyResponse({ success: true, action: TURNSTILE_ACTION.scan }),
    )

    const first = await verifyTurnstileToken({
      secretKey: SECRET,
      token: 'token-sekali-pakai',
      expectedAction: TURNSTILE_ACTION.scan,
      fetchImpl,
    })
    const replay = await verifyTurnstileToken({
      secretKey: SECRET,
      token: 'token-sekali-pakai',
      expectedAction: TURNSTILE_ACTION.scan,
      fetchImpl,
    })

    expect(first.ok).toBe(true)
    expect(replay).toEqual({ ok: false, reason: 'expired_or_reused' })
    expect(calls).toHaveLength(1)
  })

  it('memakai kembali token yang belum sempat terkirim saat jaringan gagal', async () => {
    let attempt = 0
    const fetchImpl = vi.fn(async () => {
      attempt += 1
      if (attempt === 1) throw new TypeError('fetch failed')
      return siteVerifyResponse({ success: true, action: TURNSTILE_ACTION.register })
    }) as unknown as typeof fetch

    const first = await verifyTurnstileToken({
      secretKey: SECRET,
      token: 'token-saat-jaringan-putus',
      expectedAction: TURNSTILE_ACTION.register,
      fetchImpl,
    })
    const second = await verifyTurnstileToken({
      secretKey: SECRET,
      token: 'token-saat-jaringan-putus',
      expectedAction: TURNSTILE_ACTION.register,
      fetchImpl,
    })

    expect(first).toEqual({ ok: false, reason: 'transport_failure' })
    expect(second.ok).toBe(true)
  })

  it('memperlakukan respons yang bukan objek JSON sebagai malformed, bukan keberhasilan', async () => {
    const html = stubFetch(
      () =>
        new Response('<html>502 Bad Gateway</html>', {
          status: 502,
          headers: { 'content-type': 'text/html' },
        }),
    )
    expect(
      await verifyTurnstileToken({ secretKey: SECRET, token: 'token-x', fetchImpl: html.fetchImpl }),
    ).toEqual({ ok: false, reason: 'malformed_response' })

    const arrayBody = stubFetch(() => siteVerifyResponse([{ success: true }]))
    expect(
      await verifyTurnstileToken({
        secretKey: SECRET,
        token: 'token-x',
        fetchImpl: arrayBody.fetchImpl,
      }),
    ).toEqual({ ok: false, reason: 'malformed_response' })

    // Success harus literal true; nilai truthy lain tidak dianggap sah.
    const stringTrue = stubFetch(() => siteVerifyResponse({ success: 'true' }))
    expect(
      await verifyTurnstileToken({
        secretKey: SECRET,
        token: 'token-x',
        fetchImpl: stringTrue.fetchImpl,
      }),
    ).toEqual({ ok: false, reason: 'invalid_token' })
  })

  it('cocokkan hostname hanya saat dikonfigurasi, dengan perbandingan tidak peka huruf', async () => {
    const payload = { success: true, hostname: 'app.veriguard.example', action: 'register' }

    const mismatch = stubFetch(() => siteVerifyResponse(payload))
    expect(
      await verifyTurnstileToken({
        secretKey: SECRET,
        token: 'token-host-1',
        allowedHostnames: ['lain.example'],
        expectedAction: 'register',
        fetchImpl: mismatch.fetchImpl,
      }),
    ).toEqual({ ok: false, reason: 'hostname_mismatch' })

    const match = stubFetch(() => siteVerifyResponse(payload))
    expect(
      await verifyTurnstileToken({
        secretKey: SECRET,
        token: 'token-host-2',
        allowedHostnames: ['APP.Veriguard.Example'],
        expectedAction: 'register',
        fetchImpl: match.fetchImpl,
      }),
    ).toEqual({ ok: true })

    const unconfigured = stubFetch(() => siteVerifyResponse(payload))
    expect(
      await verifyTurnstileToken({
        secretKey: SECRET,
        token: 'token-host-3',
        expectedAction: 'register',
        fetchImpl: unconfigured.fetchImpl,
      }),
    ).toEqual({ ok: true })
  })

  // VGM-06: satu hostname tidak lagi cukup karena Firebase Hosting menyajikan aplikasi dari
  // web.app DAN firebaseapp.com; sebelumnya salah satu domain selalu ditolak.
  it('menerima setiap hostname yang ada di daftar', async () => {
    const allowlist = ['YOUR_FIREBASE_PROJECT_ID.web.app', 'YOUR_FIREBASE_PROJECT_ID.firebaseapp.com']

    for (const [index, hostname] of allowlist.entries()) {
      const { fetchImpl } = stubFetch(() =>
        siteVerifyResponse({ success: true, hostname, action: 'register' }),
      )
      expect(
        await verifyTurnstileToken({
          secretKey: SECRET,
          token: `token-daftar-${index}`,
          allowedHostnames: allowlist,
          expectedAction: 'register',
          fetchImpl,
        }),
      ).toEqual({ ok: true })
    }

    const luar = stubFetch(() =>
      siteVerifyResponse({ success: true, hostname: 'situs-lain.example', action: 'register' }),
    )
    expect(
      await verifyTurnstileToken({
        secretKey: SECRET,
        token: 'token-daftar-luar',
        allowedHostnames: allowlist,
        expectedAction: 'register',
        fetchImpl: luar.fetchImpl,
      }),
    ).toEqual({ ok: false, reason: 'hostname_mismatch' })
  })

  it('menolak bila Cloudflare tidak melaporkan hostname padahal daftar diisi', async () => {
    const { fetchImpl } = stubFetch(() => siteVerifyResponse({ success: true, action: 'scan' }))

    expect(
      await verifyTurnstileToken({
        secretKey: SECRET,
        token: 'token-tanpa-hostname',
        allowedHostnames: ['YOUR_FIREBASE_PROJECT_ID.web.app'],
        expectedAction: TURNSTILE_ACTION.scan,
        fetchImpl,
      }),
    ).toEqual({ ok: false, reason: 'hostname_mismatch' })
  })
  it('memisahkan aksi sehingga token pendaftaran tidak sah dipakai untuk pemeriksaan', async () => {
    const { fetchImpl } = stubFetch(() =>
      siteVerifyResponse({ success: true, hostname: 'contoh.com', action: 'register' }),
    )

    expect(
      await verifyTurnstileToken({
        secretKey: SECRET,
        token: 'token-untuk-pendaftaran',
        expectedAction: TURNSTILE_ACTION.scan,
        fetchImpl,
      }),
    ).toEqual({ ok: false, reason: 'action_mismatch' })

    // Token tanpa aksi tidak pernah memenuhi aksi yang diminta.
    const noAction = stubFetch(() => siteVerifyResponse({ success: true }))
    expect(
      await verifyTurnstileToken({
        secretKey: SECRET,
        token: 'token-tanpa-aksi',
        expectedAction: TURNSTILE_ACTION.scan,
        fetchImpl: noAction.fetchImpl,
      }),
    ).toEqual({ ok: false, reason: 'action_mismatch' })
  })

  it('tidak pernah mengembalikan token maupun kunci rahasia', async () => {
    const token = 'token-yang-harus-tetap-rahasia'
    const { fetchImpl } = stubFetch(() =>
      siteVerifyResponse({ success: false, 'error-codes': ['invalid-input-response'] }),
    )

    const rejected = await verifyTurnstileToken({
      secretKey: SECRET,
      token,
      fetchImpl,
    })

    expect(JSON.stringify(rejected)).not.toContain(token)
    expect(JSON.stringify(rejected)).not.toContain(SECRET)

    const ok = await verifyTurnstileToken({
      secretKey: SECRET,
      token: 'token-kedua',
      fetchImpl: stubFetch(() => siteVerifyResponse({ success: true })).fetchImpl,
    })
    expect(JSON.stringify(ok)).not.toContain(SECRET)
  })

  it('melewatkan pembatalan pemanggil ke permintaan siteverify', async () => {
    const controller = new AbortController()
    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      controller.abort()
      await new Promise((resolve) => setTimeout(resolve, 0))
      if (init?.signal?.aborted) throw new DOMException('aborted', 'AbortError')
      return siteVerifyResponse({ success: true })
    }) as unknown as typeof fetch

    expect(
      await verifyTurnstileToken({
        secretKey: SECRET,
        token: 'token-dibatalkan',
        fetchImpl,
        signal: controller.signal,
      }),
    ).toEqual({ ok: false, reason: 'transport_failure' })
  })
})

describe('VGM-06: parse daftar hostname Turnstile', () => {
  it('memecah nilai koma, menormalkan huruf, dan membuang entri kosong', () => {
    expect(
      parseTurnstileHostnameAllowlist(
        ' VERIGUARD-AI-AD35D.WEB.APP ,, YOUR_FIREBASE_PROJECT_ID.firebaseapp.com ',
      ),
    ).toEqual(['YOUR_FIREBASE_PROJECT_ID.web.app', 'YOUR_FIREBASE_PROJECT_ID.firebaseapp.com'])
  })

  it('menghasilkan daftar kosong untuk nilai kosong sehingga pemeriksaan dilewati', () => {
    expect(parseTurnstileHostnameAllowlist(undefined)).toEqual([])
    expect(parseTurnstileHostnameAllowlist(null)).toEqual([])
    expect(parseTurnstileHostnameAllowlist('   ')).toEqual([])
    expect(parseTurnstileHostnameAllowlist([])).toEqual([])
  })

  it('menerima bentuk array dan menghilangkan duplikat', () => {
    expect(
      parseTurnstileHostnameAllowlist(['a.example', ' A.Example ', null, '', 'b.example']),
    ).toEqual(['a.example', 'b.example'])
  })

  it('tidak melakukan pencocokan akhiran: entri tetap hostname utuh', () => {
    expect(parseTurnstileHostnameAllowlist('example.com')).toEqual(['example.com'])
  })
})

describe('P1-3: registry token dapat diganti dengan state bersama', () => {
  it('memakai registry suntikan dan hanya mengirim sidik jari, bukan token', async () => {
    const reserved: string[] = []
    const released: string[] = []
    const registry = {
      reserve(fingerprint: string) {
        reserved.push(fingerprint)
        return reserved.length === 1 ? ('reserved' as const) : ('reused' as const)
      },
      release(fingerprint: string) {
        released.push(fingerprint)
      },
    }
    const { fetchImpl, calls } = stubFetch(() =>
      siteVerifyResponse({ success: true, action: TURNSTILE_ACTION.scan }),
    )

    const input = {
      secretKey: SECRET,
      token: 'token-sama',
      expectedAction: TURNSTILE_ACTION.scan,
      fetchImpl,
      now: () => NOW,
      tokenRegistry: registry,
    }

    expect(await verifyTurnstileToken(input)).toEqual({ ok: true })
    expect(await verifyTurnstileToken(input)).toEqual({ ok: false, reason: 'expired_or_reused' })

    // Pemakaian ulang ditolak oleh state bersama, sebelum ada kesempatan meminta Cloudflare.
    expect(calls).toHaveLength(1)
    expect(reserved).toHaveLength(2)
    expect(reserved[0]).toMatch(/^[0-9a-f]{64}$/)
    expect(reserved[0]).not.toContain('token-sama')
    expect(released).toEqual([])
  })

  it('membebaskan reservasi registry suntikan ketika siteverify gagal', async () => {
    const released: string[] = []
    const registry = {
      reserve: () => 'reserved' as const,
      release: (fingerprint: string) => {
        released.push(fingerprint)
      },
    }
    const { fetchImpl } = stubFetch(async () => {
      throw new Error('jaringan putus')
    })

    expect(
      await verifyTurnstileToken({
        secretKey: SECRET,
        token: 'token-belum-terkirim',
        fetchImpl,
        now: () => NOW,
        tokenRegistry: registry,
      }),
    ).toEqual({ ok: false, reason: 'transport_failure' })

    expect(released).toHaveLength(1)
    expect(released[0]).toMatch(/^[0-9a-f]{64}$/)
  })

  it('registry memori tetap dipakai bila tidak ada state suntikan', async () => {
    const { fetchImpl, calls } = stubFetch(() => siteVerifyResponse({ success: true }))

    const input = { secretKey: SECRET, token: 'token-default', fetchImpl, now: () => NOW }
    expect(await verifyTurnstileToken(input)).toEqual({ ok: true })
    expect(await verifyTurnstileToken(input)).toEqual({ ok: false, reason: 'expired_or_reused' })
    expect(calls).toHaveLength(1)
  })
})

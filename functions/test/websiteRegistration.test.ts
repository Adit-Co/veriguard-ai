import { describe, expect, it } from 'vitest'
import {
  analyzeDomainAge,
  parseRdapBootstrap,
  parseRdapDomain,
  queryRdapRegistration,
  rdapBaseUrl,
  STATIC_RDAP_ENDPOINTS,
  unavailableRegistration,
} from '../src/website/registration.js'
import type { RegistrationQueryResult } from '../src/website/types.js'

const DAY_MS = 86_400_000
const NOW = Date.UTC(2026, 9, 30, 12, 0, 0)
const now = () => NOW

function rdapJson(daysAgo: number, overrides: Record<string, unknown> = {}) {
  return {
    objectClassName: 'domain',
    handle: '1234_DOMAIN_COM-VRSN',
    ldhName: 'PENIPU.EXAMPLE',
    status: ['client delete prohibited', 'client transfer prohibited'],
    events: [
      { eventAction: 'registration', eventDate: new Date(NOW - daysAgo * DAY_MS).toISOString() },
      { eventAction: 'expiration', eventDate: new Date(NOW + 300 * DAY_MS).toISOString() },
      { eventAction: 'last changed', eventDate: new Date(NOW - 5 * DAY_MS).toISOString() },
    ],
    entities: [
      {
        roles: ['registrar'],
        vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar']]],
      },
    ],
    ...overrides,
  }
}

function fetchJson(body: unknown, init: { status?: number; contentType?: string } = {}): typeof fetch {
  return (async () =>
    new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      status: init.status ?? 200,
      headers: { 'content-type': init.contentType ?? 'application/rdap+json' },
    })) as unknown as typeof fetch
}

describe('parseRdapBootstrap', () => {
  it('membaca layanan bootstrap IANA menjadi peta TLD', () => {
    const entries = parseRdapBootstrap({
      services: [
        [['com', 'net'], ['https://rdap.verisign.com/com/v1/']],
        [['id'], ['http://rdap.pandi.id/rdap/']],
      ],
    })
    expect(entries).toEqual([{ tlds: ['com', 'net'], baseUrl: 'https://rdap.verisign.com/com/v1/' }])
    expect(rdapBaseUrl('com', entries)).toBe('https://rdap.verisign.com/com/v1/')
  })

  it('menolak input yang bukan objek atau tanpa layanan', () => {
    expect(parseRdapBootstrap(null)).toEqual([])
    expect(parseRdapBootstrap({ services: 'bukan daftar' })).toEqual([])
  })

  it('memakai endpoint statis untuk TLD dikenal saat bootstrap kosong', () => {
    expect(rdapBaseUrl('id', [])).toBe(STATIC_RDAP_ENDPOINTS.id)
    expect(rdapBaseUrl('tidakada', [])).toBeNull()
    expect(rdapBaseUrl('../x', [])).toBeNull()
  })
})

describe('parseRdapDomain', () => {
  it('mengambil tanggal registrasi, kedaluwarsa, dan registrar', () => {
    const registration = parseRdapDomain(rdapJson(400), 'penipu.example')
    expect(registration?.registrar).toBe('Example Registrar')
    expect(registration?.domain).toBe('penipu.example')
    expect(registration?.expiresAt).toContain('T12:00:00')
    expect(registration?.createdAt).toBe(new Date(NOW - 400 * DAY_MS).toISOString())
    expect(registration?.changedAt).toBe(new Date(NOW - 5 * DAY_MS).toISOString())
    expect(registration?.statuses).toContain('client transfer prohibited')
  })

  it('mengembalikan null untuk objek yang bukan domain', () => {
    expect(parseRdapDomain({ objectClassName: 'error' }, 'x.example')).toBeNull()
    expect(parseRdapDomain(null, 'x.example')).toBeNull()
  })
})

describe('queryRdapRegistration', () => {
  it('menanyakan domain ke endpoint registry dengan accept RDAP', async () => {
    let seen = ''
    const fetchImpl = (async (input: unknown, init?: RequestInit) => {
      seen = String(input)
      void init
      return new Response(JSON.stringify(rdapJson(10)), {
        status: 200,
        headers: { 'content-type': 'application/rdap+json' },
      })
    }) as unknown as typeof fetch

    const result = await queryRdapRegistration({
      domain: 'penipu.com',
      fetchImpl,
      now,
      signal: new AbortController().signal,
    })

    expect(result.outcome).toBe('answered')
    expect(result.source).toBe('rdap.verisign.com')
    expect(seen).toBe(`${STATIC_RDAP_ENDPOINTS.com}domain/penipu.com`)
    expect(result.registration?.createdAt).toBe(new Date(NOW - 10 * DAY_MS).toISOString())
  })

  it('membedakan 404 (tidak ada data) dari kegagalan kueri', async () => {
    const missing = await queryRdapRegistration({
      domain: 'penipu.com',
      fetchImpl: fetchJson({ objectClassName: 'error', errorCode: 404 }, { status: 404 }),
      now,
    })
    expect(missing.outcome).toBe('not_found')
    expect(missing.detail).toContain('bukan "domain aman"')

    const error = await queryRdapRegistration({
      domain: 'penipu.com',
      fetchImpl: fetchJson('boom', { status: 500, contentType: 'text/plain' }),
      now,
    })
    expect(error.outcome).toBe('failed')
    expect(error.detail).toContain('HTTP 500')
  })

  it('melaporkan TLD tanpa RDAP sebagai tidak didukung, bukan aman', async () => {
    const result = await queryRdapRegistration({
      domain: 'penipu.tldjarang',
      fetchImpl: fetchJson(rdapJson(10)),
      now,
    })
    expect(result.outcome).toBe('unsupported')
    expect(result.registration).toBeNull()
    expect(result.detail).toContain('.tldjarang')
  })

  it('menolak host yang bukan domain registrable tanpa mengirim permintaan', async () => {
    let called = 0
    const fetchImpl = (async () => {
      called += 1
      return new Response('{}')
    }) as unknown as typeof fetch
    const result = await queryRdapRegistration({ domain: '203.0.113.5', fetchImpl, now })
    expect(result.outcome).toBe('unsupported')
    expect(called).toBe(0)
  })

  it('menjadi failed ketika jawaban melebihi batas ukuran atau bukan JSON', async () => {
    const huge = await queryRdapRegistration({
      domain: 'penipu.com',
      fetchImpl: fetchJson('x'.repeat(600 * 1024)),
      now,
    })
    expect(huge.outcome).toBe('failed')

    const broken = await queryRdapRegistration({
      domain: 'penipu.com',
      fetchImpl: fetchJson('{bukan json', { contentType: 'application/json' }),
      now,
    })
    expect(broken.outcome).toBe('failed')
    expect(broken.detail).toContain('JSON')
  })

  it('menjadi timeout ketika sinyal dibatalkan saat menunggu registry', async () => {
    const controller = new AbortController()
    const abortError = () => {
      const error = new Error('aborted')
      error.name = 'AbortError'
      return error
    }
    const fetchImpl = (async (_input: unknown, init?: { signal?: AbortSignal }) =>
      new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal
        if (signal?.aborted) {
          reject(abortError())
          return
        }
        signal?.addEventListener('abort', () => reject(abortError()))
        setTimeout(() => controller.abort(), 5)
      })) as unknown as typeof fetch

    const result = await queryRdapRegistration({
      domain: 'penipu.com',
      fetchImpl,
      now,
      timeoutMs: 500,
      signal: controller.signal,
    })
    expect(result.outcome).toBe('timeout')
  })
})

describe('analyzeDomainAge', () => {
  const answered = (daysAgo: number): RegistrationQueryResult => ({
    registration: parseRdapDomain(rdapJson(daysAgo), 'penipu.example'),
    outcome: 'answered',
    source: 'rdap.example',
    detail: 'ok',
  })

  it('menilai domain sangat muda sebagai indikator sedang, bukan bukti', () => {
    const analysis = analyzeDomainAge({
      registrableDomain: 'penipu.example',
      result: answered(3),
      now,
    })
    expect(analysis.status).toBe('complete')
    expect(analysis.ageDays).toBe(3)
    expect(analysis.findings.map((entry) => entry.code)).toContain('domain_young')
    expect(analysis.findings[0]!.strength).toBe('moderate')
    expect(analysis.notes.join(' ')).toContain('indikator lemah sampai sedang')
  })

  it('menilai domain berumur beberapa bulan sebagai sinyal lemah', () => {
    const analysis = analyzeDomainAge({ registrableDomain: 'x.example', result: answered(90), now })
    expect(analysis.findings.map((entry) => entry.code)).toContain('domain_recent')
    expect(analysis.findings[0]!.strength).toBe('weak')
  })

  it('memperlakukan domain tua sebagai bukti yang menurunkan kecurigaan, bukan pembersih', () => {
    const analysis = analyzeDomainAge({ registrableDomain: 'x.example', result: answered(1500), now })
    const finding = analysis.findings[0]!
    expect(finding.code).toBe('domain_mature')
    expect(finding.strength).toBe('mitigating')
    expect(finding.detail).toContain('tidak menghapus bukti lain')
  })

  it('tidak menghitung masa sewa satu tahun sebagai apa pun', () => {
    const analysis = analyzeDomainAge({ registrableDomain: 'x.example', result: answered(10), now })
    expect(analysis.findings.map((entry) => entry.code)).not.toContain('one_year_registration')
    expect(analysis.notes.join(' ')).toContain('Masa sewa satu tahun tidak dinilai')
  })

  it('memetakan kegagalan kueri menjadi status unavailable yang jujur', () => {
    for (const outcome of ['unsupported', 'failed', 'timeout', 'not_found'] as const) {
      const analysis = analyzeDomainAge({
        registrableDomain: 'x.example',
        result: { registration: null, outcome, source: null, detail: 'tes' },
        now,
      })
      expect(['unavailable', 'partial']).toContain(analysis.status)
      expect(analysis.ageDays).toBeNull()
      expect(analysis.findings.map((entry) => entry.code)).toContain('registration_unavailable')
      expect(analysis.lookup.status).not.toBe('success')
    }
  })

  it('menilai target IP tanpa domain sebagai tidak berlaku', () => {
    const analysis = analyzeDomainAge({
      registrableDomain: null,
      result: { registration: null, outcome: 'unsupported', source: null, detail: 'tes' },
      now,
    })
    expect(analysis.status).toBe('unavailable')
    expect(analysis.findings).toEqual([])
    expect(analysis.lookup.detail).toContain('alamat IP')
  })

  it('unavailableRegistration selalu membawa alasan dan tanpa umur', () => {
    const analysis = unavailableRegistration(new Date(NOW).toISOString(), 'Probe tidak mendukung RDAP.')
    expect(analysis.status).toBe('unavailable')
    expect(analysis.ageDays).toBeNull()
    expect(analysis.notes.join(' ')).toContain('Probe tidak mendukung RDAP.')
  })
})

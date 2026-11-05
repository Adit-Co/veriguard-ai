import { describe, expect, it } from 'vitest'
import { ScanUrlError } from '../src/scanners/url.js'
import { runSiteAnalysis } from '../src/website/service.js'
import type {
  AsnQueryResult,
  DomainRegistration,
  OriginRequest,
  OriginResult,
  OriginTlsInfo,
  RecordQueryResult,
  RegistrationQueryResult,
  ResolveResult,
  SiteProbe,
  TlsProbeResult,
  WebsiteRecordType,
} from '../src/website/types.js'

const PUBLIC = '93.184.216.34'
const OTHER_PUBLIC = '104.16.1.2'
const NOW = Date.parse('2026-10-24T00:00:00.000Z')

type OkOrigin = Extract<OriginResult, { ok: true }>

function okOrigin(overrides: Partial<OkOrigin> = {}): OkOrigin {
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: [
      ['content-type', 'text/html; charset=utf-8'],
      ['server', 'nginx'],
    ],
    body: '<html><head><title>uji</title></head><body>halo</body></html>',
    bytes: 52,
    truncated: false,
    elapsedMs: 15,
    tls: null,
    ...overrides,
  }
}

function failOrigin(kind: 'error' | 'timeout' = 'error', detail = 'ECONNREFUSED'): OriginResult {
  return { ok: false, kind, detail, elapsedMs: 5 }
}

function tlsInfo(overrides: Partial<OriginTlsInfo> = {}): OriginTlsInfo {
  return {
    protocol: 'TLSv1.3',
    cipher: 'AES-256-GCM',
    issuer: 'R3',
    subject: 'example.com',
    notBefore: '2026-01-01T00:00:00.000Z',
    notAfter: '2026-12-31T00:00:00.000Z',
    authorized: true,
    authorizationError: null,
    ...overrides,
  }
}

function answered(records: string[]): RecordQueryResult {
  return { records, outcome: 'answered', detail: null }
}

const EMPTY_RECORDS: RecordQueryResult = {
  records: [],
  outcome: 'empty',
  detail: 'Kueri selesai tanpa record untuk tipe ini.',
}

type ProbeConfig = {
  ipv4?: string[]
  ipv6?: string[]
  rotateResolve?: string[][]
  resolveError?: Error
  records?: Partial<Record<WebsiteRecordType, RecordQueryResult>>
  recordErrors?: WebsiteRecordType[]
  asn?: AsnQueryResult
  tls?: TlsProbeResult
  origins?: OriginResult[]
  registration?: RegistrationQueryResult
}

function makeProbe(config: ProbeConfig = {}) {
  const calls = {
    resolve: [] as string[],
    records: [] as WebsiteRecordType[],
    asn: [] as string[],
    tls: [] as string[],
    origin: [] as OriginRequest[],
    registration: [] as string[],
  }

  const resolveAnswers = config.rotateResolve ?? [[...(config.ipv4 ?? [PUBLIC]), ...(config.ipv6 ?? [])]]
  const origins = config.origins ?? [okOrigin()]

  const probe: SiteProbe = {
    name: 'probe-uji',
    dnsSource: 'probe uji',
    resolve: async (hostname) => {
      calls.resolve.push(hostname)
      if (config.resolveError) throw config.resolveError
      const answer = resolveAnswers[Math.min(calls.resolve.length - 1, resolveAnswers.length - 1)] ?? []
      return {
        ipv4: answer.filter((entry) => !entry.includes(':')),
        ipv6: answer.filter((entry) => entry.includes(':')),
        detail: null,
      }
    },
    queryRecords: async (_hostname, type) => {
      calls.records.push(type)
      if (config.recordErrors?.includes(type)) throw new Error('SERVFAIL')
      return config.records?.[type] ?? (type === 'A' ? answered([PUBLIC]) : EMPTY_RECORDS)
    },
    lookupAsn: async (address) => {
      calls.asn.push(address)
      return (
        config.asn ?? {
          info: { asn: 'AS15133', organization: null, country: 'US', prefix: '93.184.216.0/24', registry: 'arin' },
          outcome: 'answered',
          detail: null,
        }
      )
    },
    inspectTls: async (_hostname, address) => {
      calls.tls.push(address)
      return (
        config.tls ?? {
          certificate: {
            issuer: 'R3',
            subject: 'example.com',
            notBefore: '2026-01-01T00:00:00.000Z',
            notAfter: '2026-12-31T00:00:00.000Z',
            expired: false,
            hostnameVerified: true,
            verification: 'verified' as const,
            verificationDetail: null,
            protocol: 'TLSv1.3',
          },
          httpsReachable: true,
          outcome: 'answered',
          detail: null,
        }
      )
    },
    openOrigin: async (request) => {
      calls.origin.push(request)
      return origins[Math.min(calls.origin.length - 1, origins.length - 1)] ?? okOrigin()
    },
  }

  // probe uji default sengaja TIDAK punya lookupRegistration supaya jalur
  // "runtime tanpa akses registry" ikut teruji oleh seluruh suite yang ada.
  if (config.registration) {
    probe.lookupRegistration = async (domain) => {
      calls.registration.push(domain)
      return config.registration as RegistrationQueryResult
    }
  }

  return { probe, calls }
}

function run(url: string, probe: SiteProbe | null, signal?: AbortSignal) {
  return runSiteAnalysis({ url, uid: 'uji', probe, now: () => NOW, signal })
}

describe('validasi target sebelum koneksi', () => {
  it('menyerahkan skema yang tidak didukung ke validasi terpusat', async () => {
    const { probe, calls } = makeProbe()
    await expect(run('file:///etc/passwd', probe)).rejects.toBeInstanceOf(ScanUrlError)
    await expect(run('gopher://example.com/', probe)).rejects.toBeInstanceOf(ScanUrlError)
    expect(calls.resolve).toEqual([])
    expect(calls.origin).toEqual([])
  })

  it('menolak nama host internal pada validasi terpusat sebelum probe dipakai', async () => {
    const { probe, calls } = makeProbe()
    for (const url of ['http://localhost/admin', 'http://127.1/', 'http://169.254.169.254/', 'http://[::1]/']) {
      await expect(run(url, probe)).rejects.toBeInstanceOf(ScanUrlError)
    }
    expect(calls.resolve).toEqual([])
    expect(calls.origin).toEqual([])
  })

  it('menandai nama host metadata sebagai unavailable tanpa permintaan', async () => {
    const { probe, calls } = makeProbe()
    const report = await run('http://metadata.goog/computeMetadata/v1/', probe)
    expect(report.probe.available).toBe(false)
    expect(report.website.status).toBe('unavailable')
    expect(report.website.notes[0]).toContain('Tidak ada permintaan yang dikirim ke target')
    expect(calls.resolve).toEqual([])
    expect(calls.origin).toEqual([])
  })

  it('tidak membuka URL yang memuat parameter seperti token', async () => {
    const { probe, calls } = makeProbe()
    const report = await run(`https://example.com/account?reset=${'a1'.repeat(24)}`, probe)
    expect(report.website.status).toBe('unavailable')
    expect(report.website.identity.asn.detail).toContain('token')
    expect(calls.origin).toEqual([])
  })

  it('jujur menandai seluruh bagian unavailable bila platform tanpa probe', async () => {
    const { calls } = makeProbe()
    const report = await run('https://example.com', null)
    expect(report.probe).toMatchObject({ available: false, name: 'tanpa akses platform' })
    expect(report.website.status).toBe('unavailable')
    expect(report.behavior.status).toBe('unavailable')
    expect(report.technology.categories.every((entry) => entry.state === 'unavailable')).toBe(true)
    expect(report.website.dns.every((entry) => entry.lookup.status === 'unavailable')).toBe(true)
    expect(report.behavior.cookiesCollected).toBe(false)
    expect(calls.origin).toEqual([])
  })

  it('memakai alamat hasil validasi, bukan resolusi ulang (pertahanan DNS rebinding)', async () => {
    const { probe, calls } = makeProbe({ rotateResolve: [[PUBLIC], ['127.0.0.1']] })
    const report = await run('https://example.com', probe)
    expect(calls.resolve).toEqual(['example.com'])
    expect(calls.origin).toHaveLength(1)
    expect(calls.origin[0]).toMatchObject({ address: PUBLIC, hostname: 'example.com', secure: true, port: 443 })
    expect(report.website.identity.addresses.value).toEqual([{ address: PUBLIC, kind: 'ipv4' }])
  })

  it('tidak membuka halaman ketika semua hasil resolusi internal', async () => {
    const { probe, calls } = makeProbe({ ipv4: ['127.0.0.1', '10.0.0.9'], ipv6: ['::1'] })
    const report = await run('https://example.com', probe)
    expect(report.website.identity.addresses.status).toBe('blocked')
    expect(report.website.identity.withheldAddresses).toBe(3)
    expect(report.website.response.request.status).toBe('blocked')
    expect(report.behavior.redirectOutcome).toBe('blocked')
    expect(report.website.identity.intermediary.state).toBe('no_signal')
    expect(report.website.identity.intermediary.note).toContain('server asal')
    expect(calls.origin).toEqual([])
    expect(calls.tls).toEqual([])
  })
})

describe('DNS: beda kosong, gagal, dan timeout', () => {
  it('membedakan record kosong dari kueri yang gagal', async () => {
    const { probe } = makeProbe({
      recordErrors: ['MX'],
      records: {
        A: answered([PUBLIC]),
        AAAA: EMPTY_RECORDS,
        TXT: { records: [], outcome: 'timeout', detail: 'Kueri DNS melebihi batas waktu.' },
        SOA: { records: [], outcome: 'failed', detail: 'Kueri DNS tidak dapat diselesaikan.' },
      },
    })
    const report = await run('https://example.com', probe)
    const byType = new Map(report.website.dns.map((entry) => [entry.type, entry.lookup]))
    expect(byType.get('A')).toMatchObject({ status: 'success', value: [PUBLIC] })
    expect(byType.get('AAAA')).toMatchObject({ status: 'empty', value: [] })
    expect(byType.get('MX')).toMatchObject({ status: 'failed', value: null })
    expect(byType.get('TXT')).toMatchObject({ status: 'timeout', value: null })
    expect(byType.get('SOA')).toMatchObject({ status: 'failed', value: null })
    expect(report.website.status).toBe('partial')
  })

  it('membedakan resolusi yang gagal dari resolusi yang habis waktu', async () => {
    const timeoutError = new Error('Kueri DNS melebihi batas waktu.') as Error & { code?: string }
    timeoutError.code = 'ETIMEDOUT'

    const failedProbe = makeProbe({ resolveError: new Error('SERVFAIL') })
    const failedReport = await run('https://example.com', failedProbe.probe)
    expect(failedReport.website.identity.addresses).toMatchObject({
      status: 'failed',
      value: null,
      detail: 'Kueri gagal (Error).',
    })
    expect(failedProbe.calls.origin).toEqual([])

    const timeoutProbe = makeProbe({ resolveError: timeoutError })
    const timeoutReport = await run('https://example.com', timeoutProbe.probe)
    expect(timeoutReport.website.identity.addresses).toMatchObject({
      status: 'timeout',
      value: null,
      detail: 'Kueri melebihi batas waktu.',
    })
    expect(timeoutProbe.calls.origin).toEqual([])
  })

  it('menyembunyikan record yang tampak memuat data rahasia', async () => {
    const { probe } = makeProbe({
      records: {
        TXT: answered([
          'v=spf1 include:_spf.example.com ~all',
          '-----BEGIN PRIVATE KEY----- MIIEv-----END PRIVATE KEY-----',
          'api_key=abcd1234',
        ]),
      },
    })
    const report = await run('https://example.com', probe)
    const txt = report.website.dns.find((entry) => entry.type === 'TXT')?.lookup
    expect(txt?.value).toEqual(['v=spf1 include:_spf.example.com ~all'])
    expect(txt?.detail).toContain('tidak ditampilkan')
    expect(JSON.stringify(report)).not.toContain('BEGIN PRIVATE KEY')
    expect(JSON.stringify(report)).not.toContain('abcd1234')
  })

  it('membatasi jumlah record per tipe', async () => {
    const { probe } = makeProbe({ records: { A: answered(Array.from({ length: 20 }, (_, i) => `10.0.${i}.1`)) } })
    const report = await run('https://example.com', probe)
    const a = report.website.dns.find((entry) => entry.type === 'A')?.lookup
    expect(a?.value).toHaveLength(8)
    expect(a?.detail).toContain('12 record tidak ditampilkan')
  })
})

describe('ASN dan sertifikat dilaporkan apa adanya', () => {
  it('mengisi ASN hanya dari sumber yang menjawab', async () => {
    const { probe } = makeProbe()
    const report = await run('https://example.com', probe)
    expect(report.website.identity.asn).toMatchObject({
      status: 'success',
      value: { asn: 'AS15133', country: 'US', organization: null },
    })
  })

  it('tidak mengarang ASN ketika kueri kosong atau gagal', async () => {
    for (const outcome of ['empty', 'failed'] as const) {
      const { probe } = makeProbe({
        asn: { info: null, outcome, detail: outcome === 'empty' ? 'Tidak ada data ASN untuk alamat ini.' : 'Kueri ASN gagal.' },
      })
      const report = await run('https://example.com', probe)
      expect(report.website.identity.asn.status).toBe(outcome)
      expect(report.website.identity.asn.value).toBeNull()
    }
  })

  it('memakai sertifikat dari sambungan origin dan menandai validasi yang gagal', async () => {
    const { probe } = makeProbe({
      origins: [okOrigin({ tls: tlsInfo({ authorized: false, authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID' }) })],
    })
    const report = await run('https://example.com', probe)
    expect(report.website.tls.certificate).toMatchObject({
      status: 'success',
      value: { hostnameVerified: false, verification: 'rejected', verificationDetail: 'ERR_TLS_CERT_ALTNAME_INVALID', expired: false },
    })
    expect(report.website.tls.certificateSource).toBe('sambungan TLS pada permintaan origin')
  })

  it('menandai sertifikat kedaluwarsa terhadap waktu pemeriksaan', async () => {
    const { probe } = makeProbe({ origins: [okOrigin({ tls: tlsInfo({ notAfter: '2020-01-01T00:00:00.000Z' }) })] })
    const report = await run('https://example.com', probe)
    expect(report.website.tls.certificate.value?.expired).toBe(true)
  })

  it('memeriksa TLS terpisah ketika origin menjawab tanpa HTTPS', async () => {
    const { probe, calls } = makeProbe({ origins: [okOrigin({ tls: null })] })
    const report = await run('http://example.com', probe)
    expect(calls.tls).toEqual([PUBLIC])
    expect(report.website.tls.certificateSource).toBe('percobaan koneksi TLS port 443')
    expect(report.website.tls.httpsAvailable.detail).toContain('terpisah')
  })

  it('tidak menyatakan HTTPS tersedia ketika probe TLS gagal', async () => {
    const { probe } = makeProbe({
      origins: [okOrigin({ tls: null })],
      tls: { certificate: null, httpsReachable: false, outcome: 'failed', detail: 'Koneksi TLS ditolak.' },
    })
    const report = await run('http://example.com', probe)
    expect(report.website.tls.httpsAvailable).toMatchObject({ status: 'failed', value: null })
    expect(report.website.tls.certificate).toMatchObject({ status: 'failed', value: null })
  })

  it('memakai port non-default dan mengikuti tujuan lintas host', async () => {
    const { probe, calls } = makeProbe({
      origins: [
        okOrigin({
          status: 301,
          headers: [
            ['location', 'https://lain.example/'],
            ['content-type', 'text/html'],
          ],
          tls: tlsInfo(),
        }),
        okOrigin(),
      ],
    })
    await run('https://example.com:8443/jalur', probe)
    expect(calls.origin[0]?.port).toBe(8443)
    expect(calls.origin[1]).toMatchObject({ hostname: 'lain.example', port: 443 })
  })
})

describe('rantai redirect divalidasi ulang setiap hop', () => {
  function redirectChain(...targets: string[]): OriginResult[] {
    return targets.map((location, index) =>
      location === 'FINAL'
        ? okOrigin()
        : okOrigin({
            status: 301,
            headers: [['location', location], ['content-type', 'text/html']],
            body: '',
            tls: index === 0 ? tlsInfo() : null,
          }),
    )
  }

  it('mengikuti redirect dan mencatat jumlahnya', async () => {
    const { probe, calls } = makeProbe({ origins: redirectChain('/pindah', 'FINAL') })
    const report = await run('https://example.com', probe)
    expect(report.website.response.redirectCount).toBe(1)
    expect(report.behavior.redirectOutcome).toBe('final')
    expect(report.behavior.redirects.map((hop) => hop.outcome)).toEqual(['followed', 'final'])
    expect(calls.origin).toHaveLength(2)
    expect(calls.resolve).toEqual(['example.com'])
  })

  it('resolusi dan validasi ulang tujuan lintas host sebelum diikuti', async () => {
    const { probe, calls } = makeProbe({
      ipv4: [PUBLIC],
      rotateResolve: [[PUBLIC], [OTHER_PUBLIC]],
      origins: redirectChain('https://cdn.example.org/asset', 'FINAL'),
    })
    const report = await run('https://example.com', probe)
    expect(calls.resolve).toEqual(['example.com', 'cdn.example.org'])
    expect(calls.origin[1]).toMatchObject({ hostname: 'cdn.example.org', address: OTHER_PUBLIC })
    expect(report.website.response.redirectCount).toBe(1)
  })

  it('menghentikan redirect yang menuju metadata tanpa membukanya', async () => {
    const { probe, calls } = makeProbe({ origins: redirectChain('http://169.254.169.254/latest/meta-data/', 'FINAL') })
    const report = await run('https://example.com', probe)
    expect(calls.origin).toHaveLength(1)
    expect(report.behavior.redirectOutcome).toBe('blocked')
    expect(report.behavior.redirects[1]).toMatchObject({ outcome: 'blocked' })
    expect(report.website.response.request.detail).toMatch(/redirect/i)
  })

  it('menolak tujuan redirect berupa literal host internal di dalam rantai', async () => {
    const { probe, calls } = makeProbe({ origins: redirectChain('http://127.1/admin', 'FINAL') })
    const report = await run('https://example.com', probe)
    expect(calls.origin).toHaveLength(1)
    expect(report.behavior.redirectOutcome).toBe('blocked')
    expect(report.website.identity.addresses.value).toHaveLength(1)
  })

  it('menghentikan redirect ke port di luar 80/443 tanpa menghubunginya', async () => {
    const { probe, calls } = makeProbe({
      rotateResolve: [[PUBLIC], [OTHER_PUBLIC]],
      origins: redirectChain('https://cdn.example.org:8080/aset', 'FINAL'),
    })
    const report = await run('https://example.com', probe)
    expect(calls.origin).toHaveLength(1)
    expect(report.behavior.redirectOutcome).toBe('blocked')
    expect(report.behavior.redirects.at(-1)).toMatchObject({ outcome: 'blocked' })
    expect(report.behavior.redirects.at(-1)?.detail).toContain('80/443')
  })

  it('mengikuti port pada URL yang ditulis pengguna, tetapi mencatatnya sebagai sinyal', async () => {
    const { probe, calls } = makeProbe()
    const report = await run('http://example.com:8080/admin', probe)
    expect(calls.origin[0]).toMatchObject({ port: 8080, secure: false })
    expect(report.behavior.redirectOutcome).toBe('final')
    expect(report.behavior.structure.findings.map((entry) => entry.code)).toContain('unusual_port')
    expect(report.behavior.structure.findings.map((entry) => entry.code)).toContain('insecure_scheme')
  })

  it('menolak hop pertama menuju port layanan tanpa menghubunginya', async () => {
    // Pemeriksaan situs tidak boleh dipakai sebagai primitive probe port ke alamat publik
    // mana pun dari infrastruktur hosting, meski alamatnya sendiri lintas-scope publik.
    for (const target of [
      'http://example.com:6379/',
      'http://example.com:3306/',
      'http://example.com:22/',
    ]) {
      const { probe, calls } = makeProbe()
      const report = await run(target, probe)

      expect(calls.origin).toHaveLength(0)
      expect(report.behavior.redirectOutcome).toBe('blocked')
      expect(report.behavior.redirects[0]).toMatchObject({ outcome: 'blocked' })
      expect(report.behavior.redirects[0]?.detail).toContain('80/443/8080/8443')
    }
  })

  it('mengizinkan port web yang ditulis eksplisit', async () => {
    const { probe, calls } = makeProbe()
    const report = await run('https://example.com:443/masuk', probe)
    expect(calls.origin).toHaveLength(1)
    expect(calls.origin[0]).toMatchObject({ port: 443, secure: true })
    expect(report.behavior.redirectOutcome).toBe('final')
  })

  it('menghentikan redirect ketika resolusi tujuan hanya alamat internal', async () => {
    const { probe, calls } = makeProbe({
      rotateResolve: [[PUBLIC], ['127.0.0.1']],
      origins: redirectChain('https://privat.example/x', 'FINAL'),
    })
    const report = await run('https://example.com', probe)
    expect(calls.origin).toHaveLength(1)
    expect(report.behavior.redirectOutcome).toBe('blocked')
    expect(report.behavior.redirects.at(-1)?.detail).toContain('rentang yang dilarang')
  })

  it('mendeteksi loop redirect dan berhenti', async () => {
    const { probe, calls } = makeProbe({
      origins: redirectChain('https://example.com/b', 'https://example.com/a', 'FINAL'),
    })
    const report = await run('https://example.com/a', probe)
    expect(report.behavior.redirectOutcome).toBe('loop')
    expect(calls.origin).toHaveLength(2)
    expect(report.behavior.redirects.at(-1)?.outcome).toBe('loop')
  })

  it('membatasi rantai pada empat redirect', async () => {
    const { probe, calls } = makeProbe({
      origins: redirectChain('/r1', '/r2', '/r3', '/r4', '/r5', 'FINAL'),
    })
    const report = await run('https://example.com', probe)
    expect(calls.origin).toHaveLength(5)
    expect(report.behavior.redirectCount).toBe(4)
    expect(report.behavior.redirectOutcome).toBe('limit')
    expect(report.website.response.status).toBeNull()
  })

  it('menandai tujuan dengan skema terlarang sebagai blocked', async () => {
    const { probe, calls } = makeProbe({ origins: redirectChain('ftp://example.com/file', 'FINAL') })
    const report = await run('https://example.com', probe)
    expect(calls.origin).toHaveLength(1)
    expect(report.behavior.redirectOutcome).toBe('blocked')
  })

  it('tidak menganggap kegagalan origin sebagai halaman aman', async () => {
    const { probe } = makeProbe({
      origins: [failOrigin('timeout', 'ETIMEDOUT')],
      tls: { certificate: null, httpsReachable: false, outcome: 'timeout', detail: 'Koneksi TLS melebihi batas waktu.' },
    })
    const report = await run('https://example.com', probe)
    expect(report.website.response.request.status).toBe('failed')
    expect(report.behavior.redirects[0]).toMatchObject({ outcome: 'error' })
    expect(report.website.status).toBe('partial')
    expect(report.behavior.status).toBe('failed')
    expect(report.behavior.observations.some((entry) => entry.detail.includes('Sertifikat tidak terbaca'))).toBe(true)
    expect(report.technology.findings).toEqual([])
  })
})

describe('batas ukuran dan redaksi data sensitif', () => {
  it('menandai dokumen yang dipotong pada kedua panel', async () => {
    const { probe } = makeProbe({
      origins: [okOrigin({ body: '<html><body>' + 'x'.repeat(1000), bytes: 524288, truncated: true })],
    })
    const report = await run('https://example.com', probe)
    expect(report.website.response.truncated).toBe(true)
    expect(report.technology.document.truncated).toBe(true)
    expect(report.technology.notes.join(' ')).toContain('dipotong')
    expect(report.behavior.status).toBe('partial')
  })

  it('tidak menyimpulkan teknologi dari dokumen non-HTML', async () => {
    const { probe } = makeProbe({
      origins: [
        okOrigin({
          headers: [
            ['content-type', 'application/pdf'],
            ['server', 'nginx'],
          ],
          body: '%PDF-1.7',
          bytes: 8,
        }),
      ],
    })
    const report = await run('https://example.com', probe)
    expect(report.technology.document.inspected).toBe(false)
    expect(report.technology.findings.map((entry) => entry.name)).toEqual(['nginx'])
    expect(report.technology.categories.filter((entry) => entry.state === 'unavailable').length).toBeGreaterThan(3)
    expect(report.behavior.resources).toBeNull()
  })

  it('hanya menampilkan nama dan atribut cookie, bukan nilainya', async () => {
    const { probe } = makeProbe({
      origins: [
        okOrigin({
          headers: [
            ['content-type', 'text/html'],
            ['server', 'nginx'],
            ['set-cookie', 'sesi=NYRAHASIA123456; Secure; HttpOnly; SameSite=Strict; Max-Age=60'],
            ['set-cookie', 'preferensi=terang'],
            ['authorization', 'Bearer TOKENRAHASIA'],
          ],
        }),
      ],
    })
    const report = await run('https://example.com', probe)
    const raw = JSON.stringify(report)
    expect(raw).not.toContain('NYRAHASIA123456')
    expect(raw).not.toContain('TOKENRAHASIA')
    expect(raw).not.toContain('terang')
    expect(report.behavior.cookies).toEqual([
      { name: 'sesi', secure: true, httpOnly: true, sameSite: 'strict', hasExpiry: true, valueShown: false },
      { name: 'preferensi', secure: false, httpOnly: false, sameSite: null, hasExpiry: false, valueShown: false },
    ])
    expect(report.website.response.headers.map((entry) => entry.name)).toEqual(['content-type', 'server'])
    expect(report.website.response.withheldHeaders).toBe(3)
  })

  it('membatasi jumlah header yang ditampilkan', async () => {
    const headers: Array<[string, string]> = Array.from({ length: 30 }, (_, index) => [
      `x-agen-${index}`,
      `nilai-${index}`,
    ])
    const { probe } = makeProbe({ origins: [okOrigin({ headers: [['content-type', 'text/html'], ...headers] })] })
    const report = await run('https://example.com', probe)
    expect(report.website.response.headers).toHaveLength(12)
    expect(report.website.response.withheldHeaders).toBe(19)
  })

  it('membatalkan pekerjaan ketika sinyal abort diberikan', async () => {
    const controller = new AbortController()
    const probe: SiteProbe = {
      name: 'probe-lambat',
      dnsSource: 'probe uji',
      resolve: (hostname, signal) =>
        new Promise<ResolveResult>((_resolve, reject) => {
          const abort = () => {
            const error = new Error('dibatalkan')
            error.name = 'AbortError'
            reject(error)
          }
          if (signal?.aborted) abort()
          else signal?.addEventListener('abort', abort, { once: true })
          void hostname
        }),
      queryRecords: async () => EMPTY_RECORDS,
      lookupAsn: async () => ({ info: null, outcome: 'empty', detail: null }),
      inspectTls: async () => ({ certificate: null, httpsReachable: false, outcome: 'empty' as const, detail: null }),
      openOrigin: async () => okOrigin(),
    }
    controller.abort(new Error('berhenti'))
    const report = await run('https://example.com', probe, controller.signal)
    expect(report.website.identity.addresses.status).toBe('timeout')
    expect(report.website.identity.addresses.detail).toContain('dibatalkan')
  })
})

describe('sinyal struktur URL dan form pada analisis situs', () => {
  it('menggabungkan sinyal struktur dan form tanpa memberi vonis', async () => {
    const { probe } = makeProbe({
      origins: [
        okOrigin({
          body: '<html><body><form action="https://penampung.example/kirim" method="post"><input type="password"></form></body></html>',
        }),
      ],
    })
    const report = await run('http://paypa1.com/masuk', probe)

    expect(report.behavior.structure.status).toBe('complete')
    const codes = report.behavior.structure.findings.map((entry) => entry.code)
    expect(codes).toContain('insecure_scheme')
    expect(codes).toContain('typosquat')
    expect(codes).not.toContain('unusual_port')

    expect(report.behavior.forms.inspected).toBe(true)
    expect(report.behavior.forms.totals).toMatchObject({ forms: 1, passwordFields: 1, externalActions: 1 })

    expect(report.behavior.observations.some((entry) => entry.kind === 'url')).toBe(true)
    expect(report.behavior.observations.some((entry) => entry.kind === 'form')).toBe(true)
    expect(report.behavior.structure).not.toHaveProperty('score')
    expect(report.behavior).not.toHaveProperty('verdict')
  })

  it('menyediakan struktur dari teks URL ketika halaman tidak dibuka', async () => {
    const { probe } = makeProbe({ origins: [failOrigin('error', 'ECONNREFUSED')] })
    const report = await run('https://bit.ly/x', probe)
    expect(report.behavior.structure.findings.map((entry) => entry.code)).toContain('shortener')
    expect(report.behavior.forms.inspected).toBe(false)
    expect(report.behavior.forms.detail).toContain('tidak dapat diperiksa')
  })
})

const DAY_MS = 86_400_000

function rdapAnswer(overrides: Partial<DomainRegistration> = {}): RegistrationQueryResult {
  return {
    registration: {
      domain: 'paypa1.com',
      handle: 'D12345-CIRR',
      registrar: 'Registrar Uji',
      createdAt: new Date(NOW - 10 * DAY_MS).toISOString(),
      changedAt: null,
      expiresAt: new Date(NOW + 355 * DAY_MS).toISOString(),
      statuses: ['active'],
      ...overrides,
    },
    outcome: 'answered',
    source: 'rdap.uji',
    detail: 'Tanggal registrasi terbaca dari registry RDAP.',
  }
}

const CREDENTIAL_PAGE =
  '<html><body><form action="https://penampung.example/kirim" method="post">' +
  '<input type="text" name="email"><input type="password" name="pass">' +
  '</form></body></html>'

describe('registrasi, isi halaman, dan fusi bukti pada analisis situs', () => {
  it('menggabungkan umur registrasi RDAP ke dalam bukti yang dapat ditelusuri', async () => {
    const { probe, calls } = makeProbe({
      registration: rdapAnswer(),
      origins: [okOrigin({ body: CREDENTIAL_PAGE })],
    })
    const report = await run('http://paypa1.com/masuk', probe)

    expect(calls.registration).toEqual(['paypa1.com'])
    expect(report.registration.status).toBe('complete')
    expect(report.registration.ageDays).toBe(10)
    expect(report.registration.findings.map((entry) => entry.code)).toContain('domain_young')

    const young = report.risk.evidence.find((entry) => entry.id === 'registration:domain_young')
    expect(young).toMatchObject({ category: 'registration', strength: 'moderate', availability: 'observed' })
    expect(young?.observed).toContain('2026')

    const credential = report.risk.evidence.find((entry) => entry.id === 'form:credential_request')
    expect(credential?.source).toBe('pageSignals.analyzePageContent')

    expect(report.risk.riskScore).not.toBeNull()
    expect(report.risk.status).not.toBe('failed')
  })

  it('memperlakukan registrasi yang tidak tersedia sebagai pemeriksaan netral', async () => {
    const tanpaRegistry = makeProbe()
    const tanpaRDAP = await run('http://paypa1.com/masuk', tanpaRegistry.probe)
    expect(tanpaRDAP.registration.status).toBe('unavailable')
    expect(tanpaRDAP.registration.findings).toEqual([])
    expect(tanpaRDAP.risk.evidence.some((entry) => entry.category === 'registration')).toBe(false)
    expect(tanpaRDAP.risk.notEvaluated.join(' ')).toContain('registrasi')

    // Skor harus sama persis: pemeriksaan yang tidak berjalan tidak boleh
    // menurunkan maupun menaikkan risiko.
    const timeout = makeProbe({
      registration: { registration: null, outcome: 'timeout', source: null, detail: 'Kueri RDAP melebihi batas waktu.' },
    })
    const reportTimeout = await run('http://paypa1.com/masuk', timeout.probe)
    expect(reportTimeout.registration.lookup.status).toBe('timeout')
    expect(reportTimeout.risk.riskScore).toBe(tanpaRDAP.risk.riskScore)
    const failedItem = reportTimeout.risk.evidence.find((entry) => entry.category === 'registration')
    expect(failedItem?.availability).toBe('failed')
  })

  it('domain tua memberi bukti peringan tanpa menghapus bukti merek', async () => {
    const { probe } = makeProbe({
      registration: rdapAnswer({ createdAt: new Date(NOW - 800 * DAY_MS).toISOString() }),
    })
    const report = await run('http://paypa1.com/masuk', probe)

    expect(report.registration.findings.map((entry) => entry.code)).toContain('domain_mature')
    const mature = report.risk.evidence.find((entry) => entry.id === 'registration:domain_mature')
    expect(mature?.strength).toBe('mitigating')
    expect(report.risk.evidence.some((entry) => entry.id.startsWith('brand:'))).toBe(true)
    expect(report.risk.level).not.toBe('critical')
  })

  it('hanya satu bukti merek yang dihitung walaupun temukannya banyak', async () => {
    const { probe } = makeProbe({
      origins: [okOrigin({ body: '<html><body><h1>PayPal</h1><img src="/img/paypal-logo.png"></body></html>' })],
    })
    const report = await run('http://paypa1-log0.biz/secure/paypal/masuk', probe)

    const brandItems = report.risk.evidence.filter((entry) => entry.category === 'brand')
    expect(brandItems).toHaveLength(1)
    expect(brandItems[0]?.detail).toContain('dihitung satu kali')
  })

  it('membedakan skor, keyakinan, cakupan, dan status pemindaian', async () => {
    const { probe } = makeProbe({ origins: [okOrigin({ body: CREDENTIAL_PAGE })] })
    const report = await run('https://example.com', probe)

    expect(report.risk.coverage.totalChecks).toBeGreaterThan(0)
    expect(report.risk.coverage.ratio).not.toBeNull()
    expect(typeof report.risk.riskScore).toBe('number')
    expect(['low', 'medium', 'high', 'critical', 'unknown']).toContain(report.risk.level)
    expect(['complete', 'partial', 'limited', 'failed']).toContain(report.risk.status)
    expect(report.risk.notes.join(' ')).toContain('bukan vonis')
  })

  it('membatasi penilaian ketika runtime tidak menyediakan akses sama sekali', async () => {
    const report = await run('http://paypa1.com/masuk', null)

    expect(report.registration.status).toBe('unavailable')
    expect(report.page.status).toBe('unavailable')
    expect(report.page.inspected).toBe(false)
    expect(report.risk.status).toBe('limited')
    expect(report.risk.confidence).toBe('low')
    expect(report.risk.riskScore ?? 0).toBeLessThanOrEqual(60)
    expect(report.risk.level).not.toBe('high')
    expect(report.risk.level).not.toBe('critical')
  })

  it('menilai halaman akhir pada domain tujuan, bukan domain awal', async () => {
    const sameHostForm =
      '<html><body><form action="https://pindah.example.net/api/masuk" method="post">' +
      '<input type="password"></form></body></html>'
    const { probe } = makeProbe({
      rotateResolve: [[PUBLIC], [OTHER_PUBLIC]],
      registration: rdapAnswer({ domain: 'example.com' }),
      origins: [
        okOrigin({
          status: 301,
          headers: [['location', 'https://pindah.example.net/masuk'], ['content-type', 'text/html']],
          body: '',
        }),
        okOrigin({ body: sameHostForm }),
      ],
    })
    const report = await run('https://example.com/masuk', probe)

    expect(report.registration.registrableDomain).toBe('example.com')
    expect(report.registration.notes.join(' ')).toContain('domain lain (example.net)')

    // Form mengirim ke domain tempat halaman akhir berada, jadi tidak ada
    // bukti kolom kredensial yang keluar domain.
    expect(report.page.inspected).toBe(true)
    expect(report.page.forms.totals.externalActions).toBe(0)
    expect(report.risk.evidence.some((entry) => entry.id === 'form:credential_request')).toBe(false)
  })
})

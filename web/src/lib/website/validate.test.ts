import { describe, expect, it } from 'vitest'
import { isSiteAnalysisResponse, parseSiteAnalysisResponse } from './validate'

function lookup(status: string, value: unknown, detail: string | null = null) {
  return { status, source: 'probe uji', value, detail, queriedAt: '2026-10-24T00:00:00.000Z' }
}

function rawReport(overrides: Record<string, unknown> = {}) {
  return {
    version: 1,
    target: 'https://contoh.com/',
    hostname: 'contoh.com',
    generatedAt: '2026-10-24T00:00:00.000Z',
    durationMs: 1_234,
    probe: { available: true, name: 'node-dns-tls-http', detail: null },
    website: {
      status: 'complete',
      identity: {
        hostname: 'contoh.com',
        addresses: lookup('success', [{ address: '93.184.216.34', kind: 'ipv4' }]),
        withheldAddresses: 0,
        asn: lookup('success', {
          asn: 'AS15133',
          organization: null,
          country: 'US',
          prefix: '93.184.216.0/24',
          registry: 'arin',
        }),
        intermediary: {
          state: 'possible',
          signals: [{ label: 'Cloudflare', evidence: 'Header `server`.' }],
          note: 'Belum pasti.',
        },
      },
      dns: [
        { type: 'A', lookup: lookup('success', ['93.184.216.34']) },
        { type: 'TXT', lookup: lookup('empty', [], 'Kueri selesai tanpa record.') },
      ],
      tls: {
        httpsAvailable: lookup('success', true),
        certificate: lookup('success', {
          issuer: "Let's Encrypt",
          subject: 'contoh.com',
          notBefore: '2026-01-01T00:00:00.000Z',
          notAfter: '2026-12-31T00:00:00.000Z',
          expired: false,
          hostnameVerified: true,
          verification: 'verified',
          verificationDetail: null,
          protocol: 'TLSv1.3',
        }),
        certificateSource: 'koneksi origin',
      },
      response: {
        request: lookup('success', null),
        status: 200,
        statusText: 'OK',
        finalUrl: 'https://contoh.com/',
        redirectCount: 0,
        elapsedMs: 120,
        contentType: 'text/html',
        bytes: 240,
        truncated: false,
        headers: [
          ['server', 'nginx'],
          ['content-type', 'text/html'],
        ],
        withheldHeaders: 2,
      },
      notes: ['Catatan satu.'],
    },
    technology: {
      status: 'partial',
      findings: [
        {
          name: 'nginx',
          category: 'server',
          evidence: ['header server'],
          confidence: 'medium',
          state: 'detected',
        },
      ],
      categories: [{ category: 'cms', state: 'no_signal', detail: 'Tidak ada sinyal.' }],
      document: {
        inspected: true,
        bytesScanned: 240,
        truncated: false,
        contentType: 'text/html',
        detail: null,
      },
      notes: ['Daftar tidak lengkap.'],
    },
    behavior: {
      status: 'complete',
      initialUrl: 'https://contoh.com/',
      redirects: [{ url: 'https://contoh.com/', status: 200, location: null, outcome: 'final', detail: null }],
      redirectCount: 0,
      redirectOutcome: 'final',
      hosts: [{ host: 'cdn.example', roles: ['referenced'], resourceKinds: ['script'], count: 2 }],
      resources: { scripts: 1, styles: 0, images: 2, iframes: 0, links: 3, other: 0, collected: 6, capped: false },
      securityHeaders: [{ name: 'strict-transport-security', present: true, value: 'max-age=31536000' }],
      cookies: [
        { name: 'session', secure: true, httpOnly: true, sameSite: 'lax', hasExpiry: false, valueShown: true },
      ],
      cookiesCollected: true,
      observations: [{ kind: 'response', state: 'observed', detail: 'Status 200.' }],
      notes: [],
    },
    ...overrides,
  }
}

describe('parseSiteAnalysisResponse menjaga data tidak tepercaya tetap aman', () => {
  it('mempertahankan laporan yang lengkap dan konsisten', () => {
    const report = parseSiteAnalysisResponse(rawReport())
    expect(report.version).toBe(1)
    expect(report.target).toBe('https://contoh.com/')
    expect(report.durationMs).toBe(1_234)
    expect(report.website.identity.addresses.value).toEqual([
      { address: '93.184.216.34', kind: 'ipv4' },
    ])
    expect(report.website.tls.certificate.value?.verification).toBe('verified')
    expect(report.technology.findings[0]).toMatchObject({ name: 'nginx', category: 'server' })
    expect(report.behavior.redirectOutcome).toBe('final')
    expect(report.website.notes).toEqual(['Catatan satu.'])
  })

  it('menolak payload yang bukan laporan versi 1', () => {
    expect(() => parseSiteAnalysisResponse(null)).toThrow(/tidak valid/)
    expect(() => parseSiteAnalysisResponse('ok')).toThrow(/tidak valid/)
    expect(() => parseSiteAnalysisResponse({ version: 2 })).toThrow(/tidak valid/)
    expect(
      isSiteAnalysisResponse({
        version: 1,
        target: 'x',
        hostname: 'y',
        probe: { available: false },
        website: {},
        technology: {},
        behavior: {},
      }),
    ).toBe(false)
    expect(isSiteAnalysisResponse(rawReport())).toBe(true)
  })

  it('mengganti nilai asing dengan status netral, bukan mengarang keberhasilan', () => {
    const report = parseSiteAnalysisResponse(
      rawReport({
        website: {
          status: 'aman',
          identity: {
            hostname: 'contoh.com',
            addresses: lookup('berhasil', null),
            withheldAddresses: -3,
            asn: lookup('unknown', { asn: 12_345 }),
            intermediary: { state: 'confirmed', signals: 'bukan array', note: '' },
          },
          dns: [
            { type: 'A', lookup: lookup('success', ['93.184.216.34']) },
            { type: 'HTTPS', lookup: lookup('success', ['tidak dikenal']) },
            { type: 'AAAA', lookup: lookup('success', ['2606:2800::101']) },
            { type: 'MX', lookup: lookup('success', ['10 mail']) },
            { type: 'NS', lookup: lookup('success', ['ns.example']) },
            { type: 'SOA', lookup: lookup('success', ['ns root']) },
            { type: 'TXT', lookup: lookup('success', ['v=spf1']) },
            { type: 'BOGUS', lookup: lookup('success', ['x']) },
          ],
          tls: { httpsAvailable: {}, certificate: {}, certificateSource: null },
          response: { request: {}, status: '200', redirectCount: -1, elapsedMs: '12' },
          notes: ['', 123, 'a'.repeat(900)],
        },
      }),
    )

    expect(report.website.status).toBe('unavailable')
    expect(report.website.identity.addresses.status).toBe('unavailable')
    expect(report.website.identity.withheldAddresses).toBe(0)
    expect(report.website.identity.asn.status).toBe('unavailable')
    // Angka bukan string ASN yang sah, jadi value dinolkan alih-alih ditampilkan sebagai karangan.
    expect(report.website.identity.asn.value).toBeNull()
    expect(report.website.identity.intermediary.state).toBe('unavailable')
    expect(report.website.identity.intermediary.signals).toEqual([])
    expect(report.website.identity.intermediary.note).toContain('belum dapat ditentukan')
    expect(report.website.dns.length).toBe(7)
    expect(report.website.dns.map((entry) => entry.type)).toContain('TXT')
    expect(report.website.response.status).toBeNull()
    expect(report.website.response.redirectCount).toBe(0)
    expect(report.website.response.elapsedMs).toBeNull()
    expect(report.website.response.headers).toEqual([])
    expect(report.website.tls.httpsAvailable.status).toBe('unavailable')
    expect(report.website.tls.certificate.value).toBeNull()
    expect(report.website.notes.every((note) => note.length <= 400)).toBe(true)
  })

  it('memotong teks panjang dan menghapus karakter kontrol', () => {
    const report = parseSiteAnalysisResponse(
      rawReport({
        target: `https://contoh.com/${'x'.repeat(600)}`,
        hostname: 'contoh.com\r\n injected',
        generatedAt: 'bukan tanggal',
        durationMs: -500,
        probe: { available: 'ya', name: 'x'.repeat(200), detail: '   ' },
      }),
    )

    expect(report.target.length).toBeLessThanOrEqual(300)
    expect(report.hostname).toBe('contoh.com injected')
    expect(report.generatedAt).toBe(new Date(0).toISOString())
    expect(report.durationMs).toBe(0)
    expect(report.probe.available).toBe(false)
    expect(report.probe.name.length).toBeLessThanOrEqual(80)
    expect(report.probe.detail).toBeNull()
  })

  it('tidak pernah menandai nilai cookie ditampilkan meski payload mengklaim begitu', () => {
    const report = parseSiteAnalysisResponse(
      rawReport({
        behavior: {
          ...rawReport().behavior,
          cookies: [
            { name: 'session', value: 'isi-cookie-rahasia', secure: true, httpOnly: true, sameSite: 'lax', hasExpiry: false, valueShown: true },
            { name: '', value: 'isi-cookie-kedua', secure: false, httpOnly: false, sameSite: null, hasExpiry: false, valueShown: true },
          ],
          observations: [
            { kind: 'entitas asing', state: 'observed', detail: 'Detail masih terbaca.' },
            { kind: 'cookie', state: 'di luar daftar', detail: '   ' },
          ],
          hosts: [
            { host: 'cdn.example', roles: ['observed', 'palsu'], resourceKinds: ['script'], count: -4 },
          ],
          redirects: [
            { url: 'https://contoh.com/', status: '200', location: '', outcome: 'terkamuflase', detail: 'x'.repeat(900) },
          ],
        },
      }),
    )

    expect(report.behavior.cookies.every((cookie) => cookie.valueShown === false)).toBe(true)
    expect(report.behavior.cookies[0]?.name).toBe('session')
    expect(JSON.stringify(report)).not.toContain('isi-cookie-rahasia')
    expect(JSON.stringify(report)).not.toContain('isi-cookie-kedua')
    expect(report.behavior.observations).toHaveLength(1)
    expect(report.behavior.observations[0]).toMatchObject({ kind: 'response', state: 'observed' })
    expect(report.behavior.hosts[0]).toMatchObject({ host: 'cdn.example', roles: ['observed'], count: 0 })
    expect(report.behavior.redirects[0]).toMatchObject({ status: null, outcome: 'error' })
    expect(report.behavior.redirects[0].location).toBeNull()
    expect(report.behavior.redirects[0].detail?.length).toBeLessThanOrEqual(400)
  })

  it('menormalkan bagian teknologi tanpa mengarang nama temuan', () => {
    const report = parseSiteAnalysisResponse(
      rawReport({
        technology: {
          status: 'lengkap',
          findings: [
            { name: '', category: 'cms', evidence: 'bukan array', confidence: 'pasti', state: 'detected' },
            { name: 'X', category: 'framework', evidence: ['ok'], confidence: 'high', state: 'mungkin' },
          ],
          categories: [{ category: 'cms', state: 'tepat', detail: '' }],
          document: { inspected: 'ya', bytesScanned: '240', truncated: 1, contentType: '', detail: '' },
          notes: null,
        },
      }),
    )

    expect(report.technology.status).toBe('unavailable')
    // Temuan tanpa nama dibuang supaya UI tidak menampilkan baris kosong.
    expect(report.technology.findings).toHaveLength(1)
    expect(report.technology.findings[0]).toMatchObject({
      name: 'X',
      category: 'other',
      confidence: 'high',
      state: 'possible',
    })
    expect(report.technology.findings[0].evidence).toEqual(['ok'])
    expect(report.technology.categories[0]).toMatchObject({ state: 'unavailable' })
    expect(report.technology.categories[0].detail).toBe('')
    expect(report.technology.document.inspected).toBe(false)
    expect(report.technology.document.bytesScanned).toBe(0)
    expect(report.technology.document.truncated).toBe(false)
    expect(report.technology.document.detail).toContain('tidak tersedia')
    expect(report.technology.notes).toEqual([])
  })

  it('menormalkan kategori asing menjadi tidak diketahui dengan keyakinan rendah', () => {
    const report = parseSiteAnalysisResponse(
      rawReport({
        category: {
          status: 'aman',
          primaryId: 'terorisme',
          primaryLabel: '',
          confidence: 'pasti',
          riskIndicated: false,
          summary: '',
          signals: [
            { categoryId: 'judi', label: 'x'.repeat(400), detail: '   ', source: 'isi', strength: 'keras' },
            { categoryId: 'gambling', label: 'istilah perjudian', detail: 'Judul memuat slot.', source: 'content', strength: 'strong' },
          ],
          alternatives: [{ id: 'gambling', label: '', confidence: 'yakin' }],
          evidenceBasis: { documentInspected: 'ya', visibleTextBytes: -5, redirectHops: '2' },
          notes: null,
        },
      }),
    )

    expect(report.category.status).toBe('unavailable')
    expect(report.category.primaryId).toBe('unknown')
    expect(report.category.primaryLabel).toBe('Tidak diketahui')
    expect(report.category.confidence).toBe('low')
    expect(report.category.riskIndicated).toBe(false)
    expect(report.category.summary).toContain('belum dapat ditentukan')
    expect(report.category.signals).toHaveLength(1)
    // Label alternatif yang kosong diisi dari daftar label bawaan, bukan dibiarkan kosong.
    expect(report.category.alternatives).toEqual([
      { id: 'gambling', label: 'Judi online', confidence: 'low' },
    ])
    expect(report.category.evidenceBasis).toEqual({
      documentInspected: false,
      titleAvailable: false,
      descriptionAvailable: false,
      visibleTextBytes: 0,
      redirectHops: 0,
    })
    expect(report.category.notes).toEqual([])
  })

  it('tetap memproses laporan lama yang belum membawa bagian kategori', () => {
    expect(isSiteAnalysisResponse(rawReport())).toBe(true)
    const report = parseSiteAnalysisResponse(rawReport())
    expect(report.category.primaryId).toBe('unknown')
    expect(report.category.confidence).toBe('low')
    expect(report.category.riskIndicated).toBe(false)
  })

  it('mempertahankan sinyal struktur URL dan form, membuang yang tidak dikenal', () => {
    const report = parseSiteAnalysisResponse(
      rawReport({
        behavior: {
          ...rawReport().behavior,
          observations: [
            { kind: 'url', state: 'observed', detail: '2 sinyal struktur.' },
            { kind: 'form', state: 'inferred', detail: '1 form ke host lain.' },
          ],
          structure: {
            status: 'complete',
            findings: [
              { code: 'ip_literal', label: 'Host ditulis sebagai alamat IP', detail: 'Bentuk angka.', strength: 'moderate', evidence: '93.184.216.34' },
              { code: 'vonis_pribadi', label: 'Kode asing', detail: 'Tidak boleh dilabeli ulang.', strength: 'strong', evidence: null },
              { code: 'typosquat', label: '', detail: '   ', strength: 'keras', evidence: 'paypa1' },
            ],
            hostname: 'CONTOH.COM',
            scheme: 'HTTPS',
            port: '8080',
            labelCount: 2,
            registrableDomain: 'contoh.com',
            notes: ['Sinyal berkorelasi.'],
          },
          forms: {
            inspected: true,
            forms: [
              { index: 1, action: 'https://luar.example/kirim', actionHost: 'luar.example', actionScheme: 'https', external: true, insecure: false, method: 'POST', passwordFields: 2, textFields: 1 },
              { index: 2, action: null, actionHost: null, actionScheme: null, external: 'ya', insecure: null, method: 42, passwordFields: -3, textFields: 'x' },
            ],
            totals: { forms: 2, passwordFields: 2, externalActions: 1, insecureActions: 0 },
            capped: false,
            detail: '2 form teridentifikasi.',
          },
        },
      }),
    )

    expect(report.behavior.observations.map((entry) => entry.kind)).toEqual(['url', 'form'])
    expect(report.behavior.structure.status).toBe('complete')
    // Temuan berkode asing dibuang, bukan diberi kode lain, dan temuan tanpa detail ikut dibuang.
    expect(report.behavior.structure.findings.map((entry) => entry.code)).toEqual(['ip_literal'])
    expect(report.behavior.structure.findings[0]).toMatchObject({ strength: 'moderate', label: 'Host ditulis sebagai alamat IP' })
    expect(report.behavior.structure.hostname).toBe('CONTOH.COM')
    expect(report.behavior.structure.registrableDomain).toBe('contoh.com')
    expect(report.behavior.structure.notes).toEqual(['Sinyal berkorelasi.'])

    expect(report.behavior.forms.inspected).toBe(true)
    expect(report.behavior.forms.forms[0]).toMatchObject({ external: true, method: 'POST', passwordFields: 2 })
    expect(report.behavior.forms.forms[1]).toMatchObject({ external: false, insecure: false, method: null, passwordFields: 0, textFields: 0 })
    expect(report.behavior.forms.totals).toEqual({ forms: 2, passwordFields: 2, externalActions: 1, insecureActions: 0 })
  })

  it('memperlakukan laporan tanpa bagian struktur dan form sebagai tidak tersedia', () => {
    const report = parseSiteAnalysisResponse(rawReport())
    expect(report.behavior.structure.status).toBe('unavailable')
    expect(report.behavior.structure.findings).toEqual([])
    expect(report.behavior.structure.notes.join(' ')).toContain('tidak dikembalikan oleh backend')
    expect(report.behavior.forms.inspected).toBe(false)
    expect(report.behavior.forms.forms).toEqual([])
    expect(report.behavior.forms.detail).toContain('belum dapat diperiksa')
  })

  it('tidak menerima angka negatif atau teks beracun pada struktur dan form', () => {
    const report = parseSiteAnalysisResponse(
      rawReport({
        behavior: {
          ...rawReport().behavior,
          structure: {
            status: 'aman',
            findings: [{ code: 'punycode', label: 'x'.repeat(900), detail: 'label\r\n disuntik', strength: 'erat', evidence: '<script>1</script>' }],
            hostname: 'contoh.com',
            scheme: 'x'.repeat(90),
            port: 'y'.repeat(90),
            labelCount: -4,
            registrableDomain: null,
            notes: 'bukan array',
          },
          forms: {
            inspected: 'ya',
            forms: { bukan: 'array' },
            totals: { forms: -1, passwordFields: 'x' },
            capped: 1,
            detail: '',
          },
        },
      }),
    )

    expect(report.behavior.structure.status).toBe('unavailable')
    expect(report.behavior.structure.labelCount).toBe(0)
    expect(report.behavior.structure.findings[0]?.label.length).toBeLessThanOrEqual(120)
    expect(report.behavior.structure.findings[0]?.detail).toBe('label disuntik')
    expect(report.behavior.structure.findings[0]?.strength).toBe('weak')
    expect(report.behavior.structure.findings[0]?.evidence).toBe('<script>1</script>')
    expect(report.behavior.structure.scheme?.length).toBeLessThanOrEqual(16)
    expect(report.behavior.structure.notes).toEqual([])

    expect(report.behavior.forms.inspected).toBe(false)
    expect(report.behavior.forms.forms).toEqual([])
    expect(report.behavior.forms.capped).toBe(false)
    expect(report.behavior.forms.totals.forms).toBe(0)
    expect(report.behavior.forms.detail).toContain('belum dapat diperiksa')
  })

  it('menyimpulkan indikasi risiko dari kategori, bukan dari flag payload', () => {
    const report = parseSiteAnalysisResponse(
      rawReport({
        category: {
          status: 'complete',
          primaryId: 'phishing',
          primaryLabel: 'Phishing',
          confidence: 'medium',
          riskIndicated: false,
          summary: 'Bukti mengarah ke kategori phishing.',
          signals: [],
          alternatives: [
            { id: 'phishing', label: 'Phishing', confidence: 'medium' },
            { id: 'scam', label: 'Penipuan', confidence: 'low' },
          ],
          evidenceBasis: { documentInspected: true, titleAvailable: true, descriptionAvailable: false, visibleTextBytes: 900, redirectHops: 0 },
          notes: [],
        },
      }),
    )

    expect(report.category.riskIndicated).toBe(true)
    // Alternatif yang sama dengan kategori utama dibuang agar UI tidak menduplikasi.
    expect(report.category.alternatives.map((option) => option.id)).toEqual(['scam'])
  })
})

function riskSection(overrides: Record<string, unknown> = {}) {
  return {
    status: 'limited',
    level: 'low',
    riskScore: 9,
    confidence: 'low',
    confidenceDetail:
      '1 bukti risiko dari 1 kategori berbeda, cakupan pemeriksaan 3/17. Keyakinan rendah: bukti yang tersedia sedikit atau cakupannya sempit; ini bukan pernyataan bahwa target aman.',
    coverage: {
      totalChecks: 17,
      succeeded: 3,
      unavailable: 12,
      failed: 2,
      ratio: 0.18,
      byCategory: [
        { category: 'url_structure', succeeded: 1, total: 1 },
        { category: 'registration', succeeded: 1, total: 1 },
        { category: 'dns', succeeded: 1, total: 8 },
        { category: 'tls', succeeded: 0, total: 2 },
      ],
    },
    evidence: [
      {
        id: 'registration:domain_young',
        category: 'registration',
        label: 'Domain baru berusia 0 hari',
        detail:
          'Domain scurs.net terdaftar 0 hari sebelum pemeriksaan ini. Kampanye phishing sering memakai domain yang baru dibeli, tetapi banyak situs sah juga baru didaftarkan.',
        observed: '2026-10-29T11:04:08.000Z',
        source: 'registry RDAP rdap.verisign.com',
        strength: 'moderate',
        availability: 'observed',
        observedAt: '2026-10-30T07:23:38.519Z',
      },
    ],
    notEvaluated: [
      'Sertifikat TLS tidak terbaca dari runtime ini.',
      'Dokumen HTML tidak diperiksa, jadi isi halaman tidak dinilai.',
    ],
    notes: ['Skor risiko adalah penjumlahan bobot bukti, bukan probabilitas dan bukan vonis.'],
    ...overrides,
  }
}

function registrationSection(overrides: Record<string, unknown> = {}) {
  return {
    status: 'complete',
    registrableDomain: 'scurs.net',
    lookup: lookup('success', {
      domain: 'scurs.net',
      handle: '3160244131_DOMAIN_NET-VRSN',
      registrar: 'Hosting Concepts B.V.',
      createdAt: '2026-10-29T11:04:08.000Z',
      changedAt: '2026-10-29T11:13:22.000Z',
      expiresAt: '2027-10-29T11:04:08.000Z',
      statuses: ['client transfer prohibited'],
    }),
    ageDays: 0,
    ageBasis: 'registration',
    findings: [
      {
        code: 'domain_young',
        label: 'Domain baru berusia 0 hari',
        detail: 'Domain scurs.net terdaftar 0 hari sebelum pemeriksaan ini.',
        strength: 'moderate',
        evidence: '2026-10-29T11:04:08.000Z',
      },
    ],
    notes: ['Domain muda adalah indikator lemah sampai sedang.'],
    ...overrides,
  }
}

function pageSection(overrides: Record<string, unknown> = {}) {
  return {
    status: 'complete',
    inspected: true,
    bytesScanned: 240,
    truncated: false,
    anchors: { internal: 3, external: 2, externalHosts: ['cdn.example'], ratio: 0.4 },
    scripts: { total: 4, external: 1, inline: 3 },
    forms: {
      inspected: true,
      forms: [
        {
          index: 0,
          action: 'https://luar.example/masuk',
          actionHost: 'luar.example',
          actionScheme: 'https',
          external: true,
          insecure: false,
          method: 'POST',
          passwordFields: 1,
          textFields: 2,
        },
      ],
      totals: { forms: 1, passwordFields: 1, externalActions: 1, insecureActions: 0 },
      capped: false,
      detail: '1 form mengirim ke host lain.',
    },
    findings: [
      {
        code: 'credential_request',
        label: 'Halaman meminta kredensial',
        detail: 'Terdapat kolom OTP pada dokumen.',
        strength: 'moderate',
        evidence: 'name="otp"',
      },
    ],
    notes: ['Dokumen HTML dibaca statis; skrip halaman tidak dijalankan.'],
    ...overrides,
  }
}

describe('parseSiteAnalysisResponse mempertahankan fusi risiko Stage 5', () => {
  it('mempertahankan status, level, skor, keyakinan, cakupan, bukti, dan yang tidak dinilai', () => {
    const report = parseSiteAnalysisResponse(rawReport({ risk: riskSection() }))

    expect(report.risk).not.toBeNull()
    expect(report.risk?.status).toBe('limited')
    expect(report.risk?.level).toBe('low')
    expect(report.risk?.riskScore).toBe(9)
    expect(report.risk?.confidence).toBe('low')
    expect(report.risk?.confidenceDetail).toContain('bukan pernyataan bahwa target aman')
    expect(report.risk?.coverage).toMatchObject({
      totalChecks: 17,
      succeeded: 3,
      unavailable: 12,
      failed: 2,
      ratio: 0.18,
    })
    expect(report.risk?.coverage.byCategory).toEqual([
      { category: 'url_structure', succeeded: 1, total: 1 },
      { category: 'registration', succeeded: 1, total: 1 },
      { category: 'dns', succeeded: 1, total: 8 },
      { category: 'tls', succeeded: 0, total: 2 },
    ])
    expect(report.risk?.evidence[0]).toMatchObject({
      id: 'registration:domain_young',
      category: 'registration',
      strength: 'moderate',
      availability: 'observed',
      source: 'registry RDAP rdap.verisign.com',
    })
    expect(report.risk?.notEvaluated).toHaveLength(2)
    expect(report.risk?.notes[0]).toContain('bukan probabilitas')
  })

  it('mempertahankan bagian registrasi dan halaman beserta temuannya', () => {
    const report = parseSiteAnalysisResponse(
      rawReport({ registration: registrationSection(), page: pageSection() }),
    )

    // Umur 0 hari adalah fakta, bukan kolom kosong: nol harus tetap nol.
    expect(report.registration?.ageDays).toBe(0)
    expect(report.registration?.ageBasis).toBe('registration')
    expect(report.registration?.status).toBe('complete')
    expect(report.registration?.registrableDomain).toBe('scurs.net')
    expect(report.registration?.lookup.status).toBe('success')
    expect(report.registration?.lookup.value?.registrar).toBe('Hosting Concepts B.V.')
    expect(report.registration?.lookup.value?.statuses).toEqual(['client transfer prohibited'])
    expect(report.registration?.findings[0]).toMatchObject({
      code: 'domain_young',
      strength: 'moderate',
    })

    expect(report.page?.inspected).toBe(true)
    expect(report.page?.anchors).toMatchObject({ internal: 3, external: 2, ratio: 0.4 })
    expect(report.page?.anchors.externalHosts).toEqual(['cdn.example'])
    expect(report.page?.scripts).toEqual({ total: 4, external: 1, inline: 3 })
    expect(report.page?.findings[0]?.code).toBe('credential_request')
    expect(report.page?.forms.totals).toMatchObject({ forms: 1, externalActions: 1 })
    expect(report.page?.forms.forms[0]).toMatchObject({ external: true, passwordFields: 1 })
  })

  it('membiarkan nilai yang tidak ada sebagai null alih-alih mengarang nol', () => {
    const report = parseSiteAnalysisResponse(
      rawReport({
        risk: {
          status: 'limited',
          level: 'unknown',
          riskScore: null,
          confidence: 'low',
          evidence: [],
        },
        registration: registrationSection({
          ageDays: null,
          ageBasis: 'none',
          lookup: lookup('unavailable', null, 'RDAP tidak menjawab.'),
          findings: [],
        }),
        page: pageSection({
          inspected: false,
          anchors: { internal: 0, external: 0, externalHosts: [], ratio: null },
        }),
      }),
    )

    expect(report.risk?.riskScore).toBeNull()
    expect(report.risk?.level).toBe('unknown')
    expect(report.risk?.confidenceDetail).toContain('tidak menyatakan keyakinan')
    expect(report.risk?.coverage).toEqual({
      totalChecks: 0,
      succeeded: 0,
      unavailable: 0,
      failed: 0,
      ratio: null,
      byCategory: [],
    })
    expect(report.registration?.ageDays).toBeNull()
    expect(report.registration?.ageBasis).toBe('none')
    expect(report.registration?.lookup.value).toBeNull()
    expect(report.page?.anchors.ratio).toBeNull()
  })

  it('tetap memproses laporan lama yang belum membawa registrasi, halaman, atau fusi', () => {
    expect(isSiteAnalysisResponse(rawReport())).toBe(true)

    const legacy = parseSiteAnalysisResponse(rawReport())
    expect(legacy.registration).toBeNull()
    expect(legacy.page).toBeNull()
    expect(legacy.risk).toBeNull()

    const explicitNull = parseSiteAnalysisResponse(
      rawReport({ registration: null, page: null, risk: null }),
    )
    expect(explicitNull.risk).toBeNull()
  })

  it('membuang baris bukti dan cakupan berkategori asing tanpa melabeli ulang', () => {
    const risk = riskSection({
      evidence: [
        ...riskSection().evidence,
        {
          id: 'quantum:new',
          category: 'quantum',
          label: 'Sumbu yang belum dikenal klien',
          detail: 'Bukti ini tidak boleh muncul di kategori lain.',
          observed: null,
          source: 'backend baru',
          strength: 'strong',
          availability: 'observed',
          observedAt: null,
        },
        { id: '', category: 'dns', label: 'tanpa id', detail: 'tidak dapat ditelusuri' },
      ],
    })
    const coverage = {
      totalChecks: 17,
      succeeded: 3,
      unavailable: 12,
      failed: 2,
      ratio: 0.18,
      byCategory: [
        { category: 'registration', succeeded: 1, total: 1 },
        { category: 'quantum', succeeded: 1, total: 1 },
      ],
    }

    const report = parseSiteAnalysisResponse(rawReport({ risk: { ...risk, coverage } }))

    expect(report.risk?.evidence.map((entry) => entry.id)).toEqual(['registration:domain_young'])
    expect(report.risk?.coverage.byCategory).toEqual([
      { category: 'registration', succeeded: 1, total: 1 },
    ])
    // Jumlah dari backend tidak diubah, jadi cakupan tetap terbaca apa adanya.
    expect(report.risk?.coverage.totalChecks).toBe(17)
    expect(report.risk?.coverage.succeeded).toBe(3)
  })

  it('membaca status dan level yang tidak dikenal sebagai terbatas dan tidak diketahui', () => {
    const report = parseSiteAnalysisResponse(
      rawReport({
        risk: {
          status: 'aman',
          level: 'pasti',
          riskScore: '9',
          confidence: 'yakin',
          confidenceDetail: '   ',
          coverage: 'bukan objek',
          evidence: 'bukan array',
          notEvaluated: null,
          notes: { bukan: 'array' },
        },
        registration: registrationSection({
          ageDays: '0',
          registrableDomain: '',
          findings: [{ code: 'domain_baru', label: 'Kode asing', detail: 'Tidak dinilai.' }],
        }),
      }),
    )

    expect(report.risk?.status).toBe('limited')
    expect(report.risk?.level).toBe('unknown')
    expect(report.risk?.riskScore).toBeNull()
    expect(report.risk?.confidence).toBe('low')
    expect(report.risk?.confidenceDetail).toContain('tidak menyatakan keyakinan')
    expect(report.risk?.coverage.totalChecks).toBe(0)
    expect(report.risk?.evidence).toEqual([])
    expect(report.risk?.notEvaluated).toEqual([])
    expect(report.risk?.notes).toEqual([])

    // Usia sebagai string bukan angka terhingga: dibaca tidak diketahui, bukan 0.
    expect(report.registration?.ageDays).toBeNull()
    expect(report.registration?.registrableDomain).toBeNull()
    expect(report.registration?.findings).toEqual([])
  })

  it('memotong teks panjang dan karakter kontrol pada bukti serta daftar yang tidak dinilai', () => {
    const report = parseSiteAnalysisResponse(
      rawReport({
        risk: riskSection({
          evidence: [
            {
              id: 'page:urgency_language',
              category: 'page_content',
              label: 'x'.repeat(400),
              detail: `segera\r\n injected${'y'.repeat(900)}`,
              observed: 'z'.repeat(500),
              source: '',
              strength: 'erat',
              availability: 'observed tapi palsu',
              observedAt: 'bukan tanggal',
            },
          ],
          notEvaluated: ['   ', 'a'.repeat(600)],
        }),
      }),
    )

    const entry = report.risk?.evidence[0]
    expect(entry?.label.length).toBeLessThanOrEqual(120)
    expect(entry?.detail.length).toBeLessThanOrEqual(400)
    expect(entry?.detail.startsWith('segera injected')).toBe(true)
    expect(entry?.detail).not.toContain('\r')
    expect(entry?.detail).not.toContain('\n')
    expect(entry?.observed?.length).toBeLessThanOrEqual(200)
    expect(entry?.source).toBe('sumber tidak dinyatakan')
    // Kekuatan dan ketersediaan asing dinormalkan ke nilai paling lemah / tidak tersedia.
    expect(entry?.strength).toBe('weak')
    expect(entry?.availability).toBe('unavailable')
    expect(entry?.observedAt).toBeNull()
    expect(report.risk?.notEvaluated).toHaveLength(1)
    expect(report.risk?.notEvaluated[0]?.length).toBeLessThanOrEqual(200)
  })

  it('menolak payload yang membawa bagian Stage 5 sebagai bukan objek pada gerbang tipe', () => {
    expect(isSiteAnalysisResponse(rawReport({ risk: 'bukan objek' }))).toBe(false)
    expect(isSiteAnalysisResponse(rawReport({ registration: [1, 2] }))).toBe(false)
    expect(isSiteAnalysisResponse(rawReport({ page: 3 }))).toBe(false)
    expect(isSiteAnalysisResponse(rawReport({ risk: riskSection() }))).toBe(true)
  })

  it('memakai pembaca form yang sama sehingga halaman tidak bisa menyuntik nilai', () => {
    const report = parseSiteAnalysisResponse(
      rawReport({
        page: pageSection({
          forms: {
            inspected: 'ya',
            forms: { bukan: 'array' },
            totals: { forms: -1, passwordFields: 'x' },
            capped: 1,
            detail: '',
          },
        }),
      }),
    )

    expect(report.page?.forms.inspected).toBe(false)
    expect(report.page?.forms.forms).toEqual([])
    expect(report.page?.forms.totals.forms).toBe(0)
    expect(report.page?.forms.detail).toContain('belum dapat diperiksa')
  })
})

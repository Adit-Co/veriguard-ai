import { describe, expect, it } from 'vitest'
import {
  BEHAVIOR_LIMITS,
  analyzeForms,
  buildBehaviorObservations,
  classifyHosts,
  collectSetCookies,
  extractResources,
  observeSecurityHeaders,
  readCookieMetadata,
  summarizeResources,
} from '../src/website/behavior.js'
import type { ParsedResource } from '../src/website/behavior.js'
import type { BehaviorObservation } from '../src/website/types.js'

const BASE = 'https://toko.example/cart'

function resource(kind: ParsedResource['kind'], host: string): ParsedResource {
  return { kind, host, absolute: `https://${host}/asset` }
}

describe('extractResources', () => {
  it('memilah sumber daya berdasarkan tag dan atribut', () => {
    const html = `
      <script src="https://cdn.example/app.js"></script>
      <link rel="stylesheet" href="/theme.css">
      <img src="https://img.example/a.png">
      <iframe src="https://embed.example/player"></iframe>
      <a href="https://layar.example/checkout">Bayar</a>
      <link rel="icon" href="/favicon.ico">
      <script src="data:text/javascript,alert(1)"></script>
      <script src="javascript:void(0)"></script>
    `
    const { resources, capped } = extractResources(html, BASE)
    const kinds = resources.map((entry) => `${entry.kind}:${entry.host}`)
    expect(capped).toBe(false)
    expect(kinds).toContain('script:cdn.example')
    expect(kinds).toContain('style:toko.example')
    expect(kinds).toContain('image:img.example')
    expect(kinds).toContain('frame:embed.example')
    expect(kinds).toContain('anchor:layar.example')
    expect(kinds.filter((entry) => entry.startsWith('other:'))).toEqual([])
  })

  it('mengabaikan data URI, skrip inline, dan tautan non-HTTP', () => {
    const { resources } = extractResources(
      '<a href="mailto:hi@example.com">surel</a><a href="#bagian">bagian</a><a href="ftp://x.example/f">ftp</a><script>alert(1)</script>',
      BASE,
    )
    expect(resources).toEqual([])
  })

  it('membatasi jumlah sumber daya dan menandainya', () => {
    const html = `<img src="https://a.example/${'1'}">`.repeat(BEHAVIOR_LIMITS.maxResources + 20)
    const { resources, capped } = extractResources(html, BASE)
    expect(resources).toHaveLength(BEHAVIOR_LIMITS.maxResources)
    expect(capped).toBe(true)
    const summary = summarizeResources(resources, capped)
    expect(summary).toMatchObject({ images: BEHAVIOR_LIMITS.maxResources, capped: true })
  })

  it('menjumlahkan tiap jenis sumber daya', () => {
    const { resources } = extractResources(
      '<script src="https://a.example/1.js"></script><link rel="stylesheet" href="https://a.example/1.css"><img src="https://b.example/1.png">',
      BASE,
    )
    expect(summarizeResources(resources, false)).toMatchObject({
      scripts: 1,
      styles: 1,
      images: 1,
      iframes: 0,
      collected: 3,
    })
  })
})

describe('classifyHosts memisahkan peran host', () => {
  it('hanya menandai observed untuk host yang benar-benar dihubungi', () => {
    const { entries } = classifyHosts({
      observedHosts: ['cdn.example', 'toko.example'],
      resources: [resource('script', 'api.example'), resource('image', 'cdn.example')],
      html: 'Lihat juga https://rekan.example/promo dan https://cdn.example/doc',
      pageHost: 'toko.example',
    })
    const byHost = new Map(entries.map((entry) => [entry.host, entry.roles]))
    expect(byHost.get('cdn.example')).toEqual(['observed', 'referenced'])
    expect(byHost.get('api.example')).toEqual(['referenced'])
    expect(byHost.get('rekan.example')).toEqual(['inferred'])
    expect(byHost.has('toko.example')).toBe(false)
  })

  it('tidak menyebut host yang hanya disebut dalam teks sebagai terhubung', () => {
    const { entries } = classifyHosts({
      observedHosts: [],
      resources: [],
      html: '<p>Referensi: https://sekadar-teks.example/artikel</p>',
      pageHost: 'toko.example',
    })
    expect(entries).toHaveLength(1)
    expect(entries[0]).toMatchObject({ host: 'sekadar-teks.example', roles: ['inferred'] })
  })

  it('menggabungkan peran ketika host muncul sebagai sumber daya dan teks', () => {
    const { entries } = classifyHosts({
      observedHosts: [],
      resources: [resource('frame', 'embed.example')],
      html: 'https://embed.example/page',
      pageHost: 'toko.example',
    })
    expect(entries).toHaveLength(1)
    expect(entries[0]).toMatchObject({ host: 'embed.example', roles: ['referenced'], count: 1 })
  })

  it('membatasi jumlah entri host', () => {
    const many = Array.from({ length: 60 }, (_, index) => resource('script', `h${index}.example`))
    const { entries, capped } = classifyHosts({
      observedHosts: [],
      resources: many,
      html: null,
      pageHost: 'toko.example',
    })
    expect(entries).toHaveLength(BEHAVIOR_LIMITS.maxHosts)
    expect(capped).toBe(true)
  })
})

describe('readCookieMetadata tidak pernah membaca nilai cookie', () => {
  it('mengekstrak nama dan atribut keamanan saja', () => {
    const { cookies, capped } = readCookieMetadata([
      'sesi=NYRAHASIA; Secure; HttpOnly; SameSite=Lax; Expires=Wed, 21 Oct 2026 07:28:00 GMT',
      'preferensi=terang; Path=/',
      '=tanpanilai',
      'noncookie',
    ])
    expect(capped).toBe(false)
    expect(cookies).toEqual([
      { name: 'sesi', secure: true, httpOnly: true, sameSite: 'lax', hasExpiry: true, valueShown: false },
      { name: 'preferensi', secure: false, httpOnly: false, sameSite: null, hasExpiry: false, valueShown: false },
    ])
  })

  it('membatasi jumlah cookie dan menghentikan pembacaan', () => {
    const raw = Array.from({ length: 40 }, (_, index) => `k${index}=v${index}; Secure`)
    const { cookies, capped } = readCookieMetadata(raw)
    expect(cookies).toHaveLength(BEHAVIOR_LIMITS.maxCookies)
    expect(capped).toBe(true)
    expect(cookies.every((entry) => entry.valueShown === false)).toBe(true)
    expect(JSON.stringify(cookies)).not.toContain('v0')
  })

  it('mengumpulkan header set-cookie ganda dari respons', () => {
    const values = collectSetCookies([
      ['Set-Cookie', 'a=1; Secure'],
      ['set-cookie', 'b=2'],
      ['content-type', 'text/html'],
    ])
    expect(values).toEqual(['a=1; Secure', 'b=2'])
  })
})

describe('observeSecurityHeaders', () => {
  it('menandai header keamanan yang ada dan yang tidak ada', () => {
    const observed = observeSecurityHeaders([
      ['content-security-policy', "default-src 'self'"],
      ['x-frame-options', 'DENY'],
    ])
    const byName = new Map(observed.map((entry) => [entry.name, entry]))
    expect(byName.get('content-security-policy')).toMatchObject({ present: true, value: "default-src 'self'" })
    expect(byName.get('strict-transport-security')?.present).toBe(false)
    expect(byName.get('strict-transport-security')?.value).toBeNull()
  })

  it('memotong nilai header panjang dan karakter kontrol', () => {
    const observed = observeSecurityHeaders([
      ['content-security-policy', `a\u0000b ${'x'.repeat(400)}`],
    ])
    const value = observed.find((entry) => entry.name === 'content-security-policy')?.value
    expect(value).toBeDefined()
    expect(value?.length ?? 0).toBeLessThanOrEqual(220)
    expect(value).not.toContain('\u0000')
  })
})

describe('buildBehaviorObservations', () => {
  it('menambahkan catatan status akhir tanpa mengarang kesimpulan', () => {
    const observations = buildBehaviorObservations({
      redirectCount: 2,
      finalStatus: 200,
      observations: [{ kind: 'cookie', state: 'observed', detail: 'Dua cookie diamati.' }],
    })
    expect(observations.some((entry) => entry.kind === 'cookie')).toBe(true)
    expect(observations.some((entry) => entry.kind === 'response' && entry.detail.includes('200'))).toBe(true)
    expect(observations.some((entry) => entry.kind === 'redirect' && entry.detail.startsWith('2 lompatan'))).toBe(true)
  })

  it('menyatakan ketidaktersediaan ketika respons akhir tidak diambil', () => {
    const observations = buildBehaviorObservations({ redirectCount: 0, finalStatus: null, observations: [] })
    expect(observations.some((entry) => entry.kind === 'response' && entry.state === 'unavailable')).toBe(true)
    expect(observations.some((entry) => entry.kind === 'redirect' && entry.detail.startsWith('Tidak ada'))).toBe(true)
  })

  it('tidak duplikat pengamatan redirect yang sudah ada', () => {
    const observations = buildBehaviorObservations({
      redirectCount: 1,
      finalStatus: 200,
      observations: [{ kind: 'redirect', state: 'observed', detail: ' Redirect 301 ke /pindah.' }],
    })
    expect(observations.filter((entry) => entry.kind === 'redirect')).toHaveLength(1)
  })

  it('mencatat sinyal url dan form tanpa menggeser pengamatan redirect', () => {
    const observations = buildBehaviorObservations({
      redirectCount: 1,
      finalStatus: 200,
      observations: [
        { kind: 'redirect', state: 'observed', detail: 'Satu lompatan tercatat.' },
        { kind: 'url', state: 'observed', detail: 'Struktur URL: port non-standar.' },
        { kind: 'form', state: 'inferred', detail: '2 form teridentifikasi.' },
      ],
    })
    expect(observations[0]?.kind).toBe('redirect')
    expect(observations.some((entry) => entry.kind === 'url')).toBe(true)
    expect(observations.some((entry) => entry.kind === 'form')).toBe(true)
  })

  it('membatasi daftar pengamatan pada batas yang dinyatakan', () => {
    const many = Array.from({ length: 30 }, (_, index): BehaviorObservation => ({
      kind: index % 2 === 0 ? 'redirect' : 'response',
      state: 'observed',
      detail: `Pengamatan ${index}`,
    }))
    const observations = buildBehaviorObservations({
      redirectCount: 0,
      finalStatus: 200,
      observations: many,
    })
    expect(observations.length).toBeLessThanOrEqual(14)
  })
})

describe('analyzeForms', () => {
  const PAGE = { baseUrl: 'https://toko.example/masuk', pageHost: 'toko.example', pageSecure: true }

  it('nyatakan tidak tersedia ketika HTML tidak terbaca', () => {
    const analysis = analyzeForms({ html: null, ...PAGE })
    expect(analysis.inspected).toBe(false)
    expect(analysis.forms).toEqual([])
    expect(analysis.detail).toContain('Dokumen HTML tidak tersedia')
  })

  it('nyatakan tidak tersedia ketika URL dasar tidak terbaca', () => {
    const analysis = analyzeForms({
      html: '<form action="/masuk"><input type="password"></form>',
      baseUrl: null,
      pageHost: 'toko.example',
      pageSecure: true,
    })
    expect(analysis.inspected).toBe(false)
    expect(analysis.detail).toContain('URL dasar halaman tidak terbaca')
  })

  it('membedakan form tanpa action, action relatif, dan action ke host lain', () => {
    const analysis = analyzeForms({
      html: `
        <form><input name="q"></form>
        <form action="/proses" method="post"><input name="email"><input type="password" name="sandi"></form>
        <form action="https://penampung.example/kirim" method="POST"><input type="password"><input type="submit"></form>
      `,
      ...PAGE,
    })
    expect(analysis.inspected).toBe(true)
    expect(analysis.forms).toHaveLength(3)

    const [tanpaAction, relatif, eksternal] = analysis.forms
    expect(tanpaAction?.action).toBeNull()
    expect(tanpaAction?.actionHost).toBe('toko.example')
    expect(tanpaAction?.external).toBe(false)
    expect(tanpaAction?.method).toBe('GET')

    expect(relatif?.action).toBe('https://toko.example/proses')
    expect(relatif?.external).toBe(false)
    expect(relatif?.passwordFields).toBe(1)
    expect(relatif?.textFields).toBe(1)

    expect(eksternal?.external).toBe(true)
    expect(eksternal?.actionHost).toBe('penampung.example')
    expect(eksternal?.actionScheme).toBe('https')
    expect(eksternal?.method).toBe('POST')
    expect(eksternal?.insecure).toBe(false)
  })

  it('menandai action tanpa enkripsi dan halaman aman yang membawa kolom sandi', () => {
    const analysis = analyzeForms({
      html: '<form action="http://kirim.example/deras"><input type="password"></form>',
      ...PAGE,
    })
    expect(analysis.forms[0]?.insecure).toBe(true)
    expect(analysis.totals.insecureActions).toBe(1)

    const halamanTidakAman = analyzeForms({
      html: '<form><input type="password"></form>',
      baseUrl: 'http://toko.example/masuk',
      pageHost: 'toko.example',
      pageSecure: false,
    })
    expect(halamanTidakAman.forms[0]?.insecure).toBe(true)
  })

  it('menjumlahkan total dan menolak menghitung kolom tersembunyi sebagai kolom teks', () => {
    const analysis = analyzeForms({
      html: `
        <form action="https://luar.example/a"><input type="hidden" name="tok"><input type="password"><input type="submit"></form>
        <form action="https://luar.example/b"><input name="satu"><input name="dua"></form>
      `,
      ...PAGE,
    })
    expect(analysis.totals).toEqual({
      forms: 2,
      passwordFields: 1,
      externalActions: 2,
      insecureActions: 0,
    })
    expect(analysis.forms[0]?.textFields).toBe(0)
    expect(analysis.forms[1]?.textFields).toBe(2)
  })

  it('menghitung setiap kolom, bukan hanya temuan pertama', () => {
    const analysis = analyzeForms({
      html: '<form action="/ganti"><input type="password"><input type="password"><input type="hidden"><input name="nama"></form>',
      ...PAGE,
    })
    expect(analysis.forms[0]?.passwordFields).toBe(2)
    expect(analysis.forms[0]?.textFields).toBe(1)
    expect(analysis.totals.passwordFields).toBe(2)
  })

  it('membatasi jumlah form dan menandainya sebagai terpotong', () => {
    const html = `<form action="https://luar.example/${'1'}"><input name="a"></form>`.repeat(
      BEHAVIOR_LIMITS.maxForms + 5,
    )
    const analysis = analyzeForms({ html, ...PAGE })
    expect(analysis.forms).toHaveLength(BEHAVIOR_LIMITS.maxForms)
    expect(analysis.capped).toBe(true)
  })

  it('membatasi isi form yang tidak ditutup agar tidak memindai seluruh dokumen', () => {
    const html =
      `<form action="https://luar.example/a"><input type="password">` +
      'x'.repeat(BEHAVIOR_LIMITS.maxFormBody) +
      '<input type="password">'

    const analysis = analyzeForms({ html, ...PAGE })
    expect(analysis.forms).toHaveLength(1)
    // Kolom kedua berada di luar jendela baca, jadi tidak ikut dihitung.
    expect(analysis.forms[0]?.passwordFields).toBe(1)
  })

  it('tidak menemukan form pada dokumen tanpa tag form dan menyebutnya apa adanya', () => {
    const analysis = analyzeForms({
      html: '<div class="login"><input name="email"></div>',
      ...PAGE,
    })
    expect(analysis.inspected).toBe(true)
    expect(analysis.forms).toEqual([])
    expect(analysis.detail).toContain('Tidak ada tag <form>')
  })

  it('memotong action yang sangat panjang tanpa menebak nilai lain', () => {
    const analysis = analyzeForms({
      html: `<form action="https://luar.example/${'p'.repeat(400)}"><input name="a"></form>`,
      ...PAGE,
    })
    expect((analysis.forms[0]?.action ?? '').length).toBeLessThanOrEqual(300)
  })
})

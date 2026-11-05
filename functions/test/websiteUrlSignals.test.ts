import { describe, expect, it } from 'vitest'
import {
  analyzeUrlStructure,
  boundedEditDistance,
  decodePunycodeLabel,
  levenshteinDistance,
  registrableDomain,
  splitLabels,
} from '../src/website/urlSignals.js'
import type { RedirectHop } from '../src/website/types.js'
import { URL_STRUCTURE_CODES } from '../src/website/types.js'

function codes(analysis: ReturnType<typeof analyzeUrlStructure>): string[] {
  return analysis.findings.map((finding) => finding.code)
}

function findingOf(analysis: ReturnType<typeof analyzeUrlStructure>, code: string) {
  return analysis.findings.find((finding) => finding.code === code)
}

function hop(url: string, outcome: RedirectHop['outcome'] = 'followed'): RedirectHop {
  return { url, status: 301, location: url, outcome, detail: null }
}

function analyze(url: string, extra: Partial<Parameters<typeof analyzeUrlStructure>[0]> = {}) {
  const parsed = new URL(url)
  return analyzeUrlStructure({
    initialUrl: url,
    finalUrl: url,
    hostname: parsed.hostname,
    hops: [],
    ...extra,
  })
}

describe('decodePunycodeLabel', () => {
  it('mengurai label xn-- sesuai RFC 3492', () => {
    expect(decodePunycodeLabel('xn--bcher-kva')).toBe('bücher')
    expect(decodePunycodeLabel('xn--mnchen-3ya')).toBe('münchen')
    expect(decodePunycodeLabel('xn--80ak6aa92e')).toBe('аррӏе')
  })

  it('mengembalikan null untuk label yang bukan punycode atau tidak sah', () => {
    expect(decodePunycodeLabel('amazon')).toBeNull()
    expect(decodePunycodeLabel('xn--')).toBeNull()
    expect(decodePunycodeLabel('xn--bcher-kvă')).toBeNull()
  })
})

describe('registrableDomain', () => {
  it('memakai suffix multi-level yang dikenal', () => {
    expect(registrableDomain('shop.unit.co.uk')).toBe('unit.co.uk')
    expect(registrableDomain('a.tokopedia.co.id')).toBe('tokopedia.co.id')
    expect(registrableDomain('x.y.example')).toBe('y.example')
  })

  it('memakai dua label terakhir di luar daftar', () => {
    expect(registrableDomain('a.b.example.com')).toBe('example.com')
    expect(registrableDomain('example.com')).toBe('example.com')
    expect(registrableDomain('single')).toBe('single')
  })

  it('memisahkan label tanpa titik akhir', () => {
    expect(splitLabels('A.B.Example.COM.')).toEqual(['a', 'b', 'example', 'com'])
  })
})

describe('analyzeUrlStructure — penulisan URL', () => {
  it('menandai userinfo yang menyamarkan host tujuan', () => {
    const analysis = analyze('https://paypal.com@penipu.example/masuk')
    expect(codes(analysis)).toContain('userinfo')
    expect(findingOf(analysis, 'userinfo')?.strength).toBe('strong')
    expect(findingOf(analysis, 'userinfo')?.evidence).toContain('penipu.example')
  })

  it('menandai host berupa alamat IP dan port non-standar', () => {
    const analysis = analyze('http://93.184.216.34:8080/login')
    expect(codes(analysis)).toContain('ip_literal')
    expect(codes(analysis)).toContain('unusual_port')
    expect(codes(analysis)).toContain('insecure_scheme')
    expect(findingOf(analysis, 'unusual_port')?.evidence).toContain(':8080')
  })

  it('menandai penulisan angka alternatif dan IPv6 kurung', () => {
    expect(codes(analyze('http://0x7f000001/'))).toContain('ip_literal')
    expect(codes(analyze('http://127.1/'))).toContain('ip_literal')
    expect(codes(analyze('http://[::1]:8080/'))).toContain('ip_literal')
  })

  it('tidak menandai port bawaan 80/443 sebagai port aneh', () => {
    expect(codes(analyze('https://example.com/'))).not.toContain('unusual_port')
    expect(codes(analyze('http://example.com:80/'))).not.toContain('unusual_port')
  })

  it('menandai pemendek URL, TLD berisiko, dan subdomain dalam', () => {
    expect(codes(analyze('https://bit.ly/ringkas'))).toContain('shortener')
    expect(codes(analyze('https://hadiah.zip/klaim'))).toContain('risky_tld')
    expect(codes(analyze('https://a.b.c.d.example.com/'))).toContain('deep_subdomain')
  })

  it('menandai label acak dan label bertanda hubung banyak', () => {
    expect(codes(analyze('https://qk7zx9wvp4mthx.com/'))).toContain('random_label')
    const hyphen = analyze('https://login-verify-account-now.com/')
    expect(codes(hyphen)).toContain('hyphen_labels')
  })

  it('URL yang tidak dapat diurai dinilai unavailable, bukan ditebak', () => {
    const analysis = analyzeUrlStructure({
      initialUrl: 'bukan url',
      finalUrl: null,
      hostname: '',
      hops: [],
    })
    expect(analysis.status).toBe('unavailable')
    expect(analysis.findings).toEqual([])
    expect(analysis.notes.join(' ')).toContain('tidak dapat diurai')
  })
})

describe('analyzeUrlStructure — nama host internasional', () => {
  it('menandai punycode, aksara campur, dan huruf mirip pada homograf merek', () => {
    const analysis = analyze('https://xn--rstir-jyem.example/')
    expect(codes(analysis)).toContain('punycode')
    expect(codes(analysis)).toContain('mixed_script')
    expect(codes(analysis)).toContain('homoglyph')
    const homoglyph = findingOf(analysis, 'homoglyph')
    expect(homoglyph?.evidence).toContain('xn--rstir-jyem')
  })

  it('menandai homograf yang menyerupai merek dengan label yang menyebut mereknya', () => {
    const analysis = analyze('https://xn--80ak6aa92e.com/masuk')
    const homoglyph = findingOf(analysis, 'homoglyph')
    expect(homoglyph).toBeDefined()
    expect(homoglyph?.strength).toBe('moderate')
    expect(homoglyph?.detail).toContain('bukan milik merek')
    expect(homoglyph?.label).toContain('merek')
    expect(codes(analysis)).not.toContain('mixed_script')
  })

  it('melaporkan label punycode apa adanya ketika isinya bukan merek', () => {
    const analysis = analyze('https://xn--mnchen-3ya.example/')
    const punycode = findingOf(analysis, 'punycode')
    expect(punycode?.evidence).toContain('xn--mnchen-3ya')
    expect(codes(analysis)).not.toContain('mixed_script')
    expect(codes(analysis)).not.toContain('homoglyph')
  })
})

describe('analyzeUrlStructure — merek dan peniruan', () => {
  it('menghormati domain resmi merek, termasuk subdomain miliknya', () => {
    expect(codes(analyze('https://paypal.com/'))).not.toContain('brand_in_host')
    expect(codes(analyze('https://www.paypal.com/'))).not.toContain('brand_in_host')
    expect(codes(analyze('https://s3.amazonaws.com/'))).not.toContain('brand_in_host')
  })

  it('menandai merek yang muncul di luar domain resminya', () => {
    const analysis = analyze('https://paypal.verify-penipu.example/akun')
    const brand = findingOf(analysis, 'brand_in_host')
    expect(brand).toBeDefined()
    expect(brand?.detail).toContain('bukan domain resmi')
  })

  it('tidak menaikkan nama merek tiga huruf hanya karena muncul sebagai label', () => {
    // "ovo", "bca", "dana" juga dipakai situs sah lain, jadi label host yang persis
    // tetap lemah; nama panjang yang khas boleh dinilai moderat.
    expect(findingOf(analyze('https://www.ovo.id/masuk'), 'brand_in_host')?.strength).toBe('weak')
    expect(findingOf(analyze('https://mandiri-pay.world/tagihan'), 'brand_in_host')?.strength).toBe('moderate')
  })

  it('melipat digraf yang mudah tertukar sebelum menghitung jarak edit', () => {
    // "rnandiri" berjarak 2 secara harfiah dari "mandiri"; setelah rn dilipat jadi m
    // selisihnya satu karakter, dan itu bentuk typosquat yang paling umum.
    const near = findingOf(analyze('https://rnandiri.com/'), 'typosquat')
    expect(near?.strength).toBe('moderate')
    expect(near?.detail).toContain('digraf yang mudah tertukar dilipat')
  })

  it('menandai domain yang berbeda satu karakter dari merek sebagai typosquat', () => {
    const near = findingOf(analyze('https://paypa1.com/'), 'typosquat')
    expect(near).toBeDefined()
    expect(near?.strength).toBe('moderate')
    expect(near?.evidence).toContain('paypa1')
  })

  it('menandai kemiripan dua karakter sebagai sinyal lemah', () => {
    const near = findingOf(analyze('https://paypaill.com/'), 'typosquat')
    expect(near?.strength).toBe('weak')
  })

  it('hanya satu temuan per kode meski beberapa merek cocok', () => {
    const analysis = analyze('https://paypal-netflix-support-login-verify.example/')
    expect(analysis.findings.filter((entry) => entry.code === 'brand_in_host')).toHaveLength(1)
  })
})

describe('analyzeUrlStructure — penyandian dan pembatas', () => {
  it('menandai double-encoding dan pembatas terselubung', () => {
    const analysis = analyze('https://example.com/%252f%2540%252f%2540%252f%2540')
    expect(codes(analysis)).toContain('over_encoded')
    expect(codes(analysis)).toContain('encoded_delimiter')
  })

  it('menandai URL lain yang tertanam dalam parameter', () => {
    const analysis = analyze('https://example.com/go?next=https%3A%2F%2Ftujuan-penipu.example%2F')
    const embedded = findingOf(analysis, 'embedded_url')
    expect(embedded?.detail).toContain('tujuan-penipu.example')
  })

  it('menandai pembatas tidak lazim', () => {
    expect(codes(analyze('https://example.com/a//b'))).toContain('delimiter_trick')
  })

  it('memotong bukti panjang dan menghapus karakter kontrol', () => {
    const analysis = analyze(`http://93.184.216.34:8080/${'A'.repeat(400)}`)
    expect(analysis.findings.length).toBeGreaterThan(0)
    for (const finding of analysis.findings) {
      if (!finding.evidence) continue
      expect(finding.evidence.length).toBeLessThanOrEqual(120)
      expect(/[\u0000-\u001f\u007f]/.test(finding.evidence)).toBe(false)
    }
    expect(analysis.findings.some((entry) => entry.evidence?.endsWith('…'))).toBe(true)
  })

  it('membatasi jumlah temuan dan tidak pernah memakai kode di luar daftar', () => {
    const analysis = analyze('https://paypal-netflix-verify-login-claim.bit.ly/%252f%2540%252f%2540%252f%2540?a=1//b')
    expect(analysis.findings.length).toBeLessThanOrEqual(18)
    for (const finding of analysis.findings) {
      expect(typeof finding.code).toBe('string')
      expect(finding.detail.length).toBeGreaterThan(0)
    }
  })
})

describe('analyzeUrlStructure — rantai redirect', () => {
  it('menandai redirect yang melintasi beberapa domain registrable', () => {
    const analysis = analyze('https://penipu.example/akhir', {
      hops: [
        hop('https://pemendek.example/1'),
        hop('https://iklan.example/2'),
        hop('https://penipu.example/akhir'),
      ],
    })
    const cross = findingOf(analysis, 'cross_domain_redirect')
    expect(cross?.strength).toBe('moderate')
    expect(cross?.evidence).toContain('->')
  })

  it('tidak menandai lintas domain saat satu registrable domain', () => {
    const analysis = analyze('https://www.example.com/', {
      hops: [hop('https://example.com/'), hop('https://www.example.com/')],
    })
    expect(codes(analysis)).not.toContain('cross_domain_redirect')
  })

  it('menandai penurunan https ke http', () => {
    const analysis = analyzeUrlStructure({
      initialUrl: 'https://contoh.example/masuk',
      finalUrl: 'http://contoh.example/masuk',
      hostname: 'contoh.example',
      hops: [],
    })
    expect(codes(analysis)).toContain('downgrade_redirect')
  })
})

describe('analyzeUrlStructure — batas klaim', () => {
  it('tidak menghasilkan skor, vonis, atau permintaan tambahan', () => {
    const analysis = analyze('http://93.184.216.34:8080/@paypal.com')
    expect(analysis).not.toHaveProperty('score')
    expect(analysis).not.toHaveProperty('verdict')
    expect(analysis).not.toHaveProperty('risk')
    const notes = analysis.notes.join(' ')
    expect(notes).toContain('tidak ada permintaan tambahan')
    expect(notes).toContain('bukan bukti independen')
  })

  it('setiap temuan membawa label, detail, dan kekuatan', () => {
    const analysis = analyze('http://93.184.216.34:8080/')
    expect(analysis.findings.length).toBeGreaterThan(0)
    for (const finding of analysis.findings) {
      expect(finding.label.length).toBeGreaterThan(0)
      expect(['strong', 'moderate', 'weak']).toContain(finding.strength)
      expect(URL_STRUCTURE_CODES).toContain(finding.code)
    }
  })
})

describe('jarak edit', () => {
  it('levenshteinDistance menghitung sisip, hapus, dan ganti', () => {
    expect(levenshteinDistance('paypal', 'paypal')).toBe(0)
    expect(levenshteinDistance('paypal', 'paypa1')).toBe(1)
    expect(levenshteinDistance('paypal', 'paypaill')).toBe(2)
    expect(levenshteinDistance('paypal', 'paypa')).toBe(1)
    expect(levenshteinDistance('paypal', 'g00gle')).toBe(6)
  })

  it('boundedEditDistance sama dengan levenshtein selama di dalam batas', () => {
    for (const [left, right] of [
      ['paypal', 'paypa1'],
      ['shopee', 'shope'],
      ['tokpediA', 'tokopedia'],
      ['mandiri', 'mandirl'],
    ]) {
      expect(boundedEditDistance(left.toLowerCase(), right.toLowerCase(), 2)).toBe(
        levenshteinDistance(left.toLowerCase(), right.toLowerCase()),
      )
    }
  })

  it('boundedEditDistance berhenti dan mengembalikan max + 1 saat melewati batas', () => {
    expect(boundedEditDistance('kabarhariini', 'paypal', 2)).toBe(3)
    expect(boundedEditDistance('a', 'abcdefghij', 2)).toBe(3)
  })
})

describe('analyzeUrlStructure — bentuk teks URL', () => {
  it('menandai panjang URL yang dipotong tampilan', () => {
    const long = analyze(`https://contoh.example/masuk?token=${'a'.repeat(150)}&next=${'b'.repeat(60)}`)
    expect(codes(long)).toContain('long_url')
    expect(findingOf(long, 'long_url')?.strength).toBe('moderate')
    expect(codes(analyze('https://contoh.example/masuk'))).not.toContain('long_url')
  })

  it('menandai jalur yang sangat dalam', () => {
    const deep = analyze('https://contoh.example/a/b/c/d/e/f/g')
    expect(codes(deep)).toContain('deep_path')
    expect(codes(analyze('https://contoh.example/login/akun'))).not.toContain('deep_path')
  })

  it('menandai rasio digit-terhadap-huruf yang tinggi', () => {
    const mixed = analyze('https://t0ks3lu.online/')
    const digit = findingOf(mixed, 'digit_heavy')
    expect(digit).toBeDefined()
    expect(digit?.strength).toBe('weak')
    expect(digit?.evidence).toContain('t0ks3lu')
  })

  it('memperkuat digit yang membentuk kembali nama merek', () => {
    const leet = analyze('https://micr0s0ft.support/')
    const digit = findingOf(leet, 'digit_heavy')
    expect(digit?.strength).toBe('moderate')
    expect(digit?.detail).toContain('Microsoft')
    expect(digit?.evidence).toContain('microsoft')
  })

  it('tidak menandai URL bersih atau merek sah lewat digit', () => {
    expect(codes(analyze('https://tokopedia.com/'))).not.toContain('digit_heavy')
    expect(codes(analyze('https://tokopedia.com/masuk?email=a%40b.c'))).not.toContain('digit_heavy')
  })

  it('menandai kepadatan tanda baca di luar sintaks URL', () => {
    const dense = analyze('https://contoh.example/f!lt3r{a}|b?c=1^2~3')
    expect(codes(dense)).toContain('special_heavy')
    expect(codes(analyze('https://contoh.example/lp?utm_source=wa&campaign=12'))).not.toContain(
      'special_heavy',
    )
  })
})

describe('analyzeUrlStructure — merek di jalur URL', () => {
  it('memisahkan penyebutan merek di jalur dari peniruan di host', () => {
    const analysis = analyze('https://kabarhariini.co.id/shopee-promo-hari-ini')
    expect(codes(analysis)).toContain('brand_in_path')
    expect(codes(analysis)).not.toContain('brand_in_host')
    const path = findingOf(analysis, 'brand_in_path')
    expect(path?.strength).toBe('weak')
    expect(path?.detail).toContain('tidak dibaca sebagai peniruan')
  })

  it('tidak menandai jalur milik domain resmi merek itu sendiri', () => {
    expect(codes(analyze('https://tokopedia.com/paypal'))).not.toContain('brand_in_path')
  })

  it('tidak menandai kata umum yang kebetulan mirip nama merek pendek', () => {
    expect(codes(analyze('https://amplifikasidana.co.id/dana-bantuan-kpm'))).not.toContain('brand_in_path')
  })
})

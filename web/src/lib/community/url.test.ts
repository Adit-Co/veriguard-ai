import { describe, expect, it } from 'vitest'
import {
  CommunityUrlError,
  hostnameFromCommunityUrl,
  isCommunityHostname,
  isCommunityReportedUrl,
  normalizeCommunityUrl,
  sanitizeCommunityUrlForDisplay,
} from './url'

describe('normalisasi URL Community Reports', () => {
  it('menambahkan https dan menghapus detail yang tidak relevan', () => {
    expect(normalizeCommunityUrl('Contoh.COM:443/a/../b?utm_source=x&b=2&a=1#bagian')).toBe(
      'https://contoh.com/b?a=1&b=2',
    )
  })

  it('mempertahankan protokol http, port non-default, path, dan query non-pelacak', () => {
    expect(normalizeCommunityUrl('http://contoh.com:8080/Laporan?token=abc')).toBe(
      'http://contoh.com:8080/Laporan?token=abc',
    )
  })

  it('menghapus parameter pelacak tanpa membedakan huruf besar-kecil', () => {
    expect(
      normalizeCommunityUrl(
        'https://contoh.com/?UTM_Source=promo&fbclid=123&q=halo&gclid=456',
      ),
    ).toBe('https://contoh.com/?q=halo')
  })

  it('menganggap path dan nilai query berbeda sebagai identitas berbeda', () => {
    expect(normalizeCommunityUrl('https://contoh.com/a')).not.toBe(
      normalizeCommunityUrl('https://contoh.com/b'),
    )
    expect(normalizeCommunityUrl('https://contoh.com/?id=1')).not.toBe(
      normalizeCommunityUrl('https://contoh.com/?id=2'),
    )
    expect(normalizeCommunityUrl('https://contoh.com/')).not.toBe(
      normalizeCommunityUrl('http://contoh.com/'),
    )
  })

  it('mengambil hostname dari URL ternormalisasi', () => {
    expect(hostnameFromCommunityUrl('https://sub.contoh.com/halaman')).toBe(
      'sub.contoh.com',
    )
  })

  it('tidak membawa port, path, query, atau fragment ke hostname', () => {
    const hostname = hostnameFromCommunityUrl(
      normalizeCommunityUrl('https://Sub.Contoh.COM:8443/a/b?token=abc&q=halo#bagian'),
    )

    expect(hostname).toBe('sub.contoh.com')
    expect(hostname).not.toContain(':8443')
    expect(hostname).not.toContain('/a/b')
    expect(hostname).not.toContain('token')
    expect(hostname).not.toContain('#')
  })

  it('mengambil hostname IPv6 publik bersama tanda kurung dari parser URL', () => {
    expect(
      hostnameFromCommunityUrl(
        normalizeCommunityUrl('https://[2606:4700:4700::1111]/halaman'),
      ),
    ).toBe('[2606:4700:4700::1111]')
  })

  it('menerima bentuk hostname aman dan menolak komponen URL', () => {
    expect(isCommunityHostname('contoh.com')).toBe(true)
    expect(isCommunityHostname('sub.contoh.com')).toBe(true)
    expect(isCommunityHostname('xn--bcher-kva.example')).toBe(true)
    expect(isCommunityHostname('8.8.8.8')).toBe(true)
    expect(isCommunityHostname('[2606:4700:4700::1111]')).toBe(true)

    expect(isCommunityHostname('https://contoh.com')).toBe(false)
    expect(isCommunityHostname('contoh.com/path')).toBe(false)
    expect(isCommunityHostname('contoh.com?x=1')).toBe(false)
    expect(isCommunityHostname('contoh.com#bagian')).toBe(false)
    expect(isCommunityHostname('user:rahasia@contoh.com')).toBe(false)
    expect(isCommunityHostname('contoh.com:443')).toBe(false)
    expect(isCommunityHostname('contoh com')).toBe(false)
    expect(isCommunityHostname('CONTOH.COM')).toBe(false)
    expect(isCommunityHostname('contoh')).toBe(false)
    expect(isCommunityHostname('')).toBe(false)
    expect(isCommunityHostname(null)).toBe(false)
    expect(isCommunityHostname(`${'a'.repeat(63)}.com`)).toBe(true)
    expect(isCommunityHostname(`${'a'.repeat(64)}.com`)).toBe(false)
    expect(isCommunityHostname(`${'a'.repeat(250)}.com`)).toBe(false)
  })

  it('menolak protokol selain http dan https', () => {
    expect(() => normalizeCommunityUrl('ftp://contoh.com/file')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('javascript:alert(1)')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('mailto:admin@contoh.com')).toThrow()
  })

  it('menolak alamat lokal, privat, dan tanpa domain publik', () => {
    expect(() => normalizeCommunityUrl('localhost')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('http://127.0.0.1')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('http://192.168.1.10:8080')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('http://[::1]/')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('http://[::ffff:127.0.0.1]/')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('http://[fc00::1]/')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('http://[fe90::1]/')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('http://100.64.0.1/')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('server.local')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('http://app.localhost')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('contoh')).toThrow(CommunityUrlError)
  })

  it('menolak kredensial, spasi, dan input kosong', () => {
    expect(() => normalizeCommunityUrl('https://user:rahasia@contoh.com')).toThrow(
      CommunityUrlError,
    )
    expect(() => normalizeCommunityUrl('https://contoh.com/a b')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('   ')).toThrow(CommunityUrlError)
  })

  it('menolak URL yang melebihi batas panjang', () => {
    expect(() => normalizeCommunityUrl(`https://contoh.com/${'a'.repeat(2100)}`)).toThrow(
      CommunityUrlError,
    )
  })
})

describe('URL tampilan Community Reports', () => {
  it('menampilkan shortlink forms.gle apa adanya', () => {
    const url = 'https://forms.gle/sfUqkbdPrC9uyh3b8'

    expect(sanitizeCommunityUrlForDisplay(url)).toBe(url)
    expect(isCommunityReportedUrl(url)).toBe(true)
  })

  it('mempertahankan skema, host, port, dan path tanpa query atau fragment', () => {
    expect(
      sanitizeCommunityUrlForDisplay(
        'http://Contoh.COM:8080/Laporan/2026?token=rahasia&q=halo#bagian',
      ),
    ).toBe('http://contoh.com:8080/Laporan/2026')
  })

  it('membuang query dan fragment sensitif dari URL path', () => {
    expect(
      sanitizeCommunityUrlForDisplay(
        'https://contoh.com/reset/abc?token=rahasia&code=123#langkah-2',
      ),
    ).toBe('https://contoh.com/reset/abc')
  })

  it('menolak URL berkredensial dan nilai yang bukan string', () => {
    expect(sanitizeCommunityUrlForDisplay('https://user:rahasia@contoh.com/path')).toBe(
      null,
    )
    expect(sanitizeCommunityUrlForDisplay(undefined)).toBe(null)
    expect(sanitizeCommunityUrlForDisplay('bukan url')).toBe(null)
    expect(sanitizeCommunityUrlForDisplay('localhost/path')).toBe(null)
  })

  it('meng-encode karakter @ pada path agar tidak menyerupai kredensial', () => {
    expect(sanitizeCommunityUrlForDisplay('https://contoh.com/@pengguna')).toBe(
      'https://contoh.com/%40pengguna',
    )
  })

  it('memvalidasi bentuk URL yang boleh disimpan', () => {
    expect(isCommunityReportedUrl('https://contoh.com/path?x=1')).toBe(false)
    expect(isCommunityReportedUrl('https://contoh.com/path#bagian')).toBe(false)
    expect(isCommunityReportedUrl('https://user:rahasia@contoh.com/path')).toBe(false)
    expect(isCommunityReportedUrl('https://contoh.com/a b')).toBe(false)
    expect(isCommunityReportedUrl('ftp://contoh.com/file')).toBe(false)
    expect(isCommunityReportedUrl('contoh.com/path')).toBe(false)
    expect(isCommunityReportedUrl(`https://contoh.com/${'a'.repeat(2048)}`)).toBe(false)
    expect(isCommunityReportedUrl(null)).toBe(false)
  })
})

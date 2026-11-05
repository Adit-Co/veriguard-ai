import { describe, expect, it } from 'vitest'
import {
  hostIndicatorCovers,
  hostLabels,
  hostOfIndicatorValue,
  isSameHost,
  normalizeHost,
  registrableDomain,
} from '../src/scanners/hostIdentity.js'
import { registrableDomain as websiteRegistrableDomain } from '../src/website/urlSignals.js'

// VGL-30K-R4: pemisah identitas host dipakai Agen 6 (indikator OTX) dan Agen 7 (subjek laporan
// Hybrid Analysis). Kesalahan di sini berarti reputasi host lain naik ke alamat yang diperiksa,
// jadi aturan "sama", "induk satu domain registrable", dan "host lain" diuji langsung.

describe('identitas host untuk bukti agen (hostIdentity)', () => {
  it('menormalkan host: kecil, tanpa spasi, tanpa titik akhir', () => {
    expect(normalizeHost('  WWW.ContOh.Com. ')).toBe('www.contoh.com')
    expect(hostLabels('A.Example.CO.ID')).toEqual(['a', 'example', 'co', 'id'])
    expect(hostLabels('.')).toEqual([])
  })

  it('isSameHost hanya untuk host yang benar-benar sama', () => {
    expect(isSameHost('www.bca.co.id', 'www.bca.co.id')).toBe(true)
    expect(isSameHost('www.bca.co.id.', 'WWW.BCA.CO.ID')).toBe(true)
    // Induk, subdomain lain, dan lookalike BUKAN host yang sama.
    expect(isSameHost('bca.co.id', 'www.bca.co.id')).toBe(false)
    expect(isSameHost('m.bca.co.id', 'www.bca.co.id')).toBe(false)
    expect(isSameHost('www.bca.co.id.verify-secure.top', 'www.bca.co.id')).toBe(false)
    expect(isSameHost('', 'contoh.com')).toBe(false)
  })

  it('hostIndicatorCovers menerima host persis dan induk pada batas label', () => {
    expect(hostIndicatorCovers('www.bca.co.id', 'www.bca.co.id')).toBe(true)
    expect(hostIndicatorCovers('bca.co.id', 'www.bca.co.id')).toBe(true)
    expect(hostIndicatorCovers('www.bca.co.id', 'bca.co.id')).toBe(false)
  })

  it('hostIndicatorCovers menolak public suffix, cocokan sebagian label, dan lookalike', () => {
    // Public suffix: "co.id" bukan indikator untuk "www.bca.co.id".
    expect(hostIndicatorCovers('co.id', 'www.bca.co.id')).toBe(false)
    expect(hostIndicatorCovers('com', 'contoh.com')).toBe(false)
    // Kecocokan sebagian tanpa batas label.
    expect(hostIndicatorCovers('contoh.com', 'notcontoh.com')).toBe(false)
    expect(hostIndicatorCovers('bca.co.id', 'bcaco.id')).toBe(false)
    // Lookalike yang kebetulan berawalan sama.
    expect(hostIndicatorCovers('www.bca.co.id.verify-secure.top', 'www.bca.co.id')).toBe(false)
    expect(hostIndicatorCovers('bcacoo.id', 'www.bca.co.id')).toBe(false)
    // Nilai kosong tidak pernah "covers".
    expect(hostIndicatorCovers('', 'contoh.com')).toBe(false)
    expect(hostIndicatorCovers('contoh.com', '')).toBe(false)
  })

  it('hostOfIndicatorValue membaca domain, hostname, URL, dan IP; menolak nilai kabur', () => {
    expect(hostOfIndicatorValue('contoh.com')).toBe('contoh.com')
    expect(hostOfIndicatorValue('https://Contoh.com/Path?q=1')).toBe('contoh.com')
    expect(hostOfIndicatorValue('http://sub.contoh.com:8080/x')).toBe('sub.contoh.com')
    expect(hostOfIndicatorValue('104.16.1.2')).toBe('104.16.1.2')
    expect(hostOfIndicatorValue('[2001:db8::1]/x')).toBe('[2001:db8::1]')
    expect(hostOfIndicatorValue('')).toBeNull()
    expect(hostOfIndicatorValue('user@host.example')).toBeNull()
    // URL dengan kredensial tetap dibaca host-nya; normalizeScanUrl menolak bentuk itu sebagai
    // target, jadi kecocokan URL persis tidak mungkin terjadi di jalur ini.
    expect(hostOfIndicatorValue('https://user:pw@host.example')).toBe('host.example')
    // Scheme yang tidak dapat diparse URL tidak dipakai sebagai identitas.
    expect(hostOfIndicatorValue('http://')).toBeNull()
  })

  // Anti-cabang: aturan scanners adalah salinan lokal (arah dependensi website -> scanners,
  // bukan sebaliknya). Bila salah satu daftar suffix diubah tanpa mengubah yang lain, tabel
  // host di bawah menghasilkan jawaban berbeda dan uji ini jatuh.
  it('domain registrable scanners cocok dengan aturan lapisan website', () => {
    const hosts = [
      'www.bca.co.id',
      'bca.co.id',
      'mail.google.com',
      'gov.uk',
      'www.parliament.co.uk',
      'api.example.com.au',
      'shop.example.co.nz',
      'www.contoh.go.id',
      'data.example.com.br',
      'mirror.example.co.za',
      'cdn.assets.example.org.in',
      'notcontoh.com',
      'a.b.c.example.com',
      'contoh',
      '104.16.1.2',
    ]

    for (const host of hosts) {
      expect(registrableDomain(host), host).toBe(websiteRegistrableDomain(host))
    }
  })
})

import { describe, expect, it } from 'vitest'
import { ScanUrlError, normalizeScanUrl } from '../src/scanners/url.js'
import { CommunityUrlError, normalizeCommunityUrl } from '../src/community/url.js'
import {
  classifyAddress,
  isAllowedInitialPort,
  isAllowedWebPort,
  isBlockedHostname,
} from '../src/website/guards.js'

// W8: penyaring alamat sempat tiga salinan. Daftar yang dipakai pemindaian dan pelaporan
// komunitas tertinggal dari daftar yang dipakai pemeriksaan situs, sehingga alamat yang tidak
// pernah boleh dihubungi masih bisa lolos sebagai "URL yang sah". Sekarang keduanya memakai
// tabel prefiks yang sama, dan tabel ini mengunci bahwa ketiganya menjawab sama.

const BLOCKED_CASES = [
  // Rentang yang sebelumnya hanya dikenal oleh guards.ts.
  'http://192.0.0.1/',
  'http://192.0.2.1/',
  'http://192.88.99.1/',
  'http://198.18.0.1/',
  'http://198.51.100.7/',
  'http://203.0.113.10/',
  'http://[::ffff:198.51.100.7]/',
  'http://[100::1]/',
  'http://[2001::1]/',
  // Nama host layanan internal/metadata.
  'http://db.internal/',
  'http://metadata.goog/computeMetadata',
  // Penulisan angka alternatif untuk loopback.
  'http://127.1/',
  'http://0x7f000001/',
  'http://2130706433/',
  // Rentang yang memang sudah lama ditolak ketiga-salinan, dipakai supaya perbandingan tidak
  // hanya menguji tambalan terbaru.
  'http://10.0.0.5/',
  'http://[fe80::1]/',
]

const PUBLIC_CASES = [
  'https://example.com/',
  'https://api.whatsapp.com/',
  'https://1.1.1.1/',
  'https://192.0.1.1/',
  'https://172.32.0.1/',
  'https://193.168.0.1/',
  'https://[2606:4700::6810:8334]/',
  'https://[2001:4860:8::8]/',
]

function hostnameOf(url: string): string {
  return new URL(url).hostname
}

describe('satu kebijakan alamat untuk pemindaian, komunitas, dan pemeriksaan situs', () => {
  it.each(BLOCKED_CASES)('menolak %s di ketiga jalur', (url) => {
    const host = hostnameOf(url)
    expect(isBlockedHostname(host)).toBe(true)
    expect(() => normalizeScanUrl(url)).toThrow(ScanUrlError)
    expect(() => normalizeCommunityUrl(url)).toThrow(CommunityUrlError)
  })

  it.each(PUBLIC_CASES)('tetap menerima %s di ketiga jalur', (url) => {
    const host = hostnameOf(url)
    expect(isBlockedHostname(host)).toBe(false)
    expect(() => normalizeScanUrl(url)).not.toThrow()
    expect(() => normalizeCommunityUrl(url)).not.toThrow()
  })

  it('menilai alamat IPv4 yang dipetakan IPv6 melalui tabel yang sama', () => {
    expect(classifyAddress('::ffff:c633:6407').allowed).toBe(false)
    expect(classifyAddress('::ffff:c633:6407').reason).toContain('memetakan IPv4')
    expect(classifyAddress('2606:4700::6810:8334').allowed).toBe(true)
  })

  it('memakai pesan penolakan yang sama seperti sebelumnya supaya antarmuka tidak berubah', () => {
    expect(() => normalizeScanUrl('http://203.0.113.10/')).toThrow(
      'Alamat lokal atau privat tidak dapat diperiksa.',
    )
    expect(() => normalizeCommunityUrl('http://203.0.113.10/')).toThrow(
      'Alamat lokal atau privat tidak dapat dilaporkan.',
    )
  })
})

// Batas prefiks diuji pada kedua ujungnya. `192.0.0.2` adalah alamat yang sah secara bentuk dan
// berada di dalam 192.0.0.0/24; ia dulu lolos karena penyaring hanya mengenali alamat jaringan.
// Sisi luarnya (192.0.1.x, 198.20.x) harus tetap publik supaya penolakan tidak melebar ke
// alamat yang benar-benar bisa diperiksa.
const BLOCKED_EDGES = [
  '192.0.0.0',
  '192.0.0.2',
  '192.0.0.255',
  '192.0.2.0',
  '192.0.2.254',
  '192.88.99.255',
  '198.18.0.0',
  '198.19.255.255',
  '100.127.255.255',
  '0.255.255.255',
]

const PUBLIC_EDGES = [
  '192.0.1.0',
  '192.0.1.255',
  '192.0.3.0',
  '192.89.0.0',
  '198.17.255.255',
  '198.20.0.0',
  '100.63.255.255',
  '100.128.0.0',
  '1.0.0.255',
]

describe('batas prefiks IPv4 berlaku sama di ketiga jalur', () => {
  it.each(BLOCKED_EDGES)('menolak %s sampai batas terluar prefiks', (address) => {
    const url = `http://${address}/`
    expect(isBlockedHostname(address)).toBe(true)
    expect(classifyAddress(address).allowed).toBe(false)
    expect(() => normalizeScanUrl(url)).toThrow(ScanUrlError)
    expect(() => normalizeCommunityUrl(url)).toThrow(CommunityUrlError)
  })

  it.each(PUBLIC_EDGES)('tetap menerima %s tepat di luar prefiks', (address) => {
    const url = `http://${address}/`
    expect(isBlockedHostname(address)).toBe(false)
    expect(classifyAddress(address).allowed).toBe(true)
    expect(() => normalizeScanUrl(url)).not.toThrow()
    expect(() => normalizeCommunityUrl(url)).not.toThrow()
  })
})

// Kebijakan port sengaja berbeda antara hop pertama dan redirect, dan perbedaannya adalah
// isi kebijakannya: URL tulisan pengguna boleh menghuni port alternatif yang sah (8080/8443),
// sedangkan halaman pihak ketiga tidak boleh memindahkan pemeriksaan ke port layanan.
describe('port awal dan port redirect dinilai dengan aturan yang berbeda', () => {
  it('menerima port web standar di kedua tahap, termasuk bentuk default tanpa port', () => {
    for (const port of ['80', '443', '']) {
      expect(isAllowedInitialPort(port)).toBe(true)
      expect(isAllowedWebPort(port)).toBe(true)
    }
  })

  it('menerima port alternatif hanya pada URL awal', () => {
    for (const port of ['8080', '8443']) {
      expect(isAllowedInitialPort(port)).toBe(true)
      expect(isAllowedWebPort(port)).toBe(false)
    }
  })

  it('menolak port layanan dan infrastruktur di kedua tahap', () => {
    for (const port of ['21', '22', '23', '25', '53', '135', '445', '1433', '3306', '3389', '5432', '6379', '9200', '27017', '8081']) {
      expect(isAllowedInitialPort(port)).toBe(false)
      expect(isAllowedWebPort(port)).toBe(false)
    }
  })

  it('menolak nilai port yang bukan angka port valid, bukan hanya yang di luar allowlist', () => {
    for (const port of ['0', '1', '65536', '99999', '70000', 'abc', '443a', ' 443', '+443', '-1', '1e3']) {
      expect(isAllowedInitialPort(port)).toBe(false)
      expect(isAllowedWebPort(port)).toBe(false)
    }
  })

  it('menilai port 1 sebagai sah secara bentuk tetapi berada di luar allowlist', () => {
    // Memisahkan "port tidak valid" dari "port tidak diizinkan": keduanya menolak, tetapi hanya
    // yang pertama yang berarti URL-nya rusak.
    expect(classifyAddress('1.1.1.1').allowed).toBe(true)
    expect(isAllowedInitialPort('1')).toBe(false)
    expect(isAllowedInitialPort('65535')).toBe(false)
  })
})

import { describe, expect, it } from 'vitest'
import {
  classifyAddress,
  expandIpv6,
  filterPublicAddresses,
  isAllowedInitialPort,
  isAllowedWebPort,
  isBlockedHostname,
  isBlockedMetadataAddress,
  isSafeResponseHeader,
  parseIpv4,
  sanitizeHeaderValue,
} from '../src/website/guards.js'
import { normalizeScanUrl, ScanUrlError } from '../src/scanners/url.js'

const ALLOWED_V4 = [
  '93.184.216.34',
  '142.250.1.100',
  '104.16.1.2',
  '8.8.8.8',
  '151.101.1.69',
]

const BLOCKED_V4 = [
  '0.0.0.0',
  '10.0.0.5',
  '10.255.255.255',
  '100.64.0.1',
  '100.127.255.255',
  '127.0.0.1',
  '127.255.255.255',
  '169.254.169.254',
  '169.254.170.2',
  '172.16.0.1',
  '172.31.255.255',
  '192.0.0.1',
  '192.0.2.1',
  '192.168.1.1',
  '192.88.99.1',
  '198.18.0.1',
  '198.51.100.1',
  '203.0.113.1',
  '224.0.0.1',
  '239.255.255.255',
  '240.0.0.1',
]

const BLOCKED_V6 = [
  '::',
  '::1',
  '2001:db8::1',
  '2001::1',
  '2001:20:ffff::1',
  '64:ff9b::8.8.8.8',
  '100::1',
  '2002:0808:0808::1',
  'fc00::1',
  'fd12:3456::1',
  'fe80::1',
  'febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
  'ff02::1',
  'ffff::1',
  '::ffff:127.0.0.1',
  '::ffff:10.0.0.1',
  '::ffff:169.254.169.254',
]

const ALLOWED_V6 = ['2606:4700::1111', '2001:4860:4860::8888', '2a00:1450:4001:824::200e', '::ffff:93.184.216.34']

describe('classifyAddress menolak rentang internal', () => {
  it.each(ALLOWED_V4)('mengizinkan IPv4 publik %s', (address) => {
    expect(classifyAddress(address)).toMatchObject({ kind: 'ipv4', allowed: true, reason: null })
  })

  it.each(BLOCKED_V4)('menolak IPv4 internal %s', (address) => {
    const verdict = classifyAddress(address)
    expect(verdict.allowed).toBe(false)
    expect(verdict.reason).toContain('IPv4')
  })

  it.each(ALLOWED_V6)('mengizinkan IPv6 publik %s', (address) => {
    const verdict = classifyAddress(address)
    expect(verdict.allowed).toBe(true)
    expect(verdict.reason).toBeNull()
  })

  it.each(BLOCKED_V6)('menolak IPv6 internal %s', (address) => {
    const verdict = classifyAddress(address)
    expect(verdict.allowed).toBe(false)
    expect(verdict.kind).toBe('ipv6')
    expect(verdict.reason).toContain('IPv6')
  })

  it('mendeteksi bentuk campuran dan terkompresi sekaligus', () => {
    expect(classifyAddress('::ffff:192.168.0.1').allowed).toBe(false)
    expect(classifyAddress('0:0:0:0:0:ffff:7f00:1').allowed).toBe(false)
    expect(classifyAddress('2606:4700:0:0:0:0:0:a').allowed).toBe(true)
  })

  it('menolak teks yang bukan alamat IP alih-alih menebak', () => {
    for (const junk of ['999.1.1.1', '1.2.3', '', 'abc', '10.0.0.1:80', '::1::2', 'fe80::1%eth0']) {
      const verdict = classifyAddress(junk)
      expect(verdict.allowed).toBe(false)
      expect(verdict.reason).toContain('tidak valid')
    }
  })
})

describe('parseIpv4 dan expandIpv6', () => {
  it('hanya menerima IPv4 titik-oktet yang valid', () => {
    expect(parseIpv4('10.0.0.1')).toEqual([10, 0, 0, 1])
    expect(parseIpv4('256.1.1.1')).toBeNull()
    expect(parseIpv4('1.2.3.4.5')).toBeNull()
    // Forma berangka nol di depan dinilai desimal, lalu tetap ditolak oleh validasi URL.
    expect(parseIpv4('010.0.0.1')).toEqual([10, 0, 0, 1])
  })

  it('memekarkan IPv6 menjadi 16 byte', () => {
    expect(expandIpv6('::1')).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    expect(expandIpv6('2001:4860:4860::8888')).toHaveLength(16)
    expect(expandIpv6('[::ffff:1.2.3.4]')?.slice(12)).toEqual([1, 2, 3, 4])
    expect(expandIpv6('64:ff9b::8.8.8.8')?.slice(0, 3)).toEqual([0x00, 0x64, 0xff])
    expect(expandIpv6('2001:db8::1')?.length).toBe(16)
    expect(expandIpv6('gggg::1')).toBeNull()
    expect(expandIpv6('12345::1')).toBeNull()
    expect(expandIpv6('1:2:3:4:5:6:7:8:9')).toBeNull()
  })
})

describe('isBlockedHostname dan metadata', () => {
  const blocked = [
    'localhost',
    'LOCALHOST',
    'api.localhost',
    'printer.local',
    'db.internal',
    'router.home.arpa',
    'metadata.google.internal',
    'metadata.goog',
    '169.254.169.254',
    '127.0.0.1',
    '127.1',
    '010.0.0.1',
    '2130706433',
    '0x7f000001',
    '[::ffff:127.0.0.1]',
  ]

  it.each(blocked)('menolak nama host internal %s', (hostname) => {
    expect(isBlockedHostname(hostname)).toBe(true)
  })

  it('menolak versi berhuruf besar dan berekor titik', () => {
    expect(isBlockedHostname('LocalHost.')).toBe(true)
    expect(isBlockedHostname('DB.INTERNAL.')).toBe(true)
  })

  it('tidak menolak domain publik biasa', () => {
    for (const hostname of [
      'example.com',
      'api.cloudflare.com',
      'not-localhost.dev',
      '93.184.216.34',
      '[2606:4700::1111]',
    ]) {
      expect(isBlockedHostname(hostname)).toBe(false)
    }
  })

  it('menandai endpoint metadata cloud secara spesifik', () => {
    expect(isBlockedMetadataAddress('169.254.169.254')).toBe(true)
    expect(isBlockedMetadataAddress('[fd00:ec2::254]')).toBe(false)
    expect(isBlockedMetadataAddress('169.254.1.1')).toBe(false)
    expect(isBlockedMetadataAddress('100.100.100.200')).toBe(true)
  })
})

describe('filterPublicAddresses', () => {
  it('menyaring per alamat, bukan per nama host', () => {
    const set = filterPublicAddresses(['93.184.216.34', '127.0.0.1', '10.0.0.1'], 'ipv4')
    expect(set.allowed).toEqual(['93.184.216.34'])
    expect(set.blocked).toBe(2)
    expect(set.reason).toBeNull()
  })

  it('menghasilkan alasan bila tidak ada alamat yang boleh dibuka', () => {
    const set = filterPublicAddresses(['127.0.0.1', '169.254.169.254'], 'ipv4')
    expect(set.allowed).toEqual([])
    expect(set.reason).toContain('rentang yang dilarang')
  })

  it('menolak hasil kosong dan alamat dengan kind yang tidak cocok', () => {
    expect(filterPublicAddresses([], 'ipv4').allowed).toEqual([])
    expect(filterPublicAddresses(['2606:4700::1111'], 'ipv4').allowed).toEqual([])
  })
})

describe('isSafeResponseHeader dan sanitizeHeaderValue', () => {
  const unsafe = [
    'cookie',
    'set-cookie',
    'authorization',
    'proxy-authorization',
    'www-authenticate',
    'x-api-key',
    'x-secret-token',
    'x-session-id',
    'x-csrf-token',
    'connection',
  ]

  it.each(unsafe)('menyembunyikan header %s', (name) => {
    expect(isSafeResponseHeader(name)).toBe(false)
    expect(isSafeResponseHeader(name.toUpperCase())).toBe(false)
  })

  const safe = ['server', 'content-type', 'date', 'via', 'x-powered-by', 'x-drupal-cache', 'x-amz-cf-id']

  it.each(safe)('mengizinkan header teknis %s', (name) => {
    expect(isSafeResponseHeader(name)).toBe(true)
  })

  it('menghilangkan karakter kontrol dan memotong nilai panjang', () => {
    expect(sanitizeHeaderValue('nginx\r\nSet-Cookie: secret=1')).toBe('nginx Set-Cookie: secret=1')
    expect(sanitizeHeaderValue('a'.repeat(400), 160)).toHaveLength(160)
    expect(sanitizeHeaderValue('  ruang  \u0000 ')).toBe('ruang')
  })
})

describe('normalizeScanUrl sebagai validasi terpusat', () => {
  it('menolak skema yang tidak didukung', () => {
    for (const url of [
      'file:///etc/passwd',
      'javascript:alert(1)',
      'ftp://example.com/',
      'gopher://127.0.0.1/',
      'http://[::1]/',
      'dict://10.0.0.1:6379',
    ]) {
      expect(() => normalizeScanUrl(url)).toThrow(ScanUrlError)
    }
  })

  it('menolak host loopback, privat, dan bentuk bypass desimal/heksa', () => {
    for (const url of [
      'http://localhost/admin',
      'http://127.0.0.1/',
      'http://10.1.2.3/',
      'http://192.168.0.1/',
      'http://[fd00::1]/',
      'http://[::ffff:127.0.0.1]/',
      'http://169.254.169.254/latest/meta-data',
      'http://2130706433/',
      'http://0x7f000001/',
    ]) {
      expect(() => normalizeScanUrl(url)).toThrow(ScanUrlError)
    }
  })

  it('menolak kredensial dalam URL dan URL terlalu panjang', () => {
    expect(() => normalizeScanUrl('https://user:pass@example.com/')).toThrow(ScanUrlError)
    expect(() => normalizeScanUrl(`https://example.com/${'a'.repeat(3000)}`)).toThrow(ScanUrlError)
    expect(() => normalizeScanUrl('https://example.com?a b')).toThrow(ScanUrlError)
  })

  it('menormalisasi URL publik tanpa mengubah niat target', () => {
    expect(normalizeScanUrl('HTTPS://Example.COM:443/Path?b=2&a=1#frag')).toBe(
      'https://example.com/Path?a=1&b=2',
    )
    expect(normalizeScanUrl('example.com')).toBe('https://example.com/')
  })
})

describe('isAllowedWebPort', () => {
  it('mengizinkan port bawaan dan port web yang ditulis eksplisit', () => {
    expect(isAllowedWebPort('')).toBe(true)
    expect(isAllowedWebPort('80')).toBe(true)
    expect(isAllowedWebPort('443')).toBe(true)
  })

  it('menolak port lain, port tidak sah, dan teks yang bukan angka', () => {
    expect(isAllowedWebPort('8080')).toBe(false)
    expect(isAllowedWebPort('22')).toBe(false)
    expect(isAllowedWebPort('0')).toBe(false)
    expect(isAllowedWebPort('65536')).toBe(false)
    expect(isAllowedWebPort('abc')).toBe(false)
    expect(isAllowedWebPort('443; rm')).toBe(false)
  })
})

describe('isAllowedInitialPort', () => {
  it('membiarkan URL pengguna di port web alternatif yang benar-benar dipakai situs', () => {
    for (const port of ['', '80', '443', '8080', '8443']) {
      expect(isAllowedInitialPort(port)).toBe(true)
    }
  })

  it('menutup port layanan dan infrastruktur pada hop pertama', () => {
    for (const port of ['22', '3306', '6379', '11211', '27017', '9200', '25', '135']) {
      expect(isAllowedInitialPort(port)).toBe(false)
    }
  })

  it('memakai aturan bentuk port yang sama seperti daftar redirect', () => {
    expect(isAllowedInitialPort('0')).toBe(false)
    expect(isAllowedInitialPort('65536')).toBe(false)
    expect(isAllowedInitialPort('abc')).toBe(false)
    expect(isAllowedInitialPort('8443; rm')).toBe(false)
  })

  it('tetap membatasi redirect ke 80/443 walaupun hop pertama lebih lebar', () => {
    // Ini alasan kedua daftar dipisah: halaman pihak ketiga tidak boleh memindahkan
    // pemeriksaan ke 8080/8443 setelah pengguna menulis URL yang sah.
    expect(isAllowedInitialPort('8080')).toBe(true)
    expect(isAllowedWebPort('8080')).toBe(false)
    expect(isAllowedInitialPort('8443')).toBe(true)
    expect(isAllowedWebPort('8443')).toBe(false)
  })
})

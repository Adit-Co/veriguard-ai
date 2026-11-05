const IPV4_PARTS = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

/**
 * Nama host layanan metadata cloud. Tidak pernah boleh dihubungi lewat jalur mana pun, dan
 * khusus analisis situs dilaporkan sebagai "tidak tersedia" (bukan galat), karena targetnya
 * memang tidak akan pernah terbuka.
 */
export const METADATA_SERVICE_HOSTNAMES = new Set(['metadata.google.internal', 'metadata.goog'])

/** Nama host metadata cloud yang dapat ditegakkan secara lokal: apa pun resolusinya. */
const BLOCKED_HOSTNAMES = new Set(['localhost', ...METADATA_SERVICE_HOSTNAMES])

const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.home.arpa', '.ec2-internal.com']

type Prefix = { bits: number; bytes: number[] }

function dottedPrefix(dotted: string, bits: number): Prefix {
  const bytes = dotted.split('.').map(Number)
  while (bytes.length < 4) bytes.push(0)
  return { bits, bytes }
}

// Rentang IPv4 yang tidak pernah menjadi target pemeriksaan publik.
const BLOCKED_V4: Prefix[] = [
  dottedPrefix('0.0.0.0', 8),
  dottedPrefix('10.0.0.0', 8),
  dottedPrefix('100.64.0.0', 10),
  dottedPrefix('127.0.0.0', 8),
  dottedPrefix('169.254.0.0', 16),
  dottedPrefix('172.16.0.0', 12),
  dottedPrefix('192.0.0.0', 24),
  dottedPrefix('192.0.2.0', 24),
  dottedPrefix('192.88.99.0', 24),
  dottedPrefix('192.168.0.0', 16),
  dottedPrefix('198.18.0.0', 15),
  dottedPrefix('198.51.100.0', 24),
  dottedPrefix('203.0.113.0', 24),
  dottedPrefix('224.0.0.0', 4),
  dottedPrefix('240.0.0.0', 4),
]

export function parseIpv4(address: string): number[] | null {
  const match = IPV4_PARTS.exec(address)
  if (!match) return null
  const parts = [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4])]
  if (parts.some((part) => !Number.isFinite(part) || part > 255)) return null
  return parts
}

function groupValues(text: string): number[] | null {
  if (text === '') return []
  const groups = text.split(':')
  const out: number[] = []
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null
    out.push(Number.parseInt(group, 16))
  }
  return out
}

/**
 * Ekspansi teks IPv6 menjadi 16 byte, termasuk notasi `::` dan bentuk campuran
 * IPv4. Teks yang tidak valid menghasilkan null sehingga caller menolaknya.
 * Indeks zona (`%eth0`) ikut ditolak karena tidak bisa dinilai dengan aman.
 */
export function expandIpv6(input: string): number[] | null {
  let text = input.trim().toLowerCase().replace(/^\[|\]$/g, '')
  if (!text || /[^0-9a-f:.]/.test(text)) return null
  if (text.indexOf('::') !== text.lastIndexOf('::')) return null

  // Ekor IPv4 ditulis sebagai dua kelompok heksadesimal agar kompresi `::`
  // tidak ikut terpotong saat memisahkan ekornya.
  const tailMatch = /:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(text)
  if (tailMatch) {
    const octets = parseIpv4(tailMatch[1] as string)
    if (!octets) return null
    const [first, second, third, fourth] = octets as [number, number, number, number]
    const hex = [((first << 8) | second).toString(16), ((third << 8) | fourth).toString(16)].join(':')
    text = `${text.slice(0, tailMatch.index + 1)}${hex}`
  }

  const compressed = text.includes('::')
  const separator = text.indexOf('::')
  const headGroups = groupValues(compressed ? text.slice(0, separator) : text)
  const tailGroups = compressed ? groupValues(text.slice(separator + 2)) : []
  if (headGroups === null || tailGroups === null) return null

  const named = headGroups.length + tailGroups.length
  if (named > 8) return null
  const zeros = 8 - named
  if (compressed ? zeros < 1 : zeros !== 0) return null

  const groups = [
    ...headGroups,
    ...Array.from({ length: zeros }, () => 0),
    ...tailGroups,
  ]

  const bytes: number[] = []
  for (const group of groups) {
    bytes.push((group >> 8) & 0xff, group & 0xff)
  }
  return bytes.length === 16 ? bytes : null
}

function matchesPrefix(bytes: number[], entry: Prefix): boolean {
  let remaining = entry.bits
  for (let index = 0; index < bytes.length; index += 1) {
    if (remaining <= 0) return true
    if (index >= entry.bytes.length) return remaining <= 0
    if (remaining >= 8) {
      if (bytes[index] !== entry.bytes[index]) return false
      remaining -= 8
      continue
    }
    const mask = 0xff << (8 - remaining)
    return (bytes[index] & mask) === (entry.bytes[index] & mask)
  }
  return remaining <= 0
}

function v6Prefix(bytes: string, bits: number): Prefix {
  return { bits, bytes: expandIpv6(bytes) ?? [] }
}

// Loopback, unspecified, NAT64, discard, Teredo, ORCHID, dokumentasi, 6to4,
// unique-local, link-local, dan multicast ditolak.
const BLOCKED_V6: Prefix[] = [
  v6Prefix('::', 128),
  v6Prefix('::1', 128),
  v6Prefix('::ffff:0.0.0.0', 96),
  v6Prefix('64:ff9b::', 96),
  v6Prefix('100::', 64),
  v6Prefix('2001::', 32),
  v6Prefix('2001:20::', 28),
  v6Prefix('2001:db8::', 32),
  v6Prefix('2002::', 16),
  v6Prefix('fc00::', 7),
  v6Prefix('fe80::', 10),
  v6Prefix('ff00::', 8),
].filter((entry) => entry.bytes.length === 16)

function isV4Mapped(bytes: number[]): boolean {
  return (
    bytes.slice(0, 10).every((byte) => byte === 0) &&
    bytes[10] === 0xff &&
    bytes[11] === 0xff
  )
}

export type AddressVerdict = {
  address: string
  kind: 'ipv4' | 'ipv6'
  allowed: boolean
  reason: string | null
}

export function classifyAddress(raw: string): AddressVerdict {
  const address = raw.trim().toLowerCase().replace(/^\[|\]$/g, '')
  const v4 = parseIpv4(address)

  if (v4) {
    return BLOCKED_V4.some((entry) => matchesPrefix(v4, entry))
      ? { address, kind: 'ipv4', allowed: false, reason: 'Alamat IPv4 berada di rentang yang dilarang.' }
      : { address, kind: 'ipv4', allowed: true, reason: null }
  }

  const bytes = expandIpv6(address)
  if (!bytes) {
    return { address, kind: 'ipv6', allowed: false, reason: 'Alamat IP tidak valid.' }
  }

  if (isV4Mapped(bytes)) {
    const embedded = bytes.slice(12)
    return BLOCKED_V4.some((entry) => matchesPrefix(embedded, entry))
      ? { address, kind: 'ipv6', allowed: false, reason: 'Alamat IPv6 memetakan IPv4 yang dilarang.' }
      : { address, kind: 'ipv6', allowed: true, reason: null }
  }

  return BLOCKED_V6.some((entry) => matchesPrefix(bytes, entry))
    ? { address, kind: 'ipv6', allowed: false, reason: 'Alamat IPv6 berada di rentang yang dilarang.' }
    : { address, kind: 'ipv6', allowed: true, reason: null }
}

/**
 * Host angka adalah penulisan alternatif alamat IP (`127.1`, `2130706433`,
 * `0x7f000001`). Bentuk yang bukan IPv4 lengkap ditolak karena tidak pernah
 * menjadi domain publik yang sah, dan IPv4 literal internal ikut ditolak.
 */
function isNumericLiteralHostname(normalized: string): boolean {
  if (normalized.startsWith('0x')) return true
  if (!/^[\d.]+$/.test(normalized)) return false
  if (!parseIpv4(normalized)) return true
  return !classifyAddress(normalized).allowed
}

export function isBlockedHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '')
  if (BLOCKED_HOSTNAMES.has(normalized)) return true
  if (BLOCKED_SUFFIXES.some((suffix) => normalized.endsWith(suffix))) return true
  // Literal IPv6 selalu dinilai sebagai alamat, bukan sebagai nama domain.
  if (normalized.includes(':')) return !classifyAddress(normalized).allowed
  return isNumericLiteralHostname(normalized)
}

/** Sama seperti BLOCKED_HOSTNAMES untuk nama layanan metadata, tanpa menyentuh bentuk lainnya. */
export function isMetadataServiceHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/\.$/, '')
  return METADATA_SERVICE_HOSTNAMES.has(normalized)
}

// Port yang boleh diikuti seorang redirect. Halaman pihak ketiga tidak boleh memindahkan
// pemeriksaan ke port layanan lain, jadi hanya port web bawaan yang dibuka di sini.
const ALLOWED_WEB_PORTS = new Set(['80', '443'])

// Port yang boleh dituju oleh URL yang ditulis pengguna. Tetap selebar mungkin supaya situs
// yang memang tinggal di port alternatif (8080/8443) masih dapat diperiksa — itu perilaku yang
// diuji dan dipakai — tetapi berhenti di port layanan/infrastruktur. Tanpa batas ini, satu
// permintaan analisis adalah primitive probe port ke alamat publik mana pun yang berasal dari
// infrastruktur hosting, setelah alamatnya lolos penyaring privat/metadata.
const ALLOWED_INITIAL_PORTS = new Set(['80', '443', '8080', '8443'])

function normalizePort(port: string): string | null {
  if (port === '') return ''
  if (!/^\d{1,5}$/.test(port)) return null
  const value = Number(port)
  if (value < 1 || value > 65_535) return null
  return port
}

/**
 * `port` diambil dari `URL.port`, jadi kosong berarti port bawaan skema.
 * Bentuk tidak sah (nol, melebihi 65535, atau bukan angka) ikut ditolak.
 */
export function isAllowedWebPort(port: string): boolean {
  const normalized = normalizePort(port)
  if (normalized === null) return false
  return normalized === '' || ALLOWED_WEB_PORTS.has(normalized)
}

/** Sama seperti isAllowedWebPort, tetapi untuk hop pertama (URL tulisan pengguna). */
export function isAllowedInitialPort(port: string): boolean {
  const normalized = normalizePort(port)
  if (normalized === null) return false
  return normalized === '' || ALLOWED_INITIAL_PORTS.has(normalized)
}

export type SafeAddressSet = {
  allowed: string[]
  blocked: number
  reason: string | null
}

/**
 * Menyaring hasil resolusi. Setiap alamat diuji, bukan hanya nama host, dan
 * hasil kosong berarti target tidak boleh dibuka sama sekali.
 */
export function filterPublicAddresses(addresses: string[], kind: 'ipv4' | 'ipv6'): SafeAddressSet {
  const allowed: string[] = []
  let blocked = 0
  let firstReason: string | null = null

  for (const address of addresses) {
    const verdict = classifyAddress(address)
    if (verdict.allowed && verdict.kind === kind) allowed.push(verdict.address)
    else {
      blocked += 1
      firstReason ??= verdict.reason
    }
  }

  return {
    allowed,
    blocked,
    reason:
      allowed.length > 0
        ? null
        : (firstReason ?? 'Tidak ada alamat publik yang dapat digunakan.'),
  }
}

export function isBlockedMetadataAddress(address: string): boolean {
  const normalized = address.replace(/^\[|\]$/g, '')
  return (
    normalized === '169.254.169.254' ||
    normalized === '169.254.170.2' ||
    normalized === '100.100.100.200'
  )
}

const SAFE_HEADER_NAMES = new Set([
  'server',
  'date',
  'content-type',
  'content-length',
  'content-encoding',
  'cache-control',
  'via',
  'x-powered-by',
  'x-generator',
  'x-aspnet-version',
  'x-drupal-cache',
  'link',
  'cf-cache-status',
  'x-served-by',
  'x-cache',
  'x-cache-hits',
  'x-robots',
])

/**
 * Header yang aman ditampilkan. Cookie, authorization, dan apa pun yang dapat
 * memuat kredensial tidak pernah lolos, dan nilai yang tersisa dipotong.
 */
export function isSafeResponseHeader(name: string): boolean {
  const lower = name.toLowerCase()
  if (SAFE_HEADER_NAMES.has(lower)) return true
  return (
    lower.startsWith('x-') &&
    !/(cookie|auth|token|secret|key|session|ticket|signature|credential|csrf)/.test(lower)
  )
}

export function sanitizeHeaderValue(value: string, max = 160): string {
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim()
  return cleaned.length > max ? `${cleaned.slice(0, max - 1)}…` : cleaned
}

// Kebijakan alamat tunggal. Dulu modul ini punya daftar rentang sendiri dan daftar itu
// tertinggal dari penyaring yang dipakai pemeriksaan situs (192.0.0/24, 192.88.99/24,
// 198.18/15, TEST-NET, IPv4-mapped, Teredo, discard 100::/64). Satu sumber kebenaran membuat
// pemindaian dan analisis situs menolak alamat yang sama.
import { isBlockedHostname } from '../website/guards.js'

const HAS_URL_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i
const HAS_HTTP_SCHEME = /^https?:\/\//i
const TRACKING_PARAMETERS = new Set([
  'fbclid',
  'gclid',
  'gbraid',
  'wbraid',
  'mc_cid',
  'mc_eid',
  'igshid',
  'yclid',
])

export const MAX_SCAN_URL_LENGTH = 2048

export class ScanUrlError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ScanUrlError'
  }
}

function isIpv4(host: string): boolean {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return false
  return host.split('.').every((part) => Number(part) <= 255)
}

function isIpHost(host: string): boolean {
  return isIpv4(host) || host.startsWith('[') || host.includes(':')
}

function isTrackingParameter(key: string): boolean {
  const normalized = key.toLowerCase()
  return normalized.startsWith('utm_') || TRACKING_PARAMETERS.has(normalized)
}

function normalizeSearch(url: URL): void {
  const entries = [...url.searchParams]
    .filter(([key]) => !isTrackingParameter(key))
    .sort(([keyA, valueA], [keyB, valueB]) => {
      if (keyA !== keyB) return keyA < keyB ? -1 : 1
      if (valueA === valueB) return 0
      return valueA < valueB ? -1 : 1
    })

  url.search = ''
  for (const [key, value] of entries) {
    url.searchParams.append(key, value)
  }
}

export function normalizeScanUrl(raw: string): string {
  const trimmed = raw.trim()

  if (!trimmed) {
    throw new ScanUrlError('Masukkan URL yang ingin diperiksa.')
  }

  if (trimmed.length > MAX_SCAN_URL_LENGTH) {
    throw new ScanUrlError('URL terlalu panjang.')
  }

  if (/\s/.test(trimmed)) {
    throw new ScanUrlError('URL tidak boleh mengandung spasi.')
  }

  if (HAS_URL_SCHEME.test(trimmed) && !HAS_HTTP_SCHEME.test(trimmed)) {
    throw new ScanUrlError('Hanya URL dengan protokol http atau https yang dapat diperiksa.')
  }

  let url: URL

  try {
    url = new URL(HAS_HTTP_SCHEME.test(trimmed) ? trimmed : `https://${trimmed}`)
  } catch {
    throw new ScanUrlError('Format URL tidak valid.')
  }

  if (!/^https?:$/.test(url.protocol)) {
    throw new ScanUrlError('Hanya URL dengan protokol http atau https yang dapat diperiksa.')
  }

  if (url.username || url.password) {
    throw new ScanUrlError('URL dengan nama pengguna atau kata sandi tidak dapat diperiksa.')
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, '')

  if (!host) {
    throw new ScanUrlError('URL tidak memiliki domain yang valid.')
  }

  if (isBlockedHostname(host)) {
    throw new ScanUrlError('Alamat lokal atau privat tidak dapat diperiksa.')
  }

  if (!host.includes('.') && !isIpHost(host)) {
    throw new ScanUrlError('Domain tidak valid. Sertakan alamat lengkap, misalnya contoh.com.')
  }

  if (host.length > 253) {
    throw new ScanUrlError('Nama domain terlalu panjang.')
  }

  url.hostname = host
  url.hash = ''

  if (
    (url.protocol === 'http:' && url.port === '80') ||
    (url.protocol === 'https:' && url.port === '443')
  ) {
    url.port = ''
  }

  if (!url.pathname) url.pathname = '/'
  normalizeSearch(url)

  if (url.href.length > MAX_SCAN_URL_LENGTH) {
    throw new ScanUrlError('URL ternormalisasi terlalu panjang.')
  }

  return url.href
}

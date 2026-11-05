import { COMMUNITY_POLICY } from './types.js'
// Alamat yang ditolak mengikuti satu kebijakan yang sama dengan pemindaian dan pemeriksaan
// situs; salinan lokal sebelumnya tidak memuat `.internal`, nama metadata, TEST-NET, maupun
// IPv4-mapped.
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

export class CommunityUrlError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CommunityUrlError'
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

export function normalizeCommunityUrl(raw: string): string {
  const trimmed = raw.trim()

  if (!trimmed) {
    throw new CommunityUrlError('Masukkan URL yang ingin dilaporkan.')
  }

  if (trimmed.length > COMMUNITY_POLICY.maxRawUrlLength) {
    throw new CommunityUrlError('URL terlalu panjang.')
  }

  if (/\s/.test(trimmed)) {
    throw new CommunityUrlError('URL tidak boleh mengandung spasi.')
  }

  if (HAS_URL_SCHEME.test(trimmed) && !HAS_HTTP_SCHEME.test(trimmed)) {
    throw new CommunityUrlError('Hanya URL dengan protokol http atau https yang dapat dilaporkan.')
  }

  let url: URL

  try {
    url = new URL(HAS_HTTP_SCHEME.test(trimmed) ? trimmed : `https://${trimmed}`)
  } catch {
    throw new CommunityUrlError('Format URL tidak valid.')
  }

  if (!/^https?:$/.test(url.protocol)) {
    throw new CommunityUrlError('Hanya URL dengan protokol http atau https yang dapat dilaporkan.')
  }

  if (url.username || url.password) {
    throw new CommunityUrlError('URL dengan nama pengguna atau kata sandi tidak dapat dilaporkan.')
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, '')

  if (!host) {
    throw new CommunityUrlError('URL tidak memiliki domain yang valid.')
  }

  if (isBlockedHostname(host)) {
    throw new CommunityUrlError('Alamat lokal atau privat tidak dapat dilaporkan.')
  }

  if (!host.includes('.') && !isIpHost(host)) {
    throw new CommunityUrlError('Domain tidak valid. Sertakan alamat lengkap, misalnya contoh.com.')
  }

  if (host.length > 253) {
    throw new CommunityUrlError('Nama domain terlalu panjang.')
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

  if (url.href.length > COMMUNITY_POLICY.maxNormalizedUrlLength) {
    throw new CommunityUrlError('URL ternormalisasi terlalu panjang.')
  }

  return url.href
}

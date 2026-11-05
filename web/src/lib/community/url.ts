import { isIpHost, isLocalHost } from '../analysis/text'

export const MAX_COMMUNITY_URL_LENGTH = 2048

/**
 * Batas yang sama dengan isCommunityHostname() di firestore.rules. Pola ini
 * menerima karakter yang memang dapat muncul pada host hasil parser URL (termasuk
 * underscore atau label yang tidak lazim), tetapi menolak seluruh pemisah URL:
 * skema, port, path, query, fragment, kredensial, dan spasi. Setiap label dibatasi
 * 63 karakter sesuai batas DNS agar hostname tidak sekadar "panjang total <=253".
 */
export const MAX_COMMUNITY_HOSTNAME_LENGTH = 253

const COMMUNITY_HOSTNAME_PATTERN =
  /^[a-z0-9_~!-]{1,63}(?:\.[a-z0-9_~!-]{1,63})+$/
const COMMUNITY_IPV6_HOSTNAME_PATTERN = /^\[[0-9a-f:.]+\]$/

// Sama dengan isCommunityReportedUrl() di firestore.rules. URL yang disimpan
// sengaja dibatasi pada skema, host, port opsional, dan path. Query, fragment,
// dan kredensial tidak pernah menjadi bagian dari nilai yang ditampilkan.
const COMMUNITY_REPORTED_URL_PATTERN =
  /^https?:\/\/(?:[a-z0-9_~!-]{1,63}(?:\.[a-z0-9_~!-]{1,63})+|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?(?:\/[^\s?#@]*)?$/

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

/**
 * Identity policy for Community Reports:
 * - http/https only, no credentials.
 * - Host is lowercase, trailing dot and default port removed.
 * - Fragment is ignored because it is not sent to the server.
 * - Path and non-tracking query values are retained; query keys are sorted.
 * - Common tracking parameters are removed.
 * - Different paths or query values remain different report identities.
 */
export function normalizeCommunityUrl(raw: string): string {
  const trimmed = raw.trim()

  if (!trimmed) {
    throw new CommunityUrlError('Masukkan URL yang ingin dilaporkan.')
  }

  if (trimmed.length > MAX_COMMUNITY_URL_LENGTH) {
    throw new CommunityUrlError(
      `URL terlalu panjang (maksimal ${MAX_COMMUNITY_URL_LENGTH} karakter).`,
    )
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
    throw new CommunityUrlError('Format URL tidak valid. Contoh: https://contoh.com/halaman')
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

  if (isLocalHost(host)) {
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

  if (url.href.length > MAX_COMMUNITY_URL_LENGTH) {
    throw new CommunityUrlError(
      `URL ternormalisasi terlalu panjang (maksimal ${MAX_COMMUNITY_URL_LENGTH} karakter).`,
    )
  }

  return url.href
}

export function hostnameFromCommunityUrl(normalizedUrl: string): string {
  return new URL(normalizedUrl).hostname
}

/**
 * Pemeriksaan bentuk, bukan bukti bahwa hostname benar-benar milik URL yang
 * di-hash. Hash URL satu arah dan aturan Firestore tidak dapat menghitung ulang
 * SHA-256, sehingga klien yang dimodifikasi tetap dapat memilih hostname lain
 * selama bentuknya lolos. Nilai ini hanya boleh ditampilkan sebagai laporan pengguna.
 */
export function isCommunityHostname(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_COMMUNITY_HOSTNAME_LENGTH &&
    (COMMUNITY_HOSTNAME_PATTERN.test(value) ||
      COMMUNITY_IPV6_HOSTNAME_PATTERN.test(value))
  )
}

/**
 * Bentuk URL yang boleh disimpan dan ditampilkan: http/https, host publik yang
 * berbentuk sama dengan hostname, port opsional, dan path. Tidak ada kredensial,
 * query, fragment, atau spasi. Ini pemeriksaan bentuk; bukan bukti bahwa URL
 * benar-benar milik laporan atau bahwa situsnya aman.
 */
export function isCommunityReportedUrl(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_COMMUNITY_URL_LENGTH &&
    COMMUNITY_REPORTED_URL_PATTERN.test(value)
  )
}

/**
 * Menyusun URL yang aman ditampilkan dari URL ternormalisasi. Query dan fragment
 * selalu dibuang, kredensial ditolak, dan karakter '@' pada path di-encode agar
 * tidak menyerupai bagian kredensial. Nilai ini hanya untuk ditampilkan sebagai
 * teks, bukan tautan aktif.
 */
export function sanitizeCommunityUrlForDisplay(value: unknown): string | null {
  if (typeof value !== 'string' || value !== value.trim()) return null
  if (!HAS_HTTP_SCHEME.test(value)) return null

  let normalized: string
  try {
    normalized = normalizeCommunityUrl(value)
  } catch {
    return null
  }

  const url = new URL(normalized)
  const path = url.pathname.replace(/@/g, '%40')
  const display = `${url.protocol}//${url.host}${path}`
  return isCommunityReportedUrl(display) ? display : null
}

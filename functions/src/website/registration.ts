import type {
  DomainAgeAnalysis,
  DomainRegistration,
  Lookup,
  LookupStatus,
  RegistrationQueryResult,
} from './types.js'

/**
 * Umur registrasi domain dibaca langsung dari registry melalui RDAP (RFC 9083),
 * bukan dari layanan pihak ketiga yang mengembalikan "vonis". Tujuannya terbatas:
 * mengetahui kapan sebuah domain terdaftar dan kapan ia kedaluwarsa.
 *
 * Batas yang dijaga di sini:
 * - Domain muda adalah indikator lemah sampai sedang, bukan bukti phishing.
 * - Tidak adanya data RDAP berarti "tidak tahu", sama sekali bukan "bersih".
 * - Masa sewa satu tahun adalah default hampir semua registry, jadi tidak dinilai.
 */

const MAX_BOOTSTRAP_BYTES = 2 * 1024 * 1024
const MAX_RDAP_BYTES = 512 * 1024
const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000

export const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json'

// Endpoint yang sudah diverifikasi dipakai sebagai latar ketika berkas bootstrap
// IANA tidak dapat dijangkau. Isanya sengaja kecil dan transparan supaya dapat
// diperiksa manual; TLD di luar daftar ini dilaporkan tidak didukung, bukan ditebak.
export const STATIC_RDAP_ENDPOINTS: Record<string, string> = {
  com: 'https://rdap.verisign.com/com/v1/',
  net: 'https://rdap.verisign.com/net/v1/',
  org: 'https://rdap.publicinterestregistry.org/rdap/',
  id: 'https://rdap.pandi.id/rdap/',
  sg: 'https://rdap.sgnic.sg/rdap/',
  xyz: 'https://rdap.centralnic.com/xyz/',
  top: 'https://rdap.zdnsgtld.com/top/',
}

type BootstrapEntry = { tlds: string[]; baseUrl: string }

let bootstrapCache: { entries: BootstrapEntry[]; fetchedAt: number } | null = null

function normalizeBaseUrl(value: string): string | null {
  if (!/^https:\/\//i.test(value)) return null
  return value.endsWith('/') ? value : `${value}/`
}

export function parseRdapBootstrap(json: unknown): BootstrapEntry[] {
  if (!json || typeof json !== 'object') return []
  const services = (json as { services?: unknown }).services
  if (!Array.isArray(services)) return []

  const entries: BootstrapEntry[] = []
  for (const service of services) {
    if (!Array.isArray(service)) continue
    const tlds = Array.isArray(service[0]) ? service[0].filter((t): t is string => typeof t === 'string') : []
    const servers = Array.isArray(service[1]) ? service[1] : []
    const baseUrl = servers
      .map((server) => (typeof server === 'string' ? normalizeBaseUrl(server) : null))
      .find((url): url is string => Boolean(url))
    if (!baseUrl || tlds.length === 0) continue
    entries.push({ tlds, baseUrl })
  }
  return entries
}

/**
 * Bootstrap RDAP diambil sekali per proses dan dipegang selama TTL. Kegagalan
 * pengambilannya tidak membuat pemeriksaan dianggap berhasil: pemanggil tetap
 * mendapat laporan apa adanya.
 */
export async function loadRdapBootstrap(input: {
  fetchImpl: typeof fetch
  now: () => number
  signal?: AbortSignal
}): Promise<BootstrapEntry[]> {
  const cached = bootstrapCache
  if (cached && input.now() - cached.fetchedAt < BOOTSTRAP_TTL_MS) return cached.entries

  try {
    const response = await input.fetchImpl(RDAP_BOOTSTRAP_URL, {
      redirect: 'error',
      signal: input.signal,
      headers: { accept: 'application/json' },
    })
    if (!response.ok) return Object.keys(STATIC_RDAP_ENDPOINTS).map((tld) => ({
      tlds: [tld],
      baseUrl: STATIC_RDAP_ENDPOINTS[tld]!,
    }))

    const declared = Number(response.headers.get('content-length') ?? '0')
    if (declared > MAX_BOOTSTRAP_BYTES) return []
    const text = await response.text()
    if (text.length > MAX_BOOTSTRAP_BYTES) return []

    const entries = parseRdapBootstrap(JSON.parse(text))
    if (entries.length > 0) bootstrapCache = { entries, fetchedAt: input.now() }
    return entries
  } catch {
    return Object.keys(STATIC_RDAP_ENDPOINTS).map((tld) => ({
      tlds: [tld],
      baseUrl: STATIC_RDAP_ENDPOINTS[tld]!,
    }))
  }
}

export function rdapBaseUrl(tld: string, entries: BootstrapEntry[]): string | null {
  const lowered = tld.toLowerCase().replace(/^\./, '')
  if (!/^[a-z0-9-]{1,63}$/.test(lowered)) return null
  const found = entries.find((entry) => entry.tlds.includes(lowered))
  if (found) return found.baseUrl
  const staticUrl = STATIC_RDAP_ENDPOINTS[lowered]
  return staticUrl ? normalizeBaseUrl(staticUrl) : null
}

function eventDate(events: unknown, ...actions: string[]): string | null {
  if (!Array.isArray(events)) return null
  for (const action of actions) {
    for (const raw of events) {
      if (!raw || typeof raw !== 'object') continue
      const event = raw as { eventAction?: unknown; eventDate?: unknown }
      if (typeof event.eventAction !== 'string') continue
      if (event.eventAction.toLowerCase() !== action) continue
      if (typeof event.eventDate !== 'string') continue
      const parsed = Date.parse(event.eventDate)
      if (!Number.isNaN(parsed)) return new Date(parsed).toISOString()
    }
  }
  return null
}

function registrarName(entities: unknown): string | null {
  if (!Array.isArray(entities)) return null
  for (const raw of entities) {
    if (!raw || typeof raw !== 'object') continue
    const entity = raw as { roles?: unknown; vcardArray?: unknown }
    const roles = Array.isArray(entity.roles) ? entity.roles : []
    if (!roles.includes('registrar')) continue
    const vcard = entity.vcardArray
    if (!Array.isArray(vcard) || !Array.isArray(vcard[1])) continue
    for (const row of vcard[1]) {
      if (!Array.isArray(row) || row[0] !== 'fn') continue
      const value = row[3]
      if (typeof value === 'string' && value.trim()) return value.trim().slice(0, 120)
    }
  }
  return null
}

export function parseRdapDomain(json: unknown, requested: string): DomainRegistration | null {
  if (!json || typeof json !== 'object') return null
  const domain = json as {
    objectClassName?: unknown
    ldhName?: unknown
    handle?: unknown
    status?: unknown
    events?: unknown
    entities?: unknown
  }
  if (domain.objectClassName !== 'domain') return null

  const statuses = Array.isArray(domain.status)
    ? domain.status.filter((s): s is string => typeof s === 'string').slice(0, 12)
    : []

  return {
    domain: typeof domain.ldhName === 'string' ? domain.ldhName.toLowerCase() : requested.toLowerCase(),
    handle: typeof domain.handle === 'string' ? domain.handle.slice(0, 80) : null,
    registrar: registrarName(domain.entities),
    createdAt: eventDate(domain.events, 'registration', 'domain registered'),
    changedAt: eventDate(domain.events, 'last changed'),
    expiresAt: eventDate(domain.events, 'expiration'),
    statuses,
  }
}

export async function queryRdapRegistration(input: {
  domain: string
  fetchImpl: typeof fetch
  now: () => number
  timeoutMs?: number
  signal?: AbortSignal
}): Promise<RegistrationQueryResult> {
  const domain = input.domain.toLowerCase().replace(/\.$/, '')
  const ipLiteral =
    /^(\d{1,3}\.){3}\d{1,3}$/.test(domain) || domain.startsWith('[') || /^\d+$/.test(domain)
  if (
    ipLiteral ||
    !/^[a-z0-9.-]{3,253}$/.test(domain) ||
    !domain.includes('.') ||
    domain.includes('..')
  ) {
    return {
      registration: null,
      outcome: 'unsupported',
      source: null,
      detail: 'Nama host bukan domain registrable yang sah, jadi registry tidak dapat ditanyakan.',
    }
  }

  const tld = domain.split('.').pop() ?? ''
  const entries = await loadRdapBootstrap({ fetchImpl: input.fetchImpl, now: input.now, signal: input.signal })
  const baseUrl = rdapBaseUrl(tld, entries)
  if (!baseUrl) {
    return {
      registration: null,
      outcome: 'unsupported',
      source: null,
      detail: `Registry untuk TLD .${tld} tidak menyediakan RDAP pada daftar bootstrap yang dikenal.`,
    }
  }

  const host = new URL(baseUrl).hostname
  const target = `${baseUrl}domain/${encodeURIComponent(domain)}`
  const controller = new AbortController()
  const timeoutMs = input.timeoutMs ?? 6_000
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  const onParentAbort = () => controller.abort(input.signal?.reason)
  if (input.signal) {
    if (input.signal.aborted) controller.abort(input.signal.reason)
    else input.signal.addEventListener('abort', onParentAbort, { once: true })
  }

  try {
    const response = await input.fetchImpl(target, {
      redirect: 'error',
      signal: controller.signal,
      headers: { accept: 'application/rdap+json, application/json' },
    })

    if (response.status === 404) {
      return {
        registration: null,
        outcome: 'not_found',
        source: host,
        detail: `Registry RDAP untuk .${tld} tidak mengenal domain ini. Status ini berarti "tidak ada data", bukan "domain aman".`,
      }
    }
    if (!response.ok) {
      return {
        registration: null,
        outcome: 'failed',
        source: host,
        detail: `Registry RDAP menjawab dengan status HTTP ${response.status}.`,
      }
    }

    const contentType = (response.headers.get('content-type') ?? '').toLowerCase()
    if (contentType && !contentType.includes('json')) {
      return {
        registration: null,
        outcome: 'failed',
        source: host,
        detail: 'Jawaban RDAP bukan JSON, jadi isinya tidak diurai.',
      }
    }

    const declared = Number(response.headers.get('content-length') ?? '0')
    if (declared > MAX_RDAP_BYTES) {
      return { registration: null, outcome: 'failed', source: host, detail: 'Jawaban RDAP melebihi batas ukuran yang diizinkan.' }
    }

    const text = await response.text()
    if (text.length > MAX_RDAP_BYTES) {
      return { registration: null, outcome: 'failed', source: host, detail: 'Jawaban RDAP melebihi batas ukuran yang diizinkan.' }
    }

    let parsed: unknown
    try {
      parsed = JSON.parse(text)
    } catch {
      return { registration: null, outcome: 'failed', source: host, detail: 'Jawaban RDAP tidak dapat diurai sebagai JSON.' }
    }

    const registration = parseRdapDomain(parsed, domain)
    if (!registration) {
      return { registration: null, outcome: 'empty', source: host, detail: 'Jawaban RDAP tidak memuat objek domain.' }
    }

    return {
      registration,
      outcome: 'answered',
      source: host,
      detail: registration.createdAt
        ? `Tanggal registrasi terbaca dari registry RDAP.`
        : `Registry RDAP menjawab, tetapi tidak memuat tanggal registrasi.`,
    }
  } catch (error: unknown) {
    const aborted = error instanceof Error && error.name === 'AbortError'
    return {
      registration: null,
      outcome: aborted ? 'timeout' : 'failed',
      source: null,
      detail: aborted
        ? 'Kueri RDAP melebihi batas waktu atau permintaan analisis dihentikan.'
        : 'Kueri RDAP tidak dapat diselesaikan dari jaringan ini.',
    }
  } finally {
    clearTimeout(timer)
    input.signal?.removeEventListener('abort', onParentAbort)
  }
}

const DAY_MS = 86_400_000

function ageLookup(
  result: RegistrationQueryResult,
  at: string,
): Lookup<DomainRegistration> {
  const statusByOutcome: Record<RegistrationQueryResult['outcome'], LookupStatus> = {
    answered: 'success',
    empty: 'empty',
    failed: 'failed',
    timeout: 'timeout',
    unsupported: 'unavailable',
    not_found: 'empty',
  }
  return {
    status: statusByOutcome[result.outcome],
    source: result.source ? `registry RDAP ${result.source}` : 'registry RDAP',
    value: result.registration,
    detail: result.detail,
    queriedAt: at,
  }
}

/**
 * Mengubah hasil kueri registry menjadi temuan umur domain. Tidak ada jalur kode
 * di sini yang menyimpulkan "aman" dari ketiadaan data.
 */
export function analyzeDomainAge(input: {
  registrableDomain: string | null
  result: RegistrationQueryResult
  now: () => number
}): DomainAgeAnalysis {
  const at = new Date(input.now()).toISOString()
  const lookup = ageLookup(input.result, at)
  const notes: string[] = [
    'Umur registrasi dibaca langsung dari registry RDAP; tidak ada layanan reputasi pihak ketiga yang dipakai.',
    'Domain muda adalah indikator lemah sampai sedang. Banyak situs sah baru berusia beberapa hari, dan banyak phishing memakai domain tua yang dibajak.',
    'Masa sewa satu tahun tidak dinilai sama sekali karena itu default hampir semua registry.',
    'Ketiadaan data RDAP berarti pemeriksaan tidak berjalan, bukan berarti domain bersih.',
  ]

  if (!input.registrableDomain) {
    return {
      status: 'unavailable',
      registrableDomain: null,
      lookup: { ...lookup, status: 'unavailable', detail: 'Target berupa alamat IP, jadi umur registrasi tidak berlaku.' },
      ageDays: null,
      ageBasis: 'none',
      findings: [],
      notes: [...notes, 'Tidak ada domain yang dapat ditanyakan ke registry untuk target berbentuk alamat IP.'],
    }
  }

  const registration = lookup.value
  const findings: DomainAgeAnalysis['findings'] = []

  if (!registration || !registration.createdAt) {
    const unavailable = lookup.status !== 'success'
    findings.push({
      code: unavailable ? 'registration_unavailable' : 'registration_date_missing',
      label: unavailable ? 'Data registrasi tidak tersedia' : 'Tanggal registrasi tidak dilaporkan registry',
      strength: 'weak',
      detail: unavailable
        ? `Pemeriksaan umur domain tidak berhasil (${lookup.status}): ${lookup.detail ?? 'tanpa keterangan dari registry'}. Status ini tidak dihitung sebagai bukti keamanan maupun risiko.`
        : 'Registry RDAP menjawab, tetapi tidak memuat tanggal registrasi, jadi umur domain tidak dapat dihitung.',
      evidence: input.registrableDomain,
    })
    return {
      status: unavailable ? 'unavailable' : 'partial',
      registrableDomain: input.registrableDomain,
      lookup,
      ageDays: null,
      ageBasis: 'none',
      findings,
      notes,
    }
  }

  const createdMs = Date.parse(registration.createdAt)
  const ageDays = Number.isNaN(createdMs) ? null : Math.max(0, Math.floor((input.now() - createdMs) / DAY_MS))

  if (ageDays === null) {
    findings.push({
      code: 'registration_date_missing',
      label: 'Tanggal registrasi tidak dapat dihitung',
      strength: 'weak',
      detail: 'Registry mengirim tanggal registrasi yang tidak dapat dibaca sebagai waktu, jadi umur domain tidak dihitung.',
      evidence: registration.createdAt,
    })
  } else if (ageDays <= 30) {
    findings.push({
      code: 'domain_young',
      label: `Domain baru berusia ${ageDays} hari`,
      strength: 'moderate',
      detail: `Domain ${input.registrableDomain} terdaftar ${ageDays} hari sebelum pemeriksaan ini. Kampanye phishing sering memakai domain yang baru dibeli, tetapi banyak situs sah juga baru didaftarkan.`,
      evidence: registration.createdAt,
    })
  } else if (ageDays <= 180) {
    findings.push({
      code: 'domain_recent',
      label: `Domain berusia ${Math.round(ageDays / 30)} bulan`,
      strength: 'weak',
      detail: `Domain ${input.registrableDomain} terdaftar sekitar ${ageDays} hari lalu. Usia sejauh ini hanya penanda lemah.`,
      evidence: registration.createdAt,
    })
  } else {
    findings.push({
      code: 'domain_mature',
      label: `Domain telah terdaftar ${Math.floor(ageDays / 365)} tahun`,
      strength: 'mitigating',
      detail: `Domain ${input.registrableDomain} terdaftar sejak ${registration.createdAt.slice(0, 10)}. Umur yang panjang sedikit menurunkan kecurigaan, tetapi tidak menghapus bukti lain: domain lama bisa dibajak atau dijual ulang.`,
      evidence: registration.createdAt,
    })
  }

  if (registration.expiresAt) {
    const expiresMs = Date.parse(registration.expiresAt)
    const daysToExpiry = Number.isNaN(expiresMs) ? null : Math.floor((expiresMs - input.now()) / DAY_MS)
    if (daysToExpiry !== null && daysToExpiry < 0) {
      findings.push({
        code: 'registration_expiring',
        label: 'Registrasi domain sudah kedaluwarsa di registry',
        strength: 'moderate',
        detail: `Tanggal kedaluwarsa yang dilaporkan registry (${registration.expiresAt.slice(0, 10)}) sudah lewat, sementara nama host masih menjawab. Kondisi ini biasa terjadi pada domain yang sedang dalam proses perpanjangan atau grace period.`,
        evidence: registration.expiresAt,
      })
    }
  }

  return {
    status: 'complete',
    registrableDomain: input.registrableDomain,
    lookup,
    ageDays,
    ageBasis: 'registration',
    findings,
    notes,
  }
}

export function unavailableRegistration(at: string, reason: string): DomainAgeAnalysis {
  return {
    status: 'unavailable',
    registrableDomain: null,
    lookup: {
      status: 'unavailable',
      source: 'registry RDAP',
      value: null,
      detail: reason,
      queriedAt: at,
    },
    ageDays: null,
    ageBasis: 'none',
    findings: [],
    notes: [reason, 'Ketiadaan data registrasi tidak dihitung sebagai bukti keamanan.'],
  }
}

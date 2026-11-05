import type {
  AsnInfo,
  AsnQueryResult,
  LookupOutcome,
  OriginRequest,
  OriginResult,
  RecordQueryResult,
  ResolveResult,
  SiteProbe,
  TlsProbeResult,
  WebsiteRecordType,
} from '../../functions/src/website/types.js'
import {
  classifyAddress,
  expandIpv6,
  isBlockedHostname,
  isBlockedMetadataAddress,
  parseIpv4,
} from '../../functions/src/website/guards.js'
import { queryRdapRegistration } from '../../functions/src/website/registration.js'

const DNS_TIMEOUT_MS = 5_000
const TLS_TIMEOUT_MS = 7_000
const RDAP_TIMEOUT_MS = 5_000
const MAX_DOH_BODY = 100_000

const DEFAULT_DOH_ENDPOINTS = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/resolve',
] as const

const TYPE_CODES: Record<WebsiteRecordType, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
}

type DohAnswer = {
  name?: unknown
  type?: unknown
  data?: unknown
}

type DohResult = {
  status: number
  answers: DohAnswer[]
}

type ProbeOptions = {
  fetchImpl?: typeof fetch
  dohEndpoints?: readonly string[]
}

class DohQueryError extends Error {
  readonly outcome: LookupOutcome

  constructor(message: string, outcome: LookupOutcome = 'failed') {
    super(message)
    this.name = 'DohQueryError'
    this.outcome = outcome
  }
}

function textValue(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function rcodeDetail(status: number): string {
  switch (status) {
    case 2:
      return 'Server DNS mengembalikan SERVFAIL.'
    case 5:
      return 'Server DNS menolak kueri (REFUSED).'
    default:
      return `Kueri DNS mengembalikan kode ${status}.`
  }
}

function unquoteTxt(value: string): string {
  const trimmed = value.trim()
  const unwrapped =
    trimmed.startsWith('"') && trimmed.endsWith('"') ? trimmed.slice(1, -1) : trimmed
  return unwrapped.replace(/\\"/g, '"').replace(/\\\\/g, '\\')
}

function formatAnswer(type: WebsiteRecordType, value: string): string {
  if (type === 'TXT') return unquoteTxt(value)
  return value.length > 500 ? `${value.slice(0, 499)}…` : value
}

function linkedSignal(
  parent: AbortSignal | undefined,
  timeoutMs: number,
): { signal: AbortSignal; clear: () => void; timedOut: () => boolean } {
  const controller = new AbortController()
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeoutMs)
  const onAbort = () => controller.abort()
  if (parent) {
    if (parent.aborted) controller.abort()
    else parent.addEventListener('abort', onAbort, { once: true })
  }

  return {
    signal: controller.signal,
    clear: () => {
      clearTimeout(timer)
      parent?.removeEventListener('abort', onAbort)
    },
    timedOut: () => timedOut,
  }
}

async function queryDoh(
  fetchImpl: typeof fetch,
  endpoints: readonly string[],
  name: string,
  type: WebsiteRecordType,
  signal?: AbortSignal,
): Promise<DohResult> {
  const deadline = linkedSignal(signal, DNS_TIMEOUT_MS)
  let lastDetail = 'Kueri DNS tidak dapat diselesaikan.'
  let lastOutcome: LookupOutcome = 'failed'

  try {
    for (const endpoint of endpoints) {
      if (deadline.signal.aborted) break

      let url: URL
      try {
        url = new URL(endpoint)
      } catch {
        continue
      }
      url.searchParams.set('name', name)
      url.searchParams.set('type', type)
      url.searchParams.set('ct', 'application/dns-json')

      try {
        const response = await fetchImpl(url.href, {
          method: 'GET',
          headers: { accept: 'application/dns-json' },
          redirect: 'follow',
          signal: deadline.signal,
        })
        if (!response.ok) {
          lastDetail = 'Kueri DNS ditolak oleh resolver.'
          lastOutcome = 'failed'
          continue
        }

        const raw = await response.text()
        if (raw.length > MAX_DOH_BODY) {
          lastDetail = 'Jawaban DNS terlalu besar untuk dibaca.'
          lastOutcome = 'failed'
          continue
        }

        let payload: unknown
        try {
          payload = JSON.parse(raw) as unknown
        } catch {
          lastDetail = 'Jawaban DNS tidak dapat diuraikan.'
          lastOutcome = 'failed'
          continue
        }

        if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
          lastDetail = 'Jawaban DNS tidak valid.'
          lastOutcome = 'failed'
          continue
        }
        const record = payload as { Status?: unknown; Answer?: unknown }
        const status = typeof record.Status === 'number' ? record.Status : 0
        const answers = Array.isArray(record.Answer) ? (record.Answer as DohAnswer[]) : []

        if (status !== 0 && status !== 3) {
          lastDetail = rcodeDetail(status)
          lastOutcome = 'failed'
          continue
        }

        return { status, answers }
      } catch {
        if (deadline.signal.aborted) break
        lastDetail = 'Kueri DNS gagal dihubungi.'
        lastOutcome = 'failed'
      }
    }

    if (deadline.timedOut()) {
      throw new DohQueryError('Kueri DNS melebihi batas waktu.', 'timeout')
    }
    if (signal?.aborted) {
      throw new DohQueryError('Kueri DNS dibatalkan karena batas waktu analisis.', 'timeout')
    }
    throw new DohQueryError(lastDetail, lastOutcome)
  } finally {
    deadline.clear()
  }
}

function answersOf(answers: DohAnswer[], type: WebsiteRecordType): string[] {
  const code = TYPE_CODES[type]
  return answers
    .filter((answer) => answer.type === code && typeof answer.data === 'string')
    .map((answer) => formatAnswer(type, answer.data as string))
    .filter((value) => value.length > 0)
}

function errorWithTimeoutFlag(message: string, timedOut: boolean): Error {
  const error = new Error(message) as Error & { code?: string }
  if (timedOut) error.code = 'ETIMEDOUT'
  return error
}

function cymruQname(address: string): string | null {
  const v4 = parseIpv4(address)
  if (v4) {
    return `${[...v4].reverse().join('.')}.origin.asn.cymru.com`
  }

  const bytes = expandIpv6(address)
  if (!bytes) return null
  const hex = bytes.map((byte) => byte.toString(16).padStart(2, '0')).join('')
  return `${hex.split('').reverse().join('.')}.origin6.asn.cymru.com`
}

function parseCymruAnswer(value: string): AsnInfo | null {
  const parts = unquoteTxt(value)
    .split('|')
    .map((part) => part.trim())
  if (parts.length < 4) return null
  const [asn, prefix, country, registry] = parts
  if (!asn) return null
  return {
    asn,
    organization: null,
    country: country ?? null,
    prefix: prefix ?? null,
    registry: registry ?? null,
  }
}

function authority(hostname: string, port: number, secure: boolean): string {
  const host =
    hostname.includes(':') && !hostname.startsWith('[') ? `[${hostname}]` : hostname
  const defaultPort = secure ? 443 : 80
  return `${secure ? 'https' : 'http'}://${host}${port === defaultPort ? '' : `:${port}`}`
}

// Nama host yang sudah berupa alamat literal tidak perlu (dan tidak bisa) diverifikasi ulang
// lewat DNS; kebijakan SSRF sudah menilainya langsung.
function isIpLiteral(hostname: string): boolean {
  const verdict = classifyAddress(hostname)
  return verdict.address.length > 0 && (parseIpv4(verdict.address) !== null || expandIpv6(verdict.address) !== null)
}

function headerPairs(headers: Headers): Array<[string, string]> {
  const pairs: Array<[string, string]> = []
  const getSetCookie = (
    headers as Headers & { getSetCookie?: () => string[] }
  ).getSetCookie
  const setCookies =
    typeof getSetCookie === 'function' ? getSetCookie.call(headers) : []
  const hasSetCookieList = Array.isArray(setCookies) && setCookies.length > 0

  for (const [name, value] of headers.entries()) {
    if (hasSetCookieList && name.toLowerCase() === 'set-cookie') continue
    pairs.push([name, value])
  }
  for (const cookie of setCookies) {
    pairs.push(['set-cookie', cookie])
  }
  return pairs
}

function isHtmlContentType(value: string | null): boolean {
  const lower = (value ?? '').toLowerCase()
  return lower.includes('text/html') || lower.includes('application/xhtml+xml')
}

async function readHtmlBody(
  response: Response,
  maxBytes: number,
): Promise<{ body: string; bytes: number; truncated: boolean }> {
  if (!response.body) return { body: '', bytes: 0, truncated: false }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  const chunks: Uint8Array[] = []
  let bytes = 0
  let kept = 0
  let truncated = false

  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      bytes += value.byteLength
      const room = maxBytes - kept
      if (room <= 0) {
        truncated = true
        await reader.cancel().catch(() => undefined)
        break
      }
      const slice = value.byteLength > room ? value.subarray(0, room) : value
      chunks.push(slice)
      kept += slice.byteLength
      if (slice.byteLength < value.byteLength) {
        truncated = true
        await reader.cancel().catch(() => undefined)
        break
      }
    }
  } finally {
    reader.releaseLock()
  }

  const merged = new Uint8Array(kept)
  let offset = 0
  for (const chunk of chunks) {
    merged.set(chunk, offset)
    offset += chunk.byteLength
  }

  return { body: decoder.decode(merged), bytes, truncated }
}

export function createWorkerSiteProbe(options: ProbeOptions = {}): SiteProbe {
  const fetchImpl = options.fetchImpl ?? fetch
  const dohEndpoints = options.dohEndpoints ?? DEFAULT_DOH_ENDPOINTS

  async function resolveAddresses(
    hostname: string,
    signal?: AbortSignal,
  ): Promise<ResolveResult> {
    const results = await Promise.allSettled([
      queryDoh(fetchImpl, dohEndpoints, hostname, 'A', signal),
      queryDoh(fetchImpl, dohEndpoints, hostname, 'AAAA', signal),
    ])

    const a = results[0].status === 'fulfilled' ? results[0].value : null
    const aaaa = results[1].status === 'fulfilled' ? results[1].value : null
    const ipv4 = a ? answersOf(a.answers, 'A') : []
    const ipv6 = aaaa ? answersOf(aaaa.answers, 'AAAA') : []
    const notes: string[] = []

    if (results[0].status === 'rejected') {
      const error = results[0].reason
      notes.push(
        `A: ${error instanceof Error ? error.message : 'Kueri DNS gagal.'}`,
      )
    }
    if (results[1].status === 'rejected') {
      const error = results[1].reason
      notes.push(
        `AAAA: ${error instanceof Error ? error.message : 'Kueri DNS gagal.'}`,
      )
    }

    if (ipv4.length === 0 && ipv6.length === 0) {
      const timedOut = results.some(
        (result) =>
          result.status === 'rejected' &&
          result.reason instanceof DohQueryError &&
          result.reason.outcome === 'timeout',
      )
      const detail =
        notes[0] ??
        (a?.status === 3 || aaaa?.status === 3
          ? 'Domain tidak ditemukan (NXDOMAIN).'
          : 'Nama host tidak menghasilkan alamat.')
      throw errorWithTimeoutFlag(detail, timedOut)
    }

    return {
      ipv4,
      ipv6,
      detail: notes.length > 0 ? notes.join(' | ') : null,
    }
  }

  /**
   * VGM-03: runtime Worker tidak mengizinkan fetch yang dipaksa ke satu alamat IP dengan
   * SNI hostname asli, jadi yang bisa dilakukan hanyalah MEMPERSEMPIT jeda antara validasi
   * (di `website/service.ts`) dan koneksi: jawaban DNS dipaksa ulang sesaat sebelum koneksi dan
   * permintaan ditolak bila
   *  - alamat yang sudah divalidasi tidak lagi ada di jawaban (DNS berubah = rebinding), atau
   *  - ada alamat baru yang masuk rentang terlaris/metadata.
   * Ini tidak membuktikan celahnya tertutup: koneksi tetap dibuka by hostname, jadi resolver yang
   * dipakai runtime saat menyentuh jaringan bukan resolver yang sama yang menjawab pemeriksaan ini,
   * dan perbedaan di antara keduanya tidak bisa dilihat dari dalam Worker. Penutupan penuh butuh
   * egress yang menunjuk alamat hasil validasi (proxy keluar/pinning di luar runtime) — belum ada.
   * Gagal-tutup di sini berarti: kueri DNS verifikasi tidak selesai = tidak ada koneksi.
   */
  async function assertStillPinned(input: {
    hostname: string
    address: string
    signal?: AbortSignal
  }): Promise<{ ok: true } | { ok: false; detail: string }> {
    const wanted = classifyAddress(input.address).address
    let resolved: ResolveResult
    try {
      resolved = await resolveAddresses(input.hostname, input.signal)
    } catch {
      return {
        ok: false,
        detail: 'Alamat tidak dapat diverifikasi ulang sebelum koneksi; permintaan dihentikan.',
      }
    }

    const current = [...resolved.ipv4, ...resolved.ipv6].map(
      (value) => classifyAddress(value).address,
    )
    if (current.length === 0 || !current.includes(wanted)) {
      return {
        ok: false,
        detail: 'DNS berubah antara validasi dan koneksi (potensi DNS rebinding); permintaan dihentikan.',
      }
    }

    for (const value of current) {
      const verdict = classifyAddress(value)
      if (!verdict.allowed || isBlockedMetadataAddress(value)) {
        return {
          ok: false,
          detail: 'Salah satu alamat hasil DNS terbaru ditolak kebijakan SSRF; permintaan dihentikan.',
        }
      }
    }

    return { ok: true }
  }

  return {
    name: 'cloudflare-doh-http',
    dnsSource: 'DNS-over-HTTPS Cloudflare/Google',

    resolve: (hostname: string, signal?: AbortSignal) => resolveAddresses(hostname, signal),

    async queryRecords(
      hostname: string,
      type: WebsiteRecordType,
      signal?: AbortSignal,
    ): Promise<RecordQueryResult> {
      try {
        const result = await queryDoh(fetchImpl, dohEndpoints, hostname, type, signal)
        if (result.status === 3) {
          return {
            records: [],
            outcome: 'empty',
            detail: 'Domain tidak ditemukan (NXDOMAIN).',
          }
        }
        const records = answersOf(result.answers, type).slice(0, 16)
        if (records.length === 0) {
          return {
            records: [],
            outcome: 'empty',
            detail: 'Kueri selesai tanpa record untuk tipe ini.',
          }
        }
        return { records, outcome: 'answered', detail: null }
      } catch (error) {
        if (error instanceof DohQueryError) {
          return { records: [], outcome: error.outcome, detail: error.message }
        }
        return {
          records: [],
          outcome: 'failed',
          detail: 'Kueri DNS tidak dapat diselesaikan.',
        }
      }
    },

    async lookupAsn(address: string, signal?: AbortSignal): Promise<AsnQueryResult> {
      const qname = cymruQname(address)
      if (!qname) {
        return {
          info: null,
          outcome: 'failed',
          detail: 'Alamat tidak dapat diubah menjadi kueri ASN.',
        }
      }

      try {
        const result = await queryDoh(fetchImpl, dohEndpoints, qname, 'TXT', signal)
        if (result.status === 3) {
          return {
            info: null,
            outcome: 'empty',
            detail: 'Tidak ada data ASN untuk alamat ini.',
          }
        }
        const first = answersOf(result.answers, 'TXT').find(
          (value) => value.length > 0,
        )
        if (!first) {
          return {
            info: null,
            outcome: 'empty',
            detail: 'Tidak ada data ASN untuk alamat ini.',
          }
        }
        const info = parseCymruAnswer(first)
        if (!info) {
          return {
            info: null,
            outcome: 'failed',
            detail: 'Jawaban ASN tidak dapat diuraikan.',
          }
        }
        return {
          info,
          outcome: 'answered',
          detail: 'Nama organisasi tidak tersedia dari sumber ini.',
        }
      } catch (error) {
        if (error instanceof DohQueryError) {
          return { info: null, outcome: error.outcome, detail: error.message }
        }
        return {
          info: null,
          outcome: 'failed',
          detail: 'Kueri ASN tidak dapat diselesaikan.',
        }
      }
    },

    lookupRegistration: (domain, signal) =>
      queryRdapRegistration({
        domain,
        fetchImpl,
        now: Date.now,
        timeoutMs: RDAP_TIMEOUT_MS,
        signal,
      }),

    async inspectTls(
      hostname: string,
      address: string,
      kind: 'ipv4' | 'ipv6',
      port: number,
      signal?: AbortSignal,
    ): Promise<TlsProbeResult> {
      const noCert = {
        certificate: null,
        outcome: 'failed' as const,
      }
      if (isBlockedHostname(hostname) || isBlockedMetadataAddress(hostname)) {
        return {
          ...noCert,
          httpsReachable: false,
          detail: 'Nama host internal atau metadata tidak dapat diperiksa.',
        }
      }

      const deadline = linkedSignal(signal, TLS_TIMEOUT_MS)
      try {
        if (!isIpLiteral(hostname)) {
          if (classifyAddress(address).kind !== kind) {
            return {
              ...noCert,
              httpsReachable: false,
              detail: 'Alamat tujuan tidak cocok dengan keluarga DNS yang divalidasi.',
            }
          }
          const pinned = await assertStillPinned({
            hostname,
            address,
            signal: deadline.signal,
          })
          if (!pinned.ok) {
            if (deadline.timedOut()) {
              return {
                ...noCert,
                httpsReachable: false,
                outcome: 'timeout',
                detail: 'Koneksi HTTPS melebihi batas waktu.',
              }
            }
            return { ...noCert, httpsReachable: false, detail: pinned.detail }
          }
        }

        const response = await fetchImpl(`${authority(hostname, port, true)}/`, {
          method: 'GET',
          redirect: 'manual',
          signal: deadline.signal,
        })
        await response.body?.cancel().catch(() => undefined)
        return {
          certificate: null,
          httpsReachable: true,
          outcome: 'answered',
          detail:
            'HTTPS dapat dihubungi; detail sertifikat dan protokol TLS tidak diekspos oleh runtime Cloudflare Workers.',
        }
      } catch {
        if (deadline.timedOut()) {
          return {
            certificate: null,
            httpsReachable: false,
            outcome: 'timeout',
            detail: 'Koneksi HTTPS melebihi batas waktu.',
          }
        }
        return {
          certificate: null,
          httpsReachable: false,
          outcome: 'failed',
          detail: 'Koneksi HTTPS tidak dapat dipastikan dari runtime ini.',
        }
      } finally {
        deadline.clear()
      }
    },

    async openOrigin(
      request: OriginRequest,
      signal?: AbortSignal,
    ): Promise<OriginResult> {
      const startedAt = Date.now()
      const failed = (detail: string): OriginResult => ({
        ok: false,
        kind: 'error',
        detail,
        elapsedMs: Date.now() - startedAt,
      })

      let target: URL
      try {
        target = new URL(request.url)
      } catch {
        return failed('URL tujuan tidak valid.')
      }

      const hostname = target.hostname.toLowerCase().replace(/^\[|\]$/g, '')
      const expectedPort = target.port
        ? Number(target.port)
        : target.protocol === 'https:'
          ? 443
          : 80
      if (
        hostname !== request.hostname.toLowerCase().replace(/^\[|\]$/g, '') ||
        expectedPort !== request.port ||
        request.secure !== (target.protocol === 'https:')
      ) {
        return failed('Target permintaan tidak konsisten dengan URL.')
      }
      if (isBlockedHostname(hostname) || isBlockedMetadataAddress(hostname)) {
        return failed('Nama host internal atau metadata tidak dapat dibuka.')
      }
      const address = classifyAddress(request.address)
      if (!address.allowed || address.kind !== request.kind) {
        return failed('Alamat tujuan ditolak oleh kebijakan SSRF.')
      }

      const deadline = linkedSignal(signal, request.timeoutMs)
      const failedTimeout = (): OriginResult => ({
        ok: false,
        kind: 'timeout',
        detail: 'Permintaan ke origin tidak selesai dalam batas waktu.',
        elapsedMs: Date.now() - startedAt,
      })
      try {
        if (!isIpLiteral(hostname)) {
          const pinned = await assertStillPinned({
            hostname,
            address: request.address,
            signal: deadline.signal,
          })
          if (!pinned.ok) {
            if (deadline.timedOut()) return failedTimeout()
            return failed(pinned.detail)
          }
        }

        const response = await fetchImpl(target.href, {
          method: 'GET',
          headers: {
            accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5',
            'accept-language': 'id,en;q=0.8',
            'user-agent': request.userAgent,
          },
          redirect: 'manual',
          signal: deadline.signal,
        })

        const contentType = response.headers.get('content-type')
        const headers = headerPairs(response.headers)
        let body = ''
        let bytes = 0
        let truncated = false

        if (isHtmlContentType(contentType)) {
          const result = await readHtmlBody(response, request.maxBytes)
          body = result.body
          bytes = result.bytes
          truncated = result.truncated
        } else {
          await response.body?.cancel().catch(() => undefined)
        }

        return {
          ok: true,
          status: response.status,
          statusText: response.statusText || null,
          headers,
          body,
          bytes,
          truncated,
          elapsedMs: Date.now() - startedAt,
          tls: null,
        }
      } catch {
        if (deadline.timedOut()) {
          return failedTimeout()
        }
        return failed(
          signal?.aborted
            ? 'Permintaan dibatalkan sebelum origin menjawab.'
            : 'Koneksi ke origin gagal dari runtime Cloudflare Workers.',
        )
      } finally {
        deadline.clear()
      }
    },
  }
}

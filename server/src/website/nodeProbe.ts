import { promises as dns } from 'node:dns'
import * as http from 'node:http'
import * as https from 'node:https'
import * as net from 'node:net'
import * as tls from 'node:tls'
import { queryRdapRegistration } from '../../../functions/src/website/registration.js'
import type {
  AsnInfo,
  AsnQueryResult,
  LookupOutcome,
  OriginRequest,
  OriginResult,
  OriginTlsInfo,
  RecordQueryResult,
  ResolveResult,
  SiteProbe,
  TlsCertificate,
  TlsProbeResult,
  WebsiteRecordType,
} from '../../../functions/src/website/types.js'

const DNS_FAILURE_DETAILS: Record<string, string> = {
  ESERVFAIL: 'Server DNS menolak menjawab (SERVFAIL).',
  EREFUSED: 'Server DNS menolak kueri (REFUSED).',
  ENOTIMP: 'Server DNS tidak mendukung tipe kueri ini.',
  ENOAUTH: 'Server DNS mengembalikan status gagal autentikasi (NOTAUTH).',
  EBADRESP: 'Jawaban DNS tidak dapat diuraikan.',
  EFORMERR: 'Kueri DNS ditolak karena format tidak valid.',
  ECONNREFUSED: 'Kueri DNS gagal karena koneksi ditolak.',
  ECONNRESET: 'Kueri DNS terputus.',
  EAI_AGAIN: 'Resolusi nama host gagal sementara.',
}

const EMPTY_CODES = new Set(['ENODATA', 'ENOTFOUND', 'ENOENT'])

function errorCodeOf(error: unknown): string {
  if (error && typeof error === 'object' && 'code' in error) {
    const code = (error as { code?: unknown }).code
    if (typeof code === 'string') return code
  }
  return 'UNKNOWN'
}

function outcomeForDnsError(error: unknown): { outcome: LookupOutcome; detail: string } {
  const code = errorCodeOf(error)
  if (code === 'ETIMEOUT' || code === 'ETIMEOUT'.toLowerCase()) {
    return { outcome: 'timeout', detail: 'Kueri DNS melebihi batas waktu resolver.' }
  }
  if (EMPTY_CODES.has(code)) {
    return { outcome: 'empty', detail: 'Kueri selesai tanpa record untuk tipe ini.' }
  }
  return {
    outcome: 'failed',
    detail: DNS_FAILURE_DETAILS[code] ?? `Kueri DNS gagal (kode ${code}).`,
  }
}

function textOf(value: unknown): string {
  if (typeof value === 'string') return value
  if (Buffer.isBuffer(value)) return value.toString('utf8')
  if (Array.isArray(value)) return value.map((part) => textOf(part)).join(' ')
  if (value === null || value === undefined) return ''
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>)
      .map(([key, item]) => `${key}=${textOf(item)}`)
      .join(' ')
  }
  return String(value)
}

function normalizeFamily(address: string): string {
  return address.replace(/^\[|\]$/g, '').split('%')[0] ?? address
}

function describeCertificate(raw: tls.PeerCertificate | tls.DetailedPeerCertificate): TlsCertificate | null {
  const certificate = raw as tls.DetailedPeerCertificate
  if (!certificate || Object.keys(certificate).length === 0) return null

  const notBefore = certificate.valid_from ? Date.parse(certificate.valid_from) : Number.NaN
  const notAfter = certificate.valid_to ? Date.parse(certificate.valid_to) : Number.NaN
  const issuer = certificate.issuer ?? {}
  const subject = certificate.subject ?? {}
  const issuerText = [issuer['CN'], issuer['O']].filter(Boolean).join(', ')
  const subjectText = [subject['CN'], subject['O']].filter(Boolean).join(', ')

  return {
    issuer: issuerText ? issuerText.slice(0, 160) : null,
    subject: subjectText ? subjectText.slice(0, 160) : (textOf(subject['CN']) || null),
    notBefore: Number.isNaN(notBefore) ? null : new Date(notBefore).toISOString(),
    notAfter: Number.isNaN(notAfter) ? null : new Date(notAfter).toISOString(),
    expired: Number.isNaN(notAfter) ? null : notAfter < Date.now(),
    hostnameVerified: null,
    verification: 'not_checked',
    verificationDetail: null,
    protocol: null,
  }
}

function resolveAddresses(hostname: string): Promise<ResolveResult> {
  return Promise.all([
    dns.resolve4(hostname).then(
      (values) => ({ values: values.map(normalizeFamily), error: null as string | null }),
      (error: unknown) => ({ values: [] as string[], error: outcomeForDnsError(error).detail }),
    ),
    dns.resolve6(hostname).then(
      (values) => ({ values: values.map(normalizeFamily), error: null as string | null }),
      (error: unknown) => ({ values: [] as string[], error: outcomeForDnsError(error).detail }),
    ),
  ]).then(([v4, v6]) => {
    if (v4.values.length === 0 && v6.values.length === 0) {
      const detail = v4.error ?? v6.error ?? 'Nama host tidak menghasilkan alamat.'
      throw new Error(detail)
    }
    const notes: string[] = []
    if (v4.values.length === 0 && v4.error) notes.push(`A: ${v4.error}`)
    if (v6.values.length === 0 && v6.error) notes.push(`AAAA: ${v6.error}`)
    return {
      ipv4: v4.values,
      ipv6: v6.values,
      detail: notes.length > 0 ? notes.join(' | ') : null,
    }
  })
}

function recordsForType(
  hostname: string,
  type: WebsiteRecordType,
): Promise<{ records: string[]; outcome: LookupOutcome; detail: string | null }> {
  return dns
    .resolve(hostname, type)
    .then((answer) => {
      const list = Array.isArray(answer) ? answer : [answer]
      const records = list
        .map((entry) => formatRecord(type, entry))
        .filter((entry) => entry.length > 0)
        .slice(0, 16)
      if (records.length === 0) {
        return { records: [] as string[], outcome: 'empty' as const, detail: 'Kueri selesai tanpa record untuk tipe ini.' }
      }
      return { records, outcome: 'answered' as const, detail: null }
    })
    .catch((error: unknown) => {
      const classified = outcomeForDnsError(error)
      return { records: [] as string[], outcome: classified.outcome, detail: classified.detail }
    })
}

function formatRecord(type: WebsiteRecordType, entry: unknown): string {
  if (type === 'MX') {
    const record = entry as { exchange?: string; priority?: number }
    const exchange = record.exchange ?? ''
    return record.priority === undefined ? exchange : `${record.priority} ${exchange}`
  }
  if (type === 'SOA') {
    const record = entry as Record<string, unknown>
    const order = ['primary', 'adminemail', 'serial', 'refresh', 'retry', 'expire', 'minimum']
    const parts = order.map((key) => textOf(record[key])).filter((part) => part.length > 0)
    return parts.length > 0 ? parts.join(' ') : textOf(entry)
  }
  return textOf(entry)
}

function ipv4ToCymru(address: string): string | null {
  const parts = address.split('.')
  if (parts.length !== 4) return null
  return `${parts
    .reverse()
    .map((part) => Number.parseInt(part, 10))
    .join('.')}.origin.asn.cymru.com`
}

function ipv6ToCymru(address: string): string | null {
  const expanded = expandIpv6ForArpa(address)
  if (!expanded) return null
  return `${expanded.split('').reverse().join('.')}.origin6.asn.cymru.com`
}

function expandIpv6ForArpa(address: string): string | null {
  const clean = normalizeFamily(address).toLowerCase()
  if (!clean.includes(':')) return null

  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(clean)
  if (mapped?.[1]) {
    const octets = mapped[1].split('.').map((part) => Number.parseInt(part, 10))
    if (octets.length !== 4 || octets.some((octet) => !Number.isFinite(octet))) return null
    const high = (((octets[0] ?? 0) << 8) | (octets[1] ?? 0)).toString(16).padStart(4, '0')
    const low = (((octets[2] ?? 0) << 8) | (octets[3] ?? 0)).toString(16).padStart(4, '0')
    return `00000000000000000000ffff${high}${low}`
  }

  const halves = clean.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':').filter((part) => part.length > 0) : []
  const tail = halves[1] ? halves[1].split(':').filter((part) => part.length > 0) : []
  if (halves.length === 1 && head.length !== 8) return null

  const fill = halves.length === 2 ? Math.max(0, 8 - head.length - tail.length) : 0
  const groups = [...head, ...Array.from({ length: fill }, () => '0'), ...tail]
  if (groups.length !== 8) return null

  let hex = ''
  for (const group of groups) {
    if (group.includes('.')) {
      const octets = group.split('.').map((part) => Number.parseInt(part, 10))
      if (octets.length !== 4 || octets.some((octet) => !Number.isFinite(octet))) return null
      const high = (((octets[0] ?? 0) << 8) | (octets[1] ?? 0)).toString(16).padStart(4, '0')
      const low = (((octets[2] ?? 0) << 8) | (octets[3] ?? 0)).toString(16).padStart(4, '0')
      hex += `${high}${low}`
      continue
    }
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null
    hex += group.padStart(4, '0')
  }
  return hex.length === 32 ? hex : null
}

function parseCymruAnswer(text: string): AsnInfo | null {
  const parts = text.split('|').map((part) => part.trim())
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

function lookupAsnViaDns(address: string): Promise<AsnQueryResult> {
  const qname = net.isIPv6(address) ? ipv6ToCymru(address) : ipv4ToCymru(address)
  if (!qname) {
    return Promise.resolve({
      info: null,
      outcome: 'failed',
      detail: 'Alamat tidak dapat diubah menjadi kueri ASN.',
    })
  }

  return dns
    .resolve(qname, 'TXT')
    .then((answer) => {
      const rows = (Array.isArray(answer) ? answer : [answer]).map((entry) => textOf(entry))
      const first = rows.find((row) => row.length > 0)
      if (!first) {
        return { info: null, outcome: 'empty' as const, detail: 'Tidak ada data ASN untuk alamat ini.' }
      }
      const info = parseCymruAnswer(first)
      if (!info) {
        return { info: null, outcome: 'failed' as const, detail: 'Jawaban ASN tidak dapat diuraikan.' }
      }
      return {
        info,
        outcome: 'answered' as const,
        detail: 'Nama organisasi tidak tersedia dari sumber ini.',
      }
    })
    .catch((error: unknown) => {
      const classified = outcomeForDnsError(error)
      return {
        info: null,
        outcome: classified.outcome,
        detail: classified.outcome === 'empty' ? 'Tidak ada data ASN untuk alamat ini.' : classified.detail,
      }
    })
}

function tlsDetail(error: unknown): string {
  const code = errorCodeOf(error)
  if (code === 'ECONNREFUSED') return 'Port 443 menolak koneksi.'
  if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH') return 'Port 443 tidak dapat dijangkau dari jaringan ini.'
  if (code === 'CERT_EXPIRED' || code === 'CERT_HAS_EXPIRED') return 'Sertifikat telah kedaluwarsa.'
  if (code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || code === 'SELF_SIGNED_CERT_IN_CHAIN') {
    return 'Rantai sertifikat tidak dapat diverifikasi.'
  }
  if (code === 'ERR_TLS_CERT_ALTNAME_INVALID') return 'Nama host tidak cocok dengan sertifikat.'
  if (code === 'EPROTO' || code === 'SSL_ERROR_SYSCALL') return 'Negosiasi TLS gagal.'
  return `Koneksi TLS gagal (kode ${code}).`
}

function inspectTlsOnPort(
  hostname: string,
  address: string,
  kind: 'ipv4' | 'ipv6',
  port: number,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<TlsProbeResult> {
  return new Promise((resolve) => {
    const cancelled = (): TlsProbeResult => ({
      certificate: null,
      httpsReachable: false,
      outcome: 'failed',
      detail: 'Pemeriksaan dibatalkan sebelum koneksi TLS selesai.',
    })
    // Signal yang sudah dibatalkan tidak akan pernah memicu listener, jadi diperiksa
    // lebih dulu agar tidak ada koneksi yang dibuat untuk permintaan yang sudah berakhir.
    if (signal?.aborted) {
      resolve(cancelled())
      return
    }

    let settled = false
    const finish = (value: TlsProbeResult) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
      socket.destroy()
      resolve(value)
    }

    const socket = tls.connect({
      host: kind === 'ipv6' ? `[${address}]` : address,
      servername: hostname,
      port,
      // Scanner harus tetap membaca sertifikat yang gagal divalidasi supaya status
      // verifikasinya bisa dilaporkan apa adanya. Hasilnya hanya ditampilkan, tidak
      // pernah dipercaya: tidak ada kredensial yang dikirim dan konten dianggap tidak tepercaya.
      rejectUnauthorized: false,
      timeout: timeoutMs,
    })
    const timer = setTimeout(() => {
      finish({
        certificate: null,
        httpsReachable: false,
        outcome: 'timeout',
        detail: 'Koneksi TLS melebihi batas waktu.',
      })
    }, timeoutMs)
    const onAbort = () => finish(cancelled())
    signal?.addEventListener('abort', onAbort, { once: true })

    socket.once('secureConnect', () => {
      const raw = socket.getPeerCertificate(true)
      const certificate = describeCertificate(raw)
      if (certificate) {
        const authorized = socket.authorized === true
        finish({
          certificate: {
            ...certificate,
            hostnameVerified: authorized,
            verification: authorized ? 'verified' : 'rejected',
            verificationDetail: authorized
              ? null
              : (socket.authorizationError
                  ? String(socket.authorizationError)
                  : 'Verifikasi sertifikat gagal pada sambungan ini.'),
            protocol: socket.getProtocol() ?? null,
          },
          httpsReachable: true,
          outcome: 'answered',
          detail: socket.getProtocol() ? `Protokol ${socket.getProtocol()}.` : null,
        })
        return
      }
      finish({
        certificate: null,
        httpsReachable: true,
        outcome: 'empty',
        detail: 'Port 443 terhubung tetapi tidak menghasilkan sertifikat yang terbaca.',
      })
    })

    socket.once('timeout', () =>
      finish({
        certificate: null,
        httpsReachable: false,
        outcome: 'timeout',
        detail: 'Koneksi TLS melebihi batas waktu.',
      }),
    )
    socket.once('error', (error: unknown) => {
      const code = errorCodeOf(error)
      finish({
        certificate: null,
        httpsReachable: false,
        outcome: code === 'ETIMEDOUT' ? 'timeout' : 'failed',
        detail: tlsDetail(error),
      })
    })
  })
}

function originTlsOf(socket: tls.TLSSocket): OriginTlsInfo | null {
  if (!socket || typeof socket.getPeerCertificate !== 'function') return null
  const raw = socket.getPeerCertificate(true)
  const certificate = describeCertificate(raw)
  if (!certificate) return null
  const authorized = socket.authorized === true
  return {
    protocol: socket.getProtocol() ?? null,
    cipher: socket.getCipher()?.name ?? null,
    issuer: certificate.issuer,
    subject: certificate.subject,
    notBefore: certificate.notBefore,
    notAfter: certificate.notAfter,
    authorized,
    authorizationError: authorized ? null : (socket.authorizationError ? String(socket.authorizationError) : null),
  }
}

function openOriginRequest(request: OriginRequest, signal?: AbortSignal): Promise<OriginResult> {
  const startedAt = Date.now()
  const target = new URL(request.url)
  const transport = request.secure ? https : http
  const pin = request.address
  const defaultPort = request.secure ? 443 : 80
  const hostHeader = request.port === defaultPort ? request.hostname : `${request.hostname}:${request.port}`

  return new Promise((resolveOrigin) => {
    const cancelledResult = (): OriginResult => ({
      ok: false,
      kind: 'error',
      detail: 'Permintaan dibatalkan sebelum origin menjawab.',
      elapsedMs: Date.now() - startedAt,
    })
    // Signal yang sudah dibatalkan tidak akan pernah memicu listener, jadi origin
    // tidak boleh dihubungi sama sekali untuk permintaan yang sudah berakhir.
    if (signal?.aborted) {
      resolveOrigin(cancelledResult())
      return
    }

    let settled = false
    let truncated = false
    let timedOut = false
    const chunks: Buffer[] = []
    let received = 0
    let buffered = 0
    let captureBody = true

    const finish = (value: OriginResult) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
      resolveOrigin(value)
    }

    const req = transport.request(
      {
        host: request.kind === 'ipv6' ? `[${pin}]` : pin,
        port: request.port,
        method: 'GET',
        path: `${target.pathname}${target.search}`,
        agent: false,
        servername: request.secure ? request.hostname : undefined,
        headers: {
          host: hostHeader,
          'user-agent': request.userAgent,
          accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5',
          'accept-language': 'id,en;q=0.8',
        },
        lookup: ((_hostname: string, _options: unknown, callback: (err: Error | null, address: string, family: number) => void) => {
          callback(null, pin, request.kind === 'ipv6' ? 6 : 4)
        }) as net.LookupFunction,
        timeout: request.timeoutMs,
        setHost: false,
      },
      (res) => {
        const headers: Array<[string, string]> = []
        for (const [name, value] of Object.entries(res.headers)) {
          if (Array.isArray(value)) {
            for (const item of value) headers.push([name, item])
          } else if (typeof value === 'string') {
            headers.push([name, value])
          } else if (typeof value === 'number') {
            headers.push([name, String(value)])
          }
        }

        const contentType = (res.headers['content-type'] ?? '').toString().toLowerCase()
        captureBody = contentType.includes('text/html') || contentType.includes('application/xhtml')

        const socket = res.socket
        const tlsInfo = request.secure && socket && 'getPeerCertificate' in socket ? originTlsOf(socket as tls.TLSSocket) : null

        res.on('data', (chunk: Buffer) => {
          received += chunk.byteLength
          if (!captureBody) {
            res.destroy()
            return
          }
          const room = request.maxBytes - buffered
          if (room <= 0) {
            truncated = true
            res.destroy()
            return
          }
          if (chunk.byteLength > room) {
            chunks.push(chunk.subarray(0, room))
            buffered += room
            truncated = true
            res.destroy()
            return
          }
          chunks.push(chunk)
          buffered += chunk.byteLength
        })

        res.on('error', () => {
          if (timedOut) {
            finish({ ok: false, kind: 'timeout', detail: 'Respons melebihi batas waktu.', elapsedMs: Date.now() - startedAt })
            return
          }
          finishWithBody()
        })
        res.on('close', () => finishWithBody())
        res.on('end', () => finishWithBody())

        function finishWithBody() {
          const body = captureBody ? new TextDecoder('utf-8', { fatal: false }).decode(Buffer.concat(chunks)) : ''
          finish({
            ok: true,
            status: res.statusCode ?? 0,
            statusText: res.statusMessage ?? null,
            headers,
            body,
            bytes: received,
            truncated,
            elapsedMs: Date.now() - startedAt,
            tls: tlsInfo,
          })
        }
      },
    )

    const timer = setTimeout(() => {
      timedOut = true
      req.destroy()
      finish({
        ok: false,
        kind: 'timeout',
        detail: 'Permintaan ke origin tidak selesai dalam batas waktu.',
        elapsedMs: Date.now() - startedAt,
      })
    }, request.timeoutMs)

    const onAbort = () => {
      req.destroy()
      finish({
        ok: false,
        kind: 'error',
        detail: 'Permintaan dibatalkan sebelum origin menjawab.',
        elapsedMs: Date.now() - startedAt,
      })
    }
    signal?.addEventListener('abort', onAbort, { once: true })

    req.on('error', (error: unknown) => {
      if (timedOut || settled) return
      const code = errorCodeOf(error)
      finish({
        ok: false,
        kind: code === 'ETIMEDOUT' ? 'timeout' : 'error',
        detail:
          code === 'ECONNREFUSED'
            ? 'Koneksi ke origin ditolak.'
            : code === 'ECONNRESET'
              ? 'Koneksi ke origin terputus.'
              : code === 'ETIMEDOUT'
                ? 'Koneksi ke origin melebihi batas waktu.'
                : code === 'ERR_TLS_HANDSHAKE_TIMEOUT' || code === 'EPROTO'
                  ? 'Negosiasi TLS gagal.'
                  : `Koneksi ke origin gagal (kode ${code}).`,
        elapsedMs: Date.now() - startedAt,
      })
    })

    req.end()
  })
}

export function createNodeSiteProbe(options: { dnsTimeoutMs?: number; tlsTimeoutMs?: number; rdapTimeoutMs?: number } = {}): SiteProbe {
  const dnsTimeoutMs = options.dnsTimeoutMs ?? 6_000
  const tlsTimeoutMs = options.tlsTimeoutMs ?? 8_000
  const rdapTimeoutMs = options.rdapTimeoutMs ?? 6_000

  return {
    name: 'node-dns-tls-http',
    dnsSource: 'resolver DNS sistem (node:dns)',
    resolve: (hostname) => withDnsTimeout(resolveAddresses(hostname), dnsTimeoutMs),
    queryRecords: (hostname, type) => withDnsTimeout(recordsForType(hostname, type), dnsTimeoutMs),
    lookupAsn: (address) => withDnsTimeout(lookupAsnViaDns(address), dnsTimeoutMs),
    // RDAP hanya bertanya ke registry domain (HTTPS, tanpa redirect, ukuran dibatasi)
    // dan tidak pernah mengirim data target selain nama domain yang akan ditanyakan.
    lookupRegistration: (domain, signal) =>
      queryRdapRegistration({
        domain,
        fetchImpl: globalThis.fetch,
        now: Date.now,
        timeoutMs: rdapTimeoutMs,
        signal,
      }),
    inspectTls: (hostname, address, kind, port, signal) =>
      inspectTlsOnPort(hostname, address, kind, port, tlsTimeoutMs, signal),
    openOrigin: (request, signal) => openOriginRequest(request, signal),
  }
}

function withDnsTimeout<T>(task: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolveTask, rejectTask) => {
    const timer = setTimeout(() => {
      // Kode ETIMEDOUT membuat lapisan layanan bisa membedakan waktu habis dari
      // kegagalan kueri biasa tanpa membaca teks pesan.
      const error = new Error('Kueri DNS melebihi batas waktu.') as Error & { code?: string }
      error.code = 'ETIMEDOUT'
      rejectTask(error)
    }, timeoutMs)
    task.then(
      (value) => {
        clearTimeout(timer)
        resolveTask(value)
      },
      (error: unknown) => {
        clearTimeout(timer)
        rejectTask(error instanceof Error ? error : new Error(String(error)))
      },
    )
  })
}

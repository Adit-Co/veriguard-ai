import { detectSensitiveUrl } from '../scanners/privacy.js'
import { normalizeScanUrl, ScanUrlError } from '../scanners/url.js'
import { assessIntermediary } from './classify.js'
import { classifyWebsiteCategory } from './category.js'
import {
  analyzeForms,
  buildBehaviorObservations,
  classifyHosts,
  collectSetCookies,
  extractResources,
  observeSecurityHeaders,
  readCookieMetadata,
  summarizeResources,
} from './behavior.js'
import { analyzeUrlStructure, registrableDomain } from './urlSignals.js'
import { analyzeDomainAge, unavailableRegistration } from './registration.js'
import { analyzePageContent } from './pageSignals.js'
import { fuseEvidence, registrableOf, staticOnlyFusion } from './risk.js'
import { detectTechnologies } from './technology.js'
import {
  filterPublicAddresses,
  isAllowedInitialPort,
  isAllowedWebPort,
  isBlockedHostname,
  isBlockedMetadataAddress,
  isMetadataServiceHostname,
  isSafeResponseHeader,
  sanitizeHeaderValue,
} from './guards.js'
import type {
  AsnInfo,
  BehaviorAnalysis,
  BehaviorObservation,
  DnsRecordSet,
  DomainAgeAnalysis,
  HttpResponseInfo,
  IntermediaryAssessment,
  IpAddressEntry,
  Lookup,
  LookupStatus,
  OriginResult,
  PageAnalysis,
  RedirectHop,
  RegistrationQueryResult,
  SectionStatus,
  SiteAnalysisResponse,
  SiteProbe,
  TlsCertificate,
  TlsInfo,
  WebsiteIntelligence,
  WebsiteRecordType,
} from './types.js'
import { WEBSITE_RECORD_TYPES } from './types.js'

const MAX_BYTES = 512 * 1024
const HTML_SCAN_CAP = 256 * 1024
const ORIGIN_TIMEOUT_MS = 10_000
const DNS_TIMEOUT_MS = 6_000
const TLS_TIMEOUT_MS = 8_000
const ASN_TIMEOUT_MS = 6_000
const REGISTRATION_TIMEOUT_MS = 6_000
const TOTAL_DEADLINE_MS = 25_000
const MAX_REDIRECTS = 4
const MAX_RECORDS_PER_TYPE = 8
const MAX_RESPONSE_HEADERS = 12
const DNS_CONCURRENCY = 4
const USER_AGENT = 'VERIGUARD-AI/4.0 (+analisis teknis defensif)'

const SENSITIVE_RECORD_PATTERN =
  /(-----BEGIN|private[ -]key|secret\s*=|password\s*=|api[_-]?key\s*=|token\s*=)/i

class DeadlineError extends Error {
  constructor() {
    super('deadline')
    this.name = 'DeadlineError'
  }
}

export type RunSiteAnalysisInput = {
  url: string
  uid: string
  probe?: SiteProbe | null
  now?: () => number
  signal?: AbortSignal
}

function queriedAt(now: () => number): string {
  return new Date(now()).toISOString()
}

function lookup<T>(
  status: LookupStatus,
  source: string,
  value: T | null,
  detail: string | null,
  at: string,
): Lookup<T> {
  return { status, source, value, detail, queriedAt: at }
}

async function withDeadline<T>(
  task: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
  parent?: AbortSignal,
): Promise<T> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(new DeadlineError()), timeoutMs)
  const onParentAbort = () => controller.abort(parent?.reason)
  if (parent) {
    if (parent.aborted) controller.abort(parent.reason)
    else parent.addEventListener('abort', onParentAbort, { once: true })
  }

  try {
    return await task(controller.signal)
  } finally {
    clearTimeout(timer)
    parent?.removeEventListener('abort', onParentAbort)
  }
}

function classifyProbeError(error: unknown): { status: LookupStatus; detail: string } {
  if (error instanceof DeadlineError) {
    return { status: 'timeout', detail: 'Kueri melebihi batas waktu.' }
  }
  if (error instanceof Error && error.name === 'AbortError') {
    return { status: 'timeout', detail: 'Kueri dibatalkan karena batas waktu analisis.' }
  }
  // Probe platform boleh menandai waktu habis lewat kode error agar tidak berubah
  // menjadi 'failed' generik; pesan mentah probe tidak pernah ditampilkan apa adanya.
  const code = error instanceof Error ? (error as Error & { code?: unknown }).code : undefined
  if (code === 'ETIMEDOUT') {
    return { status: 'timeout', detail: 'Kueri melebihi batas waktu.' }
  }
  const name = error instanceof Error ? error.name : typeof error
  return { status: 'failed', detail: `Kueri gagal (${name}).` }
}

async function mapLimited<T, R>(
  items: readonly T[],
  limit: number,
  task: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length)
  let cursor = 0
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (cursor < items.length) {
      const index = cursor
      cursor += 1
      results[index] = await task(items[index] as T)
    }
  })
  await Promise.all(workers)
  return results
}

function sanitizeRecords(type: WebsiteRecordType, records: string[]): { values: string[]; withheld: number } {
  const allowed = records.filter((record) => !SENSITIVE_RECORD_PATTERN.test(record))
  const withheld = records.length - allowed.length
  const trimmed = allowed.slice(0, MAX_RECORDS_PER_TYPE).map((record) =>
    record.length > 200 ? `${record.slice(0, 199)}…` : record,
  )
  return { values: trimmed, withheld: withheld + Math.max(0, allowed.length - MAX_RECORDS_PER_TYPE) }
}

function safeHeaders(headers: Array<[string, string]>): {
  entries: Array<{ name: string; value: string }>
  withheld: number
} {
  const entries: Array<{ name: string; value: string }> = []
  let withheld = 0

  for (const [name, value] of headers) {
    const lower = name.toLowerCase()
    if (!isSafeResponseHeader(lower)) {
      withheld += 1
      continue
    }
    if (entries.length >= MAX_RESPONSE_HEADERS) {
      withheld += 1
      continue
    }
    entries.push({ name: lower, value: sanitizeHeaderValue(value) })
  }

  return { entries, withheld }
}

function headerValue(headers: Array<[string, string]>, name: string): string | null {
  const lower = name.toLowerCase()
  const found = headers.find(([key]) => key.toLowerCase() === lower)
  return found ? found[1] : null
}

export async function runSiteAnalysis(
  input: RunSiteAnalysisInput,
): Promise<SiteAnalysisResponse> {
  const now = input.now ?? Date.now
  const startedAt = now()
  const probe = input.probe ?? null
  const generatedAt = new Date(startedAt).toISOString()

  const unavailableResponse = (reason: string): SiteAnalysisResponse =>
    buildResponse({
      now,
      startedAt,
      generatedAt,
      target: input.url,
      hostname: hostnameOr(input.url),
      probe,
      reason,
    })

  // VGL-41B — nama host layanan metadata dinilai SEBELUM validasi terpusat: penormalan bersama
  // menolak nama itu dengan galat (perilaku pemindaian), sedangkan kontrak analisis situs adalah
  // laporan "tidak tersedia" tanpa satu permintaan pun. Keduanya tetap tidak pernah menghubungi
  // target.
  if (isMetadataServiceHostname(hostnameOr(input.url))) {
    return unavailableResponse('Nama host target termasuk alamat internal atau metadata.')
  }

  let normalized: string
  try {
    normalized = normalizeScanUrl(input.url)
  } catch (error) {
    throw new ScanUrlError(
      error instanceof ScanUrlError ? error.message : 'URL tidak valid untuk analisis situs.',
    )
  }

  const hostname = new URL(normalized).hostname.toLowerCase()
  const privacy = detectSensitiveUrl(normalized)

  if (privacy.sensitive) {
    return unavailableResponse(
      'URL tidak dibuka karena memuat parameter yang tampak seperti token atau data pribadi.',
    )
  }

  if (isBlockedHostname(hostname) || isBlockedMetadataAddress(hostname)) {
    return unavailableResponse('Nama host target termasuk alamat internal atau metadata.')
  }

  if (!probe) {
    return unavailableResponse(
      'Platform tempat layanan ini berjalan tidak menyediakan akses DNS, TLS, dan socket langsung, jadi analisis situs tidak dapat dijalankan.',
    )
  }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(new DeadlineError()), TOTAL_DEADLINE_MS)
  const forwardAbort = () => controller.abort(input.signal?.reason)
  if (input.signal) {
    if (input.signal.aborted) controller.abort(input.signal.reason)
    else input.signal.addEventListener('abort', forwardAbort, { once: true })
  }
  const signal = controller.signal

  try {
    // 1. Resolusi + validasi alamat (dipakai untuk pinning IP, bukan hanya cek nama host).
    const resolveOutcome = await withDeadline(
      (inner) => probe.resolve(hostname, inner),
      DNS_TIMEOUT_MS,
      signal,
    ).then(
      (value) => ({ ok: true as const, value }),
      (error: unknown) => ({ ok: false as const, ...classifyProbeError(error) }),
    )

    const v4 = resolveOutcome.ok ? filterPublicAddresses(resolveOutcome.value.ipv4, 'ipv4') : null
    const v6 = resolveOutcome.ok ? filterPublicAddresses(resolveOutcome.value.ipv6, 'ipv6') : null
    const publicAddresses: IpAddressEntry[] = [
      ...(v4?.allowed ?? []).map((address): IpAddressEntry => ({ address, kind: 'ipv4' })),
      ...(v6?.allowed ?? []).map((address): IpAddressEntry => ({ address, kind: 'ipv6' })),
    ]
    const withheldAddresses = (v4?.blocked ?? 0) + (v6?.blocked ?? 0)

    const addressLookup: Lookup<IpAddressEntry[]> = !resolveOutcome.ok
      ? lookup<IpAddressEntry[]>(
          resolveOutcome.status,
          probe.dnsSource,
          null,
          resolveOutcome.detail,
          queriedAt(now),
        )
      : publicAddresses.length > 0
        ? lookup('success', probe.dnsSource, publicAddresses, null, queriedAt(now))
        : lookup(
            'blocked',
            probe.dnsSource,
            [],
            'Semua alamat hasil resolusi berada di rentang yang dilarang, jadi halaman tidak dibuka.',
            queriedAt(now),
          )

    // 2. Rekor DNS untuk ditampilkan.
    const recordLookups = await mapLimited(WEBSITE_RECORD_TYPES, DNS_CONCURRENCY, async (type) => {
      const outcome = await withDeadline(
        (inner) => probe.queryRecords(hostname, type, inner),
        DNS_TIMEOUT_MS,
        signal,
      ).then(
        (value) => ({ ok: true as const, value }),
        (error: unknown) => ({ ok: false as const, ...classifyProbeError(error) }),
      )

      if (!outcome.ok) {
        return lookup<string[]>(
          outcome.status,
          probe.dnsSource,
          null,
          outcome.detail,
          queriedAt(now),
        )
      }

      if (outcome.value.outcome === 'timeout') {
        return lookup<string[]>(
          'timeout',
          probe.dnsSource,
          null,
          outcome.value.detail ?? 'Kueri DNS melebihi batas waktu.',
          queriedAt(now),
        )
      }

      if (outcome.value.outcome === 'failed') {
        return lookup<string[]>(
          'failed',
          probe.dnsSource,
          null,
          outcome.value.detail ?? 'Kueri DNS tidak dapat diselesaikan.',
          queriedAt(now),
        )
      }

      if (outcome.value.outcome === 'empty' || outcome.value.records.length === 0) {
        return lookup<string[]>(
          'empty',
          probe.dnsSource,
          [],
          outcome.value.detail ?? 'Kueri selesai tanpa record untuk tipe ini.',
          queriedAt(now),
        )
      }

      const sanitized = sanitizeRecords(type, outcome.value.records)
      return lookup<string[]>(
        'success',
        probe.dnsSource,
        sanitized.values,
        sanitized.withheld > 0
          ? `${sanitized.withheld} record tidak ditampilkan (terlalu panjang atau dicurigai memuat data rahasia).`
          : null,
        queriedAt(now),
      )
    })

    const dns: DnsRecordSet[] = WEBSITE_RECORD_TYPES.map((type, index) => ({
      type,
      lookup: recordLookups[index] as Lookup<string[]>,
    }))

    const chosen = publicAddresses[0] ?? null

    // 3. ASN untuk alamat yang dipilih.
    const asnLookup: Lookup<AsnInfo> = !chosen
      ? lookup<AsnInfo>('blocked', 'kueri DNS asal ASN', null, 'Tidak ada alamat publik yang dapat dinilai.', queriedAt(now))
      : await withDeadline((inner) => probe.lookupAsn(chosen.address, inner), ASN_TIMEOUT_MS, signal).then(
          (value) => {
            if (value.outcome === 'timeout') {
              return lookup<AsnInfo>('timeout', 'kueri DNS asal ASN', null, value.detail ?? 'Kueri ASN melebihi batas waktu.', queriedAt(now))
            }
            if (value.outcome === 'failed') {
              return lookup<AsnInfo>('failed', 'kueri DNS asal ASN', null, value.detail ?? 'Kueri ASN tidak dapat diselesaikan.', queriedAt(now))
            }
            if (!value.info) {
              return lookup<AsnInfo>('empty', 'kueri DNS asal ASN', null, value.detail ?? 'Tidak ada data ASN untuk alamat ini.', queriedAt(now))
            }
            return lookup<AsnInfo>('success', 'kueri DNS asal ASN', value.info, value.detail, queriedAt(now))
          },
          (error: unknown) => {
            const classified = classifyProbeError(error)
            return lookup<AsnInfo>(classified.status, 'kueri DNS asal ASN', null, classified.detail, queriedAt(now))
          },
        )

    // 4. Umur registrasi dan rantai origin berjalan bersamaan. Keduanya tidak
    //    saling menunggu, dan kegagalan RDAP tidak menghentikan pemeriksaan halaman.
    const registrationTask = collectRegistration({ probe, hostname, now, signal })

    // 5. Permintaan ke origin dengan redirect yang divalidasi ulang tiap hop.
    const chain = await followOriginChain({
      probe,
      startUrl: normalized,
      hostname,
      chosen,
      now,
      signal,
    })

    const registration = await registrationTask

    const tls = await collectTls({
      probe,
      chain,
      hostname,
      chosen,
      now,
      signal,
    })

    const response = describeResponse(chain, now)
    const intermediary = assessIntermediary(dns, response, asnLookup.value)

    const htmlIsUsable =
      chain.final !== null &&
      chain.final.ok === true &&
      chain.final.result.ok === true &&
      isHtmlContentType(headerValue(chain.final.result.headers, 'content-type') ?? '')

    const rawBody = htmlIsUsable && chain.final?.ok ? (chain.final as OkHop).result.body : null
    const bytesScanned = rawBody === null ? 0 : Math.min(rawBody.length, HTML_SCAN_CAP)
    const html = rawBody === null ? null : rawBody.slice(0, HTML_SCAN_CAP)
    const truncated = chain.final?.ok === true && (chain.final as OkHop).result.truncated

    const landingUrl = chain.finalUrl ?? normalized
    let landingHost = hostname
    let pageSecure = true
    try {
      const parsed = new URL(landingUrl)
      landingHost = parsed.hostname.toLowerCase()
      pageSecure = parsed.protocol === 'https:'
    } catch {
      landingHost = hostname
      pageSecure = true
    }

    const technology = detectTechnologies({
      headers: chain.final?.ok ? (chain.final as OkHop).result.headers : [],
      html,
      contentType: response.contentType,
      inspected: htmlIsUsable,
      truncated: truncated === true,
      bytesScanned,
      detail: htmlIsUsable
        ? 'Dokumen HTML diperiksa.'
        : chain.attempts === 0
          ? 'Halaman belum dibuka, jadi teknologi tidak dapat dinilai.'
          : 'Dokumen HTML tidak tersedia atau bukan bertipe HTML, jadi teknologi tidak dapat dinilai.',
    })

    const behavior = buildBehavior({
      chain,
      probe,
      html,
      finalUrl: chain.finalUrl,
      hostname,
      pageHost: landingHost,
      response,
      tls,
      now,
      truncated: truncated === true,
    })

    const website = buildWebsite({
      hostname,
      addressLookup,
      withheldAddresses,
      dns,
      asnLookup,
      intermediary,
      tls,
      response,
      chain,
      probe,
    })

    const page = analyzePageContent({
      html,
      baseUrl: html === null ? null : landingUrl,
      pageHost: landingHost,
      pageSecure,
      registrableDomain: registrableOf(landingHost),
      forms: behavior.forms,
      bytesScanned,
      truncated: truncated === true,
      detail: htmlIsUsable
        ? undefined
        : 'Dokumen HTML tidak tersedia, jadi isi halaman (tautan, form, identitas merek, skrip) tidak dapat diperiksa.',
    })

    if (registration.status !== 'unavailable') {
      const landingRegistrable = registrableOf(landingHost)
      if (landingRegistrable && landingRegistrable !== registration.registrableDomain) {
        registration.notes.push(
          `Rantai redirect berakhir di domain lain (${landingRegistrable}); umur registrasi hanya ditanyakan untuk ${registration.registrableDomain ?? 'domain awal'}.`,
        )
      }
    }

    const category = classifyWebsiteCategory({ hostname, html, response })

    const risk = fuseEvidence({
      generatedAt,
      structure: behavior.structure,
      registration,
      website,
      behavior,
      page,
      category,
    })

    return {
      version: 1,
      target: normalized,
      hostname,
      generatedAt,
      durationMs: Math.max(0, now() - startedAt),
      probe: {
        available: true,
        name: probe.name,
        detail: chain.errorReason ?? null,
      },
      website,
      technology,
      behavior,
      registration,
      page,
      risk,
      category,
    }
  } finally {
    clearTimeout(timer)
    input.signal?.removeEventListener('abort', forwardAbort)
  }
}

async function collectRegistration(args: {
  probe: SiteProbe
  hostname: string
  now: () => number
  signal: AbortSignal
}): Promise<DomainAgeAnalysis> {
  const at = queriedAt(args.now)
  const domain = registrableOf(args.hostname)
  if (!domain) {
    return unavailableRegistration(
      at,
      'Target berupa alamat IP atau host tanpa domain yang terbaca, jadi umur registrasi tidak berlaku.',
    )
  }
  if (!args.probe.lookupRegistration) {
    return unavailableRegistration(
      at,
      'Runtime ini tidak menyediakan akses registry RDAP, jadi umur registrasi domain tidak diperiksa.',
    )
  }

  const lookupRegistration = args.probe.lookupRegistration
  const result = await withDeadline(
    (inner) => lookupRegistration(domain, inner),
    REGISTRATION_TIMEOUT_MS,
    args.signal,
  ).then(
    (value) => value,
    (error: unknown): RegistrationQueryResult => {
      const classified = classifyProbeError(error)
      return {
        registration: null,
        outcome: classified.status === 'timeout' ? 'timeout' : 'failed',
        source: null,
        detail: classified.detail,
      }
    },
  )

  return analyzeDomainAge({ registrableDomain: domain, result, now: args.now })
}

type OkHop = {
  ok: true
  url: string
  address: string
  kind: 'ipv4' | 'ipv6'
  result: Extract<OriginResult, { ok: true }>
}

type ChainState = {
  hops: RedirectHop[]
  final: OkHop | null
  finalUrl: string | null
  attempts: number
  errorReason: string | null
  observedHosts: string[]
  outcome: BehaviorAnalysis['redirectOutcome']
}

async function followOriginChain(args: {
  probe: SiteProbe
  startUrl: string
  hostname: string
  chosen: IpAddressEntry | null
  now: () => number
  signal: AbortSignal
}): Promise<ChainState> {
  const { probe, chosen } = args
  const hops: RedirectHop[] = []
  const observedHosts: string[] = []
  let currentUrl = args.startUrl
  let final: OkHop | null = null
  let attempts = 0
  let errorReason: string | null = null
  let outcome: ChainState['outcome'] = 'error'

  if (!chosen) {
    return {
      hops: [
        {
          url: safeUrlText(args.startUrl),
          status: null,
          location: null,
          outcome: 'blocked',
          detail: 'Tidak ada alamat publik yang lolos kebijakan SSRF, jadi halaman tidak dibuka.',
        },
      ],
      final: null,
      finalUrl: null,
      attempts: 0,
      errorReason: 'Halaman tidak dibuka karena tidak ada alamat publik yang diizinkan.',
      observedHosts: [],
      outcome: 'blocked',
    }
  }

  const visited = new Set<string>()

  for (let step = 0; step <= MAX_REDIRECTS; step += 1) {
    let target: URL
    try {
      target = new URL(normalizeScanUrl(currentUrl))
    } catch {
      errorReason = 'Redirect menuju URL yang tidak lolos validasi, jadi dihentikan.'
      hops.push({
        url: safeUrlText(currentUrl),
        status: null,
        location: null,
        outcome: 'blocked',
        detail: 'Tujuan berikutnya ditolak oleh kebijakan keamanan.',
      })
      outcome = 'blocked'
      break
    }

    const host = target.hostname.toLowerCase()
    if (isBlockedHostname(host) || isBlockedMetadataAddress(host)) {
      errorReason = 'Redirect menuju nama host internal atau metadata, jadi dihentikan.'
      hops.push({
        url: safeUrlText(target.href),
        status: null,
        location: null,
        outcome: 'blocked',
        detail: 'Tujuan redirect termasuk nama host internal/metadata dan tidak diikuti.',
      })
      outcome = 'blocked'
      break
    }

    // Hop pertama memakai daftar port awal (80/443 dan port web alternatif 8080/8443):
    // situs yang memang tinggal di port itu tetap bisa diperiksa, tetapi pemeriksaan tidak
    // lagi bisa disuruh menyentuh port layanan. Redirect hanya boleh ke 80/443 — yang
    // berbahaya adalah halaman pihak ketiga memindahkan pemeriksaan ke port layanan lain.
    const portAllowed =
      step === 0 ? isAllowedInitialPort(target.port) : isAllowedWebPort(target.port)
    if (!portAllowed) {
      errorReason =
        step === 0
          ? `Port ${target.port} di luar port web 80/443/8080/8443, jadi tidak dihubungi.`
          : `Redirect menuju port ${target.port}, di luar port web 80/443, jadi tidak diikuti.`
      hops.push({
        url: safeUrlText(target.href),
        status: null,
        location: null,
        outcome: 'blocked',
        detail:
          step === 0
            ? 'Hanya port web 80/443/8080/8443 yang dihubungi untuk URL yang ditulis; port lain dicatat sebagai sinyal.'
            : 'Hanya port web 80/443 yang diikuti untuk redirect; port lain dicatat sebagai sinyal, bukan dihubungi.',
      })
      outcome = 'blocked'
      break
    }

    // Re-resolusi dan validasi alamat tiap hop: hasil redirect tidak dipercaya buta.
    let address = chosen.address
    let kind = chosen.kind
    if (host !== args.hostname) {
      const resolved = await withDeadline((inner) => probe.resolve(host, inner), DNS_TIMEOUT_MS, args.signal).then(
        (value) => ({ ok: true as const, value }),
        (error: unknown) => ({ ok: false as const, ...classifyProbeError(error) }),
      )

      if (!resolved.ok) {
        errorReason = `Resolusi nama host ${host} gagal.`
        outcome = 'error'
        break
      }

      const allowedV4 = filterPublicAddresses(resolved.value.ipv4, 'ipv4')
      const allowedV6 = filterPublicAddresses(resolved.value.ipv6, 'ipv6')
      const next = allowedV4.allowed[0] ?? allowedV6.allowed[0] ?? null
      if (!next) {
        errorReason = `Redirect ke ${host} dihentikan: tidak ada alamat publik yang diizinkan.`
        hops.push({
          url: safeUrlText(target.href),
          status: null,
          location: null,
          outcome: 'blocked',
          detail: 'Alamat hasil resolusi redirect berada di rentang yang dilarang.',
        })
        outcome = 'blocked'
        break
      }
      address = next
      kind = allowedV4.allowed.includes(next) ? 'ipv4' : 'ipv6'
    }

    if (visited.has(target.href)) {
      hops.push({
        url: safeUrlText(target.href),
        status: null,
        location: null,
        outcome: 'loop',
        detail: 'URL ini sudah dikunjungi pada rantai sebelumnya, jadi loop dihentikan.',
      })
      outcome = 'loop'
      errorReason = 'Rantai redirect membentuk loop dan dihentikan.'
      break
    }
    visited.add(target.href)

    const secure = target.protocol === 'https:'
    const port = target.port ? Number(target.port) : secure ? 443 : 80
    attempts += 1
    observedHosts.push(host)

    const result = await withDeadline(
      (inner) =>
        probe.openOrigin(
          {
            url: target.href,
            address,
            kind,
            hostname: host,
            port,
            secure,
            maxBytes: MAX_BYTES,
            timeoutMs: ORIGIN_TIMEOUT_MS,
            userAgent: USER_AGENT,
          },
          inner,
        ),
      ORIGIN_TIMEOUT_MS + 2_000,
      args.signal,
    ).then(
      (value) => value,
      (error: unknown): OriginResult => {
        const classified = classifyProbeError(error)
        return {
          ok: false,
          kind: classified.status === 'timeout' ? 'timeout' : 'error',
          detail: classified.detail,
          elapsedMs: 0,
        }
      },
    )

    if (!result.ok) {
      hops.push({
        url: safeUrlText(target.href),
        status: null,
        location: null,
        outcome: 'error',
        detail:
          result.kind === 'timeout'
            ? 'Permintaan ke origin melebihi batas waktu.'
            : `Permintaan ke origin gagal${result.detail ? ` (${result.detail})` : '.'}`,
      })
      errorReason =
        result.kind === 'timeout'
          ? 'Origin tidak menjawab dalam batas waktu.'
          : `Origin tidak dapat dihubungi${result.detail ? ` (${result.detail})` : '.'}`
      outcome = 'error'
      break
    }

    const locationValue = headerValue(result.headers, 'location')
    const isRedirect = result.status >= 300 && result.status < 400 && Boolean(locationValue)

    if (!isRedirect) {
      hops.push({
        url: safeUrlText(target.href),
        status: result.status,
        location: null,
        outcome: 'final',
        detail: null,
      })
      final = { ok: true, url: target.href, address, kind, result }
      outcome = 'final'
      break
    }

    hops.push({
      url: safeUrlText(target.href),
      status: result.status,
      location: sanitizeHeaderValue(locationValue ?? '', 200),
      outcome: step === MAX_REDIRECTS ? 'limit' : 'followed',
      detail: step === MAX_REDIRECTS ? 'Batas jumlah redirect tercapai.' : null,
    })

    if (step === MAX_REDIRECTS) {
      errorReason = `Batas ${MAX_REDIRECTS} redirect tercapai; tujuan terakhir tidak diambil.`
      outcome = 'limit'
      break
    }

    try {
      currentUrl = normalizeScanUrl(new URL(locationValue ?? '', target.href).href)
    } catch {
      errorReason = 'Lokasi redirect tidak dapat dibaca sebagai URL.'
      hops.push({
        url: safeUrlText(target.href),
        status: result.status,
        location: null,
        outcome: 'blocked',
        detail: 'Header Location tidak menghasilkan URL yang valid.',
      })
      outcome = 'blocked'
      break
    }
  }

  return {
    hops,
    final,
    finalUrl: final?.url ?? null,
    attempts,
    errorReason,
    observedHosts: [...new Set(observedHosts)],
    outcome,
  }
}

function safeUrlText(url: string): string {
  return url.length > 200 ? `${url.slice(0, 199)}…` : url
}

function isHtmlContentType(contentType: string): boolean {
  const lower = contentType.toLowerCase()
  return lower.includes('text/html') || lower.includes('application/xhtml+xml')
}

async function collectTls(args: {
  probe: SiteProbe
  chain: ChainState
  hostname: string
  chosen: IpAddressEntry | null
  now: () => number
  signal: AbortSignal
}): Promise<TlsInfo> {
  const { probe, chain, chosen } = args
  const at = queriedAt(args.now)
  const okHop = chain.final
  const liveTls = okHop?.result.tls ?? null

  const certificateSource = liveTls ? 'sambungan TLS pada permintaan origin' : null

  if (liveTls) {
    const notAfter = liveTls.notAfter ? Date.parse(liveTls.notAfter) : Number.NaN
    return {
      httpsAvailable: lookup<boolean>('success', 'permintaan origin HTTPS', true, null, at),
      certificate: lookup<TlsCertificate>(
        'success',
        'sambungan TLS pada permintaan origin',
        {
          issuer: liveTls.issuer,
          subject: liveTls.subject,
          notBefore: liveTls.notBefore,
          notAfter: liveTls.notAfter,
          expired: Number.isNaN(notAfter) ? null : notAfter < args.now(),
          hostnameVerified: liveTls.authorized,
          verification:
            liveTls.authorized === true
              ? 'verified'
              : liveTls.authorized === false
                ? 'rejected'
                : 'not_checked',
          verificationDetail: liveTls.authorizationError,
          protocol: liveTls.protocol,
        },
        null,
        at,
      ),
      certificateSource,
    }
  }

  if (!chosen) {
    return {
      httpsAvailable: lookup<boolean>('blocked', 'percobaan koneksi TLS port 443', null, 'Tidak ada alamat publik yang diizinkan.', at),
      certificate: lookup<TlsCertificate>('blocked', 'percobaan koneksi TLS port 443', null, 'Tidak ada alamat publik yang diizinkan.', at),
      certificateSource: null,
    }
  }

  const originNotHttps = chain.finalUrl === null || !chain.finalUrl.startsWith('https://')

  const outcome = await withDeadline(
    (inner) => probe.inspectTls(args.hostname, chosen.address, chosen.kind, 443, inner),
    TLS_TIMEOUT_MS,
    args.signal,
  ).then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, ...classifyProbeError(error) }),
  )

  if (!outcome.ok) {
    return {
      httpsAvailable: lookup<boolean>(outcome.status, 'percobaan koneksi TLS port 443', null, outcome.detail, at),
      certificate: lookup<TlsCertificate>(outcome.status, 'percobaan koneksi TLS port 443', null, outcome.detail, at),
      certificateSource: null,
    }
  }

  if (outcome.value.outcome === 'timeout' || outcome.value.outcome === 'failed') {
    const status: LookupStatus = outcome.value.outcome === 'timeout' ? 'timeout' : 'failed'
    return {
      httpsAvailable: lookup<boolean>(status, 'percobaan koneksi TLS port 443', null, outcome.value.detail, at),
      certificate: lookup<TlsCertificate>(status, 'percobaan koneksi TLS port 443', null, outcome.value.detail, at),
      certificateSource: null,
    }
  }

  const certificate = outcome.value.certificate
  if (!certificate) {
    return {
      httpsAvailable: lookup<boolean>(
        outcome.value.httpsReachable ? 'empty' : 'failed',
        'percobaan koneksi TLS port 443',
        outcome.value.httpsReachable,
        outcome.value.detail ?? 'Sertifikat tidak tersedia dari percobaan koneksi.',
        at,
      ),
      certificate: lookup<TlsCertificate>(
        'empty',
        'percobaan koneksi TLS port 443',
        null,
        outcome.value.detail ?? 'Port 443 terhubung tetapi tidak menghasilkan sertifikat yang terbaca.',
        at,
      ),
      certificateSource: null,
    }
  }

  const notAfter = certificate.notAfter ? Date.parse(certificate.notAfter) : Number.NaN
  return {
    httpsAvailable: lookup<boolean>(
      'success',
      'percobaan koneksi TLS port 443',
      outcome.value.httpsReachable,
      originNotHttps
        ? 'Pemeriksaan TLS dilakukan terpisah karena respons origin tidak memakai TLS.'
        : null,
      at,
    ),
    certificate: lookup<TlsCertificate>(
      'success',
      'percobaan koneksi TLS port 443',
      { ...certificate, expired: Number.isNaN(notAfter) ? null : notAfter < args.now() },
      null,
      at,
    ),
    certificateSource: 'percobaan koneksi TLS port 443',
  }
}

function describeResponse(chain: ChainState, now: () => number): HttpResponseInfo {
  const final = chain.final

  if (!final) {
    return {
      request: lookup<null>(
        chain.outcome === 'blocked' ? 'blocked' : chain.outcome === 'limit' ? 'timeout' : 'failed',
        'permintaan origin',
        null,
        chain.errorReason ?? 'Permintaan origin tidak menghasilkan respons.',
        queriedAt(now),
      ),
      status: null,
      statusText: null,
      finalUrl: null,
      redirectCount: Math.max(0, chain.hops.filter((hop) => hop.outcome === 'followed').length),
      elapsedMs: null,
      contentType: null,
      bytes: null,
      truncated: false,
      headers: [],
      withheldHeaders: 0,
    }
  }

  const headers = safeHeaders(final.result.headers)
  const { entries } = headers

  return {
    request: lookup<null>('success', 'permintaan origin', null, null, queriedAt(now)),
    status: final.result.status,
    statusText: final.result.statusText,
    finalUrl: safeUrlText(final.url),
    redirectCount: chain.hops.filter((hop) => hop.outcome === 'followed').length,
    elapsedMs: final.result.elapsedMs,
    contentType: headerValue(final.result.headers, 'content-type'),
    bytes: final.result.bytes,
    truncated: final.result.truncated,
    headers: entries,
    withheldHeaders: headers.withheld,
  }
}

function buildWebsite(args: {
  hostname: string
  addressLookup: Lookup<IpAddressEntry[]>
  withheldAddresses: number
  dns: DnsRecordSet[]
  asnLookup: Lookup<AsnInfo>
  intermediary: IntermediaryAssessment
  tls: TlsInfo
  response: HttpResponseInfo
  chain: ChainState
  probe: SiteProbe
}): WebsiteIntelligence {
  const statuses: LookupStatus[] = [
    args.addressLookup.status,
    args.asnLookup.status,
    args.tls.httpsAvailable.status,
    args.tls.certificate.status,
    args.response.request.status,
    ...args.dns.map((entry) => entry.lookup.status),
  ]

  const failed = statuses.filter((status) => status === 'failed' || status === 'timeout').length
  const usable = statuses.filter((status) => status === 'success' || status === 'empty').length

  const notes: string[] = [
    'Data DNS, ASN, dan TLS diukur langsung saat pemeriksaan berlangsung, pada waktu pemeriksaan itu.',
    'Alamat hasil resolusi adalah alamat yang benar-benar dihubungi. Bila ada CDN atau proxy, alamat itu mungkin milik perantara, bukan server asal.',
    'HTTPS yang merespons bukan bukti situs tepercaya; masa berlaku dan pencocokan nama sertifikat adalah bukti yang lebih kuat.',
  ]

  if (args.withheldAddresses > 0) {
    notes.push(
      `${args.withheldAddresses} alamat hasil resolusi tidak ditampilkan dan tidak dipakai karena berada di rentang yang dilarang.`,
    )
  }

  if (args.chain.errorReason) {
    notes.push(`Permintaan origin: ${args.chain.errorReason}`)
  }

  const status: SectionStatus =
    usable === 0
      ? 'failed'
      : failed === 0
        ? 'complete'
        : usable > 0
          ? 'partial'
          : 'unavailable'

  return {
    status,
    identity: {
      hostname: args.hostname,
      addresses: args.addressLookup,
      withheldAddresses: args.withheldAddresses,
      asn: args.asnLookup,
      intermediary: args.intermediary,
    },
    dns: args.dns,
    tls: args.tls,
    response: args.response,
    notes,
  }
}

function buildBehavior(args: {
  chain: ChainState
  probe: SiteProbe
  html: string | null
  finalUrl: string | null
  hostname: string
  pageHost: string
  response: HttpResponseInfo
  tls: TlsInfo
  now: () => number
  truncated: boolean
}): BehaviorAnalysis {
  const final = args.chain.final
  const resources =
    args.html === null
      ? null
      : extractResources(args.html, args.finalUrl ?? args.chain.finalUrl ?? `https://${args.hostname}`)
  const summary = resources ? summarizeResources(resources.resources, resources.capped) : null

  const hosts = classifyHosts({
    observedHosts: args.chain.observedHosts,
    resources: resources?.resources ?? [],
    html: args.html,
    pageHost: args.pageHost,
  })

  const setCookies = final ? collectSetCookies(final.result.headers) : []
  const cookies = readCookieMetadata(setCookies)
  const securityHeaders = final ? observeSecurityHeaders(final.result.headers) : []

  const baseUrl = args.finalUrl ?? args.chain.finalUrl ?? `https://${args.hostname}`
  const structure = analyzeUrlStructure({
    initialUrl: args.chain.hops[0]?.url ?? baseUrl,
    finalUrl: args.finalUrl ?? args.chain.finalUrl,
    hostname: args.hostname,
    hops: args.chain.hops,
  })

  let pageSecure = true
  try {
    pageSecure = new URL(baseUrl).protocol === 'https:'
  } catch {
    pageSecure = true
  }

  const forms = analyzeForms({
    html: args.html === null ? null : args.html,
    baseUrl: args.html === null ? null : baseUrl,
    pageHost: args.pageHost,
    pageSecure,
  })

  const observations: BehaviorObservation[] = []

  for (const hop of args.chain.hops) {
    if (hop.outcome === 'followed' || hop.outcome === 'blocked' || hop.outcome === 'loop' || hop.outcome === 'limit') {
      observations.push({
        kind: 'redirect',
        state: 'observed',
        detail: hop.detail
          ? `Lompatan ke ${hop.url}: ${hop.detail}`
          : `Redirect ${hop.status ?? '?'} ke ${hop.location ?? 'tujuan tanpa header Location'}.`,
      })
    }
  }

  if (summary) {
    observations.push({
      kind: 'resource',
      state: 'observed',
      detail: `Dokumen HTML merujuk ${summary.scripts} skrip, ${summary.styles} stylesheet, ${summary.images} gambar, dan ${summary.iframes} iframe.`,
    })
  } else {
    observations.push({
      kind: 'resource',
      state: 'unavailable',
      detail: 'Daftar sumber daya tidak dapat disusun karena dokumen HTML tidak tersedia.',
    })
  }

  for (const header of securityHeaders) {
    if (header.present) {
      observations.push({
        kind: 'header',
        state: 'observed',
        detail: `Header \`${header.name}\` ada pada respons.`,
      })
    }
  }

  observations.push({
    kind: 'cookie',
    state: args.response.status === null ? 'unavailable' : cookies.cookies.length > 0 ? 'observed' : 'no_signal',
    detail:
      args.response.status === null
        ? 'Header respons tidak tersedia, jadi cookie tidak dapat diamati.'
        : cookies.cookies.length > 0
          ? `${cookies.cookies.length} Set-Cookie diamati; hanya nama dan atribut keamanannya yang ditampilkan, nilai cookie tidak pernah dibaca.`
          : 'Tidak ada header Set-Cookie pada respons yang diamati. Ini bukan bukti situs tidak memakai cookie sama sekali.',
  })

  observations.push({
    kind: 'tls',
    state:
      args.tls.certificate.status === 'success'
        ? 'observed'
        : args.tls.certificate.status === 'blocked' || args.tls.certificate.status === 'unavailable'
          ? 'unavailable'
          : 'no_signal',
    detail:
      args.tls.certificate.status === 'success'
        ? 'Sertifikat terbaca dari sambungan TLS yang benar-benar dipakai.'
        : 'Sertifikat tidak terbaca; kondisi TLS tidak dapat dipastikan.',
  })

  observations.push({
    kind: 'response',
    state: hosts.entries.length > 0 ? 'inferred' : 'no_signal',
    detail:
      hosts.entries.length > 0
        ? `Terdapat ${hosts.entries.length} host lain pada dokumen. Host dengan peran "disimpulkan" hanya muncul sebagai teks dan belum tentu pernah dihubungi.`
        : 'Tidak ada host lain yang muncul pada dokumen yang diperiksa.',
  })

  observations.push({
    kind: 'url',
    state: structure.findings.length > 0 ? 'observed' : 'no_signal',
    detail:
      structure.findings.length > 0
        ? `${structure.findings.length} sinyal struktur URL/domain teridentifikasi (${structure.findings
            .slice(0, 3)
            .map((finding) => finding.label.toLowerCase())
            .join(', ')}). Sinyal ini saling berkorelasi dan tidak dipakai sendiri untuk menyimpulkan apa pun.`
        : 'Tidak ada sinyal struktur yang menonjol pada URL dan rantai redirect yang diamati. Ketidakhadiran sinyal bukan bukti halaman aman.',
  })

  observations.push({
    kind: 'form',
    state: forms.inspected ? (forms.forms.length > 0 ? 'observed' : 'no_signal') : 'unavailable',
    detail: forms.detail,
  })

  const behaviorStatus: SectionStatus =
    args.chain.final === null
      ? args.chain.outcome === 'blocked'
        ? 'unavailable'
        : 'failed'
      : args.html === null
        ? 'partial'
        : args.truncated
          ? 'partial'
          : 'complete'

  const notes: string[] = [
    'Yang diamati hanya permintaan HTTP yang dilakukan backend sendiri. Skrip halaman tidak dijalankan, jadi perilaku runtime setelah pemuatan tidak dapat disimpulkan.',
    'Host dengan peran "referenced" atau "inferred" tidak berarti pernah benar-benar dihubungi oleh VERIGUARD.',
    'Nama dan atribut cookie ditampilkan; nilai cookie, token sesi, dan kredensial tidak pernah diambil atau ditampilkan.',
    'Sinyal struktur URL dan pemeriksaan form dibaca dari teks URL serta HTML statis; keduanya bukan bukti tunggal bahwa halaman berbahaya atau aman.',
  ]

  if (args.truncated) {
    notes.push('Dokumen HTML dipotong pada batas ukuran, jadi sebagian sumber daya dan rujukan tidak ikut dihitung.')
  }

  return {
    status: behaviorStatus,
    initialUrl: safeUrlText(args.chain.hops[0]?.url ?? `https://${args.hostname}`),
    redirects: args.chain.hops,
    redirectCount: args.chain.hops.filter((hop) => hop.outcome === 'followed').length,
    redirectOutcome: args.chain.outcome,
    hosts: hosts.entries,
    resources: summary,
    securityHeaders,
    cookies: cookies.cookies,
    cookiesCollected: args.chain.final !== null,
    structure,
    forms,
    observations: buildBehaviorObservations({
      redirectCount: args.chain.hops.filter((hop) => hop.outcome === 'followed').length,
      finalStatus: args.response.status,
      observations,
    }),
    notes,
  }
}

function hostnameOr(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase()
  } catch {
    return url.slice(0, 120)
  }
}

function buildResponse(args: {
  now: () => number
  startedAt: number
  generatedAt: string
  target: string
  hostname: string
  probe: SiteProbe | null
  reason: string
}): SiteAnalysisResponse {
  const at = args.generatedAt
  const source = 'analisis situs'
  const blockedStatus: LookupStatus = 'unavailable'
  const emptyLookups = {
    addresses: lookup<IpAddressEntry[]>(blockedStatus, source, null, args.reason, at),
    asn: lookup<AsnInfo>(blockedStatus, source, null, args.reason, at),
  }

  const dns: DnsRecordSet[] = WEBSITE_RECORD_TYPES.map((type) => ({
    type,
    lookup: lookup<string[]>(blockedStatus, source, null, args.reason, at),
  }))

  const response: HttpResponseInfo = {
    request: lookup<null>(blockedStatus, source, null, args.reason, at),
    status: null,
    statusText: null,
    finalUrl: null,
    redirectCount: 0,
    elapsedMs: null,
    contentType: null,
    bytes: null,
    truncated: false,
    headers: [],
    withheldHeaders: 0,
  }

  const tls: TlsInfo = {
    httpsAvailable: lookup<boolean>(blockedStatus, source, null, args.reason, at),
    certificate: lookup<TlsCertificate>(blockedStatus, source, null, args.reason, at),
    certificateSource: null,
  }

  const technology = detectTechnologies({
    headers: [],
    html: null,
    contentType: null,
    inspected: false,
    truncated: false,
    bytesScanned: 0,
    detail: args.reason,
  })

  // Struktur URL tetap dapat dinilai dari teksnya walaupun halaman tidak dibuka:
  // tidak ada permintaan tambahan yang dibuat di jalur ini.
  const structure = analyzeUrlStructure({
    initialUrl: safeUrlText(args.target),
    finalUrl: null,
    hostname: args.hostname,
    hops: [],
  })

  const unavailableBehavior: BehaviorAnalysis = {
    status: 'unavailable',
    initialUrl: safeUrlText(args.target),
    redirects: [],
    redirectCount: 0,
    redirectOutcome: 'unavailable',
    hosts: [],
    resources: null,
    securityHeaders: [],
    cookies: [],
    cookiesCollected: false,
    structure: {
      ...structure,
      notes: [...structure.notes, args.reason],
    },
    forms: {
      inspected: false,
      forms: [],
      totals: { forms: 0, passwordFields: 0, externalActions: 0, insecureActions: 0 },
      capped: false,
      detail: 'Halaman tidak dibuka, jadi form dan kolom kredensial tidak dapat diperiksa.',
    },
    observations: [
      {
        kind: 'response',
        state: 'unavailable',
        detail: args.reason,
      },
    ],
    notes: [
      'Perilaku halaman tidak dapat diamati tanpa permintaan ke target.',
      'Hasil ini bukan bukti bahwa target aman atau berbahaya.',
    ],
  }

  const registration = unavailableRegistration(at, args.reason)

  const page: PageAnalysis = analyzePageContent({
    html: null,
    baseUrl: null,
    pageHost: args.hostname,
    pageSecure: true,
    registrableDomain: registrableOf(args.hostname),
    forms: unavailableBehavior.forms,
    detail: `${args.reason} Isi halaman (tautan, form, identitas merek, skrip) tidak dapat diperiksa.`,
  })

  const category = classifyWebsiteCategory({
    hostname: args.hostname,
    html: null,
    response,
  })

  // Tanpa akses platform hanya teks URL yang dinilai. staticOnlyFusion sengaja
  // membatasi skor dan keyakinan supaya hasil parsial tidak dibaca sebagai vonis.
  const risk = staticOnlyFusion({
    generatedAt: at,
    structure,
    hostname: args.hostname,
    registrableDomain: registrableOf(args.hostname),
    reason: args.reason,
  })

  return {
    version: 1,
    target: args.target,
    hostname: args.hostname,
    generatedAt: args.generatedAt,
    durationMs: Math.max(0, args.now() - args.startedAt),
    probe: {
      available: false,
      name: args.probe?.name ?? 'tanpa akses platform',
      detail: args.reason,
    },
    website: {
      status: 'unavailable',
      identity: {
        hostname: args.hostname,
        addresses: emptyLookups.addresses,
        withheldAddresses: 0,
        asn: emptyLookups.asn,
        intermediary: {
          state: 'unavailable',
          signals: [],
          note: args.reason,
        },
      },
      dns,
      tls,
      response,
      notes: [
        'Tidak ada permintaan yang dikirim ke target. Bagian ini tidak menampilkan data contoh.',
        args.reason,
      ],
    },
    technology,
    behavior: unavailableBehavior,
    registration,
    page,
    risk,
    category,
  }
}

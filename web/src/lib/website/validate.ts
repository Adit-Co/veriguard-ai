import {
  DOMAIN_AGE_CODES,
  EVIDENCE_CATEGORIES,
  PAGE_SIGNAL_CODES,
  RISK_WEBSITE_CATEGORY_IDS,
  URL_STRUCTURE_CODES,
  WEBSITE_CATEGORY_IDS,
  WEBSITE_CATEGORY_LABELS,
  WEBSITE_RECORD_TYPES,
  type AsnInfo,
  type BehaviorAnalysis,
  type BehaviorObservation,
  type CookieMetadata,
  type DnsRecordSet,
  type DomainAgeAnalysis,
  type DomainAgeCode,
  type DomainAgeFinding,
  type DomainRegistration,
  type EvidenceAvailability,
  type EvidenceCategory,
  type EvidenceCoverage,
  type EvidenceStrength,
  type ExternalHostEntry,
  type FormAnalysis,
  type FormObservation,
  type FusedEvidence,
  type HeaderObservation,
  type HttpResponseInfo,
  type IntermediaryAssessment,
  type IpAddressEntry,
  type Lookup,
  type LookupStatus,
  type NetworkIdentity,
  type PageAnalysis,
  type PageSignalCode,
  type PageSignalFinding,
  type PageSignalStrength,
  type RedirectHop,
  type ResourceSummary,
  type ResponseHeaderEntry,
  type RiskFusion,
  type ScanStatus,
  type SectionStatus,
  type SiteAnalysisResponse,
  type SiteRiskLevel,
  type TechnologyAnalysis,
  type TechnologyCategory,
  type TechnologyCategorySignal,
  type TechnologyConfidence,
  type TechnologyFinding,
  type TlsCertificate,
  type TlsInfo,
  type UrlStructureAnalysis,
  type UrlStructureCode,
  type UrlStructureFinding,
  type UrlStructureStrength,
  type WebsiteCategoryAssessment,
  type WebsiteCategoryId,
  type WebsiteCategorySignal,
  type WebsiteCategorySignalSource,
  type WebsiteIntelligence,
  type WebsiteRecordType,
} from './types'

const LOOKUP_STATUSES = new Set<LookupStatus>([
  'success',
  'empty',
  'failed',
  'timeout',
  'blocked',
  'unavailable',
])

const SECTION_STATUSES = new Set<SectionStatus>(['complete', 'partial', 'unavailable', 'failed'])

const TECHNOLOGY_CATEGORIES = new Set<TechnologyCategory>([
  'frontend',
  'library',
  'css',
  'cms',
  'server',
  'analytics',
  'other',
])

const CONFIDENCES = new Set<TechnologyConfidence>(['high', 'medium', 'low'])

const HOP_OUTCOMES = new Set<RedirectHop['outcome']>([
  'followed',
  'final',
  'blocked',
  'loop',
  'limit',
  'error',
])

const REDIRECT_OUTCOMES = new Set<BehaviorAnalysis['redirectOutcome']>([
  'final',
  'blocked',
  'loop',
  'limit',
  'error',
  'unavailable',
])

const OBSERVATION_STATES = new Set<BehaviorObservation['state']>([
  'observed',
  'inferred',
  'no_signal',
  'unavailable',
])

const OBSERVATION_KINDS = new Set<BehaviorObservation['kind']>([
  'redirect',
  'response',
  'resource',
  'header',
  'cookie',
  'tls',
  'url',
  'form',
])

const STRUCTURE_CODES = new Set<UrlStructureCode>(URL_STRUCTURE_CODES)

const STRUCTURE_STRENGTHS = new Set<UrlStructureStrength>(['strong', 'moderate', 'weak'])

const HOST_ROLES = new Set<ExternalHostEntry['roles'][number]>([
  'observed',
  'referenced',
  'inferred',
])

const CATEGORY_IDS = new Set<WebsiteCategoryId>(WEBSITE_CATEGORY_IDS)

const CATEGORY_SOURCES = new Set<WebsiteCategorySignalSource>([
  'content',
  'domain',
  'structure',
  'network',
])

const CATEGORY_STRENGTHS = new Set<WebsiteCategorySignal['strength']>([
  'strong',
  'moderate',
  'weak',
])

const RISK_CATEGORY_IDS = new Set<WebsiteCategoryId>(RISK_WEBSITE_CATEGORY_IDS)

const RECORD_TYPES = new Set<string>(WEBSITE_RECORD_TYPES)

const DOMAIN_AGE_CODE_SET = new Set<DomainAgeCode>(DOMAIN_AGE_CODES)

const PAGE_SIGNAL_CODE_SET = new Set<PageSignalCode>(PAGE_SIGNAL_CODES)

const PAGE_STRENGTHS = new Set<PageSignalStrength>(['strong', 'moderate', 'weak'])

const EVIDENCE_STRENGTHS = new Set<EvidenceStrength>([
  'strong',
  'moderate',
  'weak',
  'mitigating',
])

const EVIDENCE_AVAILABILITIES = new Set<EvidenceAvailability>([
  'observed',
  'unavailable',
  'failed',
  'not_applicable',
])

const EVIDENCE_CATEGORY_SET = new Set<EvidenceCategory>(EVIDENCE_CATEGORIES)

const SCAN_STATUSES = new Set<ScanStatus>(['complete', 'partial', 'limited', 'failed'])

const SITE_RISK_LEVELS = new Set<SiteRiskLevel>([
  'unknown',
  'low',
  'medium',
  'high',
  'critical',
])

const MAX_TEXT = 400
const MAX_LIST = 60

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function stripControlChars(value: string): string {
  let output = ''
  for (const char of value) {
    const code = char.charCodeAt(0)
    output += code < 0x20 || code === 0x7f ? ' ' : char
  }
  return output
}

function text(value: unknown, max = MAX_TEXT): string {
  if (typeof value !== 'string') return ''
  const trimmed = stripControlChars(value).replace(/\s+/g, ' ').trim()
  return trimmed.length > max ? `${trimmed.slice(0, max - 1)}…` : trimmed
}

function optionalText(value: unknown, max = MAX_TEXT): string | null {
  const cleaned = text(value, max)
  return cleaned.length > 0 ? cleaned : null
}

function booleanOrNull(value: unknown): boolean | null {
  if (typeof value === 'boolean') return value
  return null
}

function finiteNumber(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function nonNegative(value: unknown, fallback = 0): number {
  const parsed = finiteNumber(value, fallback)
  return parsed < 0 ? 0 : parsed
}

/**
 * Nol adalah fakta, bukan nilai default. Usia registrasi, skor, dan rasio yang
 * tidak datang sebagai number terhingga dibaca null supaya UI bisa berkata
 * "tidak diketahui" alih-alih mengarang angka.
 */
function nullableNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function nonNegativeOrNull(value: unknown): number | null {
  const parsed = nullableNumber(value)
  return parsed === null || parsed < 0 ? null : parsed
}

function ratioOrNull(value: unknown): number | null {
  const parsed = nonNegativeOrNull(value)
  return parsed !== null && parsed <= 1 ? parsed : null
}

function riskScoreOrNull(value: unknown): number | null {
  const parsed = nullableNumber(value)
  if (parsed === null) return null
  return Math.min(100, Math.max(0, Math.round(parsed)))
}

function isoDateOrNull(value: unknown): string | null {
  const candidate = text(value, 40)
  if (candidate.length === 0) return null
  const parsed = Date.parse(candidate)
  return Number.isNaN(parsed) ? null : new Date(parsed).toISOString()
}

function stringList(value: unknown, max = MAX_LIST): string[] {
  if (!Array.isArray(value)) return []
  return value
    .slice(0, max)
    .map((item) => text(item, 200))
    .filter((item) => item.length > 0)
}

function isoDate(value: unknown): string {
  const candidate = text(value, 40)
  const parsed = Date.parse(candidate)
  return Number.isNaN(parsed) ? new Date(0).toISOString() : new Date(parsed).toISOString()
}

function enumOrNull<T extends string>(value: unknown, allowed: Set<T>): T | null {
  return typeof value === 'string' && allowed.has(value as T) ? (value as T) : null
}

function lookupStatus(value: unknown): LookupStatus {
  return enumOrNull(value, LOOKUP_STATUSES) ?? 'unavailable'
}

function readLookup<T>(
  value: unknown,
  readValue: (raw: unknown) => T | null,
): Lookup<T> {
  const record = isRecord(value) ? value : {}
  const detail = optionalText(record.detail)
  const raw = record.value
  return {
    status: lookupStatus(record.status),
    source: text(record.source, 120) || 'sumber tidak dinyatakan',
    value: raw === null || raw === undefined ? null : readValue(raw),
    detail,
    queriedAt: isoDate(record.queriedAt),
  }
}

function readAddresses(value: unknown): IpAddressEntry[] {
  if (!Array.isArray(value)) return []
  return value
    .slice(0, MAX_LIST)
    .filter(isRecord)
    .map((entry) => ({
      address: text(entry.address, 80),
      kind: (entry.kind === 'ipv6' ? 'ipv6' : 'ipv4') as IpAddressEntry['kind'],
    }))
    .filter((entry) => entry.address.length > 0)
}

function readAsnInfo(value: unknown): AsnInfo | null {
  if (!isRecord(value)) return null
  const info: AsnInfo = {
    asn: optionalText(value.asn, 24),
    organization: optionalText(value.organization, 160),
    country: optionalText(value.country, 8),
    prefix: optionalText(value.prefix, 80),
    registry: optionalText(value.registry, 32),
  }
  return info.asn || info.organization || info.country || info.prefix || info.registry ? info : null
}

function readIntermediary(value: unknown): IntermediaryAssessment {
  const record = isRecord(value) ? value : {}
  const state =
    enumOrNull(record.state, new Set(['possible', 'no_signal', 'unavailable'] as const)) ??
    'unavailable'
  const signals = Array.isArray(record.signals)
    ? record.signals.slice(0, 12).filter(isRecord).map((signal) => ({
        label: text(signal.label, 120),
        evidence: text(signal.evidence, 240),
      }))
    : []
  return {
    state,
    signals,
    note: text(record.note) || 'Status perantara belum dapat ditentukan.',
  }
}

function readIdentity(value: unknown): NetworkIdentity {
  const record = isRecord(value) ? value : {}
  return {
    hostname: text(record.hostname, 255),
    addresses: readLookup(record.addresses, readAddresses),
    withheldAddresses: nonNegative(record.withheldAddresses),
    asn: readLookup(record.asn, readAsnInfo),
    intermediary: readIntermediary(record.intermediary),
  }
}

function readDns(value: unknown): DnsRecordSet[] {
  if (!Array.isArray(value)) return []
  return value.slice(0, WEBSITE_RECORD_TYPES.length).map((entry) => {
    const record = isRecord(entry) ? entry : {}
    const type = (typeof record.type === 'string' && RECORD_TYPES.has(record.type)
      ? record.type
      : 'TXT') as WebsiteRecordType
    return {
      type,
      lookup: readLookup(record.lookup, (raw) => (Array.isArray(raw) ? stringList(raw) : null)),
    }
  })
}

function readCertificate(value: unknown): TlsCertificate | null {
  if (!isRecord(value)) return null
  const verification =
    enumOrNull(value.verification, new Set(['verified', 'rejected', 'not_checked'] as const)) ??
    'not_checked'
  return {
    issuer: optionalText(value.issuer, 200),
    subject: optionalText(value.subject, 200),
    notBefore: optionalText(value.notBefore, 40),
    notAfter: optionalText(value.notAfter, 40),
    expired: booleanOrNull(value.expired),
    hostnameVerified: booleanOrNull(value.hostnameVerified),
    verification,
    verificationDetail: optionalText(value.verificationDetail),
    protocol: optionalText(value.protocol, 32),
  }
}

function readTls(value: unknown): TlsInfo {
  const record = isRecord(value) ? value : {}
  return {
    httpsAvailable: readLookup(record.httpsAvailable, (raw) =>
      typeof raw === 'boolean' ? raw : null,
    ),
    certificate: readLookup(record.certificate, readCertificate),
    certificateSource: optionalText(record.certificateSource, 120),
  }
}

function readHeaders(value: unknown): { entries: ResponseHeaderEntry[]; withheld: number } {
  if (!Array.isArray(value)) return { entries: [], withheld: 0 }
  const entries = value.slice(0, MAX_LIST).filter(isRecord).map((entry) => ({
    name: text(entry.name, 60).toLowerCase(),
    value: text(entry.value, 200),
  }))
  return { entries, withheld: 0 }
}

function readResponse(value: unknown): HttpResponseInfo {
  const record = isRecord(value) ? value : {}
  const headers = readHeaders(record.headers)
  return {
    request: readLookup(record.request, () => null),
    status: typeof record.status === 'number' && Number.isFinite(record.status) ? record.status : null,
    statusText: optionalText(record.statusText, 80),
    finalUrl: optionalText(record.finalUrl, 300),
    redirectCount: nonNegative(record.redirectCount),
    elapsedMs: typeof record.elapsedMs === 'number' && Number.isFinite(record.elapsedMs) ? record.elapsedMs : null,
    contentType: optionalText(record.contentType, 120),
    bytes: typeof record.bytes === 'number' && Number.isFinite(record.bytes) ? record.bytes : null,
    truncated: record.truncated === true,
    headers: headers.entries,
    withheldHeaders: nonNegative(record.withheldHeaders),
  }
}

function readWebsite(value: unknown): WebsiteIntelligence {
  const record = isRecord(value) ? value : {}
  return {
    status: enumOrNull(record.status, SECTION_STATUSES) ?? 'unavailable',
    identity: readIdentity(record.identity),
    dns: readDns(record.dns),
    tls: readTls(record.tls),
    response: readResponse(record.response),
    notes: stringList(record.notes),
  }
}

function readTechnology(value: unknown): TechnologyAnalysis {
  const record = isRecord(value) ? value : {}
  const findings = Array.isArray(record.findings)
    ? record.findings.slice(0, MAX_LIST).filter(isRecord).map((entry) => {
        const finding: TechnologyFinding = {
          name: text(entry.name, 120),
          category:
            enumOrNull(entry.category, TECHNOLOGY_CATEGORIES) ?? 'other',
          evidence: stringList(entry.evidence, 6),
          confidence: enumOrNull(entry.confidence, CONFIDENCES) ?? 'low',
          state: entry.state === 'detected' ? 'detected' : 'possible',
        }
        return finding
      }).filter((finding: TechnologyFinding) => finding.name.length > 0)
    : []

  const categories = Array.isArray(record.categories)
    ? record.categories.slice(0, 12).filter(isRecord).map((entry) => {
        const signal: TechnologyCategorySignal = {
          category: enumOrNull(entry.category, TECHNOLOGY_CATEGORIES) ?? 'other',
          state:
            enumOrNull(entry.state, new Set(['found', 'no_signal', 'unavailable'] as const)) ??
            'unavailable',
          detail: text(entry.detail),
        }
        return signal
      })
    : []

  const document = isRecord(record.document) ? record.document : {}

  return {
    status: enumOrNull(record.status, SECTION_STATUSES) ?? 'unavailable',
    findings,
    categories,
    document: {
      inspected: document.inspected === true,
      bytesScanned: nonNegative(document.bytesScanned),
      truncated: document.truncated === true,
      contentType: optionalText(document.contentType, 120),
      detail: text(document.detail) || 'Dokumen tidak tersedia untuk diperiksa.',
    },
    notes: stringList(record.notes),
  }
}

function readRedirects(value: unknown): RedirectHop[] {
  if (!Array.isArray(value)) return []
  return value.slice(0, 12).filter(isRecord).map((entry) => ({
    url: text(entry.url, 300),
    status: typeof entry.status === 'number' && Number.isFinite(entry.status) ? entry.status : null,
    location: optionalText(entry.location, 300),
    outcome: enumOrNull(entry.outcome, HOP_OUTCOMES) ?? 'error',
    detail: optionalText(entry.detail),
  }))
}

function readHosts(value: unknown): ExternalHostEntry[] {
  if (!Array.isArray(value)) return []
  return value.slice(0, MAX_LIST).filter(isRecord).map((entry) => ({
    host: text(entry.host, 255),
    roles: Array.isArray(entry.roles)
      ? (entry.roles.filter((role) => HOST_ROLES.has(role as ExternalHostEntry['roles'][number])) as ExternalHostEntry['roles'])
      : [],
    resourceKinds: stringList(entry.resourceKinds, 8),
    count: nonNegative(entry.count),
  }))
}

function readResources(value: unknown): ResourceSummary | null {
  if (!isRecord(value)) return null
  return {
    scripts: nonNegative(value.scripts),
    styles: nonNegative(value.styles),
    images: nonNegative(value.images),
    iframes: nonNegative(value.iframes),
    links: nonNegative(value.links),
    other: nonNegative(value.other),
    collected: nonNegative(value.collected),
    capped: value.capped === true,
  }
}

function readSecurityHeaders(value: unknown): HeaderObservation[] {
  if (!Array.isArray(value)) return []
  return value.slice(0, 16).filter(isRecord).map((entry) => ({
    name: text(entry.name, 60).toLowerCase(),
    present: entry.present === true,
    value: optionalText(entry.value, 200),
  }))
}

function readCookies(value: unknown): CookieMetadata[] {
  if (!Array.isArray(value)) return []
  return value.slice(0, 24).filter(isRecord).map((entry) => ({
    name: text(entry.name, 120),
    secure: entry.secure === true,
    httpOnly: entry.httpOnly === true,
    sameSite: optionalText(entry.sameSite, 24),
    hasExpiry: entry.hasExpiry === true,
    valueShown: false,
  }))
}

function readObservations(value: unknown): BehaviorObservation[] {
  if (!Array.isArray(value)) return []
  return value
    .slice(0, MAX_LIST)
    .filter(isRecord)
    .map((entry) => ({
      kind: enumOrNull(entry.kind, OBSERVATION_KINDS) ?? 'response',
      state: enumOrNull(entry.state, OBSERVATION_STATES) ?? 'unavailable',
      detail: text(entry.detail),
    }))
    .filter((entry: BehaviorObservation) => entry.detail.length > 0)
}

function readStructureFindings(value: unknown): UrlStructureFinding[] {
  if (!Array.isArray(value)) return []
  return value.slice(0, MAX_LIST).flatMap((entry) => {
    if (!isRecord(entry)) return []
    const code = enumOrNull(entry.code, STRUCTURE_CODES)
    // Kode yang tidak dikenal berarti backend lebih baru dari klien; temuan tidak boleh
    // dilabeli ulang ke kode lain karena buktinya akan terbaca salah.
    if (!code) return []
    const detail = text(entry.detail)
    if (detail.length === 0) return []
    const finding: UrlStructureFinding = {
      code,
      label: text(entry.label, 120),
      detail,
      strength: enumOrNull(entry.strength, STRUCTURE_STRENGTHS) ?? 'weak',
      evidence: optionalText(entry.evidence, 200),
    }
    return [finding]
  })
}

// Respons dari backend lama tidak membawa bagian ini sama sekali. Validator tetap
// mengembalikan status unavailable alih-alih membuang seluruh analisis perilaku.
function readStructure(value: unknown): UrlStructureAnalysis {
  if (!isRecord(value)) {
    return {
      status: 'unavailable',
      findings: [],
      hostname: '',
      scheme: null,
      port: null,
      labelCount: 0,
      registrableDomain: null,
      notes: ['Sinyal struktur URL tidak dikembalikan oleh backend pada pemeriksaan ini.'],
    }
  }
  return {
    status: enumOrNull(value.status, SECTION_STATUSES) ?? 'unavailable',
    findings: readStructureFindings(value.findings),
    hostname: text(value.hostname, 255),
    scheme: optionalText(value.scheme, 16),
    port: optionalText(value.port, 16),
    labelCount: nonNegative(value.labelCount),
    registrableDomain: optionalText(value.registrableDomain, 255),
    notes: stringList(value.notes),
  }
}

function readForms(value: unknown): FormAnalysis {
  const record = isRecord(value) ? value : null
  const totals: Record<string, unknown> =
    record && isRecord(record.totals) ? record.totals : {}
  const rawForms = record && Array.isArray(record.forms) ? record.forms : []
  const forms = rawForms
    .slice(0, 12)
    .filter(isRecord)
    .map((entry): FormObservation => ({
      index: nonNegative(entry.index),
      action: optionalText(entry.action, 300),
      actionHost: optionalText(entry.actionHost, 255),
      actionScheme: optionalText(entry.actionScheme, 16),
      external: entry.external === true,
      insecure: entry.insecure === true,
      method: optionalText(entry.method, 16),
      passwordFields: nonNegative(entry.passwordFields),
      textFields: nonNegative(entry.textFields),
    }))
  const detail = record ? text(record.detail) : ''
  return {
    inspected: record?.inspected === true,
    forms,
    totals: {
      forms: nonNegative(totals.forms, forms.length),
      passwordFields: nonNegative(totals.passwordFields),
      externalActions: nonNegative(totals.externalActions),
      insecureActions: nonNegative(totals.insecureActions),
    },
    capped: record?.capped === true,
    detail: detail.length > 0 ? detail : 'Form dan kolom kredensial belum dapat diperiksa.',
  }
}

function readBehavior(value: unknown): BehaviorAnalysis {
  const record = isRecord(value) ? value : {}
  return {
    status: enumOrNull(record.status, SECTION_STATUSES) ?? 'unavailable',
    initialUrl: text(record.initialUrl, 300),
    redirects: readRedirects(record.redirects),
    redirectCount: nonNegative(record.redirectCount),
    redirectOutcome: enumOrNull(record.redirectOutcome, REDIRECT_OUTCOMES) ?? 'unavailable',
    hosts: readHosts(record.hosts),
    resources: readResources(record.resources),
    securityHeaders: readSecurityHeaders(record.securityHeaders),
    cookies: readCookies(record.cookies),
    cookiesCollected: record.cookiesCollected === true,
    structure: readStructure(record.structure),
    forms: readForms(record.forms),
    observations: readObservations(record.observations),
    notes: stringList(record.notes),
  }
}

function readCategory(value: unknown): WebsiteCategoryAssessment {
  const record = isRecord(value) ? value : {}
  const primaryId: WebsiteCategoryId =
    enumOrNull(record.primaryId, CATEGORY_IDS) ?? 'unknown'

  const signals = Array.isArray(record.signals)
    ? record.signals
        .slice(0, MAX_LIST)
        .filter(isRecord)
        .map((entry) => {
          const signal: WebsiteCategorySignal = {
            categoryId: enumOrNull(entry.categoryId, CATEGORY_IDS) ?? primaryId,
            label: text(entry.label, 120),
            detail: text(entry.detail),
            source: enumOrNull(entry.source, CATEGORY_SOURCES) ?? 'content',
            strength: enumOrNull(entry.strength, CATEGORY_STRENGTHS) ?? 'weak',
          }
          return signal
        })
        .filter((signal: WebsiteCategorySignal) => signal.detail.length > 0)
    : []

  const alternatives = Array.isArray(record.alternatives)
    ? record.alternatives
        .slice(0, MAX_LIST)
        .filter(isRecord)
        .map((entry) => {
          const id = enumOrNull(entry.id, CATEGORY_IDS) ?? 'unknown'
          return {
            id,
            label: text(entry.label, 120) || WEBSITE_CATEGORY_LABELS[id],
            confidence: enumOrNull(entry.confidence, CONFIDENCES) ?? 'low',
          }
        })
        .filter((entry) => entry.id !== primaryId)
    : []

  const basis = isRecord(record.evidenceBasis) ? record.evidenceBasis : {}

  return {
    status: enumOrNull(record.status, SECTION_STATUSES) ?? 'unavailable',
    primaryId,
    primaryLabel: text(record.primaryLabel, 120) || WEBSITE_CATEGORY_LABELS[primaryId],
    confidence: enumOrNull(record.confidence, CONFIDENCES) ?? 'low',
    riskIndicated: RISK_CATEGORY_IDS.has(primaryId),
    summary:
      text(record.summary) ||
      'Kategori website belum dapat ditentukan dari bukti yang tersedia.',
    signals,
    alternatives,
    evidenceBasis: {
      documentInspected: basis.documentInspected === true,
      titleAvailable: basis.titleAvailable === true,
      descriptionAvailable: basis.descriptionAvailable === true,
      visibleTextBytes: nonNegative(basis.visibleTextBytes),
      redirectHops: nonNegative(basis.redirectHops),
    },
    notes: stringList(record.notes),
  }
}

function readDomainRecord(value: unknown): DomainRegistration | null {
  if (!isRecord(value)) return null
  const domain = text(value.domain, 255)
  if (domain.length === 0) return null
  return {
    domain,
    handle: optionalText(value.handle, 120),
    registrar: optionalText(value.registrar, 160),
    createdAt: isoDateOrNull(value.createdAt),
    changedAt: isoDateOrNull(value.changedAt),
    expiresAt: isoDateOrNull(value.expiresAt),
    statuses: stringList(value.statuses, 24),
  }
}

function readAgeFindings(value: unknown): DomainAgeFinding[] {
  if (!Array.isArray(value)) return []
  return value.slice(0, MAX_LIST).flatMap((entry): DomainAgeFinding[] => {
    if (!isRecord(entry)) return []
    const code = enumOrNull(entry.code, DOMAIN_AGE_CODE_SET)
    // Kode yang tidak dikenal berarti backend lebih baru dari klien; temuan tidak
    // boleh dilabeli ulang karena buktinya akan terbaca salah.
    if (!code) return []
    return [
      {
        code,
        label: text(entry.label, 120),
        detail: text(entry.detail),
        strength: enumOrNull(entry.strength, EVIDENCE_STRENGTHS) ?? 'weak',
        evidence: optionalText(entry.evidence, 200),
      },
    ]
  })
}

function readRegistration(value: unknown): DomainAgeAnalysis | null {
  if (!isRecord(value)) return null
  return {
    status: enumOrNull(value.status, SECTION_STATUSES) ?? 'unavailable',
    registrableDomain: optionalText(value.registrableDomain, 255),
    lookup: readLookup(value.lookup, readDomainRecord),
    ageDays: nonNegativeOrNull(value.ageDays),
    ageBasis: value.ageBasis === 'registration' ? 'registration' : 'none',
    findings: readAgeFindings(value.findings),
    notes: stringList(value.notes),
  }
}

function readPageFindings(value: unknown): PageSignalFinding[] {
  if (!Array.isArray(value)) return []
  return value.slice(0, MAX_LIST).flatMap((entry): PageSignalFinding[] => {
    if (!isRecord(entry)) return []
    const code = enumOrNull(entry.code, PAGE_SIGNAL_CODE_SET)
    if (!code) return []
    return [
      {
        code,
        label: text(entry.label, 120),
        detail: text(entry.detail),
        strength: enumOrNull(entry.strength, PAGE_STRENGTHS) ?? 'weak',
        evidence: optionalText(entry.evidence, 200),
      },
    ]
  })
}

function readPage(value: unknown): PageAnalysis | null {
  if (!isRecord(value)) return null
  const anchors = isRecord(value.anchors) ? value.anchors : {}
  const scripts = isRecord(value.scripts) ? value.scripts : {}
  return {
    status: enumOrNull(value.status, SECTION_STATUSES) ?? 'unavailable',
    inspected: value.inspected === true,
    bytesScanned: nonNegative(value.bytesScanned),
    truncated: value.truncated === true,
    anchors: {
      internal: nonNegative(anchors.internal),
      external: nonNegative(anchors.external),
      externalHosts: stringList(anchors.externalHosts, 24),
      ratio: ratioOrNull(anchors.ratio),
    },
    scripts: {
      total: nonNegative(scripts.total),
      external: nonNegative(scripts.external),
      inline: nonNegative(scripts.inline),
    },
    forms: readForms(value.forms),
    findings: readPageFindings(value.findings),
    notes: stringList(value.notes),
  }
}

function readCoverage(value: unknown): EvidenceCoverage {
  const record = isRecord(value) ? value : {}
  const byCategory = Array.isArray(record.byCategory)
    ? record.byCategory
        .slice(0, MAX_LIST)
        .flatMap(
          (entry): EvidenceCoverage['byCategory'] => {
            if (!isRecord(entry)) return []
            const category = enumOrNull(entry.category, EVIDENCE_CATEGORY_SET)
            // Baris per sumbu dengan kategori asing dibuang; jumlah total dari
            // backend tetap utuh sehingga cakupan tidak berubah makna.
            if (!category) return []
            return [{ category, succeeded: nonNegative(entry.succeeded), total: nonNegative(entry.total) }]
          },
        )
    : []

  return {
    totalChecks: nonNegative(record.totalChecks),
    succeeded: nonNegative(record.succeeded),
    unavailable: nonNegative(record.unavailable),
    failed: nonNegative(record.failed),
    ratio: ratioOrNull(record.ratio),
    byCategory,
  }
}

function readFusedEvidence(value: unknown): FusedEvidence[] {
  if (!Array.isArray(value)) return []
  return value.slice(0, MAX_LIST).flatMap((entry): FusedEvidence[] => {
    if (!isRecord(entry)) return []
    const id = text(entry.id, 120)
    const detail = text(entry.detail)
    // Baris tanpa id atau detail tidak dapat ditelusuri ke modul pengamatnya.
    if (id.length === 0 || detail.length === 0) return []
    const category = enumOrNull(entry.category, EVIDENCE_CATEGORY_SET)
    // Kategori wajib dari cermin tipe backend. Bila backend lebih baru dan mengirim
    // sumbu yang tidak dikenal klien, barisnya dibuang — bukan dilabeli ulang ke
    // sumbu lain, karena itu membuat bukti terbaca berasal dari pemeriksaan yang
    // sebenarnya tidak pernah mendukungnya. Jumlah cakupan dari backend tidak berubah.
    if (!category) return []
    return [
      {
        id,
        category,
        label: text(entry.label, 120),
        detail,
        observed: optionalText(entry.observed, 200),
        source: text(entry.source, 120) || 'sumber tidak dinyatakan',
        strength: enumOrNull(entry.strength, EVIDENCE_STRENGTHS) ?? 'weak',
        availability: enumOrNull(entry.availability, EVIDENCE_AVAILABILITIES) ?? 'unavailable',
        observedAt: isoDateOrNull(entry.observedAt),
      },
    ]
  })
}

function readRisk(value: unknown): RiskFusion | null {
  if (!isRecord(value)) return null
  return {
    // Status yang tidak dikenal klien dibaca "limited": klien tidak tahu apa di
    // baliknya, jadi tidak boleh mengklaim cakupan penuh atas nama backend.
    status: enumOrNull(value.status, SCAN_STATUSES) ?? 'limited',
    level: enumOrNull(value.level, SITE_RISK_LEVELS) ?? 'unknown',
    riskScore: riskScoreOrNull(value.riskScore),
    confidence: enumOrNull(value.confidence, CONFIDENCES) ?? 'low',
    confidenceDetail:
      text(value.confidenceDetail) ||
      'Layanan pemeriksaan tidak menyatakan keyakinan hasil ini.',
    coverage: readCoverage(value.coverage),
    evidence: readFusedEvidence(value.evidence),
    notEvaluated: stringList(value.notEvaluated),
    notes: stringList(value.notes),
  }
}

export function isSiteAnalysisResponse(value: unknown): value is SiteAnalysisResponse {
  if (!isRecord(value)) return false
  if (value.version !== 1) return false
  if (typeof value.target !== 'string' || typeof value.hostname !== 'string') return false
  if (!isRecord(value.probe) || typeof value.probe.available !== 'boolean') return false
  if (!isRecord(value.website) || !isRecord(value.technology) || !isRecord(value.behavior)) {
    return false
  }
  // Kategori ditambahkan setelah versi respons lama dibuat, jadi hasilnya boleh
  // tidak ada dan akan dinormalisasi menjadi "tidak diketahui".
  if (value.category !== undefined && !isRecord(value.category)) return false
  // Begitu pula registrasi, halaman, dan fusi risiko: respons lama dan laporan
  // yang sudah tersimpan di perangkat tidak membawanya, dan itu bukan laporan rusak.
  for (const key of ['registration', 'page', 'risk'] as const) {
    if (value[key] !== undefined && !isRecord(value[key])) return false
  }
  return Array.isArray(value.website.dns)
}

/**
 * Merespons JSON tidak tepercaya menjadi tipe yang pasti aman dipakai UI:
 * string dipotong, angka dinormalisasi, dan enum asing diganti status netral.
 */
export function parseSiteAnalysisResponse(value: unknown): SiteAnalysisResponse {
  if (!isRecord(value) || value.version !== 1) {
    throw new Error('Respons analisis situs tidak valid.')
  }

  const probe = isRecord(value.probe) ? value.probe : {}

  return {
    version: 1,
    target: text(value.target, 300),
    hostname: text(value.hostname, 255),
    generatedAt: isoDate(value.generatedAt),
    durationMs: nonNegative(value.durationMs),
    probe: {
      available: probe.available === true,
      name: text(probe.name, 80) || 'tanpa probe',
      detail: optionalText(probe.detail),
    },
    website: readWebsite(value.website),
    technology: readTechnology(value.technology),
    behavior: readBehavior(value.behavior),
    category: readCategory(value.category),
    registration: readRegistration(value.registration),
    page: readPage(value.page),
    risk: readRisk(value.risk),
  }
}

export const WEBSITE_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA'] as const

export type WebsiteRecordType = (typeof WEBSITE_RECORD_TYPES)[number]

/**
 * `empty` berarti kueri selesai tetapi tidak mengembalikan record, sedangkan
 * `failed` berarti kueri tidak dapat diselesaikan. Keduanya tidak boleh dibaca
 * sebagai "aman" maupun "tidak ada".
 */
export type LookupStatus = 'success' | 'empty' | 'failed' | 'timeout' | 'blocked' | 'unavailable'

export type Lookup<T> = {
  status: LookupStatus
  source: string
  value: T | null
  detail: string | null
  queriedAt: string
}

export type SectionStatus = 'complete' | 'partial' | 'unavailable' | 'failed'
export type IpAddressEntry = {
  address: string
  kind: 'ipv4' | 'ipv6'
}

export type AsnInfo = {
  asn: string | null
  organization: string | null
  country: string | null
  prefix: string | null
  registry: string | null
}

export type IntermediarySignal = {
  label: string
  evidence: string
}

export type IntermediaryAssessment = {
  state: 'possible' | 'no_signal' | 'unavailable'
  signals: IntermediarySignal[]
  note: string
}

export type NetworkIdentity = {
  hostname: string
  addresses: Lookup<IpAddressEntry[]>
  withheldAddresses: number
  asn: Lookup<AsnInfo>
  intermediary: IntermediaryAssessment
}

export type DnsRecordSet = {
  type: WebsiteRecordType
  lookup: Lookup<string[]>
}

export type TlsCertificate = {
  issuer: string | null
  subject: string | null
  notBefore: string | null
  notAfter: string | null
  expired: boolean | null
  hostnameVerified: boolean | null
  verification: 'verified' | 'rejected' | 'not_checked'
  verificationDetail: string | null
  protocol: string | null
}

export type TlsInfo = {
  httpsAvailable: Lookup<boolean>
  certificate: Lookup<TlsCertificate>
  certificateSource: string | null
}

export type ResponseHeaderEntry = {
  name: string
  value: string
}

export type HttpResponseInfo = {
  request: Lookup<null>
  status: number | null
  statusText: string | null
  finalUrl: string | null
  redirectCount: number
  elapsedMs: number | null
  contentType: string | null
  bytes: number | null
  truncated: boolean
  headers: ResponseHeaderEntry[]
  withheldHeaders: number
}

export type WebsiteIntelligence = {
  status: SectionStatus
  identity: NetworkIdentity
  dns: DnsRecordSet[]
  tls: TlsInfo
  response: HttpResponseInfo
  notes: string[]
}

/**
 * Isi jawaban RDAP yang benar-benar terbaca. Field yang tidak ada dibiarkan null,
 * bukan diisi perkiraan: banyak ccTLD tidak menyediakan RDAP sama sekali dan
 * registry yang merahasiakan data pendaftar tidak berarti domainnya mencurigakan.
 */
export type DomainRegistration = {
  domain: string
  handle: string | null
  registrar: string | null
  createdAt: string | null
  changedAt: string | null
  expiresAt: string | null
  statuses: string[]
}

export type RegistrationOutcome = LookupOutcome | 'unsupported' | 'not_found'

export type RegistrationQueryResult = {
  registration: DomainRegistration | null
  outcome: RegistrationOutcome
  source: string | null
  detail: string | null
}

export const DOMAIN_AGE_CODES = [
  'domain_young',
  'domain_recent',
  'domain_mature',
  'registration_expiring',
  'registration_date_missing',
  'registration_unavailable',
] as const

export type DomainAgeCode = (typeof DOMAIN_AGE_CODES)[number]

export type DomainAgeFinding = {
  code: DomainAgeCode
  label: string
  detail: string
  strength: 'strong' | 'moderate' | 'weak' | 'mitigating'
  evidence: string | null
}

export type DomainAgeAnalysis = {
  status: SectionStatus
  registrableDomain: string | null
  lookup: Lookup<DomainRegistration>
  ageDays: number | null
  ageBasis: 'registration' | 'none'
  findings: DomainAgeFinding[]
  notes: string[]
}

export const WEBSITE_CATEGORY_IDS = [
  'gambling',
  'phishing',
  'scam',
  'malware',
  'marketplace',
  'banking',
  'government',
  'education',
  'media',
  'social',
  'technology',
  'entertainment',
  'business',
  'blog',
  'personal',
  'unknown',
] as const

export type WebsiteCategoryId = (typeof WEBSITE_CATEGORY_IDS)[number]

export type WebsiteCategoryConfidence = 'high' | 'medium' | 'low'

export type WebsiteCategorySignalSource = 'content' | 'domain' | 'structure' | 'network'

export type WebsiteCategorySignal = {
  categoryId: WebsiteCategoryId
  label: string
  detail: string
  source: WebsiteCategorySignalSource
  strength: 'strong' | 'moderate' | 'weak'
}

export type WebsiteCategoryAssessment = {
  status: SectionStatus
  primaryId: WebsiteCategoryId
  primaryLabel: string
  confidence: WebsiteCategoryConfidence
  riskIndicated: boolean
  summary: string
  signals: WebsiteCategorySignal[]
  alternatives: Array<{ id: WebsiteCategoryId; label: string; confidence: WebsiteCategoryConfidence }>
  evidenceBasis: {
    documentInspected: boolean
    titleAvailable: boolean
    descriptionAvailable: boolean
    visibleTextBytes: number
    redirectHops: number
  }
  notes: string[]
}

export type TechnologyCategory = 'frontend' | 'library' | 'css' | 'cms' | 'server' | 'analytics' | 'other'

export type TechnologyConfidence = 'high' | 'medium' | 'low'

export type TechnologyFinding = {
  name: string
  category: TechnologyCategory
  evidence: string[]
  confidence: TechnologyConfidence
  state: 'detected' | 'possible'
}

export type TechnologyCategorySignal = {
  category: TechnologyCategory
  state: 'found' | 'no_signal' | 'unavailable'
  detail: string
}

export type TechnologyAnalysis = {
  status: SectionStatus
  findings: TechnologyFinding[]
  categories: TechnologyCategorySignal[]
  document: {
    inspected: boolean
    bytesScanned: number
    truncated: boolean
    contentType: string | null
    detail: string
  }
  notes: string[]
}

export type RedirectHop = {
  url: string
  status: number | null
  location: string | null
  outcome: 'followed' | 'final' | 'blocked' | 'loop' | 'limit' | 'error'
  detail: string | null
}

export const URL_STRUCTURE_CODES = [
  'userinfo',
  'ip_literal',
  'unusual_port',
  'insecure_scheme',
  'punycode',
  'mixed_script',
  'homoglyph',
  'brand_in_host',
  'typosquat',
  'over_encoded',
  'encoded_delimiter',
  'delimiter_trick',
  'embedded_url',
  'encoded_payload',
  'shortener',
  'risky_tld',
  'deep_subdomain',
  'random_label',
  'hyphen_labels',
  'digit_heavy',
  'special_heavy',
  'long_url',
  'deep_path',
  'brand_in_path',
  'cross_domain_redirect',
  'downgrade_redirect',
] as const

export type UrlStructureCode = (typeof URL_STRUCTURE_CODES)[number]

export type UrlStructureStrength = 'strong' | 'moderate' | 'weak'

/**
 * Satu temuan struktur selalu membawa bukti tekstual. Tidak ada skor atau vonis
 * yang dihasilkan dari temuan ini, karena sinyalnya saling berkorelasi.
 */
export type UrlStructureFinding = {
  code: UrlStructureCode
  label: string
  detail: string
  strength: UrlStructureStrength
  evidence: string | null
}

export type UrlStructureAnalysis = {
  status: SectionStatus
  findings: UrlStructureFinding[]
  hostname: string
  scheme: string | null
  port: string | null
  labelCount: number
  registrableDomain: string | null
  notes: string[]
}

export const PAGE_SIGNAL_CODES = [
  'brand_identity_mismatch',
  'brand_anchor_target',
  'urgency_language',
  'credential_request',
  'payment_diversion',
  'anchor_external_ratio',
  'script_obfuscation',
  'meta_refresh_redirect',
  'script_location_redirect',
  'hidden_frame',
  'interaction_lock',
  'fake_secure_badge',
] as const

export type PageSignalCode = (typeof PAGE_SIGNAL_CODES)[number]

export type PageSignalStrength = 'strong' | 'moderate' | 'weak'

export type PageSignalFinding = {
  code: PageSignalCode
  label: string
  detail: string
  strength: PageSignalStrength
  evidence: string | null
}

export type PageAnalysis = {
  status: SectionStatus
  inspected: boolean
  bytesScanned: number
  truncated: boolean
  anchors: {
    internal: number
    external: number
    externalHosts: string[]
    ratio: number | null
  }
  scripts: {
    total: number
    external: number
    inline: number
  }
  forms: FormAnalysis
  findings: PageSignalFinding[]
  notes: string[]
}

export type FormObservation = {
  index: number
  action: string | null
  actionHost: string | null
  actionScheme: string | null
  external: boolean
  insecure: boolean
  method: string | null
  passwordFields: number
  textFields: number
}

export type FormAnalysis = {
  inspected: boolean
  forms: FormObservation[]
  totals: {
    forms: number
    passwordFields: number
    externalActions: number
    insecureActions: number
  }
  capped: boolean
  detail: string
}

export type ExternalHostEntry = {
  host: string
  roles: Array<'observed' | 'referenced' | 'inferred'>
  resourceKinds: string[]
  count: number
}

export type ResourceSummary = {
  scripts: number
  styles: number
  images: number
  iframes: number
  links: number
  other: number
  collected: number
  capped: boolean
}

export type HeaderObservation = {
  name: string
  present: boolean
  value: string | null
}

export type CookieMetadata = {
  name: string
  secure: boolean
  httpOnly: boolean
  sameSite: string | null
  hasExpiry: boolean
  valueShown: false
}

export type BehaviorObservation = {
  kind: 'redirect' | 'response' | 'resource' | 'header' | 'cookie' | 'tls' | 'url' | 'form'
  state: 'observed' | 'inferred' | 'no_signal' | 'unavailable'
  detail: string
}

export type BehaviorAnalysis = {
  status: SectionStatus
  initialUrl: string
  redirects: RedirectHop[]
  redirectCount: number
  redirectOutcome: 'final' | 'blocked' | 'loop' | 'limit' | 'error' | 'unavailable'
  hosts: ExternalHostEntry[]
  resources: ResourceSummary | null
  securityHeaders: HeaderObservation[]
  cookies: CookieMetadata[]
  cookiesCollected: boolean
  structure: UrlStructureAnalysis
  forms: FormAnalysis
  observations: BehaviorObservation[]
  notes: string[]
}

export type OriginRequest = {
  url: string
  address: string
  kind: 'ipv4' | 'ipv6'
  hostname: string
  port: number
  secure: boolean
  maxBytes: number
  timeoutMs: number
  userAgent: string
}

export type OriginTlsInfo = {
  protocol: string | null
  cipher: string | null
  issuer: string | null
  subject: string | null
  notBefore: string | null
  notAfter: string | null
  authorized: boolean | null
  authorizationError: string | null
}

export type OriginResult =
  | {
      ok: true
      status: number
      statusText: string | null
      headers: Array<[string, string]>
      body: string
      bytes: number
      truncated: boolean
      elapsedMs: number
      tls: OriginTlsInfo | null
    }
  | {
      ok: false
      kind: 'timeout' | 'error'
      detail: string
      elapsedMs: number
    }

export type LookupOutcome = 'answered' | 'empty' | 'failed' | 'timeout'

export type ResolveResult = {
  ipv4: string[]
  ipv6: string[]
  detail: string | null
}

export type RecordQueryResult = {
  records: string[]
  outcome: LookupOutcome
  detail: string | null
}

export type AsnQueryResult = {
  info: AsnInfo | null
  outcome: LookupOutcome
  detail: string | null
}

export type TlsProbeResult = {
  certificate: TlsCertificate | null
  httpsReachable: boolean
  outcome: LookupOutcome
  detail: string | null
}

export type SiteProbe = {
  name: string
  dnsSource: string
  resolve: (hostname: string, signal?: AbortSignal) => Promise<ResolveResult>
  queryRecords: (
    hostname: string,
    type: WebsiteRecordType,
    signal?: AbortSignal,
  ) => Promise<RecordQueryResult>
  lookupAsn: (address: string, signal?: AbortSignal) => Promise<AsnQueryResult>
  /**
   * Opsional karena tidak setiap platform bisa menghubungi registry secara aman.
   * Probe tanpa kemampuan ini membuat umur registrasi dilaporkan `unavailable`,
   * bukan dinilai aman.
   */
  lookupRegistration?: (domain: string, signal?: AbortSignal) => Promise<RegistrationQueryResult>
  inspectTls: (
    hostname: string,
    address: string,
    kind: 'ipv4' | 'ipv6',
    port: number,
    signal?: AbortSignal,
  ) => Promise<TlsProbeResult>
  openOrigin: (request: OriginRequest, signal?: AbortSignal) => Promise<OriginResult>
}

export type SiteAnalysisResponse = {
  version: 1
  target: string
  hostname: string
  generatedAt: string
  durationMs: number
  probe: {
    available: boolean
    name: string
    detail: string | null
  }
  website: WebsiteIntelligence
  technology: TechnologyAnalysis
  behavior: BehaviorAnalysis
  category: WebsiteCategoryAssessment
  registration: DomainAgeAnalysis
  page: PageAnalysis
  risk: RiskFusion
}

export const EVIDENCE_CATEGORIES = [
  'url_structure',
  'brand',
  'dns',
  'registration',
  'tls',
  'page_content',
  'form',
  'redirect',
  'script',
  'category',
  'network',
] as const

export type EvidenceCategory = (typeof EVIDENCE_CATEGORIES)[number]

export type EvidenceStrength = 'strong' | 'moderate' | 'weak' | 'mitigating'

export type EvidenceAvailability = 'observed' | 'unavailable' | 'failed' | 'not_applicable'

/**
 * Satu butir bukti hasil fusi. Yang wajib adalah jejak asalnya: modul mana yang
 * mengamati, kapan, dan apakah pemeriksaan itu benar-benar berhasil. Bukti yang
 * tidak tersedia tidak pernah menyumbang skor, positif maupun negatif.
 */
export type FusedEvidence = {
  id: string
  category: EvidenceCategory
  label: string
  detail: string
  observed: string | null
  source: string
  strength: EvidenceStrength
  availability: EvidenceAvailability
  observedAt: string | null
}

export type RiskLevel = 'unknown' | 'low' | 'medium' | 'high' | 'critical'

export type ScanStatus = 'complete' | 'partial' | 'limited' | 'failed'

export type EvidenceCoverage = {
  totalChecks: number
  succeeded: number
  unavailable: number
  failed: number
  ratio: number | null
  byCategory: Array<{ category: EvidenceCategory; succeeded: number; total: number }>
}

export type RiskFusion = {
  status: ScanStatus
  level: RiskLevel
  riskScore: number | null
  confidence: 'high' | 'medium' | 'low'
  confidenceDetail: string
  coverage: EvidenceCoverage
  evidence: FusedEvidence[]
  notEvaluated: string[]
  notes: string[]
}


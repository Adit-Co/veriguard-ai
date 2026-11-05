/**
 * Cermin tipe respons `functions/src/website/types.ts`. Data ini datang dari
 * backend dan dianggap tidak tepercaya sampai divalidasi di `validate.ts`.
 */

export const WEBSITE_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA'] as const

export type WebsiteRecordType = (typeof WEBSITE_RECORD_TYPES)[number]

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

export type TechnologyCategory =
  | 'frontend'
  | 'library'
  | 'css'
  | 'cms'
  | 'server'
  | 'analytics'
  | 'other'

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

export const WEBSITE_CATEGORY_LABELS: Record<WebsiteCategoryId, string> = {
  gambling: 'Judi online',
  phishing: 'Phishing',
  scam: 'Penipuan',
  malware: 'Malware',
  marketplace: 'Marketplace',
  banking: 'Perbankan / finansial',
  government: 'Pemerintahan',
  education: 'Pendidikan',
  media: 'Media',
  social: 'Media sosial',
  technology: 'Teknologi',
  entertainment: 'Hiburan',
  business: 'Bisnis',
  blog: 'Blog / informasi',
  personal: 'Website pribadi',
  unknown: 'Tidak diketahui',
}

export const RISK_WEBSITE_CATEGORY_IDS: readonly WebsiteCategoryId[] = [
  'gambling',
  'phishing',
  'scam',
  'malware',
]

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

/**
 * Cermin `DomainAgeAnalysis` di backend. Dinormalisasi menjadi null bila respons
 * lama tidak mengirim bagian ini sama sekali; null berarti "tidak dikembalikan",
 * bukan "domain bersih".
 */
export const DOMAIN_AGE_CODES = [
  'domain_young',
  'domain_recent',
  'domain_mature',
  'registration_expiring',
  'registration_date_missing',
  'registration_unavailable',
] as const

export type DomainAgeCode = (typeof DOMAIN_AGE_CODES)[number]

export type DomainRegistration = {
  domain: string
  handle: string | null
  registrar: string | null
  createdAt: string | null
  changedAt: string | null
  expiresAt: string | null
  statuses: string[]
}

export type DomainAgeFinding = {
  code: DomainAgeCode
  label: string
  detail: string
  strength: EvidenceStrength
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

/**
 * Cermin `RiskLevel` backend. Nama diberi awalan "Site" karena heuristik leksikal
 * `lib/analysis` punya `RiskLevel` sendiri tanpa anggota "unknown"; level di sini
 * bisa "unknown" justru ketika bukti tidak cukup untuk menyimpulkan apa pun.
 */
export type SiteRiskLevel = 'unknown' | 'low' | 'medium' | 'high' | 'critical'

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
  level: SiteRiskLevel
  riskScore: number | null
  confidence: 'high' | 'medium' | 'low'
  confidenceDetail: string
  coverage: EvidenceCoverage
  evidence: FusedEvidence[]
  notEvaluated: string[]
  notes: string[]
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
  registration: DomainAgeAnalysis | null
  page: PageAnalysis | null
  risk: RiskFusion | null
}

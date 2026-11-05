export const EXTERNAL_PROVIDER_IDS = [
  'urlscan',
  'virustotal',
  'openphish',
  'threatfox',
  'radar',
  'otx',
  'hybrid',
  'safebrowsing',
] as const

export type ExternalProviderId = (typeof EXTERNAL_PROVIDER_IDS)[number]
export type ProviderId = 'internal' | ExternalProviderId

export type ProviderStatus =
  | 'success'
  | 'not_found'
  | 'not_configured'
  | 'auth_failed'
  | 'unavailable'
  | 'rate_limited'
  | 'skipped'
  | 'timeout'
  // Provider menolak bentuk permintaan kami (HTTP 400/422). Bukan vonis: sama seperti
  // kegagalan lain, status ini tidak pernah menaikkan maupun menurunkan risiko.
  | 'invalid_request'
  | 'error'

export type ProviderVerdict =
  | 'malicious'
  | 'suspicious'
  | 'clean'
  | 'inconclusive'

export type ProviderSignalSeverity = 'info' | 'warning' | 'danger'

export type ProviderSignal = {
  label: string
  detail: string
  severity: ProviderSignalSeverity
}

export type ProviderEvidenceSource = 'existing_report' | 'new_scan'

// Asal bukti hasil agen: laporan yang sudah ada tidak pernah boleh tampil sebagai
// pemindaian langsung, sehingga umur laporan ikut dikirim.
export type ProviderEvidence = {
  source: ProviderEvidenceSource
  observedAt: string | null
  ageMs: number | null
}

// VGL-31 TAHAP 2 — kontrak bukti negatif, identik dengan bentuk backend. Ketiadaan field ini
// berarti "tidak ada bukti kebersihan", termasuk untuk semua status kegagalan.
export type NegativeEvidenceStrength = 'explicit' | 'limited'

export type NegativeEvidenceClass =
  | 'scan_verdict'
  | 'engine_verdicts'
  | 'scanner_verdict'
  | 'threat_list'

export type NegativeEvidence = {
  strength: NegativeEvidenceStrength
  scope: 'url' | 'domain'
  evidenceClass: NegativeEvidenceClass
  basis: string
}

// VGL-31 TAHAP 3 — empat dimensi yang selama ini disatukan oleh satu angka, kini dipisahkan:
// A skor risiko, B kecukupan bukti, C cakupan agen, D keyakinan vonis. Tidak satunya boleh
// direduksi menjadi yang lain.
export type EvidenceSufficiencyLevel = 'insufficient' | 'limited' | 'sufficient'

export type EvidenceSufficiency = {
  level: EvidenceSufficiencyLevel
  // Bukti negatif EKSPLISIT atas URL ini, dihitung per kelas agar dua agen dengan kebiasaan
  // sama tidak dihitung dua kali.
  confirmedClean: number
  confirmedCleanClasses: NegativeEvidenceClass[]
  // Bukti negatif terbatas (mis. daftar ancaman yang menjawab kosong): mendukung, tapi tidak
  // pernah cukup untuk menghasilkan vonis bersih sendirian.
  limitedNegatives: number
  requiredConfirmedClean: number
  // Alasan terbaca mengapa Risiko Rendah belum boleh diberikan.
  blockingReasons: string[]
}

export type ProviderCoverage = {
  // Agen yang mengembalikan hasil yang dapat dibaca (sukses atau tidak ada kecocokan).
  answered: number
  total: number
  noMatch: number
  usableNegativeEvidence: number
  positiveFindings: number
  // Timeout, galat, tidak tersedia, dibatasi, autentikasi gagal, permintaan ditolak,
  // tidak dikonfigurasi, atau dilewati. Kegiatannya BUKAN bukti kebersihan.
  unresolved: number
  percent: number
}

export type VerdictConfidence = 'low' | 'medium' | 'high'

export type ProviderResult = {
  id: ProviderId
  label: string
  status: ProviderStatus
  verdict: ProviderVerdict
  score: number | null
  summary: string
  signals: ProviderSignal[]
  reason: string | null
  durationMs: number
  evidence?: ProviderEvidence
  negative?: NegativeEvidence
  // Riwayat cache hasil agen. Opsional: respons backend versi lama tidak mengirimnya,
  // dan ketiadaan field berarti "hasil baru pada pemeriksaan ini".
  cache?: ProviderResultCache
}

// Metadata pemakaian cache untuk satu hasil agen. Namanya sengaja mengikuti bentuk backend
// (observedAt/ageMs seperti ProviderEvidence): hit = cacheHit, observedAt = waktu hasil
// diperoleh, ageMs = umur, stale = apakah bukti hulunya sudah lewat batas segarnya.
export type ProviderResultCache = {
  hit: boolean
  observedAt: string
  ageMs: number
  stale: boolean
}

export type ScanCacheStatus = 'hit' | 'partial' | 'miss'

export type ScanCacheMeta = {
  status: ScanCacheStatus
  hit: boolean
  observedAt: string | null
  ageMs: number
  reusedProviders: ExternalProviderId[]
  refreshedProviders: ExternalProviderId[]
  requestsAvoided: number
  deduplicated?: boolean
}

export type ExternalProviderResult = ProviderResult & { id: ExternalProviderId }

export type ScanUrlMultiSourceResponse = {
  providers: ExternalProviderResult[]
  sharedWithProviders: ExternalProviderId[]
  sensitiveUrl: boolean
  privacyReasons: string[]
  generatedAt: string
  durationMs: number
  cache?: ScanCacheMeta
}

export type ProviderProgressState = 'queued' | 'running' | 'completed'

export type ProviderProgress = {
  id: ExternalProviderId
  label: string
  state: ProviderProgressState
  result?: ExternalProviderResult
  shared?: boolean
}

export type ScanProgressEvent =
  | {
      type: 'init'
      scanId: string
      startedAt: string
      sensitiveUrl: boolean
      privacyReasons: string[]
      providers: Array<{
        id: ExternalProviderId
        label: string
        state: 'queued'
      }>
    }
  | {
      type: 'provider'
      scanId: string
      provider: ProviderProgress
    }
  | {
      type: 'done'
      scanId: string
      response: ScanUrlMultiSourceResponse
    }

export type ScanStreamErrorEvent = {
  type: 'error'
  scanId: string
  code: string
  message: string
}

export type ReportCompleteness = {
  checked: number
  total: number
  percent: number
  success: number
  notFound: number
  notConfigured?: number
  authFailed?: number
  unavailable: number
  rateLimited: number
  skipped?: number
  timeout?: number
  error: number
}

export type MultiSourceReport = {
  // VGL-31 TAHAP 3 — versi 2 menambahkan tiga dimensi terpisah di bawah. Versi 1 adalah riwayat
  // yang sudah tersimpan di perangkat pengguna: tetap sah, dan dimensinya diturunkan ulang di
  // klien dari baris agen yang ada, bukan dibuang.
  version: 1 | 2
  target: string
  hostname: string
  verdict: ProviderVerdict
  score: number
  completeness: ReportCompleteness
  evidenceSufficiency?: EvidenceSufficiency
  providerCoverage?: ProviderCoverage
  verdictConfidence?: VerdictConfidence
  providers: ProviderResult[]
  conflicts: string[]
  notes: string[]
  externalRequested: boolean
  externalShared: boolean
  externalError?: string | null
  sensitiveUrl: boolean
  privacyReasons: string[]
  generatedAt: string
  durationMs: number
  cache?: ScanCacheMeta
}

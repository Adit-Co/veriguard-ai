import {
  EXTERNAL_PROVIDER_IDS,
  type ExternalProviderId,
  type ExternalProviderResult,
  type MultiSourceReport,
  type ProviderId,
  type ProviderResult,
  type ProviderSignal,
  type ProviderProgressState,
  type ProviderStatus,
  type ProviderVerdict,
  type ScanProgressEvent,
  type ScanStreamErrorEvent,
  type ScanUrlMultiSourceResponse,
} from './types'

const PROVIDER_IDS = new Set<ProviderId>(['internal', ...EXTERNAL_PROVIDER_IDS])
const EXTERNAL_IDS = new Set<string>(EXTERNAL_PROVIDER_IDS)
const STATUSES = new Set<ProviderStatus>([
  'success',
  'not_found',
  'not_configured',
  'auth_failed',
  'unavailable',
  'rate_limited',
  'skipped',
  'timeout',
  'invalid_request',
  'error',
])
const VERDICTS = new Set<ProviderVerdict>([
  'malicious',
  'suspicious',
  'clean',
  'inconclusive',
])
const SEVERITIES = new Set(['info', 'warning', 'danger'])
const NEGATIVE_STRENGTHS = new Set(['explicit', 'limited'])
const NEGATIVE_SCOPES = new Set(['url', 'domain'])
const NEGATIVE_CLASSES = new Set([
  'scan_verdict',
  'engine_verdicts',
  'scanner_verdict',
  'threat_list',
])
const SUFFICIENCY_LEVELS = new Set(['insufficient', 'limited', 'sufficient'])
const CONFIDENCE_LEVELS = new Set(['low', 'medium', 'high'])

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

function isScore(value: unknown): boolean {
  return value === null || (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100)
}

function isSignal(value: unknown): value is ProviderSignal {
  return (
    isRecord(value) &&
    typeof value.label === 'string' &&
    typeof value.detail === 'string' &&
    typeof value.severity === 'string' &&
    SEVERITIES.has(value.severity)
  )
}

function isEvidence(value: unknown): boolean {
  if (value === undefined) return true
  if (!isRecord(value)) return false
  if (value.source !== 'existing_report' && value.source !== 'new_scan') return false
  if (!(value.observedAt === null || typeof value.observedAt === 'string')) return false
  if (typeof value.ageMs !== 'number' || !Number.isFinite(value.ageMs) || value.ageMs < 0) {
    return false
  }
  return value.observedAt === null || isIsoDate(value.observedAt)
}

function isProviderCache(value: unknown): boolean {
  if (value === undefined) return true
  if (!isRecord(value)) return false
  if (typeof value.hit !== 'boolean') return false
  if (typeof value.stale !== 'boolean') return false
  if (typeof value.ageMs !== 'number' || !Number.isFinite(value.ageMs) || value.ageMs < 0) {
    return false
  }
  return isIsoDate(value.observedAt)
}

function isExternalIdArray(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.every((id): id is ExternalProviderId => typeof id === 'string' && EXTERNAL_IDS.has(id))
  )
}

// Metadata cache tingkat respons. Opsional demi kompatibilitas dengan backend versi lama,
// tetapi bila ada bentuknya harus sah dan konsisten: jumlah permintaan yang dihemat tidak
// boleh melebihi daftar agen yang benar-benar dipakai ulang.
function isScanCacheMeta(value: unknown): boolean {
  if (value === undefined) return true
  if (!isRecord(value)) return false

  const status = value.status
  if (status !== 'hit' && status !== 'partial' && status !== 'miss') return false
  if (typeof value.hit !== 'boolean') return false
  if (!(value.observedAt === null || isIsoDate(value.observedAt))) return false
  if (typeof value.ageMs !== 'number' || !Number.isFinite(value.ageMs) || value.ageMs < 0) {
    return false
  }
  if (typeof value.deduplicated !== 'boolean' && value.deduplicated !== undefined) return false
  if (!isExternalIdArray(value.reusedProviders) || !isExternalIdArray(value.refreshedProviders)) {
    return false
  }

  const reused = value.reusedProviders as unknown[]
  const refreshed = value.refreshedProviders as unknown[]
  const requestsAvoided = value.requestsAvoided

  // Status harus cocok dengan daftar agen yang dipakai ulang. Tanpa ini, satu bilangan
  // "hit" palsu bisa membuat antarmuka menjanjikan penghematan yang tidak pernah terjadi.
  const coherentStatus =
    (status === 'miss' && value.hit === false && reused.length === 0 &&
      value.observedAt === null) ||
    (status === 'partial' && value.hit === false && reused.length > 0 &&
      refreshed.length > 0 && value.observedAt !== null) ||
    (status === 'hit' && value.hit === true && reused.length > 0 && refreshed.length === 0 &&
      value.observedAt !== null)

  return (
    coherentStatus &&
    typeof requestsAvoided === 'number' &&
    Number.isInteger(requestsAvoided) &&
    requestsAvoided >= 0 &&
    requestsAvoided === reused.length &&
    requestsAvoided <= EXTERNAL_PROVIDER_IDS.length &&
    reused.length + refreshed.length <= EXTERNAL_PROVIDER_IDS.length
  )
}

// VGL-31 — penanda bukti negatif adalah satu-satunya jalan sah menuju vonis Risiko Rendah,
// jadi bentuknya diverifikasi dan BUKAN dianggap anotasi bebas. Payload yang membawa penanda
// rusak membuat seluruh respons ditolak oleh pemanggil, sehingga kegagalan terbaca sebagai
// "Belum Konklusif", bukan sebagai "bersih".
function isNegativeEvidence(value: unknown): boolean {
  if (value === undefined) return true
  if (!isRecord(value)) return false
  return (
    typeof value.strength === 'string' &&
    NEGATIVE_STRENGTHS.has(value.strength) &&
    typeof value.scope === 'string' &&
    NEGATIVE_SCOPES.has(value.scope) &&
    typeof value.evidenceClass === 'string' &&
    NEGATIVE_CLASSES.has(value.evidenceClass) &&
    typeof value.basis === 'string'
  )
}

function isCount(value: unknown): boolean {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0
}

// Tiga dimensi VGL-31. Opsional agar riwayat versi 1 tetap dapat dimuat; bila ada, bentuknya
// harus lengkap supaya antarmuka tidak pernah menampilkan angka yang mengada-ada.
function isEvidenceSufficiency(value: unknown): boolean {
  if (value === undefined) return true
  if (!isRecord(value)) return false
  return (
    typeof value.level === 'string' &&
    SUFFICIENCY_LEVELS.has(value.level) &&
    isCount(value.confirmedClean) &&
    isCount(value.limitedNegatives) &&
    isCount(value.requiredConfirmedClean) &&
    Array.isArray(value.confirmedCleanClasses) &&
    value.confirmedCleanClasses.every(
      (item) => typeof item === 'string' && NEGATIVE_CLASSES.has(item),
    ) &&
    isStringArray(value.blockingReasons)
  )
}

function isProviderCoverage(value: unknown): boolean {
  if (value === undefined) return true
  if (!isRecord(value)) return false
  if (!isCount(value.noMatch) || !isCount(value.usableNegativeEvidence) || !isCount(value.positiveFindings)) {
    return false
  }

  const { answered, unresolved, total, percent } = value
  if (!isCount(answered) || !isCount(unresolved) || !isCount(total)) return false
  if (typeof percent !== 'number' || !Number.isFinite(percent) || percent < 0 || percent > 100) {
    return false
  }

  // Cakupan harus menutupi roster. Backend dapat mengirim roster lebih kecil saat deploy
  // bertahap (agen yang tidak dikirim dihitung belum menjawab), jadi jumlahnya bukan
  // persamaan ketat melainkan batas: terjawab + belum terjawab menutup total.
  const answeredCount = answered as number
  const unresolvedCount = unresolved as number
  const totalCount = total as number
  return answeredCount + unresolvedCount >= totalCount && answeredCount <= totalCount
}

function isVerdictConfidence(value: unknown): boolean {
  if (value === undefined) return true
  return typeof value === 'string' && CONFIDENCE_LEVELS.has(value)
}

function isProviderResult(value: unknown): value is ProviderResult {
  return (
    isRecord(value) &&
    typeof value.id === 'string' &&
    PROVIDER_IDS.has(value.id as ProviderId) &&
    typeof value.label === 'string' &&
    typeof value.status === 'string' &&
    STATUSES.has(value.status as ProviderStatus) &&
    typeof value.verdict === 'string' &&
    VERDICTS.has(value.verdict as ProviderVerdict) &&
    isScore(value.score) &&
    typeof value.summary === 'string' &&
    Array.isArray(value.signals) &&
    value.signals.every(isSignal) &&
    (value.reason === null || typeof value.reason === 'string') &&
    typeof value.durationMs === 'number' &&
    Number.isFinite(value.durationMs) &&
    value.durationMs >= 0 &&
    isEvidence(value.evidence) &&
    isNegativeEvidence(value.negative) &&
    isProviderCache(value.cache)
  )
}

function isExternalProviderResult(value: unknown): value is ExternalProviderResult {
  return (
    isProviderResult(value) &&
    typeof value.id === 'string' &&
    EXTERNAL_IDS.has(value.id)
  )
}

function isIsoDate(value: unknown): boolean {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value))
}

// Roster bertambah seiring waktu (6 -> 7 -> 8 agen) sedangkan backend dapat masih
// menjalankan registry versi lama saat deploy bertahap. Payload dengan lebih sedikit
// agen tetap dipakai; agen yang tidak dikirim backend ditampilkan sebagai skipped
// oleh report builder. Bentuk tetap diverifikasi: id dikenal, unik, dan tidak
// melebihi roster yang diketahui aplikasi.
function isRosterSubset(providers: ExternalProviderResult[]): boolean {
  if (providers.length === 0) return false
  const ids = new Set(providers.map((provider) => provider.id))
  return (
    ids.size === providers.length &&
    providers.length <= EXTERNAL_PROVIDER_IDS.length &&
    providers.every((provider) => EXTERNAL_IDS.has(provider.id))
  )
}

function hasUniqueExternalProviders(ids: ExternalProviderId[]): boolean {
  return new Set(ids).size === ids.length
}

function hasAllReportProviders(providers: ProviderResult[]): boolean {
  const ids = new Set(providers.map((provider) => provider.id))

  // Sejak VGL-30K-R1 laporan hanya berisi baris agen eksternal. Laporan lama masih tersimpan
  // di localStorage pengguna dan bisa memuat satu baris "internal", jadi kehadirannya
  // ditoleransi (riwayat tidak dibuang) sementara jumlahnya tetap diverifikasi: id dikenal,
  // unik, dan tidak lebih banyak baris daripada roster yang dikenal aplikasi.
  return (
    ids.size === providers.length &&
    providers.length <= EXTERNAL_PROVIDER_IDS.length + 1 &&
    providers.every((provider) => PROVIDER_IDS.has(provider.id))
  )
}

function isCompletenessConsistent(completeness: unknown, providers: unknown): boolean {
  if (!isRecord(completeness) || !Array.isArray(providers)) return false
  if (typeof completeness.total !== 'number') return false

  const external = providers.filter((provider) => isRecord(provider) && provider.id !== 'internal')
  return completeness.total === external.length
}

function isCompleteness(value: unknown): boolean {
  if (!isRecord(value)) return false

  const required = [
    'checked',
    'total',
    'percent',
    'success',
    'notFound',
    'unavailable',
    'rateLimited',
    'error',
  ]
  const optional = ['notConfigured', 'authFailed', 'skipped', 'timeout']

  return (
    required.every((key) => typeof value[key] === 'number' && Number.isFinite(value[key])) &&
    optional.every(
      (key) =>
        value[key] === undefined ||
        (typeof value[key] === 'number' && Number.isFinite(value[key])),
    )
  )
}

export function parseMultiSourceResponse(value: unknown): ScanUrlMultiSourceResponse {
  if (!isRecord(value)) {
    throw new Error('Respons pemeriksaan eksternal tidak valid.')
  }

  if (
    !Array.isArray(value.providers) ||
    !value.providers.every(isExternalProviderResult) ||
    !isRosterSubset(value.providers) ||
    !Array.isArray(value.sharedWithProviders) ||
    !value.sharedWithProviders.every(
      (id): id is ExternalProviderId =>
        typeof id === 'string' && EXTERNAL_IDS.has(id),
    ) ||
    !hasUniqueExternalProviders(value.sharedWithProviders) ||
    typeof value.sensitiveUrl !== 'boolean' ||
    !isStringArray(value.privacyReasons) ||
    !isIsoDate(value.generatedAt) ||
    typeof value.durationMs !== 'number' ||
    !Number.isFinite(value.durationMs) ||
    value.durationMs < 0 ||
    !isScanCacheMeta(value.cache)
  ) {
    throw new Error('Respons pemeriksaan eksternal tidak valid.')
  }

  return value as ScanUrlMultiSourceResponse
}

const PROGRESS_STATES = new Set<ProviderProgressState>([
  'queued',
  'running',
  'completed',
])

export function parseScanProgressEvent(value: unknown): ScanProgressEvent {
  if (!isRecord(value) || typeof value.scanId !== 'string') {
    throw new Error('Event pemeriksaan eksternal tidak valid.')
  }

  if (value.type === 'init') {
    if (
      !isIsoDate(value.startedAt) ||
      typeof value.sensitiveUrl !== 'boolean' ||
      !isStringArray(value.privacyReasons) ||
      !Array.isArray(value.providers) ||
      !value.providers.every(
        (provider) =>
          isRecord(provider) &&
          typeof provider.id === 'string' &&
          EXTERNAL_IDS.has(provider.id) &&
          typeof provider.label === 'string' &&
          provider.state === 'queued',
      )
    ) {
      throw new Error('Event pemeriksaan eksternal tidak valid.')
    }
    return value as ScanProgressEvent
  }

  if (value.type === 'provider') {
    if (!isRecord(value.provider)) {
      throw new Error('Event pemeriksaan eksternal tidak valid.')
    }

    const provider = value.provider
    if (
      typeof provider.id !== 'string' ||
      !EXTERNAL_IDS.has(provider.id) ||
      typeof provider.label !== 'string' ||
      typeof provider.state !== 'string' ||
      !PROGRESS_STATES.has(provider.state as ProviderProgressState) ||
      (provider.result !== undefined && !isExternalProviderResult(provider.result)) ||
      (provider.shared !== undefined && typeof provider.shared !== 'boolean')
    ) {
      throw new Error('Event pemeriksaan eksternal tidak valid.')
    }
    return value as ScanProgressEvent
  }

  if (value.type === 'done') {
    return {
      type: 'done',
      scanId: value.scanId,
      response: parseMultiSourceResponse(value.response),
    }
  }

  throw new Error('Event pemeriksaan eksternal tidak valid.')
}

export function parseScanStreamErrorEvent(value: unknown): ScanStreamErrorEvent {
  if (
    !isRecord(value) ||
    value.type !== 'error' ||
    typeof value.scanId !== 'string' ||
    typeof value.code !== 'string' ||
    typeof value.message !== 'string'
  ) {
    throw new Error('Respons pemeriksaan eksternal tidak valid.')
  }

  return value as ScanStreamErrorEvent
}

export function isMultiSourceReport(value: unknown): value is MultiSourceReport {
  if (!isRecord(value)) return false

  return (
    (value.version === 1 || value.version === 2) &&
    typeof value.target === 'string' &&
    typeof value.hostname === 'string' &&
    typeof value.verdict === 'string' &&
    VERDICTS.has(value.verdict as ProviderVerdict) &&
    typeof value.score === 'number' &&
    Number.isFinite(value.score) &&
    value.score >= 0 &&
    value.score <= 100 &&
    isCompleteness(value.completeness) &&
    isCompletenessConsistent(value.completeness, value.providers) &&
    isEvidenceSufficiency(value.evidenceSufficiency) &&
    isProviderCoverage(value.providerCoverage) &&
    isVerdictConfidence(value.verdictConfidence) &&
    Array.isArray(value.providers) &&
    value.providers.every(isProviderResult) &&
    hasAllReportProviders(value.providers) &&
    isStringArray(value.conflicts) &&
    isStringArray(value.notes) &&
    typeof value.externalRequested === 'boolean' &&
    typeof value.externalShared === 'boolean' &&
    (value.externalError === undefined ||
      value.externalError === null ||
      typeof value.externalError === 'string') &&
    typeof value.sensitiveUrl === 'boolean' &&
    isStringArray(value.privacyReasons) &&
    isIsoDate(value.generatedAt) &&
    isScanCacheMeta(value.cache) &&
    typeof value.durationMs === 'number' &&
    Number.isFinite(value.durationMs) &&
    value.durationMs >= 0
  )
}

import type { FetchJsonResult } from './http.js'
import type { ProviderCheck } from './types.js'

export function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

export function recordValue(value: unknown): Record<string, unknown> | null {
  return isRecord(value) ? value : null
}

export function stringValue(value: unknown): string | null {
  return typeof value === 'string' ? value : null
}

export function numberValue(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

export function booleanValue(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null
}

export function stringList(value: unknown, limit = 4): string[] {
  if (!Array.isArray(value)) return []

  return value
    .filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
    .map((item) => item.trim().slice(0, 120))
    .slice(0, limit)
}

export function clampScore(value: number): number {
  return Math.min(100, Math.max(0, Math.round(value)))
}

// Waktu kejadian nyata (analisis terakhir provider, unduhan feed terakhir) ditampilkan sebagai
// tanggal jam, bukan sebagai umur relatif. Umur relatif terbaca seperti umur entri cache meski
// yang dimaksud adalah waktu data provider, dan itu persis narasi yang tidak boleh muncul.
const OBSERVED_AT_FORMAT = new Intl.DateTimeFormat('id-ID', {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  timeZone: 'UTC',
})

export function formatObservedAt(iso: string): string {
  const ms = Date.parse(iso)
  if (!Number.isFinite(ms)) return 'waktu tidak diketahui'
  return `${OBSERVED_AT_FORMAT.format(new Date(ms))} UTC`
}

// Asal bukti disimpan sebagai METADATA terstruktur, bukan sebagai kalimat di dalam
// `summary`/`reason`. Teks bebas ikut tersimpan di laporan riwayat dan ikut ter-serialisasi
// ke klien, jadi satu kata pun tentang mekanisme laporan-ulan di sini akan bocor ke
// antarmuka selamanya. Penanda `evidence` tetap akurat: vonis dari laporan lama tidak pernah
// tampil sebagai pemindaian langsung karena umur laporannya ikut dikirim dan dirender apa
// adanya. Provenance dijelaskan lewat `observedAt`, bukan lewat narasi.
export function withExistingReportEvidence(
  check: ProviderCheck,
  observedAt: string | null,
  ageMs: number | null,
): ProviderCheck {
  return {
    ...check,
    evidence: { source: 'existing_report', observedAt, ageMs },
  }
}

export function skippedCheck(reason: string): ProviderCheck {
  return {
    status: 'skipped',
    verdict: 'inconclusive',
    score: null,
    summary: 'Provider tidak dijalankan.',
    signals: [],
    reason,
  }
}

export function timeoutCheck(reason: string): ProviderCheck {
  return {
    status: 'timeout',
    verdict: 'inconclusive',
    score: null,
    summary: 'Provider melewati batas waktu.',
    signals: [],
    reason,
  }
}

export function notConfiguredCheck(reason: string): ProviderCheck {
  return {
    status: 'not_configured',
    verdict: 'inconclusive',
    score: null,
    summary: 'Provider belum dikonfigurasi di backend.',
    signals: [],
    reason,
  }
}

export function authFailedCheck(reason: string): ProviderCheck {
  return {
    status: 'auth_failed',
    verdict: 'inconclusive',
    score: null,
    summary: 'Autentikasi ke provider gagal.',
    signals: [],
    reason,
  }
}

export function errorCheck(reason: string): ProviderCheck {
  return {
    status: 'error',
    verdict: 'inconclusive',
    score: null,
    summary: 'Pemeriksaan provider gagal.',
    signals: [],
    reason,
  }
}

export function notFoundCheck(summary: string): ProviderCheck {
  return {
    status: 'not_found',
    verdict: 'inconclusive',
    score: null,
    summary,
    signals: [],
    reason: null,
  }
}

export function failureCheck(result: Extract<FetchJsonResult, { ok: false }>): ProviderCheck {
  if (result.kind === 'rate_limited') {
    return {
      status: 'rate_limited',
      verdict: 'inconclusive',
      score: null,
      summary: 'Kuota provider tercapai.',
      signals: [],
      reason: withHttpStatus(result),
    }
  }

  if (result.kind === 'invalid_request') {
    return {
      status: 'invalid_request',
      verdict: 'inconclusive',
      score: null,
      summary: 'Permintaan pemeriksaan ditolak provider.',
      signals: [],
      reason: withHttpStatus(result),
    }
  }

  if (result.kind === 'not_found') {
    return notFoundCheck('Provider tidak memiliki data untuk URL ini.')
  }

  if (result.kind === 'not_configured') {
    return notConfiguredCheck(result.reason)
  }

  if (result.kind === 'auth_failed') {
    return authFailedCheck(withHttpStatus(result))
  }

  if (result.kind === 'timeout') {
    return timeoutCheck(result.reason)
  }

  if (result.kind === 'skipped') {
    return skippedCheck(result.reason)
  }

  return {
    status: result.kind === 'success' ? 'error' : result.kind,
    verdict: 'inconclusive',
    score: null,
    summary:
      result.kind === 'unavailable'
        ? 'Provider sedang tidak tersedia.'
        : 'Pemeriksaan provider gagal.',
    signals: [],
    reason: withHttpStatus(result),
  }
}

// Sufiks status hanya ditempel kalau reason belum memuatnya. Sebagian reason dari http.ts
// sudah menulis "(HTTP n)" sendiri (mis. "Provider menolak permintaan (HTTP 400)."), jadi
// append tanpa cek menghasilkan pesan berulang di antarmuka.
export function withHttpStatus(result: Extract<FetchJsonResult, { ok: false }>): string {
  if (result.status === null) return result.reason

  const suffix = `(HTTP ${result.status})`
  return result.reason.includes(suffix) ? result.reason : `${result.reason} ${suffix}`
}

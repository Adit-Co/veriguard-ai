import { fetchJson } from '../http.js'
import {
  authFailedCheck,
  clampScore,
  errorCheck,
  failureCheck,
  isRecord,
  notConfiguredCheck,
  notFoundCheck,
  numberValue,
  recordValue,
  stringList,
  stringValue,
} from '../result.js'
import type { ProviderAdapter, ProviderCheck, ProviderSignal } from '../types.js'

const API_ENDPOINT = 'https://threatfox-api.abuse.ch/api/v1/'
const REQUEST_TIMEOUT_MS = 8_000
const MAX_TERMS = 3
// Baris dan teks yang diturunkan dari respons provider selalu dibatasi: bentuk respons bukan
// sesuatu yang kita kendalikan, sementara isinya mengalir ke laporan dan riwayat pengguna.
const MAX_ROWS_PER_TERM = 20
const MAX_TEXT_LENGTH = 120

function clip(value: string | null): string | null {
  if (value === null) return null
  const trimmed = value.trim()
  if (!trimmed) return null
  return trimmed.length > MAX_TEXT_LENGTH ? `${trimmed.slice(0, MAX_TEXT_LENGTH)}…` : trimmed
}

function withoutScheme(value: string): string {
  return value.trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/\/$/, '')
}

function hostnameOf(value: string): string | null {
  const trimmed = value.trim()
  if (!trimmed) return null
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`
  try {
    return new URL(candidate).hostname.toLowerCase()
  } catch {
    return null
  }
}

// Tingkat kecocokan IOC yang dikembalikan provider dibanding bentuk yang kita cari.
type MatchLevel = 'exact' | 'host' | 'unrelated'

// Bentuk IOC yang dicari hanya bergantung pada istilahnya, bukan pada baris respons, jadi
// dihitung sekali per istilah lalu dipakai ulang untuk setiap baris.
type TermShape = { normalized: string; host: string | null }

function termShapeOf(term: string): TermShape {
  return { normalized: withoutScheme(term), host: hostnameOf(term) }
}

function classifyRow(ioc: string | null, term: TermShape): MatchLevel {
  if (ioc === null) return 'unrelated'
  if (withoutScheme(ioc) === term.normalized) return 'exact'
  const iocHost = hostnameOf(ioc)
  return iocHost !== null && iocHost === term.host ? 'host' : 'unrelated'
}

type TermOutcome =
  | { term: string; kind: 'match'; rows: Record<string, unknown>[] }
  | { term: string; kind: 'empty' }
  | { term: string; kind: 'auth'; status: string }
  | { term: string; kind: 'unknown'; status: string }
  | { term: string; kind: 'failed'; reason: string; rateLimited: boolean }

// ThreatFox menyimpan IOC pada beberapa bentuk (url, domain, ip:port) dan exact_match hanya
// membandingkan byte persis, jadi beberapa bentuk ditanyakan terpisah.
function searchTerms(url: string, hostname: string): string[] {
  const terms: string[] = []
  const push = (value: string | null): void => {
    if (value && !terms.includes(value)) terms.push(value)
  }

  push(url)

  try {
    const parsed = new URL(url)
    push(`${parsed.protocol}//${parsed.host}${parsed.pathname}`)
    if (parsed.pathname === '/' || parsed.pathname === '') {
      push(`${parsed.protocol}//${parsed.host}/`)
    }
  } catch {
    // Bentuk tambahan dilewati bila URL tidak dapat diurai ulang.
  }

  // Domain adalah tipe IOC tersendiri di ThreatFox.
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) && !hostname.startsWith('[')) {
    push(hostname)
  }

  return terms.slice(0, MAX_TERMS)
}

function describeTerm(term: string, url: string, hostname: string): string {
  if (term === url) return 'URL persis'
  if (term === hostname) return 'hostname'
  if (!term.includes('/')) return 'hostname'
  return 'URL tanpa parameter kueri'
}

async function queryTerm(
  context: Parameters<ProviderAdapter['check']>[0],
  apiKey: string,
  term: string,
): Promise<TermOutcome> {
  const response = await fetchJson(
    context.fetchImpl,
    API_ENDPOINT,
    {
      method: 'POST',
      headers: {
        'Auth-Key': apiKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query: 'search_ioc',
        search_term: term,
        exact_match: true,
      }),
    },
    REQUEST_TIMEOUT_MS,
  )

  if (!response.ok) {
    return {
      term,
      kind: 'failed',
      reason: response.reason,
      rateLimited: response.kind === 'rate_limited',
    }
  }

  const root = recordValue(response.data)
  const queryStatus = stringValue(root?.query_status) ?? 'kosong'

  if (queryStatus === 'ok') {
    const rows = Array.isArray(root?.data) ? root.data.filter(isRecord) : []
    return rows.length > 0 ? { term, kind: 'match', rows } : { term, kind: 'empty' }
  }

  if (queryStatus === 'no_result') return { term, kind: 'empty' }

  if (queryStatus === 'illegal_auth_key' || queryStatus === 'unauthorized') {
    return { term, kind: 'auth', status: queryStatus }
  }

  // Status lain (mis. pembatasan laju atau status yang tidak terdokumentasi) tidak boleh
  // disamarkan sebagai "tidak ada IOC".
  return { term, kind: 'unknown', status: queryStatus.slice(0, 32) }
}

export const threatFoxAdapter: ProviderAdapter = {
  id: 'threatfox',
  label: 'ThreatFox (abuse.ch)',
  requiredEnv: ['THREATFOX_API_KEY'],
  timeoutMs: 15_000,
  isConfigured: (config) => Boolean(config.threatFoxApiKey),
  async check(context, config): Promise<ProviderCheck> {
    if (!config.threatFoxApiKey) {
      return notConfiguredCheck('THREATFOX_API_KEY belum dikonfigurasi di backend.')
    }

    const terms = searchTerms(context.url, context.hostname)
    const outcomes = await Promise.all(
      terms.map((term) => queryTerm(context, config.threatFoxApiKey as string, term)),
    )

    const matched = outcomes.filter(
      (outcome): outcome is Extract<TermOutcome, { kind: 'match' }> =>
        outcome.kind === 'match',
    )
    const authFailure = outcomes.find((outcome) => outcome.kind === 'auth')
    const unknownStatus = outcomes.find((outcome) => outcome.kind === 'unknown')
    const rateLimited = outcomes.some(
      (outcome) => outcome.kind === 'failed' && outcome.rateLimited,
    )
    const failed = outcomes.filter((outcome) => outcome.kind === 'failed')

    if (matched.length > 0) {
      const classified = matched.flatMap((entry) => {
        const shape = termShapeOf(entry.term)
        return entry.rows
          .slice(0, MAX_ROWS_PER_TERM)
          .map((row) => ({ entry, row, level: classifyRow(stringValue(row.ioc), shape) }))
      })
      const exact = classified.filter((item) => item.level === 'exact')
      const hostLevel = classified.filter((item) => item.level === 'host')

      if (exact.length === 0 && hostLevel.length === 0) {
        // Provider menjawab "ok" tetapi isinya bukan IOC yang diminta. Tidak ada kecocokan
        // yang bisa dinyatakan, dan ini juga bukan bukti URL bersih.
        return errorCheck(
          'ThreatFox mengembalikan catatan yang tidak sesuai dengan bentuk IOC yang dicari; kecocokan tidak dapat dipastikan.',
        )
      }

      // Kecocokan tingkat host tidak pernah naik menjadi malicious: satu host boleh
      // menampung banyak resource dan hanya sebagian yang terdaftar sebagai IOC.
      const relevant = exact.length > 0 ? exact : hostLevel
      const rows = relevant.map((item) => item.row)
      const first = rows[0] ?? {}
      const malware = clip(stringValue(first.malware_printable) ?? stringValue(first.malware))
      const threatType = clip(stringValue(first.threat_type))
      const confidence = numberValue(first.confidence_level)
      const firstSeen = clip(stringValue(first.first_seen))
      const iocTypes = stringList(
        rows.map((row) => stringValue(row.ioc_type)),
        4,
      )
      const matchedForms = [
        ...new Set(relevant.map((item) => describeTerm(item.entry.term, context.url, context.hostname))),
      ].join(', ')

      const signals: ProviderSignal[] = [
        {
          label: 'IOC cocok',
          detail: `${rows.length} catatan ThreatFox cocok (pencocokan pada ${matchedForms}).`,
          severity: relevant === exact ? 'danger' : 'warning',
        },
      ]
      if (iocTypes.length > 0) {
        signals.push({
          label: 'Tipe IOC',
          detail: iocTypes.join(', '),
          severity: 'warning',
        })
      }
      if (malware) {
        signals.push({ label: 'Keluarga malware', detail: malware, severity: 'danger' })
      }
      if (threatType) {
        signals.push({ label: 'Jenis ancaman', detail: threatType, severity: 'warning' })
      }
      if (firstSeen) {
        signals.push({
          label: 'Indikator pertama tercatat',
          detail: firstSeen,
          severity: 'info',
        })
      }

      if (relevant === hostLevel) {
        signals.push({
          label: 'Tingkat kecocokan',
          detail: 'IOC terdaftar menunjuk host yang sama, bukan URL yang diperiksa.',
          severity: 'warning',
        })

        return {
          status: 'success',
          verdict: 'suspicious',
          score: 55,
          summary: `ThreatFox tidak memuat IOC untuk URL ini persis, tetapi ${rows.length} IOC terdaftar pada host yang sama.`,
          signals,
          reason:
            'Kecocokan berada di tingkat host; resource lain pada host yang sama bukan bukti bahwa URL ini berbahaya.',
        }
      }

      return {
        status: 'success',
        verdict: 'malicious',
        score: clampScore(Math.max(70, confidence ?? 70)),
        summary: `ThreatFox menemukan ${rows.length} IOC yang cocok dengan URL ini.`,
        signals,
        reason: null,
      }
    }

    if (authFailure && authFailure.kind === 'auth') {
      return authFailedCheck('Kredensial ThreatFox ditolak.')
    }

    if (unknownStatus && unknownStatus.kind === 'unknown') {
      return errorCheck(
        `ThreatFox mengembalikan status "${unknownStatus.status}" yang tidak dapat diproses; hasil tidak dapat dipastikan.`,
      )
    }

    if (failed.length > 0) {
      // Sebagian kueri gagal: jangan klaim "tidak ada IOC" bila kita memang tidak mengetahuinya.
      if (rateLimited) {
        const reasons = failed
          .filter((outcome) => outcome.kind === 'failed' && outcome.rateLimited)
          .map((outcome) => outcome.reason)
        return failureCheck({
          ok: false,
          status: 429,
          kind: 'rate_limited',
          reason: reasons[0] ?? 'Kuota permintaan provider tercapai.',
        })
      }

      const reasons = failed
        .map((outcome) => (outcome.kind === 'failed' ? outcome.reason : ''))
        .filter(Boolean)
      return errorCheck(
        `${failed.length} dari ${terms.length} kueri ThreatFox gagal (${reasons.join(' ').slice(0, 160)}); kecocokan IOC tidak dapat dipastikan.`,
      )
    }

    return {
      ...notFoundCheck('ThreatFox tidak memiliki IOC yang cocok untuk URL ini.'),
      signals: [
        {
          label: 'Bentuk IOC yang dicari',
          detail: terms.map((term) => describeTerm(term, context.url, context.hostname)).join(', '),
          severity: 'info',
        },
      ],
      reason:
        'Tidak ada catatan di basis IOC bukan bukti URL aman. ThreatFox mengekspirasi IOC yang lebih tua dari 6 bulan, sehingga indikator lama tidak muncul pada API ini.',
    }
  },
}

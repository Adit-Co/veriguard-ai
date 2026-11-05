import type {
  BehaviorObservation,
  CookieMetadata,
  ExternalHostEntry,
  FormAnalysis,
  FormObservation,
  HeaderObservation,
  ResourceSummary,
} from './types.js'

const ATTRIBUTE_PATTERN =
  /\b(src|href|poster|data-src|data-lazy-src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi
const URL_IN_TEXT_PATTERN = /https?:\/\/[a-z0-9.-]*[a-z0-9]/gi

const MAX_RESOURCES = 240
const MAX_HOST_ENTRIES = 40
const MAX_COOKIES = 24

const SECURITY_HEADERS = [
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
]

const RESOURCE_KIND: Record<string, ResourceKind> = {
  script: 'script',
  link: 'style',
  img: 'image',
  iframe: 'frame',
  source: 'media',
  video: 'media',
  audio: 'media',
  a: 'anchor',
}

type ResourceKind = 'script' | 'style' | 'image' | 'frame' | 'media' | 'anchor' | 'other'

export type ParsedResource = {
  kind: ResourceKind
  host: string
  absolute: string
}

function normalizeUrl(value: string, base: string): string | null {
  const trimmed = value.trim().replace(/^["']|["']$/g, '')
  if (!trimmed || trimmed.startsWith('data:') || trimmed.startsWith('javascript:') || trimmed.startsWith('#')) {
    return null
  }
  try {
    const resolved = new URL(trimmed, base)
    if (resolved.protocol !== 'https:' && resolved.protocol !== 'http:') return null
    resolved.hash = ''
    return resolved.href
  } catch {
    return null
  }
}

const RESOURCE_TAG = 'script|link|img|iframe|source|video|audio|a'

function resourceKind(tagName: string, tag: string): ResourceKind {
  if (tagName === 'link') {
    const stylesheet = /rel\s*=\s*["']?stylesheet/i.test(tag) || /as\s*=\s*["']?style/i.test(tag)
    return stylesheet ? 'style' : 'other'
  }
  return RESOURCE_KIND[tagName] ?? 'media'
}

export function extractResources(html: string, baseUrl: string): {
  resources: ParsedResource[]
  capped: boolean
} {
  const resources: ParsedResource[] = []
  let capped = false
  const tagPattern = new RegExp(`<(${RESOURCE_TAG})\\b[^>]*>`, 'gi')

  for (const match of [...html.matchAll(tagPattern)].slice(0, 800)) {
    const tag = match[0] ?? ''
    const tagName = (match[1] ?? '').toLowerCase()

    for (const attribute of tag.matchAll(ATTRIBUTE_PATTERN)) {
      const name = (attribute[1] ?? '').toLowerCase()
      const value = attribute[2] ?? attribute[3] ?? attribute[4] ?? ''
      if (name === 'href' && tagName !== 'link' && tagName !== 'a') continue

      const absolute = normalizeUrl(value, baseUrl)
      if (!absolute) continue

      let host: string
      try {
        host = new URL(absolute).hostname.toLowerCase()
      } catch {
        continue
      }
      if (!host) continue

      const kind = resourceKind(tagName, tag)
      if (kind === 'other') continue

      if (resources.length >= MAX_RESOURCES) {
        capped = true
        break
      }
      resources.push({ kind, host, absolute })
    }

    if (capped) break
  }

  return { resources, capped }
}

export function summarizeResources(resources: ParsedResource[], capped: boolean): ResourceSummary {
  const summary: ResourceSummary = {
    scripts: 0,
    styles: 0,
    images: 0,
    iframes: 0,
    links: 0,
    other: 0,
    collected: resources.length,
    capped,
  }

  for (const resource of resources) {
    if (resource.kind === 'script') summary.scripts += 1
    else if (resource.kind === 'style') summary.styles += 1
    else if (resource.kind === 'image') summary.images += 1
    else if (resource.kind === 'frame') summary.iframes += 1
    else if (resource.kind === 'anchor') summary.links += 1
    else summary.other += 1
  }

  return summary
}

/**
 * Memisahkan host yang benar-benar dihubungi probe (observed) dari host yang
 * hanya disebut sebagai sumber daya (referenced) dan host yang hanya muncul
 * sebagai teks di dalam dokumen (inferred).
 */
export function classifyHosts(input: {
  observedHosts: string[]
  resources: ParsedResource[]
  html: string | null
  pageHost: string
}): { entries: ExternalHostEntry[]; capped: boolean } {
  const map = new Map<string, ExternalHostEntry>()

  const touch = (host: string): ExternalHostEntry | undefined => {
    const normalized = host.toLowerCase().replace(/\.$/, '')
    if (!normalized || normalized === input.pageHost) return undefined
    const existing = map.get(normalized)
    if (existing) return existing
    const entry: ExternalHostEntry = { host: normalized, roles: [], resourceKinds: [], count: 0 }
    map.set(normalized, entry)
    return entry
  }

  const addRole = (entry: ExternalHostEntry, role: ExternalHostEntry['roles'][number]): void => {
    if (!entry.roles.includes(role)) entry.roles.push(role)
  }

  for (const host of input.observedHosts) {
    const entry = touch(host)
    if (entry) {
      addRole(entry, 'observed')
      entry.count += 1
    }
  }

  for (const resource of input.resources) {
    const entry = touch(resource.host)
    if (!entry) continue
    addRole(entry, 'referenced')
    if (!entry.resourceKinds.includes(resource.kind) && entry.resourceKinds.length < 5) {
      entry.resourceKinds.push(resource.kind)
    }
    entry.count += 1
  }

  if (input.html) {
    for (const match of (input.html.match(URL_IN_TEXT_PATTERN) ?? []).slice(0, 1_200)) {
      let host: string
      try {
        host = new URL(match).hostname.toLowerCase()
      } catch {
        continue
      }
      const entry = touch(host)
      if (entry && !entry.roles.includes('observed') && !entry.roles.includes('referenced')) {
        addRole(entry, 'inferred')
        entry.count += 1
      }
    }
  }

  const entries = [...map.values()]
    .sort((left, right) => right.count - left.count || left.host.localeCompare(right.host))
    .slice(0, MAX_HOST_ENTRIES)

  return { entries, capped: map.size > MAX_HOST_ENTRIES }
}

function parseSameSite(value: string): string | null {
  const match = /\bsamesite\s*=\s*([a-z-]+)/i.exec(value)
  return match ? match[1].toLowerCase() : null
}

/**
 * Hanya metadata cookie yang dikembalikan. Nilai cookie, token sesi, dan
 * kredensial tidak pernah dibaca keluar dari header.
 */
export function readCookieMetadata(setCookieHeaders: string[]): {
  cookies: CookieMetadata[]
  capped: boolean
} {
  const cookies: CookieMetadata[] = []

  for (const raw of setCookieHeaders) {
    if (cookies.length >= MAX_COOKIES) return { cookies, capped: true }

    const assignment = raw.split(';')[0] ?? ''
    const separator = assignment.indexOf('=')
    if (separator <= 0) continue

    const name = assignment.slice(0, separator).trim().replace(/[^\x21-\x7e]/g, '').slice(0, 96)
    if (!name) continue

    cookies.push({
      name,
      secure: /\bsecure\b/i.test(raw),
      httpOnly: /\bhttponly\b/i.test(raw),
      sameSite: parseSameSite(raw),
      hasExpiry: /\b(max-age|expires)\s*=/i.test(raw),
      valueShown: false,
    })
  }

  return { cookies, capped: false }
}

const MAX_FORMS = 12
const MAX_FORM_BODY = 24_000

function formAttribute(tag: string, name: string): string | null {
  const pattern = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i')
  const match = pattern.exec(tag)
  const value = match?.[1] ?? match?.[2] ?? match?.[3] ?? null
  if (value === null) return null
  const cleaned = value.replace(/^["']|["']$/g, '').trim()
  return cleaned === '' ? null : cleaned.slice(0, 300)
}

const NON_TEXT_INPUT_TYPE =
  /\btype\s*=\s*["']?(hidden|password|submit|button|reset|checkbox|radio|file|image)["']?/i

function countMatches(body: string, pattern: RegExp): number {
  // `match` tanpa bendera global mengembalikan satu hasil berikut grup tangkapnya,
  // jadi jumlahannya bisa meleset. matchAll mengembalikan satu entri per temuan.
  const global = pattern.global ? pattern : new RegExp(pattern.source, `${pattern.flags}g`)
  return [...body.matchAll(global)].length
}

/**
 * Form dibaca sebagai teks statis: tidak ada skrip yang dijalankan dan tidak ada
 * permintaan yang dikirim ke action. Ini yang membedakan "ada kolom Sandi" dari
 * "halaman benar-benar mengirim kredensial ke host lain".
 */
export function analyzeForms(input: {
  html: string | null
  baseUrl: string | null
  pageHost: string
  pageSecure: boolean
}): FormAnalysis {
  const notAvailable = (reason: string): FormAnalysis => ({
    inspected: false,
    forms: [],
    totals: { forms: 0, passwordFields: 0, externalActions: 0, insecureActions: 0 },
    capped: false,
    detail: reason,
  })

  if (input.html === null) {
    return notAvailable('Dokumen HTML tidak tersedia, jadi form dan kolom kredensial tidak dapat diperiksa.')
  }
  if (!input.baseUrl) {
    return notAvailable('URL dasar halaman tidak terbaca, jadi tujuan action form tidak dapat dinilai.')
  }

  const forms: FormObservation[] = []
  let capped = false

  for (const match of input.html.matchAll(/<form\b[^>]*>/gi)) {
    if (forms.length >= MAX_FORMS) {
      capped = true
      break
    }

    const tag = match[0] ?? ''
    const start = (match.index ?? 0) + tag.length
    const closing = input.html.indexOf('</form', start)
    const nextForm = input.html.indexOf('<form', start)
    const boundary =
      closing >= 0
        ? nextForm >= 0 && nextForm < closing
          ? nextForm
          : closing
        : (nextForm >= 0 ? nextForm : Math.min(input.html.length, start + MAX_FORM_BODY))
    const body = input.html.slice(start, Math.min(boundary, start + MAX_FORM_BODY))

    const actionRaw = formAttribute(tag, 'action')
    const absolute = actionRaw === null ? input.baseUrl : normalizeUrl(actionRaw, input.baseUrl)
    let actionHost: string | null = null
    let actionScheme: string | null = null
    if (absolute) {
      try {
        const parsed = new URL(absolute)
        actionHost = parsed.hostname.toLowerCase()
        actionScheme = parsed.protocol.replace(/:$/, '')
      } catch {
        actionHost = null
      }
    }

    const passwordFields = countMatches(body, /\btype\s*=\s*["']?password["']?/i)
    const textFields = Math.max(
      0,
      countMatches(body, /<input\b[^>]*>/gi) - countMatches(body, NON_TEXT_INPUT_TYPE),
    )
    const external = actionHost !== null && actionHost !== input.pageHost
    const insecure = actionScheme === 'http' || (passwordFields > 0 && !input.pageSecure)

    forms.push({
      index: forms.length + 1,
      action: actionRaw !== null && absolute ? absolute.slice(0, 300) : null,
      actionHost,
      actionScheme,
      external,
      insecure,
      method: (formAttribute(tag, 'method') ?? 'GET').toUpperCase().slice(0, 8),
      passwordFields,
      textFields,
    })
  }

  const totals = {
    forms: forms.length,
    passwordFields: forms.reduce((sum, form) => sum + form.passwordFields, 0),
    externalActions: forms.filter((form) => form.external).length,
    insecureActions: forms.filter((form) => form.insecure).length,
  }

  const detail =
    forms.length === 0
      ? 'Tidak ada tag <form> yang teridentifikasi pada dokumen yang dibaca.'
      : `${forms.length} form teridentifikasi: ${totals.passwordFields} kolom Sandi, ${totals.externalActions} action ke host lain, ${totals.insecureActions} action tanpa enkripsi.`

  return { inspected: true, forms, totals, capped, detail }
}

function headerValues(headers: Array<[string, string]>, name: string): string[] {
  const lower = name.toLowerCase()
  return headers.filter(([key]) => key.toLowerCase() === lower).map(([, value]) => value)
}

export function observeSecurityHeaders(headers: Array<[string, string]>): HeaderObservation[] {
  return SECURITY_HEADERS.map((name) => {
    const values = headerValues(headers, name)
    const value = values.join(', ')
    return {
      name,
      present: values.length > 0,
      value:
        values.length === 0
          ? null
          : value.replace(/[\u0000-\u001f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 220),
    }
  })
}

export function collectSetCookies(headers: Array<[string, string]>): string[] {
  return headerValues(headers, 'set-cookie')
}

export function buildBehaviorObservations(input: {
  redirectCount: number
  finalStatus: number | null
  observations: BehaviorObservation[]
}): BehaviorObservation[] {
  const list = [...input.observations]

  list.push({
    kind: 'response',
    state: input.finalStatus === null ? 'unavailable' : 'observed',
    detail:
      input.finalStatus === null
        ? 'Respons akhir tidak berhasil diambil, jadi perubahan status tidak dapat diamati.'
        : `Respons terakhir mengembalikan status HTTP ${input.finalStatus}.`,
  })

  if (!list.some((entry) => entry.kind === 'redirect')) {
    list.push({
      kind: 'redirect',
      state: 'observed',
      detail:
        input.redirectCount === 0
          ? 'Tidak ada redirect yang tercatat pada rantai yang diamati.'
          : `${input.redirectCount} lompatan redirect tercatat pada rantai yang diamati.`,
    })
  }

  // Batas daftar dinaikkan sedikit karena pengamatan struktur URL dan form ditambahkan di
  // ujung; pengamatan redirect yang lebih dulu tetap diprioritaskan.
  return list.slice(0, 14)
}

export const BEHAVIOR_LIMITS = {
  maxResources: MAX_RESOURCES,
  maxHosts: MAX_HOST_ENTRIES,
  maxCookies: MAX_COOKIES,
  maxForms: MAX_FORMS,
  maxFormBody: MAX_FORM_BODY,
} as const

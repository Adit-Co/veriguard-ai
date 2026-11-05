import type { Brand } from './brands'
import { brands } from './brands'
import { createPattern } from './patterns'
import { buildDraft } from './result'
import {
  decodePercentEncoded,
  extractEmbeddedUrls,
  isIpHost,
  isLocalHost,
  isLookalike,
  truncate,
} from './text'
import type {
  AnalysisReason,
  DetectedPattern,
  PatternConfidence,
  PatternId,
  TechnicalItem,
} from './types'
import { AnalysisError, validateLinkInput } from './validate'

const MULTI_PART_SUFFIXES = [
  'co.id',
  'net.id',
  'go.id',
  'sch.id',
  'mil.id',
  'desa.id',
  'ac.id',
  'or.id',
  'web.id',
  'my.id',
  'biz.id',
  'co.uk',
  'org.uk',
  'com.au',
  'com.sg',
  'com.my',
  'co.jp',
  'co.kr',
  'com.br',
  'co.in',
]

const SUSPICIOUS_TLDS = [
  'xyz',
  'top',
  'click',
  'link',
  'live',
  'shop',
  'site',
  'online',
  'buzz',
  'icu',
  'cyou',
  'rest',
  'monster',
  'quest',
  'cam',
  'cfd',
  'sbs',
  'lol',
  'zip',
  'mov',
]

export const SHORTENERS = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'is.gd',
  'cutt.ly',
  's.id',
  'rb.gy',
  'shorturl.at',
  'rebrand.ly',
  'ow.ly',
  'buff.ly',
]

const FREE_HOSTS = [
  'blogspot.com',
  'wordpress.com',
  'wixsite.com',
  'weebly.com',
  'github.io',
  'netlify.app',
  'vercel.app',
  'pages.dev',
  'web.app',
  'firebaseapp.com',
  '000webhostapp.com',
  'godaddysites.com',
  'business.site',
  'site123.me',
]

const CREDENTIAL_TERMS = [
  'login',
  'signin',
  'masuk',
  'verifikasi',
  'verify',
  'secure',
  'akun',
  'account',
  'update',
  'wallet',
  'otp',
  'password',
  'sandi',
  'konfirmasi',
  'topup',
  'pulsa',
  'rekening',
  'bayar',
]

const GIVEAWAY_TERMS = [
  'hadiah',
  'undian',
  'gratis',
  'bonus',
  'promo',
  'klaim',
  'giveaway',
  'cashback',
]

// Sisa kata dari merek yang menempel tanpa pemisah ("verifikasibca"). Daftar
// ini dipakai untuk memutuskan apakah bagian yang menempel itu kata bertema
// penipuan atau hanya kebetulan ("pineapplecafe").
const GLUE_CONTEXT_TERMS = new Set<string>([...CREDENTIAL_TERMS, ...GIVEAWAY_TERMS])

// Tautan yang membuka ruang percakapan, bukan halaman web: apa yang sebenarnya
// ditampilkan baru terlihat setelah obrolan berjalan.
const CHAT_HANDOFF_HOSTS = ['wa.me', 't.me', 'telegram.me', 'chat.whatsapp.com']

export type BrandMatch = {
  brand: Brand
  kind: 'official' | 'impersonation' | 'typosquat'
  detail: string
  // Nama merek hanya muncul sebagai bagian dari label yang lebih panjang
  // (mis. "xxsicepatxx"). Bukti ini lebih lemah daripada label utuh.
  glued?: boolean
  // Kata yang menempel pada merek ("verifikasi" pada "verifikasibca"). Bila
  // kata itu bertema login/hadiah, gabungan keduanya adalah bukti nyata,
  // bukan sekadar kebetulan susunan huruf.
  gluedContext?: string
}

export type ExternalTarget = {
  raw: string
  host: string
  registrable: string
  path: string
}

const CONFIDENCE_RANK: Record<PatternConfidence, number> = {
  low: 0,
  medium: 1,
  high: 2,
}

function raisePattern(
  patterns: DetectedPattern[],
  id: PatternId,
  confidence: PatternConfidence,
) {
  const index = patterns.findIndex((pattern) => pattern.id === id)

  if (index === -1) {
    patterns.push(createPattern(id, confidence))
    return
  }

  if (CONFIDENCE_RANK[confidence] > CONFIDENCE_RANK[patterns[index].confidence]) {
    patterns[index] = createPattern(id, confidence)
  }
}

function isOfficialDomain(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`)
}

function brandLabelTokens(label: string): string[] {
  return label
    .split(/[-_.]/)
    .map((token) => token.replace(/^\d+/, '').replace(/\d+$/, ''))
    .filter(Boolean)
}

function matchesBrandToken(label: string, name: string): boolean {
  if (label === name) return true
  if (label.startsWith(`${name}-`) || label.endsWith(`-${name}`)) return true
  return brandLabelTokens(label).includes(name)
}

// "xxsicepatxx" atau "mandiri99slot": nama merek menempel tanpa pemisah dan
// sisanya bukan suku kata. Sinyal lebih lemah daripada label yang persis sama.
// "verifikasibca" berbeda: sisa kata setelah merek adalah istilah login/hadiah,
// jadi gabungan keduanya adalah bukti penyamaran meski mereknya pendek.
function looksGlued(remainder: string): boolean {
  return remainder.length >= 2 && longestConsonantRun(remainder) >= 2
}

function findGluedBrand(
  labels: string[],
): { brand: Brand; name: string; label: string; context?: string } | null {
  for (const brand of brands) {
    const names = [brand.name, ...(brand.aliases ?? [])]

    for (const name of names) {
      for (const label of labels) {
        if (label.startsWith('xn--')) continue
        const index = label.indexOf(name)
        if (index === -1 || matchesBrandToken(label, name)) continue
        const remainder = label.replace(name, '')
        const context = GLUE_CONTEXT_TERMS.has(remainder) ? remainder : undefined
        if (context === undefined && (name.length < 5 || !looksGlued(remainder))) continue
        return { brand, name, label, context }
      }
    }
  }

  return null
}

export function detectBrand(host: string): BrandMatch | null {
  for (const brand of brands) {
    if (isOfficialDomain(host, brand.domain)) {
      return {
        brand,
        kind: 'official',
        detail: `Domain resmi ${brand.name} adalah ${brand.domain}.`,
      }
    }
  }

  const labels = host.split('.')

  for (const brand of brands) {
    const names = [brand.name, ...(brand.aliases ?? [])]
    for (const name of names) {
      for (const label of labels) {
        if (label.startsWith('xn--')) continue
        if (matchesBrandToken(label, name)) {
          return {
            brand,
            kind: 'impersonation',
            detail: `${host} memuat nama "${name}", sedangkan domain resmi ${brand.name} adalah ${brand.domain}.`,
          }
        }
      }
    }
  }

  for (const brand of brands) {
    const names = [brand.name, ...(brand.aliases ?? [])]
    for (const name of names) {
      for (const label of labels) {
        if (label.startsWith('xn--')) continue
        // Label berimbuhan diuji per kata: "paypa1-secure" adalah varian tulis
        // "paypal", sedangkan pemeriksaan utuh melewatkan seluruh label beranda
        // hubung. Kata persis sudah ditangkap pemeriksaan token di atas.
        const tokens = new Set([label, ...label.split(/[-_.]/)])

        for (const token of tokens) {
          if (!isLookalike(token, name)) continue

          return {
            brand,
            kind: 'typosquat',
            detail: `"${token}" menyerupai penulisan ${brand.name}; domain resminya ${brand.domain}.`,
          }
        }
      }
    }
  }

  const glued = findGluedBrand(labels)

  if (glued) {
    return {
      brand: glued.brand,
      kind: 'impersonation',
      glued: true,
      gluedContext: glued.context,
      detail:
        glued.context === undefined
          ? `"${glued.label}" memuat nama ${glued.brand.name} di dalam satu kata, sedangkan domain resminya ${glued.brand.domain}.`
          : `"${glued.label}" menggabungkan nama ${glued.brand.name} dengan kata "${glued.context}", sedangkan domain resminya ${glued.brand.domain}.`,
    }
  }

  return null
}

export function getRegistrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, '')
  if (isIpHost(host)) return host

  const labels = host.split('.')
  if (labels.length <= 2) return host

  const lastTwo = labels.slice(-2).join('.')
  if (MULTI_PART_SUFFIXES.includes(lastTwo)) return labels.slice(-3).join('.')
  return lastTwo
}

function countHyphens(host: string): number {
  return (host.match(/-/g) ?? []).length
}

// Domain resmi yang dipakai sebagai awalan label (mis.
// "www.bca.co.id.verify-secure.top") menampilkan merek di baris alamat
// sementara domain yang benar-benar terdaftar adalah milik pihak lain.
export function findBrandDomainPrefix(host: string): Brand | null {
  const labels = host.split('.')

  for (const brand of brands) {
    const suffix = brand.domain.split('.')

    for (let start = 0; start + suffix.length < labels.length; start += 1) {
      if (labels.slice(start, start + suffix.length).join('.') === brand.domain) return brand
    }
  }

  return null
}
function longestConsonantRun(value: string): number {
  let longest = 0
  let current = 0

  for (const character of value) {
    if (/[bcdfghjklmnpqrstvwxyz]/.test(character)) {
      current += 1
      longest = Math.max(longest, current)
    } else {
      current = 0
    }
  }

  return longest
}

function looksRandom(label: string): boolean {
  if (label.length < 14) return false
  const digits = (label.match(/\d/g) ?? []).length
  return digits >= 4 || longestConsonantRun(label) >= 6
}

function hasEncodedCharacters(url: URL): boolean {
  const encoded = `${url.pathname}${url.search}`.match(/%[0-9a-f]{2}/gi) ?? []
  return encoded.length >= 3
}

function hasExecutablePath(url: URL): boolean {
  return /\.(apk|exe|msi|scr|bat|cmd|vbs|jar|zip|rar)(?:$|[?#])/i.test(
    `${url.pathname}${url.search}`,
  )
}

function targetFromValue(value: string): URL | null {
  const cleaned = value
    .trim()
    .replace(/^[a-z][a-z0-9+.-]*:/i, '')
    .replace(/^\/+/, '')
    .replace(/^.*@/, '')

  if (!cleaned) return null

  try {
    const target = new URL(`https://${cleaned}`)
    const host = target.hostname.toLowerCase().replace(/\.$/, '')
    const labels = host.split('.')
    const lastLabel = labels[labels.length - 1] ?? ''

    if (isLocalHost(host)) return null

    // Alamat IP yang tertanam justru pola umum halaman login palsu.
    if (isIpHost(host)) return target

    // "v=1.5" atau "id=100.200" bukan alamat; label terakhir harus berupa TLD.
    if (labels.length < 2 || !/^[a-z][a-z0-9-]{1,}$/.test(lastLabel)) return null

    return target
  } catch {
    return null
  }
}

const DOMAIN_IN_TEXT =
  /[a-z0-9](?:[a-z0-9-]{0,60}[a-z0-9])?(?:\.[a-z0-9-]{2,63})*\.(?:com|net|org|id|my|co|io|xyz|top|online|shop|site|store|info|live|click|link|icu|sbs|cyou|buzz)\b/gi

// Domain yang ditulis apa adanya di jalur/parameter (mis. "/paypal.com/verifikasi")
// tanpa scheme: alamat yang dibuka bukan alamat di baris alamat.
function extractDomainMentions(value: string): string[] {
  return [...new Set(value.match(DOMAIN_IN_TEXT) ?? [])].slice(0, 6)
}

// Alamat di luar domain yang dibuka: tujuan sebenarnya berada di parameter
// (open redirect), di dalam path, atau ditulis dengan scheme yang disamarkan.
export function findExternalTargets(
  url: URL,
  pageRegistrable: string,
): ExternalTarget[] {
  const candidates: URL[] = []
  const blob = decodePercentEncoded(`${url.pathname}${url.search}${url.hash}`)

  for (const [, value] of url.searchParams) {
    const target = targetFromValue(value)
    if (target) candidates.push(target)
  }

  for (const match of [...extractEmbeddedUrls(blob), ...extractDomainMentions(blob)]) {
    const target = targetFromValue(match)
    if (target) candidates.push(target)
  }

  const seen = new Set<string>()
  const targets: ExternalTarget[] = []

  for (const target of candidates) {
    const host = target.hostname.toLowerCase().replace(/\.$/, '')
    const registrable = getRegistrableDomain(host)

    if (registrable === pageRegistrable || seen.has(registrable)) continue

    // Subdomain dari domain yang sedang dibuka bukan tujuan eksternal.
    if (host.endsWith(`.${pageRegistrable}`)) continue

    seen.add(registrable)
    targets.push({
      raw: `${host}${target.pathname}${target.search}`,
      host,
      registrable,
      path: target.pathname === '/' ? '' : target.pathname,
    })

    if (targets.length >= 3) break
  }

  return targets
}

export type PathBrandHit = {
  brand: Brand
  name: string
  segment: string
  wholeSegment: boolean
  context: boolean
}

const URL_SEGMENT_SEPARATORS = /[/?=&#%]+/
const PATH_WORD_SEPARATORS = /[-_.+]/

function hasFraudContext(segment: string): boolean {
  return (
    CREDENTIAL_TERMS.some((term) => segment.includes(term)) ||
    GIVEAWAY_TERMS.some((term) => segment.includes(term))
  )
}

// "1bca" dan "bca24" adalah nama merek dengan imbuhan angka, sama seperti pada
// label domain.
function withoutDigits(value: string): string {
  return value.replace(/^\d+/, '').replace(/\d+$/, '')
}

// Nama merek yang sekaligus kata biasa dalam bahasa Indonesia tidak dipakai
// sebagai penanda di jalur URL bila tidak ada kata login/verifikasi/hadiah di
// sekitarnya: "/tag/pos-indonesia" atau "/panduan-dana-darurat" bukan peniruan
// merek, sedangkan "bca", "bri", "ovo" bukan kata umum.
const GENERIC_BRAND_WORDS = new Set(['pos', 'dana', 'tiket', 'pajak', 'grab', 'apple', 'google'])

// Nama merek di jalur URL punya dua bentuk yang kekuatannya berbeda. "/paypal"
// menempatkan nama itu sebagai segmen utuh, sedangkan "/kredinal-bca" hanya
// memakainya sebagai salah satu kata. Bentuk kedua berarti nyata bila kata
// sekitarnya bertema login/hadiah, atau bila mereknya singkatan pendek yang
// jarang muncul sebagai kata biasa ("bca", "bri"); "buku-permata-biru" tetap
// lolos karena "permata" kata umum dan tidak ada konteks permintaan data.
export function findBrandInPath(
  url: URL,
  excludedNames: Set<string>,
  explainedSegments: Set<string>,
): PathBrandHit | null {
  const segments = `${url.pathname}${url.search}${url.hash}`
    .toLowerCase()
    .split(URL_SEGMENT_SEPARATORS)
    // Segmen yang merupakan bagian dari alamat tujuan yang sudah dijelaskan
    // sendiri oleh alasan `redirect_target_*` tidak dihitung dua kali.
    .filter((segment) => segment.length > 0 && !explainedSegments.has(segment))

  for (const segment of segments) {
    const bareSegment = withoutDigits(segment)

    for (const brand of brands) {
      for (const name of [brand.name, ...(brand.aliases ?? [])]) {
        if (name.length < 3 || excludedNames.has(name)) continue
        // Di bawah empat huruf hanya singkatan merek yang bukan kata umum:
        // "/bca" dihitung, "/pos" tidak.
        if (name.length < 4 && GENERIC_BRAND_WORDS.has(name)) continue
        if (segment !== name && bareSegment !== name) continue

        return { brand, name, segment, wholeSegment: true, context: false }
      }
    }
  }

  for (const segment of segments) {
    const words = segment
      .split(PATH_WORD_SEPARATORS)
      .map(withoutDigits)
      .filter(Boolean)
    if (words.length < 2) continue

    const context = hasFraudContext(segment)

    for (const brand of brands) {
      for (const name of [brand.name, ...(brand.aliases ?? [])]) {
        // Tiga huruf adalah panjang terpendek yang diuji di sini ("bca", "bri");
        // di bawah itu yang muncul hanya singkatan acak.
        if (name.length < 3 || excludedNames.has(name)) continue
        if (!words.includes(name)) continue
        if (!context && (name.length > 4 || GENERIC_BRAND_WORDS.has(name))) continue

        return { brand, name, segment, wholeSegment: false, context }
      }
    }
  }

  return null
}

function addReason(reasons: AnalysisReason[], reason: AnalysisReason) {
  if (!reasons.some((existing) => existing.id === reason.id)) {
    reasons.push(reason)
  }
}

// Host yang ikut menentukan identitas sebuah tautan: domain pada baris alamat
// ditambah alamat tujuan yang tertanam di dalamnya.
export function hostsFromLink(link: string): string[] {
  let url: URL

  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(link) ? link : `https://${link}`)
  } catch {
    return []
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, '')

  if (!host.includes('.') || isLocalHost(host)) return []

  const targets = findExternalTargets(url, getRegistrableDomain(host))

  return [host, ...targets.map((target) => target.host)]
}

export function analyzeLink(raw: string) {
  const validation = validateLinkInput(raw)

  if (!validation.ok) {
    throw new AnalysisError(validation.error)
  }

  const normalized = validation.normalized
  const url = new URL(normalized)
  const host = url.hostname.toLowerCase().replace(/\.$/, '')
  const registrable = getRegistrableDomain(host)
  const pathname = url.pathname === '/' ? '' : url.pathname
  const haystack = `${host}${url.pathname}${url.search}`.toLowerCase()
  const reasons: AnalysisReason[] = []

  const brandMatch = detectBrand(host)
  const credentialHits = CREDENTIAL_TERMS.filter((term) => haystack.includes(term))
  const giveawayHits = GIVEAWAY_TERMS.filter((term) => haystack.includes(term))
  const isShortener = SHORTENERS.some((shortener) => isOfficialDomain(host, shortener))
  const isFreeHost = FREE_HOSTS.some((freeHost) => isOfficialDomain(host, freeHost))
  const isChatHandoff = CHAT_HANDOFF_HOSTS.includes(host)
  const hostLabels = host.split('.')
  const hasPunycodeLabel = hostLabels.some((label) => label.startsWith('xn--'))
  const subdomainDepth = Math.max(0, hostLabels.length - registrable.split('.').length)
  const hostTld = hostLabels[hostLabels.length - 1] ?? ''
  const hasSuspiciousTld = SUSPICIOUS_TLDS.includes(hostTld)

  const brandPrefixHijack = findBrandDomainPrefix(host)
  const externalTargets = findExternalTargets(url, registrable)
  const targetEvidence = externalTargets.map((target) => {
    const blob = `${target.host}${target.raw}`.toLowerCase()
    const targetLabels = target.host.split('.')
    const targetTld = targetLabels[targetLabels.length - 1] ?? ''

    return {
      target,
      brand: detectBrand(target.host),
      prefix: findBrandDomainPrefix(target.host),
      credential: CREDENTIAL_TERMS.some((term) => blob.includes(term)),
      suspiciousTld: SUSPICIOUS_TLDS.includes(targetTld),
      punycode: targetLabels.some((label) => label.startsWith('xn--')),
      ip: isIpHost(target.host),
      deepSubdomain:
        Math.max(0, targetLabels.length - target.registrable.split('.').length) >= 2,
    }
  })

  const riskyTarget =
    targetEvidence.find(
      (item) => (item.brand && item.brand.kind !== 'official') || item.prefix || item.ip,
    ) ?? null

  const riskyTargetStrong =
    riskyTarget !== null &&
    (riskyTarget.credential ||
      riskyTarget.suspiciousTld ||
      riskyTarget.punycode ||
      riskyTarget.ip ||
      riskyTarget.deepSubdomain ||
      riskyTarget.prefix !== null)

  const targetBrand =
    riskyTarget?.brand && riskyTarget.brand.kind !== 'official' ? riskyTarget.brand : null
  const targetImpersonation = targetBrand !== null || Boolean(riskyTarget?.prefix)

  // Nama merek di host yang bukan domain resmi belum cukup sebagai bukti
  // penyamaran; hanya dianggap penyamaran bila ada penunjang lain. Nama yang
  // menempel tanpa pemisah ("xxsicepatxx") termasuk bukti lemah, kecuali sisa
  // kata itu justru istilah login/verifikasi/hadiah ("verifikasibca").
  const brandGluedWeak =
    brandMatch?.glued === true && brandMatch.gluedContext === undefined

  const brandCorroborated =
    !brandGluedWeak &&
    (credentialHits.length > 0 ||
      brandMatch?.gluedContext !== undefined ||
      hasPunycodeLabel ||
      hasSuspiciousTld ||
      isIpHost(host) ||
      brandPrefixHijack !== null ||
      targetImpersonation ||
      subdomainDepth >= 2 ||
      isShortener ||
      isFreeHost)

  // Satu fakta merek tidak boleh dihitung dua kali: bila nama merek di host
  // justru dijelaskan oleh pola domain-resmenjadi-awalan, alasan awalan yang dipakai.
  const prefixExplainsBrand =
    brandPrefixHijack !== null &&
    brandMatch !== null &&
    brandMatch.kind !== 'official' &&
    brandMatch.brand.name === brandPrefixHijack.name

  if (url.username || /^https?:\/\/[^/?#]*@/i.test(normalized)) {
    addReason(reasons, {
      id: 'at_symbol',
      label: 'Karakter @ pada tautan',
      detail:
        'Teks sebelum karakter @ dapat menyamarkan alamat domain yang sebenarnya dibuka.',
      severity: 'danger',
      weight: 20,
      category: 'obfuscation',
    })
  }

  if (url.protocol === 'http:') {
    addReason(reasons, {
      id: 'no_https',
      label: 'Tautan tanpa HTTPS',
      detail:
        'Koneksi tidak memakai HTTPS. Ini sinyal lemah: situs sah pun bisa memakai HTTP, dan situs penipuan bisa memakai HTTPS.',
      severity: 'info',
      weight: 6,
      category: 'url-structure',
    })
  }

  if (hasPunycodeLabel) {
    addReason(reasons, {
      id: 'punycode_host',
      label: 'Domain memakai Punycode',
      detail:
        'Domain memakai encoding xn-- yang dapat menampilkan huruf mirip situs resmi (homograf).',
      severity: 'warning',
      weight: 26,
      category: 'obfuscation',
    })
  }

  if (isIpHost(host)) {
    addReason(reasons, {
      id: 'ip_host',
      label: 'Alamat IP sebagai domain',
      detail:
        'Tautan memakai alamat IP, bukan nama domain yang dapat dicocokkan dengan layanan resmi.',
      severity: 'danger',
      weight: 26,
      category: 'domain',
    })
  }

  if (brandMatch && brandMatch.kind !== 'official' && !prefixExplainsBrand) {
    const isTypo = brandMatch.kind === 'typosquat'

    if (brandCorroborated) {
      addReason(reasons, {
        id: isTypo ? 'brand_typosquat' : 'brand_impersonation',
        label: isTypo ? 'Domain menyerupai merek resmi' : 'Nama merek pada domain tidak resmi',
        detail: brandMatch.detail,
        severity: 'danger',
        weight: isTypo ? 32 : 28,
        category: 'impersonation',
      })

      if (credentialHits.length > 0) {
        addReason(reasons, {
          id: 'brand_credential_combo',
          label: 'Merek dipadukan dengan permintaan data',
          detail:
            'Nama merek muncul bersama kata terkait login, verifikasi, atau data akun pada domain yang bukan milik merek tersebut.',
          severity: 'danger',
          weight: 20,
          category: 'impersonation',
        })
      }
    } else if (brandMatch.glued) {
      addReason(reasons, {
        id: 'brand_name_glued',
        label: 'Nama merek menempel pada domain',
        detail: `${brandMatch.detail} Nama itu tidak berdiri sendiri sebagai label domain, jadi bukti penyamaran masih lemah.`,
        severity: 'warning',
        weight: 16,
        category: 'impersonation',
      })
    } else {
      addReason(reasons, {
        id: 'brand_name_unconfirmed',
        label: isTypo ? 'Domain menyerupai merek resmi' : 'Nama merek pada domain tidak resmi',
        detail: isTypo
          ? `${brandMatch.detail} Alamat ini belum memuat permintaan login, verifikasi, atau data akun, jadi kemiripan nama belum cukup sebagai bukti penyamaran.`
          : `${brandMatch.detail} Nama merek juga bisa dipakai usaha lain; alamat ini belum memuat permintaan login, verifikasi, atau data akun.`,
        severity: 'warning',
        weight: isTypo ? 26 : 14,
        category: 'impersonation',
      })
    }
  }

  if (brandPrefixHijack) {
    addReason(reasons, {
      id: 'brand_domain_prefix',
      label: 'Domain resmi dipakai sebagai awalan',
      detail: `Alamat memuat "${brandPrefixHijack.domain}" di awal, tetapi domain yang benar-benar terdaftar adalah ${registrable}. Penulisan seperti ini menampilkan merek di baris alamat sementara situs yang dibuka milik pihak lain.`,
      severity: 'danger',
      weight: 26,
      category: 'impersonation',
    })

    if (credentialHits.length > 0 && prefixExplainsBrand) {
      addReason(reasons, {
        id: 'brand_credential_combo',
        label: 'Merek dipadukan dengan permintaan data',
        detail:
          'Nama merek muncul bersama kata terkait login, verifikasi, atau data akun pada domain yang bukan milik merek tersebut.',
        severity: 'danger',
        weight: 20,
        category: 'impersonation',
      })
    }
  }

  if (externalTargets.length > 0) {
    addReason(reasons, {
      id: 'external_target_url',
      label: 'Alamat tujuan tersembunyi di dalam tautan',
      detail: `Alamat yang dibuka memuat alamat lain (${externalTargets
        .map((target) => target.registrable)
        .join(', ')}) pada jalur atau parameternya. Domain pada baris alamat belum tentu situs yang sebenarnya diakses.`,
      severity: 'info',
      weight: 6,
      category: 'obfuscation',
    })
  }

  if (riskyTarget && targetImpersonation) {
    const targetDetail = targetBrand
      ? targetBrand.detail
      : `Domain resmi ${riskyTarget.prefix?.name} (${riskyTarget.prefix?.domain}) hanya menjadi awalan pada ${riskyTarget.target.host}.`

    addReason(reasons, {
      id: riskyTargetStrong ? 'redirect_target_brand' : 'redirect_target_unconfirmed',
      label: riskyTargetStrong
        ? 'Alamat tujuan meniru merek resmi'
        : 'Alamat tujuan memakai nama merek',
      detail: `${targetDetail} Alamat tujuan berada di dalam parameter/jalur tautan, yaitu ${truncate(riskyTarget.target.raw, 70)}.`,
      severity: riskyTargetStrong ? 'danger' : 'warning',
      weight: riskyTargetStrong ? 30 : 16,
      category: 'impersonation',
    })
  } else if (riskyTarget?.ip) {
    addReason(reasons, {
      id: 'redirect_target_ip',
      label: 'Alamat tujuan memakai IP',
      detail: `Tujuan yang tersembunyi di dalam tautan adalah alamat IP (${riskyTarget.target.host}), bukan domain yang bisa dicocokkan dengan layanan resmi.`,
      severity: 'warning',
      weight: 18,
      category: 'obfuscation',
    })
  }

  if (brandMatch?.kind === 'official' && credentialHits.length > 0) {
    addReason(reasons, {
      id: 'official_credential_path',
      label: 'Domain resmi dengan permintaan data',
      detail:
        'Domain cocok dengan situs resmi. Pastikan halaman login memang berada di domain ini dan tidak dialihkan ke alamat lain.',
      severity: 'info',
      weight: 4,
      category: 'request',
    })
  }

  // Jalur URL tetap dibaca meski domain cocok dengan situs resmi: pada
  // "sites.google.com/view/bca-verifikasi-akun" nama merek yang muncul adalah
  // merek lain, dan jalur itu bisa ditulis siapa saja.
  const excludedPathNames = new Set<string>(
    brandMatch ? [brandMatch.brand.name, ...(brandMatch.brand.aliases ?? [])] : [],
  )

  if (!brandMatch || brandMatch.kind === 'official') {
    const explainedSegments = new Set(
      externalTargets.flatMap((target) =>
        target.raw.toLowerCase().split(URL_SEGMENT_SEPARATORS).filter(Boolean),
      ),
    )
    const pathHit = findBrandInPath(url, excludedPathNames, explainedSegments)

    if (pathHit?.wholeSegment) {
      if (credentialHits.length > 0) {
        addReason(reasons, {
          id: 'brand_in_path',
          label: 'Nama merek pada jalur tautan',
          detail:
            'Nama merek muncul di jalur URL, bukan di domain. Domain tetap penentu utama identitas situs.',
          severity: 'warning',
          weight: 12,
          category: 'impersonation',
        })
      } else {
        addReason(reasons, {
          id: 'brand_path_only',
          label: 'Nama merek hanya di jalur tautan',
          detail:
            'Nama merek ditemukan di jalur atau parameter URL, bukan pada domain. Nama di jalur mudah dibuat siapa saja dan bukan penanda identitas situs.',
          severity: 'info',
          weight: 8,
          category: 'impersonation',
        })
      }
    } else if (pathHit) {
      addReason(reasons, {
        id: 'brand_path_word',
        label: 'Nama merek di dalam kata pada jalur tautan',
        detail: pathHit.context
          ? `Jalur URL memuat "${pathHit.segment}": nama ${pathHit.brand.name} digabung dengan kata terkait login, verifikasi, atau hadiah. Jalur dapat dibuat siapa saja, sedangkan ${pathHit.brand.name} hanya memakai domain ${pathHit.brand.domain}.`
          : `Jalur URL memuat "${pathHit.segment}" yang mengandung nama ${pathHit.brand.name}. Nama di jalur bukan penanda identitas: alamat ini terdaftar sebagai ${registrable}, bukan ${pathHit.brand.domain}.`,
        severity: pathHit.context ? 'warning' : 'info',
        weight: pathHit.context ? 10 : 6,
        category: 'impersonation',
      })
    }
  }

  if (hasSuspiciousTld) {
    addReason(reasons, {
      id: 'suspicious_tld',
      label: 'Akhiran domain berisiko',
      detail: `Domain memakai akhiran .${hostTld} yang sering dipakai kampanye phishing, meski juga dipakai situs sah.`,
      severity: 'warning',
      weight: 12,
      category: 'domain',
    })
  }

  if (isShortener) {
    addReason(reasons, {
      id: 'shortener',
      label: 'Tautan pendek',
      detail: 'Layanan pemendek URL menyembunyikan alamat tujuan yang sebenarnya.',
      severity: 'info',
      weight: 10,
      category: 'obfuscation',
    })

    if (credentialHits.length > 0 || giveawayHits.length > 0) {
      addReason(reasons, {
        id: 'shortener_sensitive_combo',
        label: 'Tautan pendek dengan kata sensitif',
        detail:
          'Tautan pendek dikombinasikan dengan kata terkait verifikasi, klaim, atau hadiah.',
        severity: 'warning',
        weight: 12,
        category: 'obfuscation',
      })
    }
  }

  if (isFreeHost) {
    addReason(reasons, {
      id: 'free_host',
      label: 'Subdomain layanan gratis',
      detail:
        'Domain berada di layanan hosting gratis. Layanan ini sah, tetapi sering dipakai untuk halaman penipuan sementara.',
      severity: 'info',
      weight: 6,
      category: 'domain',
    })
  }

  if (isChatHandoff) {
    addReason(reasons, {
      id: 'chat_handoff_link',
      label: 'Tautan membuka ruang percakapan',
      detail: `Alamat ${host} tidak menampilkan halaman web, melainkan memindahkan interaksi ke obrolan. Apa yang sebenarnya dikirim atau diminta baru terlihat di dalam percakapan, jadi klaim pada tautan seperti ini tidak dapat diperiksa dari baris alamat.`,
      severity: 'info',
      weight: 8,
      category: 'obfuscation',
    })
  }

  if (subdomainDepth >= 2) {
    addReason(reasons, {
      id: 'deep_subdomain',
      label: 'Subdomain berlapis',
      detail: `Tautan memakai ${subdomainDepth} level subdomain yang dapat mengaburkan domain utama (${registrable}).`,
      severity: 'warning',
      weight: 10,
      category: 'domain',
    })
  }

  if (giveawayHits.length > 0) {
    addReason(reasons, {
      id: 'giveaway_keywords',
      label: 'Kata terkait hadiah atau klaim',
      detail: `Alamat memuat kata: ${giveawayHits.slice(0, 4).join(', ')}.`,
      severity: 'warning',
      weight: 10,
      category: 'transaction',
    })
  }

  if (credentialHits.length > 0) {
    addReason(reasons, {
      id: 'credential_keywords',
      label: 'Kata terkait data akun',
      detail: `Alamat memuat kata: ${credentialHits.slice(0, 4).join(', ')}.`,
      severity: 'warning',
      weight: 8,
      category: 'request',
    })
  }

  // Bukti gabungan: merek + kata hadiah pada domain yang bukan milik merek.
  if (
    brandMatch &&
    brandMatch.kind !== 'official' &&
    !brandCorroborated &&
    !brandMatch.glued &&
    giveawayHits.length > 0
  ) {
    addReason(reasons, {
      id: 'brand_giveaway_combo',
      label: 'Merek dipadukan dengan kata hadiah',
      detail: `Nama ${brandMatch.brand.name} muncul bersama kata hadiah/promo (${giveawayHits
        .slice(0, 3)
        .join(', ')}) pada domain yang bukan resminya. Klaim hadiah atas nama merek adalah pola umum penipuan.`,
      severity: 'warning',
      weight: 12,
      category: 'transaction',
    })
  }

  if (url.port && !['80', '443'].includes(url.port)) {
    addReason(reasons, {
      id: 'nonstandard_port',
      label: 'Port jaringan tidak umum',
      detail: `Tautan memakai port ${url.port}, bukan port standar 80 atau 443.`,
      severity: 'warning',
      weight: 10,
      category: 'url-structure',
    })
  }

  if (hasEncodedCharacters(url)) {
    addReason(reasons, {
      id: 'encoded_characters',
      label: 'Banyak karakter ter-encode',
      detail:
        'Alamat memuat banyak karakter persen yang dapat menyamarkan isi tautan.',
      severity: 'warning',
      weight: 8,
      category: 'obfuscation',
    })
  }

  if (url.pathname.includes('//')) {
    addReason(reasons, {
      id: 'double_slash_path',
      label: 'Dua garis miring pada jalur',
      detail:
        'Jalur URL memuat "//" yang dapat dipakai menempatkan alamat lain di belakang domain yang tampil.',
      severity: 'info',
      weight: 6,
      category: 'url-structure',
    })
  }

  if (/^https?[-.]/i.test(host)) {
    addReason(reasons, {
      id: 'scheme_like_host',
      label: 'Nama domain meniru imbuhan protokol',
      detail: `Domain "${host}" diawali http/https. Penulisan seperti ini dipakai agar baris alamat tampak seperti situs resmi.`,
      severity: 'warning',
      weight: 8,
      category: 'url-structure',
    })
  }

  if (hasExecutablePath(url)) {
    addReason(reasons, {
      id: 'executable_file',
      label: 'Berkas yang dapat dijalankan',
      detail:
        'Tautan menunjuk ke berkas APK, EXE, atau arsip yang dapat dipakai menyebarkan malware.',
      severity: 'warning',
      weight: 16,
      category: 'request',
    })
  }

  if (normalized.length > 160) {
    addReason(reasons, {
      id: 'long_url',
      label: 'Tautan sangat panjang',
      detail: `Panjang tautan ${normalized.length} karakter, sering dipakai untuk menyembunyikan bagian penting.`,
      severity: 'info',
      weight: 6,
      category: 'url-structure',
    })
  } else if (normalized.length > 100) {
    addReason(reasons, {
      id: 'long_url',
      label: 'Tautan panjang',
      detail: `Panjang tautan ${normalized.length} karakter; periksa bagian domain dengan saksama.`,
      severity: 'info',
      weight: 4,
      category: 'url-structure',
    })
  }

  if (countHyphens(host) >= 2) {
    addReason(reasons, {
      id: 'many_hyphens',
      label: 'Banyak tanda hubung pada domain',
      detail: 'Domain memakai beberapa tanda hubung, pola yang sering dipakai untuk meniru merek.',
      severity: 'warning',
      weight: 8,
      category: 'domain',
    })
  }

  const mainLabel = registrable.split('.')[0]
  if ((!brandMatch || brandMatch.kind === 'official') && looksRandom(mainLabel)) {
    addReason(reasons, {
      id: 'random_domain',
      label: 'Nama domain tampak acak',
      detail: `Nama domain "${mainLabel}" tampak dibuat otomatis dan sulit diingat.`,
      severity: 'warning',
      weight: 8,
      category: 'domain',
    })
  }

  const patterns: DetectedPattern[] = []

  if (brandMatch && brandMatch.kind !== 'official') {
    const category = brandMatch.brand.category
    const highRiskCategory =
      category === 'bank' || category === 'wallet' || category === 'courier'
    raisePattern(
      patterns,
      'impersonation',
      brandCorroborated ? (highRiskCategory ? 'high' : 'medium') : 'low',
    )

    if (credentialHits.length > 0 && !brandGluedWeak) {
      raisePattern(patterns, 'phishing', 'high')
      raisePattern(patterns, 'fake_login', 'high')
    }

    if (brandCorroborated) {
      if (category === 'marketplace') {
        raisePattern(patterns, 'marketplace', 'medium')
      }

      if (category === 'bank' || category === 'wallet') {
        raisePattern(patterns, 'fake_login', credentialHits.length > 0 ? 'high' : 'medium')
      }
    }
  }

  if (brandPrefixHijack) {
    raisePattern(patterns, 'impersonation', 'high')

    if (credentialHits.length > 0) {
      raisePattern(patterns, 'phishing', 'high')
    }
  }

  if (riskyTarget && targetImpersonation) {
    raisePattern(patterns, 'impersonation', riskyTargetStrong ? 'high' : 'low')

    if (riskyTargetStrong) {
      raisePattern(patterns, 'phishing', 'high')

      if (riskyTarget.credential) {
        raisePattern(patterns, 'fake_login', 'high')
      }
    }
  } else if (riskyTarget?.ip) {
    raisePattern(patterns, 'phishing', 'medium')
  }

  if (credentialHits.length > 0) {
    // Kata login/verifikasi saja tidak cukup: situs sah juga memuatnya di jalur.
    // Kunci 'low' naik sendiri lewat blok merek/alamat tujuan di atas.
    raisePattern(patterns, 'fake_login', 'low')
  }

  if (giveawayHits.length > 0) {
    raisePattern(patterns, 'giveaway', 'medium')
  }

  if (patterns.length === 0 && reasons.some((reason) => reason.weight >= 12)) {
    raisePattern(patterns, 'phishing', 'low')
  }

  const technical: TechnicalItem[] = [
    {
      label: 'Domain utama',
      value: registrable,
      tone: brandMatch?.kind === 'official' ? 'neutral' : undefined,
    },
    { label: 'Alamat diperiksa', value: truncate(`${host}${pathname}`, 90) },
    { label: 'Protokol', value: url.protocol.replace(':', '').toUpperCase() },
    {
      label: 'Alamat di dalam tautan',
      value:
        externalTargets.length > 0
          ? truncate(externalTargets.map((target) => target.host).join(', '), 60)
          : 'Tidak ada',
      tone: riskyTarget ? 'danger' : externalTargets.length > 0 ? 'warning' : 'neutral',
    },
    {
      label: 'Subdomain',
      value: subdomainDepth > 0 ? `${subdomainDepth} level` : 'Tidak ada',
      tone: subdomainDepth >= 2 ? 'warning' : 'neutral',
    },
    {
      label: 'Punycode',
      value: hostLabels.some((label) => label.startsWith('xn--')) ? 'Ya' : 'Tidak',
      tone: hostLabels.some((label) => label.startsWith('xn--')) ? 'warning' : 'neutral',
    },
    {
      label: 'Pemendek URL',
      value: isShortener ? 'Ya' : 'Tidak',
      tone: isShortener ? 'warning' : 'neutral',
    },
    {
      label: 'Port',
      value: url.port || 'Standar',
      tone: url.port && !['80', '443'].includes(url.port) ? 'warning' : 'neutral',
    },
    { label: 'Panjang tautan', value: `${normalized.length} karakter` },
  ]

  return buildDraft({
    mode: 'link',
    input: normalized,
    displayTarget: truncate(`${host}${pathname}`, 90),
    reasons,
    patterns,
    technical,
  })
}

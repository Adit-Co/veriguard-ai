import type {
  RedirectHop,
  UrlStructureAnalysis,
  UrlStructureFinding,
  UrlStructureStrength,
} from './types.js'

/**
 * Pemeriksaan struktur ini murni membaca teks URL dan rantai redirect yang sudah
 * diamati probe: tidak ada permintaan jaringan tambahan, tidak ada skrip halaman
 * yang dijalankan, dan tidak ada vonis yang diambil dari sinyal struktur saja.
 */

const MAX_FINDINGS = 18
const MAX_EVIDENCE_CHARS = 120

// Ambang teks URL. Panjang dan kedalaman jalur hanyalah penanda kerja kampanye
// (pendek, sekali pakai, atau sengaja dipotong browser), jadi keduanya lemah.
const LONG_URL_WEAK = 100
const LONG_URL_MODERATE = 200
const MAX_PATH_SEGMENTS = 6

// Digit yang paling sering dipakai untuk menggantikan huruf pada nama merek.
const DIGIT_FOR_LETTER = new Map<string, string>([
  ['0', 'o'], ['1', 'l'], ['3', 'e'], ['5', 's'], ['7', 't'], ['8', 'b'],
])

// Tanda baca yang tidak muncul di jalur URL biasa. Karakter yang memang bagian dari
// sintaks URL (&, =, ?, /, ., -, _, %, #) sengaja tidak dihitung supaya halaman
// berparameter sah tidak ikut tertandai.
const SPECIAL_CHAR_PATTERN = /[`{}[\]|^~!$*()+;<>,]/g

// Suffix multi-level yang umum. Di luar daftar ini domain registrable diperkirakan
// dari dua label terakhir, dan catatan hasil jujur tentang keterbatasan itu.
const MULTI_LEVEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'net.uk', 'ltd.uk', 'plc.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
  'co.id', 'web.id', 'my.id', 'biz.id', 'or.id', 'go.id', 'sch.id', 'net.id', 'ac.id',
  'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.za', 'org.za', 'web.za',
  'com.mx', 'org.mx', 'gob.mx',
  'com.tr', 'org.tr', 'net.tr', 'gov.tr',
  'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg',
  'com.my', 'net.my', 'org.my', 'gov.my',
  'com.ph', 'net.ph', 'org.ph', 'gov.ph',
  'com.vn', 'net.vn', 'org.vn',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.kr', 'or.kr', 'ne.kr', 'go.kr',
  'com.sa', 'com.eg', 'com.pk', 'com.bd', 'com.ng', 'co.ke', 'com.gh', 'com.co',
  'com.ar', 'com.pe', 'com.cl', 'com.ve', 'com.ec', 'com.br',
  'fr.eu', 'com.eu',
])

const RISKY_TLDS = new Set([
  'zip', 'mov', 'country', 'gq', 'tk', 'ml', 'cf', 'ga', 'bu', 'km', 'pg', 'to',
  // gTLD murah yang pola pembeliannya cocok untuk kampanye singkat. Daftar ini
  // sengaja hanya menaikkan sinyal lemah: .info dan .biz juga dipakai banyak situs sah.
  'xyz', 'click', 'loan', 'top', 'biz', 'info', 'store', 'win', 'cyou', 'icu',
  'bond', 'beep', 'rest', 'men', 'download', 'stream', 'party', 'date', 'webcam',
])

const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'trib.li',
  'shorturl.at', 'cutt.ly', 'rebrand.ly', 'rb.gy', 'yi.su', 's.id', 'ini.sh',
])

// Domain resmi setiap merek. Semua domain dalam satu daftar dianggap sah untuk merek itu,
// supaya subdomain milik merek sendiri tidak dibaca sebagai peniruan. Daftarnya transparan
// dan dipakai bersama oleh pemeriksaan host (file ini) dan pemeriksaan halaman (pageSignals).
export const BRAND_DOMAINS: Array<{ label: string; domains: string[] }> = [
  { label: 'Google', domains: ['google.com', 'google.co.id', 'googleapis.com', 'gstatic.com', 'youtube.com'] },
  { label: 'Microsoft', domains: ['microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'office.com', 'onedrive.com'] },
  { label: 'PayPal', domains: ['paypal.com', 'paypal.me'] },
  { label: 'Facebook / Meta', domains: ['facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com', 'meta.com'] },
  { label: 'Netflix', domains: ['netflix.com', 'nflxvideo.net'] },
  { label: 'Amazon', domains: ['amazon.com', 'amazonaws.com', 'amzn.to'] },
  { label: 'Apple', domains: ['apple.com', 'icloud.com'] },
  { label: 'Bank BCA', domains: ['bca.co.id', 'klikbca.com'] },
  { label: 'Bank Mandiri', domains: ['mandiri.co.id'] },
  { label: 'Bank BRI', domains: ['bri.co.id', 'britama.com'] },
  { label: 'Tokopedia', domains: ['tokopedia.com'] },
  { label: 'Shopee', domains: ['shopee.co.id', 'shopee.com'] },
  { label: 'Lazada', domains: ['lazada.co.id', 'lazada.com'] },
  { label: 'Bukalapak', domains: ['bukalapak.com'] },
  { label: 'Gojek / GoTo', domains: ['gojek.com', 'goto.com'] },
  { label: 'DANA', domains: ['dana.id'] },
  { label: 'OVO', domains: ['ovo.co.id'] },
]

// Konfonabel yang paling sering dipakai untuk homograf (Cyrillic/Yunani -> Latin).
const CONFUSABLES = new Map<number, string>([
  [0x0430, 'a'], [0x0435, 'e'], [0x043f, 'p'], [0x0440, 'p'], [0x0441, 'c'], [0x0443, 'y'],
  [0x0445, 'x'], [0x0456, 'i'], [0x0458, 'j'], [0x0455, 's'], [0x04bb, 'h'], [0x04cf, 'l'],
  [0x043c, 'm'], [0x043d, 'h'], [0x0432, 'w'], [0x0434, 'd'], [0x0431, 'b'], [0x0436, 'x'],
  [0x0410, 'a'], [0x0412, 'b'], [0x0415, 'e'], [0x041c, 'm'], [0x041d, 'h'], [0x0421, 'c'],
  [0x0422, 't'], [0x0420, 'p'], [0x0406, 'i'], [0x0408, 'j'], [0x0405, 's'],
  [0x03bf, 'o'], [0x03b1, 'a'], [0x03b9, 'i'], [0x03c5, 'y'], [0x03bd, 'v'], [0x03c9, 'w'],
  [0x0391, 'a'], [0x0392, 'b'], [0x0395, 'e'], [0x0397, 'h'], [0x0399, 'i'], [0x039a, 'k'],
  [0x039c, 'm'], [0x039d, 'n'], [0x03a1, 'p'], [0x03a4, 't'], [0x03a5, 'y'], [0x03a7, 'x'],
])

const CYRILLIC = /[\u0400-\u049f]/
const GREEK = /[\u0370-\u03ff]/
const CJK = /[\u3040-\u30ff\u3400-\u9fff\uf900-\ufaff]/
const ARABIC = /[\u0600-\u06ff]/
const HEBREW = /[\u0590-\u05ff]/

function evidence(value: string): string {
  const cleaned = value.replace(/[\u0000-\u0020\u007f]/g, ' ').replace(/\s+/g, ' ').trim()
  return cleaned.length > MAX_EVIDENCE_CHARS ? `${cleaned.slice(0, MAX_EVIDENCE_CHARS - 1)}…` : cleaned
}

// Nilai digit bootstring RFC 3492: huruf adalah 0-25 dan angka adalah 26-35.
function decodeDigitValue(value: number): number | null {
  if (value >= 0x61 && value <= 0x7a) return value - 0x61
  if (value >= 0x41 && value <= 0x5a) return value - 0x41
  if (value >= 0x30 && value <= 0x39) return value - 0x30 + 26
  return null
}

function adapt(delta: number, count: number, first: boolean): number {
  let value = first ? Math.floor(delta / 700) : Math.floor(delta / 2)
  value += Math.floor(value / count)
  let k = 0
  while (value > 455) {
    value = Math.floor(value / 35)
    k += 36
  }
  return k + Math.floor((36 * value) / (value + 26))
}

/**
 * Decoding bootstring RFC 3492 untuk label `xn--`. Bentuk yang tidak sah
 * menghasilkan null dan penilikannya dilaporkan apa adanya, bukan ditebak.
 */
export function decodePunycodeLabel(label: string): string | null {
  const lowered = label.toLowerCase()
  if (!lowered.startsWith('xn--')) return null
  const body = lowered.slice(4)
  if (body === '') return null

  // Label yang seluruh isinya ter-encode (mis. aksara Cyrillic atau Arab) tidak
  // punya pemisah '-' di dalam body. Menganggapnya rusak akan menyembunyikan
  // homograf, karena bentuk inilah yang justru sering dipakai.
  const delimiter = body.lastIndexOf('-')
  const literal = delimiter < 0 ? '' : body.slice(0, delimiter)

  const codePoints: number[] = []
  for (const char of literal) {
    const value = char.codePointAt(0) ?? 0
    if (value > 0x7f) return null
    codePoints.push(value)
  }

  let n = 0x80
  let bias = 72
  let index = 0
  let position = delimiter < 0 ? 0 : delimiter + 1

  while (position < body.length) {
    const oldIndex = index
    let weight = 1
    for (let k = 36; ; k += 36) {
      if (position >= body.length) return null
      const digit = decodeDigitValue(body.charCodeAt(position))
      position += 1
      if (digit === null) return null
      index += digit * weight
      const threshold = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias
      if (digit < threshold) break
      weight *= 36 - threshold
    }

    const out = codePoints.length + 1
    bias = adapt(index - oldIndex, out, oldIndex === 0)
    n += Math.floor(index / out)
    index %= out
    if (n > 0x10ffff || n <= 0) return null
    codePoints.splice(index, 0, n)
    index += 1
  }

  try {
    return String.fromCodePoint(...codePoints)
  } catch {
    return null
  }
}

function scriptsOf(value: string): string[] {
  const found = new Set<string>()
  if (/[a-z]/i.test(value)) found.add('Latin')
  if (CYRILLIC.test(value)) found.add('Cyrillic')
  if (GREEK.test(value)) found.add('Yunani')
  if (CJK.test(value)) found.add('CJK')
  if (ARABIC.test(value)) found.add('Arab')
  if (HEBREW.test(value)) found.add('Ibrani')
  return [...found]
}

function toAsciiShape(value: string): { text: string; replaced: string[] } {
  let text = ''
  const replaced: string[] = []
  for (const char of value) {
    const mapped = CONFUSABLES.get(char.codePointAt(0) ?? -1)
    if (mapped) {
      text += mapped
      replaced.push(char)
    } else {
      text += char
    }
  }
  return { text, replaced }
}

export function splitLabels(hostname: string): string[] {
  return hostname.toLowerCase().replace(/\.$/, '').split('.').filter(Boolean)
}

/**
 * Domain registrable diperkirakan: suffix dua label dikenali dipakai, selain itu
 * dua label terakhir. Tidak ada layanan public-suffix eksternal yang dipanggil.
 */
export function registrableDomain(hostname: string): string {
  const labels = splitLabels(hostname)
  if (labels.length <= 2) return labels.join('.')
  const tail = `${labels[labels.length - 2]}.${labels[labels.length - 1]}`
  if (MULTI_LEVEL_SUFFIXES.has(tail) && labels.length >= 3) {
    return `${labels[labels.length - 3]}.${tail}`
  }
  return tail
}

function shannonEntropy(value: string): number {
  if (!value) return 0
  const counts = new Map<string, number>()
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1)
  let total = 0
  for (const count of counts.values()) {
    const p = count / value.length
    total -= p * Math.log2(p)
  }
  return total
}

export function levenshteinDistance(left: string, right: string): number {
  if (left === right) return 0
  const rows = left.length + 1
  const columns = right.length + 1
  let previous = Array.from({ length: columns }, (_, index) => index)
  for (let i = 1; i < rows; i += 1) {
    const current = [i]
    for (let j = 1; j < columns; j += 1) {
      const cost = left[i - 1] === right[j - 1] ? 0 : 1
      current[j] = Math.min(previous[j]! + 1, current[j - 1]! + 1, previous[j - 1]! + cost)
    }
    previous = current
  }
  return previous[right.length]!
}

/**
 * Jarak edit dengan batas: berhenti begitu seluruh baris tersisa melebihi `max` dan
 * mengembalikan max + 1. Dipakai untuk pencocokan merek supaya nama host panjang
 * tidak memicu matriks penuh hanya untuk menyimpulkan "tidak mirip".
 */
export function boundedEditDistance(left: string, right: string, max: number): number {
  if (left === right) return 0
  if (Math.abs(left.length - right.length) > max) return max + 1

  const columns = right.length + 1
  let previous = Array.from({ length: columns }, (_, index) => index)
  for (let i = 1; i <= left.length; i += 1) {
    const current = [i]
    let rowMin = i
    for (let j = 1; j < columns; j += 1) {
      const cost = left[i - 1] === right[j - 1] ? 0 : 1
      const value = Math.min(previous[j]! + 1, current[j - 1]! + 1, previous[j - 1]! + cost)
      current[j] = value
      if (value < rowMin) rowMin = value
    }
    if (rowMin > max) return max + 1
    previous = current
  }
  return previous[right.length]!
}

function foldDigitLetters(value: string): string {
  let text = ''
  for (const char of value) text += DIGIT_FOR_LETTER.get(char) ?? char
  return text
}

export function secondLabel(domain: string): string {
  const labels = splitLabels(domain)
  return labels.length >= 3 ? labels[labels.length - 3]! : labels[0] ?? ''
}

function hostFrom(value: string | null): string | null {
  if (!value) return null
  try {
    const url = new URL(value)
    return url.hostname.toLowerCase()
  } catch {
    return null
  }
}

const STRENGTH_RANK: Record<UrlStructureStrength, number> = { strong: 3, moderate: 2, weak: 1 }

function push(
  findings: UrlStructureFinding[],
  finding: Omit<UrlStructureFinding, 'code'> & { code: UrlStructureFinding['code'] },
): void {
  const entry: UrlStructureFinding = {
    ...finding,
    evidence: finding.evidence ? evidence(finding.evidence) : null,
  }
  const existing = findings.findIndex((item) => item.code === finding.code)
  if (existing >= 0) {
    // Kode yang sama bisa ditemukan lewat jalur yang berbeda (misalnya nama merek
    // sebagai label utuh dan sebagai hasil pemetaan digit). Yang terkuat yang dipakai,
    // supaya temuan lemah tidak menutupi temuan yang lebih meyakinkan.
    if (STRENGTH_RANK[finding.strength] > STRENGTH_RANK[findings[existing]!.strength]) {
      findings[existing] = entry
    }
    return
  }
  if (findings.length >= MAX_FINDINGS) return
  findings.push(entry)
}

function examineIdnLabels(
  hostname: string,
  findings: UrlStructureFinding[],
): void {
  const encoded = splitLabels(hostname).filter((label) => label.startsWith('xn--'))
  if (encoded.length === 0) return

  push(findings, {
    code: 'punycode',
    label: 'Label punycode',
    strength: 'moderate',
    detail: 'Nama host memakai label ter-encode (xn--). Bentuk yang ditampilkan browser dapat berisi karakter yang mirip dengan huruf domain resmi.',
    evidence: encoded.join(', '),
  })

  for (const label of encoded) {
    const decoded = decodePunycodeLabel(label)
    if (decoded === null) {
      push(findings, {
        code: 'punycode',
        label: 'Label punycode tidak dapat diurai',
        strength: 'weak',
        detail: `Label \`${label}\` tidak dapat didekode sebagai punycode yang sah, jadi isinya tidak dapat dinilai.`,
        evidence: label,
      })
      continue
    }

    const scripts = scriptsOf(decoded)
    if (scripts.length > 1) {
      push(findings, {
        code: 'mixed_script',
        label: 'Campuran aksara (skrip) pada satu label',
        strength: 'moderate',
        detail: `Label hasil dekode memuat ${scripts.join(' + ')}. Pencampuran aksara adalah teknik homograf yang umum, tetapi juga bisa terjadi pada domain sah.`,
        evidence: `${label} -> ${decoded}`,
      })
    }

    const shape = toAsciiShape(decoded)
    if (shape.replaced.length > 0) {
      const brand = BRAND_DOMAINS.find((entry) =>
        entry.domains.some((domain) => {
          const core = secondLabel(domain)
          return core.length >= 4 && shape.text.toLowerCase().includes(core)
        }),
      )
      push(findings, {
        code: 'homoglyph',
        label: brand ? 'Huruf mirip aksara asing meniru merek' : 'Huruf mirip aksara asing',
        strength: brand ? 'moderate' : 'weak',
        detail: brand
          ? `Setelah konfonabel dipetakan ke bentuk Latin, label "${shape.text}" memuat nama merek ${brand.label} padahal domain aslinya bukan milik merek tersebut.`
          : `Label hasil dekode memuat ${shape.replaced.length} karakter dari aksara lain yang berbentuk mirip huruf Latin.`,
        evidence: `${label} -> ${decoded} ~ ${shape.text}`,
      })
    }
  }
}

function examineBrands(
  hostname: string,
  pathAndQuery: string,
  findings: UrlStructureFinding[],
): void {
  const registrable = registrableDomain(hostname)
  const lowerHost = hostname
  const lowerPath = pathAndQuery.toLowerCase()
  const candidate = secondLabel(registrable)
  // Merek pendek (BCA, BRI, OVO, PLN) hanya dinilai bila muncul sebagai label atau
  // segmen hipon yang utuh. Kecocokan substring pada tiga huruf terlalu mudah salah.
  const hostTokens = new Set(
    splitLabels(hostname).flatMap((label) => label.split('-')).filter((part) => part.length > 0),
  )
  // Domain resmi merek sah menautkan banyak merek lain di jalurnya (metode bayar,
  // tautan afiliasi, halaman dukungan). Selama domain registrable milik salah satu
  // merek dalam daftar, penyebutan di jalur tidak dinilai sama sekali.
  const onOfficialBrandDomain = BRAND_DOMAINS.some((brand) => brand.domains.includes(registrable))

  for (const brand of BRAND_DOMAINS) {
    const owned = brand.domains.includes(registrable)
    if (owned) continue

    let hostCoreSeen: string | null = null

    for (const domain of brand.domains) {
      const core = secondLabel(domain)
      if (core.length < 3) continue

      const exactLabel = hostTokens.has(core)
      const substring = core.length >= 4 && lowerHost.includes(core)

      if (exactLabel || substring) {
        hostCoreSeen = core
        // Label host yang utuh adalah cocok yang paling meyakinkan, tapi hanya untuk
        // nama panjang. "ovo", "bca", "dana" juga dimiliki situs sah lain atau merupakan
        // kata umum, jadi nama pendek tetap lemah.
        push(findings, {
          code: 'brand_in_host',
          label: `Nama merek ${brand.label} di luar domain resminya`,
          strength: exactLabel && core.length >= 5 ? 'moderate' : 'weak',
          detail: exactLabel
            ? `Segmen nama host "${core}" muncul utuh, padahal domain registrable ${registrable} bukan domain resmi ${brand.label} (${domain}).`
            : `Nama host memuat substring "${core}", tetapi domain registrable ${registrable} bukan domain resmi ${brand.label}. Cocok substring lebih lemah daripada label utuh.`,
          evidence: hostname,
        })
      }

      // Label registrable dibandingkan per segmen hipon juga: "m1crosoft-support"
      // tidak mirip "microsoft" sebagai satu rangkaian, tetapi segmen pertamanya mirip.
      const distanceTargets = [...new Set([candidate, ...candidate.split('-')])].filter(
        (part) => part.length >= 5 && part !== core,
      )
      for (const target of distanceTargets) {
        // Digraf yang mudah tertukar (rn vs m, vv vs w) dilipat lebih dulu, karena
        // "rnandiri" adalah peniruan "mandiri" yang tidak berjarak 1 secara harfiah.
        const folded = foldLookalikeDigraphs(target)
        const literal = boundedEditDistance(target, core, 2)
        const collapsed = folded === target ? literal : boundedEditDistance(folded, core, 2)
        // Lipatan yang hasilnya persis nama merek tidak dilaporkan sebagai jarak 0:
        // yang dibandingkan adalah tulisan user, jadi itu tetap satu langkah edits.
        const distance = collapsed === 0 ? 1 : Math.min(literal, collapsed)
        if (distance >= 1 && distance <= 2) {
          push(findings, {
            code: 'typosquat',
            label: `Domain mirip merek ${brand.label}`,
            strength: distance === 1 ? 'moderate' : 'weak',
            detail: `Segmen registrable "${target}" berbeda ${distance} karakter dari "${core}" milik ${brand.label}${
              folded !== target && collapsed <= literal ? ' (setelah digraf yang mudah tertukar dilipat)' : ''
            }. Kemiripan seperti ini dipakai untuk typosquatting, tetapi juga bisa merupakan kebetulan.`,
            evidence: `${target} ~ ${core}`,
          })
        }
      }

      // Penulisan merek di jalur URL sangat lazim di halaman sah (berita, ulasan,
      // tautan afiliasi). Temuan ini dibuat justru untuk menyatakan bahwa nama merek
      // di jalur BUKAN bukti peniruan selama domain registrable tidak terkait.
      if (
        !onOfficialBrandDomain &&
        core.length >= 6 &&
        hostCoreSeen === null &&
        brandMentionPattern(core).test(lowerPath)
      ) {
        push(findings, {
          code: 'brand_in_path',
          label: `Nama merek ${brand.label} hanya muncul di jalur URL`,
          strength: 'weak',
          detail: `"${core}" terdapat pada jalur/query, sedangkan domain registrable ${registrable} bukan milik ${brand.label}. Penyebutan merek di jalur biasa terjadi pada halaman sah dan tidak dibaca sebagai peniruan tanpa bukti lain.`,
          evidence: lowerPath.slice(0, 120),
        })
      }
    }
  }
}

function brandMentionPattern(core: string): RegExp {
  const escaped = core.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(`(^|[/.\\-_=])${escaped}([/.\\-_?&=]|$)`)
}

/**
 * Digraf yang sering tertukar saat nama merek diketik ulang atau dibuat dengan
 * karakter pengganti. Hanya dua pasangan yang paling umum di latin; melipat lebih
 * banyak akan membuat hampir semua domain terlihat mirip.
 */
const LOOKALIKE_DIGRAPHS: Array<readonly [string, string]> = [
  ['rn', 'm'],
  ['vv', 'w'],
]

function foldLookalikeDigraphs(value: string): string {
  let folded = value
  for (const [pair, replacement] of LOOKALIKE_DIGRAPHS) folded = folded.replaceAll(pair, replacement)
  return folded
}

/**
 * Rasio digit-terhadap-huruf pada label registrable. Dua digit saja belum berarti;
 * yang menaikkan kekuatan adalah ketika digit tersebut adalah pengganti huruf yang
 * menghasilkan nama merek.
 */
function examineDigitShape(registrable: string, findings: UrlStructureFinding[]): void {
  const whole = secondLabel(registrable)
  // Segmen di dalam hipon ikut dinilai: domain kampanye sering menempelkan kata
  // lain di belakang merek ("m1crosoft-support"), sehingga rangkaian utuhnya tidak
  // lagi mirip merek mana pun.
  const shapes = [...new Set([whole, ...whole.split('-')])].filter((part) => part.length >= 4)

  for (const core of shapes) {
    const digits = (core.match(/[0-9]/g) ?? []).length
    const letters = (core.match(/[a-z]/gi) ?? []).length
    if (digits === 0 || letters === 0) continue

    const ratio = digits / (digits + letters)
    const folded = foldDigitLetters(core)
    // Pelipatan digit dianggap mengenai merek hanya kalau hasilnya benar-benar
    // lebih dekat ke merek daripada bentuk aslinya.
    const foldedBrand =
      folded === core
        ? null
        : BRAND_DOMAINS.find((brand) =>
            brand.domains.some((domain) => {
              const other = secondLabel(domain)
              return other.length >= 4 && (folded === other || folded.includes(other))
            }),
          )

    if (!foldedBrand && (digits < 2 || ratio < 0.25)) continue

    push(findings, {
      code: 'digit_heavy',
      label: foldedBrand
        ? `Digit pada domain membentuk nama merek ${foldedBrand.label}`
        : 'Label registrable mencampur digit dan huruf',
      strength: foldedBrand ? 'moderate' : 'weak',
      detail: foldedBrand
        ? `Segmen "${core}" menjadi "${folded}" setelah digit dipetakan ke huruf yang biasa ditirunya, yaitu nama merek ${foldedBrand.label}. Domain merek asli tetap ${registrable} bukan miliknya, jadi ini penanda peniruan, bukan kepastian.`
        : `Segmen "${core}" memuat ${digits} digit dari ${digits + letters} karakter alfanumerik (rasio ${ratio.toFixed(2)}). Domain buatan otomatis sering berbentuk seperti ini, tetapi banyak juga merek sah yang memakai angka.`,
      evidence: `${core} -> ${folded}`,
    })
  }
}

function examineTextShape(url: URL, findings: UrlStructureFinding[]): void {
  const href = url.href
  if (href.length >= LONG_URL_WEAK) {
    push(findings, {
      code: 'long_url',
      label: 'URL sangat panjang',
      strength: href.length >= LONG_URL_MODERATE ? 'moderate' : 'weak',
      detail: `Panjang URL ${href.length} karakter. URL sepanjang ini biasanya dipotong secara visual oleh aplikasi chat dan browser, sehingga bagian pentingnya tidak terbaca pengguna.`,
      evidence: `${href.length} karakter`,
    })
  }

  const segments = url.pathname.split('/').filter(Boolean)
  if (segments.length >= MAX_PATH_SEGMENTS) {
    push(findings, {
      code: 'deep_path',
      label: 'Jalur URL sangat dalam',
      strength: 'weak',
      detail: `Jalur memuat ${segments.length} segmen. Kedalaman jalur dipakai untuk meniru struktur halaman resmi atau menyembunyikan bagian penting di belakang.`,
      evidence: url.pathname.slice(0, 120),
    })
  }

  const rawPath = `${url.pathname}${url.search}`
  // Bentuk hasil decoding ikut dihitung karena URL yang sengaja di-encode
  // justru menyembunyikan tanda bacanya dari bentuk mentah.
  const specialCount = Math.max(
    (rawPath.match(SPECIAL_CHAR_PATTERN) ?? []).length,
    (safeDecode(rawPath).match(SPECIAL_CHAR_PATTERN) ?? []).length,
  )
  if (specialCount >= 6) {
    push(findings, {
      code: 'special_heavy',
      label: 'Kepadatan tanda baca tidak lazim',
      strength: 'weak',
      detail: `Jalur/query memuat ${specialCount} tanda baca di luar sintaks URL standar. Campuran seperti ini umum pada muatan hasil encoding atau upaya melewati penyaringan teks.`,
      evidence: rawPath.slice(0, 120),
    })
  }
}

function examineEncodingAndDelimiters(
  url: URL,
  findings: UrlStructureFinding[],
): void {
  const rawPath = `${url.pathname}${url.search}`
  const percentCount = (rawPath.match(/%[0-9a-f]{2}/gi) ?? []).length
  const doubleEncoded = /%25[0-9a-f]{2}/i.test(rawPath)
  const encodedDelimiters = /%2540|%40|%2f|%252f|%5c|%26%26/i.test(rawPath)
  const ratio = rawPath.length > 0 ? percentCount * 3 / rawPath.length : 0

  if (percentCount >= 6 || doubleEncoded || ratio >= 0.3) {
    push(findings, {
      code: 'over_encoded',
      label: 'Pengkodean persen berlebihan',
      strength: doubleEncoded ? 'moderate' : 'weak',
      detail: doubleEncoded
        ? `Terdapat ${percentCount} sekuen ter-encode dan bentuk double-encoding (%25..) pada jalur/query, sehingga apa yang sebenarnya dibaca server tidak terlihat langsung.`
        : `Terdapat ${percentCount} sekuen %XX (±${Math.round(ratio * 100)}% dari jalur/query). Pengkodean berulang dipakai untuk menyamarkan tujuan.`,
      evidence: rawPath,
    })
  }

  if (encodedDelimiters) {
    push(findings, {
      code: 'encoded_delimiter',
      label: 'Pembatas terselubung di jalur',
      strength: 'weak',
      detail: 'Jalur atau query memuat pembatas yang disandikan (%40, %2f, %5c), pola yang dipakai untuk menghindari penyaringan teks.',
      evidence: rawPath,
    })
  }

  const backslash = rawPath.includes('\\')
  const doubleSlash = /\/{2,}[^/]/.test(url.pathname)
  const controlChar = /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(rawPath)
  if (backslash || doubleSlash || controlChar) {
    const kinds = [
      backslash ? 'garis miring terbalik (\\)' : null,
      doubleSlash ? 'garis miring ganda (//)' : null,
      controlChar ? ' karakter kontrol' : null,
    ].filter(Boolean)
    push(findings, {
      code: 'delimiter_trick',
      label: 'Pembatas tidak lazim',
      strength: controlChar ? 'moderate' : 'weak',
      detail: `Jalur URL memakai ${kinds.join(', ')}. Parser yang berbeda dapat menafsirkan pembatas seperti ini secara berbeda.`,
      evidence: url.pathname,
    })
  }

  const embeddedEncoded = /https?%3a%2f%2f/i.test(rawPath)
  const decoded = safeDecode(safeDecode(rawPath))
  const embeddedFound = decoded.match(/https?:\/\/[a-z0-9.-]+\.[a-z]{2,}/i)?.[0] ?? null
  if (embeddedFound || embeddedEncoded) {
    push(findings, {
      code: 'embedded_url',
      label: 'URL lain tertanam dalam parameter',
      strength: 'moderate',
      detail: embeddedFound
        ? `Setelah decoding, jalur/query memuat URL lain (${embeddedFound}). Parameter seperti ini dipakai sebagai tujuan redirect berikutnya.`
        : 'Jalur/query memuat URL lain dalam bentuk ter-encode (http%3A%2F%2F).',
      evidence: embeddedFound ?? rawPath,
    })
  }

  const longToken = rawPath.match(/[a-z0-9+/]{24,}={1,2}$/i)?.[0] ?? null
  if (longToken) {
    push(findings, {
      code: 'encoded_payload',
      label: 'Muatan berbentuk token panjang',
      strength: 'weak',
      detail: 'Jalur/query berakhir dengan token panjang berkarakter base64. Bentuk ini lazim untuk parameter aman, dan juga dipakai untuk menyembunyikan muatan.',
      evidence: longToken,
    })
  }
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

export function analyzeUrlStructure(input: {
  initialUrl: string | null
  finalUrl: string | null
  hostname: string
  hops: RedirectHop[]
}): UrlStructureAnalysis {
  const findings: UrlStructureFinding[] = []
  const notes: string[] = []
  const hostname = input.hostname.toLowerCase().replace(/\.$/, '')

  let parsed: URL | null = null
  try {
    parsed = new URL(input.finalUrl ?? input.initialUrl ?? `https://${hostname}`)
  } catch {
    parsed = null
  }

  if (!parsed) {
    return {
      status: 'unavailable',
      findings: [],
      hostname,
      scheme: null,
      port: null,
      labelCount: splitLabels(hostname).length,
      registrableDomain: null,
      notes: ['URL tidak dapat diurai, jadi sinyal struktur tidak dapat dinilai.'],
    }
  }

  const labels = splitLabels(parsed.hostname)
  const registrable = registrableDomain(parsed.hostname)
  const port = parsed.port || (parsed.protocol === 'https:' ? '443' : parsed.protocol === 'http:' ? '80' : '')

  if (parsed.username || /^[^/?#]*@/i.test(`${parsed.host}`)) {
    push(findings, {
      code: 'userinfo',
      label: 'Karakter @ pada URL',
      strength: 'strong',
      detail: 'Bagian sebelum @ adalah userinfo, jadi host yang benar-benar dihubungi adalah teks setelah @ terakhir. Cara tulis ini dipakai untuk menyamarkan tujuan.',
      evidence: `${parsed.hostname}${parsed.pathname}`,
    })
  }

  const v4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)
  const v6 = parsed.hostname.startsWith('[')
  // Bentuk angka alternatif (0x7f000001, 2130706433, 127.1) juga host non-domain.
  const numericLiteral =
    !v4 &&
    !v6 &&
    (parsed.hostname.startsWith('0x') ||
      (/^[0-9.]+$/.test(parsed.hostname) && parsed.hostname.includes('.')))
  if (v4 || v6 || numericLiteral) {
    push(findings, {
      code: 'ip_literal',
      label: 'Host ditulis sebagai alamat IP',
      strength: 'moderate',
      detail: 'Nama host berupa alamat IP, bukan domain. Situs publik yang sah jarang memakai bentuk ini, sehingga identitas pemilik tidak terbaca dari URL.',
      evidence: parsed.hostname,
    })
  }

  if (port && port !== '80' && port !== '443') {
    push(findings, {
      code: 'unusual_port',
      label: 'Port non-standar',
      strength: 'moderate',
      detail: `URL memakai port ${port}, bukan 80/443. Layanan pada port lain jarang berupa situs web biasa.`,
      evidence: `${parsed.hostname}:${port}`,
    })
  }

  if (parsed.protocol === 'http:') {
    push(findings, {
      code: 'insecure_scheme',
      label: 'Skema tanpa enkripsi (http)',
      strength: 'moderate',
      detail: 'URL akhir memakai http, jadi isi halaman dapat dibaca dan diubah di sepanjang jalur jaringan. Situs lama yang belum migrasi juga berbentuk seperti ini.',
      evidence: parsed.href,
    })
  }

  examineIdnLabels(parsed.hostname, findings)
  examineBrands(parsed.hostname, `${parsed.pathname}${parsed.search}`, findings)
  examineDigitShape(registrable, findings)
  examineTextShape(parsed, findings)
  examineEncodingAndDelimiters(parsed, findings)

  if (SHORTENER_DOMAINS.has(registrable)) {
    push(findings, {
      code: 'shortener',
      label: 'Layanan pemendek URL',
      strength: 'weak',
      detail: `Domain registrable ${registrable} dikenal sebagai pemendek URL. Tujuan akhir hanya diketahui sejauh redirect yang benar-benar diikuti pemeriksaan ini.`,
      evidence: registrable,
    })
  }

  const tld = labels[labels.length - 1] ?? ''
  if (RISKY_TLDS.has(tld)) {
    push(findings, {
      code: 'risky_tld',
      label: `TLD .${tld} jarang dipakai situs resmi`,
      strength: 'weak',
      detail: `Ekstensi .${tld} sering muncul pada kampanye singkat karena murah dan longgar. Ekstensi saja tidak pernah menjadi bukti.`,
      evidence: `.${tld}`,
    })
  }

  if (labels.length >= 5) {
    push(findings, {
      code: 'deep_subdomain',
      label: 'Subdomain sangat dalam',
      strength: 'weak',
      detail: `Terdapat ${labels.length} label sebelum TLD. Kedalaman subdomain dipakai untuk menyembunyikan domain registrable ${registrable} di sisi kiri.`,
      evidence: parsed.hostname,
    })
  }

  const core = secondLabel(registrable)
  if (core.length >= 8) {
    const entropy = shannonEntropy(core)
    if (entropy >= 3.6 && !/[aeiouy]{2}/.test(core)) {
      push(findings, {
        code: 'random_label',
        label: 'Label domain tampak acak',
        strength: 'weak',
        detail: `Label "${core}" memiliki entropi Shannon ${entropy.toFixed(2)}. Nama acak cocok dengan pola domain yang dibuat otomatis, namun banyak juga domain sah yang singkat dan acak.`,
        evidence: core,
      })
    }
  }

  const hyphenCore = core.replace(/[^-]/g, '').length
  if (hyphenCore >= 2) {
    push(findings, {
      code: 'hyphen_labels',
      label: 'Domain registrable penuh tanda hubung',
      strength: 'weak',
      detail: `Label "${core}" memakai ${hyphenCore} tanda hubung. Merek besar jarang memakai bentuk ini karena sulit diketik ulang.`,
      evidence: core,
    })
  }

  const hopHosts = input.hops
    .map((hop) => hostFrom(hop.url))
    .filter((host): host is string => Boolean(host))
  const hopDomains = [...new Set(hopHosts.map((host) => registrableDomain(host)))]
  const finalHost = hostFrom(input.finalUrl ?? parsed.href)
  const initialHost = hostFrom(input.initialUrl ?? parsed.href)

  if (hopDomains.length > 1) {
    push(findings, {
      code: 'cross_domain_redirect',
      label: 'Redirect melintasi beberapa domain registrable',
      strength: hopDomains.length >= 3 ? 'moderate' : 'weak',
      detail: `Rantai yang diamati melewati ${hopDomains.length} domain registrable (${hopDomains.slice(0, 4).join(' -> ')}). Melintasi domain belum pasti berbahaya; yang penting adalah siapa tujuan akhirnya.`,
      evidence: hopDomains.join(' -> '),
    })
  }

  if (initialHost && finalHost) {
    const initialSecure = /^https:\/\//i.test(input.initialUrl ?? '')
    const finalSecure = parsed.protocol === 'https:'
    if (initialSecure && !finalSecure) {
      push(findings, {
        code: 'downgrade_redirect',
        label: 'Penurunan dari https ke http',
        strength: 'moderate',
        detail: 'Rantai redirect berakhir pada http dari awal https, sehingga isi halaman tidak terenkripsi pada hop terakhir.',
        evidence: `${registrableDomain(initialHost)} -> ${registrableDomain(finalHost)}`,
      })
    }
  }

  notes.push(
    'Sinyal struktur dihitung dari teks URL dan rantai redirect yang diamati; tidak ada permintaan tambahan untuk menguji teori ini.',
    'Domain registrable diperkirakan dengan daftar suffix multi-level umum. Di luar daftar itu, dua label terakhir dipakai, jadi penilaian merek dapat meleset untuk suffix jarang.',
    'Tidak ada vonis aman atau berbahaya yang diambil dari sinyal struktur saja; sinyalnya berkorelasi dan bukan bukti independen.',
  )
  if (splitLabels(hostname).length === 0) {
    notes.push('Nama host target tidak terbaca, jadi sebagian sinyal tidak dapat dinilai.')
  }

  return {
    status: 'complete',
    findings,
    hostname: parsed.hostname.toLowerCase(),
    scheme: parsed.protocol.replace(/:$/, ''),
    port: port || null,
    labelCount: labels.length,
    registrableDomain: registrable,
    notes,
  }
}

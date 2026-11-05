export function normalizeWhitespace(value: string): string {
  return value.replace(/\s+/g, ' ').trim()
}

export function truncate(value: string, max: number): string {
  if (value.length <= max) return value
  return `${value.slice(0, max - 1).trimEnd()}…`
}

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0
  if (a.length === 0) return b.length
  if (b.length === 0) return a.length

  let previous = Array.from({ length: b.length + 1 }, (_, index) => index)

  for (let i = 1; i <= a.length; i += 1) {
    const current = [i]
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1
      current[j] = Math.min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + cost)
    }
    previous = current
  }

  return previous[b.length]
}

const CONFUSION_PAIRS: Array<[string, string]> = [
  ['0', 'o'],
  ['1', 'l'],
  ['3', 'e'],
  ['4', 'a'],
  ['5', 's'],
  ['7', 't'],
  ['8', 'b'],
  ['9', 'g'],
  ['@', 'a'],
  ['rn', 'm'],
  ['rm', 'm'],
  ['nn', 'm'],
  ['vv', 'w'],
  ['cl', 'd'],
  ['ii', 'n'],
]

export function foldConfusables(value: string): string {
  let folded = value.toLowerCase()

  for (const [from, to] of CONFUSION_PAIRS) {
    folded = folded.split(from).join(to)
  }

  return folded
}

export function isLookalike(label: string, name: string): boolean {
  const foldedLabel = foldConfusables(label)
  const foldedName = foldConfusables(name)

  if (foldedLabel === foldedName) return label !== name && foldedName.length >= 4
  if (foldedName.length < 5 || foldedLabel.length < 4) return false
  if (Math.abs(foldedLabel.length - foldedName.length) > 1) return false
  if (foldedLabel[0] !== foldedName[0]) return false

  const distance = levenshtein(foldedLabel, foldedName)
  return distance > 0 && distance <= (foldedName.length >= 8 ? 2 : 1)
}

export function isIpv4(host: string): boolean {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return false
  return host.split('.').every((part) => Number(part) <= 255)
}

export function isIpHost(host: string): boolean {
  return isIpv4(host) || host.startsWith('[') || host.includes(':')
}

export function isLocalHost(host: string): boolean {
  const normalized = host.toLowerCase().replace(/\.$/, '')

  if (
    normalized === 'localhost' ||
    normalized.endsWith('.localhost') ||
    normalized.endsWith('.local') ||
    normalized.endsWith('.home.arpa') ||
    normalized === '0.0.0.0'
  ) {
    return true
  }

  if (isIpv4(normalized)) {
    const [first, second] = normalized.split('.').map(Number)
    return (
      first === 0 ||
      first === 10 ||
      first === 127 ||
      (first === 100 && second >= 64 && second <= 127) ||
      (first === 192 && second === 168) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 169 && second === 254) ||
      first >= 224
    )
  }

  if (normalized.startsWith('[') || normalized.includes(':')) {
    const address = normalized.startsWith('[')
      ? normalized.slice(1, -1)
      : normalized

    return (
      address === '::' ||
      address.startsWith('::') ||
      address.startsWith('fc') ||
      address.startsWith('fd') ||
      /^fe[89a-f]/.test(address) ||
      address.startsWith('ff') ||
      address.startsWith('64:ff9b:') ||
      address.startsWith('2002:')
    )
  }

  return false
}

export function findMatches(text: string, patterns: RegExp[]): string[] {
  const found = new Set<string>()

  for (const pattern of patterns) {
    const flags = pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`
    const matcher = new RegExp(pattern.source, flags)
    for (const match of text.matchAll(matcher)) {
      const value = match[0]?.trim().toLowerCase()
      if (value) found.add(value)
    }
  }

  return [...found]
}

const LINK_CANDIDATE =
  /(?:https?:\/\/|www\.)[^\s<>"']+|(?:[a-z0-9-]+\.)+(?:com|id|net|org|ly|me|app|site|xyz|top|info|co|io|biz|online|store|shop)(?:\/[^\s<>"']*)?/gi

export function extractLinks(text: string): string[] {
  const matches = text.match(LINK_CANDIDATE) ?? []
  return [...new Set(matches.map((match) => match.replace(/[.,;:!?)]+$/, '')))]
}

// Persentase-encoding dapat dipakai berantai (%252e) untuk menyembunyikan
// alamat tujuan. Dibatasi tiga lapis supaya tidak berlama-lama pada teks panjang.
export function decodePercentEncoded(value: string): string {
  let decoded = value

  for (let round = 0; round < 3; round += 1) {
    let next: string

    try {
      next = decodeURIComponent(decoded)
    } catch {
      break
    }

    if (next === decoded) break
    decoded = next
  }

  return decoded
}

// Alamat absolut yang tertanam di path/query/fragment adalah tujuan yang
// sebenarnya dibuka pengguna, sedangkan host pada baris alamat bisa milik situs lain.
const EMBEDDED_URL =
  /https?:\\{0,2}\/{1,2}[^\s"'<>\\]+|(?<=[/=?&])\/\/[a-z0-9][a-z0-9.-]*\.[a-z]{2,}[^\s"'<>\\]*/gi

export function extractEmbeddedUrls(value: string): string[] {
  const matches = value.match(EMBEDDED_URL) ?? []

  return [
    ...new Set(
      matches
        .map((match) => match.replace(/["'<>,;)\]]+$/, ''))
        .filter((match) => match.length > 6),
    ),
  ].slice(0, 6)
}

export function uppercaseRatio(value: string): number {
  const letters = value.replace(/[^A-Za-z]/g, '')
  if (letters.length === 0) return 0
  return value.replace(/[^A-Z]/g, '').length / letters.length
}

const FALLBACK_REPORTER_NAME = 'Pengguna'
const MAX_VISIBLE_GRAPHEMES = 5
const MAX_VISIBLE_DISPLAY_GRAPHEMES = 4
const STARRED_SUFFIX = '****'
const WHITESPACE_CONTROLS = /[\t\n\v\f\r\u0085\u2028\u2029]+/gu
const UNSAFE_CHARACTERS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu
const NAME_SEPARATOR = /[\s._-]/u

function toWellFormed(value: string): string {
  let result = ''
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (next >= 0xdc00 && next <= 0xdfff) {
        result += value[index] + value[index + 1]
        index += 1
      } else {
        result += '\uFFFD'
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      result += '\uFFFD'
    } else {
      result += value[index]
    }
  }
  return result
}

function graphemes(value: string): string[] {
  if (typeof Intl.Segmenter === 'function') {
    const segmenter = new Intl.Segmenter('id', { granularity: 'grapheme' })
    return Array.from(segmenter.segment(value), (entry) => entry.segment)
  }
  return Array.from(value)
}

const SENSOR_SUFFIX = '(sensor)'

function sanitizeReporterName(value: unknown): string | null {
  if (typeof value !== 'string') return null

  const sanitized = toWellFormed(value)
    .replace(WHITESPACE_CONTROLS, ' ')
    .replace(UNSAFE_CHARACTERS, '')
    .replace(/\s+/gu, ' ')
    .trim()
  return sanitized || null
}

/**
 * Nama pelapor untuk kartu publik. Nama ini disimpan sudah tersamar, sehingga UI
 * dapat memanggil fungsi ini lagi tanpa menyamarkan dua kali. Fungsi ini hanya
 * membentuk label tampilan dan tidak boleh dianggap sebagai kontrol akses.
 */
export function maskReporterName(value: unknown): string {
  const sanitized = sanitizeReporterName(value)
  if (!sanitized) return FALLBACK_REPORTER_NAME
  if (sanitized === FALLBACK_REPORTER_NAME) return sanitized

  if (sanitized.endsWith(SENSOR_SUFFIX)) {
    const visible = sanitized.slice(0, -SENSOR_SUFFIX.length).trim()
    return visible ? sanitized : `${FALLBACK_REPORTER_NAME}${SENSOR_SUFFIX}`
  }

  const parts = graphemes(sanitized)
  const visibleCount =
    parts.length > MAX_VISIBLE_GRAPHEMES
      ? MAX_VISIBLE_GRAPHEMES
      : Math.max(0, parts.length - 2)
  const visible = parts.slice(0, visibleCount).join('').trim()

  return visible
    ? `${visible}${SENSOR_SUFFIX}`
    : `${FALLBACK_REPORTER_NAME}${SENSOR_SUFFIX}`
}

export type ReporterNameDisplay = {
  visible: string
  masked: string
  mode: 'blur' | 'stars' | 'none'
}

function fallbackDisplay(): ReporterNameDisplay {
  return { visible: FALLBACK_REPORTER_NAME, masked: '', mode: 'none' }
}

function starredDisplay(value: string): ReporterNameDisplay {
  const visible = graphemes(value)
    .slice(0, MAX_VISIBLE_DISPLAY_GRAPHEMES)
    .join('')
  return visible
    ? { visible, masked: STARRED_SUFFIX, mode: 'stars' }
    : fallbackDisplay()
}

/**
 * Memisahkan label publik menjadi bagian yang terlihat dan bagian yang perlu
 * diburamkan. Input dari Firestore umumnya sudah berakhiran `(sensor)`; fungsi ini
 * tidak pernah merekonstruksi nama mentah, hanya membagi label yang tersedia.
 * Bagian nama setelah prefiks tetap dirender sebagai satu elemen terpisah agar UI
 * dapat menerapkan blur, dengan fallback bintang bila pembagian aman tidak ada.
 */
export function splitReporterName(value: unknown): ReporterNameDisplay {
  const sanitized = sanitizeReporterName(value)
  if (!sanitized) return fallbackDisplay()
  if (
    sanitized === FALLBACK_REPORTER_NAME ||
    sanitized === `${FALLBACK_REPORTER_NAME}${SENSOR_SUFFIX}`
  ) {
    return fallbackDisplay()
  }

  const alreadyMasked = sanitized.endsWith(SENSOR_SUFFIX)
  const base = alreadyMasked
    ? sanitized.slice(0, -SENSOR_SUFFIX.length)
    : sanitized
  const baseGraphemes = graphemes(base)
  if (baseGraphemes.length === 0) return fallbackDisplay()

  const separatorIndex = base.search(NAME_SEPARATOR)
  const separatorTail =
    separatorIndex >= 0 ? base.slice(separatorIndex + 1).trim() : ''

  if (
    !alreadyMasked &&
    separatorIndex >= 0 &&
    (separatorIndex === 0 || separatorTail.length === 0)
  ) {
    return starredDisplay(base)
  }

  let visibleCount = 0
  if (separatorIndex > 0 && (alreadyMasked || separatorTail.length > 0)) {
    visibleCount = Math.min(
      graphemes(base.slice(0, separatorIndex)).length,
      MAX_VISIBLE_DISPLAY_GRAPHEMES,
    )
    if (alreadyMasked) {
      visibleCount = Math.min(visibleCount, baseGraphemes.length - 1)
    }
  } else if (baseGraphemes.length > MAX_VISIBLE_DISPLAY_GRAPHEMES) {
    visibleCount = MAX_VISIBLE_DISPLAY_GRAPHEMES
    if (alreadyMasked) {
      visibleCount = Math.min(visibleCount, baseGraphemes.length - 1)
    }
  } else if (alreadyMasked && baseGraphemes.length > 1) {
    visibleCount = Math.min(
      baseGraphemes.length - 1,
      MAX_VISIBLE_DISPLAY_GRAPHEMES,
    )
  }

  if (visibleCount <= 0) return starredDisplay(base)

  const visible = baseGraphemes.slice(0, visibleCount).join('')
  const masked = sanitized.slice(visible.length)
  if (!masked) return starredDisplay(base)

  return { visible, masked, mode: 'blur' }
}

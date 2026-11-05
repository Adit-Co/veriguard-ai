const URL_PATTERN = /(?:https?:\/\/|www\.)[^\s<>"']+/gi
const EMAIL_PATTERN = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi
const BARE_DOMAIN_PATTERN =
  /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?:\/[^\s<>"']*)?/gi
const PHONE_PATTERN = /(?:\+62|62|0)8[1-9][0-9\s-]{6,14}/g
const DIGIT_SEQUENCE = /\b(?:\d[ .-]?){6,}\b/g

export const REDACTED_MESSAGE_FALLBACK = 'Pesan tanpa teks yang dapat disimpan.'

export function redactMessagePreview(text: string, maxLength = 140): string {
  const redacted = text
    .replace(URL_PATTERN, '[tautan]')
    .replace(EMAIL_PATTERN, '[email]')
    .replace(BARE_DOMAIN_PATTERN, '[tautan]')
    .replace(PHONE_PATTERN, '[nomor]')
    .replace(DIGIT_SEQUENCE, '[angka]')
    .replace(/\s+/g, ' ')
    .trim()

  if (!redacted) return REDACTED_MESSAGE_FALLBACK
  if (redacted.length <= maxLength) return redacted

  return `${redacted.slice(0, maxLength).trimEnd()}…`
}

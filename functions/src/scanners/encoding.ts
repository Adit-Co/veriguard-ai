const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

export function toBase64Url(value: string): string {
  const bytes = new TextEncoder().encode(value)
  let output = ''

  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index]
    const second = bytes[index + 1]
    const third = bytes[index + 2]

    output += BASE64URL_ALPHABET[first >> 2]
    output += BASE64URL_ALPHABET[((first & 3) << 4) | ((second ?? 0) >> 4)]

    if (second === undefined) break
    output += BASE64URL_ALPHABET[((second & 15) << 2) | ((third ?? 0) >> 6)]

    if (third === undefined) break
    output += BASE64URL_ALPHABET[third & 63]
  }

  return output
}

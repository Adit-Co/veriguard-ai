import { describe, expect, it } from 'vitest'
import {
  detectSensitiveUrl,
  redactSecretFragments,
  redactSensitiveUrlForStorage,
  REDACTED_PATH_SEGMENT,
  sensitiveUrlFragments,
} from './privacy'

describe('deteksi URL sensitif', () => {
  it('menandai parameter token, email, dan nomor telepon', () => {
    expect(detectSensitiveUrl('https://contoh.com/?token=rahasia').sensitive).toBe(true)
    expect(detectSensitiveUrl('https://contoh.com/?email=user@example.com').sensitive).toBe(true)
    expect(detectSensitiveUrl('https://contoh.com/?phone=%2B6281234567890').sensitive).toBe(true)
  })

  it('menandai JWT dan nilai panjang pada jalur', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123456'
    expect(detectSensitiveUrl(`https://contoh.com/reset/${jwt}`).sensitive).toBe(true)
    expect(detectSensitiveUrl('https://contoh.com/invite/abcdefghijklmnop123456').sensitive).toBe(
      true,
    )
  })

  it('tidak menandai URL biasa', () => {
    const result = detectSensitiveUrl('https://contoh.com/artikel?halaman=2&kategori=keamanan')

    expect(result.sensitive).toBe(false)
    expect(result.reasons).toHaveLength(0)
  })

  it('tidak mengembalikan nilai sensitif mentah', () => {
    const result = detectSensitiveUrl('https://contoh.com/?token=abcdef1234567890')

    expect(result.reasons.join(' ')).not.toContain('abcdef1234567890')
  })
})

describe('penyamaran URL untuk penyimpanan permanen', () => {
  const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123456'

  it('membuang kredensial, query, dan fragment', () => {
    const redacted = redactSensitiveUrlForStorage(
      'https://pemakai:rahasia@contoh.com/masuk?token=abcdef1234567890&email=user@example.com#bagian',
    )

    expect(redacted).toBe('https://contoh.com/masuk')
  })

  it('mengganti segmen jalur yang berbentuk token', () => {
    const reset = redactSensitiveUrlForStorage(`https://contoh.com/reset-password/${JWT}`)
    const invite = redactSensitiveUrlForStorage('https://contoh.com/invite/abcdefghijklmnop123456')

    expect(reset).toBe(`https://contoh.com/reset-password/${REDACTED_PATH_SEGMENT}`)
    expect(invite).toBe(`https://contoh.com/invite/${REDACTED_PATH_SEGMENT}`)
  })

  it('mempertahankan host dan jalur biasa supaya riwayat tetap dikenali', () => {
    const redacted = redactSensitiveUrlForStorage('https://contoh.com/artikel/penipuan-otp?halaman=2')

    expect(redacted).toBe('https://contoh.com/artikel/penipuan-otp')
  })

  it('tidak mengubah URL yang memang tidak membawa nilai sensitif', () => {
    const safe = 'https://contoh.com/artikel/penipuan-otp'

    expect(redactSensitiveUrlForStorage(safe)).toBe(safe)
  })

  it('berbentuk titik-tetap dan menelan input tanpa protokol', () => {
    const once = redactSensitiveUrlForStorage(`https://contoh.com/reset/${JWT}?t=1`)
    const tokenless = redactSensitiveUrlForStorage('contoh.com/reset/abcdefghijklmnop123456')

    expect(redactSensitiveUrlForStorage(once)).toBe(once)
    expect(tokenless).toBe(`https://contoh.com/reset/${REDACTED_PATH_SEGMENT}`)
  })

  it('menyembunyikan nilai sensitif sehingga tidak lolos ke hasil serialisasi', () => {
    const redacted = redactSensitiveUrlForStorage(
      'https://contoh.com/o/auth?refresh_token=abcdefghijklmnop12345678901234',
    )

    expect(redacted).not.toContain('abcdefghijklmnop12345678901234')
    expect(detectSensitiveUrl(redacted).sensitive).toBe(false)
  })

  it('mengumpul potongan sensitif lalu menyapunya dari teks lain', () => {
    const raw = 'https://contoh.com/reset/abcdefghijklmnop123456?email=user%40contoh.com'
    const fragments = sensitiveUrlFragments(raw)

    expect(fragments).toEqual(
      expect.arrayContaining(['abcdefghijklmnop123456', 'user@contoh.com', 'user%40contoh.com']),
    )

    const echoed = redactSecretFragments(
      'Alamat diperiksa: contoh.com/reset/abcdefghijklmnop123456 (user@contoh.com)',
      fragments,
    )

    expect(echoed).toBe(
      `Alamat diperiksa: contoh.com/reset/${REDACTED_PATH_SEGMENT} (${REDACTED_PATH_SEGMENT})`,
    )
  })

  it('mengabaikan nilai pendek supaya teks biasa tidak rusak', () => {
    expect(sensitiveUrlFragments('https://contoh.com/?q=abc123')).toEqual([])
    expect(sensitiveUrlFragments('bukan-url')).toEqual([])
  })
})

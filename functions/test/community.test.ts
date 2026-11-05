import { HttpsError } from 'firebase-functions/v2/https'
import { describe, expect, it } from 'vitest'
import {
  parseListLimit,
  parseReviewInput,
  parseSubmitInput,
  parseUrlPayload,
} from '../src/community/validation.js'
import { CommunityUrlError, normalizeCommunityUrl } from '../src/community/url.js'

function expectHttpsError(callback: () => unknown, code: string): void {
  try {
    callback()
    throw new Error('Fungsi seharusnya menolak input.')
  } catch (error) {
    expect(error).toBeInstanceOf(HttpsError)
    expect((error as HttpsError).code).toBe(code)
  }
}

describe('normalisasi URL backend', () => {
  it('menyamakan identitas URL yang setara', () => {
    expect(normalizeCommunityUrl('Contoh.COM:443/a/../b?utm_source=x&b=2&a=1#x')).toBe(
      'https://contoh.com/b?a=1&b=2',
    )
  })

  it('menolak alamat privat dan protokol yang tidak didukung', () => {
    expect(() => normalizeCommunityUrl('http://192.168.0.1')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('http://[::ffff:127.0.0.1]')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('http://[fe90::1]')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('http://app.localhost')).toThrow(CommunityUrlError)
    expect(() => normalizeCommunityUrl('ftp://contoh.com/file')).toThrow(CommunityUrlError)
  })
})

describe('validasi input laporan', () => {
  it('menormalkan URL dan mempertahankan kategori serta alasan', () => {
    const parsed = parseSubmitInput({
      url: 'contoh.com/path?utm_medium=promo',
      category: 'phishing',
      reason: '  Halaman ini meminta kata sandi melalui formulir palsu.  ',
    })

    expect(parsed.url).toBe('https://contoh.com/path')
    expect(parsed.category).toBe('phishing')
    expect(parsed.reason).toBe('Halaman ini meminta kata sandi melalui formulir palsu.')
  })

  it('menolak kategori tidak dikenal dan alasan yang terlalu pendek', () => {
    expectHttpsError(
      () => parseSubmitInput({ url: 'contoh.com', category: 'lainnya', reason: 'a'.repeat(25) }),
      'invalid-argument',
    )
    expectHttpsError(
      () => parseSubmitInput({ url: 'contoh.com', category: 'phishing', reason: 'pendek' }),
      'invalid-argument',
    )
  })

  it('menolak alasan berlebih dan karakter NUL', () => {
    expectHttpsError(
      () =>
        parseSubmitInput({
          url: 'contoh.com',
          category: 'other',
          reason: 'a'.repeat(501),
        }),
      'invalid-argument',
    )
    expectHttpsError(
      () =>
        parseSubmitInput({
          url: 'contoh.com',
          category: 'other',
          reason: `Alasan yang cukup panjang\u0000tetapi tidak valid`,
        }),
      'invalid-argument',
    )
  })
})

describe('validasi moderasi', () => {
  it('mewajibkan sumber verifikasi untuk status verified_malicious', () => {
    expectHttpsError(
      () => parseReviewInput({ url: 'contoh.com', status: 'verified_malicious' }),
      'invalid-argument',
    )

    const parsed = parseReviewInput({
      url: 'contoh.com',
      status: 'verified_malicious',
      verificationSource: 'manual_review',
      note: 'Bukti diperiksa manual.',
    })
    expect(parsed.status).toBe('verified_malicious')
    expect(parsed.verificationSource).toBe('manual_review')
  })

  it('menolak status dan sumber verifikasi yang tidak valid', () => {
    expectHttpsError(
      () => parseReviewInput({ url: 'contoh.com', status: 'safe' }),
      'invalid-argument',
    )
    expectHttpsError(
      () =>
        parseReviewInput({
          url: 'contoh.com',
          status: 'verified_malicious',
          verificationSource: 'a'.repeat(121),
        }),
      'invalid-argument',
    )
  })
})

describe('validasi daftar dan konteks', () => {
  it('membatasi jumlah daftar', () => {
    expect(parseListLimit({ limit: 10 })).toBe(10)
    expect(parseListLimit({})).toBe(20)
    expectHttpsError(() => parseListLimit({ limit: 0 }), 'invalid-argument')
    expectHttpsError(() => parseListLimit({ limit: 51 }), 'invalid-argument')
  })

  it('mewajibkan URL pada permintaan konteks', () => {
    expect(parseUrlPayload({ url: 'contoh.com' })).toBe('https://contoh.com/')
    expectHttpsError(() => parseUrlPayload({}), 'invalid-argument')
  })
})

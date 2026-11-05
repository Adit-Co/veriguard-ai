import { describe, expect, it } from 'vitest'
import { redactMessagePreview } from './redactMessage'

describe('redaksi cuplikan pesan', () => {
  it('menyamarkan tautan, email, nomor telepon, dan deretan angka', () => {
    const preview = redactMessagePreview(
      'Kirim OTP 123456 ke https://evil.example/login atau bit.ly/klaim-hadiah, email budi@example.com, atau 0812-3456-7890. Rekening 1234567890.',
    )

    expect(preview).not.toContain('123456')
    expect(preview).not.toContain('evil.example')
    expect(preview).not.toContain('bit.ly')
    expect(preview).not.toContain('budi@example.com')
    expect(preview).not.toContain('0812-3456-7890')
    expect(preview).toContain('[tautan]')
    expect(preview).toContain('[email]')
    expect(preview).toContain('[nomor]')
    expect(preview).toContain('[angka]')
  })

  it('memotong cuplikan pada batas panjang', () => {
    const preview = redactMessagePreview('pesan aman '.repeat(40), 40)

    expect(preview.length).toBeLessThanOrEqual(41)
    expect(preview.endsWith('…')).toBe(true)
  })

  it('memberi fallback ketika tidak ada teks', () => {
    expect(redactMessagePreview('   ')).toBe('Pesan tanpa teks yang dapat disimpan.')
  })
})

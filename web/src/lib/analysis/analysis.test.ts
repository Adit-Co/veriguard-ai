import { describe, expect, it } from 'vitest'
import { analyze, analyzeLink, analyzeMessage, riskLevelFromScore } from './index'
import { validateLinkInput, validateMessageInput } from './validate'

describe('validasi input', () => {
  it('menolak tautan kosong, cacat, atau protokol yang tidak didukung', () => {
    expect(validateLinkInput('').ok).toBe(false)
    expect(validateLinkInput('   ').ok).toBe(false)
    expect(validateLinkInput('https://').ok).toBe(false)
    expect(validateLinkInput('ftp://contoh.com').ok).toBe(false)
    expect(validateLinkInput('javascript:alert(1)').ok).toBe(false)
    expect(validateLinkInput('contoh').ok).toBe(false)
  })

  it('menolak alamat lokal dan privat', () => {
    expect(validateLinkInput('http://localhost:3000').ok).toBe(false)
    expect(validateLinkInput('http://127.0.0.1').ok).toBe(false)
    expect(validateLinkInput('http://192.168.1.1').ok).toBe(false)
    expect(validateLinkInput('http://[::1]').ok).toBe(false)
  })

  it('menambahkan https:// dan menormalkan tautan', () => {
    const result = validateLinkInput('www.bca.co.id')
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.normalized).toBe('https://www.bca.co.id/')
    }
  })

  it('menolak pesan kosong, terlalu pendek, atau terlalu panjang', () => {
    expect(validateMessageInput('').ok).toBe(false)
    expect(validateMessageInput('halo').ok).toBe(false)
    expect(validateMessageInput('a'.repeat(4001)).ok).toBe(false)
    expect(validateMessageInput('Halo, ini pesan yang cukup panjang.').ok).toBe(true)
  })
})

describe('ambang tingkat risiko', () => {
  it('memakai batas 25 dan 60', () => {
    expect(riskLevelFromScore(0)).toBe('low')
    expect(riskLevelFromScore(24)).toBe('low')
    expect(riskLevelFromScore(25)).toBe('medium')
    expect(riskLevelFromScore(59)).toBe('medium')
    expect(riskLevelFromScore(60)).toBe('high')
    expect(riskLevelFromScore(100)).toBe('high')
  })
})

describe('analisis tautan', () => {
  it('menilai domain resmi sebagai risiko rendah tanpa klaim aman', () => {
    const result = analyzeLink('https://www.bca.co.id/id/informasi')

    expect(result.riskLevel).toBe('low')
    expect(result.riskScore).toBeLessThan(25)
    expect(result.reasons).toHaveLength(0)
    expect(result.summary).toContain('bukan jaminan')
    expect(result.meta.aiStatus).toBe('not_used')
  })

  it('tidak menaikkan risiko hanya karena domain resmi punya jalur login', () => {
    const result = analyzeLink('https://www.bca.co.id/login')

    expect(result.riskLevel).toBe('low')
    expect(result.reasons.some((reason) => reason.id === 'official_credential_path')).toBe(true)
  })

  it('menandai domain yang meniru merek sebagai risiko tinggi', () => {
    const result = analyzeLink('https://bca-verifikasi-akun.example/login')

    expect(result.riskLevel).toBe('high')
    expect(result.riskScore).toBeGreaterThanOrEqual(60)
    expect(result.patterns.map((pattern) => pattern.id)).toContain('phishing')
    expect(result.reasons.some((reason) => reason.id === 'brand_impersonation')).toBe(true)
  })

  it('menandai typosquat dengan karakter pengganti', () => {
    const result = analyzeLink('https://paypa1.com/login')

    expect(result.riskLevel).toBe('high')
    expect(result.reasons.some((reason) => reason.id === 'brand_typosquat')).toBe(true)
  })

  it('menandai tautan dengan alamat IP sebagai risiko sedang', () => {
    const result = analyzeLink('http://203.0.113.5/login')

    expect(result.riskLevel).toBe('medium')
    expect(result.reasons.some((reason) => reason.id === 'ip_host')).toBe(true)
  })

  it('menandai pemendek URL yang mengarah ke kata sensitif', () => {
    const result = analyzeLink('https://bit.ly/klaim-hadiah')

    expect(result.riskLevel).toBe('medium')
    expect(result.reasons.some((reason) => reason.id === 'shortener')).toBe(true)
    expect(result.patterns.map((pattern) => pattern.id)).toContain('giveaway')
  })

  it('tidak menjadikan protokol HTTP saja sebagai risiko tinggi', () => {
    const result = analyzeLink('http://example.com')

    expect(result.riskLevel).toBe('low')
    expect(result.reasons.some((reason) => reason.id === 'no_https')).toBe(true)
  })

  it('menandai domain Punycode sebagai risiko sedang', () => {
    const result = analyzeLink('https://xn--bca-9na.com')

    expect(result.riskLevel).toBe('medium')
    expect(result.reasons.some((reason) => reason.id === 'punycode_host')).toBe(true)
  })

  it('menandai karakter @ yang menyamarkan domain sebenarnya', () => {
    const result = analyzeLink('https://bca.co.id@evil.example/login')

    expect(result.riskLevel).not.toBe('low')
    expect(result.reasons.some((reason) => reason.id === 'at_symbol')).toBe(true)
  })
})

describe('analisis pesan', () => {
  it('menilai pesan percakapan biasa sebagai risiko rendah', () => {
    const result = analyzeMessage(
      'Halo, besok kita meeting jam 10 di kantor ya. Jangan lupa bawa laptop.',
    )

    expect(result.riskLevel).toBe('low')
    expect(result.riskScore).toBe(0)
    expect(result.patterns).toHaveLength(0)
    expect(result.summary).toContain('bukan jaminan')
  })

  it('menandai pesan yang meminta OTP sebagai risiko tinggi', () => {
    const result = analyzeMessage(
      'Selamat! Anda menang hadiah Rp10.000.000. Kirim kode OTP Anda sekarang ke bit.ly/klaim-hadiah.',
    )

    expect(result.riskLevel).toBe('high')
    expect(result.riskScore).toBeGreaterThanOrEqual(60)
    expect(result.riskScore).toBeLessThanOrEqual(100)
    expect(result.patterns.map((pattern) => pattern.id)).toContain('otp_theft')
    expect(result.reasons.some((reason) => reason.id === 'otp_request')).toBe(true)
  })

  it('tidak menuduh pesan notifikasi OTP sebagai pencurian OTP', () => {
    const result = analyzeMessage('Kode OTP Anda 123456. Jangan bagikan kepada siapa pun.')

    expect(result.riskLevel).toBe('low')
    expect(result.patterns.map((pattern) => pattern.id)).not.toContain('otp_theft')
    expect(result.reasons.some((reason) => reason.id === 'otp_request')).toBe(false)
  })

  it('menandai tawaran investasi dengan janji pasti sebagai risiko tinggi', () => {
    const result = analyzeMessage(
      'Investasi pasti untung 30% per bulan, tanpa risiko. Transfer sekarang juga.',
    )

    expect(result.riskLevel).toBe('high')
    expect(result.patterns.map((pattern) => pattern.id)).toContain('investment')
    expect(result.reasons.some((reason) => reason.id === 'investment_guarantee')).toBe(true)
  })

  it('menandai lowongan kerja yang meminta biaya', () => {
    const result = analyzeMessage(
      'Lowongan kerja admin, gaji Rp8 juta, tanpa pengalaman. Transfer biaya pelatihan Rp150.000.',
    )

    expect(result.riskScore).toBeGreaterThanOrEqual(25)
    expect(result.patterns.map((pattern) => pattern.id)).toContain('job_scam')
    expect(result.reasons.some((reason) => reason.id === 'job_fee_combo')).toBe(true)
  })

  it('menandai paket tertahan yang meminta pembayaran', () => {
    const result = analyzeMessage(
      'Paket Anda tertahan. Bayar biaya kirim Rp25.000 ke rekening 123456789 sekarang.',
    )

    expect(result.riskScore).toBeGreaterThanOrEqual(25)
    expect(result.patterns.map((pattern) => pattern.id)).toContain('marketplace')
  })

  it('menjalankan analisis lewat pemilih mode', () => {
    const linkResult = analyze({ mode: 'link', value: 'https://example.com' })
    const messageResult = analyze({
      mode: 'message',
      value: 'Halo, ini pesan percakapan biasa tanpa tautan.',
    })

    expect(linkResult.mode).toBe('link')
    expect(messageResult.mode).toBe('message')
  })
})

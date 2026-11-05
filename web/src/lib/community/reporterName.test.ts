import { describe, expect, it } from 'vitest'
import { maskReporterName, splitReporterName } from './reporterName'

describe('maskReporterName', () => {
  it('menyamarkan sisa nama setelah lima karakter pertama', () => {
    expect(maskReporterName('anaksigma')).toBe('anaks(sensor)')
    expect(maskReporterName('Rani Halim')).toBe('Rani(sensor)')
  })

  it('mempertahankan hanya sebagian kecil nama pendek', () => {
    expect(maskReporterName('Dewi')).toBe('De(sensor)')
    expect(maskReporterName('Ani')).toBe('A(sensor)')
  })

  it('menyembunyikan nama yang terlalu pendek untuk disamarkan sebagian', () => {
    expect(maskReporterName('Al')).toBe('Pengguna(sensor)')
    expect(maskReporterName('A')).toBe('Pengguna(sensor)')
  })

  it('memakai nama cadangan untuk nilai kosong atau bukan string', () => {
    expect(maskReporterName('')).toBe('Pengguna')
    expect(maskReporterName('   ')).toBe('Pengguna')
    expect(maskReporterName(null)).toBe('Pengguna')
    expect(maskReporterName(undefined)).toBe('Pengguna')
    expect(maskReporterName(42)).toBe('Pengguna')
  })

  it('membuang karakter kontrol, pemisah baris, dan pengarah bidi', () => {
    expect(maskReporterName('Anak\u202Esigma')).toBe('Anaks(sensor)')
    expect(maskReporterName('Rani\nHalim\tSatu')).toBe('Rani(sensor)')
    expect(maskReporterName('\u200B\u200B')).toBe('Pengguna')
  })

  it('tidak memotong pasangan surrogate yang rusak', () => {
    const masked = maskReporterName('Rani\uD800Halim')

    expect(masked.endsWith('(sensor)')).toBe(true)
    expect(masked).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/)
  })

  it('menangani nama Unicode tanpa memecah grapheme', () => {
    expect(maskReporterName('Jöhn Doe')).toBe('Jöhn(sensor)')
    expect(maskReporterName('👩🏽‍🚀pilot')).toBe('👩🏽🚀pil(sensor)')
    expect(maskReporterName('𝒜naksigma')).toBe('𝒜naks(sensor)')
  })

  it('mengembalikan teks biasa, bukan markup, untuk nama mirip HTML', () => {
    expect(maskReporterName('<img src=x onerror=alert(1)>')).toBe('<img(sensor)')
  })

  it('idempoten untuk nama yang sudah tersamar dari Firestore', () => {
    const stored = ['anaks(sensor)', 'Rani(sensor)', 'De(sensor)', 'A(sensor)']
    for (const value of stored) {
      expect(maskReporterName(value)).toBe(value)
    }
    expect(maskReporterName('Pengguna(sensor)')).toBe('Pengguna(sensor)')
    expect(maskReporterName('Pengguna')).toBe('Pengguna')
  })
})

describe('splitReporterName', () => {
  it('memprioritaskan bagian sebelum pemisah sebagai bagian terlihat', () => {
    expect(splitReporterName('zack.jaka')).toEqual({
      visible: 'zack',
      masked: '.jaka',
      mode: 'blur',
    })
    expect(splitReporterName('zack_jaka')).toEqual({
      visible: 'zack',
      masked: '_jaka',
      mode: 'blur',
    })
    expect(splitReporterName('zack-jaka')).toEqual({
      visible: 'zack',
      masked: '-jaka',
      mode: 'blur',
    })
  })

  it('membagi username tanpa pemisah secara konsisten', () => {
    expect(splitReporterName('zackjaka')).toEqual({
      visible: 'zack',
      masked: 'jaka',
      mode: 'blur',
    })
    expect(splitReporterName('zackj(sensor)')).toEqual({
      visible: 'zack',
      masked: 'j(sensor)',
      mode: 'blur',
    })
    expect(splitReporterName('Rani Halim')).toEqual({
      visible: 'Rani',
      masked: ' Halim',
      mode: 'blur',
    })
  })

  it('memakai bintang untuk username pendek yang tidak dapat dibagi dengan aman', () => {
    expect(splitReporterName('Dewi')).toEqual({
      visible: 'Dewi',
      masked: '****',
      mode: 'stars',
    })
    expect(splitReporterName('Ani')).toEqual({
      visible: 'Ani',
      masked: '****',
      mode: 'stars',
    })
    expect(splitReporterName('A')).toEqual({
      visible: 'A',
      masked: '****',
      mode: 'stars',
    })
    expect(splitReporterName('A(sensor)')).toEqual({
      visible: 'A',
      masked: '****',
      mode: 'stars',
    })
    expect(splitReporterName('zack.')).toEqual({
      visible: 'zack',
      masked: '****',
      mode: 'stars',
    })
  })

  it('memakai fallback untuk nilai kosong atau bukan string', () => {
    for (const value of ['', '   ', null, undefined, 42]) {
      expect(splitReporterName(value)).toEqual({
        visible: 'Pengguna',
        masked: '',
        mode: 'none',
      })
    }
    expect(splitReporterName('Pengguna')).toEqual({
      visible: 'Pengguna',
      masked: '',
      mode: 'none',
    })
    expect(splitReporterName('Pengguna(sensor)')).toEqual({
      visible: 'Pengguna',
      masked: '',
      mode: 'none',
    })
  })

  it('tidak memecah grapheme Unicode', () => {
    expect(splitReporterName('Jöhn Doe')).toEqual({
      visible: 'Jöhn',
      masked: ' Doe',
      mode: 'blur',
    })
    expect(splitReporterName('👩🏽‍🚀pilot')).toEqual({
      visible: '👩🏽🚀pi',
      masked: 'lot',
      mode: 'blur',
    })
    expect(splitReporterName('𝒜naksigma')).toEqual({
      visible: '𝒜nak',
      masked: 'sigma',
      mode: 'blur',
    })
    expect(splitReporterName('Jose\u0301.Dev')).toEqual({
      visible: 'Jose\u0301',
      masked: '.Dev',
      mode: 'blur',
    })
  })

  it('tidak pernah menampilkan username lengkap tanpa bagian tersamarkan', () => {
    for (const value of [
      'zackjaka',
      'zack.jaka',
      'zack-jaka',
      'Dewi',
      'Ani',
      'A',
      'Jöhn Doe',
      '👩🏽‍🚀pilot',
      '𝒜naksigma',
      'zackj(sensor)',
      'Rani(sensor)',
    ]) {
      const parts = splitReporterName(value)
      expect(parts.masked.length).toBeGreaterThan(0)
      expect(parts.mode).not.toBe('none')
      if (parts.visible === value) {
        expect(parts.mode).toBe('stars')
      }
    }
  })
})

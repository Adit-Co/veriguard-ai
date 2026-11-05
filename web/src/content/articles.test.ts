import { describe, expect, it } from 'vitest'
import { articles, getArticle } from './articles'

describe('konten edukasi', () => {
  it('menyediakan delapan artikel dengan slug unik', () => {
    expect(articles).toHaveLength(8)
    expect(new Set(articles.map((article) => article.slug)).size).toBe(articles.length)
  })

  it('setiap artikel memiliki konten yang lengkap', () => {
    for (const article of articles) {
      expect(article.title.length).toBeGreaterThan(10)
      expect(article.summary.length).toBeGreaterThan(40)
      expect(article.intro.length).toBeGreaterThan(40)
      expect(article.takeaway.length).toBeGreaterThan(20)
      expect(article.sections.length).toBeGreaterThanOrEqual(3)
      expect(article.readTime).toMatch(/\d+ menit baca/)

      for (const section of article.sections) {
        expect(section.heading.length).toBeGreaterThan(0)
        expect(section.paragraphs.length).toBeGreaterThan(0)
        expect(section.paragraphs.every((paragraph) => paragraph.length > 20)).toBe(true)
      }
    }
  })

  it('dapat mencari artikel berdasarkan slug', () => {
    expect(getArticle('otp-dan-verifikasi-dua-langkah')?.title).toContain('verifikasi dua langkah')
    expect(getArticle('tidak-ada')).toBeUndefined()
  })
})

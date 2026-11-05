// @vitest-environment jsdom
/// <reference types="node" />

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ThemeToggle } from './ThemeToggle'
import {
  DEFAULT_PREFERENCES,
  PREFERENCES_STORAGE_KEY,
  applyPreferences,
  resetPreferences,
  updatePreferences,
} from '../../lib/preferences/preferences'

// VGL-33B — uji cakupan sakelar tema global (10 poin verifikasi wajib).

// Di environment jsdom import.meta.url bukan skema file, jadi path berkas mengunci ke root
// paket web tempat vitest berjalan ( sama dengan berkas yang dibaca test konfigurasi header).
const CSS_PATH = resolve(process.cwd(), 'src/styles/index.css')
const THEME_INIT_PATH = resolve(process.cwd(), 'public/theme-init.js')
const INDEX_HTML_PATH = resolve(process.cwd(), 'index.html')

function storedTheme(): string | null {
  const raw = window.localStorage.getItem(PREFERENCES_STORAGE_KEY)
  if (!raw) return null
  const parsed = JSON.parse(raw) as { theme?: string }
  return parsed.theme ?? null
}

beforeEach(() => {
  window.localStorage.clear()
  resetPreferences()
  delete document.documentElement.dataset.theme
})

afterEach(() => {
  cleanup()
})

describe('VGL-33B sakelar tema global', () => {
  it('1. default LIGHT tanpa preferensi tersimpan', () => {
    render(<ThemeToggle />)

    expect(screen.getByRole('radio', { name: 'DARK' }).getAttribute('aria-checked')).toBe('false')
    expect(screen.getByRole('radio', { name: 'LIGHT' }).getAttribute('aria-checked')).toBe('true')
    expect(storedTheme()).toBeNull()
  })

  it('2. pindah ke DARK langsung mengubah atribut tema dan menyimpan lokal', () => {
    render(<ThemeToggle />)

    fireEvent.click(screen.getByRole('radio', { name: 'DARK' }))

    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(storedTheme()).toBe('dark')
    expect(screen.getByRole('radio', { name: 'DARK' }).getAttribute('aria-checked')).toBe('true')
  })

  it('3. berpindah kembali ke LIGHT tanpa reload', () => {
    render(<ThemeToggle />)

    fireEvent.click(screen.getByRole('radio', { name: 'DARK' }))
    fireEvent.click(screen.getByRole('radio', { name: 'LIGHT' }))

    expect(document.documentElement.dataset.theme).toBe('light')
    expect(storedTheme()).toBe('light')
  })

  it('4. preferensi bertahan setelah reload (mount ulang membaca localStorage)', () => {
    const first = render(<ThemeToggle />)
    fireEvent.click(screen.getByRole('radio', { name: 'DARK' }))
    first.unmount()

    render(<ThemeToggle />)

    expect(screen.getByRole('radio', { name: 'DARK' }).getAttribute('aria-checked')).toBe('true')
    expect(document.documentElement.dataset.theme).toBe('dark')
  })

  it('5. satu lapis tema untuk seluruh aplikasi: setiap token dasar punya override gelap', () => {
    const css = readFileSync(CSS_PATH, 'utf8')
    const darkBlock = css.slice(css.indexOf("html[data-theme='dark']"))

    for (const token of [
      '--color-canvas',
      '--color-surface',
      '--color-subtle',
      '--color-line',
      '--color-line-strong',
      '--color-ink',
      '--color-ink-soft',
      '--color-ink-muted',
      '--color-accent',
      '--color-accent-soft',
      '--color-on-accent',
    ]) {
      expect(darkBlock).toContain(token)
    }
  })

  it('6. kontrol tunggal kompak: satu pil radiogroup dengan dua opsi, tidak melebar di header', () => {
    render(<ThemeToggle />)

    const group = screen.getByRole('radiogroup', { name: 'Tema tampilan' })
    expect(screen.getAllByRole('radio')).toHaveLength(2)
    expect(group.className).toContain('shrink-0')
    expect(group.className).toContain('rounded-full')
    // Label teks DARK/LIGHT tetap ada pada layar cukup lebar; di bawah xl hanya ikon yang
    // tampil agar pil tidak memaksa navbar overflow, dan nama accessible dijaga aria-label.
    expect(screen.getByRole('radio', { name: 'DARK' }).textContent).toContain('DARK')
    expect(screen.getByRole('radio', { name: 'LIGHT' }).textContent).toContain('LIGHT')
    expect(screen.getByRole('radio', { name: 'DARK' }).getAttribute('aria-label')).toBe('DARK')
    expect(screen.getByRole('radio', { name: 'LIGHT' }).getAttribute('aria-label')).toBe('LIGHT')
    expect(group.className).toContain('w-[5.5rem]')
    expect(group.className).toContain('xl:w-[9rem]')
    expect(
      (screen.getByRole('radio', { name: 'DARK' }).firstElementChild as HTMLElement).nextElementSibling?.className,
    ).toContain('hidden')
  })

  it('7. keyboard: panah menunjuk posisi opsi, bukan men-toggle bolak-balik', () => {
    // Cermin keadaan nyata: sebelum paint atribut tema sudah ditulis (theme-init.js),
    // jadi tes mengunci awalnya LIGHT secara eksplisit alih-alih mengandalkan sisa atribut.
    applyPreferences(updatePreferences({ theme: 'light' }))
    render(<ThemeToggle />)

    const group = screen.getByRole('radiogroup', { name: 'Tema tampilan' })
    screen.getByRole('radio', { name: 'LIGHT' }).focus()

    // Mulai LIGHT: ArrowRight tetap LIGHT, ArrowLeft pindah DARK, ArrowLeft lagi tetap DARK.
    fireEvent.keyDown(group, { key: 'ArrowRight' })
    expect(document.documentElement.dataset.theme).toBe('light')

    fireEvent.keyDown(group, { key: 'ArrowLeft' })
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(screen.getByRole('radio', { name: 'DARK' }).getAttribute('aria-checked')).toBe('true')
    expect(screen.getByRole('radio', { name: 'DARK' }).getAttribute('tabindex')).toBe('0')

    fireEvent.keyDown(group, { key: 'ArrowLeft' })
    expect(document.documentElement.dataset.theme).toBe('dark')

    fireEvent.keyDown(group, { key: 'ArrowRight' })
    expect(document.documentElement.dataset.theme).toBe('light')
  })

  it('8. script anti-flash: tema tersimpan dibaca sebelum paint dan BUKAN inline script', () => {
    const html = readFileSync(INDEX_HTML_PATH, 'utf8')
    expect(html).toContain('<script src="/theme-init.js"></script>')
    // Tidak ada <script> inline di dokumen yang akan menabrak CSP tanpa unsafe-inline.
    expect(html).not.toMatch(/<script(?![^>]*src=)[^>]*>/)

    const source = readFileSync(THEME_INIT_PATH, 'utf8')
    const run = new Function('window', 'document', source) as (
      w: unknown,
      d: unknown,
    ) => void

    const darkDoc = {
      documentElement: { dataset: {} as Record<string, string> },
      querySelector: () => null,
    }
    run(
      {
        localStorage: {
          getItem: () => JSON.stringify({ ...DEFAULT_PREFERENCES, theme: 'dark' }),
        },
      },
      darkDoc,
    )
    expect(darkDoc.documentElement.dataset.theme).toBe('dark')

    const lightDoc = {
      documentElement: { dataset: {} as Record<string, string> },
      querySelector: () => null,
    }
    run({ localStorage: { getItem: () => null } }, lightDoc)
    expect(lightDoc.documentElement.dataset.theme).toBe('light')

    const brokenDoc = {
      documentElement: { dataset: {} as Record<string, string> },
      querySelector: () => null,
    }
    run(
      {
        localStorage: {
          getItem: () => {
            throw new Error('storage tertutup')
          },
        },
      },
      brokenDoc,
    )
    expect(brokenDoc.documentElement.dataset.theme).toBe('light')
  })

  it('9. warna status keamanan lengkap didefinisikan di kedua tema (teks + latar + garis)', () => {
    const css = readFileSync(CSS_PATH, 'utf8')
    const themeBlock = css.slice(0, css.indexOf("html[data-theme='dark']"))
    const darkBlock = css.slice(css.indexOf("html[data-theme='dark']"))

    for (const token of [
      '--color-risk-low',
      '--color-risk-low-bg',
      '--color-risk-low-line',
      '--color-risk-medium',
      '--color-risk-medium-bg',
      '--color-risk-medium-line',
      '--color-risk-high',
      '--color-risk-high-bg',
      '--color-risk-high-line',
      '--color-glass-line',
    ]) {
      expect(themeBlock).toContain(token)
      expect(darkBlock).toContain(token)
    }
  })

  it('10. mount dan interaksi tanpa error konsol', () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined)

    render(<ThemeToggle />)
    fireEvent.click(screen.getByRole('radio', { name: 'DARK' }))
    fireEvent.click(screen.getByRole('radio', { name: 'LIGHT' }))

    expect(consoleError).not.toHaveBeenCalled()
    consoleError.mockRestore()
  })
})

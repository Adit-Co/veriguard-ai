// @ts-check
/// <reference types="node" />
// VGL-36 — bukti fokus, hover, active, dan kontras tombol Masuk pada dua tema.
// Pemakaian: node scripts/vgl36-masuk-style-probe.mjs
import { chromium } from 'playwright'

const BASE = process.env.VGL36_BASE ?? 'http://localhost:5178'

/** @param {string} css @param {string} fg */
function contrastPair(css, fg) {
  const parse = (value) => {
    const m = value.match(/rgba?\(([^)]+)\)/)
    if (!m) return null
    const [r, g, b, a] = m[1].split(',').map((n) => Number.parseFloat(n))
    return { r, g, b, a: a === undefined ? 1 : a }
  }
  const lum = (c) => {
    const f = (v) => {
      const s = v / 255
      return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
    }
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b)
  }
  const bg = parse(css)
  const text = parse(fg)
  if (!bg || !text) return null
  const [l1, l2] = [lum(bg), lum(text)].sort((a, b) => b - a)
  return Number(((l1 + 0.05) / (l2 + 0.05)).toFixed(2))
}

const browser = await chromium.launch()
const results = []

for (const theme of ['light', 'dark']) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 950 } })
  await ctx.addInitScript(`localStorage.setItem('veriguard.preferences.v1', JSON.stringify({ defaultScanMode: 'link', reduceMotion: false, theme: '${theme}' }))`)
  const page = await ctx.newPage()
  await page.goto(`${BASE}/`, { waitUntil: 'load' })
  await page.waitForSelector('header a[href="/masuk"]')

  const masuk = page.locator('header a[href="/masuk"]')
  const base = await masuk.evaluate((el) => {
    const s = getComputedStyle(el)
    return { bg: s.backgroundColor, color: s.color, border: s.borderTopColor, radius: s.borderTopLeftRadius, height: s.height }
  })

  await masuk.focus()
  await page.keyboard.press('Tab')
  await page.keyboard.press('Shift+Tab')
  const focused = await masuk.evaluate((el) => {
    const s = getComputedStyle(el)
    return {
      outlineStyle: s.outlineStyle,
      boxShadow: s.boxShadow.slice(0, 260),
      matches: el.matches(':focus-visible'),
    }
  })

  await masuk.hover()
  await page.waitForTimeout(300)
  const hovered = await masuk.evaluate((el) => {
    const s = getComputedStyle(el)
    return { bg: s.backgroundColor, color: s.color, border: s.borderTopColor }
  })

  const box = await masuk.boundingBox()
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
  await page.mouse.down()
  await page.waitForTimeout(200)
  const active = await masuk.evaluate((el) => {
    const s = getComputedStyle(el)
    return { bg: s.backgroundColor, color: s.color, border: s.borderTopColor }
  })
  await page.keyboard.press('Escape')
  await page.mouse.up()

  const transition = await masuk.evaluate((el) => getComputedStyle(el).transition)

  results.push({
    theme,
    base,
    contrastNormal: contrastPair(base.bg, base.color),
    focused,
    hovered,
    contrastHover: contrastPair(hovered.bg, hovered.color),
    active,
    contrastActive: contrastPair(active.bg, active.color),
    transition,
  })
  await ctx.close()
}

await browser.close()
console.log(JSON.stringify(results, null, 2))

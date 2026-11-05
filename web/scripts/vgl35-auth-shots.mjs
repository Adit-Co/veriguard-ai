// @ts-check
/// <reference types="node" />
// VGL-35 — halaman yang memerlukan sesi (riwayat, dashboard, komunitas, hasil) difoto
// memakai sesi demo lokal pada dev server tanpa konfigurasi akun.
// Pemakaian: node scripts/vgl35-auth-shots.mjs before|after
import { chromium } from 'playwright'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { seedScript } from './vgl35-seed.mjs'

const phase = process.argv[2] === 'after' ? 'after' : 'before'
const BASE = process.env.VGL35_BASE ?? 'http://localhost:5177'
const OUT = resolve(process.cwd(), '../.veriguard/live')
mkdirSync(OUT, { recursive: true })

/** @type {Array<{path: string, name: string}>} */
const PAGES = [
  { path: '/riwayat', name: 'riwayat' },
  { path: '/dashboard', name: 'dashboard' },
  { path: '/komunitas', name: 'komunitas' },
  { path: '/hasil/vgl35-sample', name: 'hasil' },
]

const VIEWPORTS = [
  { name: 'desktop', width: 1440, height: 950 },
  { name: 'laptop', width: 1024, height: 900 },
  { name: 'tablet', width: 820, height: 1000 },
  { name: 'mobile', width: 390, height: 844 },
]

/** @param {import('playwright').Page} page */
async function metrics(page) {
  return page.evaluate(() => {
    const doc = document.documentElement
    const main = document.querySelector('main')
    const h1 = main?.querySelector('h1')
    const h1Box = h1 ? h1.getBoundingClientRect() : null
    const content = main?.querySelector('section, div')
    const cBox = content ? content.getBoundingClientRect() : null
    return {
      scrollW: doc.scrollWidth,
      innerW: window.innerWidth,
      h1X: h1Box ? Math.round(h1Box.left) : null,
      h1W: h1Box ? Math.round(h1Box.width) : null,
      contentX: cBox ? Math.round(cBox.left) : null,
      contentW: cBox ? Math.round(cBox.width) : null,
      footer: (() => {
        const f = document.querySelector('footer')
        if (!f) return null
        const last = main ? main.querySelector('section:last-of-type, div:last-of-type') : null
        const gapToLast = last
          ? Math.round(f.getBoundingClientRect().top - last.getBoundingClientRect().bottom)
          : null
        return {
          h: Math.round(f.getBoundingClientRect().height),
          gapToLast: Number.isFinite(gapToLast) ? gapToLast : null,
        }
      })(),
      centeredBlocks: Array.from(document.querySelectorAll('main h1, main h2')).map((h) => ({
        text: (h.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 40),
        align: getComputedStyle(h).textAlign,
      })),
    }
  })
}

const browser = await chromium.launch()
/** @type {Record<string, unknown>} */
const report = { phase, base: BASE, pages: {} }

for (const viewport of VIEWPORTS) {
  for (const theme of ['light', 'dark']) {
    const ctx = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } })
    await ctx.addInitScript(seedScript(theme))
    const page = await ctx.newPage()
    /** @type {string[]} */
    const errors = []
    page.on('console', (m) => m.type() === 'error' && errors.push(m.text().slice(0, 160)))
    page.on('pageerror', (e) => errors.push(String(e).slice(0, 160)))

    try {
      await page.goto(`${BASE}/masuk`, { waitUntil: 'load', timeout: 30_000 })
      await page.getByLabel('Nama tampilan (opsional)').fill('Penampil VGL35')
      await page.getByRole('button', { name: 'Mulai sesi demo lokal' }).click()
      await page.waitForTimeout(500)
    } catch (error) {
      console.log(`SEED-FAIL ${viewport.name}/${theme}: ${String(error).slice(0, 120)}`)
    }

    for (const p of PAGES) {
      try {
        await page.goto(`${BASE}${p.path}`, { waitUntil: 'load', timeout: 30_000 })
        await page.waitForSelector('main', { timeout: 15_000 })
        await page.waitForTimeout(700)
        const m = await metrics(page)
        const key = `${viewport.name}.${p.name}.${theme}`
        report.pages[key] = { url: page.url(), ...m, errors }
        await page.screenshot({
          path: `${OUT}/vgl35-${phase}-auth-${key}-${theme}.png`,
          fullPage: viewport.width >= 1024,
        })
        if (errors.length) console.log(`ERROR ${key}: ${errors.join(' | ')}`)
        if (m.scrollW > m.innerW) console.log(`OVERFLOW ${key}: ${m.scrollW} > ${m.innerW}`)
      } catch (error) {
        console.log(`SKIP ${viewport.name}/${p.name}/${theme}: ${String(error).slice(0, 120)}`)
      }
    }
    await ctx.close()
  }
}

await browser.close()
writeFileSync(`${OUT}/vgl35-${phase}-auth-metrics.json`, JSON.stringify(report, null, 2))
console.log(`\nselesai ${phase} (sesi): ${Object.keys(report.pages).length} halaman terekam`)

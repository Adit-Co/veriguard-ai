// @ts-check
/// <reference types="node" />
// VGL-35 — harness screenshot + metrik overflow untuk semua halaman penting, dua tema, empat viewport.
// Pemakaian: node scripts/vgl35-shots.mjs before|after
import { chromium } from 'playwright'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const phase = process.argv[2] === 'after' ? 'after' : 'before'
const BASE = process.env.VGL35_BASE ?? 'http://localhost:5174'
const OUT = resolve(process.cwd(), '../.veriguard/live')
mkdirSync(OUT, { recursive: true })

/** @type {Array<{path: string, name: string, needsScan?: boolean}>} */
const PAGES = [
  { path: '/', name: 'beranda' },
  { path: '/periksa', name: 'periksa' },
  { path: '/komunitas', name: 'komunitas' },
  { path: '/riwayat', name: 'riwayat' },
  { path: '/dashboard', name: 'dashboard' },
  { path: '/edukasi', name: 'edukasi' },
  { path: '/masuk', name: 'masuk' },
  { path: '/daftar', name: 'daftar' },
  { path: '/pengaturan', name: 'pengaturan' },
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
    const firstSectionText = main?.querySelector('h1, h2')
    /** @param {Element | null | undefined} el */
    const boxOf = (el) => (el ? el.getBoundingClientRect() : null)
    const h1 = main?.querySelector('h1')
    const h1Box = boxOf(h1)
    const content = main?.querySelector('section, div')
    const cBox = boxOf(content)
    return {
      scrollW: doc.scrollWidth,
      innerW: window.innerWidth,
      h1X: h1Box ? Math.round(h1Box.left) : null,
      h1W: h1Box ? Math.round(h1Box.width) : null,
      contentX: cBox ? Math.round(cBox.left) : null,
      contentW: cBox ? Math.round(cBox.width) : null,
      mainPadTop: main ? Math.round(parseFloat(getComputedStyle(main).paddingTop)) : null,
      footerTop: (() => {
        const f = document.querySelector('footer')
        if (!f) return null
        const last = main ? main.querySelector('section:last-of-type, div:last-of-type') : null
        const gapToLast = last
          ? Math.round(f.getBoundingClientRect().top - last.getBoundingClientRect().bottom)
          : null
        return {
          h: Math.round(f.getBoundingClientRect().height),
          mainPadBottom: main ? Math.round(parseFloat(getComputedStyle(main).paddingBottom)) : null,
          gapToLast: Number.isFinite(gapToLast) ? gapToLast : null,
        }
      })(),
      sectionGaps: Array.from(document.querySelectorAll('main > * > section, main section')).slice(0, 12).map((s) => {
        const cs = getComputedStyle(s)
        return {
          label: (s.querySelector('h2')?.textContent || s.className.toString().slice(0, 24)).trim().slice(0, 34),
          padTop: parseInt(cs.paddingTop, 10),
          padBottom: parseInt(cs.paddingBottom, 10),
          marginTop: parseInt(cs.marginTop, 10),
        }
      }),
      centeredBlocks: Array.from(document.querySelectorAll('main h1, main h2')).map((h) => ({
        text: (h.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 40),
        align: getComputedStyle(h).textAlign,
        tag: h.tagName,
      })),
      firstText: firstSectionText ? (firstSectionText.textContent || '').slice(0, 40) : null,
    }
  })
}

const browser = await chromium.launch()
/** @type {Record<string, unknown>} */
const report = { phase, base: BASE, pages: {} }

for (const viewport of VIEWPORTS) {
  for (const theme of ['light', 'dark']) {
    const ctx = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } })
    const page = await ctx.newPage()
    /** @type {string[]} */
    const errors = []
    page.on('console', (m) => m.type() === 'error' && errors.push(m.text().slice(0, 160)))
    page.on('pageerror', (e) => errors.push(String(e).slice(0, 160)))

    await page.addInitScript(
      ([t]) => {
        window.localStorage.setItem(
          'veriguard.preferences.v1',
          JSON.stringify({ defaultScanMode: 'link', reduceMotion: false, theme: t }),
        )
        // Rekam jejak sah (lolos isScanResult) supaya riwayat/dashboard/hasil terisi saat difoto.
        window.localStorage.setItem(
          'veriguard.scans.v1',
          JSON.stringify([
            {
              id: 'vgl35-sample',
              createdAt: new Date(Date.now() - 3_600_000).toISOString(),
              mode: 'link',
              riskLevel: 'high',
              riskScore: 86,
              input: 'https://tokokita-bayar.com/promo-undian',
              displayTarget: 'tokokita-bayar.com',
              headline: 'Pola penipuan sering muncul pada tautan ini',
              summary:
                'Struktur domain, kata kunci undian, dan permintaan data pribadi membentuk pola penipuan yang umum.',
              reasons: [
                {
                  id: 'brand-lookalike',
                  label: 'Domain menyerupai merek',
                  detail: 'tokokita-bayar.com bukan domain resmi dan baru didaftarkan.',
                  severity: 'danger',
                  weight: 28,
                  category: 'impersonation',
                },
                {
                  id: 'urgency-word',
                  label: 'Desakan segera klaim',
                  detail: 'Frasa "segera klaim" memaksa keputusan cepat.',
                  severity: 'warning',
                  weight: 12,
                  category: 'urgency',
                },
              ],
              patterns: [
                {
                  id: 'giveaway',
                  label: 'Pola undian palsu',
                  description: 'Menawarkan hadiah yang harus diklaim lewat tautan.',
                  confidence: 'high',
                },
              ],
              recommendations: [
                'Buka situs resmi merek lewat pencarian manual, bukan lewat tautan ini.',
                'Jangan isi data pribadi atau kode OTP di halaman yang diklik dari pesan.',
              ],
              technical: [
                { label: 'Panjang URL', value: '39 karakter', tone: 'neutral' },
                { label: 'Subdomain', value: 'tidak dipakai', tone: 'neutral' },
              ],
              meta: {
                engineVersion: 'vgl35-baseline',
                signalCount: 2,
                inputLength: 39,
                aiStatus: 'not_used',
                inputStored: 'full',
              },
            },
          ]),
        )
      },
      [theme],
    )

    for (const p of PAGES) {
      try {
        await page.goto(`${BASE}${p.path}`, { waitUntil: 'load', timeout: 30_000 })
        await page.waitForSelector('main', { timeout: 15_000 })
        await page.waitForTimeout(600)
        const m = await metrics(page)
        const key = `${viewport.name}.${p.name}.${theme}`
        report.pages[key] = { url: page.url(), ...m, errors }
        const file = `${OUT}/vgl35-${phase}-${key}-${theme}.png`
        await page.screenshot({ path: file, fullPage: viewport.width >= 1024 })
        if (errors.length) console.log(`ERROR ${key} ${theme}: ${errors.join(' | ')}`)
        if (m.scrollW > m.innerW) console.log(`OVERFLOW ${key} ${theme}: ${m.scrollW} > ${m.innerW}`)
      } catch (error) {
        console.log(`SKIP ${viewport.name}/${p.name}/${theme}: ${String(error).slice(0, 120)}`)
      }
    }
    await ctx.close()
  }
}

await browser.close()
writeFileSync(`${OUT}/vgl35-${phase}-metrics.json`, JSON.stringify(report, null, 2))
console.log(`\nselesai ${phase}: ${Object.keys(report.pages).length} halaman terekam`)

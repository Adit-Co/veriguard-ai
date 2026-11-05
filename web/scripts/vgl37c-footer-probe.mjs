// @ts-check
/// <reference types="node" />
// VGL-37C — footer per route: /masuk & /daftar tanpa footer, halaman lain tetap.
// Local-only: semua permintaan non-lokal diblokir.
// Pemakaian: node scripts/vgl37c-footer-probe.mjs before|after
import { chromium } from 'playwright'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const BASE = process.env.VGL37C_BASE ?? 'http://localhost:5178'
const PREF_KEY = 'veriguard.preferences.v1'
const phase = process.argv[2] === 'after' ? 'after' : 'before'
const OUT = resolve(process.cwd(), '../.veriguard/live')
mkdirSync(OUT, { recursive: true })

const routes = [
  { name: 'beranda', path: '/' },
  { name: 'masuk', path: '/masuk' },
  { name: 'daftar', path: '/daftar' },
  { name: 'periksa', path: '/periksa' },
  { name: 'edukasi', path: '/edukasi' },
  { name: 'artikel', path: '/edukasi/mengenali-phishing' },
  { name: 'komunitas', path: '/komunitas' },
  { name: 'riwayat', path: '/riwayat' },
  { name: 'dashboard', path: '/dashboard' },
  { name: 'pengaturan', path: '/pengaturan' },
  { name: 'verifikasi-email', path: '/verifikasi-email' },
  { name: 'tidak-ditemukan', path: '/rute-tidak-ada-xyz' },
]

const viewports = [
  { name: 'desktop', width: 1440, height: 950 },
  { name: 'laptop', width: 1024, height: 900 },
  { name: 'tablet', width: 820, height: 1000 },
  { name: 'mobile', width: 390, height: 844 },
]

const browser = await chromium.launch()
/** @type {{phase: string, base: string, states: Record<string, any>}} */
const report = { phase, base: BASE, states: {} }

for (const theme of ['light', 'dark']) {
  for (const viewport of viewports) {
    const ctx = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } })
    await ctx.route('**/*', (route) => {
      const url = route.request().url()
      const local =
        url.startsWith(BASE) ||
        url.startsWith('http://127.0.0.1') ||
        url.startsWith('data:') ||
        url.startsWith('blob:')
      return local ? route.continue() : route.abort()
    })
    await ctx.addInitScript(
      `localStorage.setItem('${PREF_KEY}', JSON.stringify({ defaultScanMode: 'link', reduceMotion: false, theme: '${theme}' }))`,
    )
    const page = await ctx.newPage()
    const errors = []
    page.on('console', (m) => m.type() === 'error' && errors.push(m.text().slice(0, 140)))
    page.on('pageerror', (e) => errors.push(String(e).slice(0, 140)))

    for (const route of routes) {
      await page.goto(`${BASE}${route.path}`, { waitUntil: 'load' })
      await page.waitForSelector('header', { timeout: 20000 })
      await page.waitForTimeout(700)
      const data = await page.evaluate(() => {
        const px = (/** @type {number} */ n) => Math.round(n * 100) / 100;
        const box = (/** @type {Element | null} */ el) => {
          if (!el) return null;
          const r = el.getBoundingClientRect();
          return { l: px(r.left), t: px(r.top), r: px(r.right), b: px(r.bottom), w: px(r.width), h: px(r.height) };
        };
        const footers = Array.from(document.querySelectorAll('footer'));
        const visible = footers.filter((f) => {
          const s = getComputedStyle(f);
          const r = f.getBoundingClientRect();
          return s.display !== 'none' && s.visibility !== 'hidden' && r.height > 0 && r.width > 0;
        });
        const main = document.querySelector('main');
        const mainRect = main ? main.getBoundingClientRect() : null;
        const card = document.querySelector('main div[class*="shadow-card"]');
        return {
          url: location.pathname,
          scrollW: document.documentElement.scrollWidth,
          innerW: window.innerWidth,
          docH: document.documentElement.scrollHeight,
          navbar: box(document.querySelector('header')),
          footerCount: footers.length,
          footerVisibleCount: visible.length,
          footerBox: box(visible[0] || null),
          footerText: visible[0] ? (visible[0].textContent || '').replace(/\s+/g, ' ').trim().slice(0, 48) : null,
          // footer <footer> milik halaman artikel/hasil juga ikut dihitung agar tidak menipu
          footerIsSiteFooter: Boolean(
            visible[0] && /NAVIGASI|TENTANG HASIL|VERIGUARD/.test(visible[0].textContent || ''),
          ),
          mainH: mainRect ? px(mainRect.height) : null,
          cardBox: box(card),
          backdrop: box(document.querySelector('main.auth-canvas')),
        };
      });
      data.errors = errors.filter((e) => !/Failed to load resource|net::ERR/.test(e)).slice(0, 4)
      report.states[`${route.name}.${viewport.name}.${theme}`] = data
      errors.length = 0
      if (route.name === 'masuk' || route.name === 'daftar') {
        await page.screenshot({
          path: `${OUT}/vgl37c-${phase}-footer-${route.name}.${viewport.name}.${theme}.png`,
        })
      }
    }
    await ctx.close()
  }
}

await browser.close()
writeFileSync(resolve(OUT, `vgl37c-${phase}-footer-metrics.json`), JSON.stringify(report, null, 2))

const states = Object.values(report.states)
const galat = states.filter((/** @type {any} */ s) => s.errors?.length).length
const overflow = states.filter((/** @type {any} */ s) => s.scrollW !== s.innerW).length
console.log(
  `selesai ${phase}: ${states.length} rekaman | galat=${galat} | overflow=${overflow}`,
)
for (const [k, s] of Object.entries(report.states)) {
  const /** @type {any} */ v = s
  console.log(
    `${k.padEnd(26)} footer=${v.footerVisibleCount === 0 ? 'TIDAK' : `ADA (h=${v.footerBox?.h}, site=${v.footerIsSiteFooter})`} | navbar h=${v.navbar?.h} | card ${v.cardBox ? `${v.cardBox.w}x${v.cardBox.h} t${v.cardBox.t}` : '—'}`,
  )
}

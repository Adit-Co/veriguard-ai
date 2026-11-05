// @ts-check
/// <reference types="node" />
// VGL-37 — bandingkan posisi box login terhadap baseline (vgl37-before-card-metrics.json).
// Pemakaian: node scripts/vgl37-login-shift-check.mjs
import { chromium } from 'playwright'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const BASE = process.env.VGL37_BASE ?? 'http://localhost:5178'
const PREF_KEY = 'veriguard.preferences.v1'
const baseline = JSON.parse(
  readFileSync(resolve(process.cwd(), '../.veriguard/live/vgl37-before-card-metrics.json'), 'utf8'),
).states

const viewports = [
  { name: 'desktop', width: 1440, height: 950 },
  { name: 'laptop', width: 1024, height: 900 },
  { name: 'tablet', width: 820, height: 1000 },
  { name: 'mobile', width: 390, height: 844 },
]

const browser = await chromium.launch()
const rows = []

for (const viewport of viewports) {
  for (const theme of ['light', 'dark']) {
    const ctx = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } })
    await ctx.route('**/*', (route) => {
      const url = route.request().url();
      const local =
        url.startsWith(BASE) ||
        url.startsWith('http://127.0.0.1') ||
        url.startsWith('data:') ||
        url.startsWith('blob:');
      return local ? route.continue() : route.abort();
    });
    await ctx.addInitScript(
      `localStorage.setItem('${PREF_KEY}', JSON.stringify({ defaultScanMode: 'link', reduceMotion: false, theme: '${theme}' }))`,
    );
    const page = await ctx.newPage()
    await page.goto(`${BASE}/masuk`, { waitUntil: 'load' })
    await page.waitForTimeout(1200)

    const whileOpen = await page.evaluate(() => {
      const card = document.querySelector('main div[class*="shadow-card"]');
      const r = card?.getBoundingClientRect();
      const note = Array.from(document.querySelectorAll('[role="status"]')).find((n) =>
        (n.textContent || '').trim().startsWith('Layanan akun'),
      );
      const nr = note?.getBoundingClientRect();
      return {
        cardTop: r ? Math.round(r.top) : null,
        cardH: r ? Math.round(r.height) : null,
        cardW: r ? Math.round(r.width) : null,
        noteH: nr ? Math.round(nr.height) : null,
      };
    })
    await page.getByRole('button', { name: 'Tutup notifikasi layanan akun' }).click()
    await page.waitForTimeout(600)
    const afterClose = await page.evaluate(() => {
      const card = document.querySelector('main div[class*="shadow-card"]');
      const r = card?.getBoundingClientRect();
      return { cardTop: r ? Math.round(r.top) : null, cardH: r ? Math.round(r.height) : null };
    })
    const key = `masuk.${viewport.name}.${theme}`
    const base = baseline[key]
    rows.push({
      viewport: viewport.name,
      theme,
      baselineCardTop: Math.round(base.card.t),
      baselineCardH: Math.round(base.card.b - base.card.t),
      baselineNoteH: Math.round(base.infoNote.b - base.infoNote.t),
      openCardTop: whileOpen.cardTop,
      selisihSaatTampil: whileOpen.cardTop - Math.round(base.card.t),
      afterCloseCardTop: afterClose.cardTop,
      selisihSesudahTutup: afterClose.cardTop - Math.round(base.card.t),
      lebarKartu: whileOpen.cardW,
      tinggiKartu: whileOpen.cardH,
    })
    await ctx.close()
  }
}

await browser.close()
for (const r of rows) {
  console.log(
    `${(r.viewport + '/' + r.theme).padEnd(16)} baseline y${r.baselineCardTop} (note ${r.baselineNoteH}) · saat notifikasi tampil y${r.openCardTop} (Δ${r.selisihSaatTampil}) · sesudah ditutup y${r.afterCloseCardTop} (Δ${r.selisihSesudahTutup}) · kartu ${r.lebarKartu}×${r.tinggiKartu} (baseline tinggi ${r.baselineCardH})`,
  )
}

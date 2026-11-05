// @ts-check
/// <reference types="node" />
// VGL-37B — bukti tidak ada pergeseran tata letak: posisi kartu login di koordinat dokumen
// diukur sebelum dan sesudah toast hilang, dengan scrollY selalu dikembalikan ke 0 dan
// penutup dipicu lewat click di dalam halaman (bukan click Playwright yang bisa menggulir).
// Pemakaian: node scripts/vgl37b-layout-shift-probe.mjs
import { chromium } from 'playwright'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const BASE = process.env.VGL37B_BASE ?? 'http://localhost:5178'
const PREF_KEY = 'veriguard.preferences.v1'
const OUT = resolve(process.cwd(), '../.veriguard/live')
mkdirSync(OUT, { recursive: true })

const measure = (/** @type {any} */ page) =>
  page.evaluate(() => {
    const card = document.querySelector('main div[class*="shadow-card"]');
    const cr = card ? card.getBoundingClientRect() : null;
    const toast = Array.from(document.querySelectorAll('[role="status"]')).find((n) =>
      (n.textContent || '').includes('Layanan akun'),
    );
    const tr = toast ? toast.getBoundingClientRect() : null;
    const header = document.querySelector('header');
    return {
      scrollY: Math.round(window.scrollY),
      cardDocTop: cr ? Math.round(cr.top + window.scrollY) : null,
      cardDocBottom: cr ? Math.round(cr.bottom + window.scrollY) : null,
      cardSize: cr ? `${Math.round(cr.width)}x${Math.round(cr.height)}` : null,
      toastPresent: Boolean(toast),
      toastFixedTop: tr ? Math.round(tr.top) : null,
      headerBottom: header ? Math.round(header.getBoundingClientRect().bottom) : null,
    };
  });

const browser = await chromium.launch()
/** @type {any[]} */
const evidence = []

for (const theme of ['light', 'dark']) {
  for (const viewport of [
    { name: 'desktop', width: 1440, height: 950 },
    { name: 'laptop', width: 1024, height: 900 },
    { name: 'tablet', width: 820, height: 1000 },
    { name: 'mobile', width: 390, height: 844 },
  ]) {
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
    await page.waitForTimeout(1300)
    const denganToast = await measure(page)

    // tutup lewat DOM: tidak ada langkah menggulir dari driver
    await page.evaluate(() => {
      const el = Array.from(document.querySelectorAll('[role="status"]')).find((n) =>
        (n.textContent || '').includes('Layanan akun'),
      );
      const btn = el ? Array.from(el.querySelectorAll('button')).find((b) => (b.getAttribute('aria-label') || '').includes('Tutup')) : null;
      if (!btn) throw new Error('Tombol tutup tidak ditemukan');
      btn.click();
    });
    await page.waitForTimeout(700)
    const setelahTutup = await measure(page)
    await page.evaluate(() => window.scrollTo(0, 0))
    await page.waitForTimeout(150)
    const sesudahScrollNol = await measure(page)

    evidence.push({
      kombinasi: `${viewport.name}/${theme}`,
      denganToast,
      setelahTutup,
      sesudahScrollNol,
      selisihDocTop:
        denganToast.cardDocTop !== null && sesudahScrollNol.cardDocTop !== null
          ? sesudahScrollNol.cardDocTop - denganToast.cardDocTop
          : null,
      geserScroll: setelahTutup.scrollY,
    })
    await ctx.close()
  }
}

await browser.close()
writeFileSync(resolve(OUT, 'vgl37b-layout-shift.json'), JSON.stringify(evidence, null, 2))
for (const e of evidence) {
  console.log(
    `${e.kombinasi.padEnd(18)} denganToast=${e.denganToast.cardSize} docTop=${e.denganToast.cardDocTop} (toast top=${e.denganToast.toastFixedTop}, navbar=${e.denganToast.headerBottom}) | sesudahTutup docTop=${e.sesudahScrollNol.cardDocTop} | selisih=${e.selisihDocTop} px | scrollAkibatKlik=${e.geserScroll}`,
  );
}

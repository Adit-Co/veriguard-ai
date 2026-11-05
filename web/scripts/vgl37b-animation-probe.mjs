// @ts-check
/// <reference types="node" />
// VGL-37B — bukti animasi masuk/keluar toast: opacity dan perpindahan sumbu dibaca
// berulang pada rentang milidetik, termasuk saat reduce-motion aktif.
// Pemakaian: node scripts/vgl37b-animation-probe.mjs
import { chromium } from 'playwright'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const BASE = process.env.VGL37B_BASE ?? 'http://localhost:5178'
const PREF_KEY = 'veriguard.preferences.v1'
const OUT = resolve(process.cwd(), '../.veriguard/live')
mkdirSync(OUT, { recursive: true })

const sample = (/** @type {any} */ page) =>
  page.evaluate(() => {
    const el = Array.from(document.querySelectorAll('[role="status"]')).find((n) =>
      (n.textContent || '').includes('Layanan akun'),
    );
    if (!el) return { present: false };
    const s = getComputedStyle(el);
    return {
      present: true,
      opacity: Number(s.opacity),
      translate: s.translate,
      transition: s.transitionProperty + ' ' + s.transitionDuration,
    };
  });

/** @param {any} page @param {number} spanMs @param {number} stepMs */
async function sampleWindow(page, spanMs, stepMs) {
  /** @type {any[]} */
  const frames = [];
  const started = Date.now();
  while (Date.now() - started < spanMs) {
    frames.push({ ms: Date.now() - started, ...(await sample(page)) });
    await page.waitForTimeout(stepMs);
  }
  return frames;
}

/** @param {any} context @param {any} page @param {boolean} reduce */
async function openLogin(context, page, reduce) {
  await context.route('**/*', (route) => {
    const url = route.request().url();
    const local =
      url.startsWith(BASE) ||
      url.startsWith('http://127.0.0.1') ||
      url.startsWith('data:') ||
      url.startsWith('blob:');
    return local ? route.continue() : route.abort();
  });
  await context.addInitScript(
    `localStorage.setItem('${PREF_KEY}', JSON.stringify({ defaultScanMode: 'link', reduceMotion: ${reduce}, theme: 'light' }))`,
  );
}

const browser = await chromium.launch()
/** @type {any[]} */
const evidence = []

for (const reduce of [false, true]) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 950 } })
  const page = await ctx.newPage()
  await openLogin(ctx, page, reduce)
  await page.goto(`${BASE}/masuk`, { waitUntil: 'load' })
  const masuk = await sampleWindow(page, 700, 45)
  await page.getByRole('button', { name: 'Tutup notifikasi layanan akun' }).click()
  const keluar = await sampleWindow(page, 700, 45)
  await page.waitForTimeout(400)
  const settled = await sample(page)
  evidence.push({
    langkah: reduce ? 'animasi saat reduce-motion aktif' : 'animasi saat gerak penuh diizinkan',
    framesMasuk: masuk,
    framesKeluar: keluar,
    sesudahTenang: settled,
  })
  await ctx.close()
}

await browser.close()
writeFileSync(resolve(OUT, 'vgl37b-toast-animation.json'), JSON.stringify(evidence, null, 2))
for (const run of evidence) {
  const f = (/** @type {any[]} */ arr) =>
    arr
      .filter((x) => x.present)
      .map((x) => `${x.ms}ms:${x.opacity.toFixed(2)}${x.translate && x.translate !== 'none' ? '/' + x.translate : ''}`)
      .join(' ');
  console.log(run.langkah);
  console.log('  masuk :', f(run.framesMasuk));
  console.log('  keluar:', f(run.framesKeluar));
  console.log('  sesudah:', JSON.stringify(run.sesudahTenang));
}

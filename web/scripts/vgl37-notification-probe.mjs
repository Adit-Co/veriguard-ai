// @ts-check
/// <reference types="node" />
// VGL-37 — perilaku notifikasi layanan akun: auto-show, tutup dengan X, auto-dismiss 30s,
// tanpa hitungan terlihat, timer bersih, dan tidak ada duplikasi karena rerender.
// Pemakaian: node scripts/vgl37-notification-probe.mjs
import { chromium } from 'playwright'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const BASE = process.env.VGL37_BASE ?? 'http://localhost:5178'
const PREF_KEY = 'veriguard.preferences.v1'
const OUT = resolve(process.cwd(), '../.veriguard/live')
mkdirSync(OUT, { recursive: true })

/** @type {any[]} */
const evidence = []

const readNotice = (/** @type {any} */ page) =>
  page.evaluate(() => {
    const el = Array.from(document.querySelectorAll('[role="status"]')).find((n) =>
      (n.textContent || '').trim().startsWith('Layanan akun'),
    );
    if (!el) return { present: false };
    const r = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    const inner = el.querySelector('section');
    const ir = inner ? inner.getBoundingClientRect() : null;
    const close = el.querySelector('button[aria-label]');
    const cr = close ? close.getBoundingClientRect() : null;
    const card = document.querySelector('main div[class*="shadow-card"]');
    const kd = card ? card.getBoundingClientRect() : null;
    return {
      present: true,
      opacity: Number(cs.opacity),
      rows: cs.gridTemplateRows,
      h: Math.round(r.height),
      panelH: ir ? Math.round(ir.height) : null,
      panelW: ir ? Math.round(ir.width) : null,
      closeSize: cr ? `${Math.round(cr.width)}x${Math.round(cr.height)}` : null,
      closeLabel: close ? close.getAttribute('aria-label') : null,
      cardTop: kd ? Math.round(kd.top) : null,
      text: (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 150),
      timerText: /\b\d+\s*(s|detik|sec)\b|\d+:\d\d/i.test(el.textContent || ''),
      overlapsForm: (() => {
        if (!kd) return null;
        return Boolean(ir && ir.bottom > kd.top && ir.height > 0.5);
      })(),
    };
  });

const browser = await chromium.launch()

/** @param {any} context @param {any} page */
async function openLogin(context, page) {
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
    `localStorage.setItem('${PREF_KEY}', JSON.stringify({ defaultScanMode: 'link', reduceMotion: false, theme: 'light' }))`,
  );
  await page.goto(`${BASE}/masuk`, { waitUntil: 'load' });
  await page.waitForTimeout(1200);
}

// ── 1. kemunculan otomatis + animasi + posisi terhadap form ────────────────────
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 950 } })
  const page = await ctx.newPage()
  await openLogin(ctx, page)
  const shown = await readNotice(page)
  const formBox = await page.locator('main form').boundingBox()
  const noticeBox = await page.locator('[role="status"]').first().boundingBox()
  const overlaps =
    noticeBox && formBox
      ? noticeBox.y + noticeBox.height > formBox.y + 1 && noticeBox.height > 1
      : false
  evidence.push({ langkah: 'tampil otomatis saat /masuk dibuka', ...shown, menutupiForm: overlaps })
  await page.screenshot({ path: `${OUT}/vgl37-notification.masuk.light.png` })
  await ctx.close()
}

// ── 2. tombol X menutup notifikasi ─────────────────────────────────────────────
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 950 } })
  const page = await ctx.newPage()
  await openLogin(ctx, page)
  const before = await readNotice(page)
  await page.getByRole('button', { name: 'Tutup notifikasi layanan akun' }).click()
  await page.waitForTimeout(90)
  const mid = await readNotice(page)
  await page.waitForTimeout(600)
  const after = await readNotice(page)
  evidence.push({
    langkah: 'tombol X menutup notifikasi',
    sebelum: { h: before.h, opacity: before.opacity, rows: before.rows },
    segeraSesudahKlik: { h: mid.h, opacity: mid.opacity, rows: mid.rows },
    sesudahAnimasi: after,
  })
  await ctx.close()
}

// ── 3. verifikasi nyata: auto-dismiss setelah 30 detik ─────────────────────────
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 950 } })
  const page = await ctx.newPage()
  await openLogin(ctx, page)
  const started = Date.now()
  const t20 = await readNotice(page)
  await page.waitForTimeout(20_000)
  const at20 = await readNotice(page)
  await page.waitForTimeout(11_000)
  const at31 = await readNotice(page)
  await page.waitForTimeout(700)
  const at32 = await readNotice(page)
  evidence.push({
    langkah: 'auto-dismiss 30 detik (verifikasi nyata)',
    detikMulai: { present: t20.present, h: t20.h, opacity: t20.opacity },
    detik20: { present: at20.present, h: at20.h, opacity: at20.opacity },
    detik31: { present: at31.present, h: at31.h, opacity: at31.opacity },
    detik32: at32,
    elapsedMs: Date.now() - started,
  })
  await ctx.close()
}

// ── 4. tidak ada galat timer saat berpindah halaman di tengah hitungan ─────────
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 950 } })
  const page = await ctx.newPage()
  const errors = /** @type {string[]} */ ([])
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text().slice(0, 120)))
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 120)))
  await openLogin(ctx, page)
  await page.waitForTimeout(4000)
  await page.getByRole('link', { name: 'Edukasi' }).first().click()
  await page.waitForTimeout(900)
  await page.goBack({ waitUntil: 'load' })
  await page.waitForTimeout(1400)
  const again = await readNotice(page)
  evidence.push({
    langkah: 'pindah halaman saat timer berjalan, lalu kembali ke /masuk',
    galat: errors.filter((e) => !/Failed to load resource|net::ERR/.test(e)),
    notifikasiMunculLagi: again.present,
    tinggi: again.h,
  })
  await ctx.close()
}

// ── 5. tidak ada notifikasi ganda karena rerender ──────────────────────────────
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 950 } })
  const page = await ctx.newPage()
  await openLogin(ctx, page)
  await page.getByLabel('Email').fill('rerrender@example.test')
  await page.getByLabel('Kata sandi').fill('rahasia123')
  await page.waitForTimeout(400)
  const count = await page.locator('[role="status"]').evaluateAll((nodes) =>
    nodes
      .filter((n) => (n.textContent || '').trim().startsWith('Layanan akun'))
      .map((n) => Math.round(n.getBoundingClientRect().height)),
  )
  evidence.push({ langkah: 'tidak ada duplikasi setelah rerender karena mengetik', instances: count })
  await ctx.close()
}

// ── 6. tidak ada alert()/notifikasi browser; dua tema; dua viewport ────────────
for (const theme of ['light', 'dark']) {
  for (const viewport of [
    { name: 'desktop', width: 1440, height: 950 },
    { name: 'mobile', width: 390, height: 844 },
  ]) {
    const ctx = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } })
    const page = await ctx.newPage()
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
    let nativeDialog = null
    page.on('dialog', async (d) => {
      nativeDialog = d.message().slice(0, 60)
      await d.dismiss()
    })
    await page.goto(`${BASE}/masuk`, { waitUntil: 'load' })
    await page.waitForTimeout(1200)
    const n = await readNotice(page)
    evidence.push({
      langkah: `tampilan ${viewport.name}/${theme}`,
      panel: `${n.panelW}x${n.panelH}`,
      cardTop: n.cardTop,
      closeSize: n.closeSize,
      timerTerlihat: n.timerText,
      dialogBrowser: nativeDialog,
      role: 'status',
    })
    await page.screenshot({ path: `${OUT}/vgl37-notification.${viewport.name}.${theme}.png` })
    await ctx.close()
  }
}

await browser.close()
writeFileSync(resolve(OUT, 'vgl37-notification-behavior.json'), JSON.stringify(evidence, null, 2))
console.log(JSON.stringify(evidence, null, 2))

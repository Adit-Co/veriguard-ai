// @ts-check
/// <reference types="node" />
// VGL-37B — perilaku toast layanan akun: mengambang di bawah navbar, di luar kartu,
// tidak mendorong layout, tutup dengan X, auto-dismiss 30s nyata, tanpa hitungan terlihat,
// timer bersih, tidak duplikasi karena rerender, dan tidak menghalangi interaksi.
// Pemakaian: node scripts/vgl37b-notification-probe.mjs
import { chromium } from 'playwright'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const BASE = process.env.VGL37B_BASE ?? 'http://localhost:5178'
const PREF_KEY = 'veriguard.preferences.v1'
const OUT = resolve(process.cwd(), '../.veriguard/live')
mkdirSync(OUT, { recursive: true })

/** @type {any[]} */
const evidence = []

const readToast = (/** @type {any} */ page) =>
  page.evaluate(() => {
    const el = Array.from(document.querySelectorAll('[role="status"]')).find((n) =>
      (n.textContent || '').includes('Layanan akun'),
    );
    if (!el) return { present: false, scrollY: Math.round(window.scrollY) };
    const layer = el.closest('.fixed');
    const ls = layer ? getComputedStyle(layer) : null;
    const es = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    const header = document.querySelector('header');
    const hr = header ? header.getBoundingClientRect() : null;
    const card = document.querySelector('main div[class*="shadow-card"]');
    const cr = card ? card.getBoundingClientRect() : null;
    const fieldSel = ['#login-email', '#login-password', 'main button[type="submit"]'];
    const rects = (/** @type {any} */ a, /** @type {any} */ b) =>
      a && b ? a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom : null;
    const fields = /** @type {Record<string, any>} */ {};
    for (const sel of fieldSel) {
      const f = document.querySelector(sel);
      fields[sel] = f ? f.getBoundingClientRect() : null;
    }
    return {
      present: true,
      scrollY: Math.round(window.scrollY),
      panel: `${Math.round(r.width)}x${Math.round(r.height)}`,
      box: { l: Math.round(r.left), t: Math.round(r.top), r: Math.round(r.right), b: Math.round(r.bottom) },
      centerOffset: Math.round((r.left + r.right) / 2 - window.innerWidth / 2),
      widthRatio: Math.round((r.width / window.innerWidth) * 1000) / 1000,
      margins: [Math.round(r.left), Math.round(window.innerWidth - r.right)],
      docTop: Math.round(r.top + window.scrollY),
      position: ls ? ls.position : null,
      zIndex: ls ? ls.zIndex : null,
      top: ls ? ls.top : null,
      pointerEventsLayer: ls ? ls.pointerEvents : null,
      pointerEventsPanel: es.pointerEvents,
      opacity: Number(es.opacity),
      transform: es.transform.slice(0, 42),
      role: el.getAttribute('role'),
      ariaLive: el.getAttribute('aria-live'),
      closeLabel: (() => {
        const b = Array.from(el.querySelectorAll('button')).find((n) =>
          (n.getAttribute('aria-label') || '').includes('Tutup'),
        );
        return b ? b.getAttribute('aria-label') : null;
      })(),
      text: (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 220),
      timerText: /\b\d+\s*(s|detik|sec)\b|\d+:\d\d/i.test(el.textContent || ''),
      headerBottom: hr ? Math.round(hr.bottom) : null,
      cardTop: cr ? Math.round(cr.top) : null,
      cardDocTop: cr ? Math.round(cr.top + window.scrollY) : null,
      insideCard: Boolean(card && card.contains(el)),
      belowNavbar: Boolean(hr && r.top >= hr.bottom),
      coversNavbar: rects(r, hr),
      coversCard: rects(r, cr),
      coversEmail: rects(r, fields['#login-email']),
      coversPassword: rects(r, fields['#login-password']),
      coversSubmit: rects(r, fields['main button[type="submit"]']),
    };
  });

const browser = await chromium.launch()

/** @param {any} context @param {any} page @param {string} theme */
async function openLogin(context, page, theme = 'light') {
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
    `localStorage.setItem('${PREF_KEY}', JSON.stringify({ defaultScanMode: 'link', reduceMotion: false, theme: '${theme}' }))`,
  );
  await page.goto(`${BASE}/masuk`, { waitUntil: 'load' });
  await page.waitForTimeout(1200);
}

// ── 1. muncul otomatis, mengambang di bawah navbar, di luar kartu, tanpa mendorong layout ──
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 950 } })
  const page = await ctx.newPage()
  await openLogin(ctx, page)
  const shown = await readToast(page)
  // kartu tanpa toast diukur dengan melepas lapisan fixed dari alur sudah pasti;
  // pembanding: halaman /daftar memakai kolom yang sama tanpa toast
  await page.goto(`${BASE}/daftar`, { waitUntil: 'load' })
  await page.waitForTimeout(900)
  const daftar = await page.evaluate(() => {
    const card = document.querySelector('main div[class*="shadow-card"]');
    const cr = card ? card.getBoundingClientRect() : null;
    return { cardTop: cr ? Math.round(cr.top + window.scrollY) : null };
  })
  await page.goto(`${BASE}/masuk`, { waitUntil: 'load' })
  await page.waitForTimeout(1200)
  const again = await readToast(page)
  evidence.push({
    langkah: 'tampil otomatis saat /masuk dibuka + posisi + tidak mendorong layout',
    saatToast: shown,
    saatToastKedua: again,
    pembandingDaftar: daftar,
    menutupiForm: Boolean(shown.coversEmail || shown.coversPassword || shown.coversSubmit),
  })
  await page.screenshot({ path: `${OUT}/vgl37b-toast.masuk.light.png` })
  await ctx.close()
}

// ── 2. tombol X menutup toast segera ───────────────────────────────────────────
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 950 } })
  const page = await ctx.newPage()
  await openLogin(ctx, page)
  const before = await readToast(page)
  await page.getByRole('button', { name: 'Tutup notifikasi layanan akun' }).click()
  await page.waitForTimeout(90)
  const mid = await readToast(page)
  await page.waitForTimeout(600)
  const after = await readToast(page)
  evidence.push({
    langkah: 'tombol X menutup toast',
    sebelum: { panel: before.panel, opacity: before.opacity, posisi: before.position },
    segeraSesudahKlik: { present: mid.present, opacity: mid.opacity, transform: mid.transform },
    sesudahAnimasi: after,
    kartuIkutBergerak: before.cardTop !== null && after.cardTop !== null ? after.cardTop - before.cardTop : null,
  })
  await ctx.close()
}

// ── 3. verifikasi nyata: auto-dismiss setelah 30 detik waktu berjalan ──────────
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 950 } })
  const page = await ctx.newPage()
  await openLogin(ctx, page)
  const started = Date.now()
  const t0 = await readToast(page)
  await page.waitForTimeout(20_000)
  const at20 = await readToast(page)
  await page.waitForTimeout(11_000)
  const at31 = await readToast(page)
  await page.waitForTimeout(700)
  const at32 = await readToast(page)
  evidence.push({
    langkah: 'auto-dismiss 30 detik (waktu nyata, bukan periksa setTimeout)',
    detikMulai: { present: t0.present, panel: t0.panel, opacity: t0.opacity },
    detik20: { present: at20.present, opacity: at20.opacity },
    detik31: { present: at31.present, opacity: at31.opacity },
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
  const again = await readToast(page)
  evidence.push({
    langkah: 'pindah halaman saat timer berjalan, lalu kembali ke /masuk',
    galat: errors.filter((e) => !/Failed to load resource|net::ERR/.test(e)),
    toastMunculLagi: again.present,
    panel: again.panel,
  })
  await ctx.close()
}

// ── 5. tidak ada toast ganda karena rerender ───────────────────────────────────
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 950 } })
  const page = await ctx.newPage()
  await openLogin(ctx, page)
  await page.getByLabel('Email').fill('rerender@example.test')
  await page.getByLabel('Kata sandi').fill('rahasia123')
  await page.waitForTimeout(400)
  const count = await page.locator('[role="status"]').evaluateAll((nodes) =>
    nodes
      .filter((n) => (n.textContent || '').includes('Layanan akun'))
      .map((n) => Math.round(n.getBoundingClientRect().height)),
  )
  evidence.push({ langkah: 'tidak ada duplikasi setelah rerender karena mengetik', instances: count })
  await ctx.close()
}

// ── 6. interaksi form tetap jalan di bawah toast; dua tema; empat viewport ─────
for (const theme of ['light', 'dark']) {
  for (const viewport of [
    { name: 'desktop', width: 1440, height: 950 },
    { name: 'laptop', width: 1024, height: 900 },
    { name: 'tablet', width: 820, height: 1000 },
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
    const errors = /** @type {string[]} */ ([])
    page.on('console', (m) => m.type() === 'error' && errors.push(m.text().slice(0, 120)))
    page.on('pageerror', (e) => errors.push(String(e).slice(0, 120)))
    const blocked = /** @type {string[]} */ ([])
    page.on('requestfailed', (r) => {
      if (!r.url().startsWith(BASE)) blocked.push(r.url().slice(0, 60))
    })
    await page.goto(`${BASE}/masuk`, { waitUntil: 'load' })
    await page.waitForTimeout(1200)
    const toast = await readToast(page)
    // isi form + klik tombol asli: gagal kalau toast menghalangi
    let interaksi = { email: null, kataSandi: null, klik: 'ok', pesan: null }
    try {
      await page.locator('#login-email').fill('uji@example.test', { timeout: 4000 })
      await page.locator('#login-password').fill('rahasia123', { timeout: 4000 })
      await page.getByRole('button', { name: /^Masuk/ }).first().click({ timeout: 4000 })
      await page.waitForTimeout(1200)
      const alert = await page.locator('[role="alert"]').first().textContent()
      interaksi.email = await page.locator('#login-email').inputValue()
      interaksi.kataSandi = (await page.locator('#login-password').inputValue()).length
      interaksi.pesan = alert ? alert.replace(/\s+/g, ' ').trim().slice(0, 90) : null
    } catch (err) {
      interaksi.klik = String(err).slice(0, 120)
    }
    const setelahPesan = await readToast(page)
    evidence.push({
      langkah: `tampilan ${viewport.name}/${theme}`,
      viewport: `${viewport.width}x${viewport.height}`,
      toast: toast.panel,
      toastBox: toast.box,
      posisi: toast.position,
      zIndex: toast.zIndex,
      topCss: toast.top,
      headerBottom: toast.headerBottom,
      diBawahNavbar: toast.belowNavbar,
      menutupiNavbar: toast.coversNavbar,
      diLuarKartu: toast.insideCard === false,
      menutupiKartu: toast.coversCard,
      menutupiEmail: toast.coversEmail,
      menutupiKataSandi: toast.coversPassword,
      menutupiTombol: toast.coversSubmit,
      cardDocTop: toast.cardDocTop,
      timerTerlihat: toast.timerText,
      labelTutup: toast.closeLabel,
      dialogBrowser: nativeDialog,
      interaksi,
      toastSaatPesanError: setelahPesan.present,
      galat: errors.filter((e) => !/Failed to load resource|net::ERR/.test(e)),
      eksternal: [...new Set(blocked)].length,
      teks: toast.text,
    })
    await page.screenshot({ path: `${OUT}/vgl37b-toast.${viewport.name}.${theme}.png` })
    await ctx.close()
  }
}

await browser.close()
writeFileSync(resolve(OUT, 'vgl37b-toast-behavior.json'), JSON.stringify(evidence, null, 2))
console.log(JSON.stringify(evidence, null, 2))

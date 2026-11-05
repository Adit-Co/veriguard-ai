// @ts-check
/// <reference types="node" />
// VGL-37C — bukti nyata durasi toast: seluruh siklus (terlihat -> animasi keluar ->
// unmount) harus tuntas dalam batas 10 detik sejak notifikasi ditampilkan.
// Jam dipasang lewat addInitScript sehingga titik nol = saat node toast benar-benar
// ditambahkan ke DOM, bukan saat script probe sempat melihatnya.
// Pemakaian: node scripts/vgl37c-toast-timing-probe.mjs
import { chromium } from 'playwright'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const BASE = process.env.VGL37C_BASE ?? 'http://localhost:5178'
const PREF_KEY = 'veriguard.preferences.v1'
const OUT = resolve(process.cwd(), '../.veriguard/live')
mkdirSync(OUT, { recursive: true })

/** Dipasang sebelum halaman dimuat; mencatat mount/exitStart/gone relatif ke mount. */
const INSTRUMENT = `(() => {
  const state = { mount: null, reached: false, exitStart: null, gone: null, frames: [], opacityWhenGone: null, remounts: 0 };
  window.__vgl37c = state;
  const pick = () =>
    Array.from(document.querySelectorAll('[role="status"]')).find((el) =>
      String(el.className).includes('pointer-events-auto'),
    );
  const sample = () => {
    const el = pick();
    const now = performance.now();
    if (el && state.mount === null) state.mount = now;
    const o = el ? Number(getComputedStyle(el).opacity) : 1;
    // exitStart hanya boleh dicatat SETELAH toast benar-benar terlihat penuh;
    // tanpa penjaga ini, fade masuk (opacity 0 -> 1) salah dikira animasi keluar.
    if (el && state.mount !== null && !state.reached && o >= 0.999) state.reached = true;
    if (el && state.reached && state.exitStart === null && o < 0.999) state.exitStart = now;
    if (!el && state.mount !== null && state.gone === null) state.gone = now;
    if (el && state.mount !== null && state.gone !== null) state.remounts += 1;
    if (el && state.mount !== null) {
      const o = Number(getComputedStyle(el).opacity);
      const last = state.frames[state.frames.length - 1];
      if (!last || now - last.at >= 40) {
        state.frames.push({ at: Math.round(now - state.mount), opacity: Math.round(o * 1000) / 1000 });
      }
    }
    requestAnimationFrame(sample);
  };
  requestAnimationFrame(sample);
})()`

const viewports = [
  { name: 'desktop', width: 1440, height: 950 },
  { name: 'mobile', width: 390, height: 844 },
]
const themes = ['light', 'dark']

/** @type {any[]} */
const results = []
const browser = await chromium.launch()

for (const theme of themes) {
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
    await ctx.addInitScript(INSTRUMENT)
    const page = await ctx.newPage()
    const errors = []
    page.on('console', (m) => m.type() === 'error' && errors.push(m.text().slice(0, 140)))
    page.on('pageerror', (e) => errors.push(String(e).slice(0, 140)))
    const dialogs = []
    page.on('dialog', async (d) => {
      dialogs.push(d.message())
      await d.dismiss()
    })

    await page.goto(`${BASE}/masuk`, { waitUntil: 'load' })

    // 1) tunggu sampai jam terpasang & toast mount
    await page.waitForFunction(() => window.__vgl37c && window.__vgl37c.mount !== null, null, {
      timeout: 20000,
    })
    const terlihatAwal = await page.evaluate(() => ({
      present: Boolean(
        Array.from(document.querySelectorAll('[role="status"]')).find((el) =>
          String(el.className).includes('pointer-events-auto'),
        ),
      ),
      opacity: (() => {
        const el = Array.from(document.querySelectorAll('[role="status"]')).find((s) =>
          String(s.className).includes('pointer-events-auto'),
        );
        return el ? Number(getComputedStyle(el).opacity) : null;
      })(),
    }))

    // 2) cek sebelum batas 10 detik (9,4 detik sejak mount)
    await page.waitForFunction(
      (ms) => window.__vgl37c.mount !== null && performance.now() - window.__vgl37c.mount >= ms,
      9_400,
      { timeout: 25000 },
    )
    const sebelumBatas = await page.evaluate(() => {
      const el = Array.from(document.querySelectorAll('[role="status"]')).find((s) =>
        String(s.className).includes('pointer-events-auto'),
      );
      return {
        elapsedMs: Math.round(performance.now() - window.__vgl37c.mount),
        present: Boolean(el),
        opacity: el ? Number(getComputedStyle(el).opacity) : null,
      };
    })

    // 3) tunggu benar-benar hilang + 1,5 detik tambahan untuk memastikan tidak muncul lagi
    await page.waitForFunction(() => window.__vgl37c.gone !== null, null, { timeout: 25000 })
    const saatHilang = await page.evaluate(() => ({
      mount: Math.round(window.__vgl37c.mount),
      exitStart: window.__vgl37c.exitStart === null ? null : Math.round(window.__vgl37c.exitStart),
      gone: Math.round(window.__vgl37c.gone),
      elapsedExitStartMs:
        window.__vgl37c.exitStart === null
          ? null
          : Math.round(window.__vgl37c.exitStart - window.__vgl37c.mount),
      elapsedGoneMs: Math.round(window.__vgl37c.gone - window.__vgl37c.mount),
      frames: window.__vgl37c.frames,
    }))
    await page.waitForTimeout(1500)
    const sesudahJeda = await page.evaluate(() => ({
      masihHilang: window.__vgl37c.remounts === 0,
      remounts: window.__vgl37c.remounts,
      instanceSekarang: Array.from(document.querySelectorAll('[role="status"]')).filter((el) =>
        String(el.className).includes('pointer-events-auto'),
      ).length,
      elapsedSekarang: Math.round(performance.now() - window.__vgl37c.mount),
    }))

    // 4) buka lagi halaman -> toast boleh muncul lagi, lalu tutup manual dengan X
    await page.goto(`${BASE}/riwayat`, { waitUntil: 'load' })
    await page.waitForTimeout(400)
    await page.goto(`${BASE}/masuk`, { waitUntil: 'load' })
    await page.waitForFunction(
      () =>
        Boolean(
          Array.from(document.querySelectorAll('[role="status"]')).find((el) =>
            String(el.className).includes('pointer-events-auto'),
          ),
        ),
      null,
      { timeout: 20000 },
    )
    const sebelumX = await page.evaluate(() => ({
      present: true,
      opacity: Number(
        getComputedStyle(
          Array.from(document.querySelectorAll('[role="status"]')).find((el) =>
            String(el.className).includes('pointer-events-auto'),
          ),
        ).opacity,
      ),
    }))
    await page.getByRole('button', { name: 'Tutup notifikasi layanan akun' }).waitFor()
    const label = await page.evaluate(
      () =>
        Array.from(document.querySelectorAll('button')).find((b) =>
          (b.getAttribute('aria-label') || '').includes('Tutup notifikasi'),
        )?.getAttribute('aria-label') || null,
    )
    await page.evaluate((lbl) => {
      const btn = Array.from(document.querySelectorAll('button')).find(
        (b) => b.getAttribute('aria-label') === lbl,
      );
      if (btn) btn.click();
    }, label)
    await page.waitForTimeout(120)
    const segeraSesudahX = await page.evaluate(() => {
      const el = Array.from(document.querySelectorAll('[role="status"]')).find((s) =>
        String(s.className).includes('pointer-events-auto'),
      );
      return { present: Boolean(el), opacity: el ? Number(getComputedStyle(el).opacity) : null };
    })
    await page.waitForTimeout(700)
    const sesudahX = await page.evaluate(() => ({
      present: Boolean(
        Array.from(document.querySelectorAll('[role="status"]')).find((el) =>
          String(el.className).includes('pointer-events-auto'),
        ),
      ),
    }))

    results.push({
      langkah: `${viewport.name}/${theme}`,
      viewport: `${viewport.width}x${viewport.height}`,
      terlihatAwal,
      sebelumBatas,
      saatHilang,
      sesudahJeda,
      sebelumX,
      segeraSesudahX,
      sesudahX,
      dialogBrowser: dialogs.length ? dialogs : null,
      galat: errors.filter((e) => !/Failed to load resource|net::ERR/.test(e)).slice(0, 6),
    })
    await ctx.close()
  }
}

await browser.close()
writeFileSync(
  resolve(OUT, 'vgl37c-toast-timing.json'),
  JSON.stringify({ base: BASE, hasil: results }, null, 2),
)

for (const r of results) {
  const h = r.saatHilang
  console.log(
    `${r.langkah.padEnd(15)} mount→exitStart=${h.elapsedExitStartMs}ms  mount→gone=${h.elapsedGoneMs}ms  ` +
      `batas10dtk=${h.elapsedGoneMs <= 10_000 ? 'PATUH' : 'LANGGAR'}  ` +
      `sebelumBatas(${r.sebelumBatas.elapsedMs}ms)=op${r.sebelumBatas.opacity}  ` +
      `X: ${r.sebelumX.present}→op${r.segeraSesudahX.opacity}→hilang=${!r.sesudahX.present}  ` +
      `duplikasi=${r.sesudahJeda.instanceSekarang}  remount=${r.sesudahJeda.remounts}  ` +
      `dialog=${r.dialogBrowser ? 'ADA' : 'tidak'}  galat=${r.galat.length}`,
  )
}

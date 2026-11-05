// @ts-check
/// <reference types="node" />
// VGL-37 — ukur geometri box login/registrasi dan notifikasi layanan akun.
// Semua permintaan non-lokal diblokir sehingga tidak ada traffic ke production.
// Pemakaian: node scripts/vgl37-card-probe.mjs before|after
import { chromium } from 'playwright'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const BASE = process.env.VGL37_BASE ?? 'http://localhost:5178'
const PREF_KEY = 'veriguard.preferences.v1'
const phase = process.argv[2] === 'after' ? 'after' : 'before'
const OUT = resolve(process.cwd(), '../.veriguard/live')
mkdirSync(OUT, { recursive: true })

/** @param {import('playwright').Page} page */
async function readPage(page) {
  return page.evaluate(() => {
    const px = (/** @type {number} */ n) => Math.round(n * 100) / 100;
    const box = (/** @type {Element | null} */ el) => {
      if (!el) return null;
      const r = el.getBoundingClientRect();
      const s = getComputedStyle(el);
      return {
        l: px(r.left),
        t: px(r.top),
        r: px(r.right),
        b: px(r.bottom),
        w: px(r.width),
        h: px(r.height),
        pad: [s.paddingTop, s.paddingRight, s.paddingBottom, s.paddingLeft].map((v) => px(parseFloat(v))),
        radius: px(parseFloat(s.borderTopLeftRadius)),
        border: s.borderTopWidth + ' ' + s.borderTopColor,
        bg: s.backgroundColor,
        shadow: s.boxShadow.slice(0, 60),
        display: s.display,
      };
    };
    const pick = (/** @type {string} */ sel) => document.querySelector(sel);
    const byText = (
      /** @type {string} */ role,
      /** @type {string} */ text,
    ) =>
      Array.from(document.querySelectorAll(role)).find((el) =>
        (el.textContent || '').trim().startsWith(text),
      ) || null;

    const railIcon = pick('main span[class*="bg-accent-soft"]');
    const h1 = pick('main h1');
    const desc = h1 && h1.nextElementSibling;
    const card = pick('main .rounded-card[class*="shadow-card"]') || pick('main div[class*="shadow-card"]');
    const cardTitle = card ? Array.from(card.querySelectorAll('p')).find((p) => /font-semibold/.test(p.className)) || null : null;
    const firstLabel = card ? pick('main label') : null;
    const firstInput = pick('main input');
    const submit = Array.from(document.querySelectorAll('main button[type="submit"]'))[0] || null;
    const infoNote = byText('[role="note"], [role="status"]', 'Layanan akun');
    const form = pick('main form');

    const gap = (
      /** @type {{b:number} | null} */ a,
      /** @type {any} */ b,
    ) => (a && b ? px(b.t - a.b) : null);

    return {
      url: location.pathname,
      scrollW: document.documentElement.scrollWidth,
      innerW: window.innerWidth,
      railIcon: box(railIcon),
      railIconSize: railIcon ? px(railIcon.getBoundingClientRect().width) : null,
      h1: box(h1),
      desc: box(desc),
      card: box(card),
      cardTitle: box(cardTitle),
      cardTitleText: cardTitle ? (cardTitle.textContent || '').trim().slice(0, 40) : null,
      firstLabel: box(firstLabel),
      firstInput: box(firstInput),
      submit: box(submit),
      submitText: submit ? (submit.textContent || '').trim().slice(0, 24) : null,
      infoNote: box(infoNote),
      infoNoteRole: infoNote ? infoNote.getAttribute('role') : null,
      form: box(form),
      gapIconToH1: gap(box(railIcon), box(h1)),
      gapH1ToDesc: gap(box(h1), box(desc)),
      gapDescToCard: gap(box(desc), box(card)),
      gapCardToTitle: gap(box(card), box(cardTitle)),
      gapTitleToLabel: gap(box(cardTitle), box(firstLabel)),
      gapLabelToInput: gap(box(firstLabel), box(firstInput)),
      gapCardToSubmit: gap(box(card), box(submit)),
      demoMode: Boolean(byText('p', 'Sesi demo lokal')),
      readyForm: Boolean(form),
    };
  });
}

const viewports = [
  { name: 'desktop', width: 1440, height: 950 },
  { name: 'laptop', width: 1024, height: 900 },
  { name: 'tablet', width: 820, height: 1000 },
  { name: 'mobile', width: 390, height: 844 },
]
const pages = [
  { name: 'masuk', path: '/masuk' },
  { name: 'daftar', path: '/daftar' },
]

const browser = await chromium.launch()
/** @type {Record<string, any>} */
const report = { phase: 'before', base: BASE, states: {} }
report.phase = phase

for (const theme of ['light', 'dark']) {
  for (const viewport of viewports) {
    const ctx = await browser.newContext({
      viewport: { width: viewport.width, height: viewport.height },
    })
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
    const page = await ctx.newPage();
    const errors = [];
    page.on('console', (m) => m.type() === 'error' && errors.push(m.text().slice(0, 140)));
    page.on('pageerror', (e) => errors.push(String(e).slice(0, 140)));
    const blocked = [];
    page.on('requestfailed', (r) => {
      if (!r.url().startsWith(BASE)) blocked.push(r.url().slice(0, 60));
    });

    for (const target of pages) {
      await page.goto(`${BASE}${target.path}`, { waitUntil: 'load' });
      await page.waitForTimeout(1400);
      const key = `${target.name}.${viewport.name}.${theme}`;
      const data = await readPage(page);
      data.errors = errors.slice(0, 6);
      data.blockedExternal = [...new Set(blocked)].slice(0, 12);
      report.states[key] = data;
      await page.screenshot({ path: `${OUT}/vgl37-${phase}-${key}.full.png`, fullPage: false });
      const cardEl = await page.$('main div[class*="shadow-card"]');
      if (cardEl) {
        await cardEl.screenshot({ path: `${OUT}/vgl37-${phase}-${key}.card.png` });
      }
    }
    await ctx.close();
  }
}

await browser.close();
writeFileSync(
  resolve(OUT, `vgl37-${phase}-card-metrics.json`),
  JSON.stringify(report, null, 2),
);

const external = [...new Set(Object.values(report.states).flatMap((s) => s.blockedExternal))];
const err = Object.entries(report.states).filter(([, s]) => s.errors.length);
console.log(
  `selesai ${phase}: ${Object.keys(report.states).length} kombinasi terekam, galat-konsol=${err.length}, eksternal-diblokir=${external.length}`,
);
if (external.length) console.log('diblokir:', external.join(' | '));
if (err.length) console.log(JSON.stringify(err, null, 2));
for (const [k, s] of Object.entries(report.states)) {
  console.log(
    `${k.padEnd(24)} card ${s.card ? `${s.card.l}..${s.card.r} y${s.card.t}..${s.card.b} pad${s.card.pad.join('/')}` : '—'} | judul=${s.cardTitleText} | form=${s.readyForm} | demo=${s.demoMode} | note=${s.infoNote ? `${s.infoNoteRole} y${s.infoNote.t}..${s.infoNote.b}` : '—'}`,
  );
}

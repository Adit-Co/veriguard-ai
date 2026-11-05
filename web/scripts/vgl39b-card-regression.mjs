// @ts-check
/// <reference types="node" />
// VGL-37C — geometri card login/daftar + posisi notifikasi layanan akun (floating atau mengalir).
// Semua permintaan non-lokal diblokir sehingga tidak ada traffic ke production.
// VGL-39B — rekaman geometri baru dengan nama vgl39b-*; baseline VGL-37C/38/39A tidak disentuh.
import { chromium } from 'playwright'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const BASE = process.env.VGL37C_BASE ?? 'http://localhost:5173'
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
        position: s.position,
        zIndex: s.zIndex,
      };
    };
    const intersects = (
      /** @type {{t:number,b:number,l:number,r:number} | null} */ a,
      /** @type {{t:number,b:number,l:number,r:number} | null} */ b,
    ) => Boolean(a && b && a.l < b.r && b.l < a.r && a.t < b.b && b.t < a.b);

    const pick = (/** @type {string} */ sel) => document.querySelector(sel);
    const byText = (
      /** @type {string} */ sel,
      /** @type {string} */ text,
    ) =>
      Array.from(document.querySelectorAll(sel)).find((el) =>
        (el.textContent || '').includes(text),
      ) || null;

    const header = pick('header');
    const footer = pick('footer');
    const backdrop = pick('main.auth-canvas');
    const backdropInfo = (() => {
      if (!/** @type {any} */ (backdrop)) return null;
      const el = /** @type {HTMLElement} */ (backdrop);
      const s = getComputedStyle(el);
      const pseudo = (/** @type {string} */ which) => {
        const p = getComputedStyle(el, which);
        return {
          hasImage: p.backgroundImage !== 'none',
          imageCount: p.backgroundImage === 'none' ? 0 : p.backgroundImage.split(/,(?![^(]*\))/).length,
          animationName: p.animationName,
          animationDuration: p.animationDuration,
          opacity: p.opacity,
          filter: p.filter,
        };
      };
      return {
        className: String(el.className),
        ariaHidden: el.getAttribute('aria-hidden'),
        pointerEvents: s.pointerEvents,
        position: s.position,
        zIndex: s.zIndex,
        imageCount: s.backgroundImage === 'none' ? 0 : s.backgroundImage.split(/,(?![^(]*\))/).length,
        before: pseudo('::before'),
        after: pseudo('::after'),
      };
    })();
    const railIcon = pick('main span[class*="bg-accent-soft"]');
    const h1 = pick('main h1');
    const desc = h1 && h1.nextElementSibling;
    const card = pick('main .rounded-card[class*="shadow-card"]') || pick('main div[class*="shadow-card"]');
    const cardTitle = card ? Array.from(card.querySelectorAll('p')).find((p) => /font-semibold/.test(p.className)) || null : null;
    const firstLabel = card ? pick('main label') : null;
    const firstInput = pick('main input');
    const submit = Array.from(document.querySelectorAll('main button[type="submit"]'))[0] || null;
    const infoNote = byText('[role="status"], [role="note"]', 'Layanan akun');
    const form = pick('main form');
    const emailInput = pick('#login-email') || pick('main input[type="email"]');
    const passInput = pick('#login-password') || pick('main input[type="password"]');

    const gap = (
      /** @type {{b:number} | null} */ a,
      /** @type {any} */ b,
    ) => (a && b ? px(b.t - a.b) : null);

    const noteBox = box(infoNote);
    const notePanel = box(infoNote ? infoNote.querySelector('section') || infoNote : null);
    const noteParent = (() => {
      let el = /** @type {Element | null} */ infoNote;
      const trail = [];
      while (el && trail.length < 6) {
        trail.push(el.tagName.toLowerCase() + (el.className ? '.' + String(el.className).trim().split(/\s+/).slice(0, 4).join('.') : ''));
        el = el.parentElement;
      }
      return trail;
    })();
    const closeBtn = infoNote
      ? Array.from(infoNote.querySelectorAll('button')).find((b) => (b.getAttribute('aria-label') || '').includes('Tutup')) || null
      : null;

    return {
      url: location.pathname,
      scrollW: document.documentElement.scrollWidth,
      innerW: window.innerWidth,
      docH: document.documentElement.scrollHeight,
      header: box(header),
      footer: box(footer),
      footerPresent: Boolean(footer),
      footerText: footer ? (footer.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 60) : null,
      backdrop: box(backdrop),
      backdropInfo,
      railIcon: box(railIcon),
      railIconSize: railIcon ? px(railIcon.getBoundingClientRect().width) : null,
      h1: box(h1),
      desc: box(desc),
      card: box(card),
      cardTitle: box(cardTitle),
      cardTitleText: cardTitle ? (cardTitle.textContent || '').trim().slice(0, 40) : null,
      firstLabel: box(firstLabel),
      firstInput: box(firstInput),
      emailInput: box(emailInput),
      passInput: box(passInput),
      submit: box(submit),
      submitText: submit ? (submit.textContent || '').trim().slice(0, 24) : null,
      infoNote: noteBox,
      infoNotePanel: notePanel,
      noteCenterOffset: notePanel ? px((notePanel.l + notePanel.r) / 2 - window.innerWidth / 2) : null,
      noteWidthRatio: notePanel ? px(notePanel.w / window.innerWidth) : null,
      noteMargins: notePanel ? [px(notePanel.l), px(window.innerWidth - notePanel.r)] : null,
      infoNoteRole: infoNote ? infoNote.getAttribute('role') : null,
      infoNoteAriaLive: infoNote ? infoNote.getAttribute('aria-live') : null,
      infoNoteAncestorChain: noteParent,
      infoNoteInsideCard: Boolean(infoNote && card && card.contains(infoNote)),
      infoNoteBelowHeader: Boolean(noteBox && header && noteBox.t >= px(header.getBoundingClientRect().bottom) - 1),
      infoNoteOverlapsHeader: intersects(noteBox, box(header)),
      noteOverlapsCard: intersects(notePanel, box(card)),
      noteOverlapsEmail: intersects(notePanel, box(emailInput)),
      noteOverlapsPassword: intersects(notePanel, box(passInput)),
      noteOverlapsSubmit: intersects(notePanel, box(submit)),
      infoNoteText: infoNote ? (infoNote.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 200) : null,
      closeLabel: closeBtn ? closeBtn.getAttribute('aria-label') : null,
      closeSize: closeBtn
        ? `${px(closeBtn.getBoundingClientRect().width)}x${px(closeBtn.getBoundingClientRect().height)}`
        : null,
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
      // tunggu kartu benar-benar terpasang; tanpa ini, pengukuran bisa tertangkap
      // saat aplikasi belum mount dan rekaman menjadi kosong.
      await page.waitForSelector('main div[class*="shadow-card"]', { timeout: 20000 });
      await page.waitForTimeout(900);
      const key = `${target.name}.${viewport.name}.${theme}`;
      const data = await readPage(page);
      data.errors = errors.filter((e) => !/Failed to load resource|net::ERR/.test(e)).slice(0, 6);
      data.blockedExternal = [...new Set(blocked)].slice(0, 12);
      report.states[key] = data;
      await page.screenshot({ path: `${OUT}/vgl39b-reg-${key}.full.png`, fullPage: false });
      const cardEl = await page.$('main div[class*="shadow-card"]');
      if (cardEl) {
        await cardEl.screenshot({ path: `${OUT}/vgl39b-reg-${key}.card.png` });
      }
      // catat posisi card setelah notifikasi ditutup → bukti pergeseran tata letak
      if (target.name === 'masuk' && data.closeLabel) {
        await page.getByRole('button', { name: data.closeLabel }).click();
        await page.waitForTimeout(700);
        report.states[`${key}.setelah-tutup`] = await readPage(page);
      }
    }
    await ctx.close();
  }
}

await browser.close();
writeFileSync(
  resolve(OUT, `vgl39b-regression-card-metrics.json`),
  JSON.stringify(report, null, 2),
);

const external = [...new Set(Object.values(report.states).flatMap((s) => s.blockedExternal || []))];
const err = Object.entries(report.states).filter(([, s]) => s.errors?.length);
console.log(
  `selesai ${phase}: ${Object.keys(report.states).length} rekaman terekam, galat-konsol=${err.length}, eksternal-diblokir=${external.length}`,
);
if (external.length) console.log('diblokir:', external.join(' | '));
if (err.length) console.log(JSON.stringify(err, null, 2));
for (const [k, s] of Object.entries(report.states)) {
  console.log(
    `${k.padEnd(30)} card ${s.card ? `${s.card.w}x${s.card.h} y${s.card.t} pad${s.card.pad.join('/')}` : '—'} | footer=${s.footerPresent ? `ADA y${s.footer?.t}` : 'TIDAK'} | backdrop=${s.backdrop ? `${s.backdrop.w}x${s.backdrop.h} z${s.backdrop.zIndex} lapisan=${s.backdropInfo?.imageCount}` : '—'} | toast ${s.infoNote ? `${s.infoNotePanel?.w}x${s.infoNotePanel?.h} center=${s.noteCenterOffset}` : '—'}`,
  );
}

// @ts-check
/// <reference types="node" />
// VGL-36 — pengukur komposisi navbar. Merekam posisi tiap kelompok (logo, menu, sakelar
// tema, aksi akun), jarak antarmenu, rata vertikal, urutan DOM sakelar-terhadap-aksi,
// overflow, dan keberadaan tombol yang seharusnya hilang — untuk kondisi guest maupun
// sesi demo, empat lebar viewport, dua tema.
// Pemakaian: node scripts/vgl36-navbar-probe.mjs before|after
import { chromium } from 'playwright'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { seedScript } from './vgl35-seed.mjs'

const phase = process.argv[2] === 'after' ? 'after' : 'before'
const BASE = process.env.VGL36_BASE ?? 'http://localhost:5178'
const OUT = resolve(process.cwd(), '../.veriguard/live')
mkdirSync(OUT, { recursive: true })

/** Rute yang memakai navbar global; hasil akhir dicatat supaya redirect ikut terlihat. */
const ROUTES = [
  { path: '/', name: 'beranda' },
  { path: '/periksa', name: 'periksa' },
  { path: '/komunitas', name: 'komunitas' },
  { path: '/riwayat', name: 'riwayat' },
  { path: '/dashboard', name: 'dashboard' },
  { path: '/edukasi', name: 'edukasi' },
  { path: '/pengaturan', name: 'pengaturan' },
  { path: '/masuk', name: 'masuk' },
  { path: '/daftar', name: 'daftar' },
  { path: '/hasil/vgl35-sample', name: 'hasil' },
]

const VIEWPORTS = [
  { name: 'desktop', width: 1440, height: 950 },
  { name: 'laptop', width: 1024, height: 900 },
  { name: 'tablet', width: 820, height: 1000 },
  { name: 'mobile', width: 390, height: 844 },
]

/** Halaman yang difoto potongannya (header saja) agar laporan ringan dan mudah dibaca. */
const SHOT_ROUTES = new Set(['beranda', 'periksa', 'dashboard'])

function readNavbar() {
  const header = document.querySelector('header');
  if (!header) return { missing: true };

  const px = (n) => Math.round(n);
  const visible = (el) => !!el && el.checkVisibility({ checkOpacity: false });
  const box = (el) => {
    if (!visible(el)) return null;
    const r = el.getBoundingClientRect();
    return {
      l: px(r.left),
      r: px(r.right),
      t: px(r.top),
      b: px(r.bottom),
      w: px(r.width),
      h: px(r.height),
      cy: px(r.top + r.height / 2),
    };
  };

  const nav = header.querySelector('nav[aria-label="Navigasi utama"]');
  const items = nav ? Array.from(nav.querySelectorAll('a')) : [];
  const logo = header.querySelector('a[aria-label^="VERIGUARD AI"]');
  const theme = header.querySelector('[role="radiogroup"]');
  const account = header.querySelector('[aria-haspopup="menu"]');
  const loginLink = header.querySelector('a[href="/masuk"]');
  const authAction = account || loginLink;
  const burger = Array.from(header.querySelectorAll('button')).find((b) =>
    /buka menu|tutup menu/i.test(b.getAttribute('aria-label') || ''),
  );

  const navBoxes = items.map((a) => {
    const r = a.getBoundingClientRect();
    const t = document.createRange();
    t.selectNodeContents(a);
    const tr = t.getBoundingClientRect();
    return {
      text: (a.textContent || '').trim(),
      l: px(r.left),
      r: px(r.right),
      labelL: px(tr.left),
      labelR: px(tr.right),
      w: px(r.width),
    };
  });

  const gaps = [];
  for (let i = 1; i < navBoxes.length; i += 1) {
    gaps.push({
      between: navBoxes[i - 1].text + ' \u2192 ' + navBoxes[i].text,
      edgeGap: navBoxes[i].l - navBoxes[i - 1].r,
      labelGap: navBoxes[i].labelL - navBoxes[i - 1].labelR,
    });
  }

  const themeBox = box(theme);
  const authBox = box(authAction);
  const accountIsAuth = Boolean(account);

  const order = theme && authAction
    ? Boolean(
        theme.compareDocumentPosition(authAction) & Node.DOCUMENT_POSITION_FOLLOWING,
      )
    : null;

  const overflow = [];
  for (const el of header.querySelectorAll('*')) {
    if (!visible(el)) continue;
    const r = el.getBoundingClientRect();
    if (r.width === 0) continue;
    if (r.right > window.innerWidth + 1 || r.left < -1) {
      overflow.push({
        tag: el.tagName.toLowerCase(),
        cls: (el.className || '').toString().slice(0, 70),
        l: px(r.left),
        r: px(r.right),
      });
    }
  }

  const centers = [box(logo), box(nav), themeBox, authBox, box(burger)].filter(Boolean);
  const misalign = centers.length
    ? Math.max(...centers.map((c) => c.cy)) - Math.min(...centers.map((c) => c.cy))
    : null;

  const masukStyle = loginLink
    ? (() => {
        const s = getComputedStyle(loginLink);
        return { bg: s.backgroundColor, color: s.color, border: s.borderTopColor, radius: s.borderTopLeftRadius };
      })()
    : null;

  return {
    headerH: px(header.getBoundingClientRect().height),
    scrollW: document.documentElement.scrollWidth,
    innerW: window.innerWidth,
    logo: box(logo),
    nav: box(nav),
    navItems: navBoxes,
    navGaps: gaps,
    theme: themeBox,
    auth: authBox,
    authKind: accountIsAuth ? 'akun' : loginLink ? 'masuk' : null,
    burger: box(burger),
    themeBeforeAuth: order,
    masukStyle,
    hasReportUrl: /Laporkan URL/.test(header.textContent || ''),
    hasDaftar: Boolean(header.querySelector('a[href="/daftar"]')),
    verticalMisalign: misalign,
    overflow,
    mobilePanel: (() => {
      const panel = document.querySelector('#menu-seluler');
      if (!visible(panel)) return null;
      return {
        links: Array.from(panel.querySelectorAll('a')).map((a) => (a.textContent || '').trim()),
        hasReportUrl: /Laporkan URL/.test(panel.textContent || ''),
        hasThemeSwitch: Boolean(panel.querySelector('[role="radiogroup"]')),
      };
    })(),
  };
}

/** @param {import('playwright').Page} page */
async function openMobileMenu(page) {
  const button = page.getByRole('button', { name: 'Buka menu' })
  if (await button.isVisible().catch(() => false)) await button.click()
}

const browser = await chromium.launch()
/** @type {Record<string, unknown>} */
const report = { phase, base: BASE, states: {}, persistence: {} }
let loggedOutMismatch = 0

for (const state of ['guest', 'session']) {
  for (const viewport of VIEWPORTS) {
    for (const theme of ['light', 'dark']) {
      const ctx = await browser.newContext({
        viewport: { width: viewport.width, height: viewport.height },
      })
      await ctx.addInitScript(seedScript(theme))
      const page = await ctx.newPage()
      /** @type {string[]} */
      const errors = []
      page.on('console', (m) => m.type() === 'error' && errors.push(m.text().slice(0, 140)))
      page.on('pageerror', (e) => errors.push(String(e).slice(0, 140)))

      try {
        await page.goto(`${BASE}/masuk`, { waitUntil: 'load', timeout: 30_000 })
        if (state === 'session') {
          await page.getByLabel('Nama tampilan (opsional)').fill('Penampil VGL36')
          await page.getByRole('button', { name: 'Mulai sesi demo lokal' }).click()
          await page.waitForTimeout(500)
        }
      } catch (error) {
        console.log(`SEED-FAIL ${state}/${viewport.name}/${theme}: ${String(error).slice(0, 120)}`)
      }

      /** @type {Record<string, unknown>} */
      const perRoute = {}
      for (const route of ROUTES) {
        try {
          await page.goto(`${BASE}${route.path}`, { waitUntil: 'load', timeout: 30_000 })
          await page.waitForSelector('header', { timeout: 15_000 })
          await page.waitForTimeout(450)
          const m = await page.evaluate(readNavbar)
          const key = `${state}.${viewport.name}.${route.name}.${theme}`
          perRoute[route.name] = { finalUrl: page.url(), ...m }

          if (m.scrollW > m.innerW) console.log(`OVERFLOW ${key}: ${m.scrollW} > ${m.innerW}`)
          if (m.overflow?.length) console.log(`NAV-OVERFLOW ${key}: ${JSON.stringify(m.overflow)}`)
          if (m.hasReportUrl) console.log(`REPORT-URL-STILL-IN-NAV ${key}`)
          if (m.themeBeforeAuth === false) console.log(`ORDER-WRONG ${key}`)

          if (SHOT_ROUTES.has(route.name)) {
            await page
              .locator('header')
              .screenshot({ path: `${OUT}/vgl36-${phase}-nav-${key}.png` })
          }
        } catch (error) {
          console.log(`SKIP ${state}/${viewport.name}/${route.name}/${theme}: ${String(error).slice(0, 110)}`)
        }
      }

      // Panel seluler: sakelar tema harus tetap tersedia dan urutan aksi terjaga.
      if (viewport.name === 'mobile') {
        try {
          await page.goto(`${BASE}/`, { waitUntil: 'load' })
          await openMobileMenu(page)
          await page.waitForTimeout(250)
          const panel = await page.evaluate(readNavbar)
          perRoute['panel'] = panel
          await page.screenshot({
            path: `${OUT}/vgl36-${phase}-nav-${state}.mobile.panel.${theme}.png`,
            fullPage: false,
          })
        } catch (error) {
          console.log(`PANEL-FAIL ${state}/${theme}: ${String(error).slice(0, 110)}`)
        }
      }

      const first = Object.values(perRoute).find((r) => r && /** @type {any} */ (r).logo)
      for (const [name, r] of Object.entries(perRoute)) {
        if (name === 'panel' || !r || !/** @type {any} */ (r).nav) continue
        if (JSON.stringify(/** @type {any} */ (r).nav) !== JSON.stringify(/** @type {any} */ (first)?.nav)) {
          loggedOutMismatch += 1
          console.log(`NAV-DIFFERS ${state}/${viewport.name}/${name}/${theme}`)
        }
      }

      const sample = perRoute['beranda'] ?? {}
      report.states[`${state}.${viewport.name}.${theme}`] = {
        ...sample,
        routes: perRoute,
        errors,
      }
      await ctx.close()
    }
  }
}

// --- Persistensi tema: guest ganti DARK → pindah halaman → reload → login → logout ---
for (const viewport of VIEWPORTS) {
  const ctx = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
  })
  const page = await ctx.newPage()
  const trace = []
  /** @param {string} label */
  const snap = async (label) => {
    const stored = await page.evaluate(() => {
      let value = null
      try {
        value = JSON.parse(localStorage.getItem('veriguard.preferences.v1') ?? 'null')?.theme ?? null
      } catch {
        value = 'unreadable'
      }
      return {
        attr: document.documentElement.dataset.theme ?? null,
        stored: value,
        switchVisible: (() => {
          const el = document.querySelector('header [role="radiogroup"]')
          return el ? el.checkVisibility() : false
        })(),
      }
    })
    trace.push({ step: label, ...stored })
  }

  /** Navigasi internal lewat menu — memakai panel seluler bila menu desktop tersembunyi. */
  const gotoInternal = async (/** @type {string} */ name) => {
    const desktopNav = page.getByRole('navigation', { name: 'Navigasi utama' })
    if (await desktopNav.isVisible().catch(() => false)) {
      await desktopNav.getByRole('link', { name }).click()
    } else {
      await page.getByRole('button', { name: 'Buka menu' }).click()
      await page.getByRole('navigation', { name: 'Navigasi seluler' }).getByRole('link', { name }).click()
    }
    await page.waitForTimeout(400)
  }

  await page.goto(`${BASE}/`, { waitUntil: 'load' })
  await snap('awal guest')

  await page.getByRole('radio', { name: 'DARK' }).click()
  await snap('guest pilih DARK')
  await gotoInternal('Edukasi')
  await snap('guest DARK pindah halaman')
  await page.reload({ waitUntil: 'load' })
  await page.waitForTimeout(350)
  await snap('guest DARK reload (anti-flash)')

  await page.getByRole('radio', { name: 'LIGHT' }).click()
  await snap('guest pilih LIGHT')
  await gotoInternal('Periksa')
  await snap('guest LIGHT pindah halaman')

  await page.goto(`${BASE}/masuk`, { waitUntil: 'load' })
  await page.getByLabel('Nama tampilan (opsional)').fill('Penampil VGL36')
  await page.getByRole('button', { name: 'Mulai sesi demo lokal' }).click()
  await page.waitForTimeout(500)
  await snap('sesudah login (LIGHT harus tetap)')

  await page.getByRole('radio', { name: 'DARK' }).click()
  await snap('sesi pilih DARK')
  await gotoInternal('Dashboard')
  await snap('sesi DARK pindah halaman')

  // Keluar: lewat menu akun di baris bila aksinya tampil, lewat panel bila tidak (390px).
  const accountButton = page.locator('header [aria-haspopup="menu"]')
  if (await accountButton.first().isVisible().catch(() => false)) {
    await accountButton.click()
    await page.getByRole('menuitem', { name: 'Keluar' }).click()
  } else {
    await page.getByRole('button', { name: 'Buka menu' }).click()
    await page.getByRole('button', { name: 'Keluar' }).click()
  }
  await page.waitForTimeout(700)
  await snap('sesudah logout (DARK harus tetap)')

  report.persistence[viewport.name] = trace
  await ctx.close()
}

await browser.close()
writeFileSync(`${OUT}/vgl36-${phase}-navbar-metrics.json`, JSON.stringify(report, null, 2))

const stateCount = Object.keys(report.states).length
const persistBad = Object.values(report.persistence)
  .flat()
  .filter((/** @type {any} */ s) => !s.switchVisible || (s.stored !== null && s.attr !== s.stored))
console.log(`\nselesai ${phase}: ${stateCount} kombinasi kondisi terekam, beda-layout=${loggedOutMismatch}, persistensi-masalah=${persistBad.length}`)
if (persistBad.length) console.log(JSON.stringify(persistBad, null, 2))

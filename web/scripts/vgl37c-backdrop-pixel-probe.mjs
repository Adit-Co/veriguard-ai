// @ts-check
/// <reference types="node" />
// VGL-37C — bukti piksel latar sinematik halaman autentikasi.
//
// Dua jalur pengukuran supaya klaimnya tidak mudah dibantah:
//  (A) Pita "latar murni" yang SAMA dianalisis pada screenshot fase before dan after.
//      Koordinat pita diambil dari metrik geometri yang terekam (di luar header, kartu,
//      notifikasi, dan footer fase before) sehingga kedua fase membandingkan piksel yang
//      sepadan: before = kanvas polos, after = tumpukan gradien/kisi/glow.
//  (B) Latar diisolasi: seluruh anak <main> disembunyikan sehingga yang tersisa hanya
//      background-image pada main, lalu viewport penuh dianalisis (jumlah warna, variasi
//      per-kuadran) dan warna dasar di titik teks dipakai untuk rasio kontras WCAG.
// PNG dibaca lewat canvas browser headless → tidak ada dependency baru.
// Pemakaian: node scripts/vgl37c-backdrop-pixel-probe.mjs
import { chromium } from 'playwright'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const BASE = process.env.VGL37C_BASE ?? 'http://localhost:5178'
const PREF_KEY = 'veriguard.preferences.v1'
const OUT = resolve(process.cwd(), '../.veriguard/live')
mkdirSync(OUT, { recursive: true })

const SIZE = {
  desktop: { width: 1440, height: 950 },
  laptop: { width: 1024, height: 900 },
  tablet: { width: 820, height: 1000 },
  mobile: { width: 390, height: 844 },
}

/** pita latar murni per viewport — dibersihkan terhadap metrik before & after */
const BANDS = {
  desktop: [
    { nama: 'gutter-kiri', x: 20, y: 300, w: 150, h: 450 },
    { nama: 'gutter-kanan', x: 1272, y: 300, w: 148, h: 450 },
  ],
  laptop: [
    { nama: 'bawah-kolom-kiri', x: 24, y: 560, w: 450, h: 215 },
    // celah antara kolom kiri (r=476) dan kartu (l=540); di bawah toast (b≈180)
    { nama: 'samping-kartu', x: 500, y: 200, w: 34, h: 440 },
  ],
  tablet: [{ nama: 'antar-kolom', x: 24, y: 508, w: 770, h: 34 }],
  mobile: [{ nama: 'antar-kolom', x: 20, y: 516, w: 350, h: 32 }],
}

const INK = { light: [17, 24, 39], dark: [233, 239, 249] }

const relLum = (rgb) => {
  const f = (v) => (v / 255 <= 0.03928 ? v / 255 / 12.92 : Math.pow((v / 255 + 0.055) / 1.055, 2.4))
  return 0.2126 * f(rgb[0]) + 0.7152 * f(rgb[1]) + 0.0722 * f(rgb[2])
}
const contrast = (l1, l2) => {
  const a = Math.max(l1, l2)
  const b = Math.min(l1, l2)
  return Math.round(((a + 0.05) / (b + 0.05)) * 100) / 100
}

const browser = await chromium.launch()
const scratch = await browser.newPage()

/** @param {string} file */
async function loadImage(file) {
  const b64 = readFileSync(resolve(OUT, file)).toString('base64')
  return scratch.evaluate(async (data) => {
    const img = new Image()
    img.src = 'data:image/png;base64,' + data
    await img.decode()
    const c = document.createElement('canvas')
    c.width = img.width
    c.height = img.height
    const ctx = /** @type {CanvasRenderingContext2D} */ (c.getContext('2d'))
    ctx.drawImage(img, 0, 0)
    // @ts-expect-error scratch pad antar pengukuran
    window.__px = { w: img.width, h: img.height, ctx }
    return { w: img.width, h: img.height }
  }, b64)
}

/** @param {{x:number,y:number,w:number,h:number}} box */
function stats(box) {
  return scratch.evaluate((region) => {
    // @ts-expect-error scratch pad antar pengukuran
    const { w, h, ctx } = window.__px
    const x = Math.max(0, Math.round(region.x))
    const y = Math.max(0, Math.round(region.y))
    const rw = Math.min(w - x, Math.round(region.w))
    const rh = Math.min(h - y, Math.round(region.h))
    if (rw <= 0 || rh <= 0) return null
    const d = ctx.getImageData(x, y, rw, rh).data
    const lum = (r, g, b) => {
      const f = (v) =>
        v / 255 <= 0.03928 ? v / 255 / 12.92 : Math.pow((v / 255 + 0.055) / 1.055, 2.4)
      return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)
    }
    const warna = new Set()
    const bucket = new Set()
    let n = 0
    let sum = 0
    let sum2 = 0
    let min = 2
    let max = -1
    let mr = 0
    let mg = 0
    let mb = 0
    for (let i = 0; i < d.length; i += 4) {
      const r = d[i]
      const g = d[i + 1]
      const b = d[i + 2]
      warna.add((r << 16) | (g << 8) | b)
      bucket.add((r >> 3) + '.' + (g >> 3) + '.' + (b >> 3))
      mr += r
      mg += g
      mb += b
      const L = lum(r, g, b)
      sum += L
      sum2 += L * L
      n++
      if (L < min) min = L
      if (L > max) max = L
    }
    const mean = sum / n
    const q = (v) => Math.round(v * 1e5) / 1e5
    return {
      pixels: n,
      distinctColours: warna.size,
      distinctBuckets: bucket.size,
      rgbMean: [Math.round(mr / n), Math.round(mg / n), Math.round(mb / n)],
      luminanceMean: q(mean),
      luminanceStdev: q(Math.sqrt(Math.max(0, sum2 / n - mean * mean))),
      luminanceRange: q(max - min),
    }
  }, box)
}

const afterMetrics = JSON.parse(
  readFileSync(resolve(OUT, 'vgl37c-after-card-metrics.json'), 'utf8'),
)
const beforeMetrics = JSON.parse(
  readFileSync(resolve(OUT, 'vgl37c-before-card-metrics.json'), 'utf8'),
)
const keys = Object.keys(afterMetrics.states).filter(
  (k) => k.startsWith('masuk.') && !k.includes('setelah'),
)

/** @type {Record<string, any>} */
const report = { base: BASE, bands: {}, isolated: {}, contrast: {} }

/* ---------------- (A) pita latar murni: before vs after ---------------- */
for (const phase of ['before', 'after']) {
  const states = (phase === 'before' ? beforeMetrics : afterMetrics).states
  for (const key of keys) {
    const vp = key.split('.')[1]
    const s = states[key]
    if (!s) continue
    const rows = []
    for (const b of BANDS[vp] || []) {
      const size = await loadImage(`vgl37c-${phase}-${key}.full.png`)
      const scale = size.w / (s.innerW || size.w)
      const st = await stats({ x: b.x * scale, y: b.y * scale, w: b.w * scale, h: b.h * scale })
      rows.push({
        nama: b.nama,
        ukuran: `${Math.round(b.w * scale)}x${Math.round(b.h * scale)}`,
        ...st,
      })
    }
    report.bands[`${phase}.${key}`] = rows
  }
}

/* ---------------- (B) latar terisolasi + kontras ---------------- */
for (const theme of ['light', 'dark']) {
  for (const vp of Object.keys(SIZE)) {
    const context = await browser.newContext({ viewport: SIZE[vp] })
    await context.route('**/*', (route) => {
      const url = route.request().url()
      const local =
        url.startsWith(BASE) ||
        url.startsWith('http://127.0.0.1') ||
        url.startsWith('data:') ||
        url.startsWith('blob:')
      return local ? route.continue() : route.abort()
    })
    await context.addInitScript(
      `localStorage.setItem('${PREF_KEY}', JSON.stringify({ defaultScanMode: 'link', reduceMotion: false, theme: '${theme}' }))`,
    )
    const page = await context.newPage()
    /** @type {string[]} */
    const errors = []
    page.on('console', (m) => m.type() === 'error' && errors.push(m.text().slice(0, 120)))
    page.on('pageerror', (e) => errors.push(String(e).slice(0, 120)))
    await page.goto(`${BASE}/masuk`, { waitUntil: 'load' })
    await page.waitForSelector('main.auth-canvas', { timeout: 20000 })
    await page.waitForTimeout(1200)
    const tutup = page.getByRole('button', { name: 'Tutup notifikasi' })
    if ((await tutup.count()) > 0) {
      await tutup.click()
      await page.waitForTimeout(600)
    }

    const box = await page.evaluate(() => {
      const r = document.querySelector('main.auth-canvas').getBoundingClientRect()
      return { w: Math.round(r.width), h: Math.round(r.height) }
    })
    await page.evaluate(() => {
      // Latar VGL-37C dicat pada <main> itu sendiri, jadi cukup menyembunyikan seluruh
      // turunan main + header/footer: yang tersisa di kanvas hanya gradien/kisi/glow
      // tanpa isi halaman. (main bukan anak langsung body — aplikasi mount di #root.)
      const main = document.querySelector('main.auth-canvas')
      for (const el of Array.from(main.querySelectorAll('*'))) el.style.visibility = 'hidden'
      for (const el of Array.from(document.querySelectorAll('header, footer'))) {
        el.style.visibility = 'hidden'
      }
    })
    await page.waitForTimeout(300)

    const shot = `vgl37c-backdrop-only.${vp}.${theme}.png`
    await page.screenshot({ path: resolve(OUT, shot) })
    const size = await loadImage(shot)
    const full = await stats({ x: 0, y: 0, w: size.w, h: size.h })
    /** @type {Record<string, any>} */
    const quadrant = {}
    for (const [nama, fx, fy] of [
      ['atas', 0.5, 0.1],
      ['tengah', 0.5, 0.5],
      ['bawah-kanan', 0.86, 0.88],
      ['bawah-kiri', 0.14, 0.88],
      ['kanan-tengah', 0.9, 0.45],
    ]) {
      const q = await stats({ x: size.w * fx - 60, y: size.h * fy - 40, w: 120, h: 80 })
      quadrant[nama] = q ? { rgbMean: q.rgbMean, luminanceMean: q.luminanceMean } : null
    }
    report.isolated[`${vp}.${theme}`] = {
      box,
      ukuran: `${size.w}x${size.h}`,
      full,
      quadrant,
      errors: errors.filter((e) => !/Failed to load resource|net::ERR/.test(e)).slice(0, 4),
    }

    const s = afterMetrics.states[`masuk.${vp}.${theme}`]
    if (s) {
      const scale = size.w / (s.innerW || size.w)
      const ink = relLum(INK[theme])
      /** @type {Record<string, any>} */
      const titik = {}
      for (const [nama, el] of [['h1', s.h1], ['desc', s.desc]]) {
        if (!el) continue
        const patch = await stats({ x: el.l * scale, y: el.t * scale, w: 24, h: Math.max(8, el.h) })
        titik[nama] = patch
          ? {
              latarRgb: patch.rgbMean,
              latarL: patch.luminanceMean,
              rasio: contrast(ink, patch.luminanceMean),
            }
          : null
      }
      const cardSize = await loadImage(`vgl37c-after-masuk.${vp}.${theme}.full.png`)
      const cardScale = cardSize.w / (s.innerW || cardSize.w)
      const kartu = await stats({
        x: (s.card.l + 10) * cardScale,
        y: (s.card.t + 10) * cardScale,
        w: 14,
        h: 14,
      })
      report.contrast[`${vp}.${theme}`] = {
        inkL: Math.round(ink * 1e5) / 1e5,
        ...titik,
        kartu: kartu ? { rgbMean: kartu.rgbMean, rasioInk: contrast(ink, kartu.luminanceMean) } : null,
      }
    }
    await context.close()
  }
}

await browser.close()
writeFileSync(resolve(OUT, 'vgl37c-backdrop-pixels.json'), JSON.stringify(report, null, 2))

console.log('== (A) pita latar murni, before vs after ==')
for (const key of keys) {
  const rows = BANDS[key.split('.')[1]] || []
  for (let i = 0; i < rows.length; i += 1) {
    const b4 = report.bands[`before.${key}`]?.[i]
    const af = report.bands[`after.${key}`]?.[i]
    if (!b4 || !af) continue
    console.log(
      `${key.padEnd(22)} ${b4.nama.padEnd(16)} ${b4.ukuran.padEnd(9)} before warna=${String(b4.distinctColours).padStart(5)} rentang=${b4.luminanceRange} | ` +
        `after warna=${String(af.distinctColours).padStart(6)} rentang=${af.luminanceRange} stdev=${af.luminanceStdev} | Δ=+${af.distinctColours - b4.distinctColours}`,
    )
  }
}
console.log('== (B) latar terisolasi ==')
for (const [k, v] of Object.entries(report.isolated)) {
  console.log(
    `${k.padEnd(16)} ${v.ukuran.padEnd(9)} warna=${String(v.full?.distinctColours).padStart(7)} bucket=${String(v.full?.distinctBuckets).padStart(5)} ` +
      `L=${v.full?.luminanceMean} stdev=${v.full?.luminanceStdev} rentang=${v.full?.luminanceRange} ` +
      `kuadranL=${Object.values(v.quadrant).map((q) => q?.luminanceMean).join('/')} galat=${v.errors.length}`,
  )
}
console.log('== kontras ==')
for (const [k, v] of Object.entries(report.contrast)) {
  console.log(
    `${k.padEnd(16)} h1=${v.h1?.rasio}:1 (rgb ${(v.h1?.latarRgb || []).join(',')}) desc=${v.desc?.rasio}:1 ` +
      `dalamKartu=${v.kartu?.rasioInk}:1 (rgb ${(v.kartu?.rgbMean || []).join(',')})`,
  )
}

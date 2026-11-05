// @ts-check
/// <reference types="node" />
// VGL-37C — kontrol nol untuk vgl37c-card-pixel-diff.mjs.
// Screenshot diambil DUA KALI pada dua proses browser terpisah dengan kode yang tidak
// berganti sedikit pun. Kalau selisih antar-proses sebesar selisih fase 37B→37C, maka
// perbedaan di dalam kartu adalah nondeterminisme rasterisasi teks (antialiasing/tiling),
// bukan perubahan desain. Ditambah kontrol geser-1px: kalau diff tadi karena pergeseran
// layout, rect bergeser akan menghasilkan diff yang jauh lebih besar.
// Pemakaian: node scripts/vgl37c-card-pixel-nullcontrol.mjs
import { chromium } from 'playwright'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const BASE = process.env.VGL37C_BASE ?? 'http://localhost:5178'
const PREF_KEY = 'veriguard.preferences.v1'
const OUT = resolve(process.cwd(), '../.veriguard/live')
mkdirSync(OUT, { recursive: true })
const INSET = 20

const SIZE = {
  desktop: { width: 1440, height: 950 },
  laptop: { width: 1024, height: 900 },
  tablet: { width: 820, height: 1000 },
  mobile: { width: 390, height: 844 },
}

const metrics = JSON.parse(
  readFileSync(resolve(OUT, 'vgl37c-after-card-metrics.json'), 'utf8'),
)

const browser = await chromium.launch()
const scratch = await browser.newPage()

/** @param {string} file */
async function load(file) {
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
    // @ts-expect-error scratch pad
    window.__px = { w: img.width, h: img.height, ctx }
    return { w: img.width, h: img.height }
  }, b64)
}

/** @param {{x:number,y:number,w:number,h:number}} rect */
function diffRect(rect) {
  return scratch.evaluate((r) => {
    // @ts-expect-error scratch pad
    const { w: cw, h: ch, ctx } = window.__px
    const x = Math.max(0, Math.round(r.x))
    const y = Math.max(0, Math.round(r.y))
    const w = Math.min(cw - x, Math.round(r.w))
    const h = Math.min(ch - y, Math.round(r.h))
    if (w <= 0 || h <= 0) return { pixels: 0, beda: null }
    const d = ctx.getImageData(x, y, w, h).data
    // bandingkan buffer piksel dua PNG yang dimuat berurutan
    // @ts-expect-error scratch pad
    const other = window.__pxSecond
    if (!other) return { pixels: d.length / 4, beda: null, sebab: 'tanpa-buffer-kedua' }
    const B = other.getImageData(x, y, w, h).data
    let beda = 0
    let besar = 0
    let maxDelta = 0
    for (let i = 0; i < d.length; i += 4) {
      if (d[i] !== B[i] || d[i + 1] !== B[i + 1] || d[i + 2] !== B[i + 2]) {
        beda++
        const delta = Math.max(
          Math.abs(d[i] - B[i]),
          Math.abs(d[i + 1] - B[i + 1]),
          Math.abs(d[i + 2] - B[i + 2]),
        )
        if (delta > maxDelta) maxDelta = delta
        if (delta > 8) besar++
      }
    }
    return { pixels: d.length / 4, beda, bedaTerlihat: besar, maxDelta }
  }, rect)
}

/** muat PNG kedua sebagai buffer pembanding */
async function loadSecond(file) {
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
    // @ts-expect-error scratch pad
    window.__pxSecond = ctx
  }, b64)
}

/** ambil screenshot dua halaman pada proses browser BERDIRI TERSENDIRI */
async function capture(tag) {
  const runner = await chromium.launch()
  for (const theme of ['light', 'dark']) {
    for (const vp of Object.keys(SIZE)) {
      for (const target of [
        { name: 'masuk', path: '/masuk' },
        { name: 'daftar', path: '/daftar' },
      ]) {
        const context = await runner.newContext({ viewport: SIZE[vp] })
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
        await page.goto(`${BASE}${target.path}`, { waitUntil: 'load' })
        await page.waitForSelector('main div[class*="shadow-card"]', { timeout: 20000 })
        await page.waitForTimeout(1400)
        await page.screenshot({
          path: resolve(OUT, `vgl37c-null-${tag}.${target.name}.${vp}.${theme}.png`),
        })
        await context.close()
      }
    }
  }
  await runner.close()
}

await capture('p1')
await capture('p2')

/** @type {any[]} */
const rows = []
for (const key of Object.keys(metrics.states)) {
  if (key.includes('setelah')) continue
  const s = metrics.states[key]
  if (!s.card) continue
  const size = await load(`vgl37c-null-p1.${key}.png`)
  await loadSecond(`vgl37c-null-p2.${key}.png`)
  const scale = size.w / (s.innerW || size.w)
  const c = s.card
  const rect = {
    x: (c.l + INSET) * scale,
    y: (c.t + INSET) * scale,
    w: (c.w - INSET * 2) * scale,
    h: (c.h - INSET * 2) * scale,
  }
  const antarProses = await diffRect(rect)
  // kontrol tambahan: bandingkan dengan rect yang digeser 1px. Kalau diff karena pergeseran
  // layout, diff bergeser justru mengecil; kalau karena rasterisasi, tetap saja besar.
  const geser = await diffRect({ ...rect, x: rect.x + 1, y: rect.y + 1 })
  rows.push({ state: key, antarProses, geser1px: geser })
}

await browser.close()
writeFileSync(resolve(OUT, 'vgl37c-card-pixel-nullcontrol.json'), JSON.stringify(rows, null, 2))
for (const r of rows) {
  console.log(
    `${r.state.padEnd(24)} dua-proses-browser: ${r.antarProses.pixels}px beda=${r.antarProses.beda} terlihat(Δ>8)=${r.antarProses.bedaTerlihat} maxΔ=${r.antarProses.maxDelta} | digeser-1px beda=${r.geser1px?.beda} terlihat=${r.geser1px?.bedaTerlihat}`,
  )
}

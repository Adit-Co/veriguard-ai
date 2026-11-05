// @ts-check
/// <reference types="node" />
// VGL-37C — bukti bahwa KARTU tidak berubah sama sekali antara baseline VGL-37B dan
// VGL-37C. Perbandingan PNG utuh tidak adil: latar sinematik sengaja mengubah piksel di
// SEKITAR kartu (dan kartu punya sudut radius sehingga crop elemennya ikut memuat latar).
// Di sini isi kartu dibandingkan piksel-per-piksel pada rect interior (ditarik 20px dari
// tepi border-box agar sudut melengkung dan shadow tidak ikut dihitung).
// Pemakaian: node scripts/vgl37c-card-pixel-diff.mjs
import { chromium } from 'playwright'
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const OUT = resolve(process.cwd(), '../.veriguard/live')
const INSET = 20

/** @type {{states: Record<string, any>}} */
const metrics = JSON.parse(
  readFileSync(resolve(OUT, 'vgl37c-after-card-metrics.json'), 'utf8'),
)

const browser = await chromium.launch()
const page = await browser.newPage()

/** muat dua PNG sekaligus ke dua canvas */
async function loadTwo(a, b) {
  const a64 = readFileSync(resolve(OUT, a)).toString('base64')
  const b64 = readFileSync(resolve(OUT, b)).toString('base64')
  return page.evaluate(async ([da, db]) => {
    const read = async (data) => {
      const img = new Image()
      img.src = 'data:image/png;base64,' + data
      await img.decode()
      const c = document.createElement('canvas')
      c.width = img.width
      c.height = img.height
      const ctx = /** @type {CanvasRenderingContext2D} */ (c.getContext('2d'))
      ctx.drawImage(img, 0, 0)
      return ctx
    }
    const ca = await read(da)
    const cb = await read(db)
    // @ts-expect-error scratch pad
    window.__cmp = { ca, cb }
    return { w: ca.canvas.width, h: ca.canvas.height, w2: cb.canvas.width, h2: cb.canvas.height }
  }, [a64, b64])
}

/** bandingkan rect pada kedua canvas */
/** @param {{x:number,y:number,w:number,h:number}} rect */
function diffRect(rect) {
  return page.evaluate((r) => {
    // @ts-expect-error scratch pad
    const { ca, cb } = window.__cmp
    const x = Math.max(0, Math.round(r.x))
    const y = Math.max(0, Math.round(r.y))
    const w = Math.min(ca.canvas.width - x, Math.round(r.w))
    const h = Math.min(ca.canvas.height - y, Math.round(r.h))
    if (w <= 0 || h <= 0) return { pixels: 0, beda: null, sebab: 'rect-di-luar-kanvas' }
    const A = ca.getImageData(x, y, w, h).data
    const B = cb.getImageData(x, y, w, h).data
    let beda = 0
    let bedaTerlihat = 0
    let maxDelta = 0
    let minX = 1e9, minY = 1e9, maxX = -1, maxY = -1
    const grid = Array.from({ length: 6 }, () => new Array(6).fill(0))
    for (let i = 0; i < A.length; i += 4) {
      if (A[i] !== B[i] || A[i + 1] !== B[i + 1] || A[i + 2] !== B[i + 2]) {
        beda++
        const px = (i / 4) % w
        const py = Math.floor(i / 4 / w)
        if (px < minX) minX = px
        if (px > maxX) maxX = px
        if (py < minY) minY = py
        if (py > maxY) maxY = py
        grid[Math.min(5, Math.floor((py / h) * 6))][Math.min(5, Math.floor((px / w) * 6))]++
        const d = Math.max(
          Math.abs(A[i] - B[i]),
          Math.abs(A[i + 1] - B[i + 1]),
          Math.abs(A[i + 2] - B[i + 2]),
        )
        if (d > 8) bedaTerlihat++
        if (d > maxDelta) maxDelta = d
      }
    }
    return {
      pixels: A.length / 4,
      beda,
      bedaTerlihat,
      maxDelta,
      bboxBeda: beda ? { x: minX, y: minY + r.y, w: maxX - minX + 1, h: maxY - minY + 1 } : null,
      grid6x6: grid,
    }
  }, rect)
}

/** @type {any[]} */
const rows = []
for (const key of Object.keys(metrics.states)) {
  if (key.includes('setelah')) continue
  const page_ = key.split('.')[0]
  const file = `${page_}.${key.split('.')[1]}.${key.split('.')[2]}`
  const s = metrics.states[key]
  if (!s.card) continue
  const size = await loadTwo(`vgl37b-after-${file}.full.png`, `vgl37c-after-${file}.full.png`)
  if (size.w !== size.w2 || size.h !== size.h2) {
    rows.push({ state: key, error: `ukuran-bedua ${size.w}x${size.h} vs ${size.w2}x${size.h2}` })
    continue
  }
  const scale = size.w / (s.innerW || size.w)
  const c = s.card
  const interior = await diffRect({
    x: (c.l + INSET) * scale,
    y: (c.t + INSET) * scale,
    w: (c.w - INSET * 2) * scale,
    h: (c.h - INSET * 2) * scale,
  })
  // kontrol geser 1px: kalau kartu benar-benar bergeser, diff bergeser akan LEBIH kecil
  // daripada diff sejajar. Kalau diff sejajar sudah kecil dibanding diff bergeser, tidak
  // ada pergeseran sub-pixel sama sekali.
  const geser = await diffRect({
    x: (c.l + INSET) * scale + 1,
    y: (c.t + INSET) * scale + 1,
    w: (c.w - INSET * 2) * scale,
    h: (c.h - INSET * 2) * scale,
  })
  // pita judul kartu + area form: tetap di dalam kartu
  const judul = s.cardTitle
    ? await diffRect({
        x: s.cardTitle.l * scale,
        y: s.cardTitle.t * scale,
        w: s.cardTitle.w * scale,
        h: s.cardTitle.h * scale,
      })
    : null
  const form = s.form
    ? await diffRect({
        x: (s.form.l + 2) * scale,
        y: s.form.t * scale,
        w: (s.form.w - 4) * scale,
        h: s.form.h * scale,
      })
    : null
  rows.push({
    state: key,
    kanvas: `${size.w}x${size.h}`,
    inset: INSET,
    interior,
    geser1px: geser,
    judul,
    form,
  })
}

await browser.close()
writeFileSync(resolve(OUT, 'vgl37c-card-pixel-diff.json'), JSON.stringify(rows, null, 2))
let totalBeda = 0
for (const r of rows) {
  const b = (r.interior?.beda ?? 0) + (r.judul?.beda ?? 0) + (r.form?.beda ?? 0)
  totalBeda += b
  console.log(
    `${r.state.padEnd(24)} interior ${String(r.interior?.pixels ?? 0).padStart(7)}px beda=${r.interior?.beda ?? '—'} terlihat=${r.interior?.bedaTerlihat ?? '—'} maxΔ=${r.interior?.maxDelta ?? '—'} | ` +
      `judul beda=${r.judul?.beda ?? '—'}/${r.judul?.bedaTerlihat ?? '—'} | form beda=${r.form?.beda ?? '—'}/${r.form?.bedaTerlihat ?? '—'} | digeser-1px beda=${r.geser1px?.beda ?? '—'}/${r.geser1px?.bedaTerlihat ?? '—'} ${r.error ?? ''}`,
  )
}
const terlihat = rows.reduce(
  (a, r) => a + (r.interior?.bedaTerlihat ?? 0) + (r.judul?.bedaTerlihat ?? 0) + (r.form?.bedaTerlihat ?? 0),
  0,
)
console.log(`TOTAL piksel kartu yang berubah: ${totalBeda} (yang terlihat Δ>8: ${terlihat})`)

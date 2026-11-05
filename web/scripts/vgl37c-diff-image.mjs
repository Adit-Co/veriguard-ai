// @ts-check
/// <reference types="node" />
// VGL-37C — visualisasi DIFF antara baseline VGL-37B dan fase VGL-37C untuk satu state,
// dipakai untuk mengidentifikasi sumber perbedaan piksel di dalam kartu (kontrol nol
// antar-proses sudah membuktikan rasterisasi Chromium deterministik: 0 piksel berbeda).
// Pemakaian: node scripts/vgl37c-diff-image.mjs masuk.desktop.light
import { chromium } from 'playwright'
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const OUT = resolve(process.cwd(), '../.veriguard/live')
const key = process.argv[2] || 'masuk.desktop.light'

const browser = await chromium.launch()
const page = await browser.newPage()

/** @param {string} file */
async function b64(file) {
  return readFileSync(resolve(OUT, file)).toString('base64')
}

const a = await b64(`vgl37b-after-${key}.full.png`)
const b = await b64(`vgl37c-after-${key}.full.png`)

const png = await page.evaluate(async ([da, db]) => {
  const read = async (data) => {
    const img = new Image()
    img.src = 'data:image/png;base64,' + data
    await img.decode()
    const c = document.createElement('canvas')
    c.width = img.width
    c.height = img.height
    const ctx = /** @type {CanvasRenderingContext2D} */ (c.getContext('2d'))
    ctx.drawImage(img, 0, 0)
    return { ctx, w: img.width, h: img.height }
  }
  const A = await read(da)
  const B = await read(db)
  const out = document.createElement('canvas')
  out.width = A.w
  out.height = A.h
  const oc = /** @type {CanvasRenderingContext2D} */ (out.getContext('2d'))
  const da1 = A.ctx.getImageData(0, 0, A.w, A.h)
  const db1 = B.ctx.getImageData(0, 0, B.w, B.h)
  const o = oc.createImageData(A.w, A.h)
  let n = 0
  let sumX = 0
  let sumY = 0
  let minX = 1e9, maxX = -1, minY = 1e9, maxY = -1
  for (let i = 0; i < da1.data.length; i += 4) {
    const d = Math.max(
      Math.abs(da1.data[i] - db1.data[i]),
      Math.abs(da1.data[i + 1] - db1.data[i + 1]),
      Math.abs(da1.data[i + 2] - db1.data[i + 2]),
    )
    const v = Math.min(255, d * 6)
    o.data[i] = v
    o.data[i + 1] = v
    o.data[i + 2] = v
    o.data[i + 3] = 255
    if (d > 8) {
      const p = i / 4
      const x = p % A.w
      const y = Math.floor(p / A.w)
      n++
      sumX += x
      sumY += y
      if (x < minX) minX = x
      if (x > maxX) maxX = x
      if (y < minY) minY = y
      if (y > maxY) maxY = y
    }
  }
  oc.putImageData(o, 0, 0)
  // garis batas bbox perbedaan supaya mudah dibaca (setelah putImageData)
  oc.strokeStyle = 'rgba(255,0,0,.9)'
  oc.lineWidth = 2
  if (n) oc.strokeRect(minX - 1, minY - 1, maxX - minX + 2, maxY - minY + 2)
  return {
    dataUrl: out.toDataURL('image/png'),
    bedaTerlihat: n,
    bbox: n ? { x: minX, y: minY, w: maxX - minX + 1, h: maxY - minY + 1 } : null,
    rata: n ? { x: Math.round(sumX / n), y: Math.round(sumY / n) } : null,
  }
}, [a, b])

writeFileSync(resolve(OUT, `vgl37c-diff-${key}.png`), Buffer.from(png.dataUrl.split(',')[1], 'base64'))
await browser.close()
console.log(JSON.stringify({ key, ...png, dataUrl: undefined }, null, 2))

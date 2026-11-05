// @ts-check
/// <reference types="node" />
// VGL-39A — regresi VGL-34..VGL-37C: bandingkan rekaman geometry VGL-39A dengan baseline
// VGL-37C (file lama TIDAK ditimpa), lalu bandingkan piksel interior kartu.
// Pemakaian: node scripts/vgl39b-vs-37c-regression.mjs (baca saja; tidak merekam ulang)
import { chromium } from 'playwright'
import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'

const OUT = resolve(process.cwd(), '../.veriguard/live')
const INSET = 20

const base = JSON.parse(readFileSync(resolve(OUT, 'vgl37c-after-card-metrics.json'), 'utf8'))
const now = JSON.parse(readFileSync(resolve(OUT, 'vgl39b-regression-card-metrics.json'), 'utf8'))

/** diff daun rekursif */
function diff(a, b, path, hits) {
  if (a === b) return
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) hits.push(`${path}: panjang ${a.length} vs ${b.length}`)
    for (let i = 0; i < Math.max(a.length, b.length); i += 1) diff(a[i], b[i], `${path}[${i}]`, hits)
    return
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) diff(a[key], b[key], `${path}.${key}`, hits)
    return
  }
  hits.push(`${path}: ${JSON.stringify(a)} vs ${JSON.stringify(b)}`)
}

/** @type {string[]} */
const geometryLines = []
let totalDiffs = 0
for (const key of Object.keys(base.states)) {
  const hits = []
  if (!existsSync(resolve(OUT, 'vgl39b-regression-card-metrics.json'))) break
  const before = base.states[key]
  const after = now.states[key]
  if (!after) {
    geometryLines.push(`${key}: TIDAK TEREKAM pada VGL-39A`)
    totalDiffs += 1
    continue
  }
  for (const field of ['url', 'scrollW', 'innerW', 'docH', 'footerPresent', 'footerText', 'card', 'header', 'backdrop', 'backdropInfo', 'submit', 'submitText', 'emailInput', 'passInput', 'form', 'infoNote', 'infoNotePanel', 'noteCenterOffset', 'closeLabel', 'closeSize', 'demoMode', 'readyForm']) {
    diff(before[field], after[field], field, hits)
  }
  totalDiffs += hits.length
  geometryLines.push(`${key.padEnd(32)} beda-nilai=${hits.length}${hits.length ? ' :: ' + hits.slice(0, 3).join(' | ') : ''}`)
}

console.log('GEOMETRI vs baseline VGL-37C')
for (const line of geometryLines) console.log('  ' + line)
console.log(`  TOTAL beda nilai antar-lapisan: ${totalDiffs}`)

// Piksel interior kartu: baseline VGL-37C (.full.png) vs rekaman VGL-39A (.full.png).
const browser = await chromium.launch()
const page = await browser.newPage()

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

function diffRect(rect) {
  return page.evaluate((r) => {
    // @ts-expect-error scratch pad
    const { ca, cb } = window.__cmp
    const x = Math.max(0, Math.round(r.x))
    const y = Math.max(0, Math.round(r.y))
    const w = Math.min(ca.canvas.width - x, Math.round(r.w))
    const h = Math.min(ca.canvas.height - y, Math.round(r.h))
    if (w <= 0 || h <= 0) return { pixels: 0, beda: 0, bedaTerlihat: 0, maxDelta: 0, sebab: 'rect-di-luar-kanvas' }
    const A = ca.getImageData(x, y, w, h).data
    const B = cb.getImageData(x, y, w, h).data
    let beda = 0
    let bedaTerlihat = 0
    let maxDelta = 0
    for (let i = 0; i < A.length; i += 4) {
      if (A[i] !== B[i] || A[i + 1] !== B[i + 1] || A[i + 2] !== B[i + 2]) {
        beda++
        const d = Math.max(Math.abs(A[i] - B[i]), Math.abs(A[i + 1] - B[i + 1]), Math.abs(A[i + 2] - B[i + 2]))
        if (d > 8) bedaTerlihat++
        if (d > maxDelta) maxDelta = d
      }
    }
    return { pixels: A.length / 4, beda, bedaTerlihat, maxDelta }
  }, rect)
}

console.log('\nPIKSEL INTERIOR KARTU (inset ' + INSET + 'px) — VGL-37C vs VGL-39A')
let pixelBedaTotal = 0
let pixelStates = 0
for (const key of Object.keys(base.states)) {
  if (key.includes('setelah')) continue
  const parts = key.split('.')
  const file = `${parts[0]}.${parts[1]}.${parts[2]}`
  const s = base.states[key]
  if (!s.card) continue
  const bPath = `vgl37c-after-${file}.full.png`
  const nPath = `vgl39b-reg-${file}.full.png`
  if (!existsSync(resolve(OUT, bPath)) || !existsSync(resolve(OUT, nPath))) {
    console.log(`  ${key.padEnd(32)} PNG tidak tersedia (${bPath} / ${nPath})`)
    continue
  }
  const size = await loadTwo(bPath, nPath)
  if (size.w !== size.w2 || size.h !== size.h2) {
    console.log(`  ${key.padEnd(32)} UKURAN KANVAS BERBEDA ${size.w}x${size.h} vs ${size.w2}x${size.h2}`)
    pixelBedaTotal += 1
    continue
  }
  const scale = size.w / (s.innerW || size.w)
  const c = s.card
  const rect = {
    x: Math.round((c.l + INSET) * scale),
    y: Math.round((c.t + INSET) * scale),
    w: Math.round((c.w - INSET * 2) * scale),
    h: Math.round((c.h - INSET * 2) * scale),
  }
  const result = await diffRect(rect)
  pixelStates += 1
  pixelBedaTotal += result.bedaTerlihat
  console.log(`  ${key.padEnd(32)} ${result.pixels} piksel · beda=${result.beda} · bedaTerlihat(delta>8)=${result.bedaTerlihat} · maxDelta=${result.maxDelta}`)
}

console.log(`\nTOTAL state piksel=${pixelStates} · beda-terlihat=${pixelBedaTotal}`)
await browser.close()
process.exit(totalDiffs === 0 && pixelBedaTotal === 0 ? 0 : 1)

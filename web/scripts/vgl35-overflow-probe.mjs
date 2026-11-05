// @ts-check
/// <reference types="node" />
// VGL-35 — cari elemen penyebab overflow horizontal pada halaman tertentu.
import { chromium } from 'playwright'
import { resolve } from 'node:path'

const BASE = process.env.VERIGUARD_BASE_URL ?? 'http://localhost:5174'
const raw = process.argv[2] ?? 'hasil/vgl35-sample'
const route = raw.startsWith('/') ? raw : `/${raw}`
const width = Number(process.argv[3] ?? 820)

const seed = {
  'veriguard.preferences.v1': JSON.stringify({
    defaultScanMode: 'link',
    reduceMotion: false,
    theme: 'light',
  }),
  'veriguard.scans.v1': JSON.stringify([
    {
      id: 'vgl35-sample',
      createdAt: '2026-11-03T04:00:00.000Z',
      mode: 'link',
      riskLevel: 'high',
      riskScore: 86,
      input: 'https://bca-verifikasi-akun.com/login?otp=123456',
      displayTarget: 'bca-verifikasi-akun.com',
      headline: 'Perlu Perhatian',
      summary: 'Tautan menampilkan beberapa indikator risiko sekaligus.',
      reasons: [
        {
          id: 'brand-spoof',
          label: 'Domain menyerupai merek resmi',
          detail: 'bca-verifikasi-akun.com bukan domain resmi bca.co.id.',
          severity: 'danger',
          weight: 45,
          category: 'domain',
        },
        {
          id: 'otp-request',
          label: 'Meminta kode OTP',
          detail: 'Halaman meminta kode OTP melalui parameter tautan.',
          severity: 'danger',
          weight: 30,
          category: 'request',
        },
      ],
      patterns: [
        {
          id: 'giveaway',
          label: 'Hadiah instan',
          description: 'Pesan menawarkan hadiah yang diikuti permintaan data.',
          confidence: 'medium',
        },
      ],
      recommendations: [
        'Jangan memasukkan OTP atau kata sandi pada halaman ini.',
        'Buka aplikasi resmi untuk memverifikasi informasi tersebut.',
      ],
      technical: [
        { label: 'Protocol', value: 'https', tone: 'neutral' },
        { label: 'Domain', value: 'bca-verifikasi-akun.com', tone: 'danger' },
      ],
      meta: {
        engineVersion: 'vgl35-baseline',
        signalCount: 3,
        inputLength: 53,
        aiStatus: 'not_used',
        inputStored: true,
      },
    },
  ]),
}

const browser = await chromium.launch()
const context = await browser.newContext({
  viewport: { width, height: 900 },
  storageState: {
    cookies: [],
    origins: [{ origin: BASE, localStorage: Object.entries(seed).map(([k, v]) => ({ name: k, value: v })) }],
  },
})
const page = await context.newPage()
await page.goto(`${BASE}${route}`, { waitUntil: 'load' })
await page.waitForSelector('main')
await page.waitForTimeout(700)

const report = await page.evaluate((edge) => {
  const doc = document.documentElement
  const offenders = []
  for (const el of document.querySelectorAll('body *')) {
    const box = el.getBoundingClientRect()
    if (box.width === 0 || box.height === 0) continue
    if (box.right > edge + 1 || box.left < -1) {
      offenders.push({
        tag: el.tagName.toLowerCase(),
        cls: (typeof el.className === 'string' ? el.className : '').slice(0, 120),
        left: Math.round(box.left),
        right: Math.round(box.right),
        w: Math.round(box.width),
        depth: (() => {
          let d = 0
          let n = el
          while (n.parentElement && d < 20) {
            n = n.parentElement
            d += 1
          }
          return d
        })(),
        text: (el.textContent ?? '').trim().slice(0, 40),
      })
    }
  }
  return { scrollW: doc.scrollWidth, innerW: window.innerWidth, offenders }
}, width)

console.log(JSON.stringify({ route, width, scrollW: report.scrollW, innerW: report.innerW }, null, 0))
for (const o of report.offenders.sort((a, b) => a.depth - b.depth)) {
  console.log(`${' '.repeat(Math.min(o.depth, 12))}${o.tag} w=${o.w} [${o.left}..${o.right}] ${o.cls}`)
  if (o.text) console.log(`${' '.repeat(Math.min(o.depth, 12))}  text: ${o.text}`)
}
await browser.close()
void resolve

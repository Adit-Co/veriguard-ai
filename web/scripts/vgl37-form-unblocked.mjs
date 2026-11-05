// @ts-check
/// <reference types="node" />
// VGL-37 — buktikan notifikasi tidak pernah menghalangi bidang email, kata sandi, dan
// tombol Masuk. Setiap interaksi memakai Playwright sungguhan (klik akan gagal bila
// ada elemen lain yang mencegat), jadi ini bukti perilaku, bukan hanya geometri.
// Pemakaian: node scripts/vgl37-form-unblocked.mjs
import { chromium } from 'playwright'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const BASE = process.env.VGL37_BASE ?? 'http://localhost:5178'
const PREF_KEY = 'veriguard.preferences.v1'
const OUT = resolve(process.cwd(), '../.veriguard/live')

const viewports = [
  { name: 'desktop', width: 1440, height: 950 },
  { name: 'laptop', width: 1024, height: 900 },
  { name: 'tablet', width: 820, height: 1000 },
  { name: 'mobile', width: 390, height: 844 },
]

const browser = await chromium.launch()
const rows = []

const overlaps = (a, b) =>
  !!(a && b && a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h)

for (const viewport of viewports) {
  for (const theme of ['light', 'dark']) {
    const ctx = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } })
    const blocked = []
    await ctx.route('**/*', (route) => {
      const url = route.request().url()
      const local =
        url.startsWith(BASE) ||
        url.startsWith('http://127.0.0.1') ||
        url.startsWith('data:') ||
        url.startsWith('blob:')
      if (!local) blocked.push(url)
      return local ? route.continue() : route.abort()
    })
    await ctx.addInitScript(
      `localStorage.setItem('${PREF_KEY}', JSON.stringify({ defaultScanMode: 'link', reduceMotion: false, theme: '${theme}' }))`,
    )
    const page = await ctx.newPage()
    const dialogs = []
    page.on('dialog', async (dialog) => {
      dialogs.push(dialog.type() + ':' + dialog.message())
      await dialog.dismiss()
    })
    await page.goto(`${BASE}/masuk`, { waitUntil: 'load' })
    await page.waitForTimeout(1200)

    const noteUpfront = await page.evaluate(() =>
      Boolean(
        Array.from(document.querySelectorAll('[role="status"]')).find((n) =>
          (n.textContent || '').trim().startsWith('Layanan akun'),
        ),
      ),
    )

    // Isi kedua bidang sambil notifikasi tetap tampil.
    await page.getByLabel('Email').fill('penguji@contoh.com')
    await page.getByLabel('Kata sandi').fill('sandiyaku123')
    const values = await page.evaluate(() => ({
      email: document.querySelector('#login-email')?.value ?? null,
      password: document.querySelector('#login-password')?.value?.length ?? null,
    }))

    // Klik tombol masuk. Playwright menolak klik yang dicegat elemen lain.
    let klikSukses = true
    let klikError = null
    try {
      await page.getByRole('button', { name: 'Masuk' }).click({ timeout: 3000 })
    } catch (error) {
      klikSukses = false
      klikError = String(error).split('\n')[0]
    }
    await page.waitForTimeout(2500)

    const state = await page.evaluate(() => {
      const note = Array.from(document.querySelectorAll('[role="status"]')).find((n) =>
        (n.textContent || '').trim().startsWith('Layanan akun'),
      );
      const card = document.querySelector('main div[class*="shadow-card"]');
      const cr = card?.getBoundingClientRect();
      const nr = note?.getBoundingClientRect();
      const submit = document.querySelector('button[type="submit"]');
      const alert = document.querySelector('[role="alert"]');
      const rectOf = (sel) => {
        const el = document.querySelector(sel);
        const r = el?.getBoundingClientRect();
        return r ? { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) } : null;
      };
      return {
        notifikasiMasihAda: Boolean(note),
        submitLabel: submit?.textContent?.trim() ?? null,
        galatTampil: alert ? (alert.textContent || '').replace(/\s+/g, ' ').slice(0, 90) : null,
        notifikasi: nr ? { x: Math.round(nr.x), y: Math.round(nr.y), w: Math.round(nr.width), h: Math.round(nr.height) } : null,
        email: rectOf('#login-email'),
        sandi: rectOf('#login-password'),
        tombol: (() => {
          const el = document.querySelector('button[type="submit"]');
          const r = el?.getBoundingClientRect();
          return r ? { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) } : null;
        })(),
        kartuTop: cr ? Math.round(cr.top) : null,
        nilaiEmail: document.querySelector('#login-email')?.value ?? null,
      };
    })

    rows.push({
      viewport: `${viewport.name}/${theme}`,
      notifikasiSebelumInteraksi: noteUpfront,
      notifikasiSetelahInteraksi: state.notifikasiMasihAda,
      nilaiEmail: state.nilaiEmail,
      panjangSandi: values.password,
      klikSukses,
      klikError,
      labelSubmitSetelahKlik: state.submitLabel,
      galatSetelahKlik: state.galatTampil,
      overlayNotifikasi: {
        atasEmail: overlaps(state.notifikasi, state.email),
        atasSandi: overlaps(state.notifikasi, state.sandi),
        atasTombol: overlaps(state.notifikasi, state.tombol),
      },
      dialogBrowser: dialogs.length ? dialogs : null,
      diblokaiExternal: blocked,
    })

    await page.screenshot({ path: `${OUT}/vgl37-form-unblocked.${viewport.name}.${theme}.png` })
    await ctx.close()
  }
}

await browser.close()
mkdirSync(OUT, { recursive: true })
writeFileSync(`${OUT}/vgl37-form-unblocked.json`, JSON.stringify(rows, null, 2))
for (const r of rows) {
  console.log(
    `${r.viewport.padEnd(15)} notifikasi ${r.notifikasiSebelumInteraksi ? 'tampil' : ' Hilang'} · email="${r.nilaiEmail}" sandi=${r.panjangSandi} karakter · klik ${r.klikSukses ? 'OK' : 'GAGAL ' + r.klikError} · label "${r.labelSubmitSetelahKlik}" · galat ${r.galatSetelahKlik ? JSON.stringify(r.galatSetelahKlik) : 'tidak'} · overlay e/s/t = ${r.overlayNotifikasi.atasEmail}/${r.overlayNotifikasi.atasSandi}/${r.overlayNotifikasi.atasTombol} · dialog ${r.dialogBrowser ? r.dialogBrowser.join('|') : 'tidak ada'} · eksternal ${r.diblokaiExternal.length}`,
  )
}

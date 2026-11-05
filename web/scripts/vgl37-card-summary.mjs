// @ts-check
/// <reference types="node" />
// VGL-37 — bandingkan metrik box login vs registrasi (dan notifikasi bila ada).
// Pemakaian: node scripts/vgl37-card-summary.mjs before|after
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const phase = process.argv[2] === 'after' ? 'after' : 'before'
const data = JSON.parse(
  readFileSync(resolve(process.cwd(), `../.veriguard/live/vgl37-${phase}-card-metrics.json`), 'utf8'),
)

/** @param {any} b */
const fmt = (b) => (b ? `${Math.round(b.l)}..${Math.round(b.r)} y${Math.round(b.t)}..${Math.round(b.b)}` : '—')

/** @param {any} b */
const w = (b) => (b ? Math.round(b.r - b.l) : 0)
/** @param {any} b */
const h = (b) => (b ? Math.round(b.b - b.t) : 0)

const viewports = ['desktop', 'laptop', 'tablet', 'mobile']
for (const viewport of viewports) {
  for (const theme of ['light', 'dark']) {
    const key = (/** @type {string} */ page) => data.states[`${page}.${viewport}.${theme}`]
    const login = key('masuk')
    const reg = key('daftar')
    if (!login || !reg) continue
    console.log(`\n== ${viewport} / ${theme} ==`)
    console.log(
      `  ikon rail   login ${fmt(login.railIcon)} r${login.railIcon?.radius} | daftar ${fmt(reg.railIcon)} r${reg.railIcon?.radius}`,
    )
    console.log(
      `  h1          login ${fmt(login.h1)} | daftar ${fmt(reg.h1)}`,
    )
    console.log(
      `  notifikasi  login ${fmt(login.infoNote)} (${login.infoNoteRole ?? '—'}) | daftar ${fmt(reg.infoNote)}`,
    )
    console.log(
      `  box         login ${w(login.card)}×${h(login.card)} pad${login.card?.pad.join('/')} r${login.card?.radius} | daftar ${w(reg.card)}×${h(reg.card)} pad${reg.card?.pad.join('/')} r${reg.card?.radius}`,
    )
    console.log(
      `  judul box   login "${login.cardTitleText ?? '—'}" ${fmt(login.cardTitle)} | daftar "${reg.cardTitleText ?? '—'}" ${fmt(reg.cardTitle)}`,
    )
    console.log(
      `  field 1     login label ${fmt(login.firstLabel)} input ${fmt(login.firstInput)} | daftar label ${fmt(reg.firstLabel)} input ${fmt(reg.firstInput)}`,
    )
    console.log(
      `  submit      login ${fmt(login.submit)} h${login.submit?.h} "${login.submitText}" | daftar ${fmt(reg.submit)} h${reg.submit?.h} "${reg.submitText}"`,
    )
    console.log(
      `  jarak       icon→h1 ${login.gapIconToH1}/${reg.gapIconToH1} · h1→desc ${login.gapH1ToDesc}/${reg.gapH1ToDesc} · label→input ${login.gapLabelToInput}/${reg.gapLabelToInput} · card→submit ${Math.round(login.gapCardToSubmit ?? 0)}/${Math.round(reg.gapCardToSubmit ?? 0)}`,
    )
    console.log(
      `  overflow    login ${login.scrollW}/${login.innerW} · daftar ${reg.scrollW}/${reg.innerW} · galat ${login.errors.length}/${reg.errors.length}`,
    )
  }
}

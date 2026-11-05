// @ts-check
/// <reference types="node" />
// VGL-36 — ringkas metrik navbar ke tabel yang bisa dibaca manusia dan laporan.
// Pemakaian: node scripts/vgl36-navbar-summary.mjs before|after

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const phase = process.argv[2] === 'after' ? 'after' : 'before'
const file = resolve(process.cwd(), `../.veriguard/live/vgl36-${phase}-navbar-metrics.json`)
const data = JSON.parse(readFileSync(file, 'utf8'))

/** @param {any} b */
const edge = (b) => (b ? `${b.l}..${b.r}` : '—')

for (const [key, /** @type {any} */ s] of Object.entries(data.states)) {
  if (!s.logo) {
    console.log(`${key}: header tidak terbaca`)
    continue
  }
  const gaps = (s.navGaps || []).map((/** @type {any} */ g) => g.edgeGap)
  const labelGaps = (s.navGaps || []).map((/** @type {any} */ g) => g.labelGap)
  const logoToNav = s.nav ? s.nav.l - s.logo.r : null
  const navToTheme = s.nav && s.theme ? s.theme.l - s.nav.r : null
  const themeToAuth = s.theme && s.auth ? s.auth.l - s.theme.r : null
  const authToBurger = s.auth && s.burger ? s.burger.l - s.auth.r : null
  console.log(
    [
      key.padEnd(24),
      `logo ${edge(s.logo)}`,
      `nav ${edge(s.nav)}`,
      `tema ${edge(s.theme)}`,
      `aksi[${s.authKind}] ${edge(s.auth)}`,
      `burger ${edge(s.burger)}`,
      `| gap logo→nav ${logoToNav ?? '—'} nav→tema ${navToTheme ?? '—'} tema→aksi ${themeToAuth ?? '—'} aksi→burger ${authToBurger ?? '—'}`,
      `| antar-menu(edge) ${gaps.join(',')} label ${labelGaps.join(',')}`,
      `| h ${s.headerH} misalign ${s.verticalMisalign} overflow ${s.scrollW}>${s.innerW}${s.overflow?.length ? ' ELEMEN:' + s.overflow.length : ''} report=${s.hasReportUrl} daftar=${s.hasDaftar} order=${s.themeBeforeAuth}`,
    ].join('  '),
  )
  if (s.mobilePanel) {
    console.log(
      `${''.padEnd(24)}panel: links=[${s.mobilePanel.links.join('|')}] report=${s.mobilePanel.hasReportUrl} temaDiPanel=${s.mobilePanel.hasThemeSwitch}`,
    )
  }
}

console.log('\n--- persistensi tema ---')
for (const [vp, /** @type {any[]} */ trace] of Object.entries(data.persistence)) {
  console.log(vp)
  for (const step of trace) {
    console.log(`  ${String(step.step).padEnd(30)} attr=${step.attr} stored=${step.stored} switchTerlihat=${step.switchVisible}`)
  }
}

console.log('\n--- gaya tombol Masuk ---')
for (const [key, /** @type {any} */ s] of Object.entries(data.states)) {
  if (s.masukStyle) console.log(`${key.padEnd(24)} ${JSON.stringify(s.masukStyle)}`)
}

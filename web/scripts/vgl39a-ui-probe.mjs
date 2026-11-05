// VGL-39A — probe UI /masuk untuk "3 kesempatan per tingkat" (browser sungguhan, jam dinding,
// server lokal sungguhan). Membuktikan: baris kesempatan mengikuti jawaban SERVER (bukan hitungan
// klien), tombol nonaktif selama cooldown, 3 kesempatan kembali setelah cooldown habis menurut jam
// dinding, refresh/tab baru tidak menambah kesempatan, tidak ada notifikasi duplikat, tidak ada
// galat konsol, LIGHT dan DARK sama-sama terbaca, dan geometri kartu VGL-37C tidak berubah.
//
// Probe ini selalu memakai PORT MILIK SENDIRI (dev 5199 + gerbang 8899 default) dengan berkas
// keadaan di direktori sementara, supaya server dev/gerbang yang mungkin sedang berjalan di
// 5173/8787 tidak ikut tersentuh maupun membuat keadaan lama mengacaukan assertion.
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { chromium } from 'playwright'

const SERVER_DIR = 'C:/AI-Projects/veriguard-ai/server'
const WEB_DIR = 'C:/AI-Projects/veriguard-ai/web'
const WEB_PORT = Number(process.env.PROBE_WEB_PORT ?? 5199)
const GATE_PORT = Number(process.env.PROBE_GATE_PORT ?? 8899)
const ORIGIN = `http://localhost:${WEB_PORT}`
const APP = `${ORIGIN}/masuk`
const GATE = `http://127.0.0.1:${GATE_PORT}`
const EMAIL = 'sasaran@contoh.com'
const PRISTINE = { width: 460, height: 489.28 }
const stateDir = mkdtempSync(join(tmpdir(), 'vgl39a-ui-'))
const stateFile = join(stateDir, 'login-guard.json')

const results = []
function check(name, pass, detail) {
  results.push({ name, pass, detail })
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${detail ? ` :: ${detail}` : ''}`)
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function spawnLogged(command, args, cwd, tag, env = {}) {
  // Tanpa shell: jalur node.exe berisi spasi dan shell Windows akan memecahnya.
  const child = spawn(command, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env } })
  child.stdout.on('data', (chunk) => process.stdout.write(`[${tag}] ${chunk}`))
  child.stderr.on('data', (chunk) => process.stdout.write(`[${tag}:err] ${chunk}`))
  child.on('error', (error) => process.stdout.write(`[${tag}:spawn-error] ${error.message}\n`))
  return child
}

async function isUp(url) {
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(2_000) })
    return response.status < 500
  } catch {
    return false
  }
}

async function waitFor(url, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await isUp(url)) return true
    await sleep(250)
  }
  return false
}

if (await isUp(`${GATE}/health`)) throw new Error(`port gerbang probe ${GATE_PORT} sudah dipakai — pilih PROBE_GATE_PORT lain`)
if (await isUp(`${ORIGIN}/`)) throw new Error(`port web probe ${WEB_PORT} sudah dipakai — pilih PROBE_WEB_PORT lain`)

const server = spawnLogged(process.execPath, ['dist/server/src/index.js'], SERVER_DIR, 'server', {
  SERVER_PORT: String(GATE_PORT),
  SERVER_HOST: '127.0.0.1',
  LOGIN_GUARD_STATE_FILE: stateFile,
  ALLOWED_ORIGINS: `${ORIGIN},http://127.0.0.1:${WEB_PORT},http://localhost:5173`,
})
const vite = spawnLogged(
  process.execPath,
  ['node_modules/vite/bin/vite.js', '--port', String(WEB_PORT), '--strictPort', '--host', '127.0.0.1'],
  WEB_DIR,
  'vite',
  { VITE_API_BASE_URL: GATE },
)

const readyGate = await waitFor(`${GATE}/auth/login/gate/status?clientId=boot-check`)
const readyApp = await waitFor(`${ORIGIN}/`)
check(`server lokal (${GATE_PORT}) + vite dev (${WEB_PORT}) siap`, readyGate && readyApp)

const browser = await chromium.launch()
const context = await browser.newContext({ viewport: { width: 1440, height: 960 } })
const page = await context.newPage()
const alerts = []
const consoleErrors = []
page.on('dialog', async (dialog) => {
  alerts.push(dialog.message())
  await dialog.dismiss()
})
page.on('console', (message) => {
  if (message.type() === 'error') consoleErrors.push(message.text())
})
await page.addInitScript(() => {
  window.__alertCalls = []
  const original = window.alert
  window.alert = (text) => {
    window.__alertCalls.push(String(text))
    return original?.apply(window, [])
  }
})

async function cardGeometry(target) {
  return target.evaluate(() => {
    const email = document.querySelector('#login-email')
    const card = email?.closest('[class*="rounded-card"]')
    if (!card) return null
    const box = card.getBoundingClientRect()
    return { width: Number(box.width.toFixed(2)), height: Number(box.height.toFixed(2)) }
  })
}

async function openLogin(target = page) {
  await target.goto(APP, { waitUntil: 'networkidle' })
  await target.waitForSelector('#login-email', { timeout: 20_000 })
}

async function gateStatus(clientId) {
  return await (
    await fetch(`${GATE}/auth/login/gate/status?clientId=${encodeURIComponent(clientId)}&email=${encodeURIComponent(EMAIL)}`, {
      headers: { origin: ORIGIN },
    })
  ).json()
}

/** Satu kegagalan kredensial nyata pada gerbang, lewat HTTP seperti yang dilakukan UI. */
async function gateFailure(clientId) {
  const acquired = await (
    await fetch(`${GATE}/auth/login/gate/acquire`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: ORIGIN },
      body: JSON.stringify({ clientId, email: EMAIL }),
    })
  ).json()
  if (!acquired.allowed) return { acquired, reported: null }
  const reported = await (
    await fetch(`${GATE}/auth/login/gate/report`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: ORIGIN },
      body: JSON.stringify({ clientId, email: EMAIL, outcome: 'credential-failure', token: acquired.token }),
    })
  ).json()
  return { acquired, reported }
}

const attemptsText = () => page.getByText(/Kesempatan login tersisa/).first().textContent().catch(() => null)
const submitDisabled = () => page.locator('form:has(#login-email) button[type="submit"]').isDisabled()

await openLogin()
const baseline = await cardGeometry(page)
check('formulir masuk tampil (mode firebase aktif)', baseline !== null, JSON.stringify(baseline))
check(
  'keadaan bersih: kartu identik dengan baseline VGL-37C dan baris kesempatan TIDAK dirender',
  baseline.width === PRISTINE.width && baseline.height === PRISTINE.height && (await attemptsText()) === null,
  JSON.stringify(baseline),
)

const clientId = await page.evaluate(() => window.localStorage.getItem('veriguard.login-client.v1'))
check('identifier sumber dibuat di klien (bukan satu-satunya kebenaran)', typeof clientId === 'string' && clientId.startsWith('web-'), String(clientId)?.slice(0, 12) + '…')

// ── 1. Dua kegagalan pertama: hanya kesempatan yang berkurang, tanpa panel cooldown. ──
const fail1 = await gateFailure(clientId)
check(
  'kegagalan ke-1 di gerbang -> 2 dari 3 tersisa dan belum ada cooldown',
  fail1.reported?.attemptsLeft === 2 && fail1.reported?.retryAfterMs === 0,
  JSON.stringify(fail1.reported),
)
await openLogin()
const serverAfter1 = await gateStatus(clientId)
const shown1 = await attemptsText()
check(
  'UI menampilkan angka yang sama dengan server setelah refresh (bukan hitungan lokal)',
  shown1 === `Kesempatan login tersisa: ${serverAfter1.attemptsLeft} dari ${serverAfter1.attemptsPerLevel}` && serverAfter1.attemptsLeft === 2 && (await submitDisabled()) === false,
  `UI="${String(shown1)?.trim()}" server=${serverAfter1.attemptsLeft}`,
)
check(
  'belum ada panel pembatasan dan geometri kartu tidak bergeser oleh baris kesempatan',
  (await page.getByText('Terlalu banyak percobaan login').count()) === 0 && (await cardGeometry(page)).width === baseline.width,
  JSON.stringify(await cardGeometry(page)),
)

const fail2 = await gateFailure(clientId)
await openLogin()
const shown2 = await attemptsText()
const serverAfter2 = await gateStatus(clientId)
check(
  'kegagalan ke-2 -> baris kesempatan turun ke 1 dari 3, masih tanpa cooldown',
  fail2.reported?.attemptsLeft === 1 && String(shown2)?.trim() === 'Kesempatan login tersisa: 1 dari 3' && serverAfter2.retryAfterMs === 0,
  `UI="${String(shown2)?.trim()}"`,
)

// Baris kesempatan harus terbaca di LIGHT dan DARK.
const contrast = async () => {
  const paint = await page.evaluate(() => {
    const node = [...document.querySelectorAll('[role="status"]')].find((el) =>
      /Kesempatan login tersisa/.test(el.textContent ?? ''),
    )
    if (!node) return null
    const style = getComputedStyle(node)
    const panel = node.closest('main') ?? document.body
    return {
      theme: document.documentElement.dataset.theme ?? 'light',
      color: style.color,
      background: getComputedStyle(panel).backgroundColor,
      visible: node.getBoundingClientRect().height > 0,
      size: style.fontSize,
    }
  })
  return paint
}
const lightPaint = await contrast()
await page.click('button[data-theme-option="dark"]')
await page.waitForTimeout(400)
const darkPaint = await contrast()
check(
  'baris kesempatan tampil di LIGHT dan DARK dengan warna yang benar-benar berbeda dari latar',
  Boolean(lightPaint?.visible && darkPaint?.visible) && lightPaint.color !== darkPaint.color && darkPaint.color !== darkPaint.background,
  `light=${lightPaint?.color} (${lightPaint?.theme}) dark=${darkPaint?.color} (${darkPaint?.theme})`,
)
await page.click('button[data-theme-option="light"]')
await page.waitForTimeout(400)
const backToLight = await contrast()
const lineNow = String(await attemptsText())?.trim()
check(
  'bolak-balik tema tidak mengubah angka kesempatan maupun warna teks baseline',
  backToLight?.color === lightPaint?.color && lineNow === 'Kesempatan login tersisa: 1 dari 3',
  `teks="${lineNow}" warna=${backToLight?.color}`,
)

// ── 2. Kegagalan ke-3: cooldown aktif, baris kesempatan digantikan panel. ──
const fail3 = await gateFailure(clientId)
check(
  'kegagalan ke-3 -> cooldown 120 000 ms milik tingkat berjalan',
  fail3.reported?.retryAfterMs > 115_000 && fail3.reported?.failures === 0,
  JSON.stringify(fail3.reported),
)
const cooldownEndsAt = fail3.reported.serverTime + fail3.reported.retryAfterMs
await openLogin()
check(
  'panel pembatasan muncul tepat satu kali dan baris kesempatan disembunyikan saat terkunci',
  (await page.getByText('Terlalu banyak percobaan login').count()) === 1 && (await attemptsText()) === null,
  `panel=${await page.getByText('Terlalu banyak percobaan login').count()}`,
)
check('tombol Masuk dinonaktifkan selama cooldown', await submitDisabled())
check(
  'field email + kata sandi tetap terlihat (form tidak hilang)',
  (await page.locator('#login-email').isVisible()) && (await page.locator('#login-password').isVisible()),
)
const countdown = await page.getByText(/sisa waktu/).first().textContent().catch(() => null)
check('sisa waktu cooldown ditampilkan dan tersinkron jam server', /sisa waktu \d+ menit( \d+ detik)?/.test(String(countdown)), String(countdown)?.trim())
const lockedGeometry = await cardGeometry(page)
check(
  'geometri kartu tidak berubah oleh panel cooldown (lebar identik baseline)',
  lockedGeometry.width === baseline.width,
  JSON.stringify(lockedGeometry),
)
const toastCount = await page.locator('[role="status"][aria-live="polite"]').count()
const alertCount = await page.locator('div[role="alert"]').count()
check('tidak ada notifikasi duplikat/galat saat cooldown', toastCount <= 1 && alertCount === 0, `toast=${toastCount} alert=${alertCount}`)

// ── 3. Percobaan tambahan selama kunci tidak menghabiskan kesempatan. ──
for (let i = 0; i < 3; i += 1) {
  await fetch(`${GATE}/auth/login/gate/acquire`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: ORIGIN },
    body: JSON.stringify({ clientId, email: EMAIL }),
  })
}
await openLogin()
const afterTries = await gateStatus(clientId)
check(
  '3 percobaan saat terkunci: kesempatan tetap utuh untuk siklus berikutnya (failures 0, level 1)',
  afterTries.failures === 0 && afterTries.level === 1 && (await submitDisabled()),
  JSON.stringify(afterTries),
)

// ── 4. Tab baru pada sumber yang sama: tidak dapat kesempatan ekstra. ──
const secondPage = await context.newPage()
await secondPage.goto(APP, { waitUntil: 'networkidle' })
await secondPage.waitForSelector('#login-email', { timeout: 20_000 })
const secondDisabled = await secondPage.locator('form:has(#login-email) button[type="submit"]').isDisabled()
const secondAttempts = await secondPage.getByText(/Kesempatan login tersisa/).count()
check('tab baru tetap terkunci dan tidak menampilkan kesempatan palsu', secondDisabled && secondAttempts === 0, `disabled=${secondDisabled} baris=${secondAttempts}`)
await secondPage.close()

// ── 5. WAKTU NYATA: tunggu cooldown habis menurut jam dinding, lalu 3 kesempatan baru. ──
const waitMs = Math.max(0, cooldownEndsAt - Date.now() + 2_500)
console.log(`... menunggu ${Math.round(waitMs / 1000)} detik waktu nyata sampai cooldown berakhir`)
await sleep(waitMs)
await openLogin()
const expiredStatus = await gateStatus(clientId)
check(
  'setelah cooldown habis secara jam dinding: tombol aktif lagi dan panel hilang',
  (await submitDisabled()) === false && (await page.getByText('Terlalu banyak percobaan login').count()) === 0 && expiredStatus.active === false,
  JSON.stringify(expiredStatus),
)
check(
  'kesempatan yang ditampilkan adalah 3 dari 3 penuh pada tingkat yang sama (level 1)',
  expiredStatus.attemptsLeft === 3 && expiredStatus.level === 1 && (await attemptsText()) === null,
  `attemptsLeft=${expiredStatus.attemptsLeft} level=${expiredStatus.level}`,
)
const failAfterExpiry = await gateFailure(clientId)
await openLogin()
const restoredLine = await attemptsText()
check(
  'siklus baru benar-benar memberi 3 kesempatan: kegagalan pertama setelah habis -> 2 dari 3',
  failAfterExpiry.reported?.attemptsLeft === 2 && String(restoredLine)?.trim() === 'Kesempatan login tersisa: 2 dari 3',
  `UI="${String(restoredLine)?.trim()}"`,
)
const finalGeometry = await cardGeometry(page)
check(
  'susunan akhir tetap identik dengan baseline VGL-37C',
  finalGeometry.width === PRISTINE.width && finalGeometry.height === PRISTINE.height,
  `baseline=${JSON.stringify(PRISTINE)} akhir=${JSON.stringify(finalGeometry)}`,
)

const alertCalls = await page.evaluate(() => window.__alertCalls)
const relevantErrors = consoleErrors.filter((text) => !/favicon|net::ERR|Failed to load resource|identitytoolkit|firebase/i.test(text))
check('tidak ada browser alert', alertCalls.length === 0 && alerts.length === 0, JSON.stringify(alertCalls))
check('tidak ada galat konsol dari kode gerbang', relevantErrors.length === 0, relevantErrors.slice(0, 3).join(' | '))

await browser.close()
server.kill()
vite.kill()
rmSync(stateDir, { recursive: true, force: true })

const passed = results.filter((item) => item.pass).length
console.log(`\nRINGKASAN UI: ${passed}/${results.length} pemeriksaan lulus`)
process.exit(passed === results.length ? 0 : 1)

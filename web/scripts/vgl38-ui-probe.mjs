// VGL-38 — probe UI /masuk pada cooldown (browser sungguhan, jam dinding, server lokal sungguhan).
// Membuktikan: panel pembatasan muncul, tombol "Masuk" nonaktif, field email/kata sandi tetap
// terlihat, tidak ada window.alert, tidak ada notifikasi duplikat, cooldown bertahan setelah
// refresh, maju-jam-lokal tidak memperpendek, dan geometri kartu VGL-37C tidak berubah.
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { chromium } from 'playwright'

const SERVER_DIR = 'C:/AI-Projects/veriguard-ai/server'
const WEB_DIR = 'C:/AI-Projects/veriguard-ai/web'
const GATE = 'http://127.0.0.1:8787'
const APP = 'http://localhost:5173/masuk'
const stateDir = mkdtempSync(join(tmpdir(), 'vgl38-ui-'))
const stateFile = join(stateDir, 'login-guard.json')

const results = []
function check(name, pass, detail) {
  results.push({ name, pass, detail })
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${detail ? ` :: ${detail}` : ''}`)
}

function spawnLogged(command, args, cwd, tag) {
  // Tanpa shell: jalur node.exe berisi spasi dan shell Windows akan memecahnya.
  const child = spawn(command, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] })
  child.stdout.on('data', (chunk) => process.stdout.write(`[${tag}] ${chunk}`))
  child.stderr.on('data', (chunk) => process.stdout.write(`[${tag}:err] ${chunk}`))
  child.on('error', (error) => process.stdout.write(`[${tag}:spawn-error] ${error.message}\n`))
  return child
}

async function waitFor(url, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(2_000) })
      if (response.status < 500) return true
    } catch {
      /* belum siap */
    }
    await new Promise((resolve) => setTimeout(resolve, 250))
  }
  return false
}

process.env.LOGIN_GUARD_STATE_FILE = stateFile
const server = spawnLogged(process.execPath, ['dist/server/src/index.js'], SERVER_DIR, 'server')
const vite = spawnLogged(process.execPath, ['node_modules/vite/bin/vite.js', '--port', '5173', '--strictPort', '--host', '127.0.0.1'], WEB_DIR, 'vite')

const readyGate = await waitFor(`${GATE}/auth/login/gate/status?clientId=boot-check`)
const readyApp = await waitFor('http://localhost:5173/')
check('server lokal + vite dev siap', readyGate && readyApp)

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

async function cardGeometry() {
  return page.evaluate(() => {
    const email = document.querySelector('#login-email')
    const card = email?.closest('[class*="rounded-card"]')
    if (!card) return null
    const box = card.getBoundingClientRect()
    return { width: Number(box.width.toFixed(2)), height: Number(box.height.toFixed(2)) }
  })
}

async function openLogin() {
  await page.goto(APP, { waitUntil: 'networkidle' })
  await page.waitForSelector('#login-email', { timeout: 20_000 })
}

await openLogin()

// Baseline tanpa cooldown: bentuk kartu harus sama seperti VGL-37C.
const baseline = await cardGeometry()
check('formulir masuk tampil dan mode firebase aktif (form nyata ada)', baseline !== null, JSON.stringify(baseline))

const toastCountBaseline = await page.locator('[role="status"][aria-live="polite"]').count()
check('notifikasi layanan akun tunggal sebelum cooldown', toastCountBaseline === 1, `role=status: ${toastCountBaseline}`)

const clientId = await page.evaluate(() => window.localStorage.getItem('veriguard.login-client.v1'))
check('identifier sumber dibuat di klien (bukan satu-satunya kebenaran)', typeof clientId === 'string' && clientId.startsWith('web-'), String(clientId)?.slice(0, 12) + '…')

// Sumber X gagal satu kali pada gerbang -> server menahan sumber ini 120 detik.
const acquired = await (await fetch(`${GATE}/auth/login/gate/acquire`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
  body: JSON.stringify({ clientId, email: 'sasaran@contoh.com' }),
})).json()
const reported = await (await fetch(`${GATE}/auth/login/gate/report`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
  body: JSON.stringify({ clientId, email: 'sasaran@contoh.com', outcome: 'credential-failure', token: acquired.token }),
})).json()
check('sumber browser terkena tingkat 1 = 120 detik di gerbang', reported.level === 1 && reported.retryAfterMs === 120_000, JSON.stringify(reported))

// 1. Refresh: panel pembatasan harus muncul dari jawaban SERVER, bukan state React.
await page.reload({ waitUntil: 'networkidle' })
await page.waitForSelector('#login-email', { timeout: 20_000 })
const panelTitle = await page.getByText('Terlalu banyak percobaan login').count()
const panelVisible = await page.getByText('Percobaan login terlalu sering terdeteksi dari sumber ini').isVisible().catch(() => false)
check('cooldown tetap ada setelah refresh halaman', panelVisible && panelTitle === 1, `judul-panel=${panelTitle}`)

const submitDisabled = await page.locator('form:has(#login-email) button[type="submit"]').isDisabled()
check('tombol Masuk dinonaktifkan selama cooldown', submitDisabled)

const fieldsVisible = await page.locator('#login-email').isVisible() && (await page.locator('#login-password').isVisible())
check('field email + kata sandi tetap terlihat, form tidak hilang', fieldsVisible)

const countdownText = await page.getByText(/sisa waktu/).first().textContent().catch(() => null)
check('sisa waktu ditampilkan dalam format mudah dibaca', /sisa waktu \d+ menit( \d+ detik)?/.test(countdownText ?? ''), String(countdownText)?.trim())

const toastCountDuring = await page.locator('[role="status"][aria-live="polite"]').count()
const alertCount = await page.locator('div[role="alert"]').count()
check('tidak ada notifikasi duplikat saat cooldown', toastCountDuring <= 1 && alertCount === 0, `toast=${toastCountDuring} alert=${alertCount}`)

const withPanel = await cardGeometry()
check('panel muncul di bawah/atas kartu tanpa menghapus kartu', withPanel !== null && withPanel.width === baseline.width, JSON.stringify(withPanel))

const alertCalls = await page.evaluate(() => window.__alertCalls)
check('tidak ada browser alert', alertCalls.length === 0 && alerts.length === 0, JSON.stringify(alertCalls))

// 2. Jam lokal dimajukan 10 menit: server tetap penentu, cooldown TIDAK boleh memendek.
await page.addInitScript(() => {
  const realNow = Date.now
  window.__shifted = true
  Date.now = () => realNow() + 10 * 60_000
})
await page.reload({ waitUntil: 'networkidle' })
await page.waitForSelector('#login-email', { timeout: 20_000 })
const afterClockJump = await page.getByText(/sisa waktu/).first().textContent().catch(() => null)
const stillBlocked = await page.locator('form:has(#login-email) button[type="submit"]').isDisabled()
const serverSideStatus = await (await fetch(`${GATE}/auth/login/gate/status?clientId=${encodeURIComponent(clientId)}`, { headers: { origin: 'http://localhost:5173' } })).json()
check('majukan jam lokal 10 menit -> pembatasan tidak memendek', stillBlocked && serverSideStatus.active === true && serverSideStatus.retryAfterMs > 60_000, `UI="${String(afterClockJump)?.trim()}" serverRetryAfterMs=${serverSideStatus.retryAfterMs}`)

// 3. Membuka tab baru (state React hilang) tetap tertahan.
const secondPage = await context.newPage()
await secondPage.goto(APP, { waitUntil: 'networkidle' })
await secondPage.waitForSelector('#login-email', { timeout: 20_000 })
check('halaman baru pada sumber yang sama tetap tertahan', await secondPage.locator('form:has(#login-email) button[type="submit"]').isDisabled())
await secondPage.close()

// 4. Gerbang menyelesaikan cooldown (di sini: reset lewat login berhasil) -> tombol aktif lagi.
await fetch(`${GATE}/auth/login/gate/report`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
  body: JSON.stringify({ clientId, email: 'sasaran@contoh.com', outcome: 'success' }),
})
const cleared = await (await fetch(`${GATE}/auth/login/gate/status?clientId=${encodeURIComponent(clientId)}`, { headers: { origin: 'http://localhost:5173' } })).json()
check('login berhasil membersihkan riwayat sumber', cleared.active === false && cleared.failures === 0, JSON.stringify(cleared))

await page.close()
const fresh = await context.newPage()
await fresh.goto(APP, { waitUntil: 'networkidle' })
await fresh.waitForSelector('#login-email', { timeout: 20_000 })
const enabledAgain = !(await fresh.locator('form:has(#login-email) button[type="submit"]').isDisabled())
const panelGone = (await fresh.getByText('Terlalu banyak percobaan login').count()) === 0
check('setelah cooldown selesai tombol dapat dipakai dan panel hilang', enabledAgain && panelGone, `enabled=${enabledAgain} panelGone=${panelGone}`)
const restored = await fresh.evaluate(() => {
  const email = document.querySelector('#login-email')
  const card = email?.closest('[class*="rounded-card"]')
  const box = card.getBoundingClientRect()
  return { width: Number(box.width.toFixed(2)), height: Number(box.height.toFixed(2)) }
})
check('geometri kartu kembali identik dengan baseline VGL-37C', restored.width === baseline.width && restored.height === baseline.height, `baseline=${JSON.stringify(baseline)} setelah=${JSON.stringify(restored)}`)

const relevantErrors = consoleErrors.filter((text) => !/favicon|net::ERR|Failed to load resource|identitytoolkit|firebase/i.test(text))
check('tidak ada galat konsol dari kode gerbang', relevantErrors.length === 0, relevantErrors.slice(0, 3).join(' | '))

await browser.close()
server.kill()
vite.kill()
rmSync(stateDir, { recursive: true, force: true })

const passed = results.filter((item) => item.pass).length
console.log(`\nRINGKASAN UI: ${passed}/${results.length} pemeriksaan lulus`)
process.exit(passed === results.length ? 0 : 1)

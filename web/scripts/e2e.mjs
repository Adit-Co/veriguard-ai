import { spawn } from 'node:child_process'
import { mkdir, readFile, rm } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const port = 4174
const baseUrl = `http://127.0.0.1:${port}`
const outputDir = path.join(root, '.verify', 'e2e')
const buildDir = path.join(root, '.verify', 'e2e-dist')
const axePath = path.join(root, 'node_modules', 'axe-core', 'axe.min.js')
const SCAN_KEY = 'veriguard.scans.v1'
const SESSION_KEY = 'veriguard.local-session.v1'
const PREFERENCES_KEY = 'veriguard.preferences.v1'
const PENDING_SYNC_KEY = 'veriguard.pendingSync.v1'

const failures = []
const externalRequests = new Set()
let checks = 0
let currentScenario = ''

function scenario(name) {
  currentScenario = name
  console.log(`\n[E2E] ${name}`)
}

function check(condition, message) {
  checks += 1
  if (!condition) failures.push(`${currentScenario}: ${message}`)
}

function testBuildEnv() {
  return {
    ...process.env,
    VITE_FIREBASE_API_KEY: '',
    VITE_FIREBASE_AUTH_DOMAIN: '',
    VITE_FIREBASE_PROJECT_ID: '',
    VITE_FIREBASE_APP_ID: '',
    VITE_FIREBASE_STORAGE_BUCKET: '',
    VITE_FIREBASE_MESSAGING_SENDER_ID: '',
    VITE_USE_EMULATORS: 'false',
    VITE_MULTI_SOURCE_ENABLED: 'false',
    VITE_API_BASE_URL: '',
    VITE_SCANNER_WORKER_URL: '',
    VITE_COMMUNITY_BACKEND: 'firestore',
  }
}

function buildForTests(outDir) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [
        'node_modules/vite/bin/vite.js',
        'build',
        '--mode',
        'verify',
        '--outDir',
        outDir,
        '--emptyOutDir',
      ],
      {
        cwd: root,
        env: testBuildEnv(),
        stdio: 'inherit',
      },
    )

    child.on('error', reject)
    child.on('exit', (code) => {
      if (code === 0) resolve()
      else reject(new Error(`Build test gagal dengan kode ${code}`))
    })
  })
}

function startPreview(outDir) {
  const child = spawn(
    process.execPath,
    [
      'node_modules/vite/bin/vite.js',
      'preview',
      '--port',
      String(port),
      '--strictPort',
      '--host',
      '127.0.0.1',
      '--outDir',
      outDir,
    ],
    { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] },
  )

  child.stderr.on('data', (chunk) => process.stderr.write(`[preview] ${chunk}`))
  return child
}

async function waitForServer(url, timeoutMs = 30000) {
  const started = Date.now()

  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(url)
      if (response.ok) return
    } catch {
      // server not ready yet
    }
    await new Promise((resolve) => setTimeout(resolve, 250))
  }

  throw new Error(`Preview server tidak siap dalam ${timeoutMs} ms`)
}

async function waitForHeading(page, text, timeout = 7000) {
  try {
    await page
      .locator('h1')
      .filter({ hasText: text })
      .first()
      .waitFor({ state: 'visible', timeout })
    return true
  } catch {
    return false
  }
}

async function createPage(
  browser,
  viewport = { width: 1440, height: 900 },
  options = {},
) {
  const context = await browser.newContext({
    viewport,
    acceptDownloads: true,
    ...options,
  })
  const page = await context.newPage()
  const errors = []

  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`))
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(`console: ${message.text()}`)
  })
  page.on('request', (request) => {
    const url = request.url()
    if (!/^https?:/i.test(url)) return
    const origin = new URL(url).origin
    if (origin !== baseUrl) externalRequests.add(url)
  })

  return { context, page, errors }
}

async function setLocalState(page, state) {
  await page.goto(`${baseUrl}/`, { waitUntil: 'domcontentloaded' })
  await page.evaluate(
    ({ scanKey, sessionKey, preferenceKey, next }) => {
      const write = (key, value, raw = false) => {
        if (value === undefined) {
          localStorage.removeItem(key)
          return
        }
        localStorage.setItem(key, raw ? value : JSON.stringify(value))
      }

      write(scanKey, next.scans, next.scansRaw)
      write(sessionKey, next.session, next.sessionRaw)
      write(preferenceKey, next.preferences, next.preferencesRaw)
    },
    {
      scanKey: SCAN_KEY,
      sessionKey: SESSION_KEY,
      preferenceKey: PREFERENCES_KEY,
      next: state,
    },
  )
}

function makeScan({
  id,
  mode = 'link',
  input,
  displayTarget = input,
  riskScore = 0,
  riskLevel = 'low',
  createdAt,
  inputStored = 'full',
}) {
  const high = riskLevel === 'high'
  const message = mode === 'message'

  return {
    id,
    createdAt,
    mode,
    input,
    displayTarget,
    riskScore,
    riskLevel,
    headline: high
      ? 'Indikasi risiko tinggi'
      : riskLevel === 'medium'
        ? 'Indikasi risiko sedang'
        : 'Indikasi risiko rendah',
    summary: high
      ? 'Beberapa indikator risiko tinggi ditemukan pada data ini.'
      : 'Tidak banyak indikator risiko ditemukan pada data ini.',
    reasons: high
      ? [
          {
            id: 'brand_impersonation',
            label: 'Nama merek pada domain tidak resmi',
            detail: 'Domain memakai nama merek tanpa hubungan resmi.',
            severity: 'danger',
            weight: 28,
            category: 'impersonation',
          },
        ]
      : [],
    patterns: high
      ? [
          {
            id: 'phishing',
            label: 'Phishing',
            description: 'Pola yang menyerupai upaya memperoleh data.',
            confidence: 'high',
          },
        ]
      : [],
    recommendations: ['Verifikasi melalui kanal resmi sebelum bertindak.'],
    technical: [],
    meta: {
      engineVersion: 'e2e',
      signalCount: high ? 1 : 0,
      inputLength: input.length,
      aiStatus: 'not_used',
      inputStored: message ? inputStored : 'full',
    },
  }
}

function dashboardFixtures() {
  return [
    makeScan({
      id: 'e2e-high-link',
      input: 'https://bca-verifikasi-akun.example/login',
      riskScore: 72,
      riskLevel: 'high',
      createdAt: '2026-10-21T08:30:00.000Z',
    }),
    makeScan({
      id: 'e2e-high-message',
      mode: 'message',
      input: 'Kode OTP 778899 jangan dibagikan kepada siapa pun.',
      displayTarget: 'Kode OTP [angka] jangan dibagikan kepada siapa pun.',
      riskScore: 64,
      riskLevel: 'high',
      createdAt: '2026-10-21T08:20:00.000Z',
      inputStored: 'full',
    }),
    makeScan({
      id: 'e2e-low-link',
      input: 'https://www.bca.co.id/id/informasi',
      riskScore: 0,
      riskLevel: 'low',
      createdAt: '2026-10-21T08:10:00.000Z',
    }),
  ]
}

async function scanLink(page, value) {
  await page.goto(`${baseUrl}/periksa?mode=link`, { waitUntil: 'networkidle' })
  await page.getByLabel('Tautan yang diperiksa').fill(value)
  await page.getByRole('button', { name: 'Periksa tautan' }).click()
  await page.waitForURL(/\/hasil\/[0-9a-f-]+$/, { timeout: 10000 })
  check(await waitForHeading(page, 'Hasil pemeriksaan'), 'hasil tautan tidak terbuka')
}

async function scanMessage(page, value, { keepFull = false } = {}) {
  await page.goto(`${baseUrl}/periksa?mode=message`, { waitUntil: 'networkidle' })
  const keepFullInput = page.getByRole('checkbox', {
    name: 'Simpan isi pesan lengkap di riwayat',
  })
  if (keepFull) {
    await keepFullInput.check()
  } else if (await keepFullInput.isChecked()) {
    await keepFullInput.uncheck()
  }
  await page.getByLabel('Isi pesan', { exact: true }).fill(value)
  await page.getByRole('button', { name: 'Periksa pesan' }).click()
  await page.waitForURL(/\/hasil\/[0-9a-f-]+$/, { timeout: 10000 })
  check(await waitForHeading(page, 'Hasil pemeriksaan'), 'hasil pesan tidak terbuka')
}

async function axeSeriousViolations(page) {
  await page.addScriptTag({ path: axePath })
  const violations = await page.evaluate(async () => {
    const result = await window.axe.run(document, {
      runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] },
    })
    return result.violations
      .filter((violation) => ['serious', 'critical'].includes(violation.impact))
      .map((violation) => ({
        id: violation.id,
        impact: violation.impact,
        nodes: violation.nodes.length,
        targets: violation.nodes.map((node) => node.target.join(' ')),
      }))
  })

  check(
    violations.length === 0,
    `pelanggaran axe serius/kritis: ${violations
      .map((violation) => `${violation.id} (${violation.nodes}): ${violation.targets.join(' | ')}`)
      .join(', ')}`,
  )
}

async function checkNoHorizontalOverflow(page, label) {
  const dimensions = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
  }))
  check(
    dimensions.scrollWidth <= dimensions.clientWidth + 1,
    `${label}: overflow horizontal (${dimensions.scrollWidth} > ${dimensions.clientWidth})`,
  )
}

async function run() {
  await rm(outputDir, { recursive: true, force: true })
  await mkdir(outputDir, { recursive: true })
  await buildForTests(buildDir)

  const server = startPreview(buildDir)
  const browser = await chromium.launch()

  try {
    await waitForServer(baseUrl)

    {
      scenario('A11y rute inti (desktop)')
      const { context, page, errors } = await createPage(browser)
      const routes = [
        '/',
        '/periksa?mode=link',
        '/periksa?mode=message',
        '/komunitas',
        '/riwayat',
        '/edukasi',
        '/edukasi/mengenali-phishing',
        '/masuk',
        '/daftar',
        '/verifikasi-email',
        '/dashboard',
        '/pengaturan',
        '/hasil/tidak-ada',
        '/tidak-ada',
      ]

      check(
        (await page.goto(`${baseUrl}/`, { waitUntil: 'networkidle' }))?.status() === 200,
        'beranda tidak mengembalikan HTTP 200',
      )
      check((await page.locator('html').getAttribute('lang')) === 'id', 'atribut lang bukan id')
      check((await page.locator('main').count()) === 1, 'landmark main tidak tunggal')
      check((await page.locator('h1').count()) === 1, 'h1 tidak tunggal di beranda')

      for (const route of routes) {
        const response = await page.goto(`${baseUrl}${route}`, { waitUntil: 'networkidle' })
        check(response?.status() === 200, `${route}: HTTP ${response?.status()}`)
        check((await page.locator('h1').count()) === 1, `${route}: h1 tidak tunggal`)
        check((await page.locator('main').count()) === 1, `${route}: landmark main tidak tunggal`)
        await axeSeriousViolations(page)
      }

      check(errors.length === 0, `error runtime: ${errors.join(' | ')}`)
      await context.close()
    }

    {
      scenario('Navigasi keyboard, skip link, dan fokus menu seluler')
      const desktop = await createPage(browser)
      await desktop.page.goto(`${baseUrl}/`, { waitUntil: 'networkidle' })
      await desktop.page.keyboard.press('Tab')
      const skipLinkFocused = await desktop.page.evaluate(() =>
        document.activeElement?.textContent?.includes('Lewati ke konten utama'),
      )
      check(skipLinkFocused, 'Tab pertama tidak memfokuskan tautan lewati')
      check(
        await desktop.page.getByRole('link', { name: 'Lewati ke konten utama' }).isVisible(),
        'tautan lewati tidak terlihat saat fokus',
      )

      await desktop.page.keyboard.press('Enter')
      await desktop.page.waitForURL('**/#konten')
      check(
        (await desktop.page.evaluate(() => document.activeElement?.id)) === 'konten',
        'fokus tidak berpindah ke konten utama setelah tautan lewati',
      )
      check(desktop.errors.length === 0, `error desktop: ${desktop.errors.join(' | ')}`)
      await desktop.context.close()

      const mobile = await createPage(browser, { width: 390, height: 844 })
      await mobile.page.goto(`${baseUrl}/`, { waitUntil: 'networkidle' })
      const menuButton = mobile.page.getByRole('button', { name: 'Buka menu' })
      await menuButton.focus()
      await mobile.page.keyboard.press('Enter')
      check(
        (await mobile.page.locator('#menu-seluler').getAttribute('id')) === 'menu-seluler',
        'panel menu seluler tidak memiliki id yang dikontrol',
      )
      await mobile.page.waitForFunction(
        () => document.activeElement?.textContent?.trim() === 'Periksa',
        undefined,
        { timeout: 3000 },
      )
      check(
        (await mobile.page.evaluate(() => document.activeElement?.textContent?.trim())) ===
          'Periksa',
        'fokus tidak berpindah ke tautan pertama menu seluler',
      )

      await mobile.page.keyboard.press('Escape')
      await mobile.page.locator('#menu-seluler').waitFor({ state: 'hidden', timeout: 3000 })
      check(
        (await mobile.page.evaluate(() => document.activeElement?.getAttribute('aria-label'))) ===
          'Buka menu',
        'fokus tidak kembali ke tombol menu setelah Escape',
      )
      check(
        (await menuButton.getAttribute('aria-expanded')) === 'false',
        'aria-expanded menu tidak kembali false',
      )
      check(mobile.errors.length === 0, `error mobile: ${mobile.errors.join(' | ')}`)
      await mobile.context.close()
    }

    {
      scenario('Reduced motion dari preferensi sistem')
      const { context, page, errors } = await createPage(
        browser,
        { width: 1440, height: 900 },
        { reducedMotion: 'reduce' },
      )
      await page.goto(`${baseUrl}/`, { waitUntil: 'networkidle' })
      check(
        await page.evaluate(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches),
        'preferensi sistem reduced motion tidak aktif di browser uji',
      )
      check(
        (await page.evaluate(
          () => getComputedStyle(document.documentElement).scrollBehavior,
        )) === 'auto',
        'scroll behavior tetap smooth saat reduced motion',
      )
      const longestTransition = await page.evaluate(() => {
        const element = document.querySelector('main a, main button')
        if (!element) return 1
        return Math.max(
          ...getComputedStyle(element)
            .transitionDuration.split(',')
            .map((value) => Number.parseFloat(value) || 0),
        )
      })
      check(
        longestTransition <= 0.001,
        `transisi masih terlalu lama saat reduced motion (${longestTransition}s)`,
      )
      check(errors.length === 0, `error runtime: ${errors.join(' | ')}`)
      await context.close()
    }

    {
      scenario('Validasi input tautan dan pesan')
      const { context, page, errors } = await createPage(browser)
      await page.goto(`${baseUrl}/periksa?mode=link`, { waitUntil: 'networkidle' })

      await page.getByRole('button', { name: 'Periksa tautan' }).click()
      await page.getByRole('alert').waitFor({ state: 'visible' })
      check(
        ((await page.getByRole('alert').textContent()) ?? '').includes('Masukkan tautan'),
        'error tautan kosong tidak sesuai',
      )
      check(
        (await page.evaluate(() => document.activeElement?.id)) === 'scan-input',
        'fokus tidak kembali ke input tautan setelah error',
      )
      check(
        (await page.getByLabel('Tautan yang diperiksa').getAttribute('aria-invalid')) === 'true',
        'aria-invalid tidak diset pada tautan yang salah',
      )

      const linkCases = [
        ['bukan tautan', 'tidak boleh mengandung spasi'],
        ['javascript:alert(1)', 'Hanya tautan dengan protokol http atau https'],
        ['http://localhost:3000', 'Alamat lokal atau privat tidak dapat diperiksa'],
        ['https://', 'Format tautan tidak valid'],
      ]

      for (const [value, expected] of linkCases) {
        await page.getByLabel('Tautan yang diperiksa').fill(value)
        await page.getByRole('button', { name: 'Periksa tautan' }).click()
        check(
          ((await page.getByRole('alert').textContent()) ?? '').includes(expected),
          `error untuk "${value}" tidak memuat "${expected}"`,
        )
        check(page.url().includes('/periksa'), `input "${value}" keluar dari halaman periksa`)
      }

      await page.getByRole('button', { name: 'Pesan', exact: true }).click()
      await page.getByLabel('Isi pesan', { exact: true }).waitFor({ state: 'visible' })
      await page.getByRole('button', { name: 'Periksa pesan' }).click()
      await page.getByRole('alert').waitFor({ state: 'visible' })
      check(
        ((await page.getByRole('alert').textContent()) ?? '').includes('Tempel pesan'),
        'error pesan kosong tidak sesuai',
      )

      await page.getByLabel('Isi pesan', { exact: true }).fill('halo')
      await page.getByRole('button', { name: 'Periksa pesan' }).click()
      check(
        ((await page.getByRole('alert').textContent()) ?? '').includes('terlalu pendek'),
        'error pesan terlalu pendek tidak tampil',
      )

      await page.getByLabel('Isi pesan', { exact: true }).fill('1234567890123')
      await page.getByRole('button', { name: 'Periksa pesan' }).click()
      check(
        ((await page.getByRole('alert').textContent()) ?? '').includes('teks yang dapat dibaca'),
        'error pesan tanpa huruf tidak tampil',
      )
      check(errors.length === 0, `error runtime: ${errors.join(' | ')}`)
      await context.close()
    }

    {
      scenario('Scan tautan, hasil, refresh, dan aksesibilitas hasil')
      const { context, page, errors } = await createPage(browser)
      await scanLink(page, 'bca-verifikasi-akun.example/login')
      check(
        await page.getByRole('heading', { name: 'Indikasi risiko tinggi' }).isVisible(),
        'hasil tautan phishing bukan risiko tinggi',
      )
      check(
        await page.getByText('https://bca-verifikasi-akun.example/login').isVisible(),
        'tautan yang diperiksa tidak dinormalkan',
      )
      check(
        await page.getByText(/Bukan probabilitas/).first().isVisible(),
        'catatan skor bukan probabilitas tidak tampil',
      )
      check(
        await page.getByText(/AI generatif belum terhubung/).first().isVisible(),
        'status AI yang jujur tidak tampil',
      )

      const resultUrl = page.url()
      const stored = await page.evaluate((key) => {
        const scans = JSON.parse(localStorage.getItem(key) ?? '[]')
        return { length: scans.length, riskLevel: scans[0]?.riskLevel }
      }, SCAN_KEY)
      check(stored.length === 1, 'hasil tautan tidak tersimpan satu kali')
      check(stored.riskLevel === 'high', 'risiko tinggi tidak tersimpan')

      await page.reload({ waitUntil: 'networkidle' })
      check(page.url() === resultUrl, 'URL hasil berubah setelah refresh')
      check(await waitForHeading(page, 'Hasil pemeriksaan'), 'hasil hilang setelah refresh')
      await axeSeriousViolations(page)
      await page.screenshot({
        path: path.join(outputDir, 'desktop-hasil-qa.png'),
        fullPage: true,
      })
      check(errors.length === 0, `error runtime: ${errors.join(' | ')}`)
      await context.close()
    }

    {
      scenario('Privasi redaksi pesan dan izin penyimpanan lengkap')
      const { context, page, errors } = await createPage(browser)
      await scanMessage(
        page,
        'Selamat! Kode OTP 778899 untuk akun Anda. Hubungi 0812-3456-7890 atau buka https://evil.example/klaim sekarang.',
      )
      check(
        await page.getByText('Isi pesan disamarkan sebelum disimpan', { exact: true }).isVisible(),
        'pemberitahuan redaksi tidak tampil di hasil',
      )

      const redacted = await page.evaluate((key) => {
        const scans = JSON.parse(localStorage.getItem(key) ?? '[]')
        return scans[0]
      }, SCAN_KEY)
      check(redacted?.meta?.inputStored === 'redacted', 'status redaksi tidak tersimpan')
      check(!redacted?.input.includes('778899'), 'kode OTP masih tersimpan')
      check(!redacted?.input.includes('0812-3456-7890'), 'nomor telepon masih tersimpan')
      check(!redacted?.input.includes('evil.example'), 'tautan masih tersimpan')
      check(
        redacted?.input.includes('[angka]') &&
          redacted?.input.includes('[nomor]') &&
          redacted?.input.includes('[tautan]'),
        'penanda redaksi tidak lengkap',
      )
      await axeSeriousViolations(page)
      await page.screenshot({
        path: path.join(outputDir, 'desktop-hasil-redaksi-qa.png'),
        fullPage: true,
      })

      await scanMessage(
        page,
        'Kode verifikasi 554433 jangan dibagikan kepada siapa pun. Ini pesan uji.',
        { keepFull: true },
      )
      const full = await page.evaluate((key) => {
        const scans = JSON.parse(localStorage.getItem(key) ?? '[]')
        return scans[0]
      }, SCAN_KEY)
      check(full?.meta?.inputStored === 'full', 'izin simpan lengkap tidak tersimpan')
      check(full?.input.includes('554433'), 'isi lengkap tidak tersimpan setelah izin')
      check(errors.length === 0, `error runtime: ${errors.join(' | ')}`)
      await context.close()
    }

    {
      scenario('Privasi URL sensitif disamarkan sebelum disimpan di riwayat')
      const token = 'abcd1234efgh5678ijkl9012mnop3456'
      const { context, page, errors } = await createPage(browser)
      await scanLink(page, `https://contohlampiran.example/reset/${token}?kunci=rahasia123`)

      check(
        await page
          .getByText('Sebagian alamat disamarkan sebelum disimpan', { exact: true })
          .isVisible(),
        'pemberitahuan disamarkannya alamat tidak tampil di hasil',
      )

      const storedRaw = await page.evaluate((key) => localStorage.getItem(key) ?? '', SCAN_KEY)
      const stored = JSON.parse(storedRaw)
      check(stored?.[0]?.meta?.inputStored === 'redacted', 'status samar alamat tidak tersimpan')
      check(
        stored?.[0]?.input === 'https://contohlampiran.example/reset/[dirahasiakan]',
        `alamat yang tersimpan bukan hasil penyamaran: ${stored?.[0]?.input}`,
      )
      check(!storedRaw.includes(token), 'token pada jalur masih tersimpan di localStorage')
      check(!storedRaw.includes('rahasia123'), 'parameter sensitif masih tersimpan')
      check(errors.length === 0, `error runtime: ${errors.join(' | ')}`)
      await context.close()
    }

    {
      scenario('Keamanan render XSS pada input pesan')
      const { context, page, errors } = await createPage(browser)
      let dialogOpened = false
      page.on('dialog', async (dialog) => {
        dialogOpened = true
        await dialog.dismiss()
      })

      await scanMessage(
        page,
        '<img src=x onerror="window.__veriguardXss=1"> Kode OTP 998877 https://evil.example/login',
      )
      await page.waitForTimeout(300)
      check(
        (await page.evaluate(() => window.__veriguardXss)) === undefined,
        'payload onerror tereksekusi',
      )
      check(!dialogOpened, 'dialog tidak terduga muncul dari input pengguna')
      check(
        (await page.locator('main img[src="x"]').count()) === 0,
        'payload HTML dirender sebagai elemen',
      )
      check(
        ((await page.locator('blockquote').textContent()) ?? '').includes('<img src=x'),
        'payload tidak ditampilkan sebagai teks literal',
      )
      check(errors.length === 0, `error runtime: ${errors.join(' | ')}`)
      await context.close()
    }

    {
      scenario('Riwayat, filter, formula CSV, hapus, dan aksesibilitas')
      const { context, page, errors } = await createPage(browser)
      await scanLink(page, 'bca-verifikasi-akun.example/login')
      await scanLink(page, 'https://www.bca.co.id/id/informasi')
      await scanMessage(
        page,
        'Kode OTP 778899 untuk akun Anda, jangan dibagikan kepada siapa pun.',
      )

      await page.goto(`${baseUrl}/riwayat`, { waitUntil: 'networkidle' })
      const historyList = page.getByRole('list', { name: 'Daftar riwayat pemeriksaan' })
      check(
        (await historyList.getByRole('listitem').count()) === 3,
        'riwayat tidak memuat tiga pemeriksaan',
      )

      const search = page.getByLabel('Cari riwayat')
      await search.fill('bca-verifikasi-akun')
      check(
        (await historyList.getByRole('listitem').count()) === 1,
        'pencarian riwayat tidak menyaring',
      )
      await page.getByRole('button', { name: 'Hapus filter pencarian' }).click()

      const typeFilter = page.getByRole('group', { name: 'Filter jenis pemeriksaan' })
      await typeFilter.getByRole('button', { name: 'Pesan', exact: true }).click()
      check(
        (await historyList.getByRole('listitem').count()) === 1,
        'filter jenis pesan tidak menyaring',
      )
      await page.getByRole('button', { name: 'Reset filter' }).first().click()

      const riskFilter = page.getByRole('group', { name: 'Filter tingkat risiko' })
      await riskFilter.getByRole('button', { name: 'Tinggi', exact: true }).click()
      check(
        (await historyList.getByRole('listitem').count()) === 1,
        'filter risiko tinggi tidak menyaring',
      )
      await page.getByRole('button', { name: 'Reset filter' }).first().click()

      const sortGroup = page.getByRole('group', { name: 'Urutan riwayat' })
      await sortGroup.getByRole('button', { name: 'Terlama', exact: true }).click()
      check(
        ((await historyList.getByRole('link').first().textContent()) ?? '').includes(
          'bca-verifikasi-akun.example',
        ),
        'urutan terlama tidak menempatkan pemeriksaan pertama di atas',
      )
      await sortGroup.getByRole('button', { name: 'Terbaru', exact: true }).click()

      await page.evaluate((key) => {
        const scans = JSON.parse(localStorage.getItem(key) ?? '[]')
        scans[0].input = '=HYPERLINK("https://evil.example","klik")'
        scans[0].displayTarget = '=1+1'
        scans[0].summary = '+cmd|/c calc'
        localStorage.setItem(key, JSON.stringify(scans))
      }, SCAN_KEY)
      await page.reload({ waitUntil: 'networkidle' })
      await axeSeriousViolations(page)

      const [download] = await Promise.all([
        page.waitForEvent('download'),
        page.getByRole('button', { name: 'Ekspor CSV' }).click(),
      ])
      const csv = await readFile(await download.path(), 'utf8')
      check(csv.startsWith('\uFEFF'), 'CSV tidak memakai BOM UTF-8')
      check(csv.includes(`"'=HYPERLINK`), 'formula = pada input tidak dinetralkan')
      check(csv.includes(`"'+cmd`), 'formula + pada ringkasan tidak dinetralkan')
      check(!csv.includes(`,"=HYPERLINK`), 'sel formula masih dapat dieksekusi')
      check(
        /^veriguard-riwayat-\d{4}-\d{2}-\d{2}\.csv$/.test(download.suggestedFilename()),
        'nama berkas CSV tidak sesuai',
      )
      await page.screenshot({
        path: path.join(outputDir, 'desktop-riwayat-qa.png'),
        fullPage: true,
      })

      await page.getByRole('button', { name: /Hapus pemeriksaan/ }).first().click()
      check(
        (await historyList.getByRole('listitem').count()) === 2,
        'hapus satu pemeriksaan tidak memperbarui daftar',
      )
      page.once('dialog', (dialog) => {
        void dialog.accept()
      })
      await page.getByRole('button', { name: 'Hapus semua' }).click()
      await page.getByText('Belum ada riwayat', { exact: true }).waitFor({ timeout: 3000 })
      check(
        (await page.evaluate((key) => localStorage.getItem(key), SCAN_KEY)) === null,
        'hapus semua tidak membersihkan localStorage',
      )
      check(errors.length === 0, `error runtime: ${errors.join(' | ')}`)
      await context.close()
    }

    {
      scenario('Pengaturan, sesi demo, dashboard, dan pembersihan data')
      const { context, page, errors } = await createPage(browser)
      await page.goto(`${baseUrl}/dashboard`, { waitUntil: 'networkidle' })
      check(
        await page.getByRole('heading', { name: 'Dashboard memerlukan sesi' }).isVisible(),
        'dashboard tanpa sesi tidak menampilkan gate',
      )
      const guestHeader = page.locator('header').first()
      check(
        await guestHeader.getByRole('link', { name: 'Masuk', exact: true }).isVisible(),
        'header tamu tidak menampilkan Masuk',
      )
      check(
        (await guestHeader.getByRole('link', { name: 'Daftar', exact: true }).count()) === 0,
        'header tamu masih menampilkan Daftar (VGL-36: navbar hanya Masuk)',
      )

      await page.goto(`${baseUrl}/daftar`, { waitUntil: 'networkidle' })
      check(
        await page.getByRole('heading', { name: 'Buat akun VERIGUARD AI' }).isVisible(),
        'rute /daftar ikut hilang bersama tombol navbar',
      )

      await page.goto(`${baseUrl}/masuk`, { waitUntil: 'networkidle' })
      check(
        await page.getByText('Autentikasi sungguhan belum aktif', { exact: true }).isVisible(),
        'peringatan autentikasi tidak tampil',
      )
      await page.getByLabel('Nama tampilan (opsional)').fill('Penguji QA')
      await page.getByRole('button', { name: 'Mulai sesi demo lokal' }).click()
      await page.waitForURL('**/dashboard')
      check(
        await waitForHeading(page, 'Ringkasan aktivitas'),
        'dashboard tidak terbuka setelah sesi demo',
      )
      check(
        await page.getByText('Belum ada pemeriksaan tersimpan', { exact: true }).isVisible(),
        'state kosong dashboard tidak tampil',
      )
      check(
        await page
          .getByRole('navigation', { name: 'Bagian dashboard' })
          .getByRole('link', { name: 'Dashboard Saya' })
          .isVisible(),
        'tab Dashboard Saya tidak tampil',
      )
      check(
        (await page
          .getByRole('navigation', { name: 'Bagian dashboard' })
          .getByRole('link', { name: 'Dashboard Admin' })
          .count()) === 0,
        'tab Dashboard Admin tampil untuk sesi demo non-admin',
      )

      await page.goto(`${baseUrl}/dashboard/admin`, { waitUntil: 'networkidle' })
      check(
        await page
          .getByRole('heading', { name: 'Akses Dashboard Admin diperlukan' })
          .isVisible(),
        'akses langsung dashboard admin tidak ditolak untuk sesi demo',
      )
      check(
        await page
          .getByText('Sesi demo lokal bukan autentikasi sungguhan', { exact: false })
          .isVisible(),
        'alasan penolakan akses admin sesi demo tidak tampil',
      )
      await page.goto(`${baseUrl}/dashboard`, { waitUntil: 'networkidle' })

      const desktopHeader = page.locator('header').first()
      check(
        (await desktopHeader.getByRole('link', { name: 'Masuk', exact: true }).count()) === 0,
        'header desktop masih menampilkan Masuk setelah login',
      )
      check(
        (await desktopHeader.getByRole('link', { name: 'Daftar', exact: true }).count()) === 0,
        'header desktop masih menampilkan Daftar setelah login',
      )
      const accountMenuButton = desktopHeader.getByRole('button', {
        name: 'Penguji QA',
        exact: true,
      })
      check(await accountMenuButton.isVisible(), 'menu akun tidak tampil setelah login')
      const themeSwitchAfterLogin = desktopHeader.getByRole('radiogroup', { name: 'Tema tampilan' })
      check(await themeSwitchAfterLogin.isVisible(), 'sakelar tema hilang setelah login')
      check(
        await themeSwitchAfterLogin.evaluate((el) =>
          Boolean(
            el.compareDocumentPosition(
              document.querySelector('header [aria-haspopup="menu"]'),
            ) & Node.DOCUMENT_POSITION_FOLLOWING,
          ),
        ),
        'sakelar tema tidak lagi berada di kiri info akun',
      )
      await accountMenuButton.click()
      const accountMenu = page.getByRole('menu', { name: 'Menu akun' })
      check(await accountMenu.isVisible(), 'panel menu akun tidak terbuka')
      check(
        await accountMenu.getByRole('menuitem', { name: 'Dashboard' }).isVisible(),
        'menu akun tidak memuat Dashboard',
      )
      check(
        await accountMenu.getByRole('menuitem', { name: 'Pengaturan' }).isVisible(),
        'menu akun tidak memuat Pengaturan',
      )
      check(
        await accountMenu.getByRole('menuitem', { name: 'Keluar' }).isVisible(),
        'menu akun tidak memuat Keluar',
      )
      await page.keyboard.press('Escape')
      check(
        (await accountMenuButton.getAttribute('aria-expanded')) === 'false',
        'Escape tidak menutup menu akun',
      )

      await page.goto(`${baseUrl}/pengaturan`, { waitUntil: 'networkidle' })
      const modeGroup = page.getByRole('group', { name: 'Jenis pemeriksaan default' })
      await modeGroup.getByRole('button', { name: 'Pesan', exact: true }).click()
      const reduceMotion = page.getByRole('checkbox', { name: 'Kurangi gerakan antarmuka' })
      await reduceMotion.check()
      check(
        (await page.evaluate(() => document.documentElement.dataset.reduceMotion)) === 'true',
        'preferensi kurangi gerakan tidak diterapkan',
      )
      await page.reload({ waitUntil: 'networkidle' })
      check(
        (await modeGroup.getByRole('button', { name: 'Pesan', exact: true }).getAttribute(
          'aria-pressed',
        )) === 'true',
        'preferensi mode pesan tidak bertahan setelah refresh',
      )
      check(await reduceMotion.isChecked(), 'preferensi kurangi gerakan tidak bertahan')
      check(
        (await page.evaluate(() => document.documentElement.dataset.reduceMotion)) === 'true',
        'atribut kurangi gerakan hilang setelah refresh',
      )

      await page.goto(`${baseUrl}/periksa`, { waitUntil: 'networkidle' })
      check(
        (await page
          .getByRole('button', { name: 'Pesan', exact: true })
          .getAttribute('aria-pressed')) === 'true',
        'mode default dari pengaturan tidak dipakai',
      )
      check(
        await page.getByLabel('Isi pesan', { exact: true }).isVisible(),
        'form pesan tidak tampil dari preferensi default',
      )

      await page.goto(`${baseUrl}/pengaturan`, { waitUntil: 'networkidle' })
      await page.getByRole('button', { name: 'Kembalikan preferensi awal' }).click()
      check(
        (await page.evaluate(() => document.documentElement.dataset.reduceMotion)) === undefined,
        'reset preferensi tidak menghapus atribut gerakan',
      )

      await page.evaluate(
        ({ key, scans }) => localStorage.setItem(key, JSON.stringify(scans)),
        { key: SCAN_KEY, scans: dashboardFixtures() },
      )
      await page.goto(`${baseUrl}/dashboard`, { waitUntil: 'networkidle' })
      check(
        await page
          .getByText('Statistik dari 3 pemeriksaan yang tersimpan di browser ini.', {
            exact: true,
          })
          .isVisible(),
        'dashboard tidak menampilkan statistik tiga pemeriksaan',
      )
      check(
        await page
          .getByRole('img', { name: 'Risiko tinggi: 2 dari 3 pemeriksaan (67%)' })
          .isVisible(),
        'distribusi risiko dashboard tidak sesuai',
      )
      check(
        (await page
          .getByRole('list', { name: 'Riwayat pemeriksaan terbaru' })
          .getByRole('listitem')
          .count()) === 3,
        'riwayat terbaru dashboard tidak memuat tiga item',
      )
      check(
        await page.getByText('Sesi demo aktif: Penguji QA', { exact: true }).isVisible(),
        'label sesi demo dashboard tidak tampil',
      )
      await axeSeriousViolations(page)
      await page.screenshot({
        path: path.join(outputDir, 'desktop-dashboard-qa.png'),
        fullPage: true,
      })

      await page.goto(`${baseUrl}/pengaturan`, { waitUntil: 'networkidle' })
      await axeSeriousViolations(page)
      const redactButton = page.getByRole('button', { name: 'Samarkan semua isi pesan' })
      check(await redactButton.isEnabled(), 'kontrol redaksi tidak aktif untuk pesan penuh')
      page.once('dialog', (dialog) => {
        void dialog.accept()
      })
      await redactButton.click()
      await page
        .getByRole('status')
        .filter({ hasText: 'isi pesan disamarkan' })
        .waitFor({ timeout: 3000 })
      const redactedScans = await page.evaluate((key) => {
        return JSON.parse(localStorage.getItem(key) ?? '[]')
      }, SCAN_KEY)
      check(
        redactedScans
          .filter((scan) => scan.mode === 'message')
          .every((scan) => scan.meta.inputStored === 'redacted'),
        'isi pesan penuh belum seluruhnya disamarkan',
      )
      check(
        !redactedScans.some((scan) => scan.input.includes('778899')),
        'kode pesan masih tersimpan setelah redaksi',
      )
      check(await redactButton.isDisabled(), 'tombol redaksi tetap aktif tanpa pesan penuh')

      const [settingsDownload] = await Promise.all([
        page.waitForEvent('download'),
        page.getByRole('button', { name: 'Ekspor CSV' }).click(),
      ])
      const settingsCsv = await readFile(await settingsDownload.path(), 'utf8')
      check(
        settingsCsv.startsWith('\uFEFF') && settingsCsv.includes('"Isi pesan disamarkan"'),
        'CSV pengaturan tidak memakai format yang benar',
      )
      check(!settingsCsv.includes('778899'), 'CSV pengaturan masih memuat kode pesan')
      await page.screenshot({
        path: path.join(outputDir, 'desktop-pengaturan-qa.png'),
        fullPage: true,
      })

      page.once('dialog', (dialog) => {
        void dialog.accept()
      })
      await page.getByRole('button', { name: 'Hapus semua data lokal' }).click()
      await page
        .getByText('Semua data aplikasi di browser ini dihapus. Preferensi kembali ke pengaturan awal.', {
          exact: true,
        })
        .waitFor({ timeout: 3000 })
      const remainingKeys = await page.evaluate(
        ({ scanKey, sessionKey, preferenceKey, pendingKey }) => ({
          scans: localStorage.getItem(scanKey),
          session: localStorage.getItem(sessionKey),
          preferences: localStorage.getItem(preferenceKey),
          pending: localStorage.getItem(pendingKey),
        }),
        {
          scanKey: SCAN_KEY,
          sessionKey: SESSION_KEY,
          preferenceKey: PREFERENCES_KEY,
          pendingKey: PENDING_SYNC_KEY,
        },
      )
      check(
        remainingKeys.scans === null &&
          remainingKeys.session === null &&
          remainingKeys.preferences === null &&
          remainingKeys.pending === null,
        'hapus semua data lokal tidak membersihkan seluruh key',
      )
      await page.goto(`${baseUrl}/dashboard`, { waitUntil: 'networkidle' })
      check(
        await page.getByRole('heading', { name: 'Dashboard memerlukan sesi' }).isVisible(),
        'dashboard tetap terbuka setelah data lokal dihapus',
      )
      const loggedOutHeader = page.locator('header').first()
      check(
        await loggedOutHeader.getByRole('link', { name: 'Masuk', exact: true }).isVisible(),
        'header tidak menampilkan Masuk setelah logout',
      )
      check(
        (await loggedOutHeader.getByRole('button', { name: 'Penguji QA', exact: true }).count()) === 0,
        'menu akun masih tampil setelah logout',
      )

      await page.goto(`${baseUrl}/verifikasi-email`, { waitUntil: 'networkidle' })
      check(
        await page.getByRole('heading', { name: 'Verifikasi email', exact: true }).isVisible(),
        'halaman verifikasi email tidak dapat dibuka',
      )
      check(
        await page.getByText('Verifikasi email belum tersedia', { exact: true }).isVisible(),
        'status verifikasi demo tidak dijelaskan',
      )
      await axeSeriousViolations(page)
      check(errors.length === 0, `error runtime: ${errors.join(' | ')}`)
      await context.close()
    }

    {
      scenario('Pemulihan dari data lokal rusak')
      const { context, page, errors } = await createPage(browser)
      await setLocalState(page, {
        scansRaw: '{bukan json',
        session: {
          kind: 'local-demo',
          displayName: 'Penguji Rusak',
          startedAt: '2026-10-21T08:00:00.000Z',
        },
        preferencesRaw: '{bukan json',
      })

      await page.goto(`${baseUrl}/riwayat`, { waitUntil: 'networkidle' })
      check(
        await page.getByText('Belum ada riwayat', { exact: true }).isVisible(),
        'riwayat tidak menampilkan state kosong untuk JSON rusak',
      )

      await page.goto(`${baseUrl}/dashboard`, { waitUntil: 'networkidle' })
      check(
        await page.getByText('Belum ada pemeriksaan tersimpan', { exact: true }).isVisible(),
        'dashboard tidak fallback ke state kosong untuk data rusak',
      )

      await page.goto(`${baseUrl}/pengaturan`, { waitUntil: 'networkidle' })
      check(
        (await page
          .getByRole('group', { name: 'Jenis pemeriksaan default' })
          .getByRole('button', { name: 'Tautan', exact: true })
          .getAttribute('aria-pressed')) === 'true',
        'preferensi rusak tidak kembali ke default',
      )

      const valid = dashboardFixtures()[2]
      const broken = {
        ...valid,
        id: 'e2e-broken-nested',
        reasons: [{ id: 'hanya-id' }],
      }
      await page.evaluate(
        ({ key, scans }) => localStorage.setItem(key, JSON.stringify(scans)),
        { key: SCAN_KEY, scans: [broken, valid] },
      )
      await page.goto(`${baseUrl}/riwayat`, { waitUntil: 'networkidle' })
      check(
        (await page
          .getByRole('list', { name: 'Daftar riwayat pemeriksaan' })
          .getByRole('listitem')
          .count()) === 1,
        'pemeriksaan dengan data bersarang rusak tidak disaring',
      )

      await page.evaluate(
        ({ key, raw }) => localStorage.setItem(key, raw),
        { key: SESSION_KEY, raw: '{bukan json' },
      )
      await page.goto(`${baseUrl}/dashboard`, { waitUntil: 'networkidle' })
      check(
        await page.getByRole('heading', { name: 'Dashboard memerlukan sesi' }).isVisible(),
        'sesi rusak tidak kembali ke gate',
      )
      check(errors.length === 0, `error runtime: ${errors.join(' | ')}`)
      await context.close()
    }

    {
      scenario('Fallback saat localStorage diblokir')
      const { context, page, errors } = await createPage(browser)
      await context.addInitScript(() => {
        const blocked = () => {
          throw new DOMException('Penyimpanan diblokir untuk pengujian.', 'SecurityError')
        }
        Storage.prototype.setItem = blocked
        Storage.prototype.removeItem = blocked
      })

      await scanLink(page, 'bca-verifikasi-akun.example/login')
      check(
        await page.getByRole('heading', { name: 'Indikasi risiko tinggi' }).isVisible(),
        'pemeriksaan gagal saat localStorage diblokir',
      )
      check(errors.length === 0, `error runtime: ${errors.join(' | ')}`)
      await context.close()
    }

    {
      scenario('Artikel edukasi dan state tidak ditemukan')
      const { context, page, errors } = await createPage(browser)
      await page.goto(`${baseUrl}/edukasi`, { waitUntil: 'networkidle' })
      check(
        (await page.getByRole('link', { name: 'Baca artikel' }).count()) === 8,
        'daftar edukasi tidak menampilkan delapan artikel',
      )
      await page.getByRole('link', { name: /OTP dan verifikasi dua langkah/ }).first().click()
      await page.waitForURL('**/edukasi/otp-dan-verifikasi-dua-langkah')
      check(
        await waitForHeading(page, 'OTP dan verifikasi dua langkah'),
        'artikel OTP tidak terbuka',
      )
      check(
        await page.getByRole('navigation', { name: 'Breadcrumb' }).isVisible(),
        'breadcrumb artikel tidak tampil',
      )

      await page.goto(`${baseUrl}/edukasi/slug-tidak-ada`, { waitUntil: 'networkidle' })
      check(
        await page.getByRole('heading', { name: 'Artikel tidak ditemukan' }).isVisible(),
        'state artikel tidak ditemukan tidak tampil',
      )
      check(errors.length === 0, `error runtime: ${errors.join(' | ')}`)
      await context.close()
    }

    {
      scenario('Community Reports: akses, gate sesi, dan validasi')
      const { context, page, errors } = await createPage(browser)

      await page.goto(`${baseUrl}/`, { waitUntil: 'networkidle' })
      await page
        .getByRole('navigation', { name: 'Navigasi utama' })
        .getByRole('link', { name: 'Komunitas' })
        .click()
      await page.waitForURL('**/komunitas')
      check(
        await waitForHeading(page, 'Community Reports'),
        'navigasi Komunitas tidak membuka halaman laporan',
      )
      check(
        await page.getByText('Layanan akun belum tersedia', { exact: true }).isVisible(),
        'status layanan akun yang belum tersedia tidak tampil',
      )
      check(
        await page.getByLabel('URL yang dilaporkan').isVisible(),
        'form URL Community Reports tidak tampil',
      )
      check(
        await page.getByLabel('Kategori').isVisible(),
        'pilihan kategori Community Reports tidak tampil',
      )
      check(
        await page.getByLabel('Alasan singkat').isVisible(),
        'textarea alasan Community Reports tidak tampil',
      )
      check(
        await page.getByText('Daftar laporan belum dimuat', { exact: true }).isVisible(),
        'daftar komunitas tanpa sesi akun yang sah tidak diberi status tersendiri',
      )
      check(
        !(await page
          .getByText('Tidak ada laporan untuk hari ini', { exact: true })
          .isVisible()),
        'daftar yang belum dimuat dibaca sebagai tidak ada laporan',
      )
      check(
        (await page.getByText('Setiap akun dapat mengirim satu laporan per hari').count()) > 0,
        'ketentuan satu laporan per akun per hari tidak ditampilkan',
      )

      await page.getByLabel('URL yang dilaporkan').fill('contoh.com/laporan')
      await page.getByLabel('Kategori').selectOption('phishing')
      await page
        .getByLabel('Alasan singkat')
        .fill('Halaman ini meminta kata sandi melalui formulir yang meniru situs resmi.')
      await page.getByRole('button', { name: 'Masuk untuk mengirim' }).click()
      check(
        await page
          .getByText('Sesi demo lokal tidak dapat mengirim laporan', { exact: false })
          .isVisible(),
        'pengiriman laporan dari sesi demo tidak diblokir dengan jelas',
      )
      await page.screenshot({
        path: path.join(outputDir, 'desktop-community-reports.png'),
        fullPage: true,
      })
      check(errors.length === 0, `error runtime: ${errors.join(' | ')}`)
      await context.close()
    }

    {
      scenario('Viewport mobile: scan, hasil, dan overflow')
      const { context, page, errors } = await createPage(browser, { width: 390, height: 844 })
      await page.goto(`${baseUrl}/`, { waitUntil: 'networkidle' })
      await checkNoHorizontalOverflow(page, 'beranda mobile')
      check(
        await page.getByRole('button', { name: 'Buka menu' }).isVisible(),
        'tombol menu seluler tidak tampil',
      )

      await page.goto(`${baseUrl}/komunitas`, { waitUntil: 'networkidle' })
      await checkNoHorizontalOverflow(page, 'Community Reports mobile')
      check(
        await page.getByLabel('URL yang dilaporkan').isVisible(),
        'form Community Reports tidak tampil di mobile',
      )

      await scanLink(page, 'bca-verifikasi-akun.example/login')
      await checkNoHorizontalOverflow(page, 'hasil mobile')
      check(
        await page.getByRole('heading', { name: 'Indikasi risiko tinggi' }).isVisible(),
        'hasil risiko tinggi tidak tampil di mobile',
      )
      check(
        await page.getByLabel('Tautan yang diperiksa').count() === 0,
        'halaman hasil mobile masih memuat form pemeriksaan',
      )
      await page.screenshot({
        path: path.join(outputDir, 'mobile-hasil-qa.png'),
        fullPage: true,
      })

      await page.goto(`${baseUrl}/masuk`, { waitUntil: 'networkidle' })
      await page.getByLabel('Nama tampilan (opsional)').fill('Penguji Mobile')
      await page.getByRole('button', { name: 'Mulai sesi demo lokal' }).click()
      await page.waitForURL('**/dashboard')
      await page.getByRole('button', { name: 'Buka menu' }).click()
      const mobileMenu = page.locator('#menu-seluler')
      check(await mobileMenu.isVisible(), 'menu seluler tidak terbuka setelah login')
      check(
        (await mobileMenu.getByRole('link', { name: 'Masuk', exact: true }).count()) === 0,
        'menu seluler masih menampilkan Masuk setelah login',
      )
      check(
        (await mobileMenu.getByRole('link', { name: 'Daftar', exact: true }).count()) === 0,
        'menu seluler masih menampilkan Daftar setelah login',
      )
      check(
        await mobileMenu.getByText('Penguji Mobile', { exact: true }).isVisible(),
        'nama akun tidak tampil di menu seluler',
      )
      check(
        await mobileMenu.getByRole('link', { name: 'Pengaturan', exact: true }).isVisible(),
        'link Pengaturan tidak tampil di menu akun seluler',
      )
      check(
        await mobileMenu.getByRole('button', { name: 'Keluar', exact: true }).isVisible(),
        'tombol Keluar tidak tampil di menu akun seluler',
      )
      await checkNoHorizontalOverflow(page, 'menu akun mobile')
      await page.keyboard.press('Escape')

      check(errors.length === 0, `error runtime: ${errors.join(' | ')}`)
      await context.close()
    }

    scenario('Keamanan jaringan klien')
    check(
      externalRequests.size === 0,
      `aplikasi meminta sumber eksternal: ${[...externalRequests].join(', ')}`,
    )
  } finally {
    await browser.close()
    server.kill()
  }

  if (failures.length > 0) {
    console.error(`\nGAGAL - ${failures.length} dari ${checks} pemeriksaan E2E tidak lolos:`)
    for (const failure of failures) console.error(` - ${failure}`)
    process.exitCode = 1
  } else {
    console.log(`\nLULUS - ${checks} pemeriksaan E2E QA.`)
    console.log(`Screenshot: ${outputDir}`)
  }
}

run().catch((error) => {
  console.error(error)
  process.exitCode = 1
})

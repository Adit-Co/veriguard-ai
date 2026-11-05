import { spawn } from 'node:child_process'
import { mkdir, readFile, rm } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const port = 4173
const baseUrl = `http://127.0.0.1:${port}`
const outputDir = path.join(root, '.verify', 'ui')
const buildDir = path.join(root, '.verify', 'ui-dist')

const routes = [
  { path: '/', heading: 'Think Before You Click.' },
  { path: '/periksa', heading: 'Periksa tautan atau pesan' },
  { path: '/komunitas', heading: 'Community Reports' },
  { path: '/riwayat', heading: 'Riwayat pemeriksaan' },
  { path: '/edukasi', heading: 'Kenali polanya sebelum percaya' },
  {
    path: '/edukasi/mengenali-phishing',
    heading: 'Mengenali phishing sebelum kamu mengeklik',
  },
  {
    path: '/edukasi/otp-dan-verifikasi-dua-langkah',
    heading: 'OTP dan verifikasi dua langkah: siapa yang boleh memintanya',
  },
  {
    path: '/edukasi/kata-sandi-yang-kuat',
    heading: 'Kata sandi yang kuat tidak harus sulit diingat',
  },
  {
    path: '/edukasi/waspada-investasi-dan-lowongan-kerja',
    heading: 'Waspadai tawaran investasi dan kerja yang terlalu menguntungkan',
  },
  {
    path: '/edukasi/jual-beli-online-yang-aman',
    heading: 'Jual beli online dan kurir: kapan harus berhenti',
  },
  {
    path: '/edukasi/melindungi-data-pribadi',
    heading: 'Melindungi data pribadi dan memulihkan akun yang terdampak',
  },
  { path: '/masuk', heading: 'Masuk ke VERIGUARD AI' },
  { path: '/daftar', heading: 'Buat akun VERIGUARD AI' },
  { path: '/verifikasi-email', heading: 'Verifikasi email' },
  { path: '/dashboard', heading: 'Ringkasan aktivitas' },
  { path: '/pengaturan', heading: 'Pengaturan perangkat' },
  { path: '/hasil/contoh', heading: 'Hasil tidak ditemukan' },
  { path: '/tidak-ada', heading: 'Halaman tidak ditemukan' },
]

const viewports = [
  { name: 'mobile', width: 390, height: 844 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'desktop', width: 1440, height: 900 },
]

const screenshotRoutes = new Set([
  '/',
  '/periksa',
  '/komunitas',
  '/edukasi',
  '/edukasi/mengenali-phishing',
  '/masuk',
  '/verifikasi-email',
])
const failures = []
let checks = 0

function check(condition, message) {
  checks += 1
  if (!condition) failures.push(message)
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

  child.stdout.on('data', (chunk) => process.stdout.write(`[preview] ${chunk}`))
  child.stderr.on('data', (chunk) => process.stderr.write(`[preview] ${chunk}`))
  return child
}

async function waitForServer(url, timeoutMs = 30000) {  const started = Date.now()

  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(url)
      if (response.ok) return
    } catch {
      // server not ready yet
    }
    await new Promise((resolve) => setTimeout(resolve, 300))
  }

  throw new Error(`Preview server tidak siap dalam ${timeoutMs} ms`)
}

async function waitForHeading(page, text, timeout = 5000) {
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

async function run() {
  await rm(outputDir, { recursive: true, force: true })
  await mkdir(outputDir, { recursive: true })
  await buildForTests(buildDir)

  const server = startPreview(buildDir)
  const browser = await chromium.launch()

  try {
    await waitForServer(baseUrl)

    for (const viewport of viewports) {
      const context = await browser.newContext({
        viewport: { width: viewport.width, height: viewport.height },
        deviceScaleFactor: 1,
      })
      const page = await context.newPage()
      const runtimeErrors = []

      page.on('pageerror', (error) => runtimeErrors.push(`pageerror: ${error.message}`))
      page.on('console', (message) => {
        if (message.type() === 'error') runtimeErrors.push(`console: ${message.text()}`)
      })

      for (const route of routes) {
        runtimeErrors.length = 0
        const response = await page.goto(`${baseUrl}${route.path}`, { waitUntil: 'networkidle' })
        check(response?.status() === 200, `${viewport.name} ${route.path}: HTTP ${response?.status()}`)

        const heading = (await page.locator('h1').first().textContent())?.trim()
        check(
          heading === route.heading,
          `${viewport.name} ${route.path}: h1 "${heading}" != "${route.heading}"`,
        )

        const overflow = await page.evaluate(() => ({
          scrollWidth: document.documentElement.scrollWidth,
          clientWidth: document.documentElement.clientWidth,
        }))
        check(
          overflow.scrollWidth <= overflow.clientWidth + 1,
          `${viewport.name} ${route.path}: overflow horizontal (${overflow.scrollWidth} > ${overflow.clientWidth})`,
        )

        const fontFamily = await page.evaluate(() => getComputedStyle(document.body).fontFamily)
        check(
          fontFamily.toLowerCase().includes('inter'),
          `${viewport.name} ${route.path}: font tidak memuat Inter (${fontFamily})`,
        )

        check(
          runtimeErrors.length === 0,
          `${viewport.name} ${route.path}: error runtime -> ${runtimeErrors.join(' | ')}`,
        )

        if (viewport.name === 'mobile') {
          const menuButton = page.getByRole('button', { name: 'Buka menu' })
          check(await menuButton.isVisible(), `${route.path}: tombol menu seluler tidak terlihat`)
          check(
            !(await page.getByRole('navigation', { name: 'Navigasi utama' }).isVisible()),
            `${route.path}: navigasi desktop terlihat di mobile`,
          )
        }

        if (screenshotRoutes.has(route.path)) {
          const fileName = `${viewport.name}${route.path === '/' ? '-beranda' : route.path.replaceAll('/', '-')}.png`
          await page.screenshot({ path: path.join(outputDir, fileName), fullPage: true })
        }
      }

      await context.close()
    }

    const desktop = await browser.newContext({ viewport: { width: 1440, height: 900 } })
    const page = await desktop.newPage()

    await page.goto(baseUrl, { waitUntil: 'networkidle' })

    const heroCta = page.locator('main').getByRole('link', { name: 'Mulai periksa' }).first()
    check(
      (await heroCta.getAttribute('href'))?.startsWith('/periksa?mode=link') === true,
      'CTA hero tidak mengarah ke pemeriksaan tautan',
    )

    // VGL-36 — navbar: "Laporkan URL" bukan lagi entry point di header, urutan kontrol kanan
    // wajib (sakelar tema sebelum aksi akun), dan tombol Daftar tidak boleh muncul. Jalur
    // laporan tetap diverifikasi utuh pada halaman Komunitas di bawah.
    const header = page.locator('header').first()
    check(
      (await header.getByRole('link', { name: 'Laporkan URL' }).count()) === 0,
      'Tombol Laporkan URL masih menjadi entry point navbar',
    )
    check(
      (await header.getByRole('link', { name: 'Daftar', exact: true }).count()) === 0,
      'Tombol Daftar masih menjadi entry point navbar',
    )
    check(
      await header.getByRole('radiogroup', { name: 'Tema tampilan' }).isVisible(),
      'Sakelar tema tidak terlihat pada navbar sebelum login',
    )
    check(
      await header.getByRole('link', { name: 'Masuk', exact: true }).isVisible(),
      'Tombol Masuk tidak terlihat pada navbar sebelum login',
    )
    const themePrecedesAction = await header.evaluate((element) => {
      const theme = element.querySelector('[role="radiogroup"]')
      const action = element.querySelector('a[href="/masuk"]')
      if (!theme || !action) return null
      return Boolean(theme.compareDocumentPosition(action) & Node.DOCUMENT_POSITION_FOLLOWING)
    })
    check(themePrecedesAction === true, 'Sakelar tema tidak berada di kiri tombol Masuk')

    await page.getByRole('link', { name: 'Lihat cara kerja' }).click()
    await page.waitForURL('**/#cara-kerja')
    check(await page.locator('#cara-kerja').isVisible(), 'Tautan cara kerja tidak menggulir ke bagian')

    const faq = page
      .locator('details')
      .filter({ hasText: 'Apakah VERIGUARD AI sudah menggunakan model AI?' })
      .first()
    await faq.locator('summary').click()
    check(await faq.evaluate((element) => element.hasAttribute('open')), 'FAQ tidak terbuka')
    check(
      ((await faq.textContent()) ?? '').includes('Belum.'),
      'Jawaban FAQ yang jujur tentang status AI tidak tampil',
    )

    await page.goto(baseUrl, { waitUntil: 'networkidle' })
    await page.locator('main').getByRole('link', { name: 'Mulai periksa' }).click()
    await page.waitForURL(/\/periksa(\?|$)/)
    check(
      await waitForHeading(page, 'Periksa tautan'),
      'CTA beranda tidak membuka halaman periksa',
    )

    await page
      .getByRole('navigation', { name: 'Navigasi utama' })
      .getByRole('link', { name: 'Edukasi' })
      .click()
    await page.waitForURL('**/edukasi')
    check(
      await waitForHeading(page, 'Kenali polanya'),
      'Navigasi Edukasi tidak membuka halaman edukasi',
    )

    await page
      .getByRole('navigation', { name: 'Navigasi utama' })
      .getByRole('link', { name: 'Komunitas' })
      .click()
    await page.waitForURL('**/komunitas')
    check(
      await waitForHeading(page, 'Community Reports'),
      'Navigasi Komunitas tidak membuka halaman laporan',
    )
    check(
      await page.getByLabel('URL yang dilaporkan').isVisible(),
      'Form laporan komunitas tidak tampil',
    )
    check(
      await page.getByText('Daftar laporan belum dimuat', { exact: true }).isVisible(),
      'Daftar laporan tanpa sesi akun yang sah tidak diberi status jujur (bukan kosong/gagal)',
    )
    check(
      (await page.getByText('Setiap akun dapat mengirim satu laporan per hari.').count()) > 0,
      'Ketentuan satu laporan per akun per hari tidak ditampilkan',
    )

    await page.goto(`${baseUrl}/edukasi`, { waitUntil: 'networkidle' })
    await page.getByRole('link', { name: 'Baca artikel' }).first().click()
    await page.waitForURL('**/edukasi/mengenali-phishing')
    check(
      await waitForHeading(page, 'Mengenali phishing'),
      'Tautan artikel tidak membuka artikel yang benar',
    )

    await page.goto(`${baseUrl}/tidak-ada`, { waitUntil: 'networkidle' })
    await page
      .locator('main')
      .getByRole('link', { name: 'Kembali ke beranda', exact: true })
      .click()
    await page.waitForURL(baseUrl + '/')
    check(true, 'Tombol kembali ke beranda pada 404 gagal')

    await desktop.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: baseUrl })

    await page.goto(`${baseUrl}/periksa`, { waitUntil: 'networkidle' })
    await page.getByRole('button', { name: 'Periksa tautan' }).click()
    check(await page.getByRole('alert').isVisible(), 'Error validasi tautan kosong tidak tampil')
    check(
      ((await page.getByRole('alert').textContent()) ?? '').includes('Masukkan tautan'),
      'Pesan error tautan kosong tidak sesuai',
    )

    await page.getByLabel('Tautan yang diperiksa').fill('bukan tautan')
    await page.getByRole('button', { name: 'Periksa tautan' }).click()
    check(
      ((await page.getByRole('alert').textContent()) ?? '').includes('tidak boleh mengandung spasi'),
      'Pesan error tautan dengan spasi tidak tampil',
    )

    await page.getByLabel('Tautan yang diperiksa').fill('bca-verifikasi-akun.example/login')
    await page.getByRole('button', { name: 'Periksa tautan' }).click()
    await page.waitForURL(/\/hasil\/[0-9a-f-]+$/, { timeout: 10000 })
    check(await waitForHeading(page, 'Hasil pemeriksaan'), 'Hasil pemeriksaan tautan tidak terbuka')
    check(
      await page.getByRole('heading', { name: 'Indikasi risiko tinggi' }).isVisible(),
      'Tautan phishing tidak diberi hasil risiko tinggi',
    )
    check(
      await page.getByText('Laporan multi-sumber').first().isVisible(),
      'Laporan multi-sumber tidak tampil di hasil',
    )
    check(
      await page.getByText('Nama merek pada domain tidak resmi').first().isVisible(),
      'Alasan penyamaran merek tidak tampil',
    )
    check(
      await page.getByText(/Bukan probabilitas/).first().isVisible(),
      'Catatan skor bukan probabilitas tidak tampil',
    )
    check(
      await page.getByText(/AI generatif belum terhubung/).first().isVisible(),
      'Status AI yang jujur tidak tampil di hasil',
    )
    check(
      await page.getByText('https://bca-verifikasi-akun.example/login').isVisible(),
      'Tautan yang diperiksa tidak dinormalkan dengan https://',
    )

    const storedAfterLink = await page.evaluate(() =>
      JSON.parse(localStorage.getItem('veriguard.scans.v1') ?? '[]'),
    )
    check(storedAfterLink.length === 1, 'Hasil tautan tidak tersimpan di localStorage')
    check(storedAfterLink[0]?.riskLevel === 'high', 'Hasil tersimpan tidak mencatat risiko tinggi')

    await page.getByRole('button', { name: 'Salin ringkasan' }).click()
    await page.getByRole('button', { name: 'Tersalin' }).waitFor({ timeout: 3000 })
    const clipboard = await page.evaluate(() => navigator.clipboard.readText())
    check(clipboard.includes('VERIGUARD AI'), 'Ringkasan hasil tidak tersalin ke clipboard')
    check(clipboard.includes('bukan probabilitas'), 'Ringkasan salinan tidak memuat catatan skor')

    await page.screenshot({ path: path.join(outputDir, 'desktop-hasil-tinggi.png'), fullPage: true })

    await page.emulateMedia({ media: 'print' })
    check(!(await page.locator('header').first().isVisible()), 'Header tetap tampil saat mode cetak')
    check(!(await page.locator('footer').first().isVisible()), 'Footer tetap tampil saat mode cetak')
    await page.emulateMedia({ media: 'screen' })

    await page.getByRole('link', { name: 'Buka riwayat' }).click()
    await page.waitForURL('**/riwayat')
    check(await waitForHeading(page, 'Riwayat pemeriksaan'), 'Riwayat tidak terbuka dari hasil')
    check(
      await page.getByText('bca-verifikasi-akun.example').first().isVisible(),
      'Pemeriksaan tersimpan tidak muncul di riwayat',
    )
    check(
      await page.getByText('Tinggi', { exact: true }).first().isVisible(),
      'Badge risiko tinggi tidak tampil di riwayat',
    )

    await page.getByRole('link', { name: 'Lihat detail' }).first().click()
    await page.waitForURL(/\/hasil\/[0-9a-f-]+$/)
    check(await waitForHeading(page, 'Hasil pemeriksaan'), 'Detail hasil dari riwayat gagal dibuka')

    await page.goto(`${baseUrl}/periksa?mode=link`, { waitUntil: 'networkidle' })
    await page.getByLabel('Tautan yang diperiksa').fill('https://www.bca.co.id/id/informasi')
    await page.getByRole('button', { name: 'Periksa tautan' }).click()
    await page.waitForURL(/\/hasil\/[0-9a-f-]+$/, { timeout: 10000 })
    check(await waitForHeading(page, 'Hasil pemeriksaan'), 'Hasil tautan resmi tidak terbuka')
    check(
      await page.getByRole('heading', { name: 'Indikasi risiko rendah' }).isVisible(),
      'Tautan resmi tidak diberi hasil risiko rendah',
    )
    check(
      await page.getByText(/Risiko rendah bukan jaminan/).first().isVisible(),
      'Disclaimer risiko rendah tidak tampil',
    )
    await page.screenshot({ path: path.join(outputDir, 'desktop-hasil-rendah.png'), fullPage: true })

    await page.goto(`${baseUrl}/periksa?mode=message`, { waitUntil: 'networkidle' })
    check(await page.getByLabel('Isi pesan', { exact: true }).isVisible(), 'Mode pesan tidak menampilkan textarea')
    const messageTab = page.getByRole('button', { name: 'Pesan', exact: true })
    check(
      (await messageTab.getAttribute('aria-pressed')) === 'true',
      'Tombol mode pesan tidak ditandai aktif',
    )
    const keepFullMessage = page.getByRole('checkbox', {
      name: 'Simpan isi pesan lengkap di riwayat',
    })
    check(await keepFullMessage.isVisible(), 'Opsi simpan isi pesan lengkap tidak tampil')
    check(!(await keepFullMessage.isChecked()), 'Opsi simpan isi pesan lengkap aktif secara default')

    await page
      .getByLabel('Isi pesan', { exact: true })
      .fill(
        'Selamat! Anda menang hadiah Rp10.000.000. Kirim kode OTP Anda sekarang ke bit.ly/klaim-hadiah.',
      )
    await page.getByRole('button', { name: 'Periksa pesan' }).click()
    await page.waitForURL(/\/hasil\/[0-9a-f-]+$/, { timeout: 10000 })
    check(await waitForHeading(page, 'Hasil pemeriksaan'), 'Hasil pemeriksaan pesan tidak terbuka')
    check(
      await page.getByRole('heading', { name: 'Indikasi risiko tinggi' }).isVisible(),
      'Pesan penipuan tidak diberi hasil risiko tinggi',
    )
    check(
      await page.getByText('Pencurian OTP', { exact: true }).isVisible(),
      'Pola pencurian OTP tidak tampil pada hasil pesan',
    )
    check(
      await page.getByText('Isi pesan disamarkan sebelum disimpan', { exact: true }).isVisible(),
      'Pemberitahuan isi pesan disamarkan tidak tampil di hasil',
    )
    check(
      await page.getByText(/karakter dianalisis/).first().isVisible(),
      'Jumlah karakter yang dianalisis tidak tampil',
    )

    const storedAfterMessage = await page.evaluate(() =>
      JSON.parse(localStorage.getItem('veriguard.scans.v1') ?? '[]'),
    )
    check(storedAfterMessage.length === 3, 'Riwayat tidak menyimpan tiga pemeriksaan')
    check(
      storedAfterMessage[0]?.meta.inputStored === 'redacted',
      'Pesan tanpa izin tidak ditandai tersimpan dalam bentuk samaran',
    )
    check(
      !storedAfterMessage[0]?.input.includes('bit.ly') &&
        !storedAfterMessage[0]?.input.includes('10.000.000'),
      'Tautan atau angka sensitif tetap tersimpan pada pesan tanpa izin',
    )
    check(
      storedAfterMessage[0]?.input.includes('[tautan]') &&
        storedAfterMessage[0]?.input.includes('[angka]'),
      'Cuplikan pesan tersimpan tidak memakai penanda samaran',
    )
    await page.screenshot({ path: path.join(outputDir, 'desktop-hasil-pesan.png'), fullPage: true })

    await page.goto(`${baseUrl}/periksa?mode=message`, { waitUntil: 'networkidle' })
    await page
      .getByRole('checkbox', { name: 'Simpan isi pesan lengkap di riwayat' })
      .check()
    await page
      .getByLabel('Isi pesan', { exact: true })
      .fill('Kode verifikasi 998877 untuk akunmu. Jangan bagikan kode ini kepada siapa pun.')
    await page.getByRole('button', { name: 'Periksa pesan' }).click()
    await page.waitForURL(/\/hasil\/[0-9a-f-]+$/, { timeout: 10000 })
    check(
      await waitForHeading(page, 'Hasil pemeriksaan'),
      'Hasil pesan dengan izin penyimpanan lengkap tidak terbuka',
    )
    check(
      (await page.getByText('Isi pesan disamarkan sebelum disimpan', { exact: true }).count()) === 0,
      'Hasil pesan dengan izin lengkap tetap menampilkan pemberitahuan samaran',
    )
    const storedAfterConsent = await page.evaluate(() =>
      JSON.parse(localStorage.getItem('veriguard.scans.v1') ?? '[]'),
    )
    check(storedAfterConsent.length === 4, 'Riwayat tidak menyimpan pemeriksaan dengan izin lengkap')
    check(
      storedAfterConsent[0]?.meta.inputStored === 'full' &&
        storedAfterConsent[0]?.input.includes('998877'),
      'Isi pesan lengkap tidak tersimpan setelah pengguna memberi izin',
    )

    await page.goto(`${baseUrl}/periksa`, { waitUntil: 'networkidle' })
    const messageToggle = page.getByRole('button', { name: 'Pesan', exact: true })
    await messageToggle.click()
    await page.getByLabel('Isi pesan', { exact: true }).waitFor({ state: 'visible', timeout: 3000 })
    check(
      (await messageToggle.getAttribute('aria-pressed')) === 'true',
      'Tombol mode pesan tidak aktif setelah diklik',
    )
    check(
      page.url().includes('mode=message'),
      'URL tidak memperbarui mode pemeriksaan menjadi pesan',
    )
    check(await page.getByLabel('Isi pesan', { exact: true }).isVisible(), 'Form pesan tidak tampil setelah beralih mode')

    await page.goto(`${baseUrl}/hasil/tidak-ada`, { waitUntil: 'networkidle' })
    check(await waitForHeading(page, 'Hasil tidak ditemukan'), 'State hasil tidak ditemukan tidak tampil')
    check(
      await page.getByRole('link', { name: 'Mulai pemeriksaan baru' }).isVisible(),
      'CTA pemeriksaan baru tidak tampil pada hasil yang hilang',
    )

    await page.goto(`${baseUrl}/riwayat`, { waitUntil: 'networkidle' })
    const historyList = page.getByRole('list', { name: 'Daftar riwayat pemeriksaan' })
    const historySearch = page.getByLabel('Cari riwayat')
    const typeFilterGroup = page.getByRole('group', { name: 'Filter jenis pemeriksaan' })
    const riskFilterGroup = page.getByRole('group', { name: 'Filter tingkat risiko' })
    const sortGroup = page.getByRole('group', { name: 'Urutan riwayat' })

    check(await historySearch.isVisible(), 'Input pencarian riwayat tidak tampil')
    check((await historyList.getByRole('listitem').count()) === 4, 'Riwayat tidak menampilkan empat pemeriksaan')
    check(
      await page.getByRole('status').filter({ hasText: 'Menampilkan' }).first().isVisible(),
      'Status jumlah hasil riwayat tidak tampil',
    )

    await historySearch.fill('bca-verifikasi-akun')
    check(
      (await historyList.getByRole('listitem').count()) === 1,
      'Pencarian riwayat tidak menyaring berdasarkan URL',
    )
    check(
      !(await historyList.textContent())?.includes('www.bca.co.id'),
      'Hasil pencarian riwayat masih menampilkan data yang tidak cocok',
    )
    check(
      (await page.getByRole('status').filter({ hasText: 'Menampilkan' }).first().textContent())?.includes('1'),
      'Status hasil pencarian tidak menghitung hasil yang tersaring',
    )

    await page.getByRole('button', { name: 'Hapus filter pencarian' }).click()
    check(
      (await historyList.getByRole('listitem').count()) === 4,
      'Menghapus filter pencarian tidak mengembalikan seluruh riwayat',
    )

    await historySearch.fill('998877')
    check(
      (await historyList.getByRole('listitem').count()) === 1 &&
        (await historyList.textContent())?.includes('998877'),
      'Pencarian tidak menjangkau isi pesan yang tersimpan lengkap',
    )
    await page.getByRole('button', { name: 'Hapus filter pencarian' }).click()

    await typeFilterGroup.getByRole('button', { name: 'Pesan', exact: true }).click()
    check(
      (await historyList.getByRole('listitem').count()) === 2,
      'Filter jenis pesan tidak menyaring riwayat',
    )
    await riskFilterGroup.getByRole('button', { name: 'Sedang', exact: true }).click()
    check(
      await page.getByText('Tidak ada hasil yang cocok', { exact: true }).isVisible(),
      'State kosong untuk kombinasi filter tidak tampil',
    )
    await page.getByRole('button', { name: 'Reset filter' }).first().click()
    check(
      (await historyList.getByRole('listitem').count()) === 4,
      'Reset filter tidak mengembalikan seluruh riwayat',
    )

    await sortGroup.getByRole('button', { name: 'Terlama', exact: true }).click()
    const oldestFirst = await historyList.getByRole('link').first().textContent()
    check(
      oldestFirst?.includes('bca-verifikasi-akun.example'),
      'Urutan terlama tidak menampilkan pemeriksaan paling awal di atas',
    )
    await sortGroup.getByRole('button', { name: 'Terbaru', exact: true }).click()
    const newestFirst = await historyList.getByRole('link').first().textContent()
    check(
      !newestFirst?.includes('bca-verifikasi-akun.example'),
      'Urutan terbaru tidak menampilkan pemeriksaan paling akhir di atas',
    )

    await historySearch.fill('bca-verifikasi-akun')
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('button', { name: 'Ekspor CSV' }).click(),
    ])
    check(
      /^veriguard-riwayat-\d{4}-\d{2}-\d{2}\.csv$/.test(download.suggestedFilename()),
      `Nama berkas CSV tidak sesuai: ${download.suggestedFilename()}`,
    )
    const downloadPath = await download.path()
    check(Boolean(downloadPath), 'Berkas CSV hasil ekspor tidak tersedia')
    if (downloadPath) {
      const csv = await readFile(downloadPath, 'utf8')
      check(csv.startsWith('\uFEFF'), 'CSV tidak memakai BOM UTF-8')
      check(
        csv.includes('"Waktu"') && csv.includes('"Isi pesan disamarkan"'),
        'Header CSV tidak sesuai',
      )
      check(
        csv.includes('bca-verifikasi-akun.example') &&
          !csv.includes('www.bca.co.id') &&
          !csv.includes('998877'),
        'Ekspor CSV tidak mengikuti filter aktif',
      )
      check(csv.split('\r\n').length === 2, 'CSV hasil filter memuat baris yang tidak diharapkan')
    }
    check(
      await page.getByRole('button', { name: 'CSV diunduh' }).isVisible(),
      'Umpan balik unduhan CSV tidak tampil',
    )
    await page.getByRole('button', { name: 'Hapus filter pencarian' }).click()

    page.once('dialog', (dialog) => {
      void dialog.dismiss()
    })
    await page.getByRole('button', { name: 'Hapus semua' }).click()
    await page.waitForTimeout(150)
    check(
      (await historyList.getByRole('listitem').count()) === 4,
      'Membatalkan konfirmasi tetap menghapus seluruh riwayat',
    )

    page.once('dialog', (dialog) => {
      void dialog.accept()
    })
    await page.getByRole('button', { name: 'Hapus semua' }).click()
    await page.getByText('Belum ada riwayat', { exact: true }).waitFor({ timeout: 3000 })
    check(
      (await page.evaluate(() =>
        JSON.parse(localStorage.getItem('veriguard.scans.v1') ?? '[]'),
      )).length === 0,
      'Hapus semua tidak membersihkan penyimpanan lokal',
    )

    await desktop.close()

    const t6 = await browser.newContext({ viewport: { width: 1440, height: 900 } })
    const t6Page = await t6.newPage()
    const t6Errors = []

    t6Page.on('pageerror', (error) => t6Errors.push(`pageerror: ${error.message}`))
    t6Page.on('console', (message) => {
      if (message.type() === 'error') t6Errors.push(`console: ${message.text()}`)
    })

    await t6Page.goto(`${baseUrl}/edukasi`, { waitUntil: 'networkidle' })
    check(
      (await t6Page.getByRole('link', { name: 'Baca artikel' }).count()) === 8,
      'Daftar edukasi tidak menampilkan delapan artikel',
    )

    await t6Page.goto(`${baseUrl}/dashboard`, { waitUntil: 'networkidle' })
    check(
      await t6Page.getByRole('heading', { name: 'Dashboard memerlukan sesi' }).isVisible(),
      'Dashboard tanpa sesi tidak menampilkan gate',
    )
    check(
      await t6Page.getByRole('link', { name: 'Buka sesi demo lokal' }).first().isVisible(),
      'CTA sesi demo tidak tampil pada dashboard tanpa sesi',
    )

    await t6Page.goto(`${baseUrl}/masuk`, { waitUntil: 'networkidle' })
    check(
      await t6Page.getByText('Autentikasi sungguhan belum aktif', { exact: true }).isVisible(),
      'Peringatan autentikasi belum aktif tidak tampil di halaman masuk',
    )
    await t6Page.getByLabel('Nama tampilan (opsional)').fill('Penguji Demo')
    await t6Page.getByRole('button', { name: 'Mulai sesi demo lokal' }).click()
    await t6Page.waitForURL('**/dashboard')
    check(
      await waitForHeading(t6Page, 'Ringkasan aktivitas'),
      'Dashboard tidak terbuka setelah sesi demo dimulai',
    )
    check(
      await t6Page.getByText('Belum ada pemeriksaan tersimpan', { exact: true }).isVisible(),
      'Dashboard kosong tidak menampilkan state kosong',
    )
    check(
      await t6Page
        .getByRole('navigation', { name: 'Bagian dashboard' })
        .getByRole('link', { name: 'Dashboard Saya' })
        .isVisible(),
      'Tab Dashboard Saya tidak tampil',
    )
    check(
      (await t6Page
        .getByRole('navigation', { name: 'Bagian dashboard' })
        .getByRole('link', { name: 'Dashboard Admin' })
        .count()) === 0,
      'Tab Dashboard Admin tampil untuk sesi demo non-admin',
    )

    await t6Page.goto(`${baseUrl}/dashboard/admin`, { waitUntil: 'networkidle' })
    check(
      await t6Page
        .getByRole('heading', { name: 'Akses Dashboard Admin diperlukan' })
        .isVisible(),
      'Akses langsung dashboard admin tidak ditolak untuk sesi demo',
    )
    check(
      await t6Page
        .getByText('Sesi demo lokal bukan autentikasi sungguhan', { exact: false })
        .isVisible(),
      'Alasan penolakan akses admin untuk sesi demo tidak tampil',
    )

    await t6Page.goto(`${baseUrl}/periksa?mode=link`, { waitUntil: 'networkidle' })
    await t6Page.getByLabel('Tautan yang diperiksa').fill('bca-verifikasi-akun.example/login')
    await t6Page.getByRole('button', { name: 'Periksa tautan' }).click()
    await t6Page.waitForURL(/\/hasil\/[0-9a-f-]+$/, { timeout: 10000 })

    await t6Page.goto(`${baseUrl}/periksa?mode=link`, { waitUntil: 'networkidle' })
    await t6Page.getByLabel('Tautan yang diperiksa').fill('https://www.bca.co.id/id/informasi')
    await t6Page.getByRole('button', { name: 'Periksa tautan' }).click()
    await t6Page.waitForURL(/\/hasil\/[0-9a-f-]+$/, { timeout: 10000 })

    await t6Page.goto(`${baseUrl}/periksa?mode=message`, { waitUntil: 'networkidle' })
    await t6Page
      .getByLabel('Isi pesan', { exact: true })
      .fill(
        'Selamat! Anda menang hadiah Rp10.000.000. Kirim kode OTP Anda sekarang ke bit.ly/klaim-hadiah.',
      )
    await t6Page.getByRole('button', { name: 'Periksa pesan' }).click()
    await t6Page.waitForURL(/\/hasil\/[0-9a-f-]+$/, { timeout: 10000 })

    await t6Page.goto(`${baseUrl}/dashboard`, { waitUntil: 'networkidle' })
    check(
      await t6Page
        .getByText('Statistik dari 3 pemeriksaan yang tersimpan di browser ini.', { exact: true })
        .isVisible(),
      'Dashboard tidak menampilkan statistik setelah tiga pemeriksaan',
    )
    check(
      await t6Page.getByRole('heading', { name: 'Distribusi risiko' }).isVisible(),
      'Distribusi risiko tidak tampil di dashboard',
    )
    check(
      await t6Page
        .getByRole('img', { name: 'Risiko tinggi: 2 dari 3 pemeriksaan (67%)' })
        .isVisible(),
      'Perhitungan distribusi risiko dashboard tidak sesuai',
    )
    check(
      (await t6Page
        .getByRole('list', { name: 'Riwayat pemeriksaan terbaru' })
        .getByRole('listitem')
        .count()) === 3,
      'Riwayat terbaru dashboard tidak menampilkan tiga pemeriksaan',
    )
    check(
      await t6Page.getByText('Sesi demo aktif: Penguji Demo', { exact: true }).isVisible(),
      'Label sesi demo tidak tampil di dashboard',
    )
    await t6Page.screenshot({
      path: path.join(outputDir, 'desktop-dashboard.png'),
      fullPage: true,
    })

    await t6Page.setViewportSize({ width: 390, height: 844 })
    await t6Page.goto(`${baseUrl}/dashboard`, { waitUntil: 'networkidle' })
    const mobileDashboardOverflow = await t6Page.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      clientWidth: document.documentElement.clientWidth,
    }))
    check(
      mobileDashboardOverflow.scrollWidth <= mobileDashboardOverflow.clientWidth + 1,
      `Dashboard mobile: overflow horizontal (${mobileDashboardOverflow.scrollWidth} > ${mobileDashboardOverflow.clientWidth})`,
    )
    await t6Page.screenshot({
      path: path.join(outputDir, 'mobile-dashboard.png'),
      fullPage: true,
    })

    await t6Page.goto(`${baseUrl}/pengaturan`, { waitUntil: 'networkidle' })
    const mobileSettingsOverflow = await t6Page.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      clientWidth: document.documentElement.clientWidth,
    }))
    check(
      mobileSettingsOverflow.scrollWidth <= mobileSettingsOverflow.clientWidth + 1,
      `Pengaturan mobile: overflow horizontal (${mobileSettingsOverflow.scrollWidth} > ${mobileSettingsOverflow.clientWidth})`,
    )
    check(
      await t6Page.getByRole('group', { name: 'Jenis pemeriksaan default' }).isVisible(),
      'Kontrol preferensi tidak tampil di pengaturan mobile',
    )
    await t6Page.screenshot({
      path: path.join(outputDir, 'mobile-pengaturan.png'),
      fullPage: true,
    })
    await t6Page.setViewportSize({ width: 1440, height: 900 })

    await t6Page.goto(`${baseUrl}/pengaturan`, { waitUntil: 'networkidle' })
    await t6Page.screenshot({
      path: path.join(outputDir, 'desktop-pengaturan.png'),
      fullPage: true,
    })
    check(
      await waitForHeading(t6Page, 'Pengaturan perangkat'),
      'Halaman pengaturan perangkat tidak terbuka',
    )
    check(
      await t6Page
        .getByText('Profil akun dan sinkronisasi belum aktif', { exact: true })
        .isVisible(),
      'Status backend pengaturan tidak dijelaskan',
    )
    check(
      await t6Page
        .locator('#konten')
        .getByText('Penguji Demo', { exact: true })
        .isVisible(),
      'Sesi demo tidak tercermin di pengaturan',
    )

    const defaultModeGroup = t6Page.getByRole('group', {
      name: 'Jenis pemeriksaan default',
    })
    await defaultModeGroup.getByRole('button', { name: 'Pesan', exact: true }).click()
    check(
      await t6Page.getByText('Preferensi disimpan di perangkat ini.', { exact: true }).isVisible(),
      'Status penyimpanan preferensi tidak tampil',
    )
    check(
      (await defaultModeGroup.getByRole('button', { name: 'Pesan', exact: true }).getAttribute('aria-pressed')) ===
        'true',
      'Preferensi mode pesan tidak aktif setelah dipilih',
    )

    await t6Page.getByRole('checkbox', { name: 'Kurangi gerakan antarmuka' }).check()
    check(
      (await t6Page.evaluate(() => document.documentElement.dataset.reduceMotion)) === 'true',
      'Preferensi kurangi gerakan tidak diterapkan ke dokumen',
    )

    await t6Page.goto(`${baseUrl}/periksa`, { waitUntil: 'networkidle' })
    check(
      (await t6Page
        .getByRole('button', { name: 'Pesan', exact: true })
        .getAttribute('aria-pressed')) === 'true',
      'Mode default dari pengaturan tidak dipakai halaman periksa',
    )
    check(
      await t6Page.getByLabel('Isi pesan', { exact: true }).isVisible(),
      'Form pesan tidak tampil dari mode default pengaturan',
    )

    await t6Page.goto(`${baseUrl}/pengaturan`, { waitUntil: 'networkidle' })
    await t6Page.getByRole('button', { name: 'Kembalikan preferensi awal' }).click()
    check(
      await t6Page.getByText('Preferensi dikembalikan ke pengaturan awal.', { exact: true }).isVisible(),
      'Status reset preferensi tidak tampil',
    )
    check(
      (await t6Page.evaluate(() => document.documentElement.dataset.reduceMotion)) === undefined,
      'Preferensi gerakan tidak dihapus saat reset',
    )

    await t6Page.goto(`${baseUrl}/periksa?mode=message`, { waitUntil: 'networkidle' })
    await t6Page
      .getByRole('checkbox', { name: 'Simpan isi pesan lengkap di riwayat' })
      .check()
    await t6Page
      .getByLabel('Isi pesan', { exact: true })
      .fill('Kode verifikasi 554433 jangan dibagikan kepada siapa pun.')
    await t6Page.getByRole('button', { name: 'Periksa pesan' }).click()
    await t6Page.waitForURL(/\/hasil\/[0-9a-f-]+$/, { timeout: 10000 })

    await t6Page.goto(`${baseUrl}/pengaturan`, { waitUntil: 'networkidle' })
    const redactButton = t6Page.getByRole('button', { name: 'Samarkan semua isi pesan' })
    check(await redactButton.isEnabled(), 'Kontrol samarkan pesan tidak aktif untuk isi lengkap')

    t6Page.once('dialog', (dialog) => {
      void dialog.accept()
    })
    await redactButton.click()
    await t6Page
      .getByRole('status')
      .filter({ hasText: 'isi pesan disamarkan' })
      .waitFor({ timeout: 3000 })
    const redactedScans = await t6Page.evaluate(() =>
      JSON.parse(localStorage.getItem('veriguard.scans.v1') ?? '[]'),
    )
    check(
      redactedScans
        .filter((scan) => scan.mode === 'message')
        .every((scan) => scan.meta.inputStored === 'redacted'),
      'Tidak semua isi pesan ditandai tersamarkan',
    )
    check(
      !redactedScans.some((scan) => scan.input.includes('554433')),
      'Isi pesan lengkap masih tersimpan setelah penyamaran',
    )
    check(await redactButton.isDisabled(), 'Kontrol samarkan pesan tetap aktif tanpa isi lengkap')

    const [settingsDownload] = await Promise.all([
      t6Page.waitForEvent('download'),
      t6Page.getByRole('button', { name: 'Ekspor CSV' }).click(),
    ])
    const settingsDownloadPath = await settingsDownload.path()
    check(Boolean(settingsDownloadPath), 'Ekspor CSV dari pengaturan tidak menghasilkan berkas')
    if (settingsDownloadPath) {
      const settingsCsv = await readFile(settingsDownloadPath, 'utf8')
      check(
        settingsCsv.startsWith('\uFEFF') && settingsCsv.includes('"Isi pesan disamarkan"'),
        'CSV dari pengaturan tidak memakai format yang benar',
      )
      check(
        !settingsCsv.includes('554433'),
        'CSV dari pengaturan masih memuat isi pesan yang sudah disamarkan',
      )
    }

    t6Page.once('dialog', (dialog) => {
      void dialog.accept()
    })
    await t6Page.getByRole('button', { name: 'Hapus semua data lokal' }).click()
    await t6Page
      .getByText('Semua data aplikasi di browser ini dihapus. Preferensi kembali ke pengaturan awal.', {
        exact: true,
      })
      .waitFor({ timeout: 3000 })
    check(
      await t6Page.evaluate(() => localStorage.getItem('veriguard.scans.v1') === null),
      'Hapus semua data lokal tidak menghapus riwayat',
    )
    check(
      await t6Page.evaluate(() => localStorage.getItem('veriguard.local-session.v1') === null),
      'Hapus semua data lokal tidak menghapus sesi demo',
    )

    await t6Page.goto(`${baseUrl}/dashboard`, { waitUntil: 'networkidle' })
    check(
      await t6Page.getByRole('heading', { name: 'Dashboard memerlukan sesi' }).isVisible(),
      'Dashboard tetap terbuka setelah semua data lokal dihapus',
    )
    check(t6Errors.length === 0, `Kesalahan runtime T6: ${t6Errors.join('; ')}`)

    await t6.close()

    const mobile = await browser.newContext({ viewport: { width: 390, height: 844 } })
    const mobilePage = await mobile.newPage()

    await mobilePage.goto(baseUrl, { waitUntil: 'networkidle' })
    await mobilePage.getByRole('button', { name: 'Buka menu' }).click()
    check(await mobilePage.locator('#menu-seluler').isVisible(), 'Menu seluler tidak terbuka')

    await mobilePage.locator('#menu-seluler').getByRole('link', { name: 'Riwayat' }).click()
    await mobilePage.waitForURL('**/riwayat')
    check(
      await waitForHeading(mobilePage, 'Riwayat pemeriksaan'),
      'Navigasi seluler ke Riwayat gagal',
    )
    check(
      !(await mobilePage.locator('#menu-seluler').isVisible()),
      'Menu seluler tidak tertutup setelah navigasi',
    )

    await mobilePage.goto(`${baseUrl}/periksa?mode=link`, { waitUntil: 'networkidle' })
    await mobilePage.getByLabel('Tautan yang diperiksa').fill('bca-verifikasi-akun.example/login')
    await mobilePage.getByRole('button', { name: 'Periksa tautan' }).click()
    await mobilePage.waitForURL(/\/hasil\/[0-9a-f-]+$/, { timeout: 10000 })
    check(
      await waitForHeading(mobilePage, 'Hasil pemeriksaan'),
      'Hasil pemeriksaan tidak terbuka di mobile',
    )
    const mobileResultOverflow = await mobilePage.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      clientWidth: document.documentElement.clientWidth,
    }))
    check(
      mobileResultOverflow.scrollWidth <= mobileResultOverflow.clientWidth + 1,
      `Hasil mobile: overflow horizontal (${mobileResultOverflow.scrollWidth} > ${mobileResultOverflow.clientWidth})`,
    )
    check(
      await mobilePage.getByRole('heading', { name: 'Indikasi risiko tinggi' }).isVisible(),
      'Hasil risiko tinggi tidak tampil di mobile',
    )
    await mobilePage.screenshot({
      path: path.join(outputDir, 'mobile-hasil.png'),
      fullPage: true,
    })

    await mobilePage.getByRole('link', { name: 'Buka riwayat' }).click()
    await mobilePage.waitForURL('**/riwayat')
    check(
      await waitForHeading(mobilePage, 'Riwayat pemeriksaan'),
      'Riwayat tidak terbuka dari hasil mobile',
    )
    check(
      await mobilePage.getByText('bca-verifikasi-akun.example').first().isVisible(),
      'Pemeriksaan mobile tidak muncul di riwayat',
    )
    check(
      await mobilePage.getByLabel('Cari riwayat').isVisible(),
      'Pencarian riwayat tidak tampil di mobile',
    )
    check(
      await mobilePage.getByRole('group', { name: 'Filter tingkat risiko' }).isVisible(),
      'Filter tingkat risiko tidak tampil di mobile',
    )
    const mobileHistoryOverflow = await mobilePage.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      clientWidth: document.documentElement.clientWidth,
    }))
    check(
      mobileHistoryOverflow.scrollWidth <= mobileHistoryOverflow.clientWidth + 1,
      `Riwayat mobile: overflow horizontal (${mobileHistoryOverflow.scrollWidth} > ${mobileHistoryOverflow.clientWidth})`,
    )
    await mobilePage.getByLabel('Cari riwayat').fill('tidak-akan-cocok')
    check(
      await mobilePage.getByText('Tidak ada hasil yang cocok', { exact: true }).isVisible(),
      'State kosong pencarian riwayat tidak tampil di mobile',
    )
    await mobilePage.getByRole('button', { name: 'Reset filter' }).first().click()
    check(
      await mobilePage.getByText('bca-verifikasi-akun.example').first().isVisible(),
      'Reset filter riwayat mobile tidak mengembalikan data',
    )
    await mobilePage.screenshot({
      path: path.join(outputDir, 'mobile-riwayat.png'),
      fullPage: true,
    })

    await mobile.close()
  } finally {
    await browser.close()
    server.kill()
  }

  if (failures.length > 0) {
    console.error(`\nGAGAL - ${failures.length} dari ${checks} pemeriksaan tidak lolos:`)
    for (const failure of failures) console.error(` - ${failure}`)
    process.exitCode = 1
  } else {
    console.log(`\nLULUS - ${checks} pemeriksaan navigasi, konten, font, dan responsivitas.`)
    console.log(`Screenshot: ${outputDir}`)
  }
}

run().catch((error) => {
  console.error(error)
  process.exitCode = 1
})

import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'

// VGM-09: CSP diverifikasi sebelum header di firebase.json diubah menjadi enforced. Skrip ini
// menyajikan build produksi LOCAL dengan header PERSIS seperti yang tertulis di firebase.json,
// lalu mencatat setiap peristiwa securitypolicyviolation dari seluruh rute. Tidak ada layanan
// produksi yang disentuh; sumber daya eksternal yang dimuat browser sama dengan kunjungan biasa.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = path.resolve(root, '..')
const distDir = path.join(root, 'dist')
const port = Number.parseInt(process.env.CSP_VERIFY_PORT ?? '4273', 10)
const origin = `http://127.0.0.1:${port}`

const ROUTES = [
  '/',
  '/periksa',
  '/daftar',
  '/komunitas',
  '/riwayat',
  '/edukasi',
  '/hasil',
  '/dashboard',
  '/dashboard/admin',
]

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
  '.json': 'application/json; charset=utf-8',
}

function matchGlob(source, pathname) {
  if (source === '**') return true
  if (source.endsWith('/**')) return pathname.startsWith(source.slice(0, -3))
  return source === pathname
}

async function loadHeaderBlocks() {
  const raw = JSON.parse(await readFile(path.join(repoRoot, 'firebase.json'), 'utf8'))
  return raw.hosting.headers
}

/**
 * Atribut `style={{ … }}` pada JSX adalah inline style menurut CSP. Peramban hanya
 * mencatat pelanggaran untuk rute yang benar-benar merender komponennya, jadi daftar
 * statis ini dipakai sebagai syarat sebelum policy diubah menjadi enforced.
 */
function inlineStyleAttributeFiles(dir) {
  const found = []
  const walk = (current) => {
    let entries
    try {
      entries = readdirSync(current, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name)
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules') walk(full)
        continue
      }
      if (!/\.(tsx|jsx)$/.test(entry.name) || /\.(test|spec)\.(tsx|jsx)$/.test(entry.name)) continue
      const matches = readFileSync(full, 'utf8').match(/style=\{\{/g)
      if (matches) found.push({ file: path.relative(root, full), count: matches.length })
    }
  }
  walk(dir)
  return found.sort((a, b) => a.file.localeCompare(b.file))
}

function policyDirectives(policy) {
  const map = new Map()
  for (const part of policy.split(';')) {
    const tokens = part.trim().split(/\s+/)
    if (!tokens[0]) continue
    map.set(tokens[0].toLowerCase(), tokens.slice(1).join(' '))
  }
  return map
}

function contentTypeFor(pathname) {
  return MIME[path.extname(pathname).toLowerCase()] ?? 'application/octet-stream'
}

async function main() {
  const blocks = await loadHeaderBlocks()

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', origin)
    // Header dicocokkan terhadap jalur permintaan ASLI, bukan hasil rewrite. Produksi berlaku
    // seperti itu (dibuktikan dengan probe: '/' memakai default max-age=3600 sedangkan
    // '/index.html' memakai no-cache), dan emulasi yang salah akan menyembunyikan aturan cache.
    const requestPath = decodeURIComponent(url.pathname)
    const contentTypePath = path.extname(requestPath) ? requestPath : '/index.html'

    // SPA rewrite seperti di firebase.json: berkas apa pun yang tidak ada dikirim index.html.
    let fileBody
    try {
      fileBody = await readFile(path.join(distDir, path.normalize(requestPath).replace(/^(\.\.[/\\])+/, '')))
    } catch {
      if (path.extname(requestPath)) {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' })
        res.end('not found')
        return
      }
      fileBody = await readFile(path.join(distDir, 'index.html'))
    }

    const headers = { 'content-type': contentTypeFor(contentTypePath) }
    for (const block of blocks) {
      if (!matchGlob(block.source, requestPath)) continue
      for (const header of block.headers) headers[header.key] = header.value
    }
    res.writeHead(200, headers)
    res.end(fileBody)
  })

  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve))

  const browser = await chromium.launch()
  const context = await browser.newContext()
  // Catatan pelanggaran dikumpulkan sejak sebelum skrip halaman berjalan.
  await context.addInitScript(() => {
    const sink = []
    window.addEventListener('securitypolicyviolation', (event) => {
      sink.push({
        directive: event.effectiveDirective ?? event.violatedDirective,
        blocked: event.blockedURI,
        sample: (event.originalHTML ?? event.sample ?? '').slice(0, 120),
        disposition: event.disposition,
      })
    })
    window.__cspViolations = sink
  })

  const consoleReports = []
  context.on('console', (message) => {
    const text = message.text()
    if (/\[Report Only\]|Refused to|Content Security Policy/i.test(text)) {
      consoleReports.push(text.slice(0, 200))
    }
  })

  const perRoute = []
  for (const route of ROUTES) {
    const page = await context.newPage()
    try {
      await page.goto(`${origin}${route}`, { waitUntil: 'load', timeout: 30_000 })
      await page.waitForTimeout(2_500)
    } catch (error) {
      consoleReports.push(`gagal memuat ${route}: ${String(error).slice(0, 120)}`)
    }
    const violations = await page.evaluate(() => (window.__cspViolations ?? []).slice())
    perRoute.push({ route, violations })
    await page.close()
  }

  await browser.close()
  await new Promise((resolve) => server.close(resolve))

  const all = perRoute.flatMap((entry) =>
    entry.violations.map((violation) => ({ ...violation, route: entry.route })),
  )
  const unique = new Map()
  for (const violation of all) {
    unique.set(
      `${violation.directive}|${violation.blocked}|${violation.route}`,
      violation,
    )
  }

  console.log(`Rute diperiksa: ${perRoute.map((entry) => entry.route).join(', ')}`)
  console.log(
    `Header CSP yang dipakai: ${blocks
      .find((block) => block.source === '**')
      .headers.filter((header) => header.key.startsWith('Content-Security-Policy'))
      .map((header) => header.key)
      .join(', ')}`,
  )
  if (unique.size === 0) {
    console.log('TIDAK ADA pelanggaran CSP yang tercatat.')
  } else {
    console.log(`PELANGGARAN CSP tercatat: ${unique.size}`)
    for (const violation of unique.values()) {
      console.log(
        ` - [${violation.route}] ${violation.directive} blocked=${violation.blocked} disposition=${violation.disposition}`,
      )
    }
  }
  if (consoleReports.length > 0) {
    console.log(`Pesan konsol terkait CSP: ${consoleReports.length}`)
    for (const line of consoleReports.slice(0, 20)) console.log(` - ${line}`)
  }

  const wildcard = blocks.find((block) => block.source === '**')
  const cspHeaders = wildcard.headers.filter((header) =>
    header.key.startsWith('Content-Security-Policy'),
  )
  const enforced = cspHeaders.find((header) => header.key === 'Content-Security-Policy')
  const reportOnly = cspHeaders.find(
    (header) => header.key === 'Content-Security-Policy-Report-Only',
  )
  const directives = policyDirectives((enforced ?? reportOnly)?.value ?? '')
  const styleSource = `${directives.get('style-src-attr') ?? ''} ${directives.get('style-src') ?? ''}`
  const inlineStyles = inlineStyleAttributeFiles(path.join(root, 'src'))

  console.log('\nSyarat sebelum policy dijadikan enforced')
  console.log('=========================================')
  if (!directives.has('style-src') && !directives.has('style-src-attr')) {
    console.log('  policy tidak memuat style-src/style-src-attr; inline style tidak dibatasi')
  } else if (/unsafe-inline/.test(styleSource)) {
    console.log("  style-src mengizinkan 'unsafe-inline' sehingga inline style aman")
  } else if (inlineStyles.length === 0) {
    console.log('  tidak ada atribut style={{ … }} di sumber, inline style tidak diperlukan')
  } else {
    const total = inlineStyles.reduce((sum, entry) => sum + entry.count, 0)
    console.log(
      `  HAMBATAN: ${total} atribut style={{ … }} pada ${inlineStyles.length} berkas akan ` +
        "ditolak bila policy ini dipakai apa adanya; butuh 'unsafe-inline' pada style-src-attr " +
        'atau gaya inline dipindah ke kelas CSS.',
    )
    for (const entry of inlineStyles) console.log(`   - ${entry.file} (${entry.count})`)
  }
  if (reportOnly && directives.has('upgrade-insecure-requests')) {
    console.log(
      '  upgrade-insecure-requests dicantumkan pada policy report-only: diabaikan browser ' +
        'dan baru berlaku setelah enforcement.',
    )
  }
  console.log(
    enforced
      ? '  status: policy ENFORCED terpasang di firebase.json'
      : '  status: hanya report-only terpasang; belum ada enforcement.',
  )

  const blockedByInlineStyles =
    Boolean(enforced) &&
    directives.has('style-src') &&
    !/unsafe-inline/.test(styleSource) &&
    inlineStyles.length > 0
  process.exitCode = all.length > 0 || blockedByInlineStyles ? 1 : 0
}

main().catch((error) => {
  console.error(`verifikasi CSP gagal: ${error && error.message ? error.message : String(error)}`)
  process.exitCode = 2
})

import { readdir, readFile, stat } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const target = path.resolve(root, process.argv[2] ?? 'dist')
const textExtensions = new Set(['.html', '.js', '.css'])

const localEndpointPatterns = [
  {
    pattern: /\b127\.0\.0\.1\b/g,
    label: 'IPv4 loopback',
  },
  {
    pattern: /\[::1\]/g,
    label: 'IPv6 loopback',
  },
  {
    pattern: /\b(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0):\d+/gi,
    label: 'host lokal dengan port',
  },
  {
    pattern: /\/\/(?:127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?::\d+)?/gi,
    label: 'URL protocol-relative ke host lokal',
  },
  {
    pattern: /https?:\/\/(?:127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?::\d+)?/gi,
    label: 'URL ke host lokal',
  },
]

const localhostUrlPattern = /https?:\/\/localhost(?::\d+)?(?=[/?#`"']|$)/gi
const dependencyFallbacks = [/["'`]http:\/\/localhost["'`]/g]
const devPortPattern = /(?:8787|9099|8080|8081|5001|5173|4000)\b/g

// Vite hanya men-inline variabel yang bernama VITE_*, jadi kunci provider yang benar tidak
// akan pernah masuk ke bundle. Yang bisa salah adalah kunci yang *terlanjur* dinamai VITE_*
// (mis. VITE_VIRUSTOTAL_API_KEY): nama-namanya dikenal, jadi kehadirannya di hasil build adalah
// tanda bahwa nilai rahasia ikut terkompilasi ke klien.
const PROVIDER_SECRET_NAMES = [
  'URLSCAN_API_KEY',
  'URLHAUS_API_KEY',
  'VIRUSTOTAL_API_KEY',
  'OPENPHISH_API_KEY',
  'THREATFOX_API_KEY',
  'CLOUDFLARE_API_TOKEN',
  'CLOUDFLARE_ACCOUNT_ID',
  'OTX_API_KEY',
  'HYBRID_ANALYSIS_API_KEY',
  'SAFE_BROWSING_API_KEY',
  'GOOGLE_SAFE_BROWSING_API_KEY',
  'CYBERSCAN_API_KEY',
  'URLSCANNER_API_KEY',
  'TURNSTILE_SECRET_KEY',
  'GEMINI_API_KEY',
  'FIREBASE_SERVICE_ACCOUNT',
  'PRIVATE_KEY',
]

// Bentuk rahasia yang tidak pernah berupa kunci klien publik. Kunci web Firebase (AIza...)
// sengaja tidak masuk daftar: ia memang publik dan wajib ada di bundle.
const SECRET_SHAPES = [
  { pattern: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/g, label: 'kunci privat PEM' },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/g, label: 'access key ID AWS' },
  { pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, label: 'token GitHub' },
  { pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, label: 'token Slack' },
  { pattern: /\bsk_(?:live|test|proj)_[A-Za-z0-9]{16,}\b/g, label: 'token Stripe/OpenAI' },
  { pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[eyJ][A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, label: 'JWT' },
  { pattern: /\bv[0-9]\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g, label: 'token API Cloudflare' },
]

// Nama variabel saja bukan bocor (mis. pesan "belum dikonfigurasi" memang menyebut namanya).
// Yang bocor adalah nama kunci provider yang diikat ke nilai, dalam bentuk objek config hasil
// inlining maupun penugasan literal.
const providerSecretAssignments = PROVIDER_SECRET_NAMES.map((name) => ({
  name,
  pattern: new RegExp(`["']?${name}["']?\\s*[:=]\\s*["'][^"']{16,}["']`, 'gi'),
}))

async function collectFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true })
  const files = []
  for (const entry of entries) {
    const location = path.join(directory, entry.name)
    if (entry.isDirectory()) files.push(...(await collectFiles(location)))
    else files.push(location)
  }
  return files
}

function classify(file) {
  const name = path.basename(file)
  if (name.startsWith('firebase-')) return 'firebase'
  if (name.startsWith('react-')) return 'react'
  if (name.startsWith('vendor-')) return 'vendor'
  return 'app'
}

function lineContext(text, index, length) {
  const start = Math.max(0, index - 60)
  const end = Math.min(text.length, index + length + 60)
  return text.slice(start, end).replace(/\s+/g, ' ')
}

// Temuan rahasia sengaja tidak mencetak konteks: menampilkan sebagian nilai yang cocok tetap
// menyalinnya ke log, dan instruksinya adalah tidak mencetak rahasia sama sekali.
function secretFinding(relative, label, length) {
  return `${relative}: ${label} ditemukan (${length} karakter, nilai tidak dicetak)`
}

async function run() {
  let info
  try {
    info = await stat(target)
  } catch {
    throw new Error(`Direktori build tidak ditemukan: ${target}`)
  }
  if (!info.isDirectory()) throw new Error(`Bukan direktori build: ${target}`)

  const allFiles = await collectFiles(target)
  const textFiles = allFiles.filter((file) =>
    textExtensions.has(path.extname(file).toLowerCase()),
  )
  const failures = []
  const dependencyNotes = new Set()
  const validationNotes = new Set()
  const sizes = []

  for (const file of textFiles) {
    const text = await readFile(file, 'utf8')
    const relative = path.relative(target, file)
    const kind = classify(file)

    for (const check of localEndpointPatterns) {
      check.pattern.lastIndex = 0
      let match
      while ((match = check.pattern.exec(text)) !== null) {
        failures.push(
          `${relative}: ${check.label} ditemukan -> ...${lineContext(text, match.index, match[0].length)}...`,
        )
      }
    }

    localhostUrlPattern.lastIndex = 0
    let localhostMatch
    while ((localhostMatch = localhostUrlPattern.exec(text)) !== null) {
      const context = lineContext(text, localhostMatch.index, localhostMatch[0].length)
      const isExactFallback = dependencyFallbacks.some((pattern) => {
        pattern.lastIndex = 0
        return pattern.test(context)
      })
      if ((kind === 'firebase' || kind === 'react') && isExactFallback) {
        dependencyNotes.add(relative)
        continue
      }
      failures.push(
        `${relative}: URL localhost ditemukan -> ...${context}...`,
      )
    }

    devPortPattern.lastIndex = 0
    let portMatch
    while ((portMatch = devPortPattern.exec(text)) !== null) {
      failures.push(
        `${relative}: port layanan pengembangan ${portMatch[0]} ditemukan -> ...${lineContext(text, portMatch.index, portMatch[0].length)}...`,
      )
    }

    for (const secret of SECRET_SHAPES) {
      secret.pattern.lastIndex = 0
      let secretMatch
      while ((secretMatch = secret.pattern.exec(text)) !== null) {
        failures.push(secretFinding(relative, secret.label, secretMatch[0].length))
      }
    }

    for (const assignment of providerSecretAssignments) {
      assignment.pattern.lastIndex = 0
      let assignmentMatch
      while ((assignmentMatch = assignment.pattern.exec(text)) !== null) {
        failures.push(
          secretFinding(relative, `nilai rahasia terikat ke ${assignment.name}`, assignmentMatch[0].length),
        )
      }
    }

    if (/\blocalhost\b/i.test(text) && !dependencyNotes.has(relative)) {
      validationNotes.add(relative)
    }

    if (relative.endsWith('.js')) {
      sizes.push({ relative, bytes: Buffer.byteLength(text) })
    }
  }

  sizes.sort((a, b) => b.bytes - a.bytes)
  const totalKb = Math.round(sizes.reduce((sum, entry) => sum + entry.bytes, 0) / 1024)

  if (failures.length > 0) {
    console.error('GAGAL - bundle memuat endpoint/host lokal atau bentuk rahasia:')
    for (const failure of failures) console.error(` - ${failure}`)
    process.exitCode = 1
    return
  }

  console.log(
    `LULUS - ${textFiles.length} berkas build diperiksa; tidak ada endpoint API host lokal maupun bentuk rahasia.`,
  )
  console.log(`Total JavaScript: ${totalKb} kB`)
  for (const entry of sizes.slice(0, 8)) {
    console.log(` - ${entry.relative}: ${Math.round(entry.bytes / 1024)} kB`)
  }

  if (dependencyNotes.size > 0) {
    console.log(
      'CATATAN - Fallback internal dependensi "http://localhost" (bukan endpoint API aplikasi):',
    )
    for (const file of dependencyNotes) console.log(` - ${file}`)
  }
  if (validationNotes.size > 0) {
    console.log(
      'CATATAN - String "localhost" juga muncul di logika validasi/penolakan host; tidak dipakai sebagai URL fetch:',
    )
    for (const file of validationNotes) console.log(` - ${file}`)
  }
}

run().catch((error) => {
  console.error(error instanceof Error ? error.message : error)
  process.exitCode = 1
})

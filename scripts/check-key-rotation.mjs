// Validasi KESIAPAN ROTASI: memeriksa keberadaan dan bentuk nilai kunci provider di
// setiap permukaan konfigurasi lokal, tanpa pernah mencetak, menyalin, atau menampilkan
// nilai itu sendiri. Yang dicetak hanya nama kunci, panjang, dan 10 heksa pertama dari
// SHA-256 nilai (sidik-jari). Sidik-jari dipakai untuk menjawab satu pertanyaan:
// "apakah permukaan A dan B masih memegang nilai yang sama?" — bukan untuk memulihkan nilai.
//
// Sengaja tidak membaca nilai dari proses (process.env) dan tidak menghubungi provider apa
// pun. Skrip ini hanya menyentuh berkas yang sudah ada di disk dan tidak menulis apa pun.
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

// Kunci yang sedang dirotasi manual oleh pemilik akun. Daftar ini sengaja kecil dan
// dieja persis seperti yang dibaca readScannerConfig.
const KEYS = ['URLSCAN_API_KEY', 'VIRUSTOTAL_API_KEY', 'THREATFOX_API_KEY']

// Permukaan yang bisa diperiksa dari disk. Setiap baris adalah satu tempat yang HARUS
// diperbarui manual setelah kunci lama digantikan.
const LOCAL_SURFACES = [
  { file: 'server/.env', role: 'backend lokal (npm run dev:server)' },
  { file: 'functions/.env', role: 'emulator Functions (firebase emulators)' },
  { file: 'workers/.dev.vars', role: 'wrangler dev lokal' },
]

// Template nama. Kalau suatu permukaan lokal memuat nama yang tidak ada di template,
// konfigurasi itu tidak terdokumentasi; kalau template memuat nama yang hilang di
// permukaan lokal, rotasi akan meninggalkan satu tempat kosong.
const TEMPLATES = ['server/.env.example', 'functions/.env.example', 'workers/.dev.vars.example']

const LINE_PATTERN = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/

function parseEnv(text) {
  const entries = new Map()
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.trim().startsWith('#')) continue
    const match = line.match(LINE_PATTERN)
    if (!match) continue
    const value = match[2].replace(/^["']|["']$/g, '').trim()
    entries.set(match[1], value)
  }
  return entries
}

function fingerprint(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 10)
}

function readSurface(file) {
  const abs = join(ROOT, file)
  if (!existsSync(abs)) return null
  return parseEnv(readFileSync(abs, 'utf8'))
}

// Permukaan lokal dipasangkan ke templatnya sendiri supaya pengecekan nama tetap tegas.
const LOCAL_TO_TEMPLATE = {
  'server/.env': 'server/.env.example',
  'functions/.env': 'functions/.env.example',
  'workers/.dev.vars': 'workers/.dev.vars.example',
}
const templateEntries = new Map(
  TEMPLATES.map((file) => [file, readSurface(file)]).filter(([, entries]) => entries),
)

const surfaces = LOCAL_SURFACES.map((surface) => ({ ...surface, entries: readSurface(surface.file) }))

console.log('Kesiapan rotasi kunci provider (sidik-jari, bukan nilai)')
console.log('=======================================================')

let missing = 0
for (const key of KEYS) {
  console.log(`\n${key}`)
  const seen = new Map()
  for (const surface of surfaces) {
    if (!surface.entries) {
      console.log(`  ${surface.file.padEnd(22)} BERKAS TIDAK ADA — ${surface.role}`)
      missing += 1
      continue
    }
    if (!surface.entries.has(key)) {
      console.log(`  ${surface.file.padEnd(22)} NAMA KUNCI TIDAK ADA — ${surface.role}`)
      missing += 1
      continue
    }
    const value = surface.entries.get(key)
    if (!value) {
      console.log(`  ${surface.file.padEnd(22)} KOSONG — ${surface.role}`)
      missing += 1
      continue
    }
    const fp = fingerprint(value)
    seen.set(surface.file, fp)
    console.log(`  ${surface.file.padEnd(22)} terisi panjang=${value.length} sidik-jari=${fp}`)
  }

  // Nilai yang identik di lebih dari satu permukaan berarti satu rotasi manual harus
  // disalin ke permukaan lain; kalau sidik-jarinya sama rata, belum ada yang dirotasi.
  const distinct = new Set(seen.values())
  if (seen.size > 1) {
    if (distinct.size === 1) {
      console.log(`  -> SIDIK-JARI SAMA di ${seen.size} permukaan: nilai masih seragam, rotasi belum masuk.`)
    } else {
      console.log(`  -> sidik-jari berbeda di ${distinct.size} permukaan: periksa permukaan mana yang sudah dan belum.`)
    }
  }
}

console.log('\nKonsistensi nama dan template')
console.log('---------------')
for (const key of KEYS) {
  for (const surface of surfaces) {
    if (!surface.entries) continue
    const templateFile = LOCAL_TO_TEMPLATE[surface.file]
    const template = templateEntries.get(templateFile)
    const inSurface = surface.entries.has(key)
    const inTemplate = template?.has(key) ?? false
    if (inSurface === inTemplate) continue
    console.log(
      `  BEDA: ${key} ${inSurface ? 'ada di' : 'tidak ada di'} ${surface.file} tetapi ` +
        `${inTemplate ? 'ada di' : 'tidak ada di'} ${templateFile}`,
    )
  }
  console.log(`  ${key.padEnd(20)} nama dipakai konsisten di permukaan lokal dan templatnya`)
}

// Nama yang ada di permukaan lokal tetapi tidak dibaca jalur aktif: kandidat pembersihan,
// bukan bagian dari rotasi. Daftar ini dijaga tetap manual supaya tidak ada tebak-tebakan.
const UNREAD_NAMES = [
  'SAFE_BROWSING_API_KEY',
  'URLHAUS_API_KEY',
]
console.log('\nNama yang tidak dibaca jalur aktif (bukan target rotasi)')
for (const name of UNREAD_NAMES) {
  const where = surfaces.filter((s) => s.entries?.has(name)).map((s) => s.file)
  if (where.length) console.log(`  ${name.padEnd(24)} ${where.join(', ')}`)
}

console.log('\nPermukaan produksi (tidak bisa dibaca dari sini)')
console.log('  Worker   : npx --prefix workers wrangler secret list')
console.log('  Functions: firebase functions:config:get dan/atau firebase functions:secrets:access <NAMA>')
console.log('  Aturan: jangan tempel nilai apa pun ke terminal, log, laporan, atau percakapan.')

if (missing > 0) {
  console.log(`\nGAGAL: ${missing} permukaan tidak memiliki nilai ${KEYS.join('/')} yang terisi.`)
  process.exit(1)
}
console.log('\nLULUS: ketiga kunci terisi di setiap permukaan lokal yang ada di disk.')
console.log('Catatan: LULUS di sini berarti keberadaannya valid, BUKAN bahwa nilainya sudah dirotasi.')
console.log('Bandingkan sidik-jari antar permukaan di atas untuk melihat apakah rotasi sudah tersalin.')

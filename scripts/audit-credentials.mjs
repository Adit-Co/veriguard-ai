// Inventaris kredensial TERSAMAR. Skrip ini tidak pernah mencetak nilai rahasia,
// sebagian nilai, atau prefix-nya. Keluaran hanya: nama variabel, panjang, bentuk,
// apakah dibaca sumber aktif, dan apakah nilai itu pernah muncul di objek Git.
//
// Pemakaian: npm run audit:credentials [-- --no-history]
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const FILES = [
  'functions/.env',
  'server/.env',
  'web/.env.local',
  'web/.env.development.local',
  'web/.env.production.local',
  'workers/.dev.vars',
]
// Hanya sumber runtime; berkas uji dan skrip penjaga (inspect-bundle.mjs) menyebut
// nama kunci tanpa membacanya, jadi tidak dihitung sebagai pemakai.
const SOURCE_DIRS = ['server/src', 'workers/src', 'functions/src', 'web/src']
const SECRET_NAME = /key|token|secret|pass|credential|account/i
// Nilai ini sengaja ikut terkirim ke browser (bukan rahasia server), jadi tidak
// boleh masuk daftar rotasi dengan prioritas yang sama dengan kunci provider.
const PUBLIC_CLIENT_NAMES = new Set(['VITE_FIREBASE_API_KEY', 'VITE_TURNSTILE_SITE_KEY'])
const MIN_HISTORY_VALUE_LENGTH = 8

function parseEnv(text) {
  const entries = []
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const eq = trimmed.indexOf('=')
    if (eq < 1) continue
    entries.push([
      trimmed.slice(0, eq).trim(),
      trimmed.slice(eq + 1).replace(/^["']|["']$/g, ''),
    ])
  }
  return entries
}

function shape(value) {
  if (/^[0-9a-f]+$/i.test(value)) return 'hex'
  if (/^[A-Za-z0-9_-]+$/.test(value)) return 'base64url-ish'
  return 'mixed'
}

function git(args) {
  return execFileSync('git', args, {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 512 * 1024 * 1024,
  })
}

function sourceUsage(name) {
  const pattern = new RegExp(`\\b${name}\\b`)
  const hits = []
  for (const dir of SOURCE_DIRS) {
    const abs = join(ROOT, dir)
    if (!existsSync(abs)) continue
    const walk = (current) => {
      let entries
      try {
        entries = readdirSync(current, { withFileTypes: true })
      } catch {
        return
      }
      for (const item of entries) {
        if (item.name === 'node_modules' || item.name === 'dist') continue
        const full = join(current, item.name)
        if (item.isDirectory()) walk(full)
        else if (
          /\.(ts|tsx|js|mjs)$/.test(item.name) &&
          !/\.(test|spec)\.(ts|tsx|js|mjs)$/.test(item.name) &&
          pattern.test(readFileSync(full, 'utf8'))
        ) {
          hits.push(relativeToRoot(full))
        }
      }
    }
    walk(abs)
  }
  return hits
}

function relativeToRoot(absolute) {
  return absolute.slice(ROOT.length + 1).replaceAll('\\', '/')
}

const withHistory = !process.argv.includes('--no-history')
const valuesToNames = new Map()
const inventory = []

for (const file of FILES) {
  const abs = join(ROOT, file)
  if (!existsSync(abs)) {
    inventory.push({ file, missing: true })
    continue
  }
  const entries = parseEnv(readFileSync(abs, 'utf8'))
  const rows = entries.map(([name, value]) => {
    const secret = SECRET_NAME.test(name)
    const publicClient = PUBLIC_CLIENT_NAMES.has(name)
    if (secret && !publicClient && value.length >= MIN_HISTORY_VALUE_LENGTH) {
      if (!valuesToNames.has(value)) valuesToNames.set(value, new Set())
      valuesToNames.get(value).add(`${file}:${name}`)
    }
    const usedBy = secret ? sourceUsage(name) : []
    return {
      name,
      secret,
      publicClient,
      filled: value.length > 0,
      length: value.length,
      shape: value ? shape(value) : 'kosong',
      used: secret ? usedBy.length > 0 : null,
      usedBy,
    }
  })
  inventory.push({ file, rows })
}

console.log('Inventaris berkas environment (nilai tidak pernah dicetak)')
console.log('=========================================================')
for (const item of inventory) {
  if (item.missing) {
    console.log(`\n${item.file}: TIDAK ADA (berkas nyata diabaikan Git; pakai .example sebagai templat)`)
    continue
  }
  console.log(`\n${item.file} (${item.rows.length} entri)`)
  for (const row of item.rows.sort((a, b) => Number(b.secret) - Number(a.secret) || a.name.localeCompare(b.name))) {
    if (!row.secret) continue
    console.log(
      `  ${row.name} | ${row.filled ? `terisi panjang=${row.length} bentuk=${row.shape}` : 'KOSONG'} |` +
        ` ${row.used ? `dibaca ${row.usedBy.length} berkas sumber` : 'TIDAK dibaca sumber aktif'}` +
        `${row.publicClient ? ' | nilai klien publik, bukan rahasia server' : ''}`,
    )
  }
  const unused = item.rows
    .filter((row) => row.secret && row.used === false && !row.publicClient)
    .map((row) => row.name)
  if (unused.length) console.log(`  -> tidak terpakai di jalur aktif: ${unused.join(', ')}`)
  const configOnly = item.rows.filter((row) => !row.secret).map((row) => row.name)
  if (configOnly.length) console.log(`  (non-rahasia: ${configOnly.join(', ')})`)
}

console.log('\nBukti riwayat Git')
console.log('=================')
const tracked = git(['ls-files']).split(/\r?\n/).filter((f) => FILES.includes(f))
console.log(
  tracked.length
    ? `  MASALAH: berkas environment nyata dilacak Git: ${tracked.join(', ')}`
    : '  tidak ada berkas environment nyata yang dilacak di HEAD',
)

if (!withHistory) {
  console.log('  pemindaian blob dilewati (--no-history)')
} else {
  const reachable = new Set()
  for (const line of git(['rev-list', '--objects', '--all']).split('\n')) {
    const sha = line.trim().split(' ')[0]
    if (sha) reachable.add(sha)
  }
  const dangling = git(['fsck', '--dangling', '--no-progress'])
    .split('\n')
    .filter((line) => line.startsWith('dangling blob'))
    .map((line) => line.split(/\s+/)[2])

  const exposure = new Map()
  const objects = [...reachable, ...dangling]
  for (const sha of objects) {
    let content
    try {
      content = git(['cat-file', '-p', sha])
    } catch {
      continue
    }
    for (const [value, names] of valuesToNames) {
      if (!content.includes(value)) continue
      const key = [...names].sort().join(', ')
      const entry = exposure.get(key) ?? { reachable: 0, dangling: 0, danglingIds: [] }
      if (reachable.has(sha)) entry.reachable += 1
      else {
        entry.dangling += 1
        entry.danglingIds.push(sha)
      }
      exposure.set(key, entry)
    }
  }

  console.log(
    `  blob dipindai: ${reachable.size} terjangkau ref + ${dangling.length} dangling = ${objects.length}`,
  )
  if (exposure.size === 0) {
    console.log('  tidak ada nilai environment aktif yang ditemukan di objek Git mana pun')
  }
  for (const [names, info] of [...exposure].sort((a, b) => a[0].localeCompare(b[0]))) {
    const where = [
      info.reachable ? `terjangkau ref (${info.reachable} blob)` : null,
      info.dangling ? `dangling (${info.danglingIds.join(', ')})` : null,
    ]
      .filter(Boolean)
      .join(' + ')
    console.log(`  DITEMUKAN ${names} -> ${where}`)
  }
}

console.log('\nSkrip ini mencetak nama, panjang, bentuk, dan ID objek — tidak pernah nilai.')

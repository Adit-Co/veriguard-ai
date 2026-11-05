import { spawn } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * VGL-42 — peluncur dev server dengan Emulator Firebase.
 *
 * Emulator adalah jalur pengujian TERISOLASI (login demo, data kosong tiap emulator dijalankan
 * ulang). Karena itu jalurnya tidak boleh lagi menyelinap lewat berkas .env: ia harus diminta
 * lewat proses. `npm run dev:emulators -- --port 5180` meneruskan argumen apa adanya ke vite.
 */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

const child = spawn(
  process.execPath,
  ['node_modules/vite/bin/vite.js', ...process.argv.slice(2)],
  {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, VITE_USE_EMULATORS: 'true' },
  },
)

child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal)
  else process.exitCode = code ?? 0
})

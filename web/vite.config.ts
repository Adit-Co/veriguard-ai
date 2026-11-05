import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'
import {
  formatProductionEnvIssues,
  validateProductionEnv,
} from './config/productionEnv.ts'
import {
  resolveDevEmulator,
  withDevEmulatorDecision,
  EMULATOR_ENV_VAR,
} from './config/devAuthEnv.ts'
import { demoSessionPlugin } from './config/demoSessionPlugin.ts'

export default defineConfig(({ command, mode }) => {
  const loadedEnv = loadEnv(mode, process.cwd(), 'VITE_')

  // VGL-42 — pada dev server, emulator hanya aktif bila proses peluncurnya yang meminta.
  // Berkas .env (mis. web/.env.development.local) tidak lagi bisa mengarahkan login normal ke
  // Auth Emulator secara diam-diam.
  const emulator =
    command === 'serve' ? resolveDevEmulator(process.env, loadedEnv) : null
  const env = emulator ? withDevEmulatorDecision(loadedEnv, emulator) : loadedEnv

  if (mode === 'production') {
    const issues = validateProductionEnv(env)
    if (issues.length > 0) {
      throw new Error(formatProductionEnvIssues(issues))
    }
  }

  if (command === 'serve' && emulator && !process.env.VITEST) {
    console.log(
      emulator.active
        ? '[veriguard] Layanan akun: EMULATOR Firebase. Login akun asli TIDAK akan ditemukan di sini.'
        : '[veriguard] Layanan akun: Firebase Authentication asli sesuai konfigurasi proyek.' +
            (emulator.fileRequested
              ? ' Berkas .env meminta emulator tetapi diabaikan; pakai "npm run dev:emulators" untuk pengujian terisolasi.'
              : ''),
    )
  }

  return {
    // Kunci ini sengaja menyaingi injeksi `import.meta.env` supaya sisi peramban melihat keputusan
    // gerbang yang sama dengan sisi Node.
    define: emulator
      ? {
          [`import.meta.env.${EMULATOR_ENV_VAR}`]: JSON.stringify(
            emulator.active ? 'true' : 'false',
          ),
        }
      : {},
    plugins: [
      react(),
      tailwindcss(),
      // Hanya dev server. Plugin ini sendiri menolak mendaftar bila pagar demo tidak lolos,
      // dan build produksi tidak pernah memuatnya (apply: 'serve').
      command === 'serve' ? demoSessionPlugin(env) : null,
    ],
    build: {
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (!id.includes('node_modules')) return undefined
            if (id.includes('firebase') || id.includes('@firebase')) return 'firebase'
            if (id.includes('react') || id.includes('scheduler')) return 'react'
            return 'vendor'
          },
        },
      },
    },
  }
})

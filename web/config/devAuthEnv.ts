/**
 * VGL-42 — gerbang Emulator Firebase untuk dev server.
 *
 * Sebab akar yang ditutup di sini: `web/.env.development.local` men-set `VITE_USE_EMULATORS=true`
 * dan berkas itu dimuat Vite pada SETIAP `vite dev`. Vite tidak memberi tahu kode mana pun nilai
 * itu datang dari berkas atau dari seseorang yang benar-benar meminta emulator, sehingga login
 * akun asli ikut dialihkan ke Auth Emulator dan akun lama dilaporkan "tidak terdaftar".
 *
 * Aturan baru: pada dev server emulator hanya aktif bila PROSES peluncurnya yang meminta
 * (`npm run dev:emulators`). Nilai dari berkas .env tidak lagi bisa mengaktifkan emulator secara
 * diam-diam. Build produksi tidak melewati jalur ini — di sana `import.meta.env.DEV` sudah false.
 */

export type EnvRecord = Record<string, string | undefined>

export const EMULATOR_ENV_VAR = 'VITE_USE_EMULATORS'

export function isEmulatorRequested(value: string | undefined): boolean {
  return value?.trim().toLowerCase() === 'true'
}

export type DevEmulatorDecision = {
  active: boolean
  /** Dari mana keputusan berasal, dipakai untuk banner dev server. */
  source: 'proses' | 'berkas-diabaikan' | 'tidak-diminta'
  /** true ketika berkas .env meminta emulator tetapi proses tidak. */
  fileRequested: boolean
}

export function resolveDevEmulator(
  processEnv: EnvRecord,
  fileEnv: EnvRecord,
): DevEmulatorDecision {
  const fileRequested = isEmulatorRequested(fileEnv[EMULATOR_ENV_VAR])

  if (isEmulatorRequested(processEnv[EMULATOR_ENV_VAR])) {
    return { active: true, source: 'proses', fileRequested }
  }

  return {
    active: false,
    source: fileRequested ? 'berkas-diabaikan' : 'tidak-diminta',
    fileRequested,
  }
}

/**
 * Salinan env yang dipakai sisi Node (plugin sesi demo, validasi). Bendera emulator diganti dengan
 * keputusan gerbang supaya sisi server dan sisi peramban tidak pernah berbeda pendapat: login demo
 * hanya terdaftar ketika emulator benar-benar aktif.
 */
export function withDevEmulatorDecision(
  env: EnvRecord,
  decision: DevEmulatorDecision,
): EnvRecord {
  return { ...env, [EMULATOR_ENV_VAR]: decision.active ? 'true' : 'false' }
}

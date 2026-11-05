import {
  SCAN_STATE_KEY_ACTIVE_VAR,
  SCAN_STATE_KEY_SALT_VAR,
  SCAN_STATE_KEY_VERSION_PREFIX,
  createStateKeyRing,
} from '../../src/state/stateKeys.js'
import type { StateKeyRing } from '../../src/state/stateKeys.js'
import type { DurableKeyRecord, ScanStateKind } from '../../src/state/durableState.js'

/**
 * VGL-30H Tahap 5: pembuat cincin kunci untuk uji.
 *
 * Materiainya SINTETIS dan hanya ada di proses uji. Ia tidak pernah dipakai sebagai konfigurasi
 * produksi maupun staging, tidak pernah dikirim ke layanan apa pun, dan tidak pernah ditulis ke
 * berkas yang di-deploy. VGL-30H melarang membuat secret Cloudflare; tujuan berkas ini hanya
 * memberi `crypto.subtle` materi yang cukup supaya jalur berversi bisa dijalankan dan dibuktikan
 * di luar workerd.
 */

const alphabet = '0123456789abcdef'

/** Materi kunci sintetis untuk satu versi; panjangnya layak tetapi nilainya tidak rahasia. */
export function syntheticKey(version: number): string {
  const tail = String(version).padStart(3, '0')
  return `vgl30h-sintetis-${alphabet.repeat(2)}-${tail}`
}

/** Label yang tersedia secara bawaan di uji: v1..v3. */
export const TEST_LABELS = ['v1', 'v2', 'v3'] as const
/** Salt era pra-VGL-30H (bentuk legacy tanpa prefiks), juga sintetis. */
export const TEST_LEGACY_SALT = `vgl30h-legacy-${alphabet.repeat(2)}`

export type RingSpec = {
  active?: string
  /** Versi yang materialnya dipasang; default `['v1']`. */
  labels?: readonly string[]
  /** Ganti materi satu versi, mis. untuk memasang nilai terlalu pendek. */
  materialOverride?: Record<string, string>
  /** Pasang salt legacy (`true` = nilai sintetis, `undefined` = tidak dipasang). */
  legacySalt?: string
}

export function ringEnv(spec: RingSpec): Record<string, unknown> {
  const env: Record<string, unknown> = {}
  if (spec.active !== undefined) env[SCAN_STATE_KEY_ACTIVE_VAR] = spec.active
  if (spec.legacySalt !== undefined) env[SCAN_STATE_KEY_SALT_VAR] = spec.legacySalt
  for (const label of spec.labels ?? ['v1']) {
    const version = Number.parseInt(label.slice(1), 10)
    env[`${SCAN_STATE_KEY_VERSION_PREFIX}${version}`] =
      spec.materialOverride?.[label] ?? syntheticKey(version)
  }
  return env
}

export function makeRing(spec: RingSpec): StateKeyRing {
  return createStateKeyRing(ringEnv(spec))
}

/** Cincin satu versi: konfigurasi paling sederhana yang mengaktifkan jalur durable. */
export function singleRing(): StateKeyRing {
  return makeRing({ active: 'v1', labels: ['v1'] })
}

/**
 * Digest untuk satu identitas pada cincin tertentu. Uji memakai ini alih-alih menebak hash supaya
 * yang diuji adalah kontrak pemanggilan produksi (`digestsFor` -> ops), bukan string tiruan.
 */
export async function recordOf(
  ring: StateKeyRing,
  kind: ScanStateKind,
  key: string,
): Promise<DurableKeyRecord> {
  const record = await ring.digestsFor(kind, key)
  if (record === null) throw new Error(`cincin tidak menghasilkan digest untuk ${kind}`)
  return record
}

/** Semua baris `key_hash` sebuah kind, untuk memeriksa bentuk hasil migrasi. */
export function hashesFor(
  db: { prepare(sql: string): { all(...args: unknown[]): Array<Record<string, unknown>> } },
  kind: string,
): string[] {
  return db
    .prepare('SELECT key_hash FROM vgl_state WHERE kind = ?')
    .all(kind)
    .map((row) => String(row.key_hash))
}

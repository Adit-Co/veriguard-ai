/**
 * VGL-30H K-4: kebijakan retensi kunci lama.
 *
 * Yang diputuskan berkas ini: kapan sebuah versi kunci yang sudah digantikan BOLEH dikeluarkan
 * dari ring (dan pada akhirnya dihapus secret-nya oleh pemilik). Yang TIDAK dilakukan berkas ini:
 * menghapus secret, menulis konfigurasi, memanggil Wrangler, atau menyentuh `process.env`. Tidak
 * ada jalur tulis di sini — keluarannya hanya keputusan + alasan, yang kemudian dibaca manusia
 * atau skrip audit.
 *
 * Angka dan alasannya (VGL-30G §2.6):
 *   - LANTAI KERAS 26 menit = 600 s retensi token + 60 s jeda alarm sapuan + 900 s margin jam dan
 *     sapuan. Di bawah ini, mencabut kunci lama pasti meninggalkan baris yang tidak terbaca lagi.
 *   - TERJADWAL 24 jam = satu putaran rotasi, satu orang jaga, mudah diaudit. Semua state (60 s
 *     sampai 600 s) sudah lama kedaluwarsa, jadi tidak ada baris yatim dan tidak ada jendela replay.
 *   - DARURAT 0 = versi yang bocor keluar dari ring saat itu juga. Konsekuensinya tidak boleh
 *     disembunyikan: anti-replay bolong sampai 600 s, clearance hilang, pencacah tepi reset.
 *
 * Jam selalu masuk lewat argumen (`nowMs`), tidak dibaca dari `Date.now()` di dalam: kebijakan ini
 * harus bisa dibuktikan pada menit 25, 26, dan 24 jam tanpa menunggu waktu berjalan.
 */

import { LEGACY_LABEL, isAcceptableKeyMaterial, isValidActiveVersionLabel } from './stateKeys.js'

/** Lantai keras retensi kunci lama: 26 menit. */
export const KEY_RETENTION_HARD_FLOOR_MS = 26 * 60_000

/** Retensi yang diusulkan untuk rotasi terjadwal: 24 jam. */
export const KEY_RETENTION_SCHEDULED_MS = 24 * 60 * 60_000

/** Retensi rotasi darurat: nol, dengan peringatan eksplisit. */
export const KEY_RETENTION_EMERGENCY_MS = 0

/** Lubang anti-replay maksimum yang dibuka rotasi darurat = retensi token. */
export const KEY_EMERGENCY_REPLAY_WINDOW_MS = 600_000

export const KEY_EMERGENCY_REPLAY_WARNING =
  `rotasi darurat: token yang sudah dipakai sebelum pencabutan dapat diulang sampai ${
    KEY_EMERGENCY_REPLAY_WINDOW_MS / 1000
  } s (lubang anti-replay), clearance CAPTCHA hilang, dan pencacah tepi reset`

export type KeyRotationMode = 'scheduled' | 'emergency'

export type KeyRemovalBlocker =
  | 'candidate_is_active'
  | 'label_invalid'
  | 'clock_invalid'
  | 'below_hard_floor'
  | 'below_scheduled_retention'
  | 'records_still_keyed'

export type KeyRemovalWarning = 'emergency_replay_window' | 'emergency_records_dropped'

export type KeyRetentionPolicyInput = {
  mode: KeyRotationMode
  /** Label versi aktif saat ini, mis. `v2`. */
  activeLabel: string
  /** Label versi yang hendak dikeluarkan, mis. `v1`. */
  candidateLabel: string
  /** Kapan versi ini berhenti dipakai menulis (cap waktu flip `SCAN_STATE_KEY_ACTIVE`). */
  retiredSinceMs: number
  /** Jam tersuntik. */
  nowMs: number
  /** Jumlah baris per label versi di tabel state; dari sensus actor. */
  rowsByLabel?: Record<string, number>
  /** Retensi terjadwal; bawaan 24 jam. */
  scheduledRetentionMs?: number
  /** Lantai keras; bawaan 26 menit. */
  hardFloorMs?: number
}

export type KeyRetentionPolicyDecision = {
  removable: boolean
  mode: KeyRotationMode
  candidateLabel: string
  elapsedMs: number
  hardFloorSatisfied: boolean
  scheduledRetentionSatisfied: boolean
  blockers: KeyRemovalBlocker[]
  warnings: KeyRemovalWarning[]
  /** Baris yang masih memakai versi kandidat saat keputusan diambil. */
  candidateRows: number
  instructions: string[]
}

function clockSane(retiredSinceMs: number, nowMs: number): boolean {
  return (
    Number.isFinite(retiredSinceMs) &&
    Number.isFinite(nowMs) &&
    retiredSinceMs >= 0 &&
    nowMs >= 0 &&
    nowMs >= retiredSinceMs
  )
}

function rowCount(rowsByLabel: Record<string, number> | undefined, label: string): number {
  const value = rowsByLabel?.[label]
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? Math.floor(value) : 0
}

/**
 * Evaluasi kebijakan. Fungsi murni: tidak membaca env, tidak menghapus apa pun, tidak memanggil
 * runtime. `removable` berarti "aman secara kebijakan", BUKAN "silakan hapus otomatis".
 */
export function evaluateKeyRetention(input: KeyRetentionPolicyInput): KeyRetentionPolicyDecision {
  const hardFloorMs = input.hardFloorMs ?? KEY_RETENTION_HARD_FLOOR_MS
  const scheduledRetentionMs = input.scheduledRetentionMs ?? KEY_RETENTION_SCHEDULED_MS
  const candidateRows = rowCount(input.rowsByLabel, input.candidateLabel)
  const blockers: KeyRemovalBlocker[] = []
  const warnings: KeyRemovalWarning[] = []
  const instructions: string[] = []

  // Kandidat boleh berlabel `legacy`: yang dinilai allora adalah pencabutan salt pra-VGL-30H, dan
  // baris lamunya memang berbentuk tanpa prefiks.
  const validLabels =
    isValidActiveVersionLabel(input.activeLabel) &&
    (isValidActiveVersionLabel(input.candidateLabel) || input.candidateLabel === LEGACY_LABEL)
  if (!validLabels) blockers.push('label_invalid')
  if (validLabels && input.activeLabel.trim().toLowerCase() === input.candidateLabel.trim().toLowerCase()) {
    blockers.push('candidate_is_active')
  }

  const sane = clockSane(input.retiredSinceMs, input.nowMs)
  if (!sane) blockers.push('clock_invalid')
  const elapsedMs = sane ? input.nowMs - input.retiredSinceMs : 0

  const hardFloorSatisfied = sane && elapsedMs >= hardFloorMs
  const scheduledRetentionSatisfied = sane && elapsedMs >= scheduledRetentionMs

  if (input.mode === 'scheduled') {
    if (!hardFloorSatisfied) blockers.push('below_hard_floor')
    if (!scheduledRetentionSatisfied) blockers.push('below_scheduled_retention')
    // Baris yang belum sempat dipindah adalah penghalang, bukan sekadar peringatan: waktunya sudah
    // lewat bukan berarti kuncinya tidak dipakai (butir 8-9 K-4).
    if (candidateRows > 0) blockers.push('records_still_keyed')
  } else {
    // Darurat: waktu tidak menahan, tetapi konsekuensinya harus tertulis.
    warnings.push('emergency_replay_window')
    // Peringatnya ikut dalam instruksi, bukan hanya dalam kode peringatan: orang yang membaca
    // keputusan harus melihat lubang anti-replay walau tidak memeriksa field `warnings`.
    instructions.push(KEY_EMERGENCY_REPLAY_WARNING)
    if (candidateRows > 0) {
      warnings.push('emergency_records_dropped')
      instructions.push(
        `${candidateRows} baris versi ${input.candidateLabel} ikut hilang: pencacah tepi reset dan izin CAPTCHA yang masih berlaku harus diterbitkan ulang`,
      )
    }
  }

  if (candidateRows > 0) {
    instructions.push(
      `${candidateRows} baris masih memakai versi ${input.candidateLabel}; jalankan permintaan yang menulis untuk memindahkannya (re-key-on-write) sebelum menilai ulang`,
    )
  }
  instructions.push(
    'penghapusan secret selalu tindakan pemilik di konsol/wrangler; kode ini tidak pernah menghapus atau mengganti nilai',
  )

  return {
    removable: blockers.length === 0,
    mode: input.mode,
    candidateLabel: input.candidateLabel,
    elapsedMs,
    hardFloorSatisfied,
    scheduledRetentionSatisfied,
    blockers,
    warnings,
    candidateRows,
    instructions,
  }
}

/**
 * Status kunci untuk diagnostik: mana yang aktif, mana yang masih dibaca, dan mana yang tidak boleh
 * dipakai lagi. Hanya label yang keluar; materi kunci tidak pernah dinilai di sini selain panjangnya.
 */
export type KeyRingStatusInput = {
  activeLabel?: string
  readableLabels?: string[]
  excludedLabels?: string[]
  materialByLabel?: Record<string, unknown>
  rowsByLabel?: Record<string, number>
}

export type KeyRingStatusLabel = {
  label: string
  role: 'active' | 'readable' | 'excluded'
  materialPresent: boolean
  materialLengthOk: boolean
  rows: number
}

export function describeKeyRingStatus(input: KeyRingStatusInput): KeyRingStatusLabel[] {
  const labels = new Set<string>([
    ...(input.readableLabels ?? []),
    ...(input.excludedLabels ?? []),
    ...(input.activeLabel ? [input.activeLabel] : []),
  ])
  const status: KeyRingStatusLabel[] = []
  for (const label of Array.from(labels).sort()) {
    const material = input.materialByLabel?.[label]
    status.push({
      label,
      role: label === input.activeLabel ? 'active' : (input.excludedLabels ?? []).includes(label) ? 'excluded' : 'readable',
      materialPresent: typeof material === 'string' ? material.trim().length > 0 : false,
      materialLengthOk: material === undefined ? false : isAcceptableKeyMaterial(material),
      rows: rowCount(input.rowsByLabel, label),
    })
  }
  return status
}

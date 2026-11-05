/**
 * VGL-30H K-1/K-2: cincin kunci HMAC (key ring) dan penyandian versi pada identitas record.
 *
 * Masalah yang ditutup di sini: VGL-30F membangun jalur durable tetapi satu-satunya bahan kuncinya
 * adalah satu salt (`SCAN_STATE_KEY_SALT`). Satu salt berarti satu bentuk digest: rotasi kunci
 * membuat seluruh state lama tidak terbaca, dan "tidak terbaca" untuk `kind='token'` berarti
 * anti-replay bolong. Cincin kunci memisahkan dua hal yang tadinya menyatu:
 *   - MATERI kunci: `SCAN_STATE_KEY_V<n>` (secret; tidak pernah keluar dari env), dan
 *   - LABEL versi aktif: `SCAN_STATE_KEY_ACTIVE` (`[vars]`; bukan materi kunci).
 *
 * Aturan yang dijaga kode ini:
 *  1. Digest SELALU dihitung dari identitas asal (`kind` + `key`), tidak pernah diturunkan dari
 *     digest lain. `key_hash` tidak dapat dibalik, jadi tidak ada "konversi hash" yang sah
 *     (VGL-30G §2.1 butir 2).
 *  2. Versi aktif menentukan penulisan. Versi lain hanya untuk membaca dan memindahkan record.
 *  3. Nilai secret tidak pernah dibaca ke log, tidak pernah dimasukkan ke galat, dan tidak pernah
 *     dipotong sebagai "sebagian nilai" yang bisa di-korelasi. Yang keluar hanya label + alasan.
 *  4. Tidak ada kunci statis, tidak ada string kosong, tidak ada nilai default. Kalau versi aktif
 *     tidak tersedia atau tidak valid, resolver gagal secara eksplisit dan jalur durable tetap
 *     inert — persis seperti sebelum VGL-30H di produksi/staging.
 *  5. Versi lama diasumsikan TIDAK selalu ada: ring dibangun dari yang hadir, dan materi yang
 *     ditolak hanya mengeluarkan versi itu sendiri, bukan seluruh ring.
 *
 * `crypto.subtle` diakses lewat tipe struktural supaya host Node (`server/`) yang mengimpor paket
 * ini tetap bisa type-check tanpa tipe runtime Cloudflare.
 */

export const SCAN_STATE_KEY_SALT_VAR = 'SCAN_STATE_KEY_SALT'
export const SCAN_STATE_KEY_ACTIVE_VAR = 'SCAN_STATE_KEY_ACTIVE'
export const SCAN_STATE_KEY_VERSION_PREFIX = 'SCAN_STATE_KEY_V'

// Bahan kunci pendek bukan lagi rahasia: 32 karakter ~ 190 bit, cukup untuk HMAC-SHA256.
const MIN_KEY_CHARS = 32
const MAX_KEY_CHARS = 512

const DIGEST_HEX_LENGTH = 64
const MAX_KEY_VERSION = 999

/** Prefiks versi di dalam `key_hash`: `v<n>:<64 hex>`. */
const BARE_DIGEST_PATTERN = /^[0-9a-f]+$/
const SECRET_NAME_PATTERN = new RegExp(`^${SCAN_STATE_KEY_VERSION_PREFIX}([1-9][0-9]{0,2})$`)
const ACTIVE_LABEL_PATTERN = /^v([1-9][0-9]{0,2})$/
const PREFIX_SHAPE_PATTERN = /^v[0-9]*$/
const ANY_PREFIX_PATTERN = /^[A-Za-z][A-Za-z0-9]*:/

/** Label untuk baris tanpa prefiks (ditulis kode pra-VGL-30H). Bukan versi secret. */
export const LEGACY_LABEL = 'legacy'
export type KeyVersionLabel = string

export type StateKeyRingUnavailableReason =
  | 'no_keys'
  | 'active_absent'
  | 'active_invalid'
  | 'active_version_absent'
  | 'subtle_unavailable'

/**
 * Pasangan digest untuk satu identitas, sudah dihitung SEBELUM transaksi dibuka: `activeHash`
 * untuk baca-tulis biasa, `retiredHashes` (lama→baru) untuk membaca dan memindahkan record yang
 * masih memakai versi sebelumnya.
 */
export type StateKeyRecord = {
  activeHash: string
  retiredHashes: string[]
}

export type StateKeyRing = {
  available: boolean
  reason?: StateKeyRingUnavailableReason
  /** Label versi yang dipakai menulis, mis. `v2`. Bukan materi kunci. */
  activeLabel?: KeyVersionLabel
  /** Semua label yang hadir dan dipakai untuk membaca, termasuk legacy. */
  readableLabels?: KeyVersionLabel[]
  /** Versi yang ada di env tetapi materialnya ditolak; label saja, tanpa nilai. */
  excludedLabels?: KeyVersionLabel[]
  /** Digest dihitung untuk tiap versi yang dibaca; null bila keyer gagal. */
  digestsFor(kind: string, key: string): Promise<StateKeyRecord | null>
}

export type KeyRecordParse =
  | { form: 'versioned'; label: KeyVersionLabel; digest: string }
  | { form: 'legacy'; digest: string }
  | { form: 'invalid'; reason: KeyRecordInvalidReason }

export type KeyRecordInvalidReason =
  | 'empty'
  | 'malformed_prefix'
  | 'unknown_version'
  | 'digest_malformed'

const subtleUnavailable = (): boolean => resolveSubtle() === undefined

type SubtleCryptoLike = {
  importKey(
    format: string,
    keyMaterial: ArrayBuffer | Uint8Array,
    algorithm: Record<string, unknown>,
    extractable: boolean,
    keyUsages: string[],
  ): Promise<unknown>
  sign(
    algorithm: Record<string, unknown>,
    key: unknown,
    data: ArrayBuffer | Uint8Array,
  ): Promise<ArrayBuffer>
}

function resolveSubtle(): SubtleCryptoLike | undefined {
  const holder = (globalThis as { crypto?: { subtle?: unknown } }).crypto
  const subtle = holder?.subtle as SubtleCryptoLike | undefined
  if (!subtle || typeof subtle.importKey !== 'function' || typeof subtle.sign !== 'function') {
    return undefined
  }
  return subtle
}

function toHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let hex = ''
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0')
  return hex
}

function versionLabel(version: number): KeyVersionLabel {
  return `v${version}`
}

function digestOf(label: KeyVersionLabel, hex: string): string {
  return `${label}:${hex}`
}

/**
 * Bahan kunci dinilai tanpa pernah menghasilkan nilai itu ke luar: panjang diperiksa pada salinan
 * lokal, dan yang dikembalikan hanya keputusan.
 */
function usableMaterial(value: unknown): boolean {
  const material = typeof value === 'string' ? value.trim() : ''
  return material.length >= MIN_KEY_CHARS && material.length <= MAX_KEY_CHARS
}

type RingVersion = {
  label: KeyVersionLabel
  version: number
  material: string
}

/** Nama secret divalidasi ketat; nama lain di env tidak pernah disentuh maupun dicatat. */
function collectVersions(env: Record<string, unknown>): {
  versions: RingVersion[]
  rejected: KeyVersionLabel[]
} {
  const versions: RingVersion[] = []
  const rejected: KeyVersionLabel[] = []
  for (const name of Object.keys(env).sort()) {
    const match = SECRET_NAME_PATTERN.exec(name)
    if (!match) continue
    const version = Number.parseInt(match[1], 10)
    if (!Number.isInteger(version) || version < 1 || version > MAX_KEY_VERSION) {
      rejected.push(versionLabel(version))
      continue
    }
    const material = typeof env[name] === 'string' ? (env[name] as string).trim() : ''
    if (usableMaterial(material)) {
      versions.push({ label: versionLabel(version), version, material })
    } else {
      rejected.push(versionLabel(version))
    }
  }
  versions.sort((a, b) => a.version - b.version)
  return { versions, rejected }
}

function unavailable(
  reason: StateKeyRingUnavailableReason,
  detail?: Partial<Omit<StateKeyRing, 'digestsFor'>>,
): StateKeyRing {
  return {
    available: false,
    reason,
    readableLabels: [],
    // Ring yang tidak aktif tidak pernah menghasilkan digest; stub ini menjaga tipe-nya tetap
    // lengkap supaya pemanggil tidak perlu bercabang pada bentuk objek.
    digestsFor: async () => null,
    ...detail,
  }
}

/**
 * Resolver cincin. Satu-satunya tempat yang menentukan versi aktif dan daftar versi yang tersedia,
 * supaya tidak ada dua sumber kebenaran (VGL-30G §2.2).
 */
export function createStateKeyRing(env: Record<string, unknown> | undefined): StateKeyRing {
  const surface = env ?? {}
  const { versions, rejected } = collectVersions(surface)

  const activeRaw = typeof surface[SCAN_STATE_KEY_ACTIVE_VAR] === 'string'
    ? (surface[SCAN_STATE_KEY_ACTIVE_VAR] as string).trim().toLowerCase()
    : ''

  if (versions.length === 0) {
    // Tidak ada materi berversi sama sekali: durable tetap inert, termasuk bila hanya salt legacy
    // yang hadir. Salt tanpa versi aktif TIDAK mengaktifkan penulisan durable (aturan 4).
    return unavailable('no_keys', { excludedLabels: rejected })
  }
  if (!activeRaw) {
    return unavailable('active_absent', {
      excludedLabels: rejected,
      readableLabels: versions.map((entry) => entry.label),
    })
  }
  if (!ACTIVE_LABEL_PATTERN.test(activeRaw)) {
    return unavailable('active_invalid', { excludedLabels: rejected })
  }

  const active = versions.find((entry) => entry.label === activeRaw)
  if (!active) {
    // Label menunjuk versi yang secret-nya tidak dipasang: jangan diam-diam pindah ke versi lain.
    return unavailable('active_version_absent', {
      activeLabel: activeRaw,
      excludedLabels: rejected,
      readableLabels: versions.map((entry) => entry.label),
    })
  }

  const subtle = resolveSubtle()
  if (!subtle) return unavailable('subtle_unavailable', { activeLabel: active.label })

  // Salt legacy adalah SUMBER BACA saja: digest-nya tidak berprefiks, bentuk yang ditulis kode
  // pra-VGL-30H. Ia tidak pernah dipakai untuk menulis, jadi keberadaannya tidak mengaktifkan
  // jalur durable dengan sendirinya.
  const legacyMaterial =
    typeof surface[SCAN_STATE_KEY_SALT_VAR] === 'string'
      ? (surface[SCAN_STATE_KEY_SALT_VAR] as string).trim()
      : ''
  const legacyUsable = legacyMaterial.length >= MIN_KEY_CHARS && legacyMaterial.length <= MAX_KEY_CHARS

  const encoder = new TextEncoder()
  const keyPromises = new Map<string, Promise<unknown>>()
  const signingKey = (slot: string, material: string): Promise<unknown> => {
    let pending = keyPromises.get(slot)
    if (!pending) {
      // Peta diindeks label, bukan materi kunci: promise-nya yang disimpan, bukan nilainya.
      pending = subtle.importKey(
        'raw',
        encoder.encode(material),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
      )
      keyPromises.set(slot, pending)
    }
    return pending
  }

  const sign = async (slot: string, material: string, payload: string): Promise<string | null> => {
    try {
      const cryptoKey = await signingKey(slot, material)
      const signature = await subtle.sign({ name: 'HMAC' }, cryptoKey, encoder.encode(payload))
      return toHex(signature)
    } catch {
      // Bahan kunci ditolak runtime: lebih baik tanpa digest daripada kembali ke teks asli.
      keyPromises.delete(slot)
      return null
    }
  }

  const retired = versions.filter((entry) => entry.label !== active.label)
  const readableLabels = [
    ...(legacyUsable ? [LEGACY_LABEL] : []),
    ...retired.map((entry) => entry.label),
    active.label,
  ]

  return {
    available: true,
    activeLabel: active.label,
    readableLabels,
    excludedLabels: rejected,
    async digestsFor(kind, key) {
      const payload = `${kind}:${key}`
      const activeHex = await sign(active.label, active.material, payload)
      if (activeHex === null) return null
      const hashes: string[] = []
      if (legacyUsable) {
        const legacyHex = await sign(LEGACY_LABEL, legacyMaterial, payload)
        // Digest legacy gagal: lanjut tanpa legacy, jangan menggandakan pencarian.
        if (legacyHex !== null) hashes.push(legacyHex)
      }
      for (const entry of retired) {
        const hex = await sign(entry.label, entry.material, payload)
        if (hex !== null) hashes.push(digestOf(entry.label, hex))
      }
      return { activeHash: digestOf(active.label, activeHex), retiredHashes: hashes }
    },
  }
}

/** Penyandian identitas record versi aktif. Diekspor untuk uji, bukan untuk dipakai pemanggil lain. */
export function encodeVersionedKeyHash(label: KeyVersionLabel, digest: string): string {
  return digestOf(label, digest)
}

/**
 * Pembacaan bentuk `key_hash`. Tiga bentuk yang mungkin dan harus dibedakan:
 *  - `versioned`: `v<n>:<hex>` — punya versi, bisa dicocokkan dengan label;
 *  - `legacy`: 64 hex tanpa prefiks — ditulis kode pra-VGL-30H, hanya sah bila ada salt legacy;
 *  - `invalid`: prefix rusak, versi di luar 1..999, atau digest bukan hex/panjangnya salah.
 * Record `invalid` tidak pernah dianggap sebagai identitas mana pun; ia diabaikan oleh pencarian
 * dan oleh sensus versi.
 */
export function parseKeyRecord(value: unknown): KeyRecordParse {
  if (typeof value !== 'string' || value.length === 0) return { form: 'invalid', reason: 'empty' }
  if (!value.includes(':')) {
    if (value.length === DIGEST_HEX_LENGTH && BARE_DIGEST_PATTERN.test(value)) {
      return { form: 'legacy', digest: value }
    }
    return { form: 'invalid', reason: 'digest_malformed' }
  }
  const split = value.indexOf(':')
  const prefix = value.slice(0, split)
  const digest = value.slice(split + 1)
  if (!ANY_PREFIX_PATTERN.test(value)) return { form: 'invalid', reason: 'malformed_prefix' }
  if (!PREFIX_SHAPE_PATTERN.test(prefix)) return { form: 'invalid', reason: 'malformed_prefix' }
  if (!ACTIVE_LABEL_PATTERN.test(prefix)) return { form: 'invalid', reason: 'unknown_version' }
  if (digest.length !== DIGEST_HEX_LENGTH || !BARE_DIGEST_PATTERN.test(digest)) {
    return { form: 'invalid', reason: 'digest_malformed' }
  }
  const version = Number.parseInt(prefix.slice(1), 10)
  if (version < 1 || version > MAX_KEY_VERSION) return { form: 'invalid', reason: 'unknown_version' }
  return { form: 'versioned', label: prefix, digest }
}

/** `key_hash` yang boleh dipakai sebagai identitas di jalur durable. */
export function isUsableKeyHash(value: unknown): boolean {
  const parsed = parseKeyRecord(value)
  return parsed.form === 'versioned' || parsed.form === 'legacy'
}

/** Versi tempat record disimpan, atau null untuk bentuk yang tidak dikenali. */
export function keyHashLabel(value: unknown): KeyVersionLabel | null {
  const parsed = parseKeyRecord(value)
  if (parsed.form === 'versioned') return parsed.label
  if (parsed.form === 'legacy') return 'legacy'
  return null
}

/** Uji cepat label versi aktif; dipakai validasi konfigurasi dan uji. */
export function isValidActiveVersionLabel(value: unknown): boolean {
  return typeof value === 'string' && ACTIVE_LABEL_PATTERN.test(value.trim().toLowerCase())
}

/** Batas panjang bahan kunci, diekspor supaya kebijakan retensi dan uji memakai angka yang sama. */
export const SCAN_STATE_KEY_MIN_CHARS = MIN_KEY_CHARS
export const SCAN_STATE_KEY_MAX_CHARS = MAX_KEY_CHARS

/** Dipakai kebijakan retensi untuk menolak material yang tidak akan pernah diterima resolver. */
export function isAcceptableKeyMaterial(value: unknown): boolean {
  return usableMaterial(value)
}

/** Peringatan dini: `crypto.subtle` tidak ada di runtime ini. */
export function isSubtleAvailable(): boolean {
  return !subtleUnavailable()
}

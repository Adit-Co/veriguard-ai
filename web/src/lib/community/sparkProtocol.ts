/**
 * Protokol Spark-only untuk Community Reports.
 *
 * Hari kalender memakai WIB tetap (UTC+7, tanpa DST) agar identitas dokumen harian
 * dapat dihitung ulang oleh Security Rules tanpa zona waktu bernama. Rumus dan offset
 * ini harus tetap sama dengan `communityDay()` di firestore.rules.
 */
export const COMMUNITY_DAY_OFFSET_MS = 7 * 60 * 60 * 1000
export const COMMUNITY_DAY_MS = 24 * 60 * 60 * 1000

/**
 * Zona WITA (UTC+8) untuk partisi umpan harian. Batas kirim harian tetap memakai
 * WIB di atas agar penanda yang sudah ada tidak berubah; keduanya sengaja terpisah.
 */
export const COMMUNITY_FEED_DAY_OFFSET_MS = 8 * 60 * 60 * 1000

/** Jumlah maksimum laporan per URL yang dipindai untuk agregat tampilan. */
export const COMMUNITY_CONTEXT_SCAN_LIMIT = 300
export const COMMUNITY_CONTEXT_REPORT_LIMIT = 20

/**
 * Batas jumlah laporan pada umpan komunitas global. Nilai ini harus tetap sama
 * dengan `communityLatestLimit()` di firestore.rules; feed adalah daftar ID
 * berurutan terbaru, bukan kueri lintas partisi.
 */
export const COMMUNITY_LATEST_LIMIT = 8

/**
 * Kapasitas umpan "Laporan terbaru" per hari WITA. Enam item menjaga panel tetap
 * seimbang dengan formulir di desktop; query hanya meminta sebanyak ini sehingga
 * laporan yang lebih lama tidak pernah dikirim ke browser.
 */
export const COMMUNITY_DAILY_FEED_LIMIT = 6

export function communityDailyFeedDayId(nowMs: number = Date.now()): string {
  return String(
    Math.floor((nowMs + COMMUNITY_FEED_DAY_OFFSET_MS) / COMMUNITY_DAY_MS),
  )
}

/** Awal hari WITA dalam epoch milidetik (inklusif). */
export function communityDailyFeedDayStartMs(nowMs: number = Date.now()): number {
  const dayNumber = Math.floor(
    (nowMs + COMMUNITY_FEED_DAY_OFFSET_MS) / COMMUNITY_DAY_MS,
  )
  return dayNumber * COMMUNITY_DAY_MS - COMMUNITY_FEED_DAY_OFFSET_MS
}

/** Akhir hari WITA dalam epoch milidetik (eksklusif). */
export function communityDailyFeedDayEndMs(nowMs: number = Date.now()): number {
  return communityDailyFeedDayStartMs(nowMs) + COMMUNITY_DAY_MS
}

export function communityDailyFeedDayIdFromIso(
  value: string | null | undefined,
): string | null {
  if (!value) return null
  const parsed = Date.parse(value)
  return Number.isNaN(parsed) ? null : communityDailyFeedDayId(parsed)
}

/** Jeda satu kali sampai pergantian hari WITA berikutnya; bukan interval polling. */
export function msUntilNextCommunityFeedDay(nowMs: number = Date.now()): number {
  return Math.max(0, communityDailyFeedDayEndMs(nowMs) - nowMs)
}

/** Cache singkat untuk mencegah pembacaan Firestore berulang saat render ulang. */
export const COMMUNITY_CACHE_TTL_MS = 30_000
export const COMMUNITY_CACHE_MAX_ENTRIES = 32

export const COMMUNITY_REPORT_ID_PATTERN = /^[0-9a-f]{32}$/
export const COMMUNITY_REPORTER_KEY_PATTERN = /^[0-9a-f]{64}$/

export function communityDayId(nowMs: number = Date.now()): number {
  return Math.floor((nowMs + COMMUNITY_DAY_OFFSET_MS) / COMMUNITY_DAY_MS)
}

/**
 * Waktu terbit token Auth berasal dari server Google, bukan jam perangkat. Nilai ini
 * dipakai untuk memilih dokumen harian agar akun dengan jam perangkat melenceng tetap
 * dapat menulis selama token masih baru.
 */
export function communityDayIdFromIso(value: string | null | undefined): number | null {
  if (!value) return null
  const parsed = Date.parse(value)
  return Number.isNaN(parsed) ? null : communityDayId(parsed)
}

function randomHex(byteLength: number): string {
  const cryptoObject = globalThis.crypto
  if (!cryptoObject?.getRandomValues) {
    throw new Error('Web Crypto tidak tersedia sehingga identitas acak tidak dapat dibuat.')
  }

  const bytes = cryptoObject.getRandomValues(new Uint8Array(byteLength))
  let hex = ''
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0')
  return hex
}

/** ID dokumen laporan acak 128-bit; bukan bukti keaslian, hanya nama dokumen. */
export function createReportId(): string {
  return randomHex(16)
}

/**
 * Pseudonim acak per akun per URL. Nilainya tidak dapat dihitung ulang dari UID,
 * jadi tidak mengungkap identitas dan tidak menghubungkan laporan lintas URL.
 */
export function createReporterKey(): string {
  return randomHex(32)
}

export async function sha256Hex(value: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) {
    throw new Error('Web Crypto tidak tersedia sehingga identitas URL tidak dapat dihitung.')
  }

  const digest = await subtle.digest('SHA-256', new TextEncoder().encode(value))
  const bytes = new Uint8Array(digest)
  let hex = ''
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0')
  return hex
}

/**
 * Hash ini adalah kunci partisi/kelompok URL, bukan bukti kriptografis bahwa klien
 * memakai URL yang benar. Security Rules tidak dapat menghitung SHA-256 atau
 * memverifikasi normalisasi, sehingga klien yang dimodifikasi tetap dapat menulis
 * ke partisi hash lain. Jangan pernah menyebut hash ini sebagai identitas tepercaya.
 */
export async function communityUrlHash(normalizedUrl: string): Promise<string> {
  return sha256Hex(normalizedUrl)
}

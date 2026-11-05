import { fetchJson, type FetchJsonResult } from '../http.js'
import {
  errorCheck,
  failureCheck,
  isRecord,
  notConfiguredCheck,
  recordValue,
  stringValue,
} from '../result.js'
import type { ProviderAdapter, ProviderCheck, ProviderVerdict } from '../types.js'

// Kontrak resmi Google Safe Browsing v5 `urls.search` (diverifikasi dari dokumentasi
// developers.google.com + live probe 2026-10-28):
//   GET https://safebrowsing.googleapis.com/v5/urls:search?key=API_KEY&urls=<URL>
//   Tidak ada request body. `urls[]` maximal 50 URL per permintaan; VERIGUARD mengirim 1 URL.
//   No-match: HTTP 200 dengan `threats` field kosong (BUKAN 404).
//
// PENTING — format respons live (probe langsung 2026-10-28):
//   Google TIDAK mematuhi header `Accept: application/json`. Respons v5 `urls:search` selalu
//   `Content-Type: application/x-protobuf`, termasuk untuk jalur HTTP 200 no-match.
//   Contoh bytes no-match untuk https://example.com/ (5 byte):
//     12 03 08 ac 02   =  { cache_duration: { seconds: 300 } }   // proto3 elides empty `threats`
//   `$alt=json` ditolak: HTTP 400 "Unsupported Output Format".
//
// Strategi parse VERIGUARD:
//   1. Body dibaca sebagai Uint8Array (mode 'bytes' fetchJson) agar tidak ada lossy UTF-8 decode.
//   2. Jika Content-Type mengandung `application/x-protobuf` → decode wire-format minimal
//      (hanya field SearchUrlsResponse.threats=1 dan cache_duration=2 yang dikenali; field
//      lain dilewati agar kompatibel dengan penambahan proto3 di masa depan).
//   3. Content-Type `application/json`/`text/*` → dekode UTF-8 lalu parse JSON (ini menangkap
//      respons error JSON Google, mis. 400). Content-type biner → jalur protobuf. Content-Type
//      absen/tidak dikenal (proxy) → disniff: JSON lebih dulu, baru protobuf; BUKAN asumsi JSON.
//   4. Kegagalan parse protobuf maupun JSON → `error`; tidak pernah menjadi `clean` atau
//      no-match.
//
// Enum ThreatType sah (v5 proto, googleapis/googleapis):
//   0 = THREAT_TYPE_UNSPECIFIED   1 = MALWARE   2 = SOCIAL_ENGINEERING
//   3 = UNWANTED_SOFTWARE         4 = POTENTIALLY_HARMFUL_APPLICATION
// Nilai tak dikenal → diperlakukan sebagai sinyal ancaman (bukti lebih kuat dari ketiadaan match),
// bukan diabaikan atau dibaca sebagai bersih (halaman v5 mewajibkan klien toleran enum baru).
//
// Keamanan (dipertahankan dari integrasi v4):
//   (a) Kunci API dibaca HANYA di backend dari GOOGLE_SAFE_BROWSING_API_KEY; tidak pernah
//       muncul di frontend, log, source, respons API, maupun commit.
//   (b) Karena URL request memuat kunci, pesan galat runtime disanitasi `describeError` di
//       `../http.js` (URL → [url] + token 20+ char → .), sehingga kunci tidak pernah bocor.
//   (c) `threats: []` ATAU body protobuf tanpa field threats = TIDAK ADA ENTRI MATCH = bukan
//       konfirmasi aman. Laporkan `not_found`/`inconclusive`, bukan `clean`.
//   (d) Kegagalan transport / 401 / 403 / 429 / 5xx / JSON rusak / protobuf cacat / timeout /
//       abort semuanya dipetakan fetchJson+failureCheck ke status non-clean; tidak pernah diubah
//       menjadi vonis bersih.
const API_ENDPOINT = 'https://safebrowsing.googleapis.com/v5/urls:search'
const REQUEST_TIMEOUT_MS = 8_000

// Wire type konstanta protobuf (proto3 standard).
const WIRE_VARINT  = 0
const WIRE_FIXED64 = 1
const WIRE_LEN     = 2
const WIRE_FIXED32 = 5

// ThreatType: angka wire → nama enum string (identik dengan nilai string pada respons JSON v4
// sehingga `bandOfThreatType` tetap berlaku tanpa duplikasi logika vonis).
const THREAT_TYPE_NAMES: Record<number, string> = {
  0: 'THREAT_TYPE_UNSPECIFIED',
  1: 'MALWARE',
  2: 'SOCIAL_ENGINEERING',
  3: 'UNWANTED_SOFTWARE',
  4: 'POTENTIALLY_HARMFUL_APPLICATION',
}

function bandOfThreatType(value: unknown): 'malicious' | 'suspicious' {
  const raw = stringValue(value)?.trim().toUpperCase()
  if (raw === 'MALWARE' || raw === 'SOCIAL_ENGINEERING') return 'malicious'
  return 'suspicious'
}

type ThreatEntry = { url: string; threatTypes: string[] }

// ---------- JSON path (kompatibilitas bila Google mengaktifkan JSON di masa depan) ----------
function extractThreats(data: unknown): ThreatEntry[] | null {
  const obj = recordValue(data)
  if (!obj) return null
  if (!('threats' in obj)) return []
  const arr = obj.threats
  if (!Array.isArray(arr)) return null
  const entries: ThreatEntry[] = []
  for (const raw of arr) {
    if (!isRecord(raw)) return null
    const url = stringValue(raw.url) ?? ''
    const types = Array.isArray(raw.threatTypes)
      ? raw.threatTypes.filter((t): t is string => typeof t === 'string')
      : []
    entries.push({ url, threatTypes: types })
  }
  return entries
}

// ---------- Protobuf wire-format decoder (khusus SearchUrlsResponse v5) ----------

// Decode satu varint dari `bytes` mulai posisi `pos`.
// Batas `shift > 49` mencegah kehilangan presisi Number (>2^53).
// SearchUrlsResponse hanya memerlukan varint untuk field number (< 2^7) dan enum (< 2^8),
// serta length-delimited (< 2^32). Tidak ada field 64-bit penuh yang dibaca di sini.
function decodeVarint(bytes: Uint8Array, pos: number): [number, number] | null {
  let result = 0
  let shift = 0
  let i = pos
  while (i < bytes.length) {
    const b = bytes[i]!
    if (shift > 49) return null
    result += (b & 0x7f) * 2 ** shift
    if ((b & 0x80) === 0) return [result, i + 1]
    shift += 7
    i += 1
  }
  return null
}

// Lewati satu field protobuf dari posisi value-nya, kembalikan posisi berikutnya atau `null`.
function skipField(bytes: Uint8Array, pos: number, wireType: number): number | null {
  if (wireType === WIRE_VARINT) {
    const v = decodeVarint(bytes, pos)
    return v ? v[1] : null
  }
  if (wireType === WIRE_FIXED32) return pos + 4 <= bytes.length ? pos + 4 : null
  if (wireType === WIRE_FIXED64) return pos + 8 <= bytes.length ? pos + 8 : null
  if (wireType === WIRE_LEN) {
    const lenResult = decodeVarint(bytes, pos)
    if (!lenResult) return null
    const end = lenResult[1] + lenResult[0]
    return end <= bytes.length ? end : null
  }
  // Wire type 3/4 (group start/end) ditinggalkan di proto3; anggap cacat.
  return null
}

const TEXT_DECODER = new TextDecoder('utf-8', { fatal: false })

// Decode satu `ThreatUrl` sub-message yang berada pada bytes[offset .. offset+length-1].
// Field sah: 1 = url (string), 2 = threatTypes (repeated enum, packed ATAU unpacked).
// Field tak dikenal dilewati. Mengembalikan `null` bila bytes cacat.
function decodeThreatUrl(bytes: Uint8Array, offset: number, length: number): ThreatEntry | null {
  const end = offset + length
  if (end > bytes.length) return null

  let url = ''
  const threatTypes: string[] = []
  let pos = offset

  while (pos < end) {
    const keyResult = decodeVarint(bytes, pos)
    if (!keyResult) return null
    const [key, keyEnd] = keyResult
    pos = keyEnd

    const fieldNum = Math.floor(key / 8)
    const wireType = key % 8

    if (fieldNum === 1 && wireType === WIRE_LEN) {
      // url (field 1, string/bytes)
      const lenResult = decodeVarint(bytes, pos)
      if (!lenResult) return null
      const strStart = lenResult[1]
      const strEnd = strStart + lenResult[0]
      if (strEnd > end) return null
      url = TEXT_DECODER.decode(bytes.subarray(strStart, strEnd))
      pos = strEnd
    } else if (fieldNum === 2 && wireType === WIRE_VARINT) {
      // threatTypes — satu nilai enum per field occurrence (unpacked repeated)
      const v = decodeVarint(bytes, pos)
      if (!v) return null
      threatTypes.push(THREAT_TYPE_NAMES[v[0]] ?? `UNKNOWN_${v[0]}`)
      pos = v[1]
    } else if (fieldNum === 2 && wireType === WIRE_LEN) {
      // threatTypes — packed repeated enum
      const lenResult = decodeVarint(bytes, pos)
      if (!lenResult) return null
      const packStart = lenResult[1]
      const packEnd = packStart + lenResult[0]
      if (packEnd > end) return null
      let p = packStart
      while (p < packEnd) {
        const v = decodeVarint(bytes, p)
        if (!v) return null
        threatTypes.push(THREAT_TYPE_NAMES[v[0]] ?? `UNKNOWN_${v[0]}`)
        p = v[1]
      }
      pos = packEnd
    } else {
      const next = skipField(bytes, pos, wireType)
      if (next === null) return null
      pos = next
    }
  }

  return { url, threatTypes }
}

// Decode `SearchUrlsResponse` (v5) dari bytes protobuf mentah.
// Field sah: 1 = threats (repeated ThreatUrl), 2 = cache_duration (Duration). Field lain
// dilewati. `cache_duration` dibaca karena merupakan rekomendasi umur resmi dari Google:
// cache VERIGUARD memotong TTL miliknya sendiri agar tidak pernah lebih lama daripada yang
// dijanjikan penyedia. Body kosong (0 byte) = valid no-match (proto3 elision field default).
function decodeDurationSeconds(bytes: Uint8Array, offset: number, length: number): number | null {
  const end = offset + length
  if (end > bytes.length) return null

  let pos = offset
  let seconds: number | null = null

  while (pos < end) {
    const keyResult = decodeVarint(bytes, pos)
    if (!keyResult) return null
    const [key, keyEnd] = keyResult
    pos = keyEnd

    const fieldNum = Math.floor(key / 8)
    const wireType = key % 8

    if (fieldNum === 1 && wireType === WIRE_VARINT) {
      const value = decodeVarint(bytes, pos)
      if (!value) return null
      seconds = value[0]
      pos = value[1]
    } else {
      const next = skipField(bytes, pos, wireType)
      if (next === null) return null
      pos = next
    }
  }

  return seconds
}

export type ProtobufSearchResult = {
  threats: ThreatEntry[]
  cacheDurationSeconds: number | null
}

function decodeProtobufThreats(bytes: Uint8Array): ProtobufSearchResult | null {
  const threats: ThreatEntry[] = []
  let cacheDurationSeconds: number | null = null
  let pos = 0

  while (pos < bytes.length) {
    const keyResult = decodeVarint(bytes, pos)
    if (!keyResult) return null
    const [key, keyEnd] = keyResult
    pos = keyEnd

    const fieldNum = Math.floor(key / 8)
    const wireType = key % 8

    if (fieldNum === 1 && wireType === WIRE_LEN) {
      // threats — repeated ThreatUrl (length-delimited)
      const lenResult = decodeVarint(bytes, pos)
      if (!lenResult) return null
      const subStart = lenResult[1]
      const subLen = lenResult[0]
      const subEnd = subStart + subLen
      if (subEnd > bytes.length) return null
      const entry = decodeThreatUrl(bytes, subStart, subLen)
      if (entry === null) return null
      threats.push(entry)
      pos = subEnd
    } else if (fieldNum === 2 && wireType === WIRE_LEN) {
      // cache_duration — Duration { seconds = 1; nanos = 2 }
      const lenResult = decodeVarint(bytes, pos)
      if (!lenResult) return null
      const subStart = lenResult[1]
      const subLen = lenResult[0]
      const subEnd = subStart + subLen
      if (subEnd > bytes.length) return null
      cacheDurationSeconds = decodeDurationSeconds(bytes, subStart, subLen)
      pos = subEnd
    } else {
      // Field tak dikenal — skip.
      const next = skipField(bytes, pos, wireType)
      if (next === null) return null
      pos = next
    }
  }

  return { threats, cacheDurationSeconds }
}

// ---------- Vonis bersama ----------
// Dibangun dari daftar ThreatEntry (dari JSON ATAU protobuf) sehingga vonis VERIGUARD identik
// untuk kedua format. Tidak pernah menghasilkan `clean` dari ketiadaan match.
function verdictFromThreats(
  threats: ThreatEntry[],
  context: { now: () => number },
  cacheDurationSeconds: number | null,
): ProviderCheck {
  const cacheHint =
    cacheDurationSeconds === null || !Number.isFinite(cacheDurationSeconds) || cacheDurationSeconds <= 0
      ? {}
      : { providerCacheSeconds: cacheDurationSeconds }

  if (threats.length === 0) {
    return {
      status: 'not_found',
      verdict: 'inconclusive',
      score: null,
      summary: 'Google Safe Browsing tidak memiliki entri ancaman untuk URL ini.',
      signals: [
        {
          label: 'Cakupan penelusuran',
          detail:
            'Ditanyakan ke Google Safe Browsing v5 urls:search (MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION).',
          severity: 'info',
        },
      ],
      reason:
        'Ketiadaan match hanya berarti URL belum tercatat pada list yang ditanyakan; BUKAN konfirmasi bahwa URL ini aman.',
      // VGL-31 TAHAP 2 — status tetap `not_found`: daftar yang kosong adalah ketiadaan entri,
      // bukan vonis. Yang boleh ditambahkan adalah bukti negatif TERBATAS, karena lookup-nya
      // benar-benar berhasil dan Google menjawab kosong untuk keempat kategori yang ditanyakan.
      negative: {
        strength: 'limited',
        scope: 'url',
        evidenceClass: 'threat_list',
        basis:
          'Permintaan ke Google Safe Browsing berhasil dan daftar ancaman menjawab kosong untuk MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, dan POTENTIALLY_HARMFUL_APPLICATION pada URL ini.',
      },
      ...cacheHint,
    }
  }

  let verdict: ProviderVerdict = 'suspicious'
  const typesSeen: string[] = []
  for (const entry of threats) {
    if (entry.threatTypes.length === 0) {
      typesSeen.push('UNSPECIFIED')
      continue
    }
    for (const t of entry.threatTypes) {
      typesSeen.push(t)
      if (bandOfThreatType(t) === 'malicious') verdict = 'malicious'
    }
  }

  const uniqueTypes = [...new Set(typesSeen)]
  const score = verdict === 'malicious' ? 85 : 55

  return {
    status: 'success',
    verdict,
    score,
    summary: `Google Safe Browsing menandai URL ini pada list: ${uniqueTypes.join(', ')}.`,
    signals: [
      {
        label: 'List Google yang menyala',
        detail: uniqueTypes.join(', '),
        severity: verdict === 'malicious' ? 'danger' : 'warning',
      },
    ],
    reason:
      'Vonis berasal dari pemeriksaan real-time terhadap Google Safe Browsing v5 urls:search; threatType yang tidak terpetakan tetap diperlakukan sebagai sinyal ancaman, bukan bukti bersih.',
    evidence: {
      source: 'new_scan',
      observedAt: new Date(context.now()).toISOString(),
      ageMs: 0,
    },
    ...cacheHint,
  }
}

// ---------- Format respons ----------
// Content-Type NYATA menentukan parser. Tidak ada asumsi "HTTP 200 pasti JSON": tipe yang tidak
// dikenal/diabaikan proxy disniff dari byte, dan kegagalan parse tetap `error` (bukan no-match).
const PROTOBUF_CONTENT_TYPES = new Set([
  'application/x-protobuf',
  'application/protobuf',
  'application/octet-stream',
  'binary/protobuf',
])

type BodyFormat = 'protobuf' | 'json' | 'unknown'

function classifyBodyFormat(contentType: string): BodyFormat {
  const type = contentType.split(';')[0].trim().toLowerCase()
  if (!type) return 'unknown'
  if (PROTOBUF_CONTENT_TYPES.has(type)) return 'protobuf'
  if (type === 'application/json' || type.endsWith('+json') || type.startsWith('text/')) {
    return 'json'
  }
  return 'unknown'
}

type BodyParse =
  | { ok: true; threats: ThreatEntry[]; cacheDurationSeconds: number | null }
  | { ok: false; reason: string }

function parseProtobufBody(bytes: Uint8Array): BodyParse {
  // Body 0 byte = pesan SearchUrlsResponse kosong (proto3 meng-elide field kosong) = no-match sah.
  if (bytes.length === 0) return { ok: true, threats: [], cacheDurationSeconds: null }

  const decoded = decodeProtobufThreats(bytes)
  if (decoded === null) {
    return {
      ok: false,
      reason:
        'Respons protobuf Google Safe Browsing cacat; struktur wire-format tidak dikenali.',
    }
  }
  return { ok: true, threats: decoded.threats, cacheDurationSeconds: decoded.cacheDurationSeconds }
}

function parseJsonBody(bytes: Uint8Array): BodyParse {
  const rawText = bytes.length === 0 ? '' : TEXT_DECODER.decode(bytes)
  let parsed: unknown = null
  if (rawText.trim().length > 0) {
    try {
      parsed = JSON.parse(rawText)
    } catch {
      return {
        ok: false,
        reason:
          'Respons Google Safe Browsing bukan JSON yang valid; isi body tidak ditampilkan.',
      }
    }
  }

  const threats = parsed === null ? [] : extractThreats(parsed)
  if (threats === null) {
    return {
      ok: false,
      reason:
        'Respons Google Safe Browsing tidak dikenali sebagai objek { threats: [...] } maupun { threats: [] }.',
    }
  }
  return { ok: true, threats, cacheDurationSeconds: null }
}

// Sniffing untuk Content-Type yang tidak membantu: JSON dicoba lebih dulu karena teks bebas
// (halaman proxy, pesan galat plaintext) sering lolos sebagai "protobuf kosong" bila protobuf
// dicoba dahulu — dan itu akan mengubah kegagalan parse menjadi no-match. Sebaliknya body
// protobuf hampir tidak pernah lolos JSON.parse (byte kontrol < 0x20 bukan sintaks JSON sah),
// jadi urutan ini tidak mengorbankan jalur protobuf. Kedua format gagal → satu error terkendali.
function sniffBodyFormat(bytes: Uint8Array): BodyParse {
  if (bytes.length === 0) return { ok: true, threats: [], cacheDurationSeconds: null }

  const json = parseJsonBody(bytes)
  if (json.ok) return json

  const protobuf = parseProtobufBody(bytes)
  if (protobuf.ok) return protobuf

  return {
    ok: false,
    reason:
      'Format respons Google Safe Browsing tidak dikenali; bukan JSON maupun protobuf v5 yang sah.',
  }
}

// ---------- Adapter ----------
export const googleSafeBrowsingAdapter: ProviderAdapter = {
  id: 'safebrowsing',
  label: 'Google Safe Browsing',
  requiredEnv: ['GOOGLE_SAFE_BROWSING_API_KEY'],
  timeoutMs: 20_000,
  isConfigured: (config) => Boolean(config.googleSafeBrowsingApiKey),
  async check(context, config): Promise<ProviderCheck> {
    const apiKey = config.googleSafeBrowsingApiKey
    if (!apiKey) {
      return notConfiguredCheck('GOOGLE_SAFE_BROWSING_API_KEY belum dikonfigurasi di backend.')
    }

    const requestUrl =
      `${API_ENDPOINT}?key=${encodeURIComponent(apiKey)}` +
      `&urls=${encodeURIComponent(context.url)}`

    // Mode 'bytes' → body dibaca sebagai Uint8Array + Content-Type header tersedia.
    // Ini mencegah lossy UTF-8 decode yang terjadi pada respons protobuf biner.
    const result = await fetchJson(
      context.fetchImpl,
      requestUrl,
      { method: 'GET', headers: { Accept: 'application/json' } },
      REQUEST_TIMEOUT_MS,
      'bytes',
    )

    if (!result.ok) {
      // failureCheck sudah memanggil withHttpStatus() di dalam; TIDAK pre-append lagi.
      // Ini memperbaiki bug pesan ganda "Respons agen tidak dapat dibaca. (HTTP 200) (HTTP 200)"
      // yang terjadi ketika failureNote() menambahkan (HTTP N) lalu failureCheck menambah lagi.
      return failureCheck(result)
    }

    const bytes = result.data instanceof Uint8Array ? result.data : new Uint8Array(0)
    const contentType = result.contentType ?? ''
    const format = classifyBodyFormat(contentType)

    const parsed =
      format === 'protobuf'
        ? parseProtobufBody(bytes)
        : format === 'json'
          ? parseJsonBody(bytes)
          : sniffBodyFormat(bytes)

    if (!parsed.ok) return errorCheck(parsed.reason)

    return verdictFromThreats(parsed.threats, context, parsed.cacheDurationSeconds)
  },
}

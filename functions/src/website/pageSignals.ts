import { analyzeForms } from './behavior.js'
import { BRAND_DOMAINS, registrableDomain, secondLabel } from './urlSignals.js'
import type {
  FormAnalysis,
  PageAnalysis,
  PageSignalFinding,
  PageSignalStrength,
} from './types.js'

/**
 * Pemeriksaan isi halaman murni tekstual: dokumen HTML yang sudah diambil probe
 * dibaca sebagai teks. Tidak ada skrip yang dijalankan, tidak ada form yang
 * dikirim, dan tidak ada permintaan baru yang dibuat dari modul ini.
 *
 * Lexicon bahasa (merek darurat, verifikasi akun, OTP dalam teks) sudah ada di
 * category.ts dan sengaja tidak diduplikasi di sini. Yang dikerjakan modul ini
 * adalah struktur halaman: tautan, identitas merek, tujuan form, dan skrip.
 */

const MAX_FINDINGS = 12
const MAX_EVIDENCE_CHARS = 120
const MAX_ANCHOR_SAMPLES = 12

const ANCHOR_PATTERN = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>/gi
const IMG_PATTERN = /<img\b[^>]*>/gi
const IFRAME_PATTERN = /<iframe\b[^>]*>([\s\S]{0,400})<\/iframe\s*>|<iframe\b[^>]*\/?>/gi
const SCRIPT_OPEN_PATTERN = /<script\b[^>]*>/gi

// Kolom yang meminta kode sekali pakai atau data kartu. Kolom Sandi biasa tidak ikut
// dinilai di sini: hampir semua halaman masuk sah punya satu, dan yang menentukan
// panen kredensial adalah ke mana kolom itu dikirim (dihitung dari analisis form).
const CREDENTIAL_NAME_PATTERN =
  /\bname\s*=\s*["']?[^"'>\s]*(?<![a-z])(otp|cvv|cvc|ccv|pin|nomor.?kartu|card.?number)(?![a-z])[^"'>\s]*["']?/i

const SCRIPT_OBFUSCATION: Array<{ pattern: RegExp; label: string; strength: PageSignalStrength }> = [
  { pattern: /\beval\s*\(/i, label: 'eval()', strength: 'weak' },
  { pattern: /\bdocument\.write\s*\(/i, label: 'document.write()', strength: 'weak' },
  { pattern: /\b(atob|unescape)\s*\(/i, label: 'dekoding base64/escape di sisi klien', strength: 'weak' },
  {
    pattern: /String\.fromCharCode\s*\(\s*(?:0x[0-9a-f]+\s*,\s*){8,}/i,
    label: 'ranges of String.fromCharCode',
    strength: 'moderate',
  },
  { pattern: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){15,}/i, label: 'rentetan escape heksadesimal', strength: 'moderate' },
]

const URGENCY_TEXT = [
  /\b(segera|sekarang juga|dalam 24 jam|hari ini|terbatas|kedaluwarsa|diblokir|ditangguhkan|suspensi)\b/i,
  /\b(verify your|account (?:is )?locked|suspended|immediately|within \d+ hours?|expires?)\b/i,
]

const PAYMENT_DIVERSION_PATTERN =
  /\brekening\b[\s\S]{0,60}(?:\d[\d\s.-]{5,}|\b(bca|bri|mandiri|bni|dana|ovo|gopay|link ?aja)\b)|\btransfer (ke|into) (rekening|virtual account)[\s\S]{0,40}\d{6,}/i

const SECURE_BADGE_PATTERN =
  /(?:alt|title|src)\s*=\s*["'][^"']*(ssl|situs.?aman|secure.?site|trustedsite|verisign|symantec|mcaule?y?|geoTrust)[^"']*["']/i

const INTERACTION_LOCK = [
  /oncontextmenu\s*=\s*["'][^"']*return\s+false/i,
  /user-select\s*:\s*none/i,
  /on(?:keydown|keypress|copy|paste|dragstart)\s*=\s*["'][^"']*(?:return\s+false|preventDefault)/i,
]

function evidence(value: string): string {
  const cleaned = value.replace(/[\u0000-\u0020\u007f]/g, ' ').replace(/\s+/g, ' ').trim()
  return cleaned.length > MAX_EVIDENCE_CHARS ? `${cleaned.slice(0, MAX_EVIDENCE_CHARS - 1)}…` : cleaned
}

function push(findings: PageSignalFinding[], finding: PageSignalFinding): void {
  if (findings.length >= MAX_FINDINGS) return
  if (findings.some((entry) => entry.code === finding.code)) return
  findings.push({ ...finding, evidence: finding.evidence ? evidence(finding.evidence) : null })
}

function resolve(value: string, base: string): URL | null {
  try {
    const url = new URL(value.trim(), base)
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
    return url
  } catch {
    return null
  }
}

type AnchorStats = {
  internal: number
  external: number
  externalRegistrables: Array<{ domain: string; count: number }>
}

function examineAnchors(html: string, base: string, pageRegistrable: string | null): AnchorStats {
  const stats: AnchorStats = { internal: 0, external: 0, externalRegistrables: [] }
  const counts = new Map<string, number>()

  for (const match of html.matchAll(ANCHOR_PATTERN)) {
    const raw = match[1] ?? match[2] ?? match[3] ?? ''
    if (!raw || raw.startsWith('#') || raw.startsWith('mailto:') || raw.startsWith('javascript:')) continue
    const url = resolve(raw, base)
    if (!url) continue
    const host = url.hostname.toLowerCase()
    const registrable = registrableDomain(host)
    if (!pageRegistrable || registrable === pageRegistrable) {
      stats.internal += 1
      continue
    }
    stats.external += 1
    counts.set(registrable, (counts.get(registrable) ?? 0) + 1)
  }

  stats.externalRegistrables = [...counts.entries()]
    .sort((left, right) => right[1] - left[1])
    .map(([domain, count]) => ({ domain, count }))
  return stats
}

function brandPresentIn(html: string, core: string): boolean {
  // Batas kata mencegah "apple" cocok di dalam "pineapple" atau "shopee" di dalam
  // kata gabungan lain. Nama merek dalam daftar ini murni huruf, jadi \b aman dipakai.
  return new RegExp(`\\b${core}\\b`, 'i').test(html)
}

/**
 * Identitas merek yang tampil di halaman dibandingkan dengan domain yang benar-benar
 * melayani halaman. Kombinasi "memakai nama merek" + "menaruh tautan resmi merek"
 * + "tujuannya ke host lain" adalah pola halaman klon, sementara salah satu saja
 * belum tentu.
 */
function examineBrandIdentity(input: {
  html: string
  pageRegistrable: string | null
  anchors: AnchorStats
  findings: PageSignalFinding[]
}): void {
  if (!input.pageRegistrable) return

  for (const brand of BRAND_DOMAINS) {
    if (brand.domains.includes(input.pageRegistrable)) return

    const cores = [...new Set(brand.domains.map((domain) => secondLabel(domain)).filter((core) => core.length >= 5))]
    const matchedCore = cores.find((core) => brandPresentIn(input.html, core))
    if (!matchedCore) continue

    push(input.findings, {
      code: 'brand_identity_mismatch',
      label: `Halaman menampilkan identitas ${brand.label} di luar domain resminya`,
      strength: 'moderate',
      detail: `Teks, atribut gambar, atau sumber halaman menyebut "${matchedCore}" sementara domain yang melayani halaman adalah ${input.pageRegistrable}, bukan domain resmi ${brand.label}. Penampilan merek belum membuktikan peniruan: halaman edukasi, ulasan, dan tautan afiliasi juga begitu; yang menaikkan nilai adalah bukti lain yang mendukung.`,
      evidence: `${brand.label} @ ${input.pageRegistrable}`,
    })

    const official = brand.domains.find((domain) =>
      input.anchors.externalRegistrables.some((entry) => entry.domain === domain),
    )
    if (official) {
      push(input.findings, {
        code: 'brand_anchor_target',
        label: `Tautan halaman menuju domain resmi ${brand.label}`,
        strength: 'weak',
        detail: `Halaman yang bukan milik ${brand.label} menautkan ke ${official}. Halaman klon sering meninggalkan tautan merek asli (logo, kebijakan privasi, bantuan) yang masih menunjuk situs resmi.`,
        evidence: official,
      })
    }
    return
  }
}

function examineCredentialFields(input: {
  html: string
  forms: FormAnalysis
  pageRegistrable: string | null
  findings: PageSignalFinding[]
}): void {
  const otpOrPin = CREDENTIAL_NAME_PATTERN.test(input.html)
  const harvestTarget = input.forms.forms.filter(
    (form) => form.passwordFields > 0 && form.actionHost !== null && input.pageRegistrable !== null &&
      registrableDomain(form.actionHost) !== input.pageRegistrable,
  )

  if (input.forms.totals.passwordFields > 0 && harvestTarget.length > 0) {
    push(input.findings, {
      code: 'credential_request',
      label: 'Kolom sandi dikirim ke host lain',
      strength: 'moderate',
      detail: `${harvestTarget.length} form dengan kolom Sandi memiliki action ke host di luar domain halaman (${harvestTarget.map((form) => form.actionHost).filter(Boolean).join(', ')}). Halaman masuk biasa mengirim kredensial ke domainnya sendiri, jadi perbedaan tujuan inilah yang dinilai, bukan keberadaan form login.`,
      evidence: harvestTarget.map((form) => form.action).filter(Boolean).join(' | '),
    })
    return
  }

  if (otpOrPin) {
    push(input.findings, {
      code: 'credential_request',
      label: 'Halaman meminta OTP, PIN, atau data kartu',
      strength: 'moderate',
      detail: 'Terdapat kolom dengan nama yang meminta OTP, PIN, CVV, atau nomor kartu. Sebagian layanan sah juga begitu; yang harus dipastikan adalah ke mana datanya dikirim dan siapa yang meminta.',
      evidence: input.html.match(CREDENTIAL_NAME_PATTERN)?.[0] ?? null,
    })
  }
}

function examineScripts(input: {
  html: string
  base: string
  pageRegistrable: string | null
  findings: PageSignalFinding[]
}): PageAnalysis['scripts'] {
  let total = 0
  let external = 0
  let inline = 0

  for (const match of input.html.matchAll(SCRIPT_OPEN_PATTERN)) {
    total += 1
    const tag = match[0] ?? ''
    const src = /src\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(tag)
    const raw = src?.[1] ?? src?.[2] ?? src?.[3]
    if (!raw) {
      inline += 1
      continue
    }
    const url = resolve(raw, input.base)
    if (!url) continue
    if (!input.pageRegistrable || registrableDomain(url.hostname.toLowerCase()) === input.pageRegistrable) continue
    external += 1
  }

  for (const entry of SCRIPT_OBFUSCATION) {
    if (!entry.pattern.test(input.html)) continue
    push(input.findings, {
      code: 'script_obfuscation',
      label: `Pola skrip yang menyamarkan isi (${entry.label})`,
      strength: entry.strength,
      detail: `Dokumen memuat ${entry.label}. Pustaka produksi juga memakai bentuk ini, jadi yang dinilai adalah keberadaannya bersama bukti lain; scanner ini tidak menjalankan skrip halaman sehingga apa yang sebenarnya dilakukan skrip tersebut tidak dapat dipastikan.`,
      evidence: input.html.match(entry.pattern)?.[0] ?? entry.label,
    })
  }

  const metaRefresh = /<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*>/i.exec(input.html)?.[0] ?? null
  if (metaRefresh) {
    const target = /url\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))/i.exec(metaRefresh)
    const rawTarget = target?.[1] ?? target?.[2] ?? target?.[3] ?? null
    const url = rawTarget ? resolve(rawTarget, input.base) : null
    const crossDomain =
      url !== null && input.pageRegistrable !== null && registrableDomain(url.hostname.toLowerCase()) !== input.pageRegistrable
    push(input.findings, {
      code: 'meta_refresh_redirect',
      label: crossDomain ? 'Meta refresh menuju domain lain' : 'Halaman menyegarkan diri otomatis',
      strength: crossDomain ? 'moderate' : 'weak',
      detail: crossDomain
        ? `<meta http-equiv="refresh" memindahkan pengunjung ke ${url?.hostname ?? 'tujuan yang tidak terbaca'} tanpa interaksi. Pengalihan semacam ini dipakai untuk menyembunyikan tujuan sebenarnya dari pratinjau tautan.`
        : 'Meta refresh terdeteksi. Halaman yang berpindah sendiri dapat menyembunyikan apa yang sebenarnya dibaca pengguna.',
      evidence: metaRefresh,
    })
  }

  const locationWrite = /\b(?:window\.)?(?:location(?:\.href)?|document\.location)\s*=\s*["']https?:\/\/[^"']{4,120}["']/i.exec(
    input.html,
  )
  if (locationWrite?.[0]) {
    const rawTarget = /["'](https?:\/\/[^"']+)["']/i.exec(locationWrite[0])?.[1] ?? null
    const url = rawTarget ? resolve(rawTarget, input.base) : null
    const crossDomain =
      url !== null && input.pageRegistrable !== null && registrableDomain(url.hostname.toLowerCase()) !== input.pageRegistrable
    push(input.findings, {
      code: 'script_location_redirect',
      label: crossDomain ? 'Skrip mengarahkan ke domain lain' : 'Skrip mengubah alamat halaman',
      strength: crossDomain ? 'moderate' : 'weak',
      detail: crossDomain
        ? `Teks skrip menuliskan pengalihan ke ${url?.hostname}. Pemeriksaan ini hanya membaca teksnya dan tidak menjalankan skrip, jadi pengalihan itu bisa saja tidak pernah terjadi.`
        : 'Teks skrip menuliskan perubahan alamat. Pola seperti ini lazim pada halaman transisi dan juga pada halaman penipu.',
      evidence: locationWrite[0],
    })
  }

  const hiddenFrame = [...input.html.matchAll(IFRAME_PATTERN)].some((match) => {
    const tag = match[0] ?? ''
    return /display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*["']?[1-9]["']?\s|height\s*=\s*["']?[1-9]["']?\s/i.test(tag)
  })
  if (hiddenFrame) {
    push(input.findings, {
      code: 'hidden_frame',
      label: 'Iframe tersembunyi atau berukuran nyaris nol',
      strength: 'weak',
      detail: 'Dokumen memuat iframe yang disembunyikan atau berukuran sangat kecil. Bentuk ini dipakai untuk penyisipan konten, dan juga untuk halaman masuk palsu di dalam halaman lain.',
      evidence: input.html.match(IFRAME_PATTERN)?.[0] ?? null,
    })
  }

  return { total, external, inline }
}

function examineVisibleText(input: {
  html: string
  pageSecure: boolean
  findings: PageSignalFinding[]
}): void {
  const visible = input.html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .slice(0, 20_000)

  const urgencyHits = URGENCY_TEXT.filter((pattern) => pattern.test(visible))
  if (urgencyHits.length > 0) {
    push(input.findings, {
      code: 'urgency_language',
      label: 'Bahasa mendesak pada halaman',
      strength: 'weak',
      detail: `Teks yang terlihat memuat ${urgencyHits.length} pola urgensi (mis. "${visible.match(URGENCY_TEXT[0]!)?.[0] ?? ''}"). Desakan adalah teknik rekayasa sosial, tetapi halaman promosi sah juga memakainya.`,
      evidence: visible.slice(0, 100),
    })
  }

  if (PAYMENT_DIVERSION_PATTERN.test(visible)) {
    push(input.findings, {
      code: 'payment_diversion',
      label: 'Instruksi transfer ke rekening tertentu',
      strength: 'moderate',
      detail: 'Halaman menampilkan permintaan transfer ke nomor rekening atau penyedia dompet digital. Pada marketplace resmi bentuk ini juga ada; yang membuatnya berat adalah kombinasi dengan identitas merek yang salah atau kolom kredensial.',
      evidence: visible.match(PAYMENT_DIVERSION_PATTERN)?.[0] ?? null,
    })
  }

  if (SECURE_BADGE_PATTERN.test(input.html)) {
    push(input.findings, {
      code: 'fake_secure_badge',
      label: 'Lencana "aman" dipasang sendiri oleh halaman',
      strength: input.pageSecure ? 'weak' : 'moderate',
      detail: input.pageSecure
        ? 'Dokumen memuat gambar atau atribut bertema lencana keamanan/SSL. Lencana seperti ini tidak diterbitkan browser dan bisa dipasang halaman mana pun, jadi tidak ikut membuktikan apa pun.'
        : 'Halaman mengklaim keamanan lewat lencana SSL/situs aman padahal koneksi ke halaman tidak terenkripsi. Klaim tersebut tidak dapat benar pada halaman http.',
      evidence: input.html.match(SECURE_BADGE_PATTERN)?.[0] ?? null,
    })
  }

  const lockHits = INTERACTION_LOCK.filter((pattern) => pattern.test(input.html)).length
  if (lockHits >= 2) {
    push(input.findings, {
      code: 'interaction_lock',
      label: 'Interaksi browser dibatasi halaman',
      strength: 'weak',
      detail: `Halaman mencoba menonaktifkan menu klik kanan, salin/tempel, atau pemilihan teks (${lockHits} pola). Situs yang melindungi kontennya juga memakai ini, dan efeknya tidak dapat dipastikan tanpa menjalankan skrip.`,
      evidence: null,
    })
  }
}

export function analyzePageContent(input: {
  html: string | null
  baseUrl: string | null
  pageHost: string
  pageSecure: boolean
  registrableDomain: string | null
  forms?: FormAnalysis
  bytesScanned?: number
  truncated?: boolean
  detail?: string
}): PageAnalysis {
  const forms =
    input.forms ??
    analyzeForms({
      html: input.html,
      baseUrl: input.baseUrl,
      pageHost: input.pageHost,
      pageSecure: input.pageSecure,
    })

  if (!input.html || !input.baseUrl) {
    return {
      status: 'unavailable',
      inspected: false,
      bytesScanned: 0,
      truncated: input.truncated === true,
      anchors: { internal: 0, external: 0, externalHosts: [], ratio: null },
      scripts: { total: 0, external: 0, inline: 0 },
      forms,
      findings: [],
      notes: [
        input.detail ??
          'Dokumen HTML tidak tersedia, jadi isi halaman (tautan, form, identitas merek, skrip) tidak dapat diperiksa.',
        'Ketiadaan dokumen bukan bukti bahwa halaman aman.',
      ],
    }
  }

  const findings: PageSignalFinding[] = []
  const pageRegistrable = input.registrableDomain
  const anchors = examineAnchors(input.html, input.baseUrl, pageRegistrable)

  examineBrandIdentity({ html: input.html, pageRegistrable, anchors, findings })
  examineCredentialFields({ html: input.html, forms, pageRegistrable, findings })
  const scripts = examineScripts({ html: input.html, base: input.baseUrl, pageRegistrable, findings })
  examineVisibleText({ html: input.html, pageSecure: input.pageSecure, findings })

  const anchorTotal = anchors.internal + anchors.external
  if (anchorTotal >= 5 && anchors.external / anchorTotal >= 0.8) {
    push(findings, {
      code: 'anchor_external_ratio',
      label: 'Hampir semua tautan keluar menuju host lain',
      strength: 'weak',
      detail: `Dari ${anchorTotal} tautan yang terbaca, ${anchors.external} menuju domain lain dan hanya ${anchors.internal} yang tetap di domain halaman. Halaman arahan (landing) sah juga bisa begitu, jadi rasio ini hanya konteks.`,
      evidence: anchors.externalRegistrables.slice(0, MAX_ANCHOR_SAMPLES).map((entry) => `${entry.domain} (${entry.count})`).join(', '),
    })
  }

  return {
    status: 'complete',
    inspected: true,
    bytesScanned: input.bytesScanned ?? input.html.length,
    truncated: input.truncated === true,
    anchors: {
      internal: anchors.internal,
      external: anchors.external,
      externalHosts: anchors.externalRegistrables.slice(0, MAX_ANCHOR_SAMPLES).map((entry) => entry.domain),
      ratio: anchorTotal > 0 ? Number((anchors.external / anchorTotal).toFixed(2)) : null,
    },
    scripts,
    forms,
    findings,
    notes: [
      'Isi halaman dibaca sebagai teks statis. Tidak ada JavaScript yang dijalankan, tidak ada form yang dikirim, dan tidak ada permintaan tambahan ke alamat yang muncul di halaman.',
      'Kode atribut dan teks dianggap tidak tepercaya; bukti yang dilaporkan adalah apa yang tertulis, bukan apa yang akan dilakukan browser.',
      'Temuan di sini sengaja tidak menilai tampilan visual atau kemiripan logo. Tanpa gambar referensi resmi dan metode pembanding yang divalidasi, klaim "halaman ini meniru tampilan merek" tidak dapat dipertanggungjawabkan.',
    ],
  }
}

import type {
  HttpResponseInfo,
  SectionStatus,
  WebsiteCategoryAssessment,
  WebsiteCategoryConfidence,
  WebsiteCategoryId,
  WebsiteCategorySignal,
  WebsiteCategorySignalSource,
} from './types.js'

const RISK_CATEGORY_IDS = new Set<WebsiteCategoryId>(['gambling', 'phishing', 'scam', 'malware'])

const CATEGORY_LABEL: Record<WebsiteCategoryId, string> = {
  gambling: 'Judi online',
  phishing: 'Phishing',
  scam: 'Penipuan',
  malware: 'Malware',
  marketplace: 'Marketplace',
  banking: 'Perbankan / finansial',
  government: 'Pemerintahan',
  education: 'Pendidikan',
  media: 'Media',
  social: 'Media sosial',
  technology: 'Teknologi',
  entertainment: 'Hiburan',
  business: 'Bisnis',
  blog: 'Blog / informasi',
  personal: 'Website pribadi',
  unknown: 'Tidak diketahui',
}

type Strength = WebsiteCategorySignal['strength']

const STRENGTH_WEIGHT: Record<Strength, number> = {
  strong: 3,
  moderate: 2,
  weak: 1,
}

type LexiconEntry = {
  pattern: RegExp
  label: string
  strength: Strength
}

const CONTENT_LEXICON: Record<WebsiteCategoryId, LexiconEntry[]> = {
  gambling: [
    { pattern: /\bslot\s+gacor\b/i, label: "'slot gacor'", strength: 'strong' },
    { pattern: /\bjudi\s+online\b/i, label: "'judi online'", strength: 'strong' },
    { pattern: /\bcasino\s+(online|terpercaya)\b/i, label: "'casino online'", strength: 'strong' },
    { pattern: /\btogel\b/i, label: "'togel'", strength: 'strong' },
    { pattern: /\bsports\s?book\b|\bsportsbook\b/i, label: "'sportsbook'", strength: 'moderate' },
    { pattern: /\bparlay\b|\bbandar\b|\bagen\s+slot\b/i, label: "istilah bandar/parlay", strength: 'moderate' },
    { pattern: /\bjackpot\b|\bscatter\b|\bmaxwin\b/i, label: "istilah permainan jackpot", strength: 'moderate' },
    { pattern: /\bdeposit\b[\s\S]{0,40}\bwithdraw\b|\bwd\b\s*slot/i, label: 'aliran deposit/withdraw', strength: 'moderate' },
  ],
  phishing: [
    { pattern: /\bverifikasi\s+akun\b|\bkonfirmasi\s+akun\b/i, label: 'ajakan verifikasi akun', strength: 'strong' },
    { pattern: /\bakun\s+(anda|kamu)\s+(diblokir|dibekukan|ditangguhkan)\b/i, label: 'ancaman akun diblokir', strength: 'strong' },
    { pattern: /\bmasukkan\s+(password|kata\s+sandi|pin|otp)\b/i, label: 'permintaan kredensial', strength: 'strong' },
    { pattern: /\bverify\s+your\s+account\b|\bsign\s+in\s+to\s+secure\b/i, label: 'ajakan verifikasi berbahasa Inggris', strength: 'moderate' },
    { pattern: /\bkode\s+otp\b.*\b(jangan\s+dibagikan|masukkan)\b/is, label: 'permintaan kode OTP', strength: 'moderate' },
  ],
  scam: [
    { pattern: /\b(titip\s+dana|investasikan?\s+dengan\s+jaminan|profit\s+terjamin)\b/i, label: 'janji keuntungan terjamin', strength: 'strong' },
    { pattern: /\b(andata\s+berhak|menang\s+hadiah|klaim\s+hadiah)\b/i, label: 'klaim hadiah', strength: 'moderate' },
    { pattern: /\bbonus\s+baru\s+\d|\bbonus\s+member\b/i, label: 'bonus member', strength: 'moderate' },
    { pattern: /\b(passive\s+income|guaranteed\s+return|double\s+your\s+money)\b/i, label: 'janji imbal hasil tetap', strength: 'strong' },
    { pattern: /\btransfer\s+(sebesar|ke\s+rekening)\b[\s\S]{0,80}\b(sekarang|hari\s+ini)\b/i, label: 'tekanan transfer segera', strength: 'moderate' },
  ],
  malware: [
    { pattern: /\b(crack|keygen|k?rac?ker|patch\s+gratis)\b/i, label: 'istilah perangkat bajakan', strength: 'moderate' },
    { pattern: /\b(download|get)\s+(free|gratis)\b[\s\S]{0,40}\b(installer|setup|\.exe|\.apk)\b/i, label: 'ajakan mengunduh installer', strength: 'moderate' },
  ],
  marketplace: [
    { pattern: /\b(tambahkan\s+ke\s+keranjang|beli\s+sekarang|keranjang\s+belanja)\b/i, label: 'alur keranjang belanja', strength: 'strong' },
    { pattern: /\b(checkout|harga\s+coret|gratis\s+ongkir|jual\s+beli)\b/i, label: 'istilah transaksi dagang', strength: 'moderate' },
    { pattern: /\b(toko\s+online|official\s+store|seller|merchant)\b/i, label: 'istilah toko/penjual', strength: 'moderate' },
  ],
  banking: [
    { pattern: /\b(internet\s+banking|m-?banking|mobile\s+banking)\b/i, label: 'istilah perbankan', strength: 'strong' },
    { pattern: /\b(rekening\s+koran|tabungan|suku\s+bunga|kredit\s+pemilikan)\b/i, label: 'istilah produk bank', strength: 'moderate' },
    { pattern: /\b(pinjaman|pembiayaan|agunan|kpr)\b/i, label: 'istilah kredit/pembiayaan', strength: 'moderate' },
  ],
  government: [
    { pattern: /\bpelayanan\s+publik\b|\bkementerian\b|\bpemerintah\s+provinsi\b/i, label: 'layanan pemerintah', strength: 'moderate' },
  ],
  education: [
    { pattern: /\b(kurikulum|siswa|guru|perkuliahan|sekolah|akademik)\b/i, label: 'istilah pendidikan', strength: 'moderate' },
    { pattern: /\b(calon\s+peserta\s+didik|ppdb|nilai\s+rapor)\b/i, label: 'alur administrasi pendidikan', strength: 'strong' },
  ],
  media: [
    { pattern: /\b(berita\s+terkini|headline|breaking\s+news|redaksi|warta)\b/i, label: 'istilah redaksional', strength: 'moderate' },
    { pattern: /\b(artikel\s+opini|jurnalisme|koresponden|press\s+release)\b/i, label: 'istilah jurnalistik', strength: 'moderate' },
  ],
  social: [
    { pattern: /\b(followers|following|berbagi\s+cerita|postingan\s+terbaru)\b/i, label: 'istilah jejaring sosial', strength: 'moderate' },
    { pattern: /\b(gabung\s+(komunitas|grup)|pertemanan|profil\s+saya)\b/i, label: 'alur komunitas/profil', strength: 'weak' },
  ],
  technology: [
    { pattern: /\b(dokumentasi|api\s+reference|sdk|developer\s+tools|open\s+source)\b/i, label: 'istilah dokumentasi teknis', strength: 'strong' },
    { pattern: /\b(server|cloud|kubernetes|container|runtime|build)\b/i, label: 'istilah infrastruktur', strength: 'weak' },
  ],
  entertainment: [
    { pattern: /\b(nonton\s+film|situs\s+streaming|video\s+terbaru|musik\s+terbaru)\b/i, label: 'istilah hiburan', strength: 'moderate' },
    { pattern: /\b(permainan\s+gratis|game\s+online|trailer)\b/i, label: 'istilah gim/trailer', strength: 'weak' },
  ],
  business: [
    { pattern: /\b(tentang\s+ kami|tentang\s+kami|layanan\s+kami|kontak\s+kami)\b/i, label: 'halaman perusahaan', strength: 'moderate' },
    { pattern: /\b\s(pt\.|cv\.|perseroan)\b/i, label: 'badan usaha', strength: 'moderate' },
  ],
  blog: [
    { pattern: /\b(diposting\s+oleh|posted\s+by|read\s+more|selanjutnya\s+→|arsip\s+pos)\b/i, label: 'struktur blog', strength: 'moderate' },
    { pattern: /\b(komentar|komentar\s+pembaca)\b/i, label: 'kolom komentar', strength: 'weak' },
  ],
  personal: [
    { pattern: /\b(halaman\s+pribadi|personal\s+(site|page)|my\s+portfolio)\b/i, label: 'penanda situs pribadi', strength: 'moderate' },
  ],
  unknown: [],
}

const DOMAIN_LEXICON: Array<{ pattern: RegExp; categoryId: WebsiteCategoryId; label: string }> = [
  { pattern: /(^|[.-])(slot|judi|bet[0-9]?|casino|togel|parlay)([.-]|$)/i, categoryId: 'gambling', label: 'pola nama domain perjudian' },
  { pattern: /(^|[.-])(login|verify|secure|account)([.-]|$)/i, categoryId: 'phishing', label: 'pola nama host halaman masuk/verifikasi' },
  { pattern: /(^|[.-])(download|soft|apk|exe)([.-]|$)/i, categoryId: 'malware', label: 'pola nama host unduhan perangkat' },
  { pattern: /(^|[.-])(shop|store|market|toko)([.-]|$)/i, categoryId: 'marketplace', label: 'pola nama host toko' },
]

const PATH_LEXICON: Array<{ pattern: RegExp; categoryId: WebsiteCategoryId; label: string }> = [
  { pattern: /\/(slot|casino|togel|sports|parlay)(\/|$)/i, categoryId: 'gambling', label: 'struktur jalur URL perjudian' },
  { pattern: /\/(login|signin|verify|authorization)(\/|$)/i, categoryId: 'phishing', label: 'jalur URL halaman masuk' },
  { pattern: /\/(download|release)\/[^/]*\.(exe|msi|apk|zip)\b/i, categoryId: 'malware', label: 'jalur URL berkas executable' },
]

const COUNTRY_CODE_TLD: Array<{ pattern: RegExp; categoryId: WebsiteCategoryId; label: string }> = [
  { pattern: /\.(go|mil)\.[a-z]{2}$/i, categoryId: 'government', label: 'domain tingkat kedua khusus pemerintahan' },
  { pattern: /\.(gov|gc)\.[a-z]{2}$/i, categoryId: 'government', label: 'domain pemerintah resmi' },
  { pattern: /\.(sch|ac)\.[a-z]{2}$/i, categoryId: 'education', label: 'domain institusi pendidikan' },
  { pattern: /\.edu(\.[a-z]{2})?$/i, categoryId: 'education', label: 'domain pendidikan' },
  { pattern: /\.bank$/i, categoryId: 'banking', label: 'domain sektor perbankan' },
]

const MAX_SIGNALS = 6
const MAX_ALTERNATIVES = 3
const DETAIL_LIMIT = 220
const TITLE_LIMIT = 180
const DESCRIPTION_LIMIT = 320
const VISIBLE_TEXT_LIMIT = 20_000

function clip(value: string, max: number): string {
  const trimmed = value.trim()
  return trimmed.length > max ? `${trimmed.slice(0, max - 1).trimEnd()}…` : trimmed
}

function decodeBasicEntities(value: string): string {
  return value
    .replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (match) => {
      const named: Record<string, string> = {
        '&amp;': '&',
        '&lt;': '<',
        '&gt;': '>',
        '&quot;': '"',
        '&#39;': "'",
        '&nbsp;': ' ',
      }
      return named[match.toLowerCase()] ?? ' '
    })
}

function singleLine(value: string): string {
  return decodeBasicEntities(value).replace(/\s+/g, ' ').trim()
}

function firstMatch(html: string, patterns: RegExp[]): string | null {
  for (const pattern of patterns) {
    const match = html.match(pattern)
    const raw = match?.[1]
    if (raw) {
      const text = singleLine(raw)
      if (text) return text
    }
  }
  return null
}

const TITLE_PATTERNS = [/<title[^>]*>([\s\S]{1,600}?)<\/title>/i, /<meta[^>]+property=["']og:title["'][^>]*content=["']([^"']{1,600})["']/i]
const DESCRIPTION_PATTERNS = [
  /<meta[^>]+name=["']description["'][^>]*content=["']([^"']{1,900})["']/i,
  /<meta[^>]+content=["']([^"']{1,900})["'][^>]*name=["']description["']/i,
  /<meta[^>]+property=["']og:description["'][^>]*content=["']([^"']{1,900})["']/i,
]
const KEYWORD_PATTERNS = [/<meta[^>]+name=["']keywords["'][^>]*content=["']([^"']{1,600})["']/i]

function extractVisibleText(html: string): string {
  const withoutDocuments = html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
  const text = withoutDocuments
    .replace(/<[^>]+>/g, ' ')
    .replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (match) => {
      const named: Record<string, string> = {
        '&amp;': ' ',
        '&lt;': ' ',
        '&gt;': ' ',
        '&nbsp;': ' ',
        '&quot;': ' ',
        '&#39;': ' ',
      }
      return named[match.toLowerCase()] ?? ' '
    })
  return text.replace(/\s+/g, ' ').trim().slice(0, VISIBLE_TEXT_LIMIT)
}

type ContentFields = {
  title: string | null
  description: string | null
  keywords: string | null
  visibleText: string
}

function readContentFields(html: string | null): ContentFields {
  if (!html) return { title: null, description: null, keywords: null, visibleText: '' }
  return {
    title: firstMatch(html, TITLE_PATTERNS),
    description: firstMatch(html, DESCRIPTION_PATTERNS),
    keywords: firstMatch(html, KEYWORD_PATTERNS),
    visibleText: extractVisibleText(html),
  }
}

function labelOf(categoryId: WebsiteCategoryId): string {
  return CATEGORY_LABEL[categoryId] ?? CATEGORY_LABEL.unknown
}

function isRiskCategory(categoryId: WebsiteCategoryId): boolean {
  return RISK_CATEGORY_IDS.has(categoryId)
}

function bumpStrength(strength: Strength): Strength {
  if (strength === 'strong') return 'strong'
  return strength === 'moderate' ? 'strong' : 'moderate'
}

function collectContentSignals(
  fields: ContentFields,
  existing: WebsiteCategorySignal[],
): void {
  const haystacks: Array<{ text: string; where: string; boost: boolean; source: 'content' }> = [
    { text: fields.title ?? '', where: 'Judul halaman', boost: true, source: 'content' },
    { text: fields.description ?? '', where: 'Meta deskripsi', boost: true, source: 'content' },
    { text: fields.keywords ?? '', where: 'Meta kata kunci', boost: false, source: 'content' },
    { text: fields.visibleText, where: 'Teks yang terlihat pada halaman', boost: false, source: 'content' },
  ]

  for (const [categoryId, entries] of Object.entries(CONTENT_LEXICON) as Array<
    [WebsiteCategoryId, LexiconEntry[]]
  >) {
    for (const entry of entries) {
      for (const haystack of haystacks) {
        if (!haystack.text) continue
        if (!entry.pattern.test(haystack.text)) continue

        const matched = haystack.text.match(entry.pattern)?.[0] ?? ''
        const strength = haystack.boost ? bumpStrength(entry.strength) : entry.strength
        pushSignal(
          existing,
          categoryId,
          `${labelOf(categoryId)}: ${entry.label}`,
          `${haystack.where} memuat ${clip(matched, 60)} (kekuatan ${strength}).`,
          haystack.source,
          strength,
        )
        break
      }
    }
  }
}

function pushSignal(
  bucket: WebsiteCategorySignal[],
  categoryId: WebsiteCategoryId,
  label: string,
  rawDetail: string,
  source: WebsiteCategorySignalSource,
  strength: Strength,
): void {
  if (bucket.some((signal) => signal.categoryId === categoryId && signal.label === label)) return
  if (bucket.length >= MAX_SIGNALS) return
  const detail = rawDetail.length > DETAIL_LIMIT ? `${rawDetail.slice(0, DETAIL_LIMIT - 1)}…` : rawDetail
  bucket.push({ categoryId, label, detail, source, strength })
}

function collectDomainSignals(
  hostname: string,
  existing: WebsiteCategorySignal[],
): void {
  for (const entry of DOMAIN_LEXICON) {
    if (entry.pattern.test(hostname)) {
      pushSignal(
        existing,
        entry.categoryId,
        `${labelOf(entry.categoryId)}: ${entry.label}`,
        `Nama host \`${clip(hostname, 120)}\` cocok dengan ${entry.label}. Nama host saja tidak cukup untuk menegaskan kategori.`,
        'domain',
        'weak',
      )
    }
  }

  for (const entry of COUNTRY_CODE_TLD) {
    if (entry.pattern.test(hostname)) {
      pushSignal(
        existing,
        entry.categoryId,
        `${labelOf(entry.categoryId)}: ${entry.label}`,
        `Nama host \`${clip(hostname, 120)}\` memakai ${entry.label}.`,
        'domain',
        'strong',
      )
    }
  }
}

function collectStructureSignals(
  finalUrl: string | null,
  redirectCount: number,
  contentType: string | null,
  existing: WebsiteCategorySignal[],
): void {
  const path = (() => {
    if (!finalUrl) return ''
    try {
      const parsed = new URL(finalUrl)
      return `${parsed.pathname}${parsed.search}`
    } catch {
      return ''
    }
  })()

  if (path) {
    for (const entry of PATH_LEXICON) {
      if (entry.pattern.test(path)) {
        pushSignal(
          existing,
          entry.categoryId,
          `${labelOf(entry.categoryId)}: ${entry.label}`,
          `Jalur URL \`${clip(path, 120)}\` cocok dengan ${entry.label}.`,
          'structure',
          'moderate',
        )
      }
    }
  }

  if (/\.(exe|msi|apk|scr|bat|cmd)(\?|$)/i.test(path)) {
    pushSignal(
      existing,
      'malware',
      'Malware: jalur URL menunjuk berkas executable',
      `URL akhir mengakhiri jalur dengan berkas berjenis executable, sehingga distribusi perangkat menjadi perhatian.`,
      'structure',
      'strong',
    )
  }

  if (contentType && /application\/(octet-stream|x-msdownload)/i.test(contentType)) {
    pushSignal(
      existing,
      'malware',
      'Malware: tipe konten berkas biner',
      `Tipe respons \`contentType\` adalah ${clip(contentType, 60)}, bukan halaman HTML.`,
      'network',
      'moderate',
    )
  }

  if (redirectCount >= 3) {
    pushSignal(
      existing,
      'phishing',
      'Phishing: rangkaian redirect panjang',
      `Terdapat ${redirectCount} redirect sebelum halaman akhir; rantai redirect panjang dipakai untuk menyamarkan tujuan.`,
      'structure',
      'weak',
    )
  }
}

function signalsForCategory(
  signals: WebsiteCategorySignal[],
  categoryId: WebsiteCategoryId,
): WebsiteCategorySignal[] {
  return signals.filter((signal) => signal.categoryId === categoryId)
}

function scoreOf(categorySignals: WebsiteCategorySignal[]): number {
  return categorySignals.reduce((total, signal) => total + STRENGTH_WEIGHT[signal.strength], 0)
}

function hasContentSignal(categorySignals: WebsiteCategorySignal[]): boolean {
  return categorySignals.some((signal) => signal.source === 'content')
}

function qualifies(
  categoryId: WebsiteCategoryId,
  categorySignals: WebsiteCategorySignal[],
): boolean {
  const score = scoreOf(categorySignals)
  if (categorySignals.length === 0) return false

  if (isRiskCategory(categoryId)) {
    // Kategori berisiko menuntut bukti ganda: minimal dua sinyal berbeda, skor cukup,
    // dan tidak boleh ditopang oleh nama domain atau struktur URL saja.
    return score >= 5 && categorySignals.length >= 2 && hasContentSignal(categorySignals)
  }

  return score >= 3 || (score >= 2 && categorySignals.length >= 2)
}

function confidenceOf(
  categoryId: WebsiteCategoryId,
  categorySignals: WebsiteCategorySignal[],
): WebsiteCategoryConfidence {
  const score = scoreOf(categorySignals)

  if (isRiskCategory(categoryId)) {
    if (score >= 8 && categorySignals.length >= 3) return 'high'
    if (score >= 6) return 'medium'
    return 'low'
  }

  if (score >= 6 && categorySignals.length >= 3) return 'high'
  if (score >= 4) return 'medium'
  return 'low'
}

function compareCandidates(
  left: { categoryId: WebsiteCategoryId; signals: WebsiteCategorySignal[] },
  right: { categoryId: WebsiteCategoryId; signals: WebsiteCategorySignal[] },
): number {
  const scoreGap = scoreOf(right.signals) - scoreOf(left.signals)
  if (scoreGap !== 0) return scoreGap

  const riskGap = Number(isRiskCategory(right.categoryId)) - Number(isRiskCategory(left.categoryId))
  if (riskGap !== 0) return riskGap

  return left.categoryId.localeCompare(right.categoryId)
}

function summaryFor(
  categoryId: WebsiteCategoryId,
  confidence: WebsiteCategoryConfidence,
  status: SectionStatus,
): string {
  if (categoryId === 'unknown') {
    return status === 'unavailable'
      ? 'Halaman tidak dapat dibaca, jadi kategori belum dapat ditentukan dari bukti yang tersedia.'
      : 'Data yang tersedia belum cukup untuk menentukan kategori website.'
  }

  const lead = confidence === 'high' ? 'Bukti yang terkumpul konsisten dengan' : 'Bukti yang tersedia mengarah ke'
  const tail = isRiskCategory(categoryId)
    ? 'Ini adalah indikasi teknis, bukan penetapan pelanggaran hukum.'
    : 'Kategori menggambarkan jenis situs, bukan penilaian aman atau tidaknya.'

  return `${lead} kategori ${labelOf(categoryId)} berdasarkan konten dan struktur yang diperiksa. ${tail}`
}

export function classifyWebsiteCategory(input: {
  hostname: string
  html: string | null
  response: HttpResponseInfo
}): WebsiteCategoryAssessment {
  const fields = readContentFields(input.html)
  const hasDocument = input.html !== null && fields.visibleText.length > 0

  const signals: WebsiteCategorySignal[] = []
  collectContentSignals(fields, signals)
  collectDomainSignals(input.hostname, signals)
  collectStructureSignals(
    input.response.finalUrl,
    input.response.redirectCount,
    input.response.contentType,
    signals,
  )

  const candidates = (Object.keys(CATEGORY_LABEL) as WebsiteCategoryId[])
    .filter((categoryId) => categoryId !== 'unknown')
    .map((categoryId) => ({ categoryId, signals: signalsForCategory(signals, categoryId) }))
    .filter((candidate) => qualifies(candidate.categoryId, candidate.signals))
    .sort(compareCandidates)

  const notes: string[] = []
  let status: SectionStatus

  if (!hasDocument && input.response.status === null) {
    status = 'unavailable'
    notes.push('Halaman target tidak berhasil dibaca, sehingga kategori hanya dapat dinilai dari nama host dan struktur URL.')
  } else if (!hasDocument) {
    status = 'partial'
    notes.push('Dokumen HTML tidak tersedia atau bukan HTML, jadi isi halaman tidak dapat dibaca untuk klasifikasi.')
  } else {
    status = 'complete'
  }

  const primary = candidates[0]
  const confidence = primary
    ? confidenceOf(primary.categoryId, primary.signals)
    : 'low'
  const primaryId: WebsiteCategoryId = primary ? primary.categoryId : 'unknown'

  if (primary && isRiskCategory(primaryId)) {
    notes.push('Kategori berisiko hanya dinyatakan bila ada beberapa bukti yang saling menguatkan dari konten halaman.')
  }

  if (!primary) {
    notes.push('Tidak ada kategori yang memenuhi ambang bukti; hasil dilaporkan sebagai tidak diketahui alih-alih ditebak.')
  }

  const alternatives = candidates.slice(1, 1 + MAX_ALTERNATIVES).map((candidate) => ({
    id: candidate.categoryId,
    label: labelOf(candidate.categoryId),
    confidence: confidenceOf(candidate.categoryId, candidate.signals),
  }))

  return {
    status,
    primaryId,
    primaryLabel: labelOf(primaryId),
    confidence,
    riskIndicated: primary ? isRiskCategory(primaryId) : false,
    summary: summaryFor(primaryId, confidence, status),
    signals: primary ? primary.signals.slice(0, MAX_SIGNALS) : signals.slice(0, MAX_SIGNALS),
    alternatives,
    evidenceBasis: {
      documentInspected: input.html !== null,
      titleAvailable: fields.title !== null,
      descriptionAvailable: fields.description !== null,
      visibleTextBytes: fields.visibleText.length,
      redirectHops: input.response.redirectCount,
    },
    notes,
  }
}

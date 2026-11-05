import { detectBrand, hostsFromLink, SHORTENERS } from './link'
import { createPattern } from './patterns'
import { buildDraft } from './result'
import {
  extractLinks,
  findMatches,
  isIpHost,
  normalizeWhitespace,
  truncate,
  uppercaseRatio,
} from './text'
import type { AnalysisReason, DetectedPattern, PatternConfidence, PatternId } from './types'
import { AnalysisError, validateMessageInput } from './validate'

const URGENCY_STRONG_PATTERN =
  /\b(segera|secepatnya|mendesak|terburu|terburu-buru|batas waktu|deadline|dalam 24 jam|1x24 jam|24 jam lagi|sekarang juga|hari ini juga|malam ini juga|saat ini juga|jangan sampai|urgent)\b/gi

const URGENCY_GENERIC_PATTERN =
  /\b(sekarang|hari ini|malam ini|24 jam|terakhir|sebelum|terbatas)\b/gi

const THREAT_PATTERN =
  /\b(diblokir|dibekukan|ditangguhkan|disuspend|dibatalkan|denda|tuntutan|polisi|laporkan|hukum|penyalahgunaan|mencurigakan|akun bermasalah|gagal|terdeteksi|tidak aktif|tertahan)\b/gi

const PRIZE_PATTERN =
  /\b(menang|pemenang|hadiah|undian|lotre|gratis|bonus|voucher|cashback|beruntung|kupon|giveaway|juara|uang tunai)\b/gi

const SELAMAT_PATTERN =
  /selamat[^.!?\n]{0,30}(menang|hadiah|pemenang|beruntung)/gi

const MONEY_PATTERN =
  /\b(transfer|biaya admin|biaya|deposit|top ?up|pulsa|tagihan|pembayaran|bayar|rekening|saldo|uang muka|dp|ongkir|bea|pajak)\b/gi

const MONEY_SETTLED_PATTERN =
  /\b(?:sudah|telah|sudah\s+(?:aku|saya|kami))\s+(?:dibayar|bayar|ditransfer|transfer|dilunasi|lunas)\b|\bterbayar\b|\b(?:pembayaran|transfer)\s+(?:sudah|telah|berhasil)\b/i

const AMOUNT_PATTERN =
  /(?:\brp|\bidr)\s?[\d.,]+|\b\d+(?:[.,]\d+)?\s?(?:juta|ribu|jt|rb)\b/gi

// Perintah memindahkan uang ke rekening/orang, bukan sekadar sebutan "transfer".
// Beda konteks: "sudah saya kirim tadi" tidak cocok, "kirim ke rekening ini" cocok.
const TRANSFER_INSTRUCTION_PATTERN =
  /\b(?:kirim|transfer|bayar)\b[^!?\n]{0,60}?\b(?:ke|k|pada)\s+(?:nomor\s+)?(?:rekening|akun|no\.? ?rek|wa|whatsapp|08\d{6,})\b/i

const PERSONAL_PATTERN =
  /\b(nik|ktp|kartu tanda penduduk|kk|npwp|paspor|sim|nomor rekening|nomor kartu|cvv|tanggal lahir|nama ibu|selfie|foto ktp|data pribadi|kode pos|alamat lengkap|pin atm)\b/gi

const INSTITUTION_PATTERN =
  /\b(bank|bca|mandiri|bri|bni|bsi|dana|ovo|gopay|shopee|tokopedia|jne|jnt|sicepat|kurir|whatsapp|instagram|facebook|pajak|djp|bpjs|pln|telkomsel|customer service|cs|admin|petugas|layanan pelanggan)\b/gi

const CREDENTIAL_PATTERN =
  /\b(klik (?:link|tautan)|login|masuk|verifikasi|konfirmasi|validasi|aktivasi|perbarui data|update data|isi (?:data|formulir)|masukkan data|akun (?:anda )?(?:terkunci|diblokir)|pulihkan akun|reset (?:kata sandi|password))\b/gi

const OTP_TERM_PATTERN =
  /\b(otp|pin|password|kata\s+sandi|sandi|kode\s+(?:verifikasi|rahasia|akses|unik)|token)\b/i

const OTP_REQUEST_PATTERN =
  /\b(?:kirim(?:kan)?|masukkan|berikan|sebutkan|balas|bagikan|share|minta|konfirmasi(?:kan)?|verifikasi(?:kan)?|input|isi|aktifkan)\b[^.!?\n]{0,45}\b(?:otp|pin|password|kata\s+sandi|sandi|kode(?:\s+(?:verifikasi|rahasia|akses|unik))?|token)\b/i

const OTP_REQUEST_REVERSED =
  /\b(?:otp|pin|password|kode(?:\s+(?:verifikasi|rahasia|akses|unik))?|token)\b[^.!?\n]{0,35}\b(?:kirim(?:kan)?|berikan|masukkan|balas|dikirim)\b/i

const OTP_NEGATION =
  /jangan\s+(?:pernah\s+)?(?:bagikan|berikan|kirim|sebarkan)|rahasiakan|tidak\s+untuk\s+dibagikan/i

const PHONE_PATTERN = /(?:\+62|62|0)8[1-9][0-9]{6,11}/g

// "tidak/bukan/jangan ..." meniadakan permintaan yang mengikuti kata itu.
// "jangan lupa" justru meminta, jadi dikecualikan.
const NEGATION_IN_CLAUSE = /\b(tidak|tak|bukan|nihil|sia-sia)\b|\bjangan\s+(?!lupa\b)/i

// "tanpa biaya", "bukan hadiah": peniadaan yang menempel pada istilahnya.
// Sengaja tidak dimasukkan ke NEGATION_IN_CLAUSE: "transfer tanpa biaya"
// tetap permintaan transfer, yang ditiadakan hanya kata "biaya"-nya.
const NEGATOR_BEFORE_TERM =
  /(?:^|[\s,;:(])\b(?:tidak|tak|bukan|nihil|sia-sia|tanpa)\b(?:\s+\w+){0,2}\s*$/i

// Satu kata bisa menjadi bukti untuk beberapa kategori (mis. "jne" dipakai
// konteks kurir sekaligus penyebutan institusi). Penanda ini mencegah kata yang
// sama dihitung dua kali sebagai bukti independen.
const COURIER_TERMS = new Set(['jne', 'jnt', 'sicepat'])
const MARKETPLACE_BRANDS = new Set(['shopee', 'tokopedia', 'olx', 'lapak', 'blibli', 'bukalapak'])

type Clause = { start: number; end: number; negated: boolean }

function splitClauses(text: string): Clause[] {
  const clauses: Clause[] = []
  let start = 0

  for (let index = 0; index <= text.length; index += 1) {
    const character = index === text.length ? '\n' : text[index]

    if (/[.!?\n,;:]/.test(character) || index === text.length) {
      if (index > start) {
        const value = text.slice(start, index)
        clauses.push({ start, end: index, negated: NEGATION_IN_CLAUSE.test(value) })
      }
      start = index + 1
    }
  }

  return clauses
}

// Hit yang hanya pernah muncul di dalam klausula bernegasi dikecualikan:
// "saya tidak akan meminta transfer" bukan permintaan transfer.
function unnegatedHits(text: string, patterns: RegExp[]): string[] {
  const clauses = splitClauses(text)
  const positives = new Set<string>()
  const negatives = new Set<string>()

  for (const pattern of patterns) {
    const flags = pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`

    for (const match of text.matchAll(new RegExp(pattern.source, flags))) {
      const value = match[0].trim().toLowerCase()
      if (!value) continue

      const at = match.index ?? 0
      const inside = clauses.filter((clause) => at >= clause.start && at < clause.end)
      const negated =
        (inside.length > 0 && inside.every((clause) => clause.negated)) ||
        NEGATOR_BEFORE_TERM.test(text.slice((inside[0]?.start ?? 0), at))

      if (negated) negatives.add(value)
      else positives.add(value)
    }
  }

  return [...positives].filter((value) => !negatives.has(value))
}

const INVESTMENT_PATTERN =
  /\b(investasi|profit|keuntungan|cuan|return|passive income|crypto|bitcoin|trading|saham|forex|robot trading|titip dana|modal|bonus harian|dijamin|tanpa risiko|pasti untung)\b/gi

// "bunga" berdiri sendiri terlalu sering berarti lain (bunga rampai, promo
// cicilan "tanpa bunga"), jadi hanya diambil dalam konteks imbal hasil.
const INVESTMENT_INTEREST_PATTERN =
  /\b(?:bunga\s+(?:bank|deposito|tabungan|efektif|nominal)|suku\s+bunga)\b/gi

const INVESTMENT_GUARANTEE_PATTERN =
  /\b(dijamin|pasti untung|tanpa risiko|profit pasti|keuntungan pasti|return pasti)\b/i

const INVESTMENT_RETURN_PATTERN =
  /\b\d{1,3}\s?%\s?(?:per|\/|sebulan|sehari|setahun)\b|\b(?:profit|cuan|untung)\s+\d+/i

const JOB_PATTERN =
  /\b(lowongan|kerja|karir|gaji|interview|wawancara|honor|freelance|part time|magang|rekrut|hrd|tugas|like|subscribe|follow|review|tanpa pengalaman|gaji harian)\b/gi

const FEE_PATTERN = /\b(biaya admin|biaya|pajak|ongkir|deposit|modal|transfer|bayar)\b/gi

const MARKETPLACE_PATTERN =
  /\b(jual|beli|toko|penjual|pembeli|order|pesanan|barang|cod|rekber|transfer dulu|kirim barang|marketplace|olx|lapak|stok|dp)\b/gi

const COURIER_PATTERN =
  /\b(paket|kurir|resi|pengiriman|jne|jnt|sicepat|ekspedisi|barang anda|gagal kirim|alamat tidak lengkap|biaya kirim)\b/gi

const CONFIDENCE_RANK: Record<PatternConfidence, number> = {
  low: 0,
  medium: 1,
  high: 2,
}

function raisePattern(
  patterns: DetectedPattern[],
  id: PatternId,
  confidence: PatternConfidence,
) {
  const index = patterns.findIndex((pattern) => pattern.id === id)

  if (index === -1) {
    patterns.push(createPattern(id, confidence))
    return
  }

  if (CONFIDENCE_RANK[confidence] > CONFIDENCE_RANK[patterns[index].confidence]) {
    patterns[index] = createPattern(id, confidence)
  }
}

function addReason(reasons: AnalysisReason[], reason: AnalysisReason) {
  if (!reasons.some((existing) => existing.id === reason.id)) {
    reasons.push(reason)
  }
}

function listHits(hits: string[]): string {
  return hits.slice(0, 3).join(', ')
}

export function analyzeMessage(raw: string) {
  const validation = validateMessageInput(raw)

  if (!validation.ok) {
    throw new AnalysisError(validation.error)
  }

  const text = validation.normalized
  const reasons: AnalysisReason[] = []

  const urgencyStrongHits = findMatches(text, [URGENCY_STRONG_PATTERN])
  const urgencyGenericHits = findMatches(text, [URGENCY_GENERIC_PATTERN])
  const threatHits = unnegatedHits(text, [THREAT_PATTERN])
  const prizeHits = unnegatedHits(text, [PRIZE_PATTERN, SELAMAT_PATTERN])
  const moneyRawHits = findMatches(text, [MONEY_PATTERN])
  const moneyHits = unnegatedHits(text, [MONEY_PATTERN])
  const amountHits = findMatches(text, [AMOUNT_PATTERN])
  const personalHits = unnegatedHits(text, [PERSONAL_PATTERN])
  const credentialHits = unnegatedHits(text, [CREDENTIAL_PATTERN])
  const institutionRaw = findMatches(text, [INSTITUTION_PATTERN])
  const investmentHits = findMatches(text, [INVESTMENT_PATTERN, INVESTMENT_INTEREST_PATTERN])
  const jobHits = findMatches(text, [JOB_PATTERN])
  const marketplaceHits = findMatches(text, [MARKETPLACE_PATTERN])
  const courierHits = findMatches(text, [COURIER_PATTERN])

  // Kata kurir/marketplace sudah dijelaskan oleh alasan konteksnya; tidak
  // dihitung lagi sebagai penyebutan institusi.
  const claimedByContext = new Set<string>([
    ...courierHits.filter((hit) => COURIER_TERMS.has(hit)),
    ...marketplaceHits.filter((hit) => MARKETPLACE_BRANDS.has(hit)),
  ])
  const institutionHits = institutionRaw.filter((hit) => !claimedByContext.has(hit))

  // Satu sumber bukti biaya: dipakai bersama oleh alasan hadiah dan lowongan,
  // bukan dihitung sebagai dua permintaan terpisah.
  const feeWords = unnegatedHits(text, [FEE_PATTERN])

  const links = extractLinks(text)
  // Host pada baris alamat ditambah alamat tujuan yang tertanam di parameter,
  // supaya tautan pengalih juga dinilai sebagai milik pesan ini.
  const linkHosts = [...new Set(links.flatMap((link) => hostsFromLink(link)))]
  const shortenerLink = SHORTENERS.some((shortener) =>
    linkHosts.some((host) => host === shortener || host.endsWith(`.${shortener}`)),
  )
  const ipLink = linkHosts.some((host) => isIpHost(host))
  const brandLink = linkHosts
    .map((host) => detectBrand(host))
    .find((match) => match !== null && match.kind !== 'official')

  const phoneMatches = [...new Set(text.match(PHONE_PATTERN) ?? [])]
  const otpMention = OTP_TERM_PATTERN.test(text)
  const otpRequest =
    !OTP_NEGATION.test(text) &&
    (OTP_REQUEST_PATTERN.test(text) || OTP_REQUEST_REVERSED.test(text))

  const moneySettled = MONEY_SETTLED_PATTERN.test(text)
  const brandLinkCorroborated =
    !brandLink?.glued &&
    (credentialHits.length > 0 ||
      personalHits.length > 0 ||
      threatHits.length > 0 ||
      otpRequest ||
      ipLink)

  // Permintaan biaya yang disertai perintah mengirim ke rekening atau nomor
  // pribadi adalah satu rangkaian bukti: bukti kombinasinya yang diperkuat,
  // bukan kata "biaya" dan "rekening" dihitung dua kali.
  const prizeFee = prizeHits.length > 0 && feeWords.length > 0
  const jobFee = jobHits.length > 0 && feeWords.length > 0
  const transferInstruction = TRANSFER_INSTRUCTION_PATTERN.test(text)
  const investmentGuarantee =
    investmentHits.length > 0 && INVESTMENT_GUARANTEE_PATTERN.test(text)
  const investmentReturn =
    investmentHits.length > 0 && INVESTMENT_RETURN_PATTERN.test(text)

  const letters = text.replace(/[^A-Za-z]/g, '')
  const isShouting = letters.length >= 20 && uppercaseRatio(text) >= 0.5
  const exclamations = (text.match(/!/g) ?? []).length

  if (urgencyStrongHits.length > 0) {
    addReason(reasons, {
      id: 'urgency_language',
      label: 'Tekanan waktu',
      detail: `Pesan mendorong tindakan cepat dengan kata: ${listHits(urgencyStrongHits)}.`,
      severity: 'warning',
      weight: 12,
      category: 'urgency',
    })
  } else if (urgencyGenericHits.length > 0) {
    addReason(reasons, {
      id: 'time_reference',
      label: 'Menyebut batas waktu',
      detail: `Pesan menyebut waktu (${listHits(urgencyGenericHits)}) tanpa dorongan eksplisit. Kata semacam ini juga umum pada percakapan biasa.`,
      severity: 'info',
      weight: 4,
      category: 'urgency',
    })
  }

  if (threatHits.length > 0) {
    addReason(reasons, {
      id: 'threat_language',
      label: 'Ancaman atau konsekuensi',
      detail: `Pesan menyebut risiko atau sanksi: ${listHits(threatHits)}.`,
      severity: 'danger',
      weight: 14,
      category: 'urgency',
    })
  }

  if (prizeHits.length > 0) {
    addReason(reasons, {
      id: 'prize_claim',
      label: 'Klaim hadiah atau keuntungan',
      detail: `Pesan menyebut hadiah, undian, atau bonus: ${listHits(prizeHits)}.`,
      severity: 'warning',
      weight: 14,
      category: 'transaction',
    })
  }

  if (prizeFee) {
    addReason(reasons, {
      id: 'prize_fee_combo',
      label: 'Hadiah disertai permintaan biaya',
      detail: transferInstruction
        ? 'Klaim hadiah dipadukan dengan perintah mengirim biaya ke rekening atau nomor tertentu. Penerima hadiah resmi tidak dipungut biaya lebih dulu.'
        : 'Klaim hadiah dipadukan dengan permintaan biaya, transfer, atau pembayaran. Pola ini umum pada penipuan.',
      severity: 'danger',
      weight: transferInstruction ? 22 : 12,
      category: 'transaction',
    })
  }

  if (otpRequest) {
    addReason(reasons, {
      id: 'otp_request',
      label: 'Permintaan kode OTP atau PIN',
      detail:
        'Pesan meminta kode OTP, PIN, atau kata sandi. Institusi resmi tidak pernah meminta kode ini melalui pesan.',
      severity: 'danger',
      weight: 60,
      category: 'request',
    })
  } else if (otpMention) {
    addReason(reasons, {
      id: 'otp_mention',
      label: 'Menyebut kode OTP',
      detail:
        'Pesan menyebut OTP, PIN, atau kata sandi. Pastikan pesan bukan permintaan untuk membagikan kode tersebut.',
      severity: 'info',
      weight: 6,
      category: 'request',
    })
  }

  if (moneyHits.length > 0 || moneySettled) {
    const moneyWords = moneyHits.length > 0 ? moneyHits : moneyRawHits

    addReason(reasons, {
      id: 'money_request',
      label: moneySettled ? 'Konteks pembayaran' : 'Unsur transaksi keuangan',
      detail: moneySettled
        ? `Pesan memakai kata keuangan (${listHits(moneyWords)}) dalam konteks pembayaran yang sudah terjadi, bukan permintaan membayar.`
        : `Pesan menyebut pembayaran atau transfer: ${listHits(moneyWords)}.`,
      severity: moneySettled ? 'info' : 'warning',
      weight: moneySettled ? 4 : 10,
      category: 'transaction',
    })
  }

  if (amountHits.length > 0) {
    addReason(reasons, {
      id: 'money_amount',
      label: 'Nominal uang disebutkan',
      detail: `Pesan mencantumkan nominal: ${listHits(amountHits)}.`,
      severity: 'info',
      weight: 6,
      category: 'transaction',
    })
  }

  if (personalHits.length > 0) {
    addReason(reasons, {
      id: 'personal_data_request',
      label: 'Permintaan data pribadi',
      detail: `Pesan menyebut data pribadi: ${listHits(personalHits)}.`,
      severity: 'danger',
      weight: 16,
      category: 'request',
    })
  }

  if (institutionHits.length > 0) {
    addReason(reasons, {
      id: 'institution_mention',
      label: 'Menyebut institusi atau merek',
      detail: `Pesan menyebut: ${listHits(institutionHits)}. Cocokkan pengirim dengan kanal resmi.`,
      severity: 'info',
      weight: 8,
      category: 'impersonation',
    })
  }

  if (credentialHits.length > 0) {
    addReason(reasons, {
      id: 'fake_login_request',
      label: 'Permintaan login atau verifikasi',
      detail: `Pesan meminta tindakan akun: ${listHits(credentialHits)}.`,
      severity: 'danger',
      weight: 16,
      category: 'request',
    })
  }

  if (links.length > 0) {
    addReason(reasons, {
      id: 'link_in_message',
      label: 'Mengandung tautan',
      detail: `Pesan memuat ${links.length} tautan. Periksa domain sebelum membukanya.`,
      severity: 'info',
      weight: 8,
      category: 'url-structure',
    })
  }

  if (shortenerLink) {
    addReason(reasons, {
      id: 'shortener_link',
      label: 'Tautan pendek',
      detail: 'Pesan memakai layanan pemendek URL yang menyembunyikan alamat tujuan.',
      severity: 'warning',
      weight: 14,
      category: 'obfuscation',
    })
  }

  if (brandLink) {
    addReason(reasons, {
      id: brandLinkCorroborated ? 'brand_link' : 'brand_link_unconfirmed',
      label: 'Tautan meniru merek resmi',
      detail: brandLinkCorroborated
        ? brandLink.detail
        : `${brandLink.detail} Pesan belum memuat permintaan login, data pribadi, kode rahasia, atau ancaman, jadi kemiripan nama saja belum cukup sebagai bukti penyamaran.`,
      severity: brandLinkCorroborated ? 'danger' : 'warning',
      weight: brandLinkCorroborated ? 24 : 12,
      category: 'impersonation',
    })
  }

  if (ipLink) {
    addReason(reasons, {
      id: 'ip_link',
      label: 'Tautan memakai alamat IP',
      detail: 'Salah satu tautan memakai alamat IP, bukan domain yang dapat diverifikasi.',
      severity: 'warning',
      weight: 12,
      category: 'domain',
    })
  }

  if (phoneMatches.length > 0) {
    addReason(reasons, {
      id: 'phone_number',
      label: 'Nomor telepon disebutkan',
      detail: `Pesan mencantumkan ${phoneMatches.length} nomor telepon. Verifikasi nomor melalui kanal resmi.`,
      severity: 'info',
      weight: 5,
      category: 'request',
    })
  }

  if (investmentHits.length > 0) {
    addReason(reasons, {
      id: 'investment_offer',
      label: 'Tawaran investasi',
      detail: `Pesan menyebut investasi atau keuntungan: ${listHits(investmentHits)}.`,
      severity: 'warning',
      weight: 16,
      category: 'transaction',
    })
  }

  if (investmentGuarantee) {
    addReason(reasons, {
      id: 'investment_guarantee',
      label: 'Janji keuntungan pasti',
      detail:
        'Pesan menjanjikan keuntungan tanpa risiko. Tidak ada investasi sah yang dapat menjamin hasil.',
      severity: 'danger',
      weight: 10,
      category: 'transaction',
    })
  }

  if (investmentReturn) {
    addReason(reasons, {
      id: 'investment_return',
      label: 'Imbal hasil tidak wajar',
      detail: 'Pesan menyebut persentase atau nominal keuntungan yang tidak wajar.',
      severity: 'warning',
      weight: 12,
      category: 'transaction',
    })
  }

  if (jobHits.length > 0) {
    addReason(reasons, {
      id: 'job_offer',
      label: 'Tawaran pekerjaan',
      detail: `Pesan menyebut lowongan atau tugas kerja: ${listHits(jobHits)}.`,
      severity: 'warning',
      weight: 12,
      category: 'transaction',
    })
  }

  if (jobFee) {
    addReason(reasons, {
      id: 'job_fee_combo',
      label: 'Pekerjaan disertai biaya',
      detail: transferInstruction
        ? 'Tawaran kerja dipadukan dengan perintah mengirim biaya ke rekening atau nomor tertentu. Lowongan resmi tidak memungut biaya.'
        : 'Tawaran kerja dipadukan dengan permintaan biaya, deposit, atau transfer. Lowongan resmi tidak memungut biaya.',
      severity: 'danger',
      weight: transferInstruction ? 18 : 10,
      category: 'transaction',
    })
  }

  if (marketplaceHits.length > 0) {
    addReason(reasons, {
      id: 'marketplace_context',
      label: 'Konteks jual beli',
      detail: `Pesan menyebut transaksi jual beli: ${listHits(marketplaceHits)}.`,
      severity: 'warning',
      weight: 8,
      category: 'transaction',
    })
  }

  if (courierHits.length > 0) {
    addReason(reasons, {
      id: 'courier_context',
      label: 'Konteks pengiriman paket',
      detail: `Pesan menyebut pengiriman atau kurir: ${listHits(courierHits)}.`,
      severity: 'warning',
      weight: 8,
      category: 'transaction',
    })
  }

  if (isShouting) {
    addReason(reasons, {
      id: 'uppercase_text',
      label: 'Banyak huruf kapital',
      detail: 'Pesan ditulis dengan huruf kapital berlebihan, sering dipakai untuk menekan penerima.',
      severity: 'info',
      weight: 6,
      category: 'language',
    })
  }

  if (exclamations >= 3) {
    addReason(reasons, {
      id: 'excessive_exclamation',
      label: 'Tanda seru berlebihan',
      detail: `Pesan memakai ${exclamations} tanda seru untuk mendesak penerima.`,
      severity: 'info',
      weight: 5,
      category: 'language',
    })
  }

  if (threatHits.length > 0 && links.length > 0) {
    addReason(reasons, {
      id: 'threat_link_combo',
      label: 'Ancaman disertai tautan',
      detail: 'Pesan menakut-nakuti penerima sekaligus mengarahkan ke tautan.',
      severity: 'warning',
      weight: 8,
      category: 'urgency',
    })
  }

  if (institutionHits.length > 0 && credentialHits.length > 0) {
    addReason(reasons, {
      id: 'impersonation_credential_combo',
      label: 'Institusi disertai permintaan akun',
      detail:
        'Nama institusi atau merek muncul bersama permintaan login atau verifikasi akun.',
      severity: 'danger',
      weight: 12,
      category: 'impersonation',
    })
  }

  const patterns: DetectedPattern[] = []

  if (otpRequest) {
    raisePattern(patterns, 'otp_theft', 'high')
    raisePattern(patterns, 'phishing', links.length > 0 ? 'high' : 'medium')
  }

  if (personalHits.length > 0) {
    raisePattern(patterns, 'phishing', 'high')
  }

  if (credentialHits.length > 0) {
    raisePattern(patterns, 'fake_login', links.length > 0 ? 'high' : 'medium')
  }

  if (
    institutionHits.length > 0 &&
    (credentialHits.length > 0 || otpRequest || personalHits.length > 0)
  ) {
    raisePattern(patterns, 'impersonation', 'high')
  }

  if (brandLink) {
    raisePattern(patterns, 'impersonation', brandLinkCorroborated ? 'high' : 'low')

    if (brandLinkCorroborated) {
      raisePattern(patterns, 'phishing', 'high')
    }
  }

  if (prizeHits.length > 0) {
    raisePattern(patterns, 'giveaway', prizeFee ? 'high' : 'medium')
  }

  if (urgencyStrongHits.length > 0 && threatHits.length > 0) {
    raisePattern(patterns, 'urgency', 'high')
  } else if (urgencyStrongHits.length > 0 || threatHits.length > 0) {
    raisePattern(patterns, 'urgency', 'medium')
  }

  if (investmentHits.length > 0) {
    raisePattern(patterns, 'investment', investmentGuarantee || investmentReturn ? 'high' : 'medium')
  }

  if (jobHits.length > 0) {
    raisePattern(patterns, 'job_scam', jobFee ? 'high' : 'low')
  }

  if (
    (marketplaceHits.length > 0 || courierHits.length > 0) &&
    (moneyHits.length > 0 || credentialHits.length > 0)
  ) {
    raisePattern(patterns, 'marketplace', 'medium')
  }

  if (
    shortenerLink &&
    (institutionHits.length > 0 || prizeHits.length > 0 || otpRequest || credentialHits.length > 0)
  ) {
    raisePattern(patterns, 'phishing', 'high')
  }

  const technical = [
    { label: 'Jenis konten', value: 'Pesan teks' },
    { label: 'Panjang pesan', value: `${text.length} karakter` },
    {
      label: 'Tautan terdeteksi',
      value: links.length > 0 ? `${links.length} tautan` : 'Tidak ada',
      tone: links.length > 0 ? ('warning' as const) : ('neutral' as const),
    },
    {
      label: 'Pemendek URL',
      value: shortenerLink ? 'Ya' : 'Tidak',
      tone: shortenerLink ? ('warning' as const) : ('neutral' as const),
    },
    {
      label: 'Nomor telepon',
      value: phoneMatches.length > 0 ? `${phoneMatches.length} nomor` : 'Tidak ada',
      tone: phoneMatches.length > 0 ? ('warning' as const) : ('neutral' as const),
    },
    {
      label: 'Kode OTP disebut',
      value: otpMention ? 'Ya' : 'Tidak',
      tone: 'neutral' as const,
    },
  ]

  return buildDraft({
    mode: 'message',
    input: text,
    displayTarget: truncate(normalizeWhitespace(text), 90),
    reasons,
    patterns,
    technical,
  })
}

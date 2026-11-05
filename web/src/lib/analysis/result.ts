import type {
  AnalysisReason,
  DetectedPattern,
  PatternId,
  RiskLevel,
  ScanDraft,
  ScanMode,
  TechnicalItem,
} from './types'

export const ENGINE_VERSION = '1.4.0'

export const RISK_THRESHOLDS = {
  medium: 25,
  high: 60,
} as const

const MAX_EXPLAINED_REASONS = 8

export function riskLevelFromScore(score: number): RiskLevel {
  if (score >= RISK_THRESHOLDS.high) return 'high'
  if (score >= RISK_THRESHOLDS.medium) return 'medium'
  return 'low'
}

const HEADLINES: Record<RiskLevel, string> = {
  low: 'Indikasi risiko rendah',
  medium: 'Indikasi risiko sedang',
  high: 'Indikasi risiko tinggi',
}

function buildSummary(level: RiskLevel, mode: ScanMode): string {
  const subject = mode === 'link' ? 'tautan' : 'pesan'

  if (level === 'high') {
    return `Beberapa indikator yang saling menguatkan mengarah pada upaya penipuan. Jangan ${
      mode === 'link' ? 'membuka tautan' : 'menindaklanjuti pesan'
    } ini sebelum melakukan verifikasi.`
  }

  if (level === 'medium') {
    return `Ada beberapa indikator pada ${subject} ini yang perlu diverifikasi sebelum kamu bertindak.`
  }

  return `Tidak banyak indikator risiko ditemukan pada ${subject} ini. Ini bukan jaminan bahwa ${subject} tersebut aman.`
}

function buildRecommendations(
  mode: ScanMode,
  level: RiskLevel,
  patterns: DetectedPattern[],
): string[] {
  const recommendations: string[] = []

  if (level === 'high') {
    recommendations.push('Hentikan interaksi dan laporkan pesan atau tautan ke penyedia layanan.')
  }

  recommendations.push(
    mode === 'link'
      ? 'Jangan membuka tautan sebelum memastikan domain melalui situs resmi.'
      : 'Jangan membalas pesan atau mengikuti instruksinya sebelum memverifikasi pengirim.',
  )

  recommendations.push(
    'Verifikasi melalui aplikasi atau situs resmi yang kamu cari sendiri, bukan melalui tautan di pesan.',
  )

  const ids = new Set<PatternId>(patterns.map((pattern) => pattern.id))

  if (ids.has('otp_theft')) {
    recommendations.push(
      'Jika kode OTP atau PIN sudah dibagikan, hubungi bank atau penyedia layanan sekarang dan ganti kata sandi.',
    )
  } else {
    recommendations.push('Jangan pernah membagikan kode OTP, PIN, atau kata sandi kepada siapa pun.')
  }

  if (ids.has('giveaway')) {
    recommendations.push(
      'Abaikan klaim hadiah yang tidak kamu ikuti dan jangan membayar biaya apa pun.',
    )
  }

  if (ids.has('investment')) {
    recommendations.push(
      'Waspadai janji keuntungan pasti; periksa izin penyedia layanan melalui kanal resmi.',
    )
  }

  if (ids.has('job_scam')) {
    recommendations.push(
      'Jangan membayar biaya pelatihan, seragam, atau deposit untuk memperoleh pekerjaan.',
    )
  }

  if (ids.has('marketplace')) {
    recommendations.push(
      'Bertransaksi hanya melalui platform resmi yang memiliki perlindungan pembeli.',
    )
  }

  if (ids.has('impersonation')) {
    recommendations.push(
      'Hubungi institusi melalui nomor resmi yang tertera di situs mereka, bukan nomor pada pesan.',
    )
  }

  if (ids.has('urgency')) {
    recommendations.push('Jangan terburu-buru; tekanan waktu adalah tanda umum penipuan.')
  }

  if (ids.has('phishing') || ids.has('fake_login')) {
    recommendations.push(
      'Jangan memasukkan kata sandi, PIN, atau data kartu pada halaman yang dibuka dari tautan ini.',
    )
  }

  if (level === 'low') {
    recommendations.push(
      'Tetap waspada: tidak banyak indikator bukan berarti bebas dari risiko.',
    )
  }

  return [...new Set(recommendations)].slice(0, 6)
}

export function buildDraft(params: {
  mode: ScanMode
  input: string
  displayTarget: string
  reasons: AnalysisReason[]
  patterns: DetectedPattern[]
  technical: TechnicalItem[]
}): ScanDraft {
  const { mode, input, displayTarget, reasons, patterns, technical } = params
  const sortedReasons = [...reasons]
    .sort((a, b) => b.weight - a.weight)
    .slice(0, MAX_EXPLAINED_REASONS)
  const totalWeight = sortedReasons.reduce((sum, reason) => sum + reason.weight, 0)
  const riskScore = Math.min(100, totalWeight)
  const riskLevel = riskLevelFromScore(riskScore)
  const uniquePatterns = [...new Map(patterns.map((pattern) => [pattern.id, pattern])).values()]

  return {
    mode,
    input,
    displayTarget,
    riskScore,
    riskLevel,
    headline: HEADLINES[riskLevel],
    summary: buildSummary(riskLevel, mode),
    reasons: sortedReasons,
    patterns: uniquePatterns,
    recommendations: buildRecommendations(mode, riskLevel, uniquePatterns),
    technical,
    meta: {
      engineVersion: ENGINE_VERSION,
      signalCount: reasons.length,
      inputLength: input.length,
      aiStatus: 'not_used',
      inputStored: 'full',
    },
  }
}

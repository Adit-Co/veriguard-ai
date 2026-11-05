import type { PatternId, DetectedPattern, PatternConfidence } from './types'

type PatternDefinition = {
  label: string
  description: string
}

export const PATTERN_CATALOG: Record<PatternId, PatternDefinition> = {
  phishing: {
    label: 'Phishing',
    description: 'Upaya memperoleh data dengan menyamar sebagai pihak tepercaya.',
  },
  fake_login: {
    label: 'Login palsu',
    description: 'Halaman atau tautan yang meniru proses masuk layanan resmi.',
  },
  giveaway: {
    label: 'Hadiah & undian',
    description: 'Klaim hadiah yang tidak pernah diikuti atau disertai permintaan biaya.',
  },
  marketplace: {
    label: 'Jual beli online',
    description: 'Pola transaksi yang mengarah pada penipuan jual beli.',
  },
  impersonation: {
    label: 'Penyamaran institusi',
    description: 'Nama bank, kurir, atau institusi dipakai untuk meniru pihak resmi.',
  },
  urgency: {
    label: 'Urgensi & ancaman',
    description: 'Tekanan waktu atau ancaman dipakai agar korban bertindak cepat.',
  },
  investment: {
    label: 'Investasi',
    description: 'Janji keuntungan tidak wajar atau tawaran investasi tanpa izin.',
  },
  job_scam: {
    label: 'Lowongan kerja',
    description: 'Tawaran kerja dengan biaya di muka atau tugas yang tidak wajar.',
  },
  otp_theft: {
    label: 'Pencurian OTP',
    description: 'Permintaan kode OTP atau PIN yang dapat dipakai mengambil alih akun.',
  },
}

export function createPattern(
  id: PatternId,
  confidence: PatternConfidence,
): DetectedPattern {
  const definition = PATTERN_CATALOG[id]
  return {
    id,
    label: definition.label,
    description: definition.description,
    confidence,
  }
}

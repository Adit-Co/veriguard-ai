import type { ScanMode } from './types'
import { isIpHost, isLocalHost } from './text'

export const MAX_LINK_LENGTH = 2048
export const MAX_MESSAGE_LENGTH = 4000
export const MIN_MESSAGE_LENGTH = 12

export type ValidationResult =
  | { ok: true; normalized: string }
  | { ok: false; error: string }

export class AnalysisError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AnalysisError'
  }
}

const HAS_SCHEME = /^[a-z][a-z0-9+.-]*:/i

export function validateLinkInput(raw: string): ValidationResult {
  const trimmed = raw.trim()

  if (!trimmed) {
    return { ok: false, error: 'Masukkan tautan yang ingin diperiksa.' }
  }

  if (trimmed.length > MAX_LINK_LENGTH) {
    return { ok: false, error: `Tautan terlalu panjang (maksimal ${MAX_LINK_LENGTH} karakter).` }
  }

  if (/\s/.test(trimmed)) {
    return { ok: false, error: 'Tautan tidak boleh mengandung spasi. Pastikan hanya alamat tautan.' }
  }

  if (HAS_SCHEME.test(trimmed) && !/^https?:\/\//i.test(trimmed)) {
    return { ok: false, error: 'Hanya tautan dengan protokol http atau https yang dapat diperiksa.' }
  }

  let url: URL

  try {
    url = new URL(HAS_SCHEME.test(trimmed) ? trimmed : `https://${trimmed}`)
  } catch {
    return { ok: false, error: 'Format tautan tidak valid. Contoh yang benar: https://contoh.com' }
  }

  if (!/^https?:$/.test(url.protocol)) {
    return { ok: false, error: 'Hanya tautan dengan protokol http atau https yang dapat diperiksa.' }
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, '')

  if (!host) {
    return { ok: false, error: 'Tautan tidak memiliki alamat domain yang valid.' }
  }

  if (isLocalHost(host)) {
    return { ok: false, error: 'Alamat lokal atau privat tidak dapat diperiksa.' }
  }

  if (!host.includes('.') && !isIpHost(host)) {
    return {
      ok: false,
      error: 'Domain tidak valid. Sertakan alamat lengkap, misalnya contoh.com.',
    }
  }

  if (host.length > 253) {
    return { ok: false, error: 'Nama domain terlalu panjang.' }
  }

  return { ok: true, normalized: url.href }
}

export function validateMessageInput(raw: string): ValidationResult {
  const trimmed = raw.trim()

  if (!trimmed) {
    return { ok: false, error: 'Tempel pesan yang ingin diperiksa.' }
  }

  if (trimmed.length < MIN_MESSAGE_LENGTH) {
    return {
      ok: false,
      error: `Pesan terlalu pendek. Masukkan minimal ${MIN_MESSAGE_LENGTH} karakter agar pola dapat dianalisis.`,
    }
  }

  if (trimmed.length > MAX_MESSAGE_LENGTH) {
    return {
      ok: false,
      error: `Pesan terlalu panjang (maksimal ${MAX_MESSAGE_LENGTH} karakter).`,
    }
  }

  if (!/[a-z]/i.test(trimmed)) {
    return { ok: false, error: 'Pesan harus mengandung teks yang dapat dibaca.' }
  }

  return { ok: true, normalized: trimmed }
}

export function validateInput(mode: ScanMode, raw: string): ValidationResult {
  return mode === 'link' ? validateLinkInput(raw) : validateMessageInput(raw)
}

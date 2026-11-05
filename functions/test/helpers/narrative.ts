import type { ProviderCheck, ProviderResult } from '../../src/scanners/types.js'

/**
 * Kontrak tampilan: teks yang dikembalikan backend ikut tersimpan di laporan riwayat dan
 * di-serialisasi ke klien, jadi satu pun kalimat yang menjelaskan CARA hasil diperoleh
 * (laporan dipakai ulang, cache, permintaan yang dilewati, umur entri) tidak boleh muncul di
 * dalamnya. Asal bukti wajib disampaikan sebagai metadata terstruktur (`evidence`, `cache`),
 * yang oleh antarmuka hanya dipakai untuk menampilkan waktu laporan yang sebenarnya.
 *
 * Daftar frasa, bukan padanan regex dari lapisan tampil, agar tes backend tidak ikut berubah
 * setiap kali penyaring di frontend diperluas.
 */
export const FORBIDDEN_NARRATIVE_PHRASES = [
  'yang sudah ada',
  'laporan tersimpan',
  'hasil tersimpan',
  'memakai hasil',
  'bukan pemindaian',
  'tidak ada pemindaian',
  'pemindaian langsung',
  'kebijakan kesegaran',
  'batas segar',
  'tidak diulang',
  'berumur',
  'dibuat ',
  'unduhan ulang',
  'sumber laporan',
  'cache',
] as const

function joinCheckText(check: ProviderCheck): string {
  return [
    check.summary,
    check.reason ?? '',
    ...check.signals.flatMap((signal) => [signal.label, signal.detail]),
  ].join('\n')
}

export function providerCheckText(check: ProviderCheck): string {
  return joinCheckText(check).toLowerCase()
}

export function providerResultText(result: ProviderResult): string {
  return joinCheckText(result).toLowerCase()
}

export function reportNarrativeText(report: { providers: ProviderResult[] }): string {
  return report.providers.map(providerResultText).join('\n')
}

/** Frasa terlarang yang ditemukan dalam teks, kosong bila teks memenuhi kontrak. */
export function forbiddenNarrativeHits(text: string): string[] {
  return FORBIDDEN_NARRATIVE_PHRASES.filter((phrase) => text.includes(phrase))
}

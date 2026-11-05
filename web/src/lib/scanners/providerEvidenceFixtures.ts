import type { ExternalProviderId, NegativeEvidence, ProviderResult } from './types'

// VGL-31 — fixture yang MENIRU bentuk hasil adapter nyata, dipakai uji agregasi dan uji panel.
//
// Alasannya: sejak VGL-31 vonis Risiko Rendah tidak lagi lahir dari "semua agen berwarna
// bersih", melainkan dari penanda bukti negatif yang benar-benar dikirim adapter. Fixture yang
// hanya menyetel status/verdict akan menggambarkan provider yang tidak ada, jadi bentuk
// penanda ini diturunkan dari aturan adapter yang sebenarnya:
//   - urlscan      : vonis pemindaian selesai + skor serta klasifikasi dieksplisitkan -> explicit
//   - radar        : vonis pemindai dengan kategori yang dikenali tidak berbahaya      -> explicit
//   - virustotal   : cukup mesin melapor, 0 ditandai, tanpa mesin gagal               -> explicit
//                    (VGL-32B: laporan lengkap tetap explicit walau mayoritas `undetected`)
//   - safebrowsing : daftar ancaman menjawab kosong untuk kategori yang ditanyakan     -> limited
//   - openphish, threatfox, otx, hybrid: tidak pernah membawa penanda (feed/komunitas)
const CREDITABLE: Record<
  ExternalProviderId,
  { evidenceClass: NegativeEvidence['evidenceClass']; strength: NegativeEvidence['strength'] } | null
> = {
  urlscan: { evidenceClass: 'scan_verdict', strength: 'explicit' },
  radar: { evidenceClass: 'scanner_verdict', strength: 'explicit' },
  virustotal: { evidenceClass: 'engine_verdicts', strength: 'explicit' },
  safebrowsing: { evidenceClass: 'threat_list', strength: 'limited' },
  openphish: null,
  threatfox: null,
  otx: null,
  hybrid: null,
}

// Penanda hanya boleh menempel pada hasil yang cocok dengan perilaku penyedia:
// `explicit` pada vonis bersih, `limited` pada jawaban daftar yang kosong.
export function negativeEvidenceFor(
  id: ExternalProviderId,
  provider: Pick<ProviderResult, 'status' | 'verdict'>,
): NegativeEvidence | undefined {
  const shape = CREDITABLE[id]
  if (!shape) return undefined

  if (shape.strength === 'explicit') {
    if (provider.status !== 'success' || provider.verdict !== 'clean') return undefined
  } else if (provider.status !== 'not_found') {
    return undefined
  }

  return {
    strength: shape.strength,
    scope: 'url',
    evidenceClass: shape.evidenceClass,
    basis: `Fixture meniru hasil agen ${id}: ${
      shape.strength === 'explicit'
        ? 'provider menyatakan hasil negatif untuk URL ini secara eksplisit.'
        : 'daftar ancaman menjawab kosong untuk URL ini.'
    }`,
  }
}

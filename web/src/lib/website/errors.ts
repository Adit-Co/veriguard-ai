import { ExternalScanRequestError } from '../scanners/errors'
import { EXTERNAL_PROVIDER_IDS } from '../scanners/types'
import { userFacingText } from '../uiText'

const SITE_ERROR_MESSAGES: Record<string, string> = {
  consent_required: 'Persetujuan untuk membuka URL pada layanan analisis situs belum diberikan.',
  invalid_request: 'Permintaan analisis situs tidak valid.',
  invalid_url:
    'URL ditolak oleh kebijakan keamanan layanan analisis situs (skema, format, atau alamat internal).',
  site_rate_limited: 'Batas analisis situs tercapai. Coba lagi setelah jendela batas selesai.',
  rate_limited: 'Batas permintaan ke layanan analisis situs tercapai. Coba lagi nanti.',
  origin_not_allowed:
    'Layanan analisis situs belum siap untuk alamat aplikasi ini. Hubungi pengelola layanan.',
  not_found:
    'Layanan analisis situs belum tersedia pada versi ini. Coba lagi nanti atau hubungi pengelola layanan.',
  unavailable:
    'Layanan analisis situs tidak dapat dihubungi. Periksa koneksi lalu coba lagi.',
  timeout: 'Analisis situs melebihi batas waktu. Data tidak pernah dibuat-buat.',
  invalid_response: 'Respons analisis situs tidak valid.',
  payload_too_large: 'Permintaan analisis situs terlalu besar.',
  unsupported_media_type: 'Format permintaan analisis situs tidak didukung.',
  worker_not_configured: 'Layanan analisis situs belum tersedia pada versi ini.',
  internal: 'Analisis situs gagal diproses.',
}

export function siteAnalysisErrorMessage(error: unknown): string {
  if (error instanceof ExternalScanRequestError) {
    return SITE_ERROR_MESSAGES[error.code] ?? userFacingText(error.message)
  }
  if (error instanceof Error && error.message === 'timeout') {
    return SITE_ERROR_MESSAGES.timeout ?? 'Analisis situs melebihi batas waktu.'
  }
  // VGL-30K-R1 §5: jumlah agen dibaca dari registry, bukan ditanam sebagai kata, supaya pesan
  // tidak basi ketika roster berubah.
  return `Analisis situs gagal dijalankan. Hasil ${EXTERNAL_PROVIDER_IDS.length} agen dan Reputasi Ancaman tidak berubah.`
}

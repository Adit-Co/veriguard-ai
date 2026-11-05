import { resetInFlightScans } from '../../src/scanners/inFlight.js'
import { resetOpenPhishFeedCache } from '../../src/scanners/providers/openphishFeed.js'
import { resetProviderCache } from '../../src/scanners/providerCache.js'
import { resetScanRateLimit } from '../../src/scanners/rateLimit.js'

// Semua state proses-lokal yang dipakai jalur pemeriksaan. Produksi memulai setiap proses
// dalam keadaan bersih; tes harus mendapat keadaan yang sama, bukan warisan dari tes
// sebelumnya yang memeriksa URL yang sama.
export function resetScanState(): void {
  resetScanRateLimit()
  resetProviderCache()
  resetInFlightScans()
  resetOpenPhishFeedCache()
}

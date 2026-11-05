import type { ProviderAdapter } from '../types.js'
import { hybridAnalysisAdapter } from './hybrid.js'
import { otxAdapter } from './otx.js'
import { openPhishAdapter } from './openphish.js'
import { radarAdapter } from './radar.js'
import { googleSafeBrowsingAdapter } from './safebrowsing.js'
import { threatFoxAdapter } from './threatfox.js'
import { urlScanAdapter } from './urlscan.js'
import { virusTotalAdapter } from './virustotal.js'

// Urutan daftar ini adalah nomor agen yang tampil di antarmuka: agen ke-N = indeks N.
// Penomoran tidak boleh berubah kecuali sebuah agen benar-benar ditambahkan di ujung.
export const PROVIDER_ADAPTERS: ProviderAdapter[] = [
  urlScanAdapter,
  virusTotalAdapter,
  openPhishAdapter,
  threatFoxAdapter,
  radarAdapter,
  otxAdapter,
  // Agen 7: Hybrid Analysis (CrowdStrike Falcon Sandbox) — penelusuran reputasi read-only
  // atas laporan yang sudah ada (/search/terms); tidak pernah mengirim URL untuk sandbox.
  hybridAnalysisAdapter,
  // Agen 8: Google Safe Browsing v5 `urls.search` — pemeriksaan real-time terhadap list resmi
  // Google (menggantikan Lookup API v4 yang deprecated). Respons `{threats:[]}` tetap `not_found`
  // /`inconclusive` (BUKAN vonis bersih), tetapi sejak VGL-31 membawa bukti negatif TERBATAS:
  // daftar yang menjawab kosong adalah jawaban provider, bukan ketiadaan jawaban.
  googleSafeBrowsingAdapter,
]

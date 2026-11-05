export const SCANNER_PROVIDER_IDS = [
  'urlscan',
  'virustotal',
  'openphish',
  'threatfox',
  'radar',
  'otx',
  'hybrid',
  'safebrowsing',
] as const

export type ScannerProviderId = (typeof SCANNER_PROVIDER_IDS)[number]

export type ProviderStatus =
  | 'success'
  | 'not_found'
  | 'not_configured'
  | 'auth_failed'
  | 'unavailable'
  | 'rate_limited'
  | 'skipped'
  | 'timeout'
  // Permintaan kami DITOLAK provider karena bentuknya (HTTP 400/422). Dipisahkan dari
  // `error` agar "agen tidak menerima permintaan ini" tidak pernah disamakan dengan
  // "agen gagal", dan agar laporan yang sudah ada tetap dapat dipakai sebagai fallback.
  | 'invalid_request'
  | 'error'

export type ProviderVerdict =
  | 'malicious'
  | 'suspicious'
  | 'clean'
  | 'inconclusive'

export type ProviderSignalSeverity = 'info' | 'warning' | 'danger'

export type ProviderSignal = {
  label: string
  detail: string
  severity: ProviderSignalSeverity
}

export type ProviderEvidenceSource = 'existing_report' | 'new_scan'

// Asal bukti sebuah hasil agen. Waktu laporan asal dipertahankan agar laporan lama
// tidak pernah tampil sebagai pemindaian langsung.
export type ProviderEvidence = {
  source: ProviderEvidenceSource
  observedAt: string | null
  ageMs: number | null
}

// VGL-31 TAHAP 2 — bukti negatif.
// "Tidak ada temuan" punya banyak sebab yang berbeda sama sekali: provider memeriksa URL ini
// lalu menyimpulkan tidak berbahaya, provider menyimpan daftar yang ternyata kosong untuk URL
// ini, provider tidak punya data sama sekali, atau provider gagal. Empat hal itu tidak boleh
// berbagi satu makna. Sebuah hasil HANYA boleh membawa bukti negatif bila perilaku nyata
// penyedia membenarkannya; tidak ada jalur lain yang boleh mengarangnya.
export type NegativeEvidenceStrength =
  // Provider menyatakan hasil negatif untuk URL ini secara eksplisit (vonis selesai, daftar
  // ancaman menjawab, atau mesin memilih "tidak berbahaya").
  | 'explicit'
  // Hasilnya konsisten dengan "tidak berbahaya" tetapi bertumpu pada ketiadaan tanda, bukan
  // pada pernyataan. Boleh ditampilkan sebagai pendukung, TIDAK cukup untuk vonis bersih.
  | 'limited'

// Kelas bukti dipakai agregator agar dua agen yang menyalin kebiasaan yang sama tidak
// dihitung sebagai dua bukti yang independen.
export type NegativeEvidenceClass =
  | 'scan_verdict'      // pemindaian langsung atas URL ini selesai dan vonisnya dieksplisitkan
  | 'engine_verdicts'   // sekumpulan mesin memberikan hasil dan tidak ada yang menandai
  | 'scanner_verdict'   // pemindai memberi vonis dengan kategori yang dikenali tidak berbahaya
  | 'threat_list'       // daftar ancaman menjawab dan kosong untuk kategori yang ditanyakan

export type NegativeEvidence = {
  strength: NegativeEvidenceStrength
  // 'url' = bukti menargetkan alamat yang diperiksa; 'domain' = bukti selebar domain.
  scope: 'url' | 'domain'
  evidenceClass: NegativeEvidenceClass
  // Mengapa ketiadaan temuan ini boleh dibaca sebagai bukti, dalam bahasa pengguna.
  basis: string
}

// Riwayat sebuah entri cache hasil agen. `observedAt` adalah waktu hasil pertama kali
// diperoleh (bukan waktu permintaan), sehingga hasil cache tidak pernah tampil sebagai
// pemindaian baru. `stale` menandai entri yang dipertahankan melewati batas segarnya
// karena penyedia sedang gagal; ia tidak pernah mengubah verdict.
export type ProviderResultCache = {
  hit: boolean
  observedAt: string
  ageMs: number
  stale: boolean
}

export type ScanCacheStatus = 'hit' | 'partial' | 'miss'

// Ringkasan pemakaian cache untuk satu pemeriksaan multi-agen. `requestsAvoided`
// menghitung permintaan agen yang benar-benar dilewati, bukan sekadar entri yang ada.
export type ScanCacheMeta = {
  status: ScanCacheStatus
  hit: boolean
  observedAt: string | null
  ageMs: number
  reusedProviders: ScannerProviderId[]
  refreshedProviders: ScannerProviderId[]
  requestsAvoided: number
  // true bila permintaan ini memakai hasil scan lain yang sedang berjalan (dedup
  // bersamaan), bukan entri cache yang sudah tersimpan.
  deduplicated?: boolean
}

export type ProviderResult = {
  id: ScannerProviderId
  label: string
  status: ProviderStatus
  verdict: ProviderVerdict
  score: number | null
  summary: string
  signals: ProviderSignal[]
  reason: string | null
  durationMs: number
  evidence?: ProviderEvidence
  cache?: ProviderResultCache
  // Bukti negatif dari penyedia, bila perilaku nyatanya membenarkan. Ketiadaan field berarti
  // "tidak ada bukti kebersihan", termasuk untuk semua status kegagalan.
  negative?: NegativeEvidence
}

export type ProviderProgressState = 'queued' | 'running' | 'completed'

export type ProviderProgress = {
  id: ScannerProviderId
  label: string
  state: ProviderProgressState
  result?: ProviderResult
  shared?: boolean
}

export type ScanProgressEvent =
  | {
      type: 'init'
      scanId: string
      startedAt: string
      sensitiveUrl: boolean
      privacyReasons: string[]
      providers: Array<{
        id: ScannerProviderId
        label: string
        state: 'queued'
      }>
    }
  | {
      type: 'provider'
      scanId: string
      provider: ProviderProgress
    }
  | {
      type: 'done'
      scanId: string
      response: MultiSourceScanResponse
    }

export type ProviderCheck = {
  status: ProviderStatus
  verdict: ProviderVerdict
  score: number | null
  summary: string
  signals: ProviderSignal[]
  reason?: string | null
  evidence?: ProviderEvidence
  // VGL-31: bukti negatif yang dibenarkan perilaku penyedia. Hanya adapter yang boleh
  // mengisinya; semua helper kegagalan di `result.ts` sengaja tidak pernah mengisinya.
  negative?: NegativeEvidence
  // Umur maksimum (detik) yang DIREKOMENDASIKAN penyedia untuk hasilnya sendiri, bila
  // ada. Hanya dipakai internal cache; `toResult` menyusun objek respons secara eksplisit
  // sehingga field ini tidak pernah ikut ke wire.
  providerCacheSeconds?: number | null
  // true bila hasil ini dibangun di atas snapshot hulu yang sudah melewati batas segarnya
  // (mis. feed OpenPhish yang dipakai karena sumber sedang gagal). Dirawat lewat cache agar
  // penanda tidak hilang saat hasil dipakai ulang.
  staleEvidence?: boolean
}

// Kebijakan cache hasil agen. Semua TTL adalah milik aplikasi dan disimpan sebagai
// milidetik yang sudah ternormalisasi (lihat `readScannerConfig`); nilai dari env
// yang tidak valid diabaikan sehingga default yang aman dipakai.
export type ScanCacheConfig = {
  enabled: boolean
  maxEntries: number
  // TTL untuk hasil yang layak cache (success/not_found), per agen.
  resultTtlMs: Partial<Record<ScannerProviderId, number>>
  // TTL singkat untuk kegagalan sementara (rate_limited/unavailable/timeout). Status
  // disimpan apa adanya dan tidak pernah diubah menjadi not_found.
  failureTtlMs: number
  openPhishFeedTtlMs: number
  openPhishFeedStaleTtlMs: number
}

export type ScannerConfig = {
  urlscanApiKey: string | null
  virusTotalApiKey: string | null
  openPhishApiKey: string | null
  threatFoxApiKey: string | null
  cloudflareApiToken: string | null
  cloudflareAccountId: string | null
  otxApiKey: string | null
  hybridAnalysisApiKey: string | null
  googleSafeBrowsingApiKey: string | null
  // Kebijakan kesegaran laporan; tidak diatur bila env tidak diisi (adapter memakai default).
  urlscanMaxReportAgeHours?: number
  virusTotalMaxReportAgeHours?: number
  radarMaxReportAgeHours?: number
  // Kebijakan cache hasil. Opsional di tipe karena pemanggil dapat menyusun konfigurasi
  // sendiri (mis. uji), sementara `readScannerConfig` selalu mengisinya dengan default aman.
  scanCache?: ScanCacheConfig
}

export type ProviderContext = {
  url: string
  hostname: string
  fetchImpl: typeof fetch
  now: () => number
  sleep: (ms: number) => Promise<void>
  signal?: AbortSignal
}

export type ProviderAdapter = {
  id: ScannerProviderId
  label: string
  requiredEnv?: readonly string[]
  // Alasan why-not-configured yang ditulis adapter sendiri; dipakai service ketika
  // isConfigured false, menggantikan pesan generik "isi ENV".
  notConfiguredReason?: string
  // Batas waktu khusus untuk adapter yang memakai siklus submit + polling.
  timeoutMs?: number
  isConfigured: (config: ScannerConfig) => boolean
  check: (context: ProviderContext, config: ScannerConfig) => Promise<ProviderCheck>
}

export type MultiSourceScanResponse = {
  providers: ProviderResult[]
  sharedWithProviders: ScannerProviderId[]
  sensitiveUrl: boolean
  privacyReasons: string[]
  generatedAt: string
  durationMs: number
  cache?: ScanCacheMeta
}

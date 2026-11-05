import { toBase64Url } from '../encoding.js'
import { fetchJson } from '../http.js'
import {
  clampScore,
  failureCheck,
  formatObservedAt,
  notFoundCheck,
  numberValue,
  recordValue,
  notConfiguredCheck,
  stringValue,
  withExistingReportEvidence,
} from '../result.js'
import type {
  ProviderAdapter,
  ProviderCheck,
  ProviderContext,
  ProviderSignal,
  ScannerConfig,
} from '../types.js'

const MIN_ENGINES_FOR_CLEAN = 20
const DEFAULT_MAX_REPORT_AGE_HOURS = 168

// VGL-33A — mekanisme analisis baru resmi VT v3: POST /urls (submit) -> GET /analyses/{id}
// (pantau) -> GET /urls/{id} (laporan terbaru). Dipakai TERBATAS sebagai pemulihan laporan
// yang kedaluwarsa: maksimal satu submit per pemeriksaan, hanya untuk vonis 0 berbahaya +
// 0 mencurigakan dengan cukup engine melapor. Submission yang ditolak (400) atau kena kuota
// (429) TIDAK pernah diulang; kegagalan apa pun mengembalikan laporan lama apa adanya.
const RESCAN_SUBMIT_URL = 'https://www.virustotal.com/api/v3/urls'
const LOOKUP_REQUEST_TIMEOUT_MS = 8_000
const SUBMIT_REQUEST_TIMEOUT_MS = 10_000
const POLL_REQUEST_TIMEOUT_MS = 8_000
const REREAD_REQUEST_TIMEOUT_MS = 8_000
const POLL_DELAY_MS = 5_000
const MAX_POLLS = 6
// Anggaran dihitung sejak submit sampai baca ulang. Worst case = RESCAN_BUDGET +
// REREAD_REQUEST_TIMEOUT = 48 dtk, ditambah lookup 8 dtk masih di bawah timeoutMs
// adapter (70 dtk) dan di bawah tenggat proses scan (80 dtk).
const RESCAN_BUDGET_MS = 40_000
const MIN_POLL_BUDGET_MS = POLL_DELAY_MS + POLL_REQUEST_TIMEOUT_MS

type VtReport = {
  check: ProviderCheck
  observedAt: string | null
  ageMs: number | null
  stale: boolean
  rescanCandidate: boolean
}

function interpretVtReport(data: unknown, nowMs: number, maxAgeHours: number): VtReport {
  const root = recordValue(data)
  const dataRecord = recordValue(root?.data)
  const attributes = recordValue(dataRecord?.attributes) ?? {}
  const stats = recordValue(attributes.last_analysis_stats)

  const malicious = numberValue(stats?.malicious) ?? 0
  const suspicious = numberValue(stats?.suspicious) ?? 0
  const harmless = numberValue(stats?.harmless) ?? 0
  const undetected = numberValue(stats?.undetected) ?? 0
  // Mesin yang gagal/tidak melapor bukan "mesin yang memilih bersih". Keduanya dihitung
  // agar rasio 0/total tidak dibaca lebih kuat daripada kenyataannya.
  const analysisFailures = numberValue(stats?.failure) ?? 0
  const analysisTimeouts = numberValue(stats?.timeout) ?? 0
  const total = malicious + suspicious + harmless + undetected

  // Umur laporan dihitung dari waktu analisis provider, bukan dari waktu respons adapter,
  // supaya vonis dari analisis lama tidak pernah terbaca sebagai kondisi hari ini.
  const lastAnalysisAt = numberValue(attributes.last_analysis_date)
  const observedAt = lastAnalysisAt === null ? null : new Date(lastAnalysisAt * 1_000).toISOString()
  const ageMs = lastAnalysisAt === null ? null : Math.max(0, nowMs - lastAnalysisAt * 1_000)
  const stale = ageMs !== null && ageMs > maxAgeHours * 60 * 60_000

  const provenance: ProviderSignal = {
    label: 'Waktu analisis terakhir',
    detail: observedAt
      ? stale
        ? `Analisis terakhir ${formatObservedAt(observedAt)}, melewati batas umur laporan ${maxAgeHours} jam yang diterima agen ini.`
        : `Analisis terakhir ${formatObservedAt(observedAt)}.`
      : 'Agen tidak melaporkan waktu analisis terakhir untuk URL ini.',
    severity: stale ? 'warning' : 'info',
  }

  if (total === 0) {
    return {
      check: {
        status: 'success',
        verdict: 'inconclusive',
        score: null,
        summary: 'VirusTotal merespons, tetapi data analisis belum lengkap.',
        signals: [
          provenance,
          {
            label: 'Detection ratio VirusTotal',
            detail: 'Tidak tersedia. Tidak ada engine yang melaporkan hasil analisis.',
            severity: 'info',
          },
        ],
        reason: null,
      },
      observedAt,
      ageMs,
      stale,
      rescanCandidate: false,
    }
  }

  const ratioPercent = Math.round((malicious / total) * 10_000) / 100

  const signals: ProviderSignal[] = [
    provenance,
    {
      label: 'Detection ratio VirusTotal',
      detail: `${malicious}/${total} security engine menandai URL ini berbahaya (${ratioPercent}%).`,
      severity: 'info',
    },
  ]
  if (malicious > 0) {
    signals.push({
      label: 'Engine menandai berbahaya',
      detail: `${malicious} dari ${total} engine menandai URL ini berbahaya.`,
      severity: 'danger',
    })
  }
  if (suspicious > 0) {
    signals.push({
      label: 'Engine menandai mencurigakan',
      detail: `${suspicious} dari ${total} engine menandai URL ini mencurigakan.`,
      severity: 'warning',
    })
  }
  if (harmless > 0) {
    signals.push({
      label: 'Engine tidak menemukan indikasi',
      detail: `${harmless} dari ${total} engine tidak menemukan indikasi.`,
      severity: 'info',
    })
  }

  if (malicious > 0) {
    return {
      check: {
        status: 'success',
        verdict: 'malicious',
        score: clampScore(Math.max(60, malicious * 25 + suspicious * 10)),
        summary: `${malicious}/${total} engine mendeteksi berbahaya; ${suspicious} mencurigakan.`,
        signals,
        reason: null,
      },
      observedAt,
      ageMs,
      stale,
      // Vonis berbahaya tidak dikejar ulang: rescan bukan alat untuk melemahkan deteksi.
      rescanCandidate: false,
    }
  }

  if (suspicious > 0) {
    return {
      check: {
        status: 'success',
        verdict: 'suspicious',
        score: clampScore(Math.max(30, suspicious * 15)),
        summary: `0/${total} engine mendeteksi berbahaya; ${suspicious} engine menandai mencurigakan.`,
        signals,
        reason: null,
      },
      observedAt,
      ageMs,
      stale,
      rescanCandidate: false,
    }
  }

  // Rasio 0/total hanya bermakna bila cukup mesin yang benar-benar melaporkan hasil.
  // Dengan laporan yang sangat sedikit, "tidak ada yang menandai" belum bukti URL aman.
  if (total < MIN_ENGINES_FOR_CLEAN) {
    return {
      check: {
        status: 'success',
        verdict: 'inconclusive',
        score: null,
        summary: `0/${total} engine mendeteksi berbahaya, tetapi baru ${total} engine yang melaporkan hasil.`,
        signals,
        reason: 'Jumlah engine yang melaporkan masih sedikit, jadi hasilnya belum dapat dibaca sebagai aman.',
      },
      observedAt,
      ageMs,
      stale,
      rescanCandidate: false,
    }
  }

  // VGL-31 TAHAP 2 — laporan 0 berbahaya hanya menjadi bukti bila cukup mesin yang benar-benar
  // memberikan hasil DAN tidak ada mesin yang gagal/bisu.
  // VGL-32B: pembedaan harmless vs undetected tidak lagi menentukan kekuatan bukti. Laporan
  // yang LENGKAP (>= MIN_ENGINES_FOR_CLEAN mesin melapor, 0 berbahaya, 0 mencurigakan,
  // 0 gagal/bisu) adalah pernyataan agregat provider atas URL ini — sebuah vonis, bukan
  // kumpulan absennya tanda. Pada domain besar (mis. mail.google.com) mesin umumnya menjawab
  // `undetected`, sehingga syarat "harmless >= 20" dulu membuat bukti bersih eksplisit nyaris
  // tidak pernah tercapai meski provider jelas menyatakan 0 deteksi.
  const noCheckIssues = analysisFailures === 0 && analysisTimeouts === 0

  return {
    check: {
      status: 'success',
      verdict: 'clean',
      score: 0,
      summary: `0/${total} engine mendeteksi berbahaya.`,
      signals,
      reason: noCheckIssues
        ? null
        : `${analysisFailures + analysisTimeouts} engine tidak memberikan hasil, jadi rasio 0 tidak dapat dibaca sebagai bukti kebersihan.`,
      ...(noCheckIssues
        ? {
            negative: {
              strength: 'explicit' as const,
              scope: 'url' as const,
              evidenceClass: 'engine_verdicts' as const,
              basis: `Laporan lengkap: ${total} engine melapor (${harmless} memilih tidak berbahaya, ${undetected} tidak menemukan tanda), 0 berbahaya dan 0 mencurigakan, tanpa engine yang gagal.`,
            },
          }
        : {}),
    },
    observedAt,
    ageMs,
    stale,
    rescanCandidate: stale,
  }
}

type RescanOutcome =
  | { kind: 'fresh'; report: VtReport }
  | { kind: 'fallback'; reason: string }

async function rescanStaleReport(
  context: ProviderContext,
  config: ScannerConfig,
  maxAgeHours: number,
): Promise<RescanOutcome> {
  const startedAt = context.now()
  const apiKeyHeaders = { 'x-apikey': config.virusTotalApiKey as string }

  const submission = await fetchJson(
    context.fetchImpl,
    RESCAN_SUBMIT_URL,
    {
      method: 'POST',
      headers: { ...apiKeyHeaders, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ url: context.url }).toString(),
      ...(context.signal ? { signal: context.signal } : {}),
    },
    SUBMIT_REQUEST_TIMEOUT_MS,
  )

  // Satu percobaan saja. 429/400/kegagalan jaringan TIDAK pernah memicu submission ulang:
  // dokumentasi VT membatasi laju submit, dan mengirim ulang permintaan identik atas
  // penolakan 400 justru perilaku spam yang dihindari sistem ini sendiri.
  if (!submission.ok) {
    return { kind: 'fallback', reason: submission.reason }
  }

  const submissionRoot = recordValue(submission.data)
  const analysisId = stringValue(recordValue(submissionRoot?.data)?.id)
  if (!analysisId) {
    return {
      kind: 'fallback',
      reason: 'VirusTotal tidak mengembalikan ID analisis untuk permintaan pemindaian ulang.',
    }
  }

  let completed = false
  let lastPollReason: string | null = null
  for (let poll = 0; poll < MAX_POLLS; poll += 1) {
    const elapsedMs = context.now() - startedAt
    if (elapsedMs + MIN_POLL_BUDGET_MS > RESCAN_BUDGET_MS) {
      lastPollReason = 'Anggaran waktu pemindaian ulang tidak cukup untuk polls berikutnya.'
      break
    }
    await context.sleep(POLL_DELAY_MS)
    const pollResult = await fetchJson(
      context.fetchImpl,
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: apiKeyHeaders,
        ...(context.signal ? { signal: context.signal } : {}),
      },
      POLL_REQUEST_TIMEOUT_MS,
    )
    if (!pollResult.ok) {
      lastPollReason = pollResult.reason
      break
    }
    const pollAttributes = recordValue(
      recordValue(recordValue(pollResult.data)?.data)?.attributes,
    )
    // Respons live VT memakai varian "in-progress" (hyphen) di samping "in_progress" pada
    // dokumentasi, jadi status dinormalisasi sebelum diputuskan lanjut pantau atau berhenti.
    const status =
      stringValue(pollAttributes?.status)
        ?.toLowerCase()
        .replace(/[-\s]+/g, '_') ?? null
    if (status === 'completed') {
      completed = true
      break
    }
    if (status !== 'queued' && status !== 'in_progress' && status !== 'not_started') {
      lastPollReason = `VirusTotal menyelesaikan analisis dengan status "${status ?? 'tidak diketahui'}" tanpa hasil yang dapat dibaca.`
      break
    }
  }

  if (!completed) {
    return {
      kind: 'fallback',
      reason: lastPollReason ?? 'Pemindaian ulang belum selesai dalam batas waktu polling.',
    }
  }

  const reread = await fetchJson(
    context.fetchImpl,
    `https://www.virustotal.com/api/v3/urls/${toBase64Url(context.url)}`,
    {
      headers: apiKeyHeaders,
      ...(context.signal ? { signal: context.signal } : {}),
    },
    REREAD_REQUEST_TIMEOUT_MS,
  )
  if (!reread.ok) {
    return { kind: 'fallback', reason: reread.reason }
  }

  const report = interpretVtReport(reread.data, context.now(), maxAgeHours)
  // Laporan hasil rescan yang timestamp-nya tetap lama tidak boleh dilabeli baru.
  if (report.stale || report.ageMs === null) {
    return {
      kind: 'fallback',
      reason: 'Laporan hasil pemindaian ulang masih berumur lewat batas yang diterima agen ini.',
    }
  }

  return { kind: 'fresh', report }
}

export const virusTotalAdapter: ProviderAdapter = {
  id: 'virustotal',
  label: 'VirusTotal',
  requiredEnv: ['VIRUSTOTAL_API_KEY'],
  // Siklus lookup + submit + polling + baca ulang butuh lebih dari default 50 dtk; tetap
  // di bawah batas provider maksimum (75 dtk) dan tenggat proses scan (80 dtk).
  timeoutMs: 70_000,
  isConfigured: (config) => Boolean(config.virusTotalApiKey),
  async check(context, config): Promise<ProviderCheck> {
    if (!config.virusTotalApiKey) {
      return notConfiguredCheck('VIRUSTOTAL_API_KEY belum dikonfigurasi di backend.')
    }

    const id = toBase64Url(context.url)
    const maxAgeHours = config.virusTotalMaxReportAgeHours ?? DEFAULT_MAX_REPORT_AGE_HOURS

    const response = await fetchJson(
      context.fetchImpl,
      `https://www.virustotal.com/api/v3/urls/${id}`,
      { headers: { 'x-apikey': config.virusTotalApiKey } },
      LOOKUP_REQUEST_TIMEOUT_MS,
    )

    if (!response.ok) {
      return response.kind === 'not_found'
        ? notFoundCheck('VirusTotal belum memiliki data untuk URL ini.')
        : failureCheck(response)
    }

    const first = interpretVtReport(response.data, context.now(), maxAgeHours)
    if (!first.rescanCandidate) {
      return withExistingReportEvidence(first.check, first.observedAt, first.ageMs)
    }

    // VGL-33A: laporan bersih yang kedaluwarsa di-vonis engine sebagai bukti tak berlaku.
    // Mekanisme resmi provider dipakai sekali untuk mengejar laporan baru; kegagalan apa pun
    // kembali ke laporan lama tanpa perubahan (stale, timestamp asli, transparan di signals).
    const outcome = await rescanStaleReport(context, config, maxAgeHours)
    if (outcome.kind === 'fresh') {
      const stamped = withExistingReportEvidence(
        outcome.report.check,
        outcome.report.observedAt,
        outcome.report.ageMs,
      )
      return {
        ...stamped,
        evidence: {
          source: 'new_scan',
          observedAt: outcome.report.observedAt,
          ageMs: outcome.report.ageMs,
        },
      }
    }

    const notice: ProviderSignal = {
      label: 'Pemulihan laporan kedaluwarsa',
      detail: `Analisis baru atas laporan lama belum berhasil diperoleh: ${outcome.reason} Laporan lama tetap dipakai apa adanya beserta umur aslinya.`,
      severity: 'warning',
    }
    return withExistingReportEvidence(
      { ...first.check, signals: [...first.check.signals, notice] },
      first.observedAt,
      first.ageMs,
    )
  },
}

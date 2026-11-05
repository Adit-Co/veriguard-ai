import { fetchJson, type FetchJsonResult } from '../http.js'
import { normalizeScanUrl } from '../url.js'
import {
  booleanValue,
  clampScore,
  errorCheck,
  failureCheck,
  numberValue,
  recordValue,
  stringList,
  stringValue,
  notConfiguredCheck,
  timeoutCheck,
  withExistingReportEvidence,
} from '../result.js'
import type {
  ProviderAdapter,
  ProviderCheck,
  ProviderContext,
  ProviderSignal,
  ScannerConfig,
} from '../types.js'

const SUBMIT_URL = 'https://urlscan.io/api/v1/scan/'
const RESULT_URL = 'https://urlscan.io/api/v1/result/'
const SEARCH_URL = 'https://urlscan.io/api/v1/search/'
const RESULT_REQUEST_TIMEOUT_MS = 5_000
const SEARCH_REQUEST_TIMEOUT_MS = 6_000
const SUBMIT_REQUEST_TIMEOUT_MS = 10_000
const POLL_DELAY_MS = 2_000
const MAX_POLLS = 40
// Anggaran dihitung dari waktu berjalan (tidur + permintaan), sehingga adapter berhenti
// sendiri sebelum pembatas waktu provider memutusnya dan menghasilkan `timeout` palsu.
// Total terburuk (lookup + submit 10 dtk + anggaran 60 dtk) harus tetap di bawah timeoutMs adapter.
const POLL_BUDGET_MS = 60_000
const STOP_MARGIN_MS = RESULT_REQUEST_TIMEOUT_MS
const MIN_POLL_BUDGET_MS = POLL_DELAY_MS + STOP_MARGIN_MS
// Laporan lama dibaca langsung; bila belum selesai, jeda polling dibuat singkat.
const REUSE_READ_BUDGET_MS = 12_000
// Satu 429 di tengah polling tidak menghapus pemindaian yang sudah dikirim: tunggu lebih
// lama (mengikuti Retry-After provider) lalu coba sekali lagi selama anggaran masih cukup.
const LIMIT_BACKOFF_MS = 8_000
const UUID_PATTERN = /^[a-f0-9-]{16,64}$/i
const DEFAULT_MAX_REPORT_AGE_HOURS = 24

function maxReportAgeMs(config: ScannerConfig): number {
  const hours = config.urlscanMaxReportAgeHours ?? DEFAULT_MAX_REPORT_AGE_HOURS
  return hours * 60 * 60_000
}

function checkFromResult(value: unknown): ProviderCheck | null {
  const root = recordValue(value)
  const verdicts = recordValue(root?.verdicts)
  if (!verdicts) return null

  const overall = recordValue(verdicts.overall)
  const engines = recordValue(verdicts.engines)
  const score = clampScore(numberValue(overall?.score) ?? 0)
  const categories = stringList(overall?.categories)
  const tags = stringList(overall?.tags)
  const brands = stringList(overall?.brands)
  const malicious =
    booleanValue(overall?.malicious) === true || booleanValue(engines?.malicious) === true

  const signals: ProviderSignal[] = []
  if (categories.length > 0) {
    signals.push({
      label: 'Kategori URLScan',
      detail: categories.join(', '),
      severity: 'warning',
    })
  }
  if (brands.length > 0) {
    signals.push({
      label: 'Merek yang terdeteksi',
      detail: brands.join(', '),
      severity: 'info',
    })
  }
  const maliciousTotal = numberValue(engines?.maliciousTotal)
  if (maliciousTotal !== null && maliciousTotal > 0) {
    signals.push({
      label: 'Mesin URLScan menandai ancaman',
      detail: `${maliciousTotal} mesin menandai URL ini.`,
      severity: 'danger',
    })
  }
  if (tags.length > 0) {
    signals.push({
      label: 'Tag URLScan',
      detail: tags.join(', '),
      severity: 'info',
    })
  }

  // Konvensi skor URLScan.io (verifikasi dari dokumentasi resmi 2026-10-28):
  //   `verdicts.overall.score` = skor RISIKO 0..100 (0 = tanpa indikasi, 100 = sangat
  //   berbahaya). Ini BUKAN skor reputasi terbalik. Provider kadang mengirim
  //   `malicious: true` dengan `score: 0` (mis. hasil parsial), jadi VERIGUARD memakai
  //   band minimum agar label "Berbahaya" tidak menampilkan "0/100" yang menyesatkan.
  //   Skor mentah provider tetap ditampilkan apa adanya lewat signal "Makna skor" supaya
  //   pengguna dapat melihat angka asli tanpa mengira VERIGUARD mengubah bukti.
  signals.push({
    label: 'Makna skor',
    detail:
      'Skor URLScan adalah skala risiko 0..100 (makin tinggi makin berbahaya). VERIGUARD menyesuaikan band minimum agar vonis tidak bertentangan dengan skor, tanpa mengubah bukti mentah provider.',
    severity: 'info',
  })

  if (malicious || score >= 75) {
    const bandedScore = Math.max(75, score)
    // Provider menandai berbahaya tanpa detail engine/kategori/tag/brand: laporkan
    // keterbatasan ini secara jujur, JANGAN mengarang alasan.
    if (
      categories.length === 0 &&
      brands.length === 0 &&
      tags.length === 0 &&
      (maliciousTotal === null || maliciousTotal === 0)
    ) {
      signals.push({
        label: 'Keterbatasan bukti',
        detail:
          maliciousTotal === null || maliciousTotal === 0
            ? 'URLScan memberi bendera `malicious` pada laporan ini tanpa merinci engine, kategori, atau tag yang menjadi dasar. Vonis provider dibaca apa adanya; detail tambahan tidak dikarang.'
            : 'URLScan memberi bendera `malicious` tanpa merinci alasan spesifik.',
        severity: 'warning',
      })
    }
    if (score < 75) {
      signals.push({
        label: 'Skor mentah provider',
        detail: `URLScan mengirim skor mentah ${score}/100 namun menandai bendera malicious; VERIGUARD menaikkan band menjadi ${bandedScore}/100 agar konsisten dengan vonis.`,
        severity: 'info',
      })
    }
    return {
      status: 'success',
      verdict: 'malicious',
      score: bandedScore,
      summary: `URLScan menilai URL ini berbahaya (skor ${bandedScore}/100).`,
      signals,
      reason: null,
    }
  }

  const suspiciousCategory = categories.some((category) =>
    /phishing|malware|scam|suspicious/i.test(category),
  )

  if (score >= 30 || suspiciousCategory) {
    return {
      status: 'success',
      verdict: 'suspicious',
      score: Math.max(30, score),
      summary: `URLScan menemukan indikasi risiko (skor ${Math.max(30, score)}/100).`,
      signals,
      reason: null,
    }
  }

  // VGL-31 TAHAP 2 — skor 0 atau daftar kategori kosong BUKAN dengan sendirinya vonis bersih.
  // Yang boleh dihitung sebagai bukti negatif eksplisit hanyalah respons yang benar-benar
  // menyatakan kedua hal itu: `verdicts.overall.score` dikirim provider (bukan nol hasil
  // default kita) dan `categories` memang sebuah daftar (termasuk daftar kosong yang berarti
  // "diklasifikasikan, tidak ada kategori berbahaya").
  const scoreStated = numberValue(overall?.score) !== null
  const classificationStated = Array.isArray(overall?.categories)

  if (!scoreStated || !classificationStated) {
    return {
      status: 'success',
      verdict: 'inconclusive',
      score: null,
      summary: 'URLScan mengembalikan vonis tanpa menyatakan skor atau klasifikasinya.',
      signals,
      reason:
        'Ketiadaan angka pada respons tidak dapat dibaca sebagai "bersih"; VERIGUARD tidak mengarang vonis dari bagian respons yang tidak dikirim provider.',
    }
  }

  return {
    status: 'success',
    verdict: 'clean',
    score: 0,
    summary: 'URLScan tidak menemukan indikasi berbahaya.',
    signals,
    reason: null,
    negative: {
      strength: 'explicit',
      scope: 'url',
      evidenceClass: 'scan_verdict',
      basis:
        'Pemindaian URL ini selesai dan URLScan menyatakan skor serta daftar klasifikasinya secara eksplisit, tanpa bendera berbahaya.',
    },
  }
}

function withExistingEvidence(
  check: ProviderCheck,
  ageMs: number,
  observedAt: string,
): ProviderCheck {
  return withExistingReportEvidence(check, observedAt, ageMs)
}

type ExistingReport = {
  uuid: string
  observedAt: string
  ageMs: number
}

function sameTarget(candidate: string, target: string): boolean {
  try {
    return normalizeScanUrl(candidate) === target
  } catch {
    return false
  }
}

function findExistingReport(
  value: unknown,
  target: string,
  nowMs: number,
  maxAgeMs: number,
): { fresh: ExistingReport | null; newest: ExistingReport | null } {
  const root = recordValue(value)
  const results = Array.isArray(root?.results) ? root.results : []
  let fresh: ExistingReport | null = null
  let newest: ExistingReport | null = null

  for (const entry of results) {
    const record = recordValue(entry)
    const task = recordValue(record?.task)
    const uuid = stringValue(task?.uuid)
    const observedAt = stringValue(task?.time)
    // Identitas laporan adalah URL yang DIKIRIM (task.url), bukan halaman akhir (page.url).
    // page.url adalah tujuan redirect: laporan yang dikirim sebagai tautan phishing lalu
    // mengalihkan korban ke situs resmi juga punya page.url resmi, sementara vonis provider
    // bercerita tentang pengiriman itu — bukan tentang situs resmi. Kecocokan pada page.url
    // menghasilkan vonis "berbahaya" untuk situs resmi, dan sebaliknya membuang laporan yang
    // justru dikirim untuk URL ini ketika situs tersebut berpindah halaman.
    const submittedUrl = stringValue(task?.url)
    if (!uuid || !UUID_PATTERN.test(uuid) || !observedAt || !submittedUrl) continue

    const timestamp = Date.parse(observedAt)
    if (Number.isNaN(timestamp)) continue

    const ageMs = Math.max(0, nowMs - timestamp)
    const report: ExistingReport = { uuid, observedAt, ageMs }

    if (!sameTarget(submittedUrl, target)) continue
    if (!newest || report.ageMs < newest.ageMs) newest = report
    if (ageMs <= maxAgeMs && (!fresh || report.ageMs < fresh.ageMs)) fresh = report
  }

  return { fresh, newest }
}

type ReadOutcome =
  | { kind: 'check'; check: ProviderCheck }
  | { kind: 'failed'; failure: Extract<FetchJsonResult, { ok: false }> }
  | { kind: 'unfinished' }

async function readScanResult(
  context: ProviderContext,
  config: ScannerConfig,
  uuid: string,
  options: { budgetMs: number; firstDelayMs: number },
): Promise<ReadOutcome> {
  const deadlineAt = context.now() + options.budgetMs
  let delayMs = options.firstDelayMs

  for (let attempt = 0; attempt < MAX_POLLS; attempt += 1) {
    if (deadlineAt - context.now() < delayMs + STOP_MARGIN_MS) return { kind: 'unfinished' }
    if (delayMs > 0) await context.sleep(delayMs)

    const result = await fetchJson(
      context.fetchImpl,
      `${RESULT_URL}${encodeURIComponent(uuid)}/`,
      { headers: { 'API-Key': config.urlscanApiKey ?? '' } },
      RESULT_REQUEST_TIMEOUT_MS,
    )

    if (!result.ok) {
      if (result.kind === 'not_found') {
        delayMs = POLL_DELAY_MS
        continue
      }

      if (result.kind === 'rate_limited' && delayMs <= POLL_DELAY_MS) {
        const waitMs = Math.max(LIMIT_BACKOFF_MS, result.retryAfterMs ?? 0)
        if (deadlineAt - context.now() >= waitMs + STOP_MARGIN_MS) {
          delayMs = waitMs
          continue
        }
      }

      return { kind: 'failed', failure: result }
    }

    delayMs = POLL_DELAY_MS
    const check = checkFromResult(result.data)
    if (check) return { kind: 'check', check }
  }

  return { kind: 'unfinished' }
}

export const urlScanAdapter: ProviderAdapter = {
  id: 'urlscan',
  label: 'URLScan.io',
  requiredEnv: ['URLSCAN_API_KEY'],
  timeoutMs: 75_000,
  isConfigured: (config) => Boolean(config.urlscanApiKey),
  async check(context, config): Promise<ProviderCheck> {
    if (!config.urlscanApiKey) {
      return notConfiguredCheck('URLSCAN_API_KEY belum dikonfigurasi di backend.')
    }

    const startedAt = context.now()
    // Pemindaian privat hanya 5/menit dan 50/hari pada key biasa, sedangkan lookup hasil
    // pencarian jauh lebih longgar. Karena itu laporan yang sudah ada dipakai lebih dulu.
    // Field kueri harus field identitas laporan (task.url = URL yang dikirim, menurut
    // https://urlscan.io/docs/search/). page.url adalah halaman akhir setelah redirect, jadi
    // laporan untuk URL ini tidak pernah ditemukan dan permintaan ulang berakhir HTTP 400.
    const lookup = await fetchJson(
      context.fetchImpl,
      `${SEARCH_URL}?q=${encodeURIComponent(`task.url:"${context.url}"`)}&size=5`,
      { headers: { 'API-Key': config.urlscanApiKey } },
      SEARCH_REQUEST_TIMEOUT_MS,
    )

    // 429 pada lookup berarti kuota account sudah habis: jangan mengirim pemindaian baru.
    if (!lookup.ok) {
      if (lookup.kind === 'rate_limited' || lookup.kind === 'auth_failed') {
        return failureCheck(lookup)
      }
    }

    const found = lookup.ok
      ? findExistingReport(lookup.data, context.url, context.now(), maxReportAgeMs(config))
      : null

    if (found?.fresh) {
      const read = await readScanResult(context, config, found.fresh.uuid, {
        budgetMs: REUSE_READ_BUDGET_MS,
        firstDelayMs: 0,
      })
      if (read.kind === 'check') {
        return withExistingEvidence(read.check, found.fresh.ageMs, found.fresh.observedAt)
      }
      if (
        read.kind === 'failed' &&
        (read.failure.kind === 'rate_limited' || read.failure.kind === 'auth_failed')
      ) {
        return failureCheck(read.failure)
      }
    }

    const remainingBudgetMs = POLL_BUDGET_MS - (context.now() - startedAt)
    if (remainingBudgetMs < MIN_POLL_BUDGET_MS) {
      return timeoutCheck('Batas waktu URLScan tidak cukup untuk memulai pemindaian baru.')
    }

    const submission = await fetchJson(
      context.fetchImpl,
      SUBMIT_URL,
      {
        method: 'POST',
        headers: {
          'API-Key': config.urlscanApiKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: context.url, visibility: 'private' }),
      },
      SUBMIT_REQUEST_TIMEOUT_MS,
    )

    if (!submission.ok) {
      // Pemindaian yang sudah pernah dikirim tetap dipakai bila laporan lamanya tersedia,
      // dengan umur laporan yang jujur; tidak pernah mengirim ulang setelah HTTP 429.
      // Permintaan yang DITOLAK (HTTP 400/422) masuk cabang yang sama: provider menolak
      // pembuatan pemindaian baru, sedangkan bukti yang sudah ada di lookup tetap sah dan
      // lebih berguna daripada melaporkan "tidak dapat dinilai".
      if (
        (submission.kind === 'rate_limited' || submission.kind === 'invalid_request') &&
        found?.newest
      ) {
        const stale = await readScanResult(context, config, found.newest.uuid, {
          budgetMs: REUSE_READ_BUDGET_MS,
          firstDelayMs: 0,
        })
        if (stale.kind === 'check') {
          return withExistingEvidence(stale.check, found.newest.ageMs, found.newest.observedAt)
        }
      }
      return failureCheck(submission)
    }

    const submissionRoot = recordValue(submission.data)
    const uuid = stringValue(submissionRoot?.uuid)
    if (!uuid || !UUID_PATTERN.test(uuid)) {
      return errorCheck('URLScan tidak mengembalikan ID pemindaian yang valid.')
    }

    const poll = await readScanResult(context, config, uuid, {
      budgetMs: remainingBudgetMs,
      firstDelayMs: POLL_DELAY_MS,
    })

    if (poll.kind === 'check') {
      return {
        ...poll.check,
        evidence: { source: 'new_scan', observedAt: null, ageMs: 0 },
      }
    }
    if (poll.kind === 'failed') return failureCheck(poll.failure)

    return timeoutCheck('URLScan belum menyelesaikan pemindaian dalam batas waktu.')
  },
}

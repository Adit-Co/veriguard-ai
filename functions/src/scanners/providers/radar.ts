import {
  booleanValue,
  errorCheck,
  failureCheck,
  notConfiguredCheck,
  recordValue,
  stringList,
  stringValue,
  timeoutCheck,
  withExistingReportEvidence,
} from '../result.js'
import {
  describeError,
  describeQuota,
  discardResponseBody,
  rateLimitInfo,
  readBoundedJson,
  retryAfterMs,
} from '../http.js'
import { normalizeScanUrl } from '../url.js'
import type { ProviderAdapter, ProviderCheck, ProviderStatus, ScannerConfig } from '../types.js'

const SCAN_ENDPOINT = 'https://api.cloudflare.com/client/v4/accounts'
const RESULT_REQUEST_TIMEOUT_MS = 8_000
const SEARCH_REQUEST_TIMEOUT_MS = 8_000
const SUBMIT_REQUEST_TIMEOUT_MS = 10_000
const POLL_DELAY_MS = 2_000
const MAX_POLLS = 30
// Anggaran dihitung dari awal pemeriksaan (lookup + submit + polling) agar berhenti sendiri
// sebelum dipotong provider. Worst case = TOTAL_BUDGET + RESULT_REQUEST_TIMEOUT = 66 dtk,
// masih di bawah timeoutMs adapter (70 dtk) dan di bawah tenggat proses scan (80 dtk).
const TOTAL_BUDGET_MS = 58_000
const STOP_MARGIN_MS = RESULT_REQUEST_TIMEOUT_MS
const MIN_POLL_BUDGET_MS = POLL_DELAY_MS + STOP_MARGIN_MS
// Laporan yang dipakai ulang dibaca tanpa jeda polling; batasnya terpisah dari anggaran utama.
const REUSE_READ_BUDGET_MS = 12_000
const UUID_PATTERN = /^[a-f0-9-]{16,64}$/i
const DEFAULT_MAX_REPORT_AGE_HOURS = 24
// Cloudflare URL Scanner memakai satu boolean `malicious` plus daftar kategori/tag. Sebagian
// kategori bersifat keamanan (phishing, malware) dan sebagian hanya taksonomi konten (iklan,
// analitik). Tanpa pemisahan ini, vonis berjenjang akan terbaca sebagai "bersih".
const SECURITY_VERDICT_PATTERN =
  /(malicious|blacklist|phish|malware|ransom|crypto.?min|botnet|exploit|scam|trojan|worm|virus|compromis|potentially.?unwanted|open.?redirect|social.?engineering|spam|fraud|fake.?store)/i
const CONTENT_CATEGORY_PATTERN =
  /(advertis|analytic|chat|forum|search|social.?media|dating|vpn|streaming|gambl|porn|violence|hate|news|shopping|educat|technolog|business|gaming|webmail|blog|wiki|cdn|hosting|job|finance|health|travel|sport|art|culture|kids|government|military|translation|keyword|redirect|cookie|popups|aggregator|domain.?parking|parked|no.?content|placeholder|web.?ads)/i

// Satu 429 di tengah polling tidak menghapus pemindaian yang sudah dikirim: tunggu lebih
// lama (mengikuti Retry-After Cloudflare) lalu coba sekali lagi selama anggaran masih cukup.
const LIMIT_BACKOFF_MS = 8_000

type RadarRequestResult =
  | { ok: true; status: number; data: unknown }
  | {
      ok: false
      status: number | null
      kind: ProviderStatus
      reason: string
      retryAfterMs?: number | null
    }

function maxReportAgeMs(config: ScannerConfig): number {
  const hours = config.radarMaxReportAgeHours ?? DEFAULT_MAX_REPORT_AGE_HOURS
  return hours * 60 * 60_000
}

/**
 * Pemetaan kegagalan permintaan memakai taksonomi yang sama dengan `fetchJson` (http.ts):
 * pembatalan oleh proses scan -> skipped, tenggat kami -> timeout, selain itu penyedia
 * benar-benar tidak dapat dihubungi (DNS/TCP/TLS). Sebelumnya galat jaringan non-timeout
 * dibuang sebagai "dibatalkan", sehingga kegagalan DNS tampil sebagai agen yang tidak
 * berjalan dan penyebabnya tidak terbaca sama sekali.
 */
function requestFailure(
  error: unknown,
  timedOut: boolean,
  aborted: boolean,
): RadarRequestResult {
  if (aborted && !timedOut) {
    return {
      ok: false,
      status: null,
      kind: 'skipped',
      reason: 'Permintaan ke Cloudflare URL Scanner dibatalkan saat proses scan berjalan.',
    }
  }

  const abortLike = error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError')

  if (timedOut || abortLike) {
    return {
      ok: false,
      status: null,
      kind: 'timeout',
      reason: 'Permintaan ke Cloudflare URL Scanner melebihi batas waktu.',
    }
  }

  return {
    ok: false,
    status: null,
    kind: 'unavailable',
    reason: `Provider tidak dapat dihubungi. (${describeError(error)})`,
  }
}

async function requestRadarJson(
  context: Parameters<ProviderAdapter['check']>[0],
  method: 'GET' | 'POST',
  input: string,
  headers: Record<string, string>,
  body: string | undefined,
  timeoutMs: number,
): Promise<RadarRequestResult> {
  const controller = new AbortController()
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeoutMs)
  const externalSignal = context.signal
  const onExternalAbort = () => controller.abort()
  if (externalSignal?.aborted) controller.abort()
  else {
    externalSignal?.addEventListener('abort', onExternalAbort, { once: true })
  }

  try {
    const response = await context.fetchImpl(input, {
      method,
      headers,
      body,
      redirect: 'error',
      signal: controller.signal,
    })
    // Status diperiksa DAN body dibuang lebih dulu untuk kegagalan. Body respons error adalah
    // teks bebas dari pihak ketiga yang tidak pernah dibutuhkan antarmuka; membacanya sebagai
    // JSON sebelum tahu status memberi jalan respons besar atau berisi echoed input masuk ke
    // proses. Body hanya dibaca untuk respons yang memang dipakai, dengan batas ukuran.
    if (response.status === 401 || response.status === 403) {
      discardResponseBody(response)
      return {
        ok: false,
        status: response.status,
        kind: 'auth_failed',
        reason: 'Token API Cloudflare ditolak.',
      }
    }

    // Menurut dokumentasi Cloudflare, hasil pemindaian yang masih berjalan menjawab 404.
    if (response.status === 404 && method === 'GET') {
      discardResponseBody(response)
      return {
        ok: false,
        status: response.status,
        kind: 'not_found',
        reason: 'Hasil pemindaian belum tersedia di Cloudflare URL Scanner.',
      }
    }

    if (response.status === 429) {
      const nowMs = context.now()
      const retryAfter = retryAfterMs(response, nowMs)
      const quota = rateLimitInfo(response, nowMs)
      const waitMs = retryAfter ?? quota?.resetAfterMs ?? null
      const quotaText = describeQuota(quota)
      const hint =
        waitMs === null
          ? null
          : retryAfter !== null
            ? `Cloudflare menyarankan jeda ${Math.round(waitMs / 1_000)} detik`
            : `jendela kuota berikutnya terbuka dalam ±${Math.round(waitMs / 1_000)} detik`
      discardResponseBody(response)
      return {
        ok: false,
        status: response.status,
        kind: 'rate_limited',
        reason:
          hint === null
            ? 'Kuota permintaan Cloudflare tercapai.'
            : `Kuota permintaan Cloudflare tercapai; ${hint}${quotaText ? ` (${quotaText})` : ''}.`,
        retryAfterMs: waitMs,
      }
    }

    // Bentuk permintaan kami ditolak provider. Sam dengan http.ts: body TIDAK dibaca untuk
    // alasan, karena isinya bebas dan bisa membawa URL/parameter permintaan; yang dibutuhkan
    // antarmuka hanyalah "permintaan ditolak" plus status HTTP-nya. Status ini BUKAN vonis:
    // failureCheck memutusnya menjadi inconclusive.
    if (response.status === 400 || response.status === 422) {
      discardResponseBody(response)
      return {
        ok: false,
        status: response.status,
        kind: 'invalid_request',
        reason: 'Permintaan pemeriksaan ditolak provider.',
      }
    }

    if (!response.ok && response.status !== 409) {
      const kind: ProviderStatus = response.status >= 500 ? 'unavailable' : 'error'
      discardResponseBody(response)
      return {
        ok: false,
        status: response.status,
        kind,
        reason:
          kind === 'unavailable'
            ? 'Layanan provider sedang tidak tersedia.'
            : `Provider menolak permintaan (HTTP ${response.status}).`,
      }
    }

    const data: unknown = await readBoundedJson(response)
    return { ok: true, status: response.status, data }
  } catch (error) {
    return requestFailure(error, timedOut, controller.signal.aborted)
  } finally {
    clearTimeout(timer)
    externalSignal?.removeEventListener('abort', onExternalAbort)
  }
}

function uuidFromSubmission(data: unknown): string | null {
  const root = recordValue(data)
  const result = recordValue(root?.result)
  const direct =
    stringValue(result?.uuid) ??
    stringValue(root?.uuid) ??
    stringValue(recordValue(result?.task)?.uuid)
  if (direct && UUID_PATTERN.test(direct)) return direct

  const tasks = Array.isArray(result?.tasks) ? result?.tasks : Array.isArray(root?.tasks) ? root?.tasks : []
  for (const entry of tasks) {
    const uuid = stringValue(recordValue(entry)?.uuid)
    if (uuid && UUID_PATTERN.test(uuid)) return uuid
  }
  return null
}

function checkFromResult(value: unknown): ProviderCheck | null {
  const root = recordValue(value)
  if (!root) return null

  const task = recordValue(root.task)
  const status = stringValue(task?.status)?.toLowerCase() ?? null

  if (booleanValue(task?.success) === false) {
    return errorCheck(
      'Cloudflare URL Scanner menyelesaikan pemindaian dengan status gagal (misalnya kesalahan DNS), sehingga tidak ada vonis yang dapat dilaporkan.',
    )
  }

  if (status && status !== 'finished' && status !== 'success') {
    return null
  }

  const verdicts = recordValue(root.verdicts)
  const overall = recordValue(verdicts?.overall)
  if (!overall) return null

  const categories = stringList(overall.categories)
  const tags = stringList(overall.tags)
  const reportUrl = stringValue(task?.reportURL)

  const signals: ProviderCheck['signals'] = []
  if (categories.length > 0) {
    signals.push({
      label: 'Kategori pemindai',
      detail: categories.join(', '),
      severity: 'warning',
    })
  }
  if (tags.length > 0) {
    signals.push({
      label: 'Tag pemindai',
      detail: tags.join(', '),
      severity: 'info',
    })
  }
  if (reportUrl) {
    signals.push({
      label: 'Laporan Cloudflare',
      detail: 'Hasil pemindaian dapat dibuka di Cloudflare Radar.',
      severity: 'info',
    })
  }

  if (booleanValue(overall.malicious) === true) {
    return {
      status: 'success',
      verdict: 'malicious',
      score: 85,
      summary: 'Cloudflare URL Scanner menilai URL ini berbahaya.',
      signals,
      reason: null,
    }
  }

  const verdictLabels = [...categories, ...tags]
  const securityLabels = verdictLabels.filter((label) => SECURITY_VERDICT_PATTERN.test(label))
  if (securityLabels.length > 0) {
    return {
      status: 'success',
      verdict: 'suspicious',
      score: 60,
      summary: `Cloudflare URL Scanner memberi vonis berjenjang untuk URL ini (${securityLabels.join(', ')}).`,
      signals,
      reason: 'Vonis keamanan tingkat rendah dilaporkan sebagai suspicious, bukan clean.',
    }
  }

  if (booleanValue(overall.hasVerdicts) === true) {
    // `hasVerdicts` hanya berarti "ada label", bukan "labelnya aman". Kategori yang tidak
    // dikenal taksonomi ini tidak boleh dinaik-turunkan menjadi clean.
    const unknown = verdictLabels.filter(
      (label) => !label.trim() || !CONTENT_CATEGORY_PATTERN.test(label),
    )
    if (unknown.length > 0) {
      return {
        status: 'success',
        verdict: 'inconclusive',
        score: null,
        summary: 'Cloudflare URL Scanner memberi vonis dengan kategori yang tidak dapat dipastikan aman.',
        signals,
        reason: `Kategori tidak dikenal taksonomi VERIGUARD: ${unknown.join(', ')}.`,
      }
    }
    return {
      status: 'success',
      verdict: 'clean',
      score: 0,
      summary: 'Cloudflare URL Scanner memberikan vonis dan tidak menandai URL ini berbahaya.',
      signals,
      reason: null,
      // VGL-31 TAHAP 2: yang dihitung BUKAN "tidak ada kategori ancaman", melainkan vonis yang
      // benar-benar diberikan pemindai atas URL ini. Cakupan yang jelas berarti provider menyebut
      // minimal satu kategori dan semuanya dikenali VERIGUARD sebagai konten tanpa tanda bahaya;
      // vonis tanpa satu label pun tetap konsisten dengan "tidak berbahaya", tapi kekuatannya
      // terbatas dan tidak boleh berdiri sendiri sebagai kepastian bersih.
      negative:
        verdictLabels.length > 0
          ? {
              strength: 'explicit',
              scope: 'url',
              evidenceClass: 'scanner_verdict',
              basis: `Pemindaian selesai dengan vonis eksplisit dan seluruh kategori yang dilaporkan (${verdictLabels.join(', ')}) dikenali VERIGUARD sebagai konten tanpa tanda bahaya.`,
            }
          : {
              strength: 'limited',
              scope: 'url',
              evidenceClass: 'scanner_verdict',
              basis:
                'Provider menyatakan punya vonis tetapi tidak mengirim satu pun kategori; tidak ada kategori berbahaya memang, namun tanpa label yang dikenali cakupannya tidak jelas, jadi ini hanya bukti pendukung.',
            },
    }
  }

  return {
    status: 'success',
    verdict: 'inconclusive',
    score: null,
    summary: 'Cloudflare URL Scanner selesai memindai tanpa menghasilkan vonis.',
    signals,
    reason: 'Pemindaian bersih tanpa vonis tidak menjamin URL aman.',
  }
}

type ExistingScan = {
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

function finishedTask(value: unknown): { uuid: string; observedAt: string; timestamp: number } | null {
  const task = recordValue(value)
  const uuid = stringValue(task?.uuid)
  const observedAt = stringValue(task?.time)
  if (!uuid || !UUID_PATTERN.test(uuid) || !observedAt) return null
  if (booleanValue(task?.success) === false) return null

  const timestamp = Date.parse(observedAt)
  if (Number.isNaN(timestamp)) return null

  return { uuid, observedAt, timestamp }
}

// Rute pencarian Cloudflare hanya mengembalikan laporan yang sudah selesai; pemindaian
// yang sedang berjalan harus dikirim ulang, bukan dipakai sebagai bukti.
function findExistingScan(
  value: unknown,
  target: string,
  nowMs: number,
  maxAgeMs: number,
): { fresh: ExistingScan | null; newest: ExistingScan | null } {
  const root = recordValue(value)
  const results = Array.isArray(root?.results) ? root.results : []
  let fresh: ExistingScan | null = null
  let newest: ExistingScan | null = null

  for (const entry of results) {
    const record = recordValue(entry)
    const task = recordValue(record?.task)
    const submittedUrl = stringValue(task?.url)
    if (!submittedUrl || !sameTarget(submittedUrl, target)) continue

    const parsed = finishedTask(task)
    if (!parsed) continue

    const report: ExistingScan = {
      uuid: parsed.uuid,
      observedAt: parsed.observedAt,
      ageMs: Math.max(0, nowMs - parsed.timestamp),
    }

    if (!newest || report.ageMs < newest.ageMs) newest = report
    if (report.ageMs <= maxAgeMs && (!fresh || report.ageMs < fresh.ageMs)) fresh = report
  }

  return { fresh, newest }
}

type ReadResult =
  | { kind: 'check'; check: ProviderCheck }
  | { kind: 'unfinished' }
  | { kind: 'failed'; failure: Extract<RadarRequestResult, { ok: false }> }

async function readScanResult(
  context: Parameters<ProviderAdapter['check']>[0],
  resultUrl: string,
  headers: Record<string, string>,
  options: { budgetMs: number; firstDelayMs: number },
): Promise<ReadResult> {
  const deadlineAt = context.now() + options.budgetMs
  let delayMs = options.firstDelayMs

  for (let attempt = 0; attempt < MAX_POLLS; attempt += 1) {
    if (deadlineAt - context.now() < delayMs + STOP_MARGIN_MS) return { kind: 'unfinished' }
    if (delayMs > 0) await context.sleep(delayMs)

    const result = await requestRadarJson(
      context,
      'GET',
      resultUrl,
      headers,
      undefined,
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

function withExistingEvidence(
  check: ProviderCheck,
  ageMs: number,
  observedAt: string,
): ProviderCheck {
  return withExistingReportEvidence(check, observedAt, ageMs)
}

export const radarAdapter: ProviderAdapter = {
  id: 'radar',
  label: 'Cloudflare Radar URL Scanner',
  requiredEnv: ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'],
  timeoutMs: 70_000,
  isConfigured: (config) => Boolean(config.cloudflareApiToken && config.cloudflareAccountId),
  async check(context, config): Promise<ProviderCheck> {
    if (!config.cloudflareApiToken || !config.cloudflareAccountId) {
      const missing = [
        ...(config.cloudflareApiToken ? [] : ['CLOUDFLARE_API_TOKEN']),
        ...(config.cloudflareAccountId ? [] : ['CLOUDFLARE_ACCOUNT_ID']),
      ]
      return notConfiguredCheck(`${missing.join(' dan ')} belum dikonfigurasi di backend.`)
    }

    const startedAt = context.now()
    const accountBase = `${SCAN_ENDPOINT}/${encodeURIComponent(config.cloudflareAccountId.trim())}`
    const headers = {
      Authorization: `Bearer ${config.cloudflareApiToken}`,
      'Content-Type': 'application/json',
    }
    const authHeaders = { Authorization: headers.Authorization }

    // Pencarian laporan yang sudah ada jauh lebih murah daripada memindai ulang, dan
    // memangkas durasi agen ini untuk URL yang pernah diperiksa.
    const searchSafe = !context.url.includes('"') && !context.url.includes('\\')
    const lookup = searchSafe
      ? await requestRadarJson(
          context,
          'GET',
          `${accountBase}/urlscanner/v2/search?q=${encodeURIComponent(`task.url:"${context.url}"`)}&size=3`,
          authHeaders,
          undefined,
          SEARCH_REQUEST_TIMEOUT_MS,
        )
      : null

    if (lookup && !lookup.ok && (lookup.kind === 'rate_limited' || lookup.kind === 'auth_failed')) {
      return failureCheck(lookup)
    }

    const found = lookup?.ok
      ? findExistingScan(lookup.data, context.url, context.now(), maxReportAgeMs(config))
      : null

    if (found?.fresh) {
      const read = await readScanResult(
        context,
        `${accountBase}/urlscanner/v2/result/${encodeURIComponent(found.fresh.uuid)}`,
        authHeaders,
        { budgetMs: REUSE_READ_BUDGET_MS, firstDelayMs: 0 },
      )
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

    const remainingBudgetMs = TOTAL_BUDGET_MS - (context.now() - startedAt)
    if (remainingBudgetMs < MIN_POLL_BUDGET_MS) {
      return timeoutCheck('Batas waktu Cloudflare URL Scanner tidak cukup untuk memulai pemindaian baru.')
    }

    const submission = await requestRadarJson(
      context,
      'POST',
      `${accountBase}/urlscanner/v2/scan`,
      headers,
      JSON.stringify({ url: context.url, visibility: 'unlisted' }),
      SUBMIT_REQUEST_TIMEOUT_MS,
    )

    if (!submission.ok) {
      // Pemindaian lama tetap dipakai bila tidak dapat mengirim yang baru, dengan umur
      // laporan yang jujur; tidak pernah mengirim ulang setelah HTTP 429.
      if (submission.kind === 'rate_limited' && found?.newest) {
        const stale = await readScanResult(
          context,
          `${accountBase}/urlscanner/v2/result/${encodeURIComponent(found.newest.uuid)}`,
          authHeaders,
          { budgetMs: REUSE_READ_BUDGET_MS, firstDelayMs: 0 },
        )
        if (stale.kind === 'check') {
          return withExistingEvidence(stale.check, found.newest.ageMs, found.newest.observedAt)
        }
      }
      return failureCheck(submission)
    }

    const uuid = uuidFromSubmission(submission.data)
    if (!uuid) {
      return errorCheck('Cloudflare URL Scanner tidak mengembalikan ID pemindaian yang valid.')
    }

    const resultUrl = `${accountBase}/urlscanner/v2/result/${encodeURIComponent(uuid)}`
    const poll = await readScanResult(context, resultUrl, authHeaders, {
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

    return timeoutCheck('Cloudflare URL Scanner belum menyelesaikan pemindaian dalam batas waktu.')
  },
}

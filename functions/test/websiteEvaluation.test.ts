import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { analyzePageContent } from '../src/website/pageSignals.js'
import { unavailableRegistration } from '../src/website/registration.js'
import { fuseEvidence } from '../src/website/risk.js'
import { runSiteAnalysis } from '../src/website/service.js'
import type {
  AsnQueryResult,
  OriginResult,
  RegistrationQueryResult,
  ResolveResult,
  SiteProbe,
  TlsProbeResult,
  UrlStructureAnalysis,
} from '../src/website/types.js'
import {
  byCategory,
  formatCategoryTable,
  formatMetricsTable,
  metricsOf,
  splitOutcomes,
  type Outcome,
} from '../../evaluation/metrics.js'
import { datasetCensus, parseUrlDataset, type UrlRecord } from '../../evaluation/dataset.js'

const REF_TIME = Date.parse('2026-10-24T00:00:00.000Z')
const FIXTURE_ADDRESS = '93.184.216.34'

/** Kode yang ditambahkan pada tahap upgrade; dipakai untuk ablation. */
const NEW_STRUCTURE_CODES = ['digit_heavy', 'special_heavy', 'long_url', 'deep_path', 'brand_in_path']

const THRESHOLDS = [9, 12, 15, 25, 35]
/**
 * Ambang utama = batas level 'medium' milik engine (LEVEL_THRESHOLDS di
 * src/website/risk.ts), dipilih lebih dulu karena itu titik di mana laporan
 * mulai menyebut risiko, bukan karena menghasilkan metrik terbaik di dataset ini.
 */
const PRIMARY_THRESHOLD = 15

function datasetText(): string {
  return readFileSync(new URL('../../evaluation/datasets/urls.jsonl', import.meta.url), 'utf8')
}

function registrationFixture(record: UrlRecord, domain: string): RegistrationQueryResult {
  if (!record.registration) {
    return {
      registration: null,
      outcome: 'unsupported',
      source: null,
      detail: 'Dataset tidak menyertakan data registrasi untuk catatan ini.',
    }
  }
  return {
    registration: {
      domain,
      handle: 'FIXTURE',
      registrar: record.registration.registrar ?? 'Registrar Uji',
      createdAt: record.registration.createdAt,
      changedAt: null,
      expiresAt: record.registration.expiresAt ?? null,
      statuses: ['active'],
    },
    outcome: 'answered',
    source: 'rdap.fixture',
    detail: 'Data registrasi datang dari fixture dataset, bukan registry sungguhan.',
  }
}

/**
 * Probe deterministik: tidak ada satu pun panggilan jaringan. Alamat, rekor DNS,
 * sertifikat, jawaban RDAP, dan dokumen HTML semuanya berasal dari fixture.
 * Guard SSRF di dalam engine tetap berjalan penuh terhadap nilai fixture ini.
 */
function makeFixtureProbe(record: UrlRecord): SiteProbe {
  const chain = record.redirectChain ?? []
  const html = record.html ?? '<html><head><title>Laman uji</title></head><body>halo</body></html>'
  let originCalls = 0

  const pageOrigin = (): OriginResult => ({
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: [
      ['content-type', 'text/html; charset=utf-8'],
      ['server', 'fixture'],
    ],
    body: html,
    bytes: html.length,
    truncated: false,
    elapsedMs: 12,
    tls: null,
  })

  return {
    name: 'probe-fixture-evaluasi',
    dnsSource: 'probe fixture',
    resolve: (hostname): ResolveResult => {
      const literal = /^\d+\.\d+\.\d+\.\d+$/.test(hostname) ? hostname : FIXTURE_ADDRESS
      return Promise.resolve({ ipv4: [literal], ipv6: [], detail: null })
    },
    queryRecords: (hostname, type) =>
      Promise.resolve(
        type === 'A'
          ? {
              records: [/^\d+\.\d+\.\d+\.\d+$/.test(hostname) ? hostname : FIXTURE_ADDRESS],
              outcome: 'answered' as const,
              detail: null,
            }
          : { records: [], outcome: 'empty' as const, detail: 'Kueri selesai tanpa record untuk tipe ini.' },
      ),
    lookupAsn: (address): Promise<AsnQueryResult> =>
      Promise.resolve({
        info: { asn: 'AS-FIXTURE', organization: null, country: 'ID', prefix: `${address}/24`, registry: 'idnic' },
        outcome: 'answered',
        detail: 'Data fixture, bukan hasil query registry ASN.',
      }),
    lookupRegistration: (domain) => Promise.resolve(registrationFixture(record, domain)),
    inspectTls: (_hostname, _address, _kind, _port): Promise<TlsProbeResult> =>
      Promise.resolve({
        certificate: {
          issuer: 'Fixture CA',
          subject: record.id,
          notBefore: new Date(REF_TIME - 30 * 86_400_000).toISOString(),
          notAfter: new Date(REF_TIME + 60 * 86_400_000).toISOString(),
          expired: false,
          hostnameVerified: true,
          verification: 'verified',
          verificationDetail: null,
          protocol: 'TLSv1.3',
        },
        httpsReachable: true,
        outcome: 'answered',
        detail: 'Sertifikat fixture.',
      }),
    openOrigin: (request): Promise<OriginResult> => {
      const step = originCalls
      originCalls += 1
      const target = chain[step]
      if (target) {
        return Promise.resolve({
          ok: true,
          status: 301,
          statusText: 'Moved',
          headers: [
            ['location', target],
            ['content-type', 'text/html'],
          ],
          body: '',
          bytes: 0,
          truncated: false,
          elapsedMs: 9,
          tls: request.secure
            ? {
                protocol: 'TLSv1.3',
                cipher: 'fixture',
                issuer: 'Fixture CA',
                subject: request.hostname,
                notBefore: new Date(REF_TIME - 30 * 86_400_000).toISOString(),
                notAfter: new Date(REF_TIME + 60 * 86_400_000).toISOString(),
                authorized: true,
                authorizationError: null,
              }
            : null,
        })
      }
      const origin = pageOrigin()
      if (request.secure) {
        return Promise.resolve({
          ...origin,
          tls: {
            protocol: 'TLSv1.3',
            cipher: 'fixture',
            issuer: 'Fixture CA',
            subject: request.hostname,
            notBefore: new Date(REF_TIME - 30 * 86_400_000).toISOString(),
            notAfter: new Date(REF_TIME + 60 * 86_400_000).toISOString(),
            authorized: true,
            authorizationError: null,
          },
        })
      }
      return Promise.resolve(origin)
    },
  }
}

function withoutNewLayers(structure: UrlStructureAnalysis): UrlStructureAnalysis {
  const findings = structure.findings.filter((finding) => !NEW_STRUCTURE_CODES.includes(finding.code))
  return { ...structure, findings }
}

function scoreWithoutNewLayers(
  report: Awaited<ReturnType<typeof runSiteAnalysis>>,
  record: UrlRecord,
  at: string,
): number | null {
  const page = analyzePageContent({
    html: null,
    baseUrl: null,
    pageHost: new URL(record.url).hostname.toLowerCase(),
    pageSecure: true,
    registrableDomain: null,
    detail: 'Ablation: lapisan isi halaman dimatikan.',
  })
  const fused = fuseEvidence({
    generatedAt: at,
    structure: withoutNewLayers(report.behavior.structure),
    registration: unavailableRegistration(at, 'Ablation: lapisan registrasi dimatikan.'),
    website: report.website,
    behavior: report.behavior,
    page,
    category: report.category,
  })
  return fused.riskScore
}

type Scored = {
  record: UrlRecord
  score: number | null
  baseline: number | null
  evidenceCount: number
  /** Butir bukti yang benar-benar teramati, dipakai untuk menelusuri sumber FP. */
  evidence: string
}

async function scoreAll(records: UrlRecord[]): Promise<Scored[]> {
  const scored: Scored[] = []
  for (const record of records) {
    const report = await runSiteAnalysis({
      url: record.url,
      uid: 'evaluasi',
      probe: makeFixtureProbe(record),
      now: () => REF_TIME,
    })
    const at = report.generatedAt
    scored.push({
      record,
      score: report.risk.riskScore,
      baseline: scoreWithoutNewLayers(report, record, at),
      evidenceCount: report.risk.evidence.length,
      evidence: report.risk.evidence
        .filter((item) => item.availability === 'observed')
        .map((item) => `${item.id}(${item.strength})`)
        .join(' '),
    })
  }
  return scored
}

function outcomesFor(scored: Scored[], threshold: number): Outcome[] {
  return scored.map(({ record, score }) => ({
    id: record.id,
    split: record.split,
    category: record.category,
    label: record.label,
    predicted: (score ?? 0) >= threshold ? 'phishing' : 'legitimate',
  }))
}

describe('harness metrik evaluasi', () => {
  it('menghitung confusion matrix dari data mainan', () => {
    const outcomes: Outcome[] = [
      { id: 'a', split: 'dev', category: 'x', label: 'phishing', predicted: 'phishing' },
      { id: 'b', split: 'dev', category: 'x', label: 'phishing', predicted: 'legitimate' },
      { id: 'c', split: 'dev', category: 'y', label: 'legitimate', predicted: 'phishing' },
      { id: 'd', split: 'dev', category: 'y', label: 'legitimate', predicted: 'legitimate' },
      { id: 'e', split: 'holdout', category: 'y', label: 'legitimate', predicted: 'legitimate' },
    ]
    const metrics = metricsOf(outcomes)
    expect(metrics).toMatchObject({ truePositive: 1, falsePositive: 1, falseNegative: 1, trueNegative: 2 })
    expect(metrics.precision).toBe(0.5)
    expect(metrics.recall).toBe(0.5)
    expect(metrics.f1).toBe(0.5)
    expect(metrics.falsePositiveRate).toBeCloseTo(1 / 3, 3)
    expect(metrics.falseNegativeRate).toBe(0.5)
    expect(metrics.accuracy).toBe(0.6)
  })

  it('mengembalikan null ketika pembaginya nol', () => {
    const metrics = metricsOf([
      { id: 'a', split: 'dev', category: 'x', label: 'legitimate', predicted: 'legitimate' },
    ])
    expect(metrics.precision).toBeNull()
    expect(metrics.recall).toBeNull()
    expect(metrics.falseNegativeRate).toBeNull()
  })

  it('memecah hasil per kategori dan per split', () => {
    const outcomes: Outcome[] = [
      { id: 'a', split: 'dev', category: 'typosquat', label: 'phishing', predicted: 'phishing' },
      { id: 'b', split: 'dev', category: 'typosquat', label: 'phishing', predicted: 'phishing' },
      { id: 'c', split: 'holdout', category: 'legitimate', label: 'legitimate', predicted: 'legitimate' },
    ]
    expect(byCategory(outcomes)).toEqual([
      { category: 'legitimate', label: 'legitimate', total: 1, detected: 1, detectionRate: 1 },
      { category: 'typosquat', label: 'phishing', total: 2, detected: 2, detectionRate: 1 },
    ])
    expect(splitOutcomes(outcomes, 'holdout')).toHaveLength(1)
  })

  it('menolak dataset yang tidak sah', () => {
    expect(() =>
      parseUrlDataset('{"id":"x","split":"dev","label":"phishing","category":"typosquat","url":"ftp://a.com"}'),
    ).toThrow(/skema/)
    expect(() => parseUrlDataset('{"id":"x","split":"dev","label":"maybe","category":"typosquat","url":"https://a.com"}')).toThrow(
      /label pada x tidak valid/,
    )
    expect(() =>
      parseUrlDataset(
        '{"id":"x","split":"dev","label":"phishing","category":"typosquat","url":"https://a.com"}\n{"id":"x","split":"dev","label":"phishing","category":"typosquat","url":"https://b.com"}',
      ),
    ).toThrow(/duplikat/)
  })
})

describe('metrik engine pada dataset berlabel', () => {
  const records = parseUrlDataset(datasetText())

  it('melaporkan metrik dev dan holdout secara terpisah', async () => {
    expect(records.length).toBeGreaterThanOrEqual(40)
    const scored = await scoreAll(records)

    const all = outcomesFor(scored, PRIMARY_THRESHOLD)
    const rows = [
      { name: 'semua', metrics: metricsOf(all) },
      { name: 'dev', metrics: metricsOf(splitOutcomes(all, 'dev')) },
      { name: 'holdout', metrics: metricsOf(splitOutcomes(all, 'holdout')) },
    ]

    const lines: string[] = []
    lines.push('== dataset ==')
    lines.push(...datasetCensus(records))
    lines.push('')
    lines.push(`== ambang utama ${PRIMARY_THRESHOLD} ==`)
    lines.push(formatMetricsTable(rows))
    lines.push('')
    lines.push('== per kategori (ambang utama) ==')
    lines.push(formatCategoryTable(byCategory(all)))

    for (const threshold of THRESHOLDS) {
      const outcomes = outcomesFor(scored, threshold)
      lines.push('')
      lines.push(`== ambang ${threshold}: presisi ${metricText(metricsOf(outcomes).precision)} ` +
        `recall ${metricText(metricsOf(outcomes).recall)} ` +
        `FP-rate ${metricText(metricsOf(outcomes).falsePositiveRate)} ` +
        `FN-rate ${metricText(metricsOf(outcomes).falseNegativeRate)}`)
      const misses = outcomes.filter((o) => o.label !== o.predicted)
      if (misses.length > 0) {
        lines.push(
          '  salah: ' +
            misses
              .map((m) => {
                const found = scored.find((s) => s.record.id === m.id)
                return `${m.id}(${m.label === 'phishing' ? 'FN' : 'FP'}, skor ${found?.score ?? 'null'}, ${m.category})`
              })
              .join(', '),
        )
        // Bukti pemicu salah positif dicetak supaya tiap FP bisa ditelusuri ke modul
        // yang menghasilkan butiran itu, bukan hanya ke sebuah angka.
        for (const m of misses.filter((outcome) => outcome.label === 'legitimate')) {
          const found = scored.find((s) => s.record.id === m.id)
          if (found) lines.push(`  bukti FP ${m.id}: ${found.evidence}`)
        }
      }
    }

    const withNew = scored.filter((s) => (s.score ?? 0) >= PRIMARY_THRESHOLD).length
    const withoutNew = scored.filter((s) => (s.baseline ?? 0) >= PRIMARY_THRESHOLD).length
    lines.push('')
    lines.push(
      `== ablation ==\ndengan lapisan baru: ${withNew}/${records.length} ditandai | ` +
        `tanpa lapisan baru (kode Stage 1 + registrasi + isi halaman dimatikan): ${withoutNew}/${records.length} ditandai`,
    )

    console.info(lines.join('\n'))

    const holdout = metricsOf(splitOutcomes(all, 'holdout'))
    const dev = metricsOf(splitOutcomes(all, 'dev'))
    const combined = metricsOf(all)

    // Batas yang dikunci adalah angka yang TERUKUR pada dataset ini, bukan angka
    // impian dan bukan target pasar. Nilai terukur 2026-10-30 (ambang 15, 49 catatan):
    //   gabungan  presisi 100.0%  recall 71.9%  F1 83.6%  FP-rate 0.0%  FN-rate 28.1%
    //   dev       presisi 100.0%  recall 78.3%  F1 87.8%  FP-rate 0.0%
    //   holdout   presisi 100.0%  recall 55.6%  F1 71.4%  FP-rate 0.0%
    // Kalau perubahan berikutnya menurunkan recall atau menaikkan FP di bawah batas
    // ini, suite gagal dan selisihnya harus dijelaskan, bukan ditutupi. Dataset ini
    // sintetis dan kecil, jadi angkanya tidak boleh dikutip sebagai akurasi dunia nyata.
    expect(records.length).toBeGreaterThanOrEqual(45)
    expect(combined.recall ?? 0).toBeGreaterThanOrEqual(0.7)
    expect(combined.precision ?? 0).toBeGreaterThanOrEqual(0.95)
    expect(combined.falsePositiveRate ?? 1).toBeLessThanOrEqual(0.06)
    expect(dev.recall ?? 0).toBeGreaterThanOrEqual(0.75)
    expect(holdout.recall ?? 0).toBeGreaterThanOrEqual(0.5)
    expect(holdout.falsePositiveRate ?? 1).toBeLessThanOrEqual(0.1)

    // Tidak ada klaim sempurna: recall di bawah 1 dan tetap harus dinyatakan.
    expect(combined.recall ?? 1).toBeLessThan(1)

    // Kontribusi lapisan baru harus terlihat pada dataset ini, bukan diasumsikan.
    expect(withNew).toBeGreaterThan(withoutNew)
  })
})

function metricText(value: number | null): string {
  return value === null ? 'n/a' : `${(value * 100).toFixed(1)}%`
}

import { describe, expect, it } from 'vitest'
import dataset from '../../../../evaluation/datasets/messages-id.jsonl?raw'
import {
  datasetCensus,
  MESSAGE_CATEGORIES,
  parseMessageDataset,
  type MessageRecord,
} from '../../../../evaluation/dataset.js'
import {
  byCategory,
  formatCategoryTable,
  formatMetricsTable,
  metricsOf,
  splitOutcomes,
  type Label,
  type Metrics,
  type Outcome,
} from '../../../../evaluation/metrics.js'
import { analyzeMessage } from './index'

/**
 * Harness evaluasi untuk mesin pesan Indonesia. Ia membaca dataset berlabel di
 * evaluation/datasets lalu memprediksi dari riskScore yang benar-benar
 * dihasilkan analyzeMessage — tidak ada penyesuaian skor di dalam harness.
 *
 * Semua catatan pesan adalah konstruk sintetis (lihat evaluation/MANIFEST.md),
 * jadi angka di bawah mengukur perilaku pada dataset itu, bukan akurasi di dunia nyata.
 */

/**
 * Ambang yang dipakai adalah batas level milik engine itu sendiri
 * (RISK_THRESHOLDS.medium/high di web/src/lib/analysis/result.ts), bukan angka
 * yang dipilih setelah metriknya terlihat: memilih ambang dari data yang sama
 * lalu melaporkan metrik pada ambang itu akan melebih-lebihkan hasil.
 */
const THRESHOLDS = [25, 40, 60]
const PRIMARY_THRESHOLD = 60

type Scored = { record: MessageRecord; score: number; level: string }

function scoreAll(records: readonly MessageRecord[]): Scored[] {
  return records.map((record) => {
    const result = analyzeMessage(record.text)
    return { record, score: result.riskScore, level: result.riskLevel }
  })
}

function outcomesFor(scored: readonly Scored[], threshold: number): Outcome[] {
  return scored.map(({ record, score }) => ({
    id: record.id,
    split: record.split,
    category: record.category,
    label: record.label,
    predicted: (score >= threshold ? 'phishing' : 'legitimate') satisfies Label,
  }))
}

function metricText(value: number | null): string {
  return value === null ? 'n/a' : `${(value * 100).toFixed(1)}%`
}

describe('dataset pesan', () => {
  it('menolak kategori yang tidak dikenal', () => {
    expect(() =>
      parseMessageDataset(
        '{"id":"x","split":"dev","label":"phishing","category":"pesan","text":"Ambil dana ini sekarang."}',
      ),
    ).toThrow(/category pada x tidak valid/)
  })
})

describe('metrik pesan pada dataset berlabel', () => {
  const records = parseMessageDataset(dataset)

  it('melaporkan metrik dev dan holdout secara terpisah', () => {
    expect(records.length).toBeGreaterThanOrEqual(25)
    const perCategory = new Map<string, number>()
    for (const record of records) perCategory.set(record.category, (perCategory.get(record.category) ?? 0) + 1)
    for (const category of MESSAGE_CATEGORIES) {
      expect((perCategory.get(category) ?? 0) >= 2, `kategori ${category} terlalu sedikit`).toBe(true)
    }
    const scored = scoreAll(records)
    const all = outcomesFor(scored, PRIMARY_THRESHOLD)

    const rows: Array<{ name: string; metrics: Metrics }> = [
      { name: 'semua', metrics: metricsOf(all) },
      { name: 'dev', metrics: metricsOf(splitOutcomes(all, 'dev')) },
      { name: 'holdout', metrics: metricsOf(splitOutcomes(all, 'holdout')) },
    ]

    const lines: string[] = ['== dataset ==', ...datasetCensus(records), '']
    lines.push(`== ambang utama ${PRIMARY_THRESHOLD} ==`, formatMetricsTable(rows), '')
    lines.push('== per kategori (ambang utama) ==', formatCategoryTable(byCategory(all)))

    for (const threshold of THRESHOLDS) {
      const metrics = metricsOf(outcomesFor(scored, threshold))
      const misses = outcomesFor(scored, threshold).filter((outcome) => outcome.label !== outcome.predicted)
      lines.push(
        '',
        `== ambang ${threshold}: presisi ${metricText(metrics.precision)} ` +
          `recall ${metricText(metrics.recall)} ` +
          `FP-rate ${metricText(metrics.falsePositiveRate)} ` +
          `FN-rate ${metricText(metrics.falseNegativeRate)}`,
      )
      if (misses.length > 0) {
        lines.push(
          '  salah: ' +
            misses
              .map((miss) => {
                const found = scored.find((entry) => entry.record.id === miss.id)
                return `${miss.id}(${miss.label === 'phishing' ? 'FN' : 'FP'}, skor ${found?.score}, ${miss.category})`
              })
              .join(', '),
        )
      }
    }

    console.info(lines.join('\n'))

    const combined = metricsOf(all)
    const dev = metricsOf(splitOutcomes(all, 'dev'))
    const holdout = metricsOf(splitOutcomes(all, 'holdout'))

    // Batas yang dikunci adalah angka TERUKUR pada dataset ini, bukan angka impian.
    // Terukur 2026-10-30 pada ambang 'high' engine (60, 27 catatan):
    //   gabungan  presisi 100.0%  recall 76.9%  F1 87.0%  FP-rate 0.0%  FN-rate 23.1%
    //   dev       presisi 100.0%  recall 75.0%  FP-rate 0.0%
    //   holdout   presisi 100.0%  recall 80.0%  FP-rate 0.0%
    // Pada ambang 'medium' (25) recall naik ke 100.0% tapi FP-rate ke 35.7% — pesan
    // sah yang menyebut biaya/uang ikut naik level. Tradeoff itu dilaporkan, tidak
    // ditutupi dengan memilih ambang setelah metriknya dilihat.
    expect(combined.recall ?? 0).toBeGreaterThanOrEqual(0.75)
    expect(combined.precision ?? 0).toBeGreaterThanOrEqual(0.95)
    expect(combined.falsePositiveRate ?? 1).toBeLessThanOrEqual(0.1)
    expect(dev.recall ?? 0).toBeGreaterThanOrEqual(0.7)
    expect(holdout.recall ?? 0).toBeGreaterThanOrEqual(0.75)
    expect(holdout.falsePositiveRate ?? 1).toBeLessThanOrEqual(0.1)

    // Dataset sintetis kecil: tidak ada vonis sempurna yang boleh diklaim.
    expect(combined.recall ?? 1).toBeLessThan(1)
  })
})

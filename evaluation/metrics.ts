/**
 * Matematika evaluasi untuk harness VERIGUARD. Modul ini sengaja tidak menyentuh
 * mesin deteksi: ia hanya menerima pasangan (label, prediksi) lalu menghitung
 * metrik. Dengan begitu angkanya dapat diuji terpisah dari skoring engine.
 */

export type Label = 'phishing' | 'legitimate'
export type Split = 'dev' | 'holdout'

export type Outcome = {
  id: string
  split: Split
  category: string
  label: Label
  predicted: Label
}

export type Confusion = {
  truePositive: number
  falsePositive: number
  falseNegative: number
  trueNegative: number
}

export type Metrics = Confusion & {
  total: number
  positives: number
  negatives: number
  precision: number | null
  recall: number | null
  specificity: number | null
  f1: number | null
  accuracy: number | null
  falsePositiveRate: number | null
  falseNegativeRate: number | null
}

function ratio(numerator: number, denominator: number): number | null {
  if (denominator === 0) return null
  return Number((numerator / denominator).toFixed(4))
}

export function confusionOf(outcomes: readonly Outcome[]): Confusion {
  const confusion: Confusion = { truePositive: 0, falsePositive: 0, falseNegative: 0, trueNegative: 0 }
  for (const outcome of outcomes) {
    if (outcome.label === 'phishing' && outcome.predicted === 'phishing') confusion.truePositive += 1
    else if (outcome.label === 'legitimate' && outcome.predicted === 'phishing') confusion.falsePositive += 1
    else if (outcome.label === 'phishing' && outcome.predicted === 'legitimate') confusion.falseNegative += 1
    else confusion.trueNegative += 1
  }
  return confusion
}

export function metricsOf(outcomes: readonly Outcome[]): Metrics {
  const c = confusionOf(outcomes)
  const positives = c.truePositive + c.falseNegative
  const negatives = c.trueNegative + c.falsePositive
  const precision = ratio(c.truePositive, c.truePositive + c.falsePositive)
  const recall = ratio(c.truePositive, positives)
  const f1 =
    precision === null || recall === null || precision + recall === 0
      ? null
      : Number(((2 * precision * recall) / (precision + recall)).toFixed(4))

  return {
    ...c,
    total: outcomes.length,
    positives,
    negatives,
    precision,
    recall,
    specificity: ratio(c.trueNegative, negatives),
    f1,
    accuracy: ratio(c.truePositive + c.trueNegative, outcomes.length),
    falsePositiveRate: ratio(c.falsePositive, negatives),
    falseNegativeRate: ratio(c.falseNegative, positives),
  }
}

export type CategoryRow = {
  category: string
  label: Label
  total: number
  detected: number
  detectionRate: number | null
}

export function byCategory(outcomes: readonly Outcome[]): CategoryRow[] {
  const groups = new Map<string, { label: Label; total: number; detected: number }>()
  for (const outcome of outcomes) {
    const key = `${outcome.label}|${outcome.category}`
    const row = groups.get(key) ?? { label: outcome.label, total: 0, detected: 0 }
    row.total += 1
    // Untuk label legitimate yang diinginkan adalah TIDAK ditandai, jadi "detected"
    // di sini berarti "diprediksi sama dengan labelnya".
    if (outcome.predicted === outcome.label) row.detected += 1
    groups.set(key, row)
  }

  return [...groups.entries()]
    .map(([key, row]) => ({
      category: key.slice(key.indexOf('|') + 1),
      label: row.label,
      total: row.total,
      detected: row.detected,
      detectionRate: ratio(row.detected, row.total),
    }))
    .sort((left, right) => left.category.localeCompare(right.category))
}

export function splitOutcomes(outcomes: readonly Outcome[], split: Split): Outcome[] {
  return outcomes.filter((outcome) => outcome.split === split)
}

export function percent(value: number | null): string {
  return value === null ? 'n/a' : `${(value * 100).toFixed(1)}%`
}

export function formatMetricsTable(rows: Array<{ name: string; metrics: Metrics }>): string {
  const header =
    'sumber          | total | prec  | recall | F1    | FP-rate | FN-rate | TP/FP/FN/TN'
  const line = '-'.repeat(header.length)
  const body = rows.map(
    (row) =>
      `${row.name.padEnd(16)} | ${String(row.metrics.total).padStart(5)} | ${percent(row.metrics.precision).padStart(5)} | ${percent(
        row.metrics.recall,
      ).padStart(6)} | ${percent(row.metrics.f1).padStart(5)} | ${percent(row.metrics.falsePositiveRate).padStart(7)} | ${percent(
        row.metrics.falseNegativeRate,
      ).padStart(7)} | ${row.metrics.truePositive}/${row.metrics.falsePositive}/${row.metrics.falseNegative}/${row.metrics.trueNegative}`,
  )
  return [header, line, ...body].join('\n')
}

export function formatCategoryTable(rows: CategoryRow[]): string {
  const header = 'kategori                         | label      | benar/total | rate'
  const line = '-'.repeat(header.length)
  const body = rows.map(
    (row) =>
      `${row.category.padEnd(32)} | ${row.label.padEnd(10)} | ${String(row.detected).padStart(5)}/${String(row.total).padEnd(
        5,
      )} | ${percent(row.detectionRate)}`,
  )
  return [header, line, ...body].join('\n')
}

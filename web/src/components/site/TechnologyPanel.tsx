import { Card } from '../ui/Card'
import { Badge } from '../ui/Badge'
import type {
  TechnologyAnalysis,
  TechnologyCategory,
  TechnologyConfidence,
} from '../../lib/website/types'
import { userFacingText } from '../../lib/uiText'
import {
  EmptyHint,
  NoteList,
  SectionTitle,
} from './siteKit'
import { formatBytes, sectionBadge } from './siteFormat'

const CATEGORY_LABEL: Record<TechnologyCategory, string> = {
  frontend: 'Frontend',
  library: 'Pustaka',
  css: 'CSS',
  cms: 'CMS',
  server: 'Web server',
  analytics: 'Analytics',
  other: 'Lainnya',
}

const CONFIDENCE_LABEL: Record<TechnologyConfidence, string> = {
  high: 'Keyakinan tinggi',
  medium: 'Keyakinan sedang',
  low: 'Keyakinan rendah',
}

const CONFIDENCE_TONE: Record<TechnologyConfidence, 'info' | 'medium' | 'neutral'> = {
  high: 'info',
  medium: 'neutral',
  low: 'neutral',
}

export function TechnologyPanel({ data }: { data: TechnologyAnalysis }) {
  const view = sectionBadge(data.status)

  return (
    <Card className="p-5 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <SectionTitle description="Deteksi pasif dari header dan dokumen HTML. Tidak ada skrip target yang dijalankan.">
          Analisis Teknologi
        </SectionTitle>
        <Badge tone={view.tone}>{view.label}</Badge>
      </div>

      <div className="mt-4">
        <p className="type-caption text-ink-muted">Dokumen yang diperiksa</p>
        <dl className="mt-1.5">
          <div className="flex flex-col gap-1 border-b border-line py-2.5 sm:flex-row sm:justify-between sm:gap-4">
            <dt className="type-caption sm:w-44">Status dokumen</dt>
            <dd className="text-sm text-ink">
              {data.document.inspected
                ? 'Dokumen HTML dibaca pasif.'
                : 'Tidak ada dokumen HTML yang dapat dibaca.'}
            </dd>
          </div>
          <div className="flex flex-col gap-1 border-b border-line py-2.5 sm:flex-row sm:justify-between sm:gap-4">
            <dt className="type-caption sm:w-44">Ukuran dipindai</dt>
            <dd className="text-sm tabular-nums text-ink">
              {formatBytes(data.document.bytesScanned)}
              {data.document.truncated ? (
                <Badge tone="medium" className="ml-2">
                  Dipotong batas ukuran
                </Badge>
              ) : null}
            </dd>
          </div>
          <div className="flex flex-col gap-1 py-2.5 sm:flex-row sm:justify-between sm:gap-4">
            <dt className="type-caption sm:w-44">Content-Type</dt>
            <dd className="break-all font-mono text-sm text-ink">
              {data.document.contentType ?? 'tidak dinyatakan'}
            </dd>
          </div>
        </dl>
        <p className="type-caption mt-2 text-ink-soft">
          {userFacingText(data.document.detail)}
        </p>
      </div>

      {data.findings.length > 0 ? (
        <ul className="mt-5 grid gap-3 sm:grid-cols-2">
          {data.findings.map((finding) => (
            <li key={`${finding.category}-${finding.name}`} className="rounded-card border border-line bg-canvas p-3.5">
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-sm font-semibold text-ink">{finding.name}</p>
                <Badge tone="neutral">{CATEGORY_LABEL[finding.category]}</Badge>
                <Badge tone={finding.state === 'detected' ? 'low' : 'medium'}>
                  {finding.state === 'detected' ? 'Terdeteksi' : 'Kemungkinan'}
                </Badge>
                <Badge tone={CONFIDENCE_TONE[finding.confidence]}>
                  {CONFIDENCE_LABEL[finding.confidence]}
                </Badge>
              </div>
              <ul className="mt-2 flex flex-col gap-1">
                {finding.evidence.map((item) => (
                  <li key={item} className="type-caption flex gap-2">
                    <span aria-hidden="true" className="mt-1.5 size-1 shrink-0 rounded-full bg-line-strong" />
                    <span className="break-words">{item}</span>
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      ) : (
        <EmptyHint>
          Tidak ada teknologi yang dapat dipastikan dari bukti pasif. Ini bukan bukti bahwa situs
          tidak memakai teknologi tertentu.
        </EmptyHint>
      )}

      <div className="mt-5">
        <p className="type-caption text-ink-muted">Status per kategori</p>
        <ul className="mt-2 flex flex-col gap-1.5">
          {data.categories.map((entry) => (
            <li key={entry.category} className="flex flex-wrap items-start gap-2">
              <Badge tone={entry.state === 'found' ? 'low' : entry.state === 'no_signal' ? 'neutral' : 'medium'}>
                {entry.state === 'found'
                  ? 'Ditemukan'
                  : entry.state === 'no_signal'
                    ? 'Tidak ada sinyal'
                    : 'Belum dapat dinilai'}
              </Badge>
              <span className="type-small min-w-0 flex-1 text-ink-soft">
                <span className="font-medium text-ink">{CATEGORY_LABEL[entry.category]}</span> —{' '}
                {userFacingText(entry.detail)}
              </span>
            </li>
          ))}
        </ul>
      </div>

      <NoteList notes={data.notes} />
    </Card>
  )
}

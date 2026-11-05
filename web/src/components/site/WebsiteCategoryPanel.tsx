import { Card } from '../ui/Card'
import { Badge } from '../ui/Badge'
import type {
  WebsiteCategoryAssessment,
  WebsiteCategoryConfidence,
  WebsiteCategoryId,
  WebsiteCategorySignalSource,
} from '../../lib/website/types'
import { WEBSITE_CATEGORY_LABELS } from '../../lib/website/types'
import { userFacingText } from '../../lib/uiText'
import { EmptyHint, NoteList, SectionTitle } from './siteKit'
import { formatBytes, sectionBadge } from './siteFormat'

type Tone = 'neutral' | 'accent' | 'low' | 'medium' | 'high' | 'info'

const CONFIDENCE_LABEL: Record<WebsiteCategoryConfidence, string> = {
  high: 'Tinggi',
  medium: 'Sedang',
  low: 'Rendah',
}

const CONFIDENCE_TONE: Record<WebsiteCategoryConfidence, Tone> = {
  high: 'info',
  medium: 'neutral',
  low: 'neutral',
}

const SOURCE_LABEL: Record<WebsiteCategorySignalSource, string> = {
  content: 'isi halaman',
  domain: 'nama domain',
  structure: 'struktur URL',
  network: 'data jaringan',
}

const STRENGTH_LABEL: Record<WebsiteCategoryAssessment['signals'][number]['strength'], string> = {
  strong: 'bukti kuat',
  moderate: 'bukti sedang',
  weak: 'bukti lemah',
}

export function WebsiteCategoryPanel({
  data,
  riskLevelLabel,
}: {
  data: WebsiteCategoryAssessment
  riskLevelLabel: string
}) {
  const view = sectionBadge(data.status)

  return (
    <Card className="p-5 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <SectionTitle description="Kategori disusun dari bukti yang sudah terbaca oleh analisis situs: judul, deskripsi, teks halaman, nama domain, dan rantai pengalihan.">
          Kategori Website
        </SectionTitle>
        <Badge tone={view.tone}>{view.label}</Badge>
      </div>

      <div className="mt-4 rounded-card border border-line bg-canvas p-4">
        <p className="type-caption text-ink-muted">Kategori</p>
        <p className="text-lg font-semibold text-ink">{data.primaryLabel}</p>
        <p className="type-small mt-1.5 text-ink-soft">{userFacingText(data.summary)}</p>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Badge tone={CONFIDENCE_TONE[data.confidence]}>
            Tingkat keyakinan: {CONFIDENCE_LABEL[data.confidence]}
          </Badge>
          {data.riskIndicated ? (
            <Badge tone="medium">Masuk kategori yang perlu diperiksa lebih lanjut</Badge>
          ) : null}
        </div>
      </div>

      <dl className="mt-4">
        <div className="flex flex-col gap-1 border-b border-line py-2.5 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
          <dt className="type-caption shrink-0 sm:w-44">Bukti yang dibaca</dt>
          <dd className="min-w-0 flex-1 text-sm text-ink">
            {data.evidenceBasis.documentInspected
              ? `Dokumen halaman terbaca (${formatBytes(data.evidenceBasis.visibleTextBytes)} teks terlihat)`
              : 'Dokumen halaman tidak terbaca, jadi kategori hanya dapat dinilai dari metadata.'}
            {data.evidenceBasis.titleAvailable ? ' · judul' : ''}
            {data.evidenceBasis.descriptionAvailable ? ' · deskripsi' : ''}
            {data.evidenceBasis.redirectHops > 0
              ? ` · ${data.evidenceBasis.redirectHops} pengalihan`
              : ''}
          </dd>
        </div>
        <div className="flex flex-col gap-1 border-b border-line py-2.5 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
          <dt className="type-caption shrink-0 sm:w-44">Terpisah dari tingkat risiko</dt>
          <dd className="min-w-0 flex-1 text-sm text-ink">
            Kategori menyebut jenis situs, sedangkan tingkat risiko berasal dari hasil pemeriksaan
            terpisah. Tingkat risiko saat ini: {riskLevelLabel}.
          </dd>
        </div>
      </dl>

      {data.signals.length > 0 ? (
        <ul className="mt-4 flex flex-col gap-2">
          {data.signals.map((signal) => (
            <li
              key={`${signal.categoryId}-${signal.source}-${signal.label}`}
              className="rounded-card border border-line bg-canvas p-3"
            >
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-sm font-semibold text-ink">
                  {WEBSITE_CATEGORY_LABELS[signal.categoryId as WebsiteCategoryId] ?? signal.label}
                </p>
                <Badge tone="neutral">{SOURCE_LABEL[signal.source]}</Badge>
                <Badge tone={signal.strength === 'strong' ? 'info' : 'neutral'}>
                  {STRENGTH_LABEL[signal.strength]}
                </Badge>
              </div>
              <p className="type-caption mt-1 break-words text-ink-soft">
                {userFacingText(signal.detail)}
              </p>
            </li>
          ))}
        </ul>
      ) : (
        <EmptyHint>
          Belum ada bukti yang cukup untuk menandai kategori tertentu. Status ini bukan pernyataan
          bahwa situs aman atau tidak aman.
        </EmptyHint>
      )}

      {data.alternatives.length > 0 ? (
        <div className="mt-4">
          <p className="type-caption text-ink-muted">Kemungkinan lain</p>
          <ul className="mt-2 flex flex-wrap items-center gap-2">
            {data.alternatives.map((option) => (
              <li key={option.id} className="flex flex-wrap items-center gap-2">
                <Badge tone="neutral">{option.label}</Badge>
                <span className="type-caption">
                  keyakinan {CONFIDENCE_LABEL[option.confidence].toLowerCase()}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <NoteList notes={data.notes} />
    </Card>
  )
}

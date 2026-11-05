import { Check, CircleDashed } from 'lucide-react'
import { Badge } from '../ui/Badge'
import { Spinner } from '../ui/Spinner'
import { cn } from '../../lib/cn'
import { agentLabel, sanitizeAgentText } from '../../lib/scanners/agentLabels'
import type {
  ProviderProgress,
  ProviderStatus,
} from '../../lib/scanners/types'

const STATUS_LABEL: Record<ProviderStatus, string> = {
  success: 'Selesai',
  not_found: 'Tidak ada kecocokan',
  not_configured: 'Belum dikonfigurasi',
  auth_failed: 'Gagal autentikasi',
  unavailable: 'Tidak tersedia',
  rate_limited: 'Dibatasi',
  skipped: 'Tidak dijalankan',
  timeout: 'Melebihi batas waktu',
  invalid_request: 'Permintaan ditolak',
  error: 'Gagal',
}

const STATUS_TONE: Record<
  ProviderStatus,
  'neutral' | 'low' | 'medium' | 'high'
> = {
  success: 'low',
  not_found: 'neutral',
  not_configured: 'neutral',
  auth_failed: 'high',
  unavailable: 'neutral',
  rate_limited: 'medium',
  skipped: 'neutral',
  timeout: 'medium',
  invalid_request: 'medium',
  error: 'high',
}

export function LiveScanPanel({
  providers,
  sensitiveUrl = false,
}: {
  providers: ProviderProgress[]
  sensitiveUrl?: boolean
}) {
  if (providers.length === 0) return null

  const completed = providers.filter((provider) => provider.state === 'completed').length

  return (
    <section
      aria-labelledby="live-scan-title"
      aria-live="polite"
      className="mt-4 rounded-card border border-line bg-surface p-4"
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 id="live-scan-title" className="text-sm font-medium text-ink">
            Pemeriksaan reputasi
          </h2>
          <p className="type-caption mt-0.5">
            {sensitiveUrl
              ? 'URL sensitif tidak dikirim ke agen eksternal.'
              : 'Status diperbarui saat setiap agen selesai.'}
          </p>
        </div>
        <Badge tone={completed === providers.length ? 'low' : 'accent'}>
          {completed}/{providers.length} selesai
        </Badge>
      </div>

      <ul className="mt-3 divide-y divide-line">
        {providers.map((provider) => {
          const result = provider.result
          const label = agentLabel(provider.id, provider.label)
          return (
            <li key={provider.id} className="flex items-start gap-3 py-2.5">
              <span
                aria-hidden="true"
                className={cn(
                  'mt-0.5 grid size-5 shrink-0 place-items-center rounded-full border',
                  provider.state === 'completed'
                    ? 'border-risk-low-line bg-risk-low-bg text-risk-low'
                    : provider.state === 'running'
                      ? 'border-accent/30 bg-accent-soft text-accent'
                      : 'border-line bg-subtle text-ink-muted',
                )}
              >
                {provider.state === 'completed' ? (
                  <Check size={11} strokeWidth={2.5} />
                ) : provider.state === 'running' ? (
                  <Spinner className="size-3" label={`Memeriksa ${label}`} />
                ) : (
                  <CircleDashed size={10} />
                )}
              </span>

              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-ink">{label}</p>
                {result ? (
                  <p className="type-caption mt-0.5">{sanitizeAgentText(result.summary)}</p>
                ) : (
                  <p className="type-caption mt-0.5">
                    {provider.state === 'running'
                      ? 'Permintaan agen sedang berjalan...'
                      : 'Menunggu giliran.'}
                  </p>
                )}
              </div>

              {result ? (
                <Badge tone={STATUS_TONE[result.status]}>{STATUS_LABEL[result.status]}</Badge>
              ) : (
                <Badge tone={provider.state === 'running' ? 'accent' : 'neutral'}>
                  {provider.state === 'running' ? 'Berjalan' : 'Menunggu'}
                </Badge>
              )}
            </li>
          )
        })}
      </ul>
    </section>
  )
}

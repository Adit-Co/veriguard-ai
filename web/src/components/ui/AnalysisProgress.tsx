import { Check } from 'lucide-react'
import { cn } from '../../lib/cn'

const STEPS = ['Memvalidasi input', 'Menganalisis indikator', 'Menyimpan hasil'] as const

type AnalysisProgressProps = {
  activeStep: number
  className?: string
  // Label tahap dapat diganti agar sesuai fase yang benar-benar sedang berjalan,
  // misalnya saat agen reputasi eksternal masih memproses permintaan.
  steps?: readonly string[]
  title?: string
}

export function AnalysisProgress({
  activeStep,
  className,
  steps = STEPS,
  title = 'Memeriksa input…',
}: AnalysisProgressProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      aria-label="Proses pemeriksaan"
      className={cn('rounded-card border border-line bg-surface p-4', className)}
    >
      <p className="text-sm font-medium text-ink">{title}</p>
      <ol className="mt-3 space-y-2.5">
        {steps.map((step, index) => {
          const number = index + 1
          const done = number < activeStep
          const active = number === activeStep

          return (
            <li
              key={step}
              aria-current={active ? 'step' : undefined}
              className="flex items-center gap-3 text-sm"
            >
              <span
                className={cn(
                  'grid size-6 shrink-0 place-items-center rounded-full border',
                  done && 'border-risk-low-line bg-risk-low-bg text-risk-low',
                  active && 'border-accent/30 bg-accent-soft text-accent',
                  !done && !active && 'border-line bg-subtle text-ink-muted',
                )}
                aria-hidden="true"
              >
                {done ? (
                  <Check size={13} strokeWidth={2.5} />
                ) : active ? (
                  <span className="size-3 animate-spin rounded-full border-2 border-current border-t-transparent" />
                ) : (
                  <span className="size-1.5 rounded-full bg-current" />
                )}
              </span>
              <span
                className={cn(
                  active && 'font-medium text-ink',
                  done && 'text-ink-soft',
                  !done && !active && 'text-ink-muted',
                )}
              >
                {step}
              </span>
            </li>
          )
        })}
      </ol>
    </div>
  )
}

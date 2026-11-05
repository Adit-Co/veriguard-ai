import type { LucideIcon } from 'lucide-react'
import type { HTMLAttributes, ReactNode } from 'react'
import { cn } from '../../lib/cn'
import { Card } from './Card'

type StateTone = 'accent' | 'neutral' | 'warning' | 'danger'

const toneChip: Record<StateTone, string> = {
  accent: 'bg-accent-soft text-accent',
  neutral: 'bg-subtle text-ink-soft',
  warning: 'bg-risk-medium-bg text-risk-medium',
  danger: 'bg-risk-high-bg text-risk-high',
}

export type StatePanelProps = {
  icon: LucideIcon
  title: string
  description?: ReactNode
  tone?: StateTone
  actions?: ReactNode
  children?: ReactNode
  className?: string
} & Pick<HTMLAttributes<HTMLDivElement>, 'role'>

// VGL-35: panel status sebaris-kiri. State kosong/muat/gagal sebelumnya berupa kartu
// terpusat yang berulang di setiap halaman, sehingga tidak punya jangkar baca.
export function StatePanel({
  icon: Icon,
  title,
  description,
  tone = 'accent',
  actions,
  children,
  className,
  role,
}: StatePanelProps) {
  return (
    <Card role={role} className={cn('flex gap-4 p-6 sm:gap-5 sm:p-8', className)}>
      <span
        aria-hidden="true"
        className={cn('grid size-11 shrink-0 place-items-center rounded-xl', toneChip[tone])}
      >
        <Icon size={20} />
      </span>
      <div className="min-w-0">
        <h2 className="type-h3">{title}</h2>
        {description ? (
          <div className="type-small mt-2 max-w-[62ch] text-ink-soft">{description}</div>
        ) : null}
        {children}
        {actions ? <div className="mt-5 flex flex-wrap items-center gap-3">{actions}</div> : null}
      </div>
    </Card>
  )
}

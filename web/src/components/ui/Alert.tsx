import { CircleCheck, Info, TriangleAlert, CircleX } from 'lucide-react'
import type { HTMLAttributes, ReactNode } from 'react'
import { cn } from '../../lib/cn'

type Tone = 'info' | 'success' | 'warning' | 'danger'

const toneStyles: Record<Tone, string> = {
  info: 'border-accent/20 bg-info-bg text-info',
  success: 'border-risk-low-line bg-risk-low-bg text-risk-low',
  warning: 'border-risk-medium-line bg-risk-medium-bg text-risk-medium',
  danger: 'border-risk-high-line bg-risk-high-bg text-risk-high',
}

const toneIcons: Record<Tone, typeof Info> = {
  info: Info,
  success: CircleCheck,
  warning: TriangleAlert,
  danger: CircleX,
}

export type AlertProps = HTMLAttributes<HTMLDivElement> & {
  tone?: Tone
  title?: string
  icon?: ReactNode
}

export function Alert({
  tone = 'info',
  title,
  icon,
  className,
  children,
  ...props
}: AlertProps) {
  const Icon = toneIcons[tone]

  return (
    <div
      role="note"
      className={cn('flex gap-3 rounded-card border p-4', toneStyles[tone], className)}
      {...props}
    >
      <span aria-hidden="true" className="mt-0.5 shrink-0">
        {icon ?? <Icon size={18} strokeWidth={2} />}
      </span>
      <div className="min-w-0 text-sm leading-relaxed">
        {title ? <p className="font-semibold text-ink">{title}</p> : null}
        <div className={cn(title && 'mt-1', 'text-ink-soft')}>{children}</div>
      </div>
    </div>
  )
}

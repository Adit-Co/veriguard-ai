import type { ReactNode } from 'react'
import { cn } from '../../lib/cn'

type PageHeaderProps = {
  eyebrow?: string
  title: string
  description?: ReactNode
  actions?: ReactNode
  className?: string
}

export function PageHeader({ eyebrow, title, description, actions, className }: PageHeaderProps) {
  return (
    <div
      className={cn(
        'flex flex-col gap-6 border-b border-line pb-8 pt-12 sm:flex-row sm:items-end sm:justify-between sm:pb-10 sm:pt-16',
        className,
      )}
    >
      <div className="max-w-[640px]">
        {eyebrow ? <p className="type-eyebrow text-accent">{eyebrow}</p> : null}
        <h1 className={cn('type-h1', eyebrow && 'mt-3')}>{title}</h1>
        {description ? <div className="type-lead mt-3 text-base">{description}</div> : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-3">{actions}</div> : null}
    </div>
  )
}

import { forwardRef, type SelectHTMLAttributes } from 'react'
import { cn } from '../../lib/cn'

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  function Select({ className, ...props }, ref) {
    return (
      <select
        ref={ref}
        className={cn(
          'h-11 w-full rounded-btn border border-line bg-surface px-3.5 text-sm text-ink shadow-card transition-colors',
          'hover:border-line-strong focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/15',
          'disabled:cursor-not-allowed disabled:bg-subtle disabled:text-ink-muted',
          className,
        )}
        {...props}
      />
    )
  },
)

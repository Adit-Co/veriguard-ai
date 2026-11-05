import { forwardRef, type InputHTMLAttributes } from 'react'
import { cn } from '../../lib/cn'

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, ...props }, ref) {
    return (
      <input
        ref={ref}
        className={cn(
          'h-11 w-full rounded-btn border border-line bg-surface px-3.5 text-sm text-ink shadow-card transition-colors',
          'placeholder:text-ink-muted hover:border-line-strong',
          'focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/15',
          'disabled:cursor-not-allowed disabled:bg-subtle disabled:text-ink-muted',
          className,
        )}
        {...props}
      />
    )
  },
)

import { forwardRef, type TextareaHTMLAttributes } from 'react'
import { cn } from '../../lib/cn'

export const Textarea = forwardRef<
  HTMLTextAreaElement,
  TextareaHTMLAttributes<HTMLTextAreaElement>
>(function Textarea({ className, ...props }, ref) {
  return (
    <textarea
      ref={ref}
      className={cn(
        'min-h-32 w-full resize-y rounded-btn border border-line bg-surface px-3.5 py-3 text-sm leading-relaxed text-ink shadow-card transition-colors',
        'placeholder:text-ink-muted hover:border-line-strong',
        'focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/15',
        'disabled:cursor-not-allowed disabled:bg-subtle disabled:text-ink-muted',
        className,
      )}
      {...props}
    />
  )
})

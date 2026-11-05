import { cva, type VariantProps } from 'class-variance-authority'
import type { HTMLAttributes } from 'react'
import { cn } from '../../lib/cn'

const badgeStyles = cva(
  'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium leading-none',
  {
    variants: {
      tone: {
        neutral: 'border-line bg-subtle text-ink-soft',
        accent: 'border-accent/20 bg-accent-soft text-accent',
        low: 'border-risk-low-line bg-risk-low-bg text-risk-low',
        medium: 'border-risk-medium-line bg-risk-medium-bg text-risk-medium',
        high: 'border-risk-high-line bg-risk-high-bg text-risk-high',
        info: 'border-accent/20 bg-info-bg text-info',
      },
    },
    defaultVariants: {
      tone: 'neutral',
    },
  },
)

export type BadgeProps = HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeStyles>

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeStyles({ tone }), className)} {...props} />
}

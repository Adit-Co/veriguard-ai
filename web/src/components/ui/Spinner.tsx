import { cn } from '../../lib/cn'

type SpinnerProps = {
  className?: string
  label?: string
}

export function Spinner({ className, label = 'Memuat' }: SpinnerProps) {
  return (
    <span role="status" className="inline-flex items-center gap-2">
      <svg
        aria-hidden="true"
        viewBox="0 0 24 24"
        fill="none"
        className={cn('size-4 animate-spin text-current', className)}
      >
        <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.2" strokeWidth="3" />
        <path
          d="M21 12a9 9 0 0 0-9-9"
          stroke="currentColor"
          strokeWidth="3"
          strokeLinecap="round"
        />
      </svg>
      <span className="sr-only">{label}</span>
    </span>
  )
}

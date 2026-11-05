import { ShieldCheck } from 'lucide-react'
import { Link } from 'react-router-dom'

export function Logo() {
  return (
    <Link
      to="/"
      aria-label="VERIGUARD AI — kembali ke beranda"
      className="inline-flex shrink-0 items-center gap-2.5 rounded-md focus-visible:outline-none"
    >
      <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
        <ShieldCheck size={18} strokeWidth={2} aria-hidden="true" />
      </span>
      <span className="whitespace-nowrap text-[15px] font-semibold tracking-[0.1em] text-ink">
        VERIGUARD{' '}
        <span className="text-[11px] font-semibold tracking-[0.1em] text-accent">AI</span>
      </span>
    </Link>
  )
}

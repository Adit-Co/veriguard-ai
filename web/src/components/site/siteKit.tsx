import { Check, Copy } from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Badge } from '../ui/Badge'
import { cn } from '../../lib/cn'
import type { Lookup } from '../../lib/website/types'
import { lookupSourceLabel, userFacingText } from '../../lib/uiText'
import { formatDateTime, lookupBadge } from './siteFormat'

export function SectionTitle({
  children,
  description,
}: {
  children: ReactNode
  description?: string
}) {
  return (
    <div>
      <h3 className="text-sm font-semibold text-ink">{children}</h3>
      {description ? <p className="type-caption mt-1">{description}</p> : null}
    </div>
  )
}

export function DataRow({
  label,
  children,
  copy,
}: {
  label: string
  children: ReactNode
  copy?: string
}) {
  return (
    <div className="flex flex-col gap-1 border-b border-line py-2.5 last:border-b-0 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
      <dt className="type-caption shrink-0 sm:w-44">{label}</dt>
      <dd className="min-w-0 flex-1 break-words text-sm text-ink">
        <div className="flex flex-wrap items-center gap-2">
          <span className="min-w-0">{children}</span>
          {copy ? <CopyButton value={copy} label={label} /> : null}
        </div>
      </dd>
    </div>
  )
}

export function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState<'idle' | 'copied' | 'failed'>('idle')
  const resetTimer = useRef<number | null>(null)

  useEffect(
    () => () => {
      if (resetTimer.current !== null) window.clearTimeout(resetTimer.current)
    },
    [],
  )

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied('copied')
      if (resetTimer.current !== null) window.clearTimeout(resetTimer.current)
      resetTimer.current = window.setTimeout(() => {
        resetTimer.current = null
        setCopied('idle')
      }, 1_800)
    } catch {
      setCopied('failed')
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={`Salin ${label}`}
      title={copied === 'failed' ? 'Penyalinan gagal' : `Salin ${label}`}
      className={cn(
        'inline-flex size-7 shrink-0 items-center justify-center rounded-btn border border-line bg-surface text-ink-muted transition-colors hover:border-line-strong hover:text-ink',
        copied === 'failed' && 'border-risk-medium-line text-risk-medium',
      )}
    >
      {copied === 'copied' ? (
        <Check size={13} aria-hidden="true" />
      ) : (
        <Copy size={13} aria-hidden="true" />
      )}
    </button>
  )
}

export function Mono({ children }: { children: ReactNode }) {
  return <span className="break-all font-mono text-[13px] leading-5">{children}</span>
}

export function Muted({ children }: { children: ReactNode }) {
  return <span className="text-ink-muted">{children}</span>
}

export function StatusLine({ lookup }: { lookup: Lookup<unknown> }) {
  const view = lookupBadge(lookup.status)
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Badge tone={view.tone}>{view.label}</Badge>
      <span className="type-caption">
        Sumber: {lookupSourceLabel(lookup.source)} · ditanya {formatDateTime(lookup.queriedAt)}
      </span>
    </div>
  )
}

export function LookupDetail({ lookup }: { lookup: { detail: string | null } }) {
  if (!lookup.detail) return null
  return <p className="type-caption mt-1 text-ink-soft">{userFacingText(lookup.detail)}</p>
}

export function EmptyHint({ children }: { children: ReactNode }) {
  return <p className="type-small mt-2 text-ink-soft">{children}</p>
}

export function NoteList({ notes }: { notes: string[] }) {
  if (notes.length === 0) return null
  return (
    <ul className="mt-4 flex flex-col gap-1.5 border-t border-line pt-3">
      {notes.map((note) => (
        <li key={note} className="type-caption flex gap-2">
          <span aria-hidden="true" className="mt-1.5 size-1 shrink-0 rounded-full bg-line-strong" />
          <span>{userFacingText(note)}</span>
        </li>
      ))}
    </ul>
  )
}

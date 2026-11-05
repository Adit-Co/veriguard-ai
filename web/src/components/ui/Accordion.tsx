import { Plus } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '../../lib/cn'

export type AccordionItem = {
  id: string
  question: string
  answer: ReactNode
}

type AccordionProps = {
  items: AccordionItem[]
  className?: string
}

export function Accordion({ items, className }: AccordionProps) {
  return (
    <div className={cn('border-t border-line', className)}>
      {items.map((item) => (
        <details key={item.id} className="group border-b border-line">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-6 py-5 text-left text-base font-medium text-ink transition-colors hover:text-accent [&::-webkit-details-marker]:hidden">
            {item.question}
            <Plus
              size={18}
              aria-hidden="true"
              className="shrink-0 text-ink-muted transition-transform duration-200 group-open:rotate-45"
            />
          </summary>
          <div className="max-w-[72ch] pb-5 pr-8 text-sm leading-relaxed text-ink-soft">
            {item.answer}
          </div>
        </details>
      ))}
    </div>
  )
}

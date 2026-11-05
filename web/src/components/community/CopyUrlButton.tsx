import { Check, ClipboardCopy } from 'lucide-react'
import { useState } from 'react'
import { Button } from '../ui/Button'
import type { ButtonStyleProps } from '../ui/buttonStyles'

type CopyUrlButtonProps = {
  value: string
  variant?: ButtonStyleProps['variant']
  size?: ButtonStyleProps['size']
  className?: string
}

export function CopyUrlButton({
  value,
  variant = 'secondary',
  size = 'sm',
  className,
}: CopyUrlButtonProps) {
  const [result, setResult] = useState<{
    value: string
    state: 'copied' | 'failed'
  } | null>(null)
  const state = result?.value === value ? result.state : 'idle'

  async function handleCopy() {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('clipboard unavailable')
      await navigator.clipboard.writeText(value)
      setResult({ value, state: 'copied' })
    } catch {
      setResult({ value, state: 'failed' })
    }
  }

  return (
    <span className={className}>
      <Button
        variant={variant}
        size={size}
        onClick={() => void handleCopy()}
        aria-label="Salin URL laporan"
      >
        {state === 'copied' ? (
          <Check size={14} aria-hidden="true" />
        ) : (
          <ClipboardCopy size={14} aria-hidden="true" />
        )}
        {state === 'copied' ? 'URL tersalin' : 'Salin URL'}
      </Button>
      {state === 'failed' ? (
        <span role="status" className="type-caption mt-1 block">
          Browser tidak mengizinkan salin otomatis. Pilih teks URL secara manual.
        </span>
      ) : null}
    </span>
  )
}

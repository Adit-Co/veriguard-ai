import type { LucideIcon } from 'lucide-react'
import { cn } from '../../lib/cn'

export type SegmentedOption<T extends string> = {
  value: T
  label: string
  icon?: LucideIcon
}

type SegmentedControlProps<T extends string> = {
  options: readonly SegmentedOption<T>[]
  value: T
  onChange: (value: T) => void
  label: string
  disabled?: boolean
  className?: string
}

export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  label,
  disabled = false,
  className,
}: SegmentedControlProps<T>) {
  return (
    <div
      role="group"
      aria-label={label}
      className={cn(
        // Label yang panjang harus pindah baris, bukan melebarkan halaman. Baris tetap
        // menempel satu garis penuh hanya mulai lg; pada lebar tablet jumlah tab bisa
        // melebihi kontainer sehingga wajib boleh membungkus.
        'flex w-full flex-wrap gap-1 rounded-btn border border-line bg-subtle p-1 lg:w-auto lg:flex-nowrap',
        className,
      )}
    >
      {options.map(({ value: optionValue, label: optionLabel, icon: Icon }) => {
        const selected = optionValue === value

        return (
          <button
            key={optionValue}
            type="button"
            aria-pressed={selected}
            disabled={disabled}
            onClick={() => onChange(optionValue)}
            className={cn(
              'inline-flex h-9 flex-1 items-center justify-center gap-2 whitespace-nowrap rounded-[8px] px-3 text-sm font-medium transition-colors sm:flex-none',
              selected
                ? 'bg-surface text-ink shadow-card'
                : 'text-ink-soft hover:text-ink',
              disabled && 'cursor-not-allowed opacity-60',
            )}
          >
            {Icon ? <Icon size={15} aria-hidden="true" /> : null}
            {optionLabel}
          </button>
        )
      })}
    </div>
  )
}

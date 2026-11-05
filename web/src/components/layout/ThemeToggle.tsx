import { Moon, Sun } from 'lucide-react'
import { useRef, useState } from 'react'
import { cn } from '../../lib/cn'
import {
  applyPreferences,
  getPreferences,
  updatePreferences,
  type ThemeMode,
} from '../../lib/preferences/preferences'

// VGL-33B — SATU sakelar tema global untuk seluruh aplikasi: pil horizontal dengan indikator
// geser, bukan dua tombol terpisah. Kiri = Moon + DARK, kanan = Sun + LIGHT. Semantik
// radiogroup: panah kiri/kanan berpindah opsi, status aktif terbaca aria-checked, dan posisi
// indikator (bukan hanya warna) menandakan tema — tidak mengandalkan warna semata.
// Animasi otomatis nonaktif lewat prefers-reduced-motion / data-reduce-motion di index.css.

const OPTIONS: ReadonlyArray<{ value: ThemeMode; label: string; icon: typeof Moon }> = [
  { value: 'dark', label: 'DARK', icon: Moon },
  { value: 'light', label: 'LIGHT', icon: Sun },
]

export function ThemeToggle({ className }: { className?: string }) {
  const [theme, setTheme] = useState<ThemeMode>(() => getPreferences().theme)
  const groupRef = useRef<HTMLDivElement>(null)

  function selectTheme(next: ThemeMode) {
    if (next === theme) return

    setTheme(next)
    applyPreferences(updatePreferences({ theme: next }))
  }

  function handleKeyDown(event: React.KeyboardEvent) {
    // Panah menunjuk POSISI opsi (kiri = DARK, kanan = LIGHT), bukan men-toggle: dari tema
    // apa pun, ArrowLeft selalu memilih DARK dan ArrowRight selalu memilih LIGHT.
    let next: ThemeMode | null = null
    if (event.key === 'ArrowLeft') next = 'dark'
    else if (event.key === 'ArrowRight') next = 'light'
    else return

    event.preventDefault()
    selectTheme(next)
    groupRef.current
      ?.querySelector<HTMLButtonElement>(`button[data-theme-option="${next}"]`)
      ?.focus()
  }

  return (
    <div
      ref={groupRef}
      role="radiogroup"
      aria-label="Tema tampilan"
      onKeyDown={handleKeyDown}
      className={cn(
        // Lebar tetap + grid-cols-2: tiap sel persis setengah lintasan, jadi indikator geser
        // (translate-x-full = lebar sel) selalu mendarat presisi di sel sebelah. Di bawah
        // breakpoint xl hanya ikon yang tampil; teks DARK/LIGHT baru muncul ketika baris navbar
        // sudah cukup longgar untuk memuat menu dan aksi kanan sekaligus.
        'relative grid h-9 w-[5.5rem] shrink-0 grid-cols-2 items-center rounded-full border border-line bg-surface p-0.5 xl:w-[9rem]',
        className,
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          'pointer-events-none absolute inset-y-0.5 left-0.5 w-[calc(50%-0.125rem)] rounded-full border border-accent/40 bg-accent-soft transition-transform duration-200 ease-out',
          theme === 'light' ? 'translate-x-full' : 'translate-x-0',
        )}
      />
      {OPTIONS.map(({ value, label, icon: Icon }) => {
        const selected = value === theme

        return (
          <button
            key={value}
            type="button"
            role="radio"
            aria-checked={selected}
            aria-label={label}
            data-theme-option={value}
            tabIndex={selected ? 0 : -1}
            onClick={() => selectTheme(value)}
            className={cn(
              'relative z-10 inline-flex h-full w-full items-center justify-center gap-1.5 rounded-full text-xs font-semibold tracking-wide transition-colors focus-visible:outline-none',
              selected ? 'text-accent' : 'text-ink-muted hover:text-ink',
            )}
          >
            <Icon size={14} aria-hidden="true" />
            <span className="hidden xl:inline">{label}</span>
          </button>
        )
      })}
    </div>
  )
}

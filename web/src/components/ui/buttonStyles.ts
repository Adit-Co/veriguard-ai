import { cva, type VariantProps } from 'class-variance-authority'

export const buttonStyles = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-btn font-medium transition-colors duration-150 focus-visible:outline-none disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        primary: 'bg-accent text-on-accent hover:bg-accent-hover',
        secondary:
          'border border-line bg-surface text-ink hover:border-line-strong hover:bg-subtle',
        // VGL-36 — aksi navigasi utama (Masuk). Seluruh warna memakai token merek sehingga
        // kontras ikut berganti bersama tema; tidak ada nilai hardcoded. Fokus keyboard lewat
        // ring (bukan outline) karena kelas dasar sudah mematikan outline untuk varian lain.
        soft: 'border border-accent/25 bg-accent-soft text-accent hover:border-accent/45 hover:bg-accent hover:text-on-accent active:bg-accent-hover active:text-on-accent focus-visible:ring-2 focus-visible:ring-accent/55 focus-visible:ring-offset-2 focus-visible:ring-offset-canvas',
        ghost: 'text-ink-soft hover:bg-subtle hover:text-ink',
        danger: 'bg-risk-high text-on-risk-high hover:bg-risk-high-hover',
      },
      size: {
        sm: 'h-9 px-3 text-sm',
        md: 'h-11 px-4 text-sm',
        lg: 'h-12 px-5 text-[15px]',
      },
    },
    defaultVariants: {
      variant: 'primary',
      size: 'md',
    },
  },
)

export type ButtonStyleProps = VariantProps<typeof buttonStyles>

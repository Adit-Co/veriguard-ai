import { X } from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { cn } from '../../lib/cn'
import { Container } from './Container'

// VGL-37A/VGL-37B — toast mengambang (bukan alert() dan bukan notifikasi browser).
// Navbar publik tingginya 65px dan sticky, jadi 80px menjatuhkan panel tepat di
// bawahnya tanpa menutupinya. Keluar dari alur halaman berarti penutup tidak lagi
// mendorong kartu ke bawah; animasi cukup translate+opacity. Panel diratakan ke
// tengah kolom konten dengan max-width 840px supaya deskripsi cukup satu-dua baris
// dan tingginya tetap rendah.
//
// VGL-37C — anggaran waktu ditutup dalam SATU batas, bukan 10 detik lalu ditambah
// animasi keluar. EXIT_MS 200ms sama persis dengan duration-200 pada kelas transisi,
// dan durasi default 9.900ms berarti: terlihat sampai 9,7 detik, animasi keluar mulai
// 9,7 detik, fade selesai 9,9 detik, dan 100ms di bawah batas 10 detik dipakai untuk
// menyerap jitter timer/render sehingga komponen pasti sudah ter-unmount tepat waktu.
const EXIT_MS = 200

export type NotificationProps = {
  title: string
  icon: ReactNode
  children: ReactNode
  /** Baris identitas di atas judul; dipertahankan agar tetap satu baris. */
  app?: string
  label?: string
  /** Otomatis hilang setelah milidetik ini. 0 = tidak ada auto-dismiss. */
  durationMs?: number
  closeLabel?: string
  className?: string
}

export function Notification({
  title,
  icon,
  children,
  app = 'VERIGUARD AI',
  label = 'Informasi layanan akun',
  durationMs = 9_900,
  closeLabel = 'Tutup notifikasi',
  className,
}: NotificationProps) {
  const [mounted, setMounted] = useState(true)
  const [entered, setEntered] = useState(false)
  const [closing, setClosing] = useState(false)
  const shownAt = useRef(0)
  const sumberTutup = useRef<'auto' | 'manual'>('manual')

  // Kelas "buka" diterapkan satu frame setelah mount agar transisi masuk terlihat.
  useEffect(() => {
    const frame = requestAnimationFrame(() => setEntered(true))
    return () => cancelAnimationFrame(frame)
  }, [])

  // VGL-37C — seluruh siklus dijatah dari SATU angka (durationMs) dan titik nolnya
  // adalah saat toast ditampilkan. Animasi keluar mulai pada durationMs - EXIT_MS,
  // sedangkan pelepasan komponen dijadwalkan ke TENGGAT MUTLAK durationMs sejak mount,
  // bukan "EXIT_MS sesudah event closing". Rantai dua timer terbukti bisa meleset
  // +4ms lewat batas (terukur), sedangkan tenggat mutlak hanya menanggung jitter
  // timer terakhir — dan masih menyisakan 100ms ruang di bawah 10 detik.
  useEffect(() => {
    if (durationMs <= 0) return
    shownAt.current = performance.now()
    const timer = window.setTimeout(() => {
      sumberTutup.current = 'auto'
      setClosing(true)
    }, Math.max(0, durationMs - EXIT_MS))
    return () => window.clearTimeout(timer)
  }, [durationMs])

  // Satu timer saja per instance; dibersihkan saat lepas sehingga pindah halaman
  // tidak meninggalkan callback yang menyentuh state. Menutup lewat X juga membersihkan
  // timer auto di atas karena effect-nya ikut dibongkar saat mounted false.
  useEffect(() => {
    if (!closing) return
    const sisa =
      sumberTutup.current === 'auto'
        ? Math.max(0, durationMs - (performance.now() - shownAt.current))
        : EXIT_MS
    const timer = window.setTimeout(() => setMounted(false), sisa)
    return () => window.clearTimeout(timer)
  }, [closing, durationMs])

  if (!mounted) return null

  const open = entered && !closing

  return (
    <div className="pointer-events-none fixed inset-x-0 top-20 z-50">
      <Container className="flex justify-center">
        <div
          role="status"
          aria-live="polite"
          className={cn(
            'pointer-events-auto w-full max-w-[840px] transition-[translate,opacity] duration-200 ease-out',
            open ? 'translate-y-0 opacity-100' : '-translate-y-3 opacity-0',
            className,
          )}
        >
          <section className="relative rounded-card border border-accent/25 bg-surface p-3.5 shadow-lift">
            <span
              aria-hidden="true"
              className="absolute inset-x-0 top-0 h-0.5 rounded-t-card bg-gradient-to-r from-accent to-accent-hover"
            />
            <div className="flex items-start gap-3">
              <span
                aria-hidden="true"
                className="grid size-9 shrink-0 place-items-center rounded-btn bg-accent-soft text-accent"
              >
                {icon}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline gap-x-2">
                  <p className="text-sm font-semibold text-ink">{title}</p>
                  <p className="type-caption text-ink-muted">
                    {app}
                    <span aria-hidden="true"> · </span>
                    {label}
                  </p>
                </div>
                <p className="mt-1 text-sm leading-relaxed text-ink-soft">{children}</p>
              </div>
              <button
                type="button"
                onClick={() => setClosing(true)}
                aria-label={closeLabel}
                className="-mt-0.5 -mr-0.5 grid size-8 shrink-0 place-items-center rounded-btn text-ink-muted transition-colors hover:bg-subtle hover:text-ink focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/55"
              >
                <X size={16} aria-hidden="true" />
              </button>
            </div>
          </section>
        </div>
      </Container>
    </div>
  )
}

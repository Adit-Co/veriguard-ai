import { MessageSquareWarning } from 'lucide-react'
import { useCallback, useState } from 'react'
import { Link } from 'react-router-dom'
import { Container } from '../ui/Container'
import { BugReportDialog } from './BugReportDialog'
import { Logo } from './Logo'

const CURRENT_YEAR = new Date().getFullYear()

const navigationGroups = [
  {
    label: 'Jelajahi',
    links: [
      { to: '/periksa', name: 'Periksa' },
      { to: '/komunitas', name: 'Community Reports' },
      { to: '/edukasi', name: 'Edukasi' },
    ],
  },
  {
    label: 'Akun',
    links: [
      { to: '/riwayat', name: 'Riwayat' },
      { to: '/dashboard', name: 'Dashboard' },
      { to: '/pengaturan', name: 'Pengaturan' },
    ],
  },
]

export function Footer() {
  const [bugDialogOpen, setBugDialogOpen] = useState(false)
  const closeBugDialog = useCallback(() => setBugDialogOpen(false), [])

  return (
    <footer className="border-t border-line bg-surface">
      <Container className="py-10 sm:py-12 lg:py-14">
        <div className="grid gap-8 md:grid-cols-2 md:gap-10 lg:grid-cols-[1.2fr_1.5fr_1.5fr] lg:gap-12">
          <div>
            <Logo />
            <p className="type-small mt-4 max-w-[34ch] text-ink-soft">
              Alat bantu pemeriksaan awal untuk mengenali indikasi penipuan digital pada tautan
              dan pesan.
            </p>
          </div>

          <nav aria-label="Navigasi kaki halaman">
            <p className="type-eyebrow text-ink-muted">Navigasi</p>
            <div className="mt-4 grid grid-cols-2 gap-x-8 gap-y-6 sm:max-w-[420px]">
              {navigationGroups.map((group) => (
                <div key={group.label}>
                  <p className="type-caption font-semibold text-ink-muted">{group.label}</p>
                  <ul className="mt-3 flex flex-col gap-2.5 text-sm">
                    {group.links.map((link) => (
                      <li key={link.to}>
                        <Link
                          to={link.to}
                          className="text-ink-soft transition-colors hover:text-ink"
                        >
                          {link.name}
                        </Link>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </nav>

          <div className="md:col-span-2 lg:col-span-1">
            <p className="type-eyebrow text-ink-muted">Tentang hasil</p>
            <p className="type-small mt-4 max-w-[52ch] text-ink-soft">
              Hasil pemeriksaan didasarkan pada analisis indikator keamanan dan potensi ancaman
              digital yang terdeteksi oleh sistem. Gunakan hasil ini sebagai dasar pertimbangan dan
              selalu lakukan verifikasi melalui sumber resmi sebelum mengambil keputusan penting.
            </p>

            <div className="mt-4 border-t border-line pt-4">
              <button
                type="button"
                onClick={() => setBugDialogOpen(true)}
                aria-haspopup="dialog"
                aria-expanded={bugDialogOpen}
                aria-controls={bugDialogOpen ? 'bug-report-dialog' : undefined}
                className="inline-flex items-center gap-2 rounded-btn text-sm text-ink-soft transition-colors hover:text-ink focus-visible:outline-none"
              >
                <MessageSquareWarning size={15} aria-hidden="true" className="text-accent" />
                Laporkan Bug
              </button>
            </div>
          </div>
        </div>

        <div className="mt-8 flex flex-col gap-2 border-t border-line pt-6 text-xs text-ink-muted sm:mt-10 sm:flex-row sm:items-center sm:justify-between">
          <p>© {CURRENT_YEAR} VERIGUARD AI</p>
          <p>Dibuat untuk hackathon keamanan siber — Defensive Shield.</p>
        </div>
      </Container>

      <BugReportDialog open={bugDialogOpen} onClose={closeBugDialog} />
    </footer>
  )
}

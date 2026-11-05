import {
  LayoutDashboard,
  LogOut,
  MailWarning,
  Menu,
  Settings,
  X,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link, NavLink } from 'react-router-dom'
import { useAuth } from '../../lib/auth/useAuth'
import { useDemoEmailText } from '../../lib/auth/demoIdentity'
import { authErrorMessage } from '../../lib/firebase/errors'
import { buttonStyles } from '../ui/buttonStyles'
import { Container } from '../ui/Container'
import { Spinner } from '../ui/Spinner'
import { Logo } from './Logo'
import { ThemeToggle } from './ThemeToggle'
import { UserMenu } from './UserMenu'

const navigation = [
  { to: '/periksa', label: 'Periksa' },
  { to: '/komunitas', label: 'Komunitas' },
  { to: '/riwayat', label: 'Riwayat' },
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/edukasi', label: 'Edukasi' },
]

const navLinkClass = ({ isActive }: { isActive: boolean }) =>
  [
    'whitespace-nowrap rounded-md px-3 py-2 text-sm transition-colors',
    isActive ? 'bg-subtle font-medium text-ink' : 'text-ink-soft hover:bg-subtle/70 hover:text-ink',
  ].join(' ')

// VGL-36 — tiga zona navbar: logo kiri, kelompok menu pada ruang tengah yang tersisa,
// lalu sakelar tema diikuti aksi akun di kanan dengan urutan tetap. nav memakai
// `grow shrink-0`: ia menyerap ruang kosong supaya menu tidak menumpuk di samping logo,
// tetapi tidak boleh menyusut di bawah lebar isinya karena menyusut berarti baris melebar
// melewati kontainer — itu yang memotong sakelar tema pada 1024.
export function PublicHeader() {
  const auth = useAuth()
  const [menuOpen, setMenuOpen] = useState(false)
  const [signingOut, setSigningOut] = useState(false)
  const [authError, setAuthError] = useState<string | null>(null)
  const menuButtonRef = useRef<HTMLButtonElement>(null)
  const mobileMenuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!menuOpen) return

    mobileMenuRef.current?.querySelector<HTMLAnchorElement>('a')?.focus()

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setMenuOpen(false)
        menuButtonRef.current?.focus()
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [menuOpen])

  async function handleSignOut() {
    if (signingOut) return

    setSigningOut(true)
    setAuthError(null)
    try {
      await auth.signOut()
      setMenuOpen(false)
    } catch (cause) {
      setAuthError(authErrorMessage(cause))
    } finally {
      setSigningOut(false)
    }
  }

  const authLoading = auth.mode === 'firebase' && auth.status === 'loading'
  const user = auth.user && !auth.user.isAnonymous ? auth.user : null
  // VGL-41E: panel akun versi seluler memakai penyamaran yang sama dengan dropdown navbar.
  const emailText = useDemoEmailText(user?.email)

  return (
    <header className="sticky top-0 z-40 border-b border-line bg-canvas">
      <Container>
        <div className="flex h-16 items-center gap-3 sm:gap-4 lg:gap-6">
          <Logo />

          <nav
            aria-label="Navigasi utama"
            className="hidden grow shrink-0 items-center justify-center gap-2 lg:flex xl:gap-3 2xl:gap-4"
          >
            {navigation.map((item) => (
              <NavLink key={item.to} to={item.to} className={navLinkClass}>
                {item.label}
              </NavLink>
            ))}
          </nav>

          <div className="ml-auto flex shrink-0 items-center gap-2.5 lg:ml-0">
            {/* Satu sakelar tema untuk semua breakpoint dan semua status login: posisinya di
                luar bercabang autentikasi sehingga login/logout tidak pernah menghilangkan
                kontrol maupun preferensinya. Tidak ada instans kedua di panel seluler agar
                sumber state tetap satu. */}
            <ThemeToggle />

            {/* Aksi akun selalu paling kanan. Di bawah sm muatannya pindah ke panel menu
                karena baris sudah penuh oleh logo, sakelar tema, dan tombol menu. */}
            <div className="hidden sm:flex sm:items-center">
              {authLoading ? (
                <span
                  role="status"
                  aria-label="Memuat status akun"
                  className="h-9 w-24 animate-pulse rounded-btn bg-subtle"
                />
              ) : user ? (
                <UserMenu />
              ) : (
                // VGL-34: navbar tidak memuat "Daftar"; entry point registrasi ada di halaman
                // Masuk. VGL-36: "Laporkan URL" bukan lagi entry point navbar — rute
                // /komunitas#community-report-form, halaman, dan formulirnya tetap utuh.
                <Link to="/masuk" className={buttonStyles({ variant: 'soft', size: 'sm' })}>
                  Masuk
                </Link>
              )}
            </div>
          </div>

          <button
            ref={menuButtonRef}
            type="button"
            onClick={() => setMenuOpen((open) => !open)}
            aria-expanded={menuOpen}
            aria-controls="menu-seluler"
            aria-label={menuOpen ? 'Tutup menu' : 'Buka menu'}
            className="grid size-11 shrink-0 place-items-center rounded-btn border border-line bg-surface text-ink-soft transition-colors hover:text-ink lg:hidden"
          >
            {menuOpen ? <X size={20} aria-hidden="true" /> : <Menu size={20} aria-hidden="true" />}
          </button>
        </div>
      </Container>

      {menuOpen ? (
        <div
          ref={mobileMenuRef}
          id="menu-seluler"
          className="border-t border-line bg-canvas lg:hidden"
        >
          <Container className="flex flex-col gap-1 py-4">
            <nav aria-label="Navigasi seluler" className="flex flex-col gap-1">
              {navigation.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  onClick={() => setMenuOpen(false)}
                  className={({ isActive }) =>
                    [
                      'rounded-btn px-3 py-3 text-sm transition-colors',
                      isActive
                        ? 'bg-subtle font-medium text-ink'
                        : 'text-ink-soft hover:bg-subtle hover:text-ink',
                    ].join(' ')
                  }
                >
                  {item.label}
                </NavLink>
              ))}
            </nav>
            {/* sm ke atas aksi akun sudah tampil di baris, jadi panel tidak mengulanginya. */}
            <div className="mt-3 flex flex-col gap-2 border-t border-line pt-4 sm:hidden">
              {authLoading ? (
                <p role="status" className="rounded-btn bg-subtle px-3 py-3 text-sm text-ink-soft">
                  Memuat status akun...
                </p>
              ) : user ? (
                <div className="rounded-card border border-line bg-surface p-3">
                  <div className="flex items-center gap-3">
                    <span
                      aria-hidden="true"
                      className="grid size-9 shrink-0 place-items-center rounded-full bg-accent-soft text-xs font-semibold text-accent"
                    >
                      {user.displayName.slice(0, 1).toUpperCase()}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-semibold text-ink">
                        {user.displayName}
                      </p>
                      <p className="truncate text-xs text-ink-muted">{emailText}</p>
                    </div>
                  </div>
                  <div className="mt-3 grid gap-1 border-t border-line pt-2">
                    <Link
                      to="/dashboard"
                      onClick={() => setMenuOpen(false)}
                      className="flex items-center gap-2.5 rounded-btn px-2.5 py-2.5 text-sm text-ink-soft hover:bg-subtle hover:text-ink"
                    >
                      <LayoutDashboard size={16} aria-hidden="true" />
                      Dashboard
                    </Link>
                    <Link
                      to="/pengaturan"
                      onClick={() => setMenuOpen(false)}
                      className="flex items-center gap-2.5 rounded-btn px-2.5 py-2.5 text-sm text-ink-soft hover:bg-subtle hover:text-ink"
                    >
                      <Settings size={16} aria-hidden="true" />
                      Pengaturan
                    </Link>
                    {!user.emailVerified ? (
                      <Link
                        to="/verifikasi-email"
                        onClick={() => setMenuOpen(false)}
                        className="flex items-center gap-2.5 rounded-btn px-2.5 py-2.5 text-sm text-risk-medium hover:bg-risk-medium-bg"
                      >
                        <MailWarning size={16} aria-hidden="true" />
                        Verifikasi email
                      </Link>
                    ) : null}
                  </div>
                  <button
                    type="button"
                    onClick={() => void handleSignOut()}
                    disabled={signingOut}
                    className="mt-1 flex w-full items-center gap-2.5 rounded-btn px-2.5 py-2.5 text-left text-sm text-ink-soft hover:bg-subtle hover:text-ink disabled:opacity-60"
                  >
                    {signingOut ? (
                      <Spinner label="Keluar dari akun" />
                    ) : (
                      <LogOut size={16} aria-hidden="true" />
                    )}
                    {signingOut ? 'Keluar...' : 'Keluar'}
                  </button>
                </div>
              ) : (
                // VGL-34: menu seluler juga hanya memuat Masuk; pendaftaran dibuka lewat
                // halaman Masuk agar tidak ada dua jalur yang saling bersaing.
                <Link
                  to="/masuk"
                  onClick={() => setMenuOpen(false)}
                  className={buttonStyles({ variant: 'soft', className: 'w-full' })}
                >
                  Masuk
                </Link>
              )}

              {authError ? (
                <p
                  role="alert"
                  className="rounded-btn border border-risk-high-line bg-risk-high-bg px-3 py-2 text-sm text-risk-high"
                >
                  {authError}
                </p>
              ) : null}
            </div>
          </Container>
        </div>
      ) : null}
    </header>
  )
}

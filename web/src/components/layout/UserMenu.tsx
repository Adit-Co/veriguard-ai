import {
  ChevronDown,
  LayoutDashboard,
  LogOut,
  MailWarning,
  Settings,
} from 'lucide-react'
import { useEffect, useId, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../../lib/auth/useAuth'
import { useDemoEmailText } from '../../lib/auth/demoIdentity'
import { emailStateLabel } from '../../lib/auth/verification'
import { cn } from '../../lib/cn'
import { authErrorMessage } from '../../lib/firebase/errors'
import { Badge } from '../ui/Badge'
import { Spinner } from '../ui/Spinner'

function initials(displayName: string): string {
  const parts = displayName.trim().split(/\s+/).filter(Boolean)
  const value = parts
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? '')
    .join('')
  return value || 'P'
}

export function UserMenu() {
  const auth = useAuth()
  const menuId = useId()
  const [open, setOpen] = useState(false)
  const [signingOut, setSigningOut] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const user = auth.user
  // VGL-41E: alamat email hanya disamar untuk akun demo; akun biasa tampil seperti sebelumnya.
  const emailText = useDemoEmailText(user?.email)

  useEffect(() => {
    if (!open) return

    menuRef.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus()

    const handlePointerDown = (event: MouseEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) setOpen(false)
    }
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false)
        triggerRef.current?.focus()
        return
      }

      if (!menuRef.current?.contains(document.activeElement)) return
      if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return

      const items = Array.from(
        menuRef.current.querySelectorAll<HTMLElement>('[role="menuitem"]:not(:disabled)'),
      )
      if (items.length === 0) return

      event.preventDefault()
      const currentIndex = items.indexOf(document.activeElement as HTMLElement)
      let nextIndex = 0

      if (event.key === 'End') nextIndex = items.length - 1
      else if (event.key === 'ArrowUp') {
        nextIndex = currentIndex <= 0 ? items.length - 1 : currentIndex - 1
      } else if (event.key === 'ArrowDown') {
        nextIndex = currentIndex < 0 || currentIndex === items.length - 1 ? 0 : currentIndex + 1
      }

      items[nextIndex]?.focus()
    }

    document.addEventListener('mousedown', handlePointerDown)
    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('mousedown', handlePointerDown)
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [open])

  if (!user) return null

  async function handleSignOut() {
    if (signingOut) return
    setSigningOut(true)
    setError(null)

    try {
      await auth.signOut()
      setOpen(false)
    } catch (cause) {
      setError(authErrorMessage(cause))
    } finally {
      setSigningOut(false)
    }
  }

  return (
    <div ref={containerRef} className="relative">
      <button
        ref={triggerRef}
        type="button"
        onClick={() => {
          setOpen((current) => !current)
          setError(null)
        }}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        className={cn(
          // Batas nama dipersempit sampai xl: pada 1024 baris navbar harus memuat logo,
          // lima menu, aksi kanan, dan sakelar tema sekaligus.
          'flex h-9 max-w-[150px] items-center gap-2 rounded-btn border border-line bg-surface px-2.5 text-left text-sm text-ink transition-colors hover:border-line-strong hover:bg-subtle xl:max-w-[220px]',
          open && 'border-line-strong bg-subtle',
        )}
      >
        <span
          aria-hidden="true"
          className="grid size-6 shrink-0 place-items-center rounded-full bg-accent-soft text-[11px] font-semibold text-accent"
        >
          {initials(user.displayName)}
        </span>
        <span className="min-w-0 flex-1 truncate font-medium">{user.displayName}</span>
        <ChevronDown
          size={14}
          aria-hidden="true"
          className={cn('shrink-0 text-ink-muted transition-transform', open && 'rotate-180')}
        />
      </button>

      {open ? (
        <div
          ref={menuRef}
          id={menuId}
          role="menu"
          aria-label="Menu akun"
          className="absolute right-0 top-[calc(100%+8px)] z-50 w-[272px] overflow-hidden rounded-card border border-line bg-surface p-1.5 shadow-lift"
        >
          <div className="border-b border-line px-3 pb-3 pt-2">
            <p className="truncate text-sm font-semibold text-ink">{user.displayName}</p>
            <p className="mt-0.5 truncate text-xs text-ink-muted">{emailText}</p>
            <div className="mt-2">
              <Badge tone={user.emailVerified ? 'low' : 'medium'}>
                {emailStateLabel(user)}
              </Badge>
            </div>
          </div>

          <div className="py-1.5">
            <Link
              to="/dashboard"
              role="menuitem"
              onClick={() => setOpen(false)}
              className="flex items-center gap-2.5 rounded-btn px-3 py-2 text-sm text-ink-soft transition-colors hover:bg-subtle hover:text-ink focus:bg-subtle focus:text-ink focus:outline-none"
            >
              <LayoutDashboard size={16} aria-hidden="true" />
              Dashboard
            </Link>
            <Link
              to="/pengaturan"
              role="menuitem"
              onClick={() => setOpen(false)}
              className="flex items-center gap-2.5 rounded-btn px-3 py-2 text-sm text-ink-soft transition-colors hover:bg-subtle hover:text-ink focus:bg-subtle focus:text-ink focus:outline-none"
            >
              <Settings size={16} aria-hidden="true" />
              Pengaturan
            </Link>
            {!user.emailVerified ? (
              <Link
                to="/verifikasi-email"
                role="menuitem"
                onClick={() => setOpen(false)}
                className="flex items-center gap-2.5 rounded-btn px-3 py-2 text-sm text-risk-medium transition-colors hover:bg-risk-medium-bg focus:bg-risk-medium-bg focus:outline-none"
              >
                <MailWarning size={16} aria-hidden="true" />
                Verifikasi email
              </Link>
            ) : null}
          </div>

          {error ? (
            <p role="alert" className="mx-1 mb-1 rounded-btn bg-risk-high-bg px-3 py-2 text-xs text-risk-high">
              {error}
            </p>
          ) : null}

          <div className="border-t border-line pt-1.5">
            <button
              type="button"
              role="menuitem"
              onClick={() => void handleSignOut()}
              disabled={signingOut}
              className="flex w-full items-center gap-2.5 rounded-btn px-3 py-2 text-left text-sm text-ink-soft transition-colors hover:bg-subtle hover:text-ink focus:bg-subtle focus:text-ink focus:outline-none disabled:opacity-60"
            >
              {signingOut ? (
                <Spinner label="Keluar dari akun" />
              ) : (
                <LogOut size={16} aria-hidden="true" />
              )}
              {signingOut ? 'Keluar...' : 'Keluar'}
            </button>
          </div>
        </div>
      ) : null}
    </div>
  )
}

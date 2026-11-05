import { Mail, MessageCircle, X } from 'lucide-react'
import { useEffect, useId, useRef } from 'react'
import type { AppUser } from '../../lib/auth/context'
import { useAuth } from '../../lib/auth/useAuth'
import type { UserProfileDocument } from '../../lib/firebase/profileDocuments'
import { cn } from '../../lib/cn'
import { Button } from '../ui/Button'
import { buttonStyles } from '../ui/buttonStyles'

const WHATSAPP_NUMBER = '62881038202105'
const GMAIL_ADDRESS = 'r10885053@gmail.com'
const GMAIL_SUBJECT = 'Laporan Bug VERIGUARD AI'
const DIALOG_ID = 'bug-report-dialog'

function usableName(
  value: string | null | undefined,
  email: string | null | undefined,
): string | null {
  const name = value?.trim()
  if (!name || name === 'Pengguna' || name.includes('@')) return null
  if (email && name.toLowerCase() === email.trim().toLowerCase()) return null
  return name
}

function resolveReportName(
  user: AppUser | null,
  profile: UserProfileDocument | null,
): string | null {
  if (!user || user.isAnonymous) return null
  return (
    usableName(profile?.displayName, user.email) ??
    usableName(user.displayName, user.email)
  )
}

function whatsAppMessage(name: string | null): string {
  if (!name) {
    return 'Hallo min, saya ingin melaporkan bug pada website VERIGUARD AI.'
  }

  return `Hallo min, saya ${name}. Saya mau melaporkan bug pada website VERIGUARD AI.\n\nMohon bantu dicek ya. Terima kasih 🙏`
}

function gmailBody(name: string | null): string {
  const nameLine = name ? `\n\nNama pengguna: ${name}` : ''

  return `Halo Admin VERIGUARD AI,\n\nSaya ingin melaporkan bug yang saya temukan pada website VERIGUARD AI.${nameLine}\n\nDetail bug:\n[Silakan jelaskan masalah yang ditemukan]\n\nTerima kasih.`
}

function whatsAppUrl(name: string | null): string {
  return `https://wa.me/${WHATSAPP_NUMBER}?text=${encodeURIComponent(whatsAppMessage(name))}`
}

function gmailUrl(name: string | null): string {
  return `mailto:${GMAIL_ADDRESS}?subject=${encodeURIComponent(GMAIL_SUBJECT)}&body=${encodeURIComponent(gmailBody(name))}`
}

export function BugReportDialog({
  open,
  onClose,
}: {
  open: boolean
  onClose: () => void
}) {
  const auth = useAuth()
  const reportName = resolveReportName(auth.user, auth.profile)
  const titleId = useId()
  const descriptionId = useId()
  const panelRef = useRef<HTMLDivElement>(null)
  const whatsAppRef = useRef<HTMLAnchorElement>(null)

  useEffect(() => {
    if (!open) return

    const previouslyFocused =
      document.activeElement instanceof HTMLElement ? document.activeElement : null
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const focusFrame = window.requestAnimationFrame(() => whatsAppRef.current?.focus())

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onClose()
        return
      }

      if (event.key !== 'Tab' || !panelRef.current) return

      const items = Array.from(
        panelRef.current.querySelectorAll<HTMLElement>('a[href], button:not([disabled])'),
      )
      if (items.length === 0) return

      const first = items[0]
      const last = items[items.length - 1]
      const active = document.activeElement

      if (!panelRef.current.contains(active)) {
        event.preventDefault()
        first.focus()
      } else if (event.shiftKey && active === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && active === last) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => {
      window.cancelAnimationFrame(focusFrame)
      document.removeEventListener('keydown', handleKeyDown)
      document.body.style.overflow = previousOverflow
      previouslyFocused?.focus()
    }
  }, [open, onClose])

  if (!open) return null

  return (
    <div
      className="fixed inset-0 z-[100] flex items-end justify-center bg-ink/45 p-3 sm:items-center sm:p-4"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose()
      }}
    >
      <div
        ref={panelRef}
        id={DIALOG_ID}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        className="max-h-[calc(100dvh-1.5rem)] w-full max-w-[440px] overflow-y-auto rounded-panel border border-line bg-surface p-5 shadow-lift sm:p-6"
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="type-eyebrow text-ink-muted">Bantuan</p>
            <h2 id={titleId} className="mt-1.5 text-lg font-semibold text-ink">
              Laporkan Bug
            </h2>
            <p id={descriptionId} className="type-small mt-1.5 text-ink-soft">
              Menemukan masalah di VERIGUARD? Pilih cara untuk mengirim laporan.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Tutup dialog laporan bug"
            className="grid size-9 shrink-0 place-items-center rounded-btn text-ink-muted transition-colors hover:bg-subtle hover:text-ink focus-visible:outline-none"
          >
            <X size={18} aria-hidden="true" />
          </button>
        </div>

        <div className="mt-5 flex flex-col gap-2.5">
          <a
            ref={whatsAppRef}
            href={whatsAppUrl(reportName)}
            target="_blank"
            rel="noopener noreferrer"
            onClick={onClose}
            className={cn(
              buttonStyles({ variant: 'secondary', size: 'lg' }),
              'h-auto w-full justify-start gap-3 whitespace-normal px-4 py-3.5 text-left',
            )}
          >
            <span
              aria-hidden="true"
              className="grid size-9 shrink-0 place-items-center rounded-btn bg-risk-low-bg text-risk-low"
            >
              <MessageCircle size={18} />
            </span>
            <span className="min-w-0">
              <span className="block font-semibold text-ink">WhatsApp</span>
              <span className="type-caption mt-0.5 block">
                Kirim laporan melalui WhatsApp
              </span>
            </span>
          </a>

          <a
            href={gmailUrl(reportName)}
            onClick={onClose}
            className={cn(
              buttonStyles({ variant: 'secondary', size: 'lg' }),
              'h-auto w-full justify-start gap-3 whitespace-normal px-4 py-3.5 text-left',
            )}
          >
            <span
              aria-hidden="true"
              className="grid size-9 shrink-0 place-items-center rounded-btn bg-accent-soft text-accent"
            >
              <Mail size={18} />
            </span>
            <span className="min-w-0">
              <span className="block font-semibold text-ink">Gmail</span>
              <span className="type-caption mt-0.5 block">
                Kirim laporan melalui email
              </span>
            </span>
          </a>
        </div>

        <div className="mt-5 flex justify-end border-t border-line pt-4">
          <Button variant="secondary" onClick={onClose}>
            Batal
          </Button>
        </div>
      </div>
    </div>
  )
}

import { LayoutDashboard, ShieldCheck } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { cn } from '../../lib/cn'

type DashboardTabsProps = {
  isAdmin: boolean
}

const tabClass = ({ isActive }: { isActive: boolean }) =>
  cn(
    'inline-flex h-10 items-center justify-center gap-2 rounded-[8px] px-3.5 text-sm font-medium transition-colors',
    isActive
      ? 'bg-surface text-ink shadow-card'
      : 'text-ink-soft hover:text-ink',
  )

export function DashboardTabs({ isAdmin }: DashboardTabsProps) {
  return (
    <nav
      aria-label="Bagian dashboard"
      className="mt-6 flex w-full flex-wrap gap-1 rounded-btn border border-line bg-subtle p-1 sm:w-auto sm:flex-nowrap"
    >
      <NavLink to="/dashboard" end className={tabClass}>
        <LayoutDashboard size={15} aria-hidden="true" />
        Dashboard Saya
      </NavLink>
      {isAdmin ? (
        <NavLink to="/dashboard/admin" className={tabClass}>
          <ShieldCheck size={15} aria-hidden="true" />
          Dashboard Admin
        </NavLink>
      ) : null}
    </nav>
  )
}

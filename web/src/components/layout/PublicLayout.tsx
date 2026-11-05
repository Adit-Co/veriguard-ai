import { useEffect } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { applyPreferences } from '../../lib/preferences/preferences'
import { Footer } from './Footer'
import { PublicHeader } from './PublicHeader'

function ScrollToTop() {
  const { pathname, hash } = useLocation()

  useEffect(() => {
    if (hash) {
      const frame = window.requestAnimationFrame(() => {
        let id = hash.slice(1)
        try {
          id = decodeURIComponent(id)
        } catch {
          return
        }
        document.getElementById(id)?.scrollIntoView()
      })
      return () => window.cancelAnimationFrame(frame)
    }

    window.scrollTo(0, 0)
  }, [pathname, hash])

  return null
}

// VGL-37C — halaman autentikasi tampil tanpa footer situs dan dengan latar sinematik.
// Komponen Footer, isi, dan desainnya tidak diubah sama sekali; hanya dua route ini yang
// tidak merendernya supaya latar tetap terbaca sampai ke tepi bawah. Selain /masuk dan
// /daftar, seluruh halaman memakai footer seperti sebelumnya.
const AUTH_PAGE_PATHS = new Set(['/masuk', '/daftar'])

export function PublicLayout() {
  const { pathname } = useLocation()

  useEffect(() => {
    applyPreferences()
  }, [])

  const authPage = AUTH_PAGE_PATHS.has(pathname.replace(/\/+$/, '') || '/')

  return (
    <div className="flex min-h-dvh flex-col">
      <a
        href="#konten"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-btn focus:bg-surface focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-ink focus:shadow-lift"
      >
        Lewati ke konten utama
      </a>
      <ScrollToTop />
      <PublicHeader />
      {/* VGL-37C — latar dipasang di <main>, bukan lewat elemen tambahan: layer ekstra
          mengubah antialiasing teks di dalam kartu (lihat catatan di styles/index.css). */}
      <main id="konten" tabIndex={-1} className={authPage ? 'auth-canvas flex-1' : 'flex-1'}>
        <Outlet />
      </main>
      {authPage ? null : <Footer />}
    </div>
  )
}

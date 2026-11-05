import { Compass } from 'lucide-react'
import { Link } from 'react-router-dom'
import { buttonStyles } from '../components/ui/buttonStyles'
import { Container } from '../components/ui/Container'

export function NotFoundPage() {
  return (
    <Container className="pb-16">
      <div className="mx-auto max-w-[560px] pt-24 text-center">
        <p className="type-eyebrow text-accent">Kesalahan 404</p>
        <h1 className="type-h1 mt-4">Halaman tidak ditemukan</h1>
        <p className="type-small mt-3 text-ink-soft">
          Alamat yang kamu buka tidak tersedia. Periksa kembali tautannya atau mulai dari beranda.
        </p>
        <div className="mt-7 flex flex-wrap justify-center gap-3">
          <Link to="/" className={buttonStyles()}>
            <Compass size={16} aria-hidden="true" />
            Kembali ke beranda
          </Link>
          <Link to="/periksa" className={buttonStyles({ variant: 'secondary' })}>
            Buka halaman periksa
          </Link>
        </div>
      </div>
    </Container>
  )
}

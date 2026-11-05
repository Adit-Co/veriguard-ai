import { ArrowLeft, ArrowRight, Check } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import { Alert } from '../components/ui/Alert'
import { Badge } from '../components/ui/Badge'
import { buttonStyles } from '../components/ui/buttonStyles'
import { Card } from '../components/ui/Card'
import { Container } from '../components/ui/Container'
import { getArticle } from '../content/articles'

export function ArticlePage() {
  const { slug } = useParams<{ slug: string }>()
  const article = slug ? getArticle(slug) : undefined

  if (!article) {
    return (
      <Container className="pb-16 sm:pb-20">
        <div className="mx-auto max-w-[760px] pt-16">
          <h1 className="type-h1">Artikel tidak ditemukan</h1>
          <p className="type-small mt-3 text-ink-soft">
            Tautan yang kamu buka mungkin sudah berubah atau tidak tersedia.
          </p>
          <Link to="/edukasi" className={buttonStyles({ className: 'mt-6' })}>
            Kembali ke daftar edukasi
          </Link>
        </div>
      </Container>
    )
  }

  return (
    <Container className="pb-16 sm:pb-20">
      <article className="mx-auto max-w-[760px]">
        <nav aria-label="Breadcrumb" className="pt-8">
          <Link
            to="/edukasi"
            className="inline-flex items-center gap-1.5 text-sm text-ink-soft transition-colors hover:text-ink"
          >
            <ArrowLeft size={16} aria-hidden="true" />
            Edukasi
          </Link>
        </nav>

        <header className="mt-6 border-b border-line pb-8">
          <Badge tone="neutral">{article.readTime}</Badge>
          <h1 className="type-h1 mt-4">{article.title}</h1>
          <p className="type-lead mt-4">{article.summary}</p>
          <p className="mt-5 text-base text-ink-soft">{article.intro}</p>
        </header>

        {article.sections.map((section) => (
          <section key={section.heading} className="mt-10">
            <h2 className="type-h2">{section.heading}</h2>
            {section.paragraphs.map((paragraph) => (
              <p key={paragraph} className="mt-4 text-base leading-relaxed text-ink-soft">
                {paragraph}
              </p>
            ))}
            {section.bullets ? (
              <ul className="mt-5 flex flex-col gap-2.5">
                {section.bullets.map((bullet) => (
                  <li key={bullet} className="flex gap-3 text-sm text-ink-soft">
                    <Check size={16} className="mt-1 shrink-0 text-accent" aria-hidden="true" />
                    {bullet}
                  </li>
                ))}
              </ul>
            ) : null}
          </section>
        ))}

        <Card className="mt-10 border-accent/20 bg-accent-soft p-6">
          <p className="type-eyebrow text-accent">Intinya</p>
          <p className="mt-3 text-base leading-relaxed text-ink">{article.takeaway}</p>
        </Card>

        <Alert tone="warning" className="mt-8" title="Tetap verifikasi">
          Artikel ini bersifat panduan umum. Modus penipuan terus berubah, jadi selalu periksa
          melalui saluran resmi sebelum memberikan data atau melakukan transaksi.
        </Alert>

        <div className="mt-8 flex flex-wrap gap-3">
          <Link to="/periksa" className={buttonStyles()}>
            Periksa tautan atau pesan
            <ArrowRight size={16} aria-hidden="true" />
          </Link>
          <Link to="/edukasi" className={buttonStyles({ variant: 'secondary' })}>
            Artikel lainnya
          </Link>
        </div>
      </article>
    </Container>
  )
}

import { ArrowRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Badge } from '../components/ui/Badge'
import { Card, CardDescription, CardTitle } from '../components/ui/Card'
import { Container } from '../components/ui/Container'
import { PageHeader } from '../components/ui/PageHeader'
import { articles } from '../content/articles'

export function EducationPage() {
  return (
    <Container className="pb-16 sm:pb-20">
      <PageHeader
        eyebrow="Edukasi"
        title="Kenali polanya sebelum percaya"
        description="Penjelasan singkat tentang modus penipuan digital, ciri yang perlu diwaspadai, dan langkah aman yang bisa langsung diterapkan."
      />

      <div className="mt-8 grid gap-4 sm:mt-10 sm:grid-cols-2 lg:grid-cols-3">
        {articles.map((article, index) => (
          <Card
            key={article.slug}
            className={`flex flex-col p-6${index === 0 ? ' sm:col-span-2 sm:p-8' : ''}`}
          >
            <Badge tone="neutral" className="self-start">
              {article.readTime}
            </Badge>
            <CardTitle className="mt-4">
              <Link
                to={`/edukasi/${article.slug}`}
                className="underline-offset-4 transition-colors hover:text-accent hover:underline"
              >
                {article.title}
              </Link>
            </CardTitle>
            <CardDescription className="mt-2 flex-1 max-w-[62ch]">{article.summary}</CardDescription>
            <Link
              to={`/edukasi/${article.slug}`}
              className="mt-5 inline-flex items-center gap-1.5 text-sm font-medium text-accent underline-offset-4 hover:underline"
            >
              Baca artikel
              <ArrowRight size={16} aria-hidden="true" />
            </Link>
          </Card>
        ))}
      </div>
    </Container>
  )
}

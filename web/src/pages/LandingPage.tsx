import {
  ArrowRight,
  Banknote,
  Check,
  Clock,
  Gift,
  KeyRound,
  Link2,
  ListChecks,
  LockKeyhole,
  MessageSquareText,
  ScanSearch,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { Accordion } from '../components/ui/Accordion'
import { Badge } from '../components/ui/Badge'
import { buttonStyles } from '../components/ui/buttonStyles'
import { Card } from '../components/ui/Card'
import { Container } from '../components/ui/Container'
import { articles } from '../content/articles'

const assurances = ['Tanpa unggah file', 'Dua mode pemeriksaan', 'Alasan yang mudah dipahami']

const steps = [
  {
    number: '01',
    title: 'Tempel tautan atau pesan',
    body: 'Masukkan alamat tautan, atau salin isi pesan dari WhatsApp, SMS, email, dan media sosial.',
  },
  {
    number: '02',
    title: 'Sistem memeriksa indikator',
    body: 'Aturan heuristik memeriksa struktur tautan, domain, dan pola bahasa. Analisis berjalan di perangkatmu.',
  },
  {
    number: '03',
    title: 'Baca alasan, lalu bertindak',
    body: 'Lihat tingkat indikasi, alasan yang ditemukan, pola penipuan, dan langkah yang disarankan.',
  },
]

const linkIndicators = [
  {
    title: 'Domain menyerupai merek resmi',
    body: 'Nama merek dipakai pada domain yang bukan miliknya, misalnya bca-verifikasi-akun.com alih-alih bca.co.id.',
  },
  {
    title: 'Tautan diperpendek',
    body: 'Alamat seperti bit.ly atau tinyurl menyembunyikan tujuan sebenarnya sampai kamu membukanya.',
  },
  {
    title: 'Alamat IP langsung',
    body: 'Situs resmi jarang menggunakan alamat angka sebagai halaman login atau pembayaran.',
  },
  {
    title: 'Subdomain berlapis',
    body: 'Nama merek bisa diletakkan di subdomain, sementara domain utamanya tetap milik pelaku.',
  },
]

const messageIndicators = [
  {
    title: 'Tekanan waktu',
    body: 'Frasa seperti “dalam 30 menit” atau “jangan sampai hangus” dipakai agar kamu bertindak sebelum sempat memeriksa.',
  },
  {
    title: 'Permintaan data sensitif',
    body: 'Permintaan OTP, PIN, kata sandi, atau foto kartu identitas melalui pesan adalah tanda bahaya.',
  },
  {
    title: 'Hadiah yang tidak pernah diikuti',
    body: 'Klaim menang undian disertai biaya administrasi atau permintaan data rekening.',
  },
  {
    title: 'Penyamaran institusi',
    body: 'Pengirim mengaku sebagai bank, kurir, atau petugas resmi untuk membangun kepercayaan.',
  },
]

const patterns = [
  'Phishing & login palsu',
  'Hadiah & undian',
  'Jual beli online',
  'Penyamaran institusi',
  'Urgensi & ancaman',
  'Investasi',
  'Lowongan kerja',
]

const faqItems = [
  {
    id: 'ai',
    question: 'Apakah VERIGUARD AI sudah menggunakan model AI?',
    answer: (
      <p>
        Belum. Versi saat ini menganalisis tautan dan pesan dengan aturan heuristik yang berjalan di
        perangkat. Integrasi model AI direncanakan melalui layanan pemeriksaan yang aman, dan hasil yang memakai AI
        akan ditandai secara jelas agar tidak tertukar dengan analisis aturan.
      </p>
    ),
  },
  {
    id: 'kepastian',
    question: 'Apakah hasil pemeriksaan bisa dijadikan kepastian?',
    answer: (
      <p>
        Tidak. Hasil merupakan indikasi awal berbasis pola, bukan vonis bahwa sebuah tautan atau
        pesan pasti berbahaya maupun pasti aman. Selalu verifikasi melalui saluran resmi sebelum
        memberikan data atau melakukan transaksi.
      </p>
    ),
  },
  {
    id: 'tanpa-indikator',
    question: 'Jika tidak ada indikator, apakah berarti tautannya aman?',
    answer: (
      <p>
        Tidak. Banyak situs penipuan baru belum masuk daftar ancaman dan tidak memakai pola yang
        sudah dikenal. Ketidakadaan indikator hanya berarti tidak ada pola risiko yang terdeteksi
        oleh aturan saat ini.
      </p>
    ),
  },
  {
    id: 'https',
    question: 'Mengapa tautan HTTPS masih bisa berbahaya?',
    answer: (
      <p>
        HTTPS hanya mengenkripsi koneksi antara peramban dan situs. Situs palsu juga bisa memakai
        HTTPS. Karena itu, pemeriksaan berfokus pada domain, struktur tautan, dan konteks pesan,
        bukan hanya keberadaan ikon gembok.
      </p>
    ),
  },
  {
    id: 'data',
    question: 'Apakah data yang saya masukkan dikirim ke layanan lain?',
    answer: (
      <p>
        Saat ini tidak. Analisis berjalan di peramban dan riwayat disimpan secara lokal di perangkat
        (maksimal 30 pemeriksaan). Kamu dapat menghapusnya kapan saja. Integrasi layanan pemeriksaan nanti akan
        dijelaskan sebelum data mulai dikirim.
      </p>
    ),
  },
  {
    id: 'akun',
    question: 'Apakah saya perlu membuat akun?',
    answer: (
      <p>
        Tidak untuk memeriksa. Akun diperlukan untuk menyimpan riwayat secara permanen dan membuka
        dashboard. Fitur akun akan aktif pada tahap integrasi layanan akun.
      </p>
    ),
  },
]

function IndicatorList({
  icon: Icon,
  title,
  items,
}: {
  icon: typeof Link2
  title: string
  items: { title: string; body: string }[]
}) {
  return (
    <div className="border-t border-line pt-6">
      <div className="flex items-center gap-2.5">
        <span className="grid size-9 place-items-center rounded-lg bg-accent-soft text-accent">
          <Icon size={18} aria-hidden="true" />
        </span>
        <h3 className="text-base font-semibold">{title}</h3>
      </div>
      <ul className="mt-5 flex flex-col gap-4">
        {items.map((item) => (
          <li key={item.title}>
            <p className="text-sm font-medium text-ink">{item.title}</p>
            <p className="type-small mt-1 text-ink-soft">{item.body}</p>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function LandingPage() {
  return (
    <>
      <section className="border-b border-line">
        <Container className="grid items-center gap-12 py-16 lg:grid-cols-12 lg:py-24">
          <div className="lg:col-span-7">
            <p className="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-3 py-1.5 text-xs font-medium text-ink-soft">
              <span aria-hidden="true" className="size-1.5 rounded-full bg-accent" />
              Defensive Shield · Hackathon Cybersecurity
            </p>

            <h1 className="type-display mt-6 max-w-[13ch]">Think Before You Click.</h1>

            <p className="type-lead mt-6 max-w-[56ch]">
              Tempel tautan atau pesan yang terasa mencurigakan. VERIGUARD AI menunjukkan indikator
              risiko, pola penipuan, dan langkah aman dalam bahasa yang mudah dipahami.
            </p>

            <div className="mt-8 flex flex-col gap-3 sm:flex-row">
              <Link to="/periksa?mode=link" className={buttonStyles({ size: 'lg' })}>
                Mulai periksa
                <ArrowRight size={18} aria-hidden="true" />
              </Link>
              <Link to="#cara-kerja" className={buttonStyles({ variant: 'secondary', size: 'lg' })}>
                Lihat cara kerja
              </Link>
            </div>

            <ul className="mt-8 flex flex-wrap gap-x-6 gap-y-2 text-sm text-ink-soft">
              {assurances.map((item) => (
                <li key={item} className="inline-flex items-center gap-2">
                  <Check size={16} className="text-accent" aria-hidden="true" />
                  {item}
                </li>
              ))}
            </ul>
          </div>

          <div className="lg:col-span-5">
            <Card className="overflow-hidden">
              <div className="flex items-center justify-between gap-3 border-b border-line px-6 py-4">
                <p className="type-eyebrow text-ink-muted">Contoh hasil</p>
                <Badge tone="neutral">Ilustrasi</Badge>
              </div>

              <div className="p-6">
                <div className="flex items-center gap-2">
                  <span aria-hidden="true" className="size-2 rounded-full bg-risk-high" />
                  <p className="text-sm font-semibold text-ink">Indikasi risiko tinggi</p>
                </div>

                <div className="mt-4 rounded-btn border border-risk-high-line bg-risk-high-bg p-4">
                  <p className="text-sm font-medium text-ink">Domain menyerupai merek resmi</p>
                  <p className="type-caption mt-1">
                    bca-verifikasi-akun.com bukan domain resmi bca.co.id
                  </p>
                </div>

                <ul className="mt-4 flex flex-col gap-3 text-sm text-ink-soft">
                  <li className="flex gap-2.5">
                    <TriangleAlert size={16} className="mt-1 shrink-0 text-risk-medium" aria-hidden="true" />
                    Meminta kode OTP melalui halaman tautan
                  </li>
                  <li className="flex gap-2.5">
                    <Link2 size={16} className="mt-1 shrink-0 text-risk-medium" aria-hidden="true" />
                    Tautan diperpendek sehingga tujuan tidak terlihat
                  </li>
                </ul>

                <p className="type-caption mt-5 border-t border-line pt-4">
                  Setiap hasil menyertakan alasan, pola penipuan, indikator teknis, dan rekomendasi
                  tindakan.
                </p>
              </div>
            </Card>
          </div>
        </Container>
      </section>

      <section id="cara-kerja" className="border-b border-line py-16 sm:py-24">
        <Container>
          <div className="max-w-[620px]">
            <p className="type-eyebrow text-accent">Cara kerja</p>
            <h2 className="type-h2 mt-3">Tiga langkah, tanpa istilah rumit.</h2>
            <p className="type-small mt-3 text-ink-soft">
              Pemeriksaan dirancang agar bisa dimulai dalam hitungan detik, bahkan tanpa akun.
            </p>
          </div>

          <ol className="mt-10 grid gap-8 md:grid-cols-3">
            {steps.map((step) => (
              <li key={step.number} className="border-t border-line pt-5">
                <span className="text-xs font-semibold tabular-nums tracking-[0.14em] text-accent">
                  {step.number}
                </span>
                <h3 className="mt-3 text-base font-semibold">{step.title}</h3>
                <p className="type-small mt-2 text-ink-soft">{step.body}</p>
              </li>
            ))}
          </ol>

          <p className="type-caption mt-8">
            Analisis saat ini berbasis aturan heuristik di perangkat. Model AI belum terhubung.
          </p>
        </Container>
      </section>

      <section className="border-b border-line bg-subtle py-20 sm:py-28">
        <Container>
          <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
            <div className="max-w-[560px]">
              <p className="type-eyebrow text-accent">Indikator</p>
              <h2 className="type-h2 mt-3">Yang diperiksa dari tautan dan pesan.</h2>
            </div>
            <p className="type-caption max-w-[38ch]">
              Contoh di bawah bersifat ilustratif, bukan hasil pemindaian.
            </p>
          </div>

          <div className="mt-10 grid gap-10 md:grid-cols-2 md:gap-12">
            <IndicatorList icon={Link2} title="Pada tautan" items={linkIndicators} />
            <IndicatorList icon={MessageSquareText} title="Pada pesan" items={messageIndicators} />
          </div>
        </Container>
      </section>

      <section className="border-b border-line py-16 sm:py-24">
        <Container>
          <div className="grid gap-8 lg:grid-cols-12 lg:items-start">
            <div className="lg:col-span-4">
              <p className="type-eyebrow text-accent">Pola penipuan</p>
              <h2 className="type-h2 mt-3">Nama untuk pola yang berulang.</h2>
              <p className="type-small mt-3 text-ink-soft">
                Sistem mencocokkan temuan dengan pola yang sudah dikenal. Pola yang muncul adalah
                indikasi, bukan tuduhan terhadap pengirim.
              </p>
            </div>

            <div className="lg:col-span-8">
              <ul className="flex flex-wrap gap-2.5">
                {patterns.map((pattern) => (
                  <li key={pattern}>
                    <Badge tone="neutral" className="px-3 py-1.5 text-[13px]">
                      {pattern}
                    </Badge>
                  </li>
                ))}
              </ul>

              <div className="mt-8 grid gap-4 sm:grid-cols-3">
                {[
                  { icon: Gift, title: 'Hadiah', body: 'Klaim hadiah disertai biaya atau data rekening.' },
                  { icon: KeyRound, title: 'Kredensial', body: 'Permintaan OTP, PIN, atau kata sandi.' },
                  { icon: Banknote, title: 'Transaksi', body: 'Transfer mendesak ke rekening yang belum terverifikasi.' },
                ].map(({ icon: Icon, title, body }) => (
                  <div key={title} className="rounded-card border border-line bg-surface p-4">
                    <Icon size={18} className="text-accent" aria-hidden="true" />
                    <p className="mt-3 text-sm font-medium">{title}</p>
                    <p className="type-caption mt-1">{body}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Container>
      </section>

      <section className="border-b border-line py-20 sm:py-24">
        <Container>
          <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
            <div className="max-w-[560px]">
              <p className="type-eyebrow text-accent">Edukasi</p>
              <h2 className="type-h2 mt-3">Kenali polanya sebelum percaya.</h2>
            </div>
            <Link
              to="/edukasi"
              className="inline-flex items-center gap-1.5 text-sm font-medium text-accent underline-offset-4 hover:underline"
            >
              Lihat semua artikel
              <ArrowRight size={16} aria-hidden="true" />
            </Link>
          </div>

          <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {articles.map((article, index) => (
              <Link
                key={article.slug}
                to={`/edukasi/${article.slug}`}
                className={`group rounded-card border border-line bg-surface p-5 transition-colors hover:border-line-strong${
                  index === 0 ? ' sm:col-span-2 sm:p-7' : ''
                }`}
              >
                <p className="type-caption">{article.readTime}</p>
                <h3 className="mt-2 text-base font-semibold text-ink transition-colors group-hover:text-accent">
                  {article.title}
                </h3>
                <p className="type-small mt-2 text-ink-soft">{article.summary}</p>
              </Link>
            ))}
          </div>
        </Container>
      </section>

      <section className="border-b border-line py-16 sm:py-20">
        <Container>
          <div className="grid gap-10 lg:grid-cols-12">
            <div className="lg:col-span-4">
              <p className="type-eyebrow text-accent">Pertanyaan umum</p>
              <h2 className="type-h2 mt-3">Sebelum kamu mulai.</h2>
              <p className="type-small mt-3 text-ink-soft">
                Batasan dan cara kerja dijelaskan terbuka, termasuk bagian yang belum aktif.
              </p>
            </div>
            <div className="lg:col-span-8">
              <Accordion items={faqItems} />
            </div>
          </div>
        </Container>
      </section>

      <section className="py-20 sm:py-28">
        <Container>
          <Card className="flex flex-col gap-6 border-accent/20 bg-accent-soft p-8 sm:flex-row sm:items-center sm:justify-between sm:p-10">
            <div className="flex items-start gap-4">
              <span className="grid size-11 shrink-0 place-items-center rounded-xl bg-surface text-accent">
                <ShieldCheck size={22} aria-hidden="true" />
              </span>
              <div>
                <h2 className="type-h3">Siap memeriksa sebelum mengeklik?</h2>
                <p className="type-small mt-1.5 max-w-[52ch] text-ink-soft">
                  Mulai dari satu tautan atau satu pesan. Tidak perlu akun, dan hasilnya bisa
                  langsung kamu baca.
                </p>
              </div>
            </div>
            <div className="flex shrink-0 flex-col gap-2 sm:flex-row">
              <Link to="/periksa?mode=link" className={buttonStyles()}>
                <ScanSearch size={16} aria-hidden="true" />
                Periksa tautan
              </Link>
              <Link
                to="/periksa?mode=message"
                className={buttonStyles({ variant: 'secondary' })}
              >
                <MessageSquareText size={16} aria-hidden="true" />
                Periksa pesan
              </Link>
            </div>
          </Card>

          <div className="mt-8 flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-ink-muted">
            <span className="inline-flex items-center gap-1.5">
              <LockKeyhole size={14} aria-hidden="true" />
              Analisis di perangkat
            </span>
            <span className="inline-flex items-center gap-1.5">
              <Clock size={14} aria-hidden="true" />
              Hasil dalam hitungan detik
            </span>
            <span className="inline-flex items-center gap-1.5">
              <ListChecks size={14} aria-hidden="true" />
              Alasan yang dapat dibaca
            </span>
          </div>
        </Container>
      </section>
    </>
  )
}

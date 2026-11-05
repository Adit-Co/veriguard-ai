import {
  Activity,
  ArrowRight,
  Gauge,
  History,
  Link2,
  LockKeyhole,
  MessageSquareText,
  ShieldAlert,
} from 'lucide-react'
import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { ProfileSyncNotice } from '../components/auth/ProfileSyncNotice'
import { DashboardTabs } from '../components/dashboard/DashboardTabs'
import { Alert } from '../components/ui/Alert'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { buttonStyles } from '../components/ui/buttonStyles'
import { Card } from '../components/ui/Card'
import { Container } from '../components/ui/Container'
import { PageHeader } from '../components/ui/PageHeader'
import { StatePanel } from '../components/ui/StatePanel'
import { RISK_VISUALS } from '../lib/analysis'
import type { RiskLevel } from '../lib/analysis'
import { useAdminRole } from '../lib/auth/useAdminRole'
import { useAuth } from '../lib/auth/useAuth'
import { isVerifiedAccount } from '../lib/auth/verification'
import { buildDashboardStats, riskPercentage } from '../lib/dashboard/stats'
import { useScanHistory } from '../lib/scans/useScanHistory'
import { styleValue } from '../lib/styleValue'

const dateFormatter = new Intl.DateTimeFormat('id-ID', {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
})

const RISK_ORDER: RiskLevel[] = ['high', 'medium', 'low']

function formatDate(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'Waktu tidak diketahui' : dateFormatter.format(date)
}

export function DashboardPage() {
  const auth = useAuth()
  const adminRole = useAdminRole()
  const { scans, loading, error, source, refresh } = useScanHistory()
  const stats = useMemo(() => buildDashboardStats(scans), [scans])
  const session =
    auth.user &&
    (auth.mode === 'demo' || (auth.mode === 'firebase' && isVerifiedAccount(auth.user)))
      ? auth.user
      : null
  const cloud = source === 'cloud'
  const demo = auth.mode === 'demo'

  if (auth.status === 'loading') {
    return (
      <Container className="pb-16 sm:pb-20">
        <PageHeader
          eyebrow="Dashboard"
          title="Ringkasan aktivitas"
          actions={<Badge tone="neutral">Memuat sesi</Badge>}
        />
        <StatePanel
          role="status"
          icon={Activity}
          tone="neutral"
          title="Memulihkan sesi akun…"
          description="Dashboard akan terbuka setelah status akun diketahui."
          className="mt-8 max-w-[720px]"
        />
      </Container>
    )
  }

  if (auth.status === 'error') {
    return (
      <Container className="pb-16 sm:pb-20">
        <PageHeader
          eyebrow="Dashboard"
          title="Ringkasan aktivitas"
          actions={<Badge tone="high">Layanan akun bermasalah</Badge>}
        />
        <Alert tone="danger" className="mt-8" title="Layanan akun gagal disiapkan">
          {auth.initializationError ??
            'Layanan akun belum dapat disiapkan. Muat ulang halaman atau hubungi pengelola layanan.'}
        </Alert>
      </Container>
    )
  }

  if (loading) {
    return (
      <Container className="pb-16 sm:pb-20">
        <PageHeader
          eyebrow="Dashboard"
          title="Ringkasan aktivitas"
          actions={<Badge tone="neutral">Memuat data</Badge>}
        />
        <StatePanel
          role="status"
          icon={History}
          tone="neutral"
          title="Memuat riwayat akun…"
          description="Statistik dihitung setelah pemeriksaan milik akun ini selesai dimuat."
          className="mt-8 max-w-[720px]"
        />
      </Container>
    )
  }

  if (error) {
    return (
      <Container className="pb-16 sm:pb-20">
        <PageHeader
          eyebrow="Dashboard"
          title="Ringkasan aktivitas"
          actions={<Badge tone="high">Data gagal dimuat</Badge>}
        />
        <Alert tone="danger" className="mt-8" title="Riwayat akun gagal dimuat">
          <p>{error}</p>
          <Button variant="secondary" size="sm" className="mt-3" onClick={refresh}>
            Coba lagi
          </Button>
        </Alert>
      </Container>
    )
  }

  if (!session) {
    return (
      <Container className="pb-16 sm:pb-20">
        <PageHeader
          eyebrow="Dashboard"
          title="Ringkasan aktivitas"
          description="Dashboard ini hanya menampilkan pemeriksaan yang tersimpan untuk akun yang sedang aktif di sesi ini."
          actions={<Badge tone="neutral">Menunggu sesi</Badge>}
        />

        <StatePanel
          icon={LockKeyhole}
          tone="neutral"
          title="Dashboard memerlukan sesi"
          actions={
            <>
              <Link to="/masuk" className={buttonStyles()}>
                {demo ? 'Buka sesi demo lokal' : 'Masuk dengan email'}
              </Link>
              <Link
                to={demo ? '/riwayat' : '/daftar'}
                className={buttonStyles({ variant: 'secondary' })}
              >
                {demo ? 'Buka riwayat' : 'Buat akun'}
              </Link>
            </>
          }
          className="mt-8 max-w-[720px]"
        >
          <p className="type-small mt-2 max-w-[62ch] text-ink-soft">
            {demo
              ? 'Layanan akun belum aktif. Untuk mencoba alur dashboard, buka sesi demo lokal di perangkat ini. Sesi tersebut bukan autentikasi dan tidak menyinkronkan data.'
              : 'Masuk dengan akun untuk membuka statistik pemeriksaan milikmu. Data akun hanya dapat dibaca oleh pengguna yang sedang masuk.'}
          </p>
        </StatePanel>

        <Alert
          tone={demo ? 'warning' : 'info'}
          className="mt-6"
          title={demo ? 'Autentikasi sungguhan belum tersedia' : 'Sesi akun diperlukan'}
        >
          {demo
            ? 'Login email, masuk dengan Google, dan penyimpanan akun belum tersedia. Dashboard hanya dapat dibuka melalui sesi demo yang tersimpan di browser ini.'
            : 'Layanan akun akan memverifikasi sesi saat halaman dimuat. Jika kamu baru mendaftar, periksa email verifikasi untuk keamanan pemulihan akun.'}
        </Alert>
      </Container>
    )
  }

  if (stats.total === 0) {
    return (
      <Container className="pb-16 sm:pb-20">
        <PageHeader
          eyebrow="Dashboard"
          title="Ringkasan aktivitas"
          description={`Halo, ${session.displayName}. Belum ada pemeriksaan tersimpan untuk akun ini.`}
          actions={<Badge tone="neutral">{demo ? 'Sesi demo lokal' : 'Akun'}</Badge>}
        />

        <DashboardTabs isAdmin={adminRole.isAdmin} />

        <ProfileSyncNotice />

        <StatePanel
          icon={History}
          title="Belum ada pemeriksaan tersimpan"
          actions={
            <>
              <Link to="/periksa" className={buttonStyles()}>
                Mulai pemeriksaan
                <ArrowRight size={15} aria-hidden="true" />
              </Link>
              <Link to="/riwayat" className={buttonStyles({ variant: 'secondary' })}>
                Buka riwayat
              </Link>
            </>
          }
          className="mt-6 max-w-[720px]"
        >
          <p className="type-small mt-2 max-w-[62ch] text-ink-soft">
            {cloud
              ? 'Riwayat akun ini masih kosong. Mulai pemeriksaan tautan atau pesan; hasil yang tersimpan akan muncul di statistik dan riwayat akun ini.'
              : 'Riwayat di perangkat ini masih kosong. Mulai pemeriksaan tautan atau pesan; hasil yang tersimpan akan muncul di statistik dan riwayat.'}
          </p>
        </StatePanel>

        <Alert
          tone="info"
          className="mt-6"
          title={demo ? 'Sesi demo lokal' : 'Akun aktif'}
        >
          {demo
            ? `Kamu masuk sebagai ${session.displayName}. Sesi ini bukan autentikasi dan hanya berada di browser ini; statistik akan dihitung dari pemeriksaan yang tersimpan di perangkat ini.`
            : `Masuk sebagai ${session.displayName}. Statistik hanya dihitung dari data akun ini, bukan dari akun lain di perangkat yang sama.`}
        </Alert>
      </Container>
    )
  }

  const statCards = [
    {
      label: 'Total pemeriksaan',
      value: String(stats.total),
      caption: cloud ? 'Tersimpan di akun' : 'Tersimpan di perangkat ini',
      icon: History,
    },
    {
      label: 'Risiko tinggi',
      value: String(stats.byRisk.high),
      caption: `${riskPercentage(stats.byRisk.high, stats.total)}% dari total`,
      icon: ShieldAlert,
    },
    {
      label: 'Skor rata-rata',
      value: `${stats.averageScore}/100`,
      caption: 'Jumlah bobot indikator',
      icon: Gauge,
    },
    {
      label: 'Pola terdeteksi',
      value: String(stats.topPatterns.length),
      caption: 'Jenis pola unik',
      icon: Activity,
    },
  ]

  const highestPatternCount = stats.topPatterns[0]?.count ?? 1

  return (
    <Container className="pb-16 sm:pb-20">
      <PageHeader
        eyebrow="Dashboard"
        title="Ringkasan aktivitas"
        description={
          cloud
            ? `Statistik dari ${stats.total} pemeriksaan yang tersimpan di akunmu.`
            : `Statistik dari ${stats.total} pemeriksaan yang tersimpan di browser ini.`
        }
        actions={
          <>
            <Badge tone="neutral">{demo ? 'Sesi demo lokal' : 'Akun'}</Badge>
            <Link
              to="/pengaturan"
              className={buttonStyles({ variant: 'secondary', size: 'sm' })}
            >
              Kelola data
            </Link>
          </>
        }
      />

      <DashboardTabs isAdmin={adminRole.isAdmin} />

      <ProfileSyncNotice />

      <Alert
        tone="info"
        className="mt-6"
        title={
          demo
            ? `Sesi demo aktif: ${session.displayName}`
            : `Akun aktif: ${session.displayName}`
        }
      >
        {demo
          ? 'Dashboard membaca riwayat lokal di browser ini. Ini bukan autentikasi, tidak memverifikasi identitas, dan tidak menyinkronkan data ke perangkat lain.'
          : 'Dashboard membaca data milik akun ini. Aturan akses membatasi akses ke pengguna yang sedang masuk.'}{' '}
        <Link
          to="/pengaturan"
          className="font-medium text-accent underline-offset-4 hover:underline"
        >
          {demo ? 'Kelola sesi dan data lokal' : 'Kelola akun dan data'}
        </Link>
      </Alert>

      <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {statCards.map(({ label, value, caption, icon: Icon }) => (
          <Card key={label} className="p-5">
            <div className="flex items-center justify-between gap-3">
              <p className="text-sm text-ink-soft">{label}</p>
              <Icon size={18} className="text-ink-muted" aria-hidden="true" />
            </div>
            <p className="mt-4 text-3xl font-semibold tabular-nums tracking-tight text-ink">
              {value}
            </p>
            <p className="type-caption mt-1">{caption}</p>
          </Card>
        ))}
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2 lg:items-start">
        <Card className="p-5 sm:p-6">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="type-h3">Distribusi risiko</h2>
            <Badge tone="neutral">{stats.total} pemeriksaan</Badge>
          </div>
          <p className="type-caption mt-1">Berdasarkan tingkat indikasi pada hasil pemeriksaan.</p>

          <div className="mt-5 flex flex-col gap-4">
            {RISK_ORDER.map((level) => {
              const visual = RISK_VISUALS[level]
              const count = stats.byRisk[level]
              const percentage = riskPercentage(count, stats.total)

              return (
                <div key={level}>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <Badge tone={visual.badgeTone}>{visual.shortLabel}</Badge>
                    <span className="text-sm tabular-nums text-ink-soft">
                      <span className="font-semibold text-ink">{count}</span> · {percentage}%
                    </span>
                  </div>
                  <div
                    role="img"
                    aria-label={`${visual.label}: ${count} dari ${stats.total} pemeriksaan (${percentage}%)`}
                    className="mt-2 h-2 overflow-hidden rounded-full bg-line"
                  >
                    <div
                      aria-hidden="true"
                      className={`h-full rounded-full ${visual.barClass}`}
                      ref={styleValue('width', `${percentage}%`)}
                    />
                  </div>
                </div>
              )
            })}
          </div>

          <p className="type-caption mt-5">
            Risiko rendah bukan jaminan bahwa tautan atau pesan aman. Tetap verifikasi melalui kanal
            resmi.
          </p>
        </Card>

        <Card className="p-5 sm:p-6">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="type-h3">Pola terbanyak</h2>
            <Badge tone="neutral">Aturan heuristik</Badge>
          </div>
          <p className="type-caption mt-1">
            Pola yang paling sering muncul pada pemeriksaan tersimpan.
          </p>

          {stats.topPatterns.length > 0 ? (
            <ul className="mt-5 flex flex-col gap-3">
              {stats.topPatterns.slice(0, 6).map((pattern) => {
                const width = Math.round((pattern.count / highestPatternCount) * 100)

                return (
                  <li key={pattern.id}>
                    <div className="flex items-center justify-between gap-3 text-sm">
                      <span className="truncate font-medium text-ink">{pattern.label}</span>
                      <span className="shrink-0 tabular-nums text-ink-soft">{pattern.count}x</span>
                    </div>
                    <div aria-hidden="true" className="mt-1.5 h-1.5 rounded-full bg-line">
                      <div
                        className="h-full rounded-full bg-accent"
                        ref={styleValue('width', `${width}%`)}
                      />
                    </div>
                  </li>
                )
              })}
            </ul>
          ) : (
            <p className="mt-5 text-sm text-ink-soft">
              Belum ada pola penipuan spesifik yang terdeteksi pada pemeriksaan tersimpan.
            </p>
          )}
        </Card>
      </div>

      <Card className="mt-4 p-5 sm:p-6">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="type-h3">Riwayat terbaru</h2>
          <Link
            to="/riwayat"
            className="text-sm font-medium text-accent underline-offset-4 hover:underline"
          >
            Lihat semua riwayat
          </Link>
        </div>
        <p className="type-caption mt-1">Lima pemeriksaan terakhir berdasarkan waktu.</p>

        <ul aria-label="Riwayat pemeriksaan terbaru" className="mt-4 divide-y divide-line">
          {stats.latest.map((scan) => {
            const visual = RISK_VISUALS[scan.riskLevel]
            const Icon = scan.mode === 'link' ? Link2 : MessageSquareText

            return (
              <li key={scan.id} className="py-3 first:pt-0 last:pb-0">
                <div className="flex items-start gap-3">
                  <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-subtle text-ink-muted">
                    <Icon size={16} aria-hidden="true" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <Link
                        to={`/hasil/${scan.id}`}
                        className="min-w-0 truncate text-sm font-medium text-ink hover:text-accent"
                      >
                        {scan.displayTarget}
                      </Link>
                      <Badge tone={visual.badgeTone}>{visual.shortLabel}</Badge>
                    </div>
                    <p className="type-caption mt-1">
                      {formatDate(scan.createdAt)} · {scan.mode === 'link' ? 'Tautan' : 'Pesan'} ·
                      Skor {scan.riskScore}/100
                    </p>
                  </div>
                </div>
              </li>
            )
          })}
        </ul>
      </Card>

      <Alert tone="warning" className="mt-6" title="Tentang angka di dashboard">
        {cloud
          ? 'Statistik dihitung dari data akun ini. Jumlah sampel yang kecil membuat angka ini hanya gambaran awal, bukan penilaian risiko menyeluruh.'
          : 'Statistik dihitung dari riwayat lokal, bukan dari data akun atau data bersama. Jumlah sampel yang kecil membuat angka ini hanya gambaran awal, bukan penilaian risiko menyeluruh.'}
      </Alert>
    </Container>
  )
}

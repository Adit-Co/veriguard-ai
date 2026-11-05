import { ArrowRight, Clock3, MessageSquareWarning, Users } from 'lucide-react'
import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '../../lib/auth/useAuth'
import { VERIFICATION_EMAIL_PATH } from '../../lib/auth/verification'
import { COMMUNITY_CONTEXT_SCAN_LIMIT } from '../../lib/community/sparkProtocol'
import { useCommunityContext } from '../../lib/community/useCommunityContext'
import {
  COMMUNITY_CATEGORY_LABELS,
  type CommunityCategory,
  type CommunityModerationStatus,
} from '../../lib/community/types'
import { computeCommunityReputation } from '../../lib/community/reputation'
import { isFirebaseConfigured } from '../../lib/firebase/config'
import { EXTERNAL_PROVIDER_IDS } from '../../lib/scanners/types'
import { MaskedReporterName } from './MaskedReporterName'
import { Alert } from '../ui/Alert'
import { Badge } from '../ui/Badge'
import { buttonStyles } from '../ui/buttonStyles'
import { Card } from '../ui/Card'
import { styleValue } from '../../lib/styleValue'

const dateFormatter = new Intl.DateTimeFormat('id-ID', {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
})

const STATUS_LABEL: Record<CommunityModerationStatus, string> = {
  community_reported: 'Dilaporkan komunitas',
  under_review: 'Sedang ditinjau',
  cleared: 'Ditinjau, belum ada bukti',
  verified_malicious: 'Diverifikasi berbahaya',
}

function formatDate(value: string | null): string {
  if (!value) return 'belum diketahui'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'belum diketahui' : dateFormatter.format(date)
}

function topCategories(categoryCounts: Partial<Record<CommunityCategory, number>>) {
  return Object.entries(categoryCounts)
    .filter((entry): entry is [CommunityCategory, number] => typeof entry[1] === 'number')
    .sort(([, countA], [, countB]) => countB - countA)
    .slice(0, 3)
}

function reputationTone(score: number): 'high' | 'medium' | 'low' {
  if (score >= 55) return 'high'
  if (score >= 25) return 'medium'
  return 'low'
}

type CommunityContextPanelProps = {
  url: string
}

export function CommunityContextPanel({ url }: CommunityContextPanelProps) {
  const location = useLocation()
  const auth = useAuth()
  const signedIn =
    auth.mode === 'firebase' && auth.status === 'ready' && auth.user && !auth.user.isAnonymous
      ? auth.user
      : null
  const verified = Boolean(signedIn?.emailVerified)
  const waitingForSession = auth.mode === 'firebase' && auth.status === 'loading'
  const { status, normalizedUrl, context, error, refresh } = useCommunityContext(url, verified)
  const from = `${location.pathname}${location.search}`

  if (!isFirebaseConfigured) return null

  const summary = context?.summary ?? null
  const report = context?.report ?? null
  const reports = context?.reports ?? []
  const reputation = status === 'ready' ? computeCommunityReputation(reports, summary) : null
  const reportHref = normalizedUrl
    ? `/komunitas?url=${encodeURIComponent(normalizedUrl)}`
    : '/komunitas'
  const categories = summary ? topCategories(summary.categoryCounts) : []

  return (
    <Card className="mt-4 p-5 print-avoid-break sm:p-6" aria-labelledby="community-context-title">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="grid size-8 place-items-center rounded-full bg-accent-soft text-accent">
              <MessageSquareWarning size={16} aria-hidden="true" />
            </span>
            <h2 id="community-context-title" className="text-sm font-semibold text-ink">
              Konteks komunitas
            </h2>
            {summary ? (
              <Badge tone={SUMMARY_TONE[summary.moderationStatus]}>
                {STATUS_LABEL[summary.moderationStatus]}
              </Badge>
            ) : null}
          </div>
          <p className="type-caption mt-2">
            Sinyal tambahan dari laporan pengguna. Tidak mengubah Skor Indikasi Internal
            pemeriksaan ini.
          </p>
        </div>
      </div>

      {waitingForSession ? (
        <p className="type-small mt-4 text-ink-soft" role="status">
          Memeriksa sesi akun sebelum memuat konteks komunitas…
        </p>
      ) : null}

      {!waitingForSession && auth.mode === 'firebase' && auth.status === 'error' ? (
        <Alert tone="warning" className="mt-4" title="Sesi akun tidak dapat diperiksa">
          {auth.initializationError ??
            'Konteks komunitas memerlukan layanan akun yang siap digunakan.'}
        </Alert>
      ) : null}

      {!waitingForSession && auth.status !== 'error' && !verified ? (
        <div className="mt-4 rounded-card border border-dashed border-line bg-subtle/50 p-4">
          <p className="text-sm font-medium text-ink">Konteks komunitas belum dimuat</p>
          <p className="type-small mt-1 text-ink-soft">
            {auth.mode === 'firebase' && signedIn
              ? 'Laporan komunitas hanya dapat dibaca oleh akun dengan email terverifikasi. Keadaan ini bukan berarti tidak ada laporan, dan bukan penilaian bahwa tautan aman.'
              : auth.mode === 'firebase'
                ? 'Masuk dengan akun terverifikasi untuk melihat laporan komunitas. Keadaan ini bukan berarti tidak ada laporan, dan bukan penilaian bahwa tautan aman.'
                : 'Layanan akun tidak tersedia pada versi ini, sehingga laporan komunitas tidak dapat dimuat.'}
          </p>
          {auth.mode === 'firebase' ? (
            <Link
              to={signedIn ? VERIFICATION_EMAIL_PATH : '/masuk'}
              state={{ from }}
              className="mt-2 inline-block text-sm font-medium text-accent hover:underline"
            >
              {signedIn ? 'Verifikasi email akun' : 'Masuk dengan akun'}
            </Link>
          ) : null}
        </div>
      ) : null}

      {verified && status === 'loading' ? (
        <p className="type-small mt-4 text-ink-soft" role="status">
          Memeriksa konteks komunitas…
        </p>
      ) : null}

      {verified && status === 'idle' ? (
        <p className="type-small mt-4 text-ink-soft">
          Konteks komunitas belum dimuat untuk tautan ini.
        </p>
      ) : null}

      {verified && status === 'error' ? (
        <Alert tone="warning" className="mt-4" title="Konteks komunitas tidak tersedia">
          <p>{error ?? 'Layanan komunitas tidak dapat dihubungi.'}</p>
          <p className="mt-2">
            Status ini berbeda dari hasil pemindaian dan bukan penilaian bahwa tautan aman.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => void refresh()}
              className="text-sm font-medium text-accent hover:underline"
            >
              Coba lagi
            </button>
            <Link
              to={reportHref}
              state={{ from }}
              className="text-sm font-medium text-accent hover:underline"
            >
              Buka Community Reports
            </Link>
          </div>
        </Alert>
      ) : null}

      {verified && status === 'ready' ? (
        <>
          {summary?.moderationStatus === 'verified_malicious' ? (
            <Alert tone="danger" className="mt-4" title="Diverifikasi berbahaya oleh moderator">
              URL ini telah ditinjau. Sumber verifikasi: {summary.verificationSource ?? 'moderator'}.
              {summary.verifiedAt ? ` Diverifikasi ${formatDate(summary.verifiedAt)}.` : null}
            </Alert>
          ) : summary?.moderationStatus === 'under_review' ? (
            <Alert tone="warning" className="mt-4" title="Laporan sedang ditinjau">
              Ada laporan yang perlu ditinjau manual. Status ini belum merupakan kesimpulan akhir.
            </Alert>
          ) : summary?.moderationStatus === 'cleared' ? (
            <Alert tone="info" className="mt-4" title="Sudah ditinjau, belum ada bukti">
              Moderator belum menemukan bukti yang cukup. Ini bukan jaminan bahwa URL aman.
            </Alert>
          ) : summary && summary.reportCount > 0 ? (
            <Alert tone="warning" className="mt-4" title="Dilaporkan oleh komunitas">
              {summary.reportCount.toLocaleString('id-ID')} laporan aktif. Laporan komunitas belum
              tentu terverifikasi; tetap periksa melalui kanal resmi.
            </Alert>
          ) : (
            <Alert tone="info" className="mt-4" title="Belum ada laporan komunitas">
              Tidak ada laporan aktif untuk URL ini. Ini bukan jaminan bahwa URL aman.
            </Alert>
          )}

          <dl className="mt-4 grid gap-3 border-t border-line pt-4 text-sm sm:grid-cols-3">
            <div>
              <dt className="type-caption">Laporan aktif</dt>
              <dd className="mt-0.5 font-medium text-ink">
                {(summary?.reportCount ?? 0).toLocaleString('id-ID')}
              </dd>
            </div>
            <div>
              <dt className="type-caption">Aktivitas terakhir</dt>
              <dd className="mt-0.5 text-ink">{formatDate(summary?.lastActivityAt ?? null)}</dd>
            </div>
            <div>
              <dt className="type-caption">Laporan terakhirmu</dt>
              <dd className="mt-0.5 text-ink">
                {report
                  ? `Sudah dikirim (${COMMUNITY_CATEGORY_LABELS[report.category]})`
                  : summary && !summary.aggregatesComplete
                    ? `Tidak ditemukan dalam ${COMMUNITY_CONTEXT_SCAN_LIMIT} laporan terbaru`
                    : 'Belum ada'}
              </dd>
            </div>
          </dl>

          {summary && !summary.aggregatesComplete ? (
            <p className="type-caption mt-3">
              Ringkasan memindai hingga {COMMUNITY_CONTEXT_SCAN_LIMIT} laporan terbaru. Total
              laporan aktif tetap tepat, tetapi jumlah pseudonim pelapor dan kategori belum
              lengkap, jadi Skor Reputasi tidak ditampilkan.
            </p>
          ) : null}

          {reputation ? (
            <div className="mt-4 rounded-card border border-line bg-subtle/60 p-4">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <p className="type-caption text-ink-muted">Skor Reputasi</p>
                <Badge tone={reputationTone(reputation.score)}>{reputation.label}</Badge>
              </div>
              <p className="mt-1 text-3xl font-semibold tabular-nums tracking-tight text-ink">
                {reputation.score}
                <span className="ml-1 text-base font-normal text-ink-muted">/100</span>
              </p>
              <div
                role="img"
                aria-label={`Skor Reputasi ${reputation.score} dari 100`}
                className="mt-3 h-2 overflow-hidden rounded-full bg-line"
              >
                <div
                  className="h-full rounded-full bg-accent"
                  ref={styleValue('width', `${reputation.score}%`)}
                />
              </div>
              <p className="type-caption mt-3">
                Dihitung dari {(summary?.reportCount ?? 0).toLocaleString('id-ID')} laporan aktif
                oleh {reputation.reporters.toLocaleString('id-ID')} pseudonim pelapor untuk URL ini.
                Pseudonim dibuat oleh aplikasi, jadi jumlahnya bukan bukti akun unik dan dapat
                dipengaruhi penyalinan pseudonim. Nilai ini berdiri sendiri: Skor Indikasi Internal,
                verdict, dan hasil {EXTERNAL_PROVIDER_IDS.length} agen tidak berubah karena ada
                laporan.
              </p>
            </div>
          ) : null}

          {reputation === null &&
          status === 'ready' &&
          (summary?.reportCount ?? 0) === 0 &&
          reports.length === 0 ? (
            <p className="type-caption mt-4">
              Skor Reputasi belum dihitung karena belum ada laporan yang cocok untuk URL ini. Tidak
              ada skor yang dikarang untuk keadaan kosong.
            </p>
          ) : null}

          {reports.length > 0 ? (
            <section className="mt-4 border-t border-line pt-4" aria-labelledby="community-reports-title">
              <h3
                id="community-reports-title"
                className="type-caption inline-flex items-center gap-1.5 font-semibold text-ink-muted"
              >
                <Users size={13} aria-hidden="true" />
                Laporan komunitas untuk URL ini
              </h3>
              <ul className="mt-3 flex flex-col gap-2.5">
                {reports.map((entry) => (
                  <li
                    key={entry.id}
                    className="rounded-card border border-line bg-canvas p-3.5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-sm font-semibold text-ink">
                        <MaskedReporterName value={entry.userName} />
                      </p>
                      <span className="type-caption inline-flex items-center gap-1">
                        <Clock3 size={12} aria-hidden="true" />
                        {formatDate(entry.createdAt)}
                      </span>
                    </div>
                    <p className="mt-1.5 text-sm break-words text-ink-soft">{entry.reportText}</p>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      <Badge tone="neutral">{COMMUNITY_CATEGORY_LABELS[entry.category]}</Badge>
                      {entry.hostname ? (
                        <span className="type-caption break-all">{entry.hostname}</span>
                      ) : null}
                    </div>
                  </li>
                ))}
              </ul>
              <p className="type-caption mt-3">
                Isi laporan adalah dugaan pengguna, bukan hasil pemeriksaan yang terverifikasi.
              </p>
            </section>
          ) : null}

          {categories.length > 0 ? (
            <div className="mt-3 flex flex-wrap items-center gap-1.5">
              <span className="type-caption">Kategori terbanyak:</span>
              {categories.map(([category, count]) => (
                <Badge key={category} tone="neutral">
                  {COMMUNITY_CATEGORY_LABELS[category]} · {count}
                </Badge>
              ))}
            </div>
          ) : null}

          <div className="mt-4 flex flex-wrap items-center gap-3">
            <Link
              to={reportHref}
              state={{ from }}
              className={buttonStyles({ variant: 'secondary', size: 'sm' })}
            >
              {report ? 'Kirim laporan lagi' : 'Laporkan URL ini'}
              <ArrowRight size={15} aria-hidden="true" />
            </Link>
            <span className="inline-flex items-center gap-1.5 type-caption">
              <Clock3 size={13} aria-hidden="true" />
              Laporan komunitas belum diverifikasi moderator
            </span>
          </div>
        </>
      ) : null}
    </Card>
  )
}

const SUMMARY_TONE: Record<
  CommunityModerationStatus,
  'neutral' | 'medium' | 'low' | 'high' | 'info'
> = {
  community_reported: 'medium',
  under_review: 'info',
  cleared: 'low',
  verified_malicious: 'high',
}

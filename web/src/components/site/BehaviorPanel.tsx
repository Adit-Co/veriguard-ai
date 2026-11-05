import { Card } from '../ui/Card'
import { Badge } from '../ui/Badge'
import type { BehaviorAnalysis } from '../../lib/website/types'
import { userFacingText } from '../../lib/uiText'
import {
  CopyButton,
  EmptyHint,
  Mono,
  Muted,
  NoteList,
  SectionTitle,
} from './siteKit'
import { sectionBadge } from './siteFormat'

const HOP_OUTCOME_LABEL: Record<BehaviorAnalysis['redirects'][number]['outcome'], string> = {
  followed: 'Diikuti',
  final: 'Tujuan akhir',
  blocked: 'Diblokir kebijakan',
  loop: 'Loop dihentikan',
  limit: 'Batas redirect',
  error: 'Gagal dihubungi',
}

const HOP_OUTCOME_TONE: Record<
  BehaviorAnalysis['redirects'][number]['outcome'],
  'neutral' | 'low' | 'medium' | 'high'
> = {
  followed: 'neutral',
  final: 'low',
  blocked: 'medium',
  loop: 'medium',
  limit: 'medium',
  error: 'high',
}

const ROLE_LABEL: Record<'observed' | 'referenced' | 'inferred', string> = {
  observed: 'Dihubungi VERIGUARD',
  referenced: 'Dirujuk halaman',
  inferred: 'Disimpulkan dari teks',
}

const STRENGTH_LABEL: Record<'strong' | 'moderate' | 'weak', string> = {
  strong: 'Sinyal erat',
  moderate: 'Sinyal sedang',
  weak: 'Sinyal lemah',
}

const STRENGTH_TONE: Record<'strong' | 'moderate' | 'weak', 'medium' | 'neutral'> = {
  strong: 'medium',
  moderate: 'neutral',
  weak: 'neutral',
}

export function BehaviorPanel({ data }: { data: BehaviorAnalysis }) {
  const view = sectionBadge(data.status)

  return (
    <Card className="p-5 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <SectionTitle description="Yang diamati hanya permintaan, header, dan HTML yang dibaca layanan pemeriksaan. Skrip halaman tidak dijalankan.">
          Analisis Perilaku
        </SectionTitle>
        <Badge tone={view.tone}>{view.label}</Badge>
      </div>

      <section aria-labelledby="behavior-structure-title" className="mt-5">
        <h3 id="behavior-structure-title" className="type-eyebrow text-ink-muted">
          Struktur URL &amp; nama host
        </h3>
        <p className="type-caption mt-1">
          Diperiksa dari teks URL saja: skema <Mono>{data.structure.scheme ?? 'tidak dikenal'}</Mono>,
          port <Mono>{data.structure.port ?? 'bawaan'}</Mono>, {data.structure.labelCount} label host,
          domain terdaftar{' '}
          <Mono>{data.structure.registrableDomain ?? 'tidak dapat dipastikan'}</Mono>.
        </p>
        {data.structure.findings.length > 0 ? (
          <ul className="mt-3 flex flex-col gap-2">
            {data.structure.findings.map((finding) => (
              <li key={finding.code} className="rounded-card border border-line bg-canvas p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={STRENGTH_TONE[finding.strength]}>
                    {STRENGTH_LABEL[finding.strength]}
                  </Badge>
                  <span className="type-small font-medium text-ink">{finding.label}</span>
                </div>
                <p className="type-caption mt-1 text-ink-soft">{userFacingText(finding.detail)}</p>
                {finding.evidence ? (
                  <p className="type-caption mt-1 break-all">
                    <Muted>Bukti: </Muted>
                    <Mono>{finding.evidence}</Mono>
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        ) : (
          <EmptyHint>
            {data.structure.status === 'unavailable'
              ? 'Struktur URL belum dapat dinilai pada pemeriksaan ini.'
              : 'Tidak ada pola struktur yang menonjol pada URL ini. Ini bukan bukti bahwa URL aman.'}
          </EmptyHint>
        )}
        <p className="type-caption mt-2 text-ink-muted">
          Sinyal struktur saling berkorelasi dan tidak dijadikan vonis. Penamaan yang mirip merek bisa
          sah (situs resmi atau mitra), sementara URL yang singkat pun dapat menipu.
        </p>
      </section>

      <section aria-labelledby="behavior-redirect-title" className="mt-6">
        <h3 id="behavior-redirect-title" className="type-eyebrow text-ink-muted">
          Rantai redirect
        </h3>
        <p className="type-caption mt-1 text-ink-soft">
          URL awal: <Mono>{data.initialUrl}</Mono> · {data.redirectCount} redirect diikuti ·{' '}
          {data.redirectOutcome === 'final'
            ? 'berakhir pada tujuan akhir'
            : data.redirectOutcome === 'blocked'
              ? 'dihentikan oleh kebijakan keamanan'
              : data.redirectOutcome === 'loop'
                ? 'loop redirect dihentikan'
                : data.redirectOutcome === 'limit'
                  ? 'batas jumlah redirect tercapai'
                  : data.redirectOutcome === 'error'
                    ? 'berhenti karena kegagalan koneksi'
                    : 'belum dapat dinilai'}
        </p>

        {data.redirects.length > 0 ? (
          <ol className="mt-3 flex flex-col gap-2">
            {data.redirects.map((hop, index) => (
              <li key={`${hop.url}-${index}`} className="rounded-card border border-line bg-canvas p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="type-caption tabular-nums text-ink-muted">#{index + 1}</span>
                  <Badge tone={HOP_OUTCOME_TONE[hop.outcome]}>{HOP_OUTCOME_LABEL[hop.outcome]}</Badge>
                  <span className="type-caption tabular-nums text-ink-soft">
                    {hop.status !== null ? `HTTP ${hop.status}` : 'tanpa status'}
                  </span>
                </div>
                <p className="mt-1.5 flex items-start gap-2">
                  <Mono>{hop.url}</Mono>
                  <CopyButton value={hop.url} label={`URL hop ${index + 1}`} />
                </p>
                {hop.location ? (
                  <p className="type-caption mt-1 break-all">
                    <Muted>Location: </Muted>
                    {hop.location}
                  </p>
                ) : null}
                {hop.detail ? (
                  <p className="type-caption mt-1 text-ink-soft">{userFacingText(hop.detail)}</p>
                ) : null}
              </li>
            ))}
          </ol>
        ) : (
          <EmptyHint>Rantai redirect belum tersedia karena halaman tidak berhasil diminta.</EmptyHint>
        )}
      </section>

      <section aria-labelledby="behavior-hosts-title" className="mt-6">
        <h3 id="behavior-hosts-title" className="type-eyebrow text-ink-muted">
          Koneksi &amp; host terkait
        </h3>
        <p className="type-caption mt-1">
          Peran host dibedakan: hanya <b>Dihubungi VERIGUARD</b> yang benar-benar diminta oleh
          layanan pemeriksaan. Host yang dirujuk atau disimpulkan dari teks tidak berarti pernah
          dibuka.
        </p>
        {data.hosts.length > 0 ? (
          <ul className="mt-3 grid gap-2 sm:grid-cols-2">
            {data.hosts.map((entry) => (
              <li key={entry.host} className="rounded-card border border-line bg-canvas p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Mono>{entry.host}</Mono>
                  <CopyButton value={entry.host} label="Nama host" />
                  <Muted>×{entry.count}</Muted>
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {entry.roles.map((role) => (
                    <Badge key={role} tone={role === 'observed' ? 'info' : 'neutral'}>
                      {ROLE_LABEL[role]}
                    </Badge>
                  ))}
                </div>
                {entry.resourceKinds.length > 0 ? (
                  <p className="type-caption mt-1.5">
                    Jenis sumber daya: {entry.resourceKinds.join(', ')}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        ) : (
          <EmptyHint>
            Tidak ada host yang dapat didaftar. Ketiadaan daftar ini bukan bukti bahwa halaman
            tidak memuat sumber daya eksternal.
          </EmptyHint>
        )}
      </section>

      <section aria-labelledby="behavior-resources-title" className="mt-6">
        <h3 id="behavior-resources-title" className="type-eyebrow text-ink-muted">
          Sumber daya halaman
        </h3>
        {data.resources ? (
          <dl className="mt-2 grid gap-2 sm:grid-cols-3">
            {[
              ['Skrip', data.resources.scripts],
              ['Gaya', data.resources.styles],
              ['Gambar', data.resources.images],
              ['Iframe', data.resources.iframes],
              ['Tautan', data.resources.links],
              ['Lainnya', data.resources.other],
            ].map(([label, count]) => (
              <div key={String(label)} className="rounded-card border border-line bg-canvas p-3">
                <dt className="type-caption">{label}</dt>
                <dd className="mt-0.5 text-lg font-semibold tabular-nums text-ink">{String(count)}</dd>
              </div>
            ))}
          </dl>
        ) : (
          <EmptyHint>Dokumen HTML tidak tersedia, jadi sumber daya halaman tidak dapat didaftar.</EmptyHint>
        )}
        {data.resources?.capped ? (
          <p className="type-caption mt-2 text-risk-medium">
            Pengumpulan sumber daya dihentikan pada batas jumlah; jumlah di atas bukan total
            menyeluruh.
          </p>
        ) : null}
      </section>

      <section aria-labelledby="behavior-headers-title" className="mt-6">
        <h3 id="behavior-headers-title" className="type-eyebrow text-ink-muted">
          Header keamanan
        </h3>
        {data.securityHeaders.length > 0 ? (
          <ul className="mt-2 flex flex-col gap-1.5">
            {data.securityHeaders.map((header) => (
              <li key={header.name} className="flex flex-wrap items-start gap-2">
                <Badge tone={header.present ? 'low' : 'neutral'}>
                  {header.present ? 'Hadir' : 'Tidak terlihat'}
                </Badge>
                <span className="type-small min-w-0 flex-1 break-all">
                  <span className="font-mono text-ink">{header.name}</span>
                  {header.value ? <Muted>: {header.value}</Muted> : null}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyHeaderNote />
        )}
      </section>

      <section aria-labelledby="behavior-cookies-title" className="mt-6">
        <h3 id="behavior-cookies-title" className="type-eyebrow text-ink-muted">
          Cookie (metadata saja)
        </h3>
        <p className="type-caption mt-1">
          Yang ditampilkan hanya nama dan atribut keamanan. Nilai cookie, sesi masuk, dan data
          sensitif tidak pernah diambil atau ditampilkan.
        </p>
        {data.cookies.length > 0 ? (
          <ul className="mt-3 flex flex-col gap-2">
            {data.cookies.map((cookie) => (
              <li key={cookie.name} className="rounded-card border border-line bg-canvas p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Mono>{cookie.name}</Mono>
                  {cookie.secure ? <Badge tone="low">Secure</Badge> : <Badge tone="medium">tanpa Secure</Badge>}
                  {cookie.httpOnly ? <Badge tone="low">HttpOnly</Badge> : <Badge tone="medium">tanpa HttpOnly</Badge>}
                  <Badge tone="neutral">SameSite: {cookie.sameSite ?? 'tidak dinyatakan'}</Badge>
                  <Badge tone="neutral">{cookie.hasExpiry ? 'Punya masa berlaku' : 'Cookie sesi'}</Badge>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyHint>
            {data.cookiesCollected
              ? 'Header Set-Cookie tidak teramati pada respons ini. Ini bukan bukti situs tidak memakai cookie.'
              : 'Respons tidak terbaca, jadi metadata cookie tidak tersedia.'}
          </EmptyHint>
        )}
      </section>

      <section aria-labelledby="behavior-forms-title" className="mt-6">
        <h3 id="behavior-forms-title" className="type-eyebrow text-ink-muted">
          Form &amp; kolom kredensial
        </h3>
        <p className="type-caption mt-1">
          Dibaca dari HTML statis tanpa menjalankan skrip: {data.forms.totals.forms} form,{" "}
          {data.forms.totals.passwordFields} kolom sandi, {data.forms.totals.externalActions} tujuan
          ke host lain, {data.forms.totals.insecureActions} tujuan tanpa HTTPS. Nilai isian form tidak
          pernah dibaca.
        </p>
        {data.forms.forms.length > 0 ? (
          <ul className="mt-3 flex flex-col gap-2">
            {data.forms.forms.map((form) => (
              <li key={form.index} className="rounded-card border border-line bg-canvas p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="type-caption tabular-nums text-ink-muted">
                    Form #{form.index}
                  </span>
                  <Badge tone="neutral">{form.method ? form.method.toUpperCase() : 'GET (bawaan)'}</Badge>
                  {form.external ? <Badge tone="medium">Host tujuan berbeda</Badge> : null}
                  {form.insecure ? <Badge tone="high">Tujuan tanpa HTTPS</Badge> : null}
                  {form.passwordFields > 0 ? (
                    <Badge tone="medium">{form.passwordFields} kolom sandi</Badge>
                  ) : null}
                  <Muted>{form.textFields} kolom teks lain</Muted>
                </div>
                <p className="type-caption mt-1 break-all">
                  <Muted>Aksi: </Muted>
                  <Mono>{form.action ?? 'tidak dinyatakan (termuat ke halaman ini)'}</Mono>
                </p>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyHint>
            {data.forms.inspected
              ? 'Tidak ada form yang terbaca pada HTML yang diperiksa. Halaman bisa saja menyisipkan form lewat skrip, yang tidak dijalankan.'
              : 'Dokumen HTML tidak terbaca, jadi form dan kolom kredensial tidak dapat diperiksa.'}
          </EmptyHint>
        )}
        {data.forms.capped ? (
          <p className="type-caption mt-2 text-risk-medium">
            Pendaftaran form dihentikan pada batas jumlah; daftar di atas bukan seluruh form di
            halaman.
          </p>
        ) : null}
      </section>

      <section aria-labelledby="behavior-observations-title" className="mt-6">
        <h3 id="behavior-observations-title" className="type-eyebrow text-ink-muted">
          Perilaku teramati &amp; batas bukti
        </h3>
        {data.observations.length > 0 ? (
          <ul className="mt-2 flex flex-col gap-1.5">
            {data.observations.map((observation, index) => (
              <li key={`${observation.kind}-${index}`} className="flex flex-wrap items-start gap-2">
                <Badge
                  tone={
                    observation.state === 'observed'
                      ? 'low'
                      : observation.state === 'inferred'
                        ? 'medium'
                        : observation.state === 'unavailable'
                          ? 'neutral'
                          : 'neutral'
                  }
                >
                  {observation.state === 'observed'
                    ? 'Teramati'
                    : observation.state === 'inferred'
                      ? 'Disimpulkan'
                      : observation.state === 'no_signal'
                        ? 'Tidak ada sinyal'
                        : 'Tidak dapat dinilai'}
                </Badge>
                <span className="type-small min-w-0 flex-1 text-ink-soft">
                  {userFacingText(observation.detail)}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyHint>Belum ada perilaku yang dapat diamati dari pemeriksaan ini.</EmptyHint>
        )}
      </section>

      <NoteList notes={data.notes} />
    </Card>
  )
}

function EmptyHeaderNote() {
  return (
    <EmptyHint>
      Header respons tidak tersedia, jadi keberadaan header keamanan belum dapat dinilai.
      Ketidakhadiran header pada daftar ini bukan bukti situs aman, dan kehadirannya bukan jaminan
      aman.
    </EmptyHint>
  )
}

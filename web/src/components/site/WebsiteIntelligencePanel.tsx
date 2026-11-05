import { Card } from '../ui/Card'
import { Badge } from '../ui/Badge'
import type { Lookup, WebsiteIntelligence } from '../../lib/website/types'
import { userFacingText } from '../../lib/uiText'
import {
  DataRow,
  EmptyHint,
  LookupDetail,
  Mono,
  Muted,
  NoteList,
  SectionTitle,
  StatusLine,
} from './siteKit'
import { formatBytes, formatDuration, lookupBadge } from './siteFormat'

function AddressList({ lookup }: { lookup: Lookup<import('../../lib/website/types').IpAddressEntry[]> }) {
  const addresses = lookup.value ?? []

  if (addresses.length === 0) {
    return (
      <EmptyHint>
        {lookup.status === 'blocked'
          ? 'Tidak ada alamat publik yang diizinkan oleh kebijakan keamanan, jadi halaman tidak dibuka.'
          : 'Alamat IP tidak dapat ditampilkan. Status di atas bukan bukti aman maupun berbahaya.'}
      </EmptyHint>
    )
  }

  return (
    <ul className="mt-2 flex flex-col gap-2">
      {addresses.map((entry) => (
        <li key={`${entry.kind}-${entry.address}`} className="flex flex-wrap items-center gap-2">
          <Mono>{entry.address}</Mono>
          <Badge tone="neutral">{entry.kind === 'ipv6' ? 'IPv6' : 'IPv4'}</Badge>
        </li>
      ))}
    </ul>
  )
}

export function WebsiteIntelligencePanel({ data }: { data: WebsiteIntelligence }) {
  const { identity, dns, tls, response } = data
  const certificate = tls.certificate.value

  return (
    <Card className="p-5 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <SectionTitle description="Hasil pembacaan jaringan, DNS, sertifikat, dan respons HTTP oleh layanan pemeriksaan.">
          Website Intelligence
        </SectionTitle>
        <Badge tone={data.status === 'complete' ? 'low' : data.status === 'failed' ? 'high' : 'neutral'}>
          {data.status === 'complete'
            ? 'Selesai'
            : data.status === 'partial'
              ? 'Sebagian tersedia'
              : data.status === 'failed'
                ? 'Gagal'
                : 'Tidak tersedia'}
        </Badge>
      </div>

      <div className="mt-5 flex flex-col gap-6">
        <section aria-labelledby="site-network-title">
          <h4 id="site-network-title" className="type-eyebrow text-ink-muted">
            Network Identity
          </h4>
          <dl className="mt-2">
            <DataRow label="Nama host" copy={identity.hostname}>
              <Mono>{identity.hostname || '—'}</Mono>
            </DataRow>
            <div className="border-b border-line py-2.5">
              <p className="type-caption sm:w-44">Alamat hasil resolusi</p>
              <div className="mt-1.5">
                <StatusLine lookup={identity.addresses} />
                <AddressList lookup={identity.addresses} />
                <LookupDetail lookup={identity.addresses} />
                {identity.withheldAddresses > 0 ? (
                  <p className="type-caption mt-1 text-risk-medium">
                    {identity.withheldAddresses} alamat disembunyikan karena berada di rentang
                    internal, loopback, link-local, multicast, atau metadata.
                  </p>
                ) : null}
              </div>
            </div>
          </dl>
          <OriginAddressNote />
        </section>

        <section aria-labelledby="site-asn-title">
          <h4 id="site-asn-title" className="type-eyebrow text-ink-muted">
            ASN &amp; Jaringan
          </h4>
          <div className="mt-1.5">
            <StatusLine lookup={identity.asn} />
            <LookupDetail lookup={identity.asn} />
            {identity.asn.value ? (
              <dl className="mt-2">
                <DataRow label="ASN" copy={identity.asn.value.asn ?? ''}>
                  {identity.asn.value.asn ? <Mono>AS{identity.asn.value.asn}</Mono> : <Muted>tidak tersedia</Muted>}
                </DataRow>
                <DataRow label="Organisasi">
                  {identity.asn.value.organization ?? <Muted>tidak tersedia dari sumber ini</Muted>}
                </DataRow>
                <DataRow label="Negara">
                  {identity.asn.value.country ?? <Muted>tidak tersedia</Muted>}
                </DataRow>
                <DataRow label="Prefix" copy={identity.asn.value.prefix ?? ''}>
                  {identity.asn.value.prefix ? <Mono>{identity.asn.value.prefix}</Mono> : <Muted>tidak tersedia</Muted>}
                </DataRow>
                <DataRow label="Registry">
                  {identity.asn.value.registry ?? <Muted>tidak tersedia</Muted>}
                </DataRow>
              </dl>
            ) : (
              <EmptyHint>
                Data ASN tidak ditampilkan. Ini bukan bukti bahwa alamat tersebut milik pihak
                tertentu, dan bukan pula bukti aman atau berbahaya.
              </EmptyHint>
            )}
          </div>
        </section>

        <section aria-labelledby="site-intermediary-title" className="rounded-card border border-line bg-canvas p-4">
          <h4 id="site-intermediary-title" className="type-eyebrow text-ink-muted">
            Kemungkinan perantara
          </h4>
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <Badge tone={identity.intermediary.state === 'possible' ? 'medium' : 'neutral'}>
              {identity.intermediary.state === 'possible'
                ? 'Ada sinyal CDN/proxy/LB'
                : identity.intermediary.state === 'no_signal'
                  ? 'Tidak ada sinyal perantara'
                  : 'Belum dapat dinilai'}
            </Badge>
          </div>
          {identity.intermediary.signals.length > 0 ? (
            <ul className="mt-2 flex flex-col gap-1.5">
              {identity.intermediary.signals.map((signal) => (
                <li key={`${signal.label}-${signal.evidence}`} className="type-small text-ink-soft">
                  <span className="font-medium text-ink">{signal.label}</span> — {signal.evidence}
                </li>
              ))}
            </ul>
          ) : null}
          <p className="type-caption mt-2 text-ink-soft">
            {userFacingText(identity.intermediary.note)}
          </p>
        </section>

        <section aria-labelledby="site-dns-title">
          <h4 id="site-dns-title" className="type-eyebrow text-ink-muted">
            DNS Records
          </h4>
          <div className="mt-2 grid gap-2">
            {dns.map((entry) => {
              const view = lookupBadge(entry.lookup.status)
              const records = entry.lookup.value ?? []
              return (
                <div key={entry.type} className="rounded-card border border-line bg-canvas p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-sm font-semibold text-ink">{entry.type}</p>
                    <Badge tone={view.tone}>{view.label}</Badge>
                  </div>
                  {records.length > 0 ? (
                    <ul className="mt-2 flex flex-col gap-1">
                      {records.map((record) => (
                        <li key={record} className="flex items-start gap-2">
                          <Mono>{record}</Mono>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="type-caption mt-1.5 text-ink-soft">
                      {entry.lookup.status === 'empty'
                        ? 'Kueri selesai dan tidak mengembalikan record tipe ini.'
                        : entry.lookup.status === 'failed'
                          ? 'Kueri gagal; ketiadaan record bukan bukti aman.'
                          : entry.lookup.status === 'blocked'
                            ? 'Kueri tidak dijalankan karena kebijakan keamanan.'
                            : 'Record belum dapat diambil.'}
                    </p>
                  )}
                  {entry.lookup.detail ? (
                    <p className="type-caption mt-1.5 text-ink-muted">{entry.lookup.detail}</p>
                  ) : null}
                </div>
              )
            })}
          </div>
        </section>

        <section aria-labelledby="site-tls-title">
          <h4 id="site-tls-title" className="type-eyebrow text-ink-muted">
            TLS Certificate
          </h4>
          <div className="mt-1.5 flex flex-col gap-2">
            <div>
              <StatusLine lookup={tls.httpsAvailable} />
              <p className="type-caption mt-1 text-ink-soft">
                {tls.httpsAvailable.value === true
                  ? 'HTTPS berhasil dijawab pada pemeriksaan ini.'
                  : tls.httpsAvailable.value === false
                    ? 'HTTPS tidak terkonfirmasi pada pemeriksaan ini.'
                    : 'Ketersediaan HTTPS belum dapat dinilai.'}{' '}
                HTTPS yang merespons bukan bukti sertifikat tepercaya.
              </p>
              <LookupDetail lookup={tls.httpsAvailable} />
            </div>
            <StatusLine lookup={tls.certificate} />
            {certificate ? (
              <dl className="mt-1">
                <DataRow label="Issuer">
                  {certificate.issuer ?? <Muted>tidak tersedia</Muted>}
                </DataRow>
                <DataRow label="Subject" copy={certificate.subject ?? ''}>
                  {certificate.subject ? <Mono>{certificate.subject}</Mono> : <Muted>tidak tersedia</Muted>}
                </DataRow>
                <DataRow label="Berlaku dari">
                  {certificate.notBefore ?? <Muted>tidak tersedia</Muted>}
                </DataRow>
                <DataRow label="Berlaku sampai">
                  {certificate.notAfter ?? <Muted>tidak tersedia</Muted>}
                </DataRow>
                <DataRow label="Kedaluwarsa">
                  {certificate.expired === null ? (
                    <Muted>tidak dapat ditentukan</Muted>
                  ) : certificate.expired ? (
                    <Badge tone="high">Sudah kedaluwarsa</Badge>
                  ) : (
                    <Badge tone="low">Masih dalam periode berlaku</Badge>
                  )}
                </DataRow>
                <DataRow label="Verifikasi nama host">
                  {certificate.verification === 'verified' ? (
                    <Badge tone="low">Terverifikasi pada sambungan ini</Badge>
                  ) : certificate.verification === 'rejected' ? (
                    <Badge tone="high">Verifikasi ditolak</Badge>
                  ) : (
                    <Badge tone="neutral">Tidak diperiksa</Badge>
                  )}
                </DataRow>
                {certificate.verificationDetail ? (
                  <DataRow label="Catatan verifikasi">
                    {userFacingText(certificate.verificationDetail)}
                  </DataRow>
                ) : null}
                <DataRow label="Protokol">
                  {certificate.protocol ?? <Muted>tidak tersedia</Muted>}
                </DataRow>
                {tls.certificateSource ? (
                  <DataRow label="Sumber sertifikat">
                    {userFacingText(tls.certificateSource)}
                  </DataRow>
                ) : null}
              </dl>
            ) : (
              <EmptyHint>
                Sertifikat tidak dapat diambil. Ketiadaan data ini tidak berarti sertifikat tidak
                ada atau tidak sah.
              </EmptyHint>
            )}
          </div>
        </section>

        <section aria-labelledby="site-http-title">
          <h4 id="site-http-title" className="type-eyebrow text-ink-muted">
            HTTP Response
          </h4>
          <div className="mt-1.5">
            <StatusLine lookup={response.request} />
            <LookupDetail lookup={response.request} />
          </div>
          {response.status !== null ? (
            <dl className="mt-1">
              <DataRow label="Status">
                <span className="tabular-nums">{response.status}</span>
                {response.statusText ? <Muted> {response.statusText}</Muted> : null}
              </DataRow>
              <DataRow label="URL akhir" copy={response.finalUrl ?? ''}>
                {response.finalUrl ? <Mono>{response.finalUrl}</Mono> : <Muted>tidak tercapai</Muted>}
              </DataRow>
              <DataRow label="Jumlah redirect">{response.redirectCount}</DataRow>
              <DataRow label="Waktu respons">
                {response.elapsedMs !== null ? formatDuration(response.elapsedMs) : <Muted>tidak terukur</Muted>}
              </DataRow>
              <DataRow label="Content-Type">
                {response.contentType ? <Mono>{response.contentType}</Mono> : <Muted>tidak dinyatakan</Muted>}
              </DataRow>
              <DataRow label="Ukuran dibaca">
                {response.bytes !== null ? formatBytes(response.bytes) : <Muted>tidak terukur</Muted>}
                {response.truncated ? <Badge tone="medium">Dipotong batas ukuran</Badge> : null}
              </DataRow>
              <div className="border-b border-line py-2.5">
                <p className="type-caption sm:w-44">Header aman yang ditampilkan</p>
                {response.headers.length > 0 ? (
                  <ul className="mt-1.5 flex flex-col gap-1">
                    {response.headers.map((header) => (
                      <li key={header.name} className="type-small break-all">
                        <span className="font-mono text-ink">{header.name}</span>
                        <Muted>: </Muted>
                        <span className="font-mono text-ink-soft">{header.value}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="type-caption mt-1.5">Tidak ada header yang lolos penyaring.</p>
                )}
                {response.withheldHeaders > 0 ? (
                  <p className="type-caption mt-1.5 text-ink-muted">
                    {response.withheldHeaders} header tidak ditampilkan karena dapat memuat
                    cookie, data masuk, atau data sensitif.
                  </p>
                ) : null}
              </div>
            </dl>
          ) : (
            <EmptyHint>
              Halaman tidak berhasil dibuka, jadi respons HTTP tidak tersedia. Status ini bukan
              bukti bahwa situs berbahaya maupun aman.
            </EmptyHint>
          )}
        </section>
      </div>

      <NoteList notes={data.notes} />
    </Card>
  )
}

function OriginAddressNote() {
  return (
    <p className="type-caption mt-2 text-ink-soft">
      Alamat yang ditampilkan adalah alamat hasil resolusi publik, belum tentu server asal. Jika
      terdapat CDN, proxy, atau penyeimbang beban, alamat itu bisa milik perantara. VERIGUARD tidak
      mencoba menembus CDN atau mencari infrastruktur asal.
    </p>
  )
}

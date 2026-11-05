import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { BehaviorPanel } from './BehaviorPanel'
import { RiskFusionSummary, SiteAnalysisArea, type SiteSection } from './SiteAnalysisArea'
import { TechnologyPanel } from './TechnologyPanel'
import { WebsiteCategoryPanel } from './WebsiteCategoryPanel'
import { WebsiteIntelligencePanel } from './WebsiteIntelligencePanel'
import { parseSiteAnalysisResponse } from '../../lib/website/validate'
import { EXTERNAL_PROVIDER_IDS } from '../../lib/scanners/types'
import type {
  BehaviorAnalysis,
  RiskFusion,
  SiteAnalysisResponse,
  TechnologyAnalysis,
  WebsiteIntelligence,
} from '../../lib/website/types'
import type { UseSiteAnalysisResult } from '../../lib/website/useSiteAnalysis'

function parse<T>(value: unknown): T {
  const report = parseSiteAnalysisResponse({
    version: 1,
    target: 'https://contoh.com/',
    hostname: 'contoh.com',
    generatedAt: '2026-10-24T00:00:00.000Z',
    durationMs: 900,
    probe: { available: true, name: 'node-dns-tls-http', detail: null },
    website: value,
    technology: {},
    behavior: {},
  })
  return report.website as unknown as T
}

function website(value?: unknown): WebsiteIntelligence {
  return parse<WebsiteIntelligence>(value ?? {})
}

function behavior(value?: unknown): BehaviorAnalysis {
  const report = parseSiteAnalysisResponse({
    version: 1,
    target: 'https://contoh.com/',
    hostname: 'contoh.com',
    generatedAt: '2026-10-24T00:00:00.000Z',
    durationMs: 1,
    probe: { available: true, name: 'probe', detail: null },
    website: {},
    technology: {},
    behavior: value ?? {},
  })
  return report.behavior
}

function technology(value: unknown): TechnologyAnalysis {
  const report = parseSiteAnalysisResponse({
    version: 1,
    target: 'https://contoh.com/',
    hostname: 'contoh.com',
    generatedAt: '2026-10-24T00:00:00.000Z',
    durationMs: 1,
    probe: { available: true, name: 'probe', detail: null },
    website: {},
    technology: value ?? {},
    behavior: {},
  })
  return report.technology
}

const UNAVAILABLE_LOOKUP = {
  status: 'unavailable',
  source: 'tanpa akses platform',
  value: null,
  detail: null,
  queriedAt: '1970-01-01T00:00:00.000Z',
}

function fullReport(overrides: Partial<SiteAnalysisResponse> = {}): SiteAnalysisResponse {
  const base = parseSiteAnalysisResponse({
    version: 1,
    target: 'https://contoh.com/masuk',
    hostname: 'contoh.com',
    generatedAt: '2026-10-24T06:30:00.000Z',
    durationMs: 1_240,
    probe: { available: true, name: 'node-dns-tls-http', detail: null },
    website: {
      status: 'complete',
      identity: {
        hostname: 'contoh.com',
        addresses: {
          status: 'success',
          source: 'resolver DNS sistem',
          value: [
            { address: '93.184.216.34', kind: 'ipv4' },
            { address: '2606:2800:220:1:26::101', kind: 'ipv6' },
          ],
          detail: null,
          queriedAt: '2026-10-24T06:29:58.000Z',
        },
        withheldAddresses: 2,
        asn: {
          status: 'success',
          source: 'DNS Cymru',
          value: { asn: '15133', organization: null, country: 'US', prefix: '93.184.216.0/24', registry: 'arin' },
          detail: 'Nama organisasi tidak tersedia dari sumber ini.',
          queriedAt: '2026-10-24T06:29:58.000Z',
        },
        intermediary: {
          state: 'possible',
          signals: [{ label: 'Cloudflare', evidence: 'Rekor CNAME mengarah ke cdn.cloudflare.net.' }],
          note: 'Sinyal perantara belum pasti.',
        },
      },
      dns: [
        { type: 'A', lookup: { status: 'success', source: 'resolver', value: ['93.184.216.34'], detail: null, queriedAt: '2026-10-24T06:29:58.000Z' } },
        { type: 'AAAA', lookup: { ...UNAVAILABLE_LOOKUP, status: 'empty', detail: 'Kueri selesai tanpa record.', value: [] } },
        { type: 'TXT', lookup: { ...UNAVAILABLE_LOOKUP, status: 'failed', detail: 'Server DNS menolak menjawab (SERVFAIL).' } },
      ],
      tls: {
        httpsAvailable: { status: 'success', source: 'probe TLS', value: true, detail: null, queriedAt: '2026-10-24T06:29:59.000Z' },
        certificate: {
          status: 'success',
          source: 'probe TLS',
          value: {
            issuer: "Let's Encrypt (R12)",
            subject: 'contoh.com',
            notBefore: '2026-08-01T00:00:00.000Z',
            notAfter: '2026-10-01T00:00:00.000Z',
            expired: true,
            hostnameVerified: false,
            verification: 'rejected',
            verificationDetail: 'DEPTH_ZERO_SELF_SIGNED_CERT',
            protocol: 'TLSv1.3',
          },
          detail: null,
          queriedAt: '2026-10-24T06:29:59.000Z',
        },
        certificateSource: 'Probe TLS terpisah pada port 443.',
      },
      response: {
        request: { status: 'success', source: 'probe HTTP', value: null, detail: null, queriedAt: '2026-10-24T06:29:59.000Z' },
        status: 200,
        statusText: 'OK',
        finalUrl: 'https://contoh.com/masuk',
        redirectCount: 1,
        elapsedMs: 812,
        contentType: 'text/html; charset=utf-8',
        bytes: 4_096,
        truncated: true,
        headers: [
          { name: 'server', value: 'nginx' },
          { name: 'content-type', value: 'text/html; charset=utf-8' },
        ],
        withheldHeaders: 3,
      },
      notes: ['Alamat yang ditampilkan bisa milik perantara, bukan server asal.'],
    },
    technology: {
      status: 'partial',
      findings: [
        { name: 'nginx', category: 'server', evidence: ['header `server: nginx`'], confidence: 'medium', state: 'detected' },
        { name: 'Tailwind CSS', category: 'css', evidence: ['kelas utilitas di HTML'], confidence: 'low', state: 'possible' },
      ],
      categories: [
        { category: 'cms', state: 'no_signal', detail: 'Tidak ada sinyal pasif untuk CMS.' },
        { category: 'analytics', state: 'unavailable', detail: 'Dokumen analytics tidak dapat dinilai.' },
      ],
      document: { inspected: true, bytesScanned: 262_144, truncated: true, contentType: 'text/html', detail: null },
      notes: ['Deteksi hanya memakai sinyal pasif.'],
    },
    behavior: {
      status: 'complete',
      initialUrl: 'https://contoh.com/',
      redirects: [
        { url: 'https://contoh.com/', status: 301, location: 'https://contoh.com/masuk', outcome: 'followed', detail: null },
        { url: 'https://contoh.com/masuk', status: 200, location: null, outcome: 'final', detail: null },
        { url: 'https://evil.internal/', status: null, location: null, outcome: 'blocked', detail: 'Ditolak karena rentang alamat yang dilarang.' },
      ],
      redirectCount: 2,
      redirectOutcome: 'blocked',
      hosts: [
        { host: 'cdn.EXAMPLE.net', roles: ['observed', 'referenced'], resourceKinds: ['script', 'style'], count: 3 },
        { host: 'stat-examples.com', roles: ['inferred'], resourceKinds: [], count: 1 },
      ],
      resources: { scripts: 4, styles: 2, images: 6, iframes: 0, links: 9, other: 1, collected: 22, capped: true },
      securityHeaders: [
        { name: 'strict-transport-security', present: true, value: 'max-age=31536000' },
        { name: 'content-security-policy', present: false, value: null },
      ],
      cookies: [
        { name: 'cf_clearance', secure: true, httpOnly: false, sameSite: 'lax', hasExpiry: true, valueShown: false },
      ],
      cookiesCollected: true,
      structure: {
        status: 'complete',
        findings: [
          { code: 'ip_literal', label: 'Host ditulis sebagai alamat IP', detail: 'Nama host berupa angka, bukan domain.', strength: 'moderate', evidence: '93.184.216.34' },
          { code: 'delimiter_trick', label: 'Pembatas tidak lazim', detail: 'Jalur memakai garis miring ganda.', strength: 'weak', evidence: null },
        ],
        hostname: 'contoh.com',
        scheme: 'https',
        port: '8080',
        labelCount: 2,
        registrableDomain: 'contoh.com',
        notes: ['Sinyal struktur tidak dipakai sendiri untuk menyimpulkan apa pun.'],
      },
      forms: {
        inspected: true,
        forms: [
          { index: 1, action: 'https://penampung.example/kirim', actionHost: 'penampung.example', actionScheme: 'https', external: true, insecure: true, method: 'post', passwordFields: 1, textFields: 2 },
          { index: 2, action: null, actionHost: 'contoh.com', actionScheme: 'https', external: false, insecure: false, method: null, passwordFields: 0, textFields: 1 },
        ],
        totals: { forms: 2, passwordFields: 1, externalActions: 1, insecureActions: 1 },
        capped: true,
        detail: '2 form teridentifikasi: 1 kolom Sandi, 1 action ke host lain, 1 action tanpa enkripsi.',
      },
      observations: [
        { kind: 'redirect', state: 'observed', detail: '2 lompatan redirect tercatat.' },
        { kind: 'cookie', state: 'inferred', detail: 'Cookie disimpulkan dari teks halaman.' },
      ],
      notes: ['Skrip halaman tidak dijalankan sehingga perilaku dinamis tidak teramati.'],
    },
    category: {
      status: 'complete',
      primaryId: 'gambling',
      primaryLabel: 'Judi online',
      confidence: 'medium',
      riskIndicated: true,
      summary: 'Bukti yang tersedia mengarah ke kategori judi online berdasarkan konten dan struktur yang diperiksa.',
      signals: [
        { categoryId: 'gambling', label: 'istilah perjudian', detail: 'Judul memuat kata slot dan casino online.', source: 'content', strength: 'strong' },
        { categoryId: 'gambling', label: 'pola nama domain perjudian', detail: 'Nama host memuat kata slot.', source: 'domain', strength: 'weak' },
      ],
      alternatives: [{ id: 'entertainment', label: 'Hiburan', confidence: 'low' }],
      evidenceBasis: {
        documentInspected: true,
        titleAvailable: true,
        descriptionAvailable: true,
        visibleTextBytes: 4_200,
        redirectHops: 2,
      },
      notes: ['Kategori adalah indikasi teknis, bukan penetapan pelanggaran hukum.'],
    },
  })
  return { ...base, ...overrides }
}

function areaResult(overrides: Partial<UseSiteAnalysisResult> = {}): UseSiteAnalysisResult {
  return {
    state: 'ready',
    data: null,
    error: null,
    available: true,
    autoRun: false,
    run: vi.fn(async () => {}),
    reset: vi.fn(),
    ...overrides,
  }
}

function renderArea(section: SiteSection, overrides: Partial<UseSiteAnalysisResult> = {}): string {
  return renderToStaticMarkup(
    <SiteAnalysisArea
      section={section}
      analysis={areaResult(overrides)}
      riskLevelLabel="Risiko rendah"
    />,
  )
}

describe('WebsiteIntelligencePanel', () => {
  it('menampilkan lima grup data dengan status dan salinan yang jujur', () => {
    const markup = renderToStaticMarkup(
      <WebsiteIntelligencePanel data={fullReport().website} />,
    )

    expect(markup).toContain('Network Identity')
    expect(markup).toContain('DNS Records')
    expect(markup).toContain('ASN &amp; Jaringan')
    expect(markup).toContain('TLS Certificate')
    expect(markup).toContain('HTTP Response')

    expect(markup).toContain('93.184.216.34')
    expect(markup).toContain('IPv6')
    expect(markup).toContain('AS15133')
    expect(markup).toContain('Selesai')
    expect(markup).toContain('Salin Nama host')

    // Alamat tidak pernah diklaim sebagai server asal.
    expect(markup).toContain('belum tentu server asal')
    expect(markup).toContain('tidak mencoba menembus CDN')
    expect(markup).toContain('2 alamat disembunyikan')
  })

  it('tidak menyebut sertifikat tepercaya walau HTTPS menjawab', () => {
    const markup = renderToStaticMarkup(
      <WebsiteIntelligencePanel data={fullReport().website} />,
    )

    expect(markup).toContain('HTTPS yang merespons bukan bukti sertifikat tepercaya')
    expect(markup).toContain('Verifikasi ditolak')
    expect(markup).toContain('Sudah kedaluwarsa')
    expect(markup).toContain('DEPTH_ZERO_SELF_SIGNED_CERT')
    expect(markup).not.toContain('Sertifikat valid')
  })

  it('membedakan record kosong, gagal, dan belum diambil tanpa mengarang', () => {
    const markup = renderToStaticMarkup(
      <WebsiteIntelligencePanel data={fullReport().website} />,
    )

    expect(markup).toContain('Kueri selesai dan tidak mengembalikan record tipe ini.')
    expect(markup).toContain('Kueri gagal; ketiadaan record bukan bukti aman.')
    expect(markup).toContain('Server DNS menolak menjawab (SERVFAIL).')
    expect(markup).toContain('Tidak ada data')
    expect(markup).toContain('Gagal')
  })

  it('menyembunyikan header dan menandai body yang dipotong', () => {
    const markup = renderToStaticMarkup(
      <WebsiteIntelligencePanel data={fullReport().website} />,
    )

    expect(markup).toContain('3 header tidak ditampilkan')
    expect(markup).toContain('Dipotong batas ukuran')
    expect(markup).toContain('4.0 KiB')
    expect(markup).not.toContain('set-cookie')
  })

  it('melaporkan bagian tidak tersedia tanpa data contoh', () => {
    const markup = renderToStaticMarkup(
      <WebsiteIntelligencePanel data={website(undefined)} />,
    )

    expect(markup).toContain('Tidak tersedia')
    expect(markup).toContain('Alamat IP tidak dapat ditampilkan')
    expect(markup).toContain('Data ASN tidak ditampilkan')
    expect(markup).toContain('Sertifikat tidak dapat diambil')
    expect(markup).toContain('Belum dapat dinilai')
    expect(markup).not.toContain('93.184.216.34')
  })
})

describe('TechnologyPanel', () => {
  it('membedakan terdeteksi, kemungkinan, dan status per kategori', () => {
    const markup = renderToStaticMarkup(<TechnologyPanel data={fullReport().technology} />)

    expect(markup).toContain('nginx')
    expect(markup).toContain('Terdeteksi')
    expect(markup).toContain('Kemungkinan')
    expect(markup).toContain('Keyakinan sedang')
    expect(markup).toContain('Keyakinan rendah')
    expect(markup).toContain('Web server')
    expect(markup).toContain('Tidak ada sinyal')
    expect(markup).toContain('Belum dapat dinilai')
    expect(markup).toContain('Dipotong batas ukuran')
    expect(markup).toContain('Tidak ada skrip target yang dijalankan')
  })

  it('tidak mengarang temuan ketika bukti pasif kosong', () => {
    const markup = renderToStaticMarkup(<TechnologyPanel data={technology(undefined)} />)

    expect(markup).toContain(
      'Tidak ada teknologi yang dapat dipastikan dari bukti pasif',
    )
    expect(markup).toContain('bukan bukti bahwa situs tidak memakai teknologi tertentu')
    expect(markup).toContain('Tidak ada dokumen HTML yang dapat dibaca')
    expect(markup).not.toContain('Terdeteksi')
  })
})

describe('BehaviorPanel', () => {
  it('memisahkan host yang benar-benar dihubungi dari yang hanya disimpulkan', () => {
    const markup = renderToStaticMarkup(<BehaviorPanel data={fullReport().behavior} />)

    expect(markup).toContain('Rantai redirect')
    expect(markup).toContain('Diikuti')
    expect(markup).toContain('Tujuan akhir')
    expect(markup).toContain('Diblokir kebijakan')
    expect(markup).toContain('cdn.EXAMPLE.net')
    expect(markup).toContain('Dihubungi VERIGUARD')
    expect(markup).toContain('Disimpulkan dari teks')
    expect(markup).toContain('tidak berarti pernah dibuka')
    expect(markup).toContain('Skrip halaman tidak dijalankan')
  })

  it('menampilkan metadata cookie tanpa nilai', () => {
    const markup = renderToStaticMarkup(<BehaviorPanel data={fullReport().behavior} />)

    expect(markup).toContain('cf_clearance')
    expect(markup).toContain('Cookie (metadata saja)')
    expect(markup).toContain('tidak pernah diambil atau ditampilkan')
    expect(markup).toContain('tanpa HttpOnly')
    expect(markup).toContain('SameSite: lax')
  })

  it('menandai pengumpulan yang berhenti di batas jumlah', () => {
    const markup = renderToStaticMarkup(<BehaviorPanel data={fullReport().behavior} />)

    expect(markup).toContain('Pengumpulan sumber daya dihentikan pada batas jumlah')
    expect(markup).toContain('Hadir')
    expect(markup).toContain('Tidak terlihat')
    expect(markup).toContain('Disimpulkan')
  })

  it('menampilkan sinyal struktur URL beserta bukti dan kekuatannya', () => {
    const markup = renderToStaticMarkup(<BehaviorPanel data={fullReport().behavior} />)

    expect(markup).toContain('Struktur URL')
    expect(markup).toContain('nama host')
    expect(markup).toContain('Host ditulis sebagai alamat IP')
    expect(markup).toContain('Sinyal sedang')
    expect(markup).toContain('Sinyal lemah')
    expect(markup).toContain('Bukti:')
    expect(markup).toContain('93.184.216.34')
    expect(markup).toContain('port')
    expect(markup).toContain('8080')
    // Panel tidak boleh menghasilkan vonis dari sinyal struktur.
    expect(markup).not.toMatch(/\b(Berbahaya|Aman)\b/)
    expect(markup).toContain('saling berkorelasi')
  })

  it('menampilkan form, kolom sandi, dan tujuan action yang berbeda host', () => {
    const markup = renderToStaticMarkup(<BehaviorPanel data={fullReport().behavior} />)

    expect(markup).toContain('Form &amp; kolom kredensial')
    expect(markup).toContain('Form #1')
    expect(markup).toContain('POST')
    expect(markup).toContain('Host tujuan berbeda')
    expect(markup).toContain('Tujuan tanpa HTTPS')
    expect(markup).toContain('1 kolom sandi')
    expect(markup).toContain('penampung.example')
    expect(markup).toContain('Form #2')
    expect(markup).toContain('GET (bawaan)')
    expect(markup).toContain('tidak dinyatakan (termuat ke halaman ini)')
    expect(markup).toContain('Pendaftaran form dihentikan pada batas jumlah')
    expect(markup).toContain('Nilai isian form tidak pernah dibaca')
  })

  it('jujur saat rantai dan sumber daya tidak tersedia', () => {
    const markup = renderToStaticMarkup(<BehaviorPanel data={behavior(undefined)} />)

    expect(markup).toContain('Rantai redirect belum tersedia')
    expect(markup).toContain('belum dapat dinilai')
    expect(markup).toContain('Dokumen HTML tidak tersedia')
    expect(markup).toContain('Ketiadaan daftar ini bukan bukti')
    expect(markup).toContain('Respons tidak terbaca, jadi metadata cookie tidak tersedia')
    expect(markup).toContain('Belum ada perilaku yang dapat diamati')
    expect(markup).toContain('Struktur URL belum dapat dinilai pada pemeriksaan ini')
    expect(markup).toContain('Dokumen HTML tidak terbaca, jadi form dan kolom kredensial tidak dapat diperiksa')
  })

  it('menyatakan ketiadaan sinyal struktur bukan bukti halaman aman', () => {
    const markup = renderToStaticMarkup(
      <BehaviorPanel
        data={
          behavior({
            status: 'complete',
            initialUrl: 'https://contoh.com/',
            structure: {
              status: 'complete',
              findings: [],
              hostname: 'contoh.com',
              scheme: 'https',
              port: null,
              labelCount: 2,
              registrableDomain: 'contoh.com',
              notes: [],
            },
            forms: {
              inspected: true,
              forms: [],
              totals: { forms: 0, passwordFields: 0, externalActions: 0, insecureActions: 0 },
              capped: false,
              detail: 'Tidak ada tag <form> yang teridentifikasi pada dokumen yang dibaca.',
            },
          })
        }
      />,
    )

    expect(markup).toContain('Tidak ada pola struktur yang menonjol pada URL ini')
    expect(markup).toContain('bukan bukti bahwa URL aman')
    expect(markup).toContain('Tidak ada form yang terbaca pada HTML yang diperiksa')
  })
})

describe('WebsiteCategoryPanel', () => {
  it('menampilkan kategori, bukti, dan tingkat keyakinan tanpa mencampur tingkat risiko', () => {
    const markup = renderToStaticMarkup(
      <WebsiteCategoryPanel data={fullReport().category} riskLevelLabel="Risiko rendah" />,
    )

    expect(markup).toContain('Kategori Website')
    expect(markup).toContain('Judi online')
    expect(markup).toContain('Tingkat keyakinan: Sedang')
    expect(markup).toContain('isi halaman')
    expect(markup).toContain('nama domain')
    expect(markup).toContain('Hiburan')
    expect(markup).toContain('Tingkat risiko saat ini: Risiko rendah')
    expect(markup).toContain('bukan penetapan pelanggaran hukum')
    expect(markup).not.toMatch(/pasti/i)
  })

  it('menyatakan belum cukup data alih-alih mengarang kategori', () => {
    const markup = renderToStaticMarkup(
      <WebsiteCategoryPanel
        data={{
          ...fullReport().category,
          status: 'partial',
          primaryId: 'unknown',
          primaryLabel: 'Tidak diketahui',
          confidence: 'low',
          riskIndicated: false,
          summary: 'Data yang tersedia belum cukup untuk menentukan kategori website.',
          signals: [],
          alternatives: [],
        }}
        riskLevelLabel="Risiko rendah"
      />,
    )

    expect(markup).toContain('Tidak diketahui')
    expect(markup).toContain('Tingkat keyakinan: Rendah')
    expect(markup).toContain('Belum ada bukti yang cukup')
    expect(markup).not.toContain('Masuk kategori yang perlu diperiksa lebih lanjut')
  })

  it('tidak menyebut istilah internal layanan kepada pengguna', () => {
    const markup = renderToStaticMarkup(
      <WebsiteCategoryPanel data={fullReport().category} riskLevelLabel="Risiko rendah" />,
    )

    expect(markup).not.toMatch(/Firestore|Firebase|Cloudflare|Worker|API key/i)
  })
})

describe('SiteAnalysisArea', () => {
  it('menyatakan backend tanpa kemampuan membaca situs dan tidak menampilkan data contoh', () => {
    const markup = renderArea('website', { available: false, state: 'idle', data: null })
    expect(markup).toContain('Versi ini tidak terhubung ke layanan pemeriksaan')
    expect(markup).toContain('tidak menampilkan data contoh maupun data karangan')
    expect(markup).not.toContain('Jalankan analisis situs')
  })

  it('menampilkan skeleton saat analisis berjalan', () => {
    const markup = renderArea('technology', { state: 'running' })
    expect(markup).toContain('aria-busy="true"')
    expect(markup).toContain('Memuat Analisis Teknologi')
    expect(markup).toContain('sedang berjalan')
    expect(markup).toContain(
      `tidak mengubah hasil ${EXTERNAL_PROVIDER_IDS.length} agen maupun Reputasi Ancaman`,
    )
  })

  it('meminta tombol sebelum target pertama kali dibuka', () => {
    const markup = renderArea('behavior', { state: 'idle', data: null })
    expect(markup).toContain('Jalankan analisis situs')
    expect(markup).toContain('Menekan tombol adalah persetujuan')
    expect(markup).toContain('Hanya periksa URL yang berwenang kamu periksa')
    expect(markup).toContain('alamat internal/loopback/metadata diblokir')
  })

  it('menampilkan skeleton alih-alih tombol saat analisis berjalan otomatis', () => {
    const markup = renderArea('website', { state: 'idle', data: null, autoRun: true })

    expect(markup).toContain('aria-busy="true"')
    expect(markup).not.toContain('Jalankan analisis situs')
  })

  it('tetap menawarkan tombol saat auto-run gagal', () => {
    const markup = renderArea('website', {
      state: 'idle',
      data: null,
      autoRun: true,
      error: 'Permintaan analisis situs tidak sampai ke layanan pemeriksaan.',
    })

    expect(markup).toContain('Permintaan analisis situs tidak sampai ke layanan pemeriksaan.')
  })

  it('memisahkan kegagalan analisis dari hasil agen eksternal', () => {
    const markup = renderArea('website', {
      state: 'failed',
      data: null,
      error: 'URL ditolak oleh kebijakan keamanan layanan pemeriksaan.',
    })
    expect(markup).toContain('Analisis situs tidak selesai')
    expect(markup).toContain('URL ditolak oleh kebijakan keamanan layanan pemeriksaan.')
    expect(markup).toContain('tetap seperti sebelumnya')
    expect(markup).toContain('Coba lagi')
  })

  it('menyajikan panel sesuai menu yang dipilih tanpa menjalankan ulang', () => {
    const data = fullReport()
    const websiteMarkup = renderArea('website', { data })
    const behaviorMarkup = renderArea('behavior', { data })

    expect(websiteMarkup).toContain('Website Intelligence')
    expect(websiteMarkup).toContain('Target: https://contoh.com/masuk')
    expect(websiteMarkup).toContain('layanan pemeriksaan siap')
    expect(websiteMarkup).not.toContain('node-dns-tls-http')
    expect(websiteMarkup).toContain('Jalankan ulang')
    expect(websiteMarkup).not.toContain('Rantai redirect')

    expect(behaviorMarkup).toContain('Analisis Perilaku')
    expect(behaviorMarkup).toContain('Rantai redirect')
    expect(behaviorMarkup).not.toContain('Network Identity')

    const categoryMarkup = renderArea('category', { data })
    expect(categoryMarkup).toContain('Kategori Website')
    expect(categoryMarkup).toContain('Judi online')
    expect(categoryMarkup).toContain('Tingkat keyakinan: Sedang')
    expect(categoryMarkup).toContain('Tingkat risiko saat ini: Risiko rendah')
    expect(categoryMarkup).not.toContain('Rantai redirect')
  })

  it('mengingatkan bila laporan datang dari backend tanpa probe', () => {
    const data = fullReport({
      probe: { available: false, name: 'tanpa akses platform', detail: 'Platform tidak menyediakan akses DNS/TLS/HTTP.' },
    })
    const markup = renderArea('website', { data })

    expect(markup).toContain('layanan pemeriksaan tidak tersedia')
    expect(markup).toContain('Layanan pemeriksaan tidak dapat membaca situs')
    expect(markup).toContain('Platform tidak menyediakan akses DNS/TLS/HTTP.')
  })
})

function fusion(overrides: Partial<RiskFusion> = {}): RiskFusion {
  return {
    status: 'limited',
    level: 'low',
    riskScore: 9,
    confidence: 'low',
    confidenceDetail:
      '1 bukti risiko dari 1 kategori berbeda, cakupan pemeriksaan 3/17. Keyakinan rendah: bukti yang tersedia sedikit.',
    coverage: {
      totalChecks: 17,
      succeeded: 3,
      unavailable: 12,
      failed: 2,
      ratio: 0.18,
      byCategory: [{ category: 'registration', succeeded: 1, total: 1 }],
    },
    evidence: [
      {
        id: 'registration:domain_young',
        category: 'registration',
        label: 'Domain baru berusia 0 hari',
        detail: 'Domain didaftarkan 0 hari sebelum pemeriksaan ini.',
        observed: '2026-10-29T11:04:08.000Z',
        source: 'registry RDAP rdap.verisign.com',
        strength: 'moderate',
        availability: 'observed',
        observedAt: '2026-10-30T07:23:38.519Z',
      },
    ],
    notEvaluated: ['Sertifikat TLS tidak terbaca dari runtime ini.'],
    notes: ['Skor risiko bukan probabilitas dan bukan vonis.'],
    ...overrides,
  }
}

describe('RiskFusionSummary — nilai internal di blok Internal Reputasi Ancaman', () => {
  // VGL-18: kartu ini tidak lagi dipasang di setiap menu analisis situs; ResultPage
  // merendernya di dalam blok Internal. Assertion dipertahankan utuh, hanya titik
  // mounted-nya yang mengikuti perpindahan.
  const renderFusion = (risk: Parameters<typeof RiskFusionSummary>[0]['risk']) =>
    renderToStaticMarkup(<RiskFusionSummary risk={risk} />)

  it('menampilkan skor, level, status, keyakinan, cakupan, bukti, dan yang tidak dinilai', () => {
    const markup = renderFusion(fusion())

    expect(markup).toContain('Skor Analisis Situs')
    expect(markup).toContain('Skor fusi')
    expect(markup).toContain('9')
    expect(markup).toContain('/100')
    expect(markup).toContain('Tingkat risiko: Rendah')
    expect(markup).toContain('Cakupan terbatas')
    expect(markup).toContain('Keyakinan rendah')
    expect(markup).toContain('3/17 pemeriksaan selesai')
    expect(markup).toContain('(18%)')
    expect(markup).toContain('Domain baru berusia 0 hari')
    expect(markup).toContain('bukti sedang')
    expect(markup).toContain('registry RDAP rdap.verisign.com')
    expect(markup).toContain('sumbu registration')
    expect(markup).toContain('Pemeriksaan yang tidak dinilai')
    expect(markup).toContain('Sertifikat TLS tidak terbaca dari runtime ini.')
    // Sumber angka dinyatakan terpisah agar tidak tertukar dengan skor heuristik.
    expect(markup).toContain(
      `terpisah dari skor heuristik leksikal maupun vonis ${EXTERNAL_PROVIDER_IDS.length} agen`,
    )
  })

  it('tidak pernah menampilkan cakupan terbatas sebagai konfirmasi aman', () => {
    const markup = renderFusion(fusion())

    expect(markup).toContain('Cakupan belum lengkap')
    expect(markup).toContain('bukan konfirmasi bahwa target aman')
    expect(markup).toContain('1 pemeriksaan tidak dinilai')
  })

  it('memperlakukan laporan tanpa fusi sebagai belum dinilai tanpa mengarang skor', () => {
    const markup = renderFusion(null)

    expect(markup).toContain('Skor Analisis Situs')
    expect(markup).toContain('Belum dinilai')
    expect(markup).not.toContain('Skor fusi')
    expect(markup).not.toContain('/100')
    expect(markup).toContain('tidak ada skor yang dikarang atau dianggap nol')
  })

  it('menampilkan tanda hubung dan level tidak dikenal saat skor null', () => {
    const markup = renderFusion(fusion({ riskScore: null, level: 'unknown' }))

    expect(markup).toContain('—')
    expect(markup).not.toContain('/100')
    expect(markup).toContain('Tingkat risiko: Tidak dapat ditentukan')
    // Bilah progres hanya dibuat bila ada angka, bukan dari nol karangan.
    expect(markup).not.toContain('Skor fusi analisis situs dari 100')
  })

  it('menyatakan cakupan yang tidak dikenal apa adanya', () => {
    const markup = renderFusion(
      fusion({
        coverage: {
          totalChecks: 0,
          succeeded: 0,
          unavailable: 0,
          failed: 0,
          ratio: null,
          byCategory: [],
        },
      }),
    )

    expect(markup).toContain('cakupan tidak dinyatakan')
    expect(markup).not.toContain('0/17')
  })

  it('membedakan tidak ada bukti dari bukti yang menegangkan', () => {
    const markup = renderFusion(fusion({ evidence: [], status: 'complete', level: 'low' }))

    expect(markup).toContain('Tidak ada bukti risiko yang dikumpulkan')
    expect(markup).toContain('bukan konfirmasi bahwa target aman')
    // Pemeriksaan lengkap tanpa catatan yang tidak dinilai tidak menampilkan peringatan cakupan.
    expect(markup).not.toContain('Cakupan belum lengkap')
  })

  it('tidak lagi ditampilkan SiteAnalysisArea supaya nilainya tidak dobel', () => {
    // Menu analisis situs hanya menampilkan panel bagiannya; angka internal ada di Reputasi Ancaman.
    for (const section of ['website', 'category', 'technology', 'behavior'] as const) {
      const markup = renderArea(section, { data: fullReport({ risk: fusion() }) })

      expect(markup).not.toContain('Skor Analisis Situs')
      expect(markup).not.toContain('Skor fusi')
    }

    expect(renderArea('website', { data: fullReport() })).toContain('Website Intelligence')
  })
})

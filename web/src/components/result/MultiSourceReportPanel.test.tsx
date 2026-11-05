import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import {
  EXTERNAL_PROVIDER_IDS,
  type ExternalProviderId,
  type MultiSourceReport,
  type ProviderId,
  type ProviderResult,
} from '../../lib/scanners/types'
import { MultiSourceReportPanel } from './MultiSourceReportPanel'

function provider(
  id: ProviderId,
  overrides: Partial<ProviderResult> = {},
): ProviderResult {
  return {
    id,
    label: id,
    status: 'success',
    verdict: 'clean',
    score: 0,
    summary: 'Tidak ditemukan indikasi.',
    signals: [],
    reason: null,
    durationMs: 100,
    ...overrides,
  }
}

const report: MultiSourceReport = {
  version: 1,
  target: 'https://contoh.com/path',
  hostname: 'contoh.com',
  verdict: 'suspicious',
  score: 45,
  completeness: {
    checked: 2,
    total: 8,
    percent: 25,
    success: 1,
    notFound: 1,
    notConfigured: 3,
    authFailed: 1,
    unavailable: 0,
    rateLimited: 1,
    error: 1,
  },
  providers: [
    provider('internal', {
      label: 'Analisis internal',
      verdict: 'inconclusive',
      summary: 'Aturan internal belum cukup untuk menyimpulkan.',
    }),
    provider('virustotal', {
      label: 'VirusTotal',
      summary: '0/93 engine mendeteksi berbahaya.',
    }),
    provider('threatfox', {
      label: 'ThreatFox',
      status: 'not_found',
      verdict: 'inconclusive',
      score: null,
      summary: 'ThreatFox tidak menemukan IOC untuk URL ini.',
    }),
    provider('openphish', {
      label: 'OpenPhish',
      status: 'not_configured',
      verdict: 'inconclusive',
      score: null,
      summary: 'Provider belum dikonfigurasi di backend.',
      reason: 'API key belum diisi.',
    }),
    provider('urlscan', {
      label: 'URLScan.io',
      status: 'auth_failed',
      verdict: 'inconclusive',
      score: null,
      summary: 'Autentikasi ke provider gagal.',
      reason: 'Kredensial provider ditolak.',
    }),
    provider('radar', {
      label: 'Cloudflare Radar URL Scanner',
      status: 'rate_limited',
      verdict: 'inconclusive',
      score: null,
      summary: 'Kuota provider tercapai.',
      reason: 'Kuota permintaan provider tercapai.',
    }),
    provider('otx', {
      label: 'AlienVault OTX',
      status: 'error',
      verdict: 'inconclusive',
      score: null,
      summary: 'Pemeriksaan provider gagal.',
      reason: 'Provider menolak permintaan.',
    }),
    provider('hybrid', {
      label: 'Hybrid Analysis',
      status: 'not_configured',
      verdict: 'inconclusive',
      score: null,
      summary: 'Provider belum dikonfigurasi di backend.',
      reason: 'Hybrid Analysis belum dapat dipakai; endpoint URL resmi belum terbukti.',
    }),
    provider('safebrowsing', {
      label: 'Google Safe Browsing',
      status: 'not_configured',
      verdict: 'inconclusive',
      score: null,
      summary: 'GOOGLE_SAFE_BROWSING_API_KEY belum dikonfigurasi di backend.',
      reason: 'API key belum diisi.',
    }),
  ],
  conflicts: [],
  notes: ['Skor gabungan adalah indikator bukti, bukan probabilitas.'],
  externalRequested: true,
  externalShared: true,
  sensitiveUrl: false,
  privacyReasons: [],
  generatedAt: '2026-01-01T00:00:00.000Z',
  durationMs: 1_000,
}

describe('panel laporan multi-sumber', () => {
  it('menampilkan alert "belum ada agen" saat kedelapan agen not_configured', () => {
    // Regresi: dulu alert ini terkunci pada notConfigured === 6, sehingga tidak muncul
    // lagi begitu roster bertambah menjadi 8 agen. Sekarang mengikuti total roster.
    const allUnconfigured: MultiSourceReport = {
      ...report,
      verdict: 'inconclusive',
      score: 0,
      externalShared: false,
      completeness: {
        checked: 0,
        total: 8,
        percent: 0,
        success: 0,
        notFound: 0,
        notConfigured: 8,
        authFailed: 0,
        unavailable: 0,
        rateLimited: 0,
        error: 0,
      },
      providers: report.providers.map((item) =>
        item.id === 'internal'
          ? item
          : {
              ...item,
              status: 'not_configured',
              verdict: 'inconclusive',
              score: null,
              summary: 'Provider belum dikonfigurasi di backend.',
              reason: 'API key belum diisi.',
            },
      ),
      notes: ['Skor gabungan adalah indikator bukti, bukan probabilitas.'],
    }
    const html = renderToStaticMarkup(
      <MultiSourceReportPanel report={allUnconfigured} />,
    )

    expect(html).toContain('Belum ada agen yang dikonfigurasi')
  })

  it('menampilkan hasil dan kategori risiko per agen', () => {
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={report} />)

    expect(html).toContain('Perlu Perhatian')
    expect(html).toContain('Bukti penilaian')
    expect(html).toContain('>Selesai — </span>')
    expect(html).toContain('0/93 mesin keamanan mendeteksi berbahaya.')
    expect(html).toContain('Risiko: Tidak ditemukan indikasi')
    // Regresi aturan global: no-match = eksekusi Selesai, temuan = "Tidak ada kecocokan data".
    // Badge status TIDAK lagi menampilkan "Tidak ada kecocokan"; label itu hidup di sisi
    // temuan di bawah, supaya kegagalan provider dan ketiadaan data tidak tertukar.
    expect(html).not.toContain('>Tidak ada kecocokan — </span>')
    expect(html).toContain('Agen 4 tidak menemukan IOC untuk URL ini.')
    expect(html).toContain('Risiko: Tidak ada kecocokan data')
    expect(html).toContain('Belum dikonfigurasi')
    expect(html).toContain('Gagal autentikasi')
    expect(html).toContain('Risiko: Tidak dapat dinilai')
  })

  it('menampilkan no-match sebagai eksekusi Selesai dengan temuan "Tidak ada kecocokan data"', () => {
    // Aturan global (Agents 1..8 + future): provider yang selesai memeriksa tetapi tidak
    // memiliki data harus tampil sebagai Selesai dengan temuan "Tidak ada kecocokan data",
    // BUKAN Gagal dan BUKAN Aman.
    const noMatchReport: MultiSourceReport = {
      ...report,
      verdict: 'inconclusive',
      score: 0,
      providers: [
        provider('internal', { label: 'Analisis internal', verdict: 'inconclusive' }),
        ...EXTERNAL_PROVIDER_IDS.map((id) =>
          provider(id, {
            status: 'not_found',
            verdict: 'inconclusive',
            score: null,
            summary: `${id} tidak memiliki data.`,
            signals: [
              {
                label: 'Cakupan penelusuran',
                detail: 'Indikator URL dan domain diperiksa; keduanya tanpa laporan.',
                severity: 'info',
              },
            ],
            reason: 'Ketiadaan data bukan konfirmasi aman.',
          }),
        ),
      ],
      completeness: {
        checked: 8,
        total: 8,
        percent: 100,
        success: 0,
        notFound: 8,
        notConfigured: 0,
        authFailed: 0,
        unavailable: 0,
        rateLimited: 0,
        skipped: 0,
        timeout: 0,
        error: 0,
      },
      conflicts: [],
    }
    const html = renderToStaticMarkup(
      <MultiSourceReportPanel report={noMatchReport} />,
    )

    // Status badge menampilkan "Selesai" untuk setiap agen yang no-match.
    expect(html).toContain('>Selesai — </span>')
    // Temuan menampilkan "Tidak ada kecocokan data", bukan "Tidak dapat dinilai" atau Aman.
    expect(html).toContain('Risiko: Tidak ada kecocokan data')
    // Detail cakupan tetap tampil, tidak diganti label generik.
    expect(html).toContain('Cakupan penelusuran')
    expect(html).toContain('Ketiadaan data bukan konfirmasi aman.')
    // No-match tidak boleh naik menjadi "Aman" atau "Indikasi Risiko Rendah".
    expect(html).not.toContain('Indikasi Risiko Rendah')
    expect(html).not.toContain('Risiko: Aman')
    expect(html).not.toContain('Risiko: Tidak ditemukan indikasi')
    // Tidak dianggap Gagal.
    expect(html).not.toContain('>Gagal — </span>')
  })

  it('memisahkan tampilan bukti yang menilai dari intelijen komunitas tanpa skor', () => {
    // VGL-30K-R4: Agen 6/7 mengembalikan Kategori B (penyebutan komunitas / laporan URL lain pada
    // host ini) sebagai success + inconclusive + tanpa skor dengan sinyal `info`. Antarmuka harus
    // menyebut kelompok itu apa adanya, dan tetap menampilkan bukti berbobot secara terpisah.
    // Invarian yang diuji: DI DALAM satu kartu agen, bukti yang menilai alamat ini tampil di atas
    // intelijen komunitas. Kalau kedua kelompok itu dipecah ke kartu berbeda, urutan antar-kartu
    // ikut menentukan dan klaimnya tidak lagi berarti apa-apa — jadi fixture ini menaruh keduanya
    // pada Agen 6, persis bentuk payload Kategori A + B dari backend.
    const communityReport: MultiSourceReport = {
      ...report,
      verdict: 'inconclusive',
      score: 0,
      providers: [
        provider('otx', {
          label: 'AlienVault OTX',
          verdict: 'suspicious',
          score: 55,
          summary:
            'Domain ini dikaitkan dengan keluarga AsyncRAT; 55 laporan komunitas menyebutnya tanpa kecocokan URL.',
          reason: 'Bukti berasal dari indikator domain, bukan URL persis yang diperiksa.',
          signals: [
            {
              label: 'Indikator terverifikasi',
              detail: 'Kecocokan indikator pada domain contoh.com, keluarga AsyncRAT.',
              severity: 'warning',
            },
            {
              label: 'Laporan komunitas',
              detail: '55 laporan komunitas menyebut domain contoh.com.',
              severity: 'info',
            },
            { label: 'Tag laporan', detail: 'phishing, botnet', severity: 'info' },
          ],
        }),
        provider('hybrid', {
          label: 'Hybrid Analysis',
          verdict: 'inconclusive',
          score: null,
          summary: 'Hybrid Analysis tidak memiliki bukti untuk URL persis ini.',
          signals: [
            {
              label: 'Laporan pada host lain',
              detail: '2 laporan ikut terkembalikan menunjuk host di luar contoh.com.',
              severity: 'info',
            },
          ],
        }),
      ],
    }

    const html = renderToStaticMarkup(<MultiSourceReportPanel report={communityReport} />)

    expect(html).toContain('Intelijen komunitas — tanpa kontribusi skor')
    expect(html).toContain('Bukti yang menilai alamat ini')
    // Sinyal komunitas tidak kehilangan datanya, hanya diberi konteks yang benar.
    expect(html).toContain('55 laporan komunitas')
    expect(html).toContain('2 laporan ikut terkembalikan')
    // Bukti berbobot pada kartu Agen 6 tidak tersingkir ke bawah hitungan komunitas, dan kartu
    // tanpa bukti berbobot hanya menampilkan kelompok komunitas.
    expect(html.match(/Bukti yang menilai alamat ini/g)).toHaveLength(1)
    expect(html.match(/Intelijen komunitas — tanpa kontribusi skor/g)).toHaveLength(2)
    expect(html.indexOf('Bukti yang menilai alamat ini')).toBeLessThan(
      html.indexOf('Intelijen komunitas'),
    )
  })

  it('mempertahankan kegagalan provider sebagai non-Selesai', () => {
    // Regresi: GAGAL (transport/timeout/auth/error) TIDAK boleh ikut tampil sebagai
    // "Selesai" walau label temuan mirip. Ini pasangan dari aturan no-match.
    const failureReport: MultiSourceReport = {
      ...report,
      providers: [
        provider('internal', { label: 'Analisis internal', verdict: 'inconclusive' }),
        provider('urlscan', {
          label: 'URLScan.io',
          status: 'error',
          verdict: 'inconclusive',
          score: null,
          summary: 'Pemeriksaan provider gagal.',
          reason: 'Respons provider tidak dapat dibaca.',
        }),
        provider('virustotal', {
          label: 'VirusTotal',
          status: 'timeout',
          verdict: 'inconclusive',
          score: null,
          summary: 'Provider melewati batas waktu.',
        }),
        provider('openphish', { label: 'OpenPhish', status: 'not_found', score: null }),
        provider('threatfox', { label: 'ThreatFox', status: 'not_found', score: null }),
        provider('radar', { label: 'Cloudflare Radar URL Scanner', status: 'not_found', score: null }),
        provider('otx', { label: 'AlienVault OTX', status: 'not_found', score: null }),
        provider('hybrid', { label: 'Hybrid Analysis', status: 'not_found', score: null }),
        provider('safebrowsing', { label: 'Google Safe Browsing', status: 'not_found', score: null }),
      ],
      completeness: {
        ...report.completeness,
        checked: 6,
        notFound: 6,
        error: 1,
        timeout: 1,
      },
    }
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={failureReport} />)
    // Status error & timeout tetap tampil sebagai Gagal/Melebihi batas waktu, bukan Selesai.
    expect(html).toContain('>Gagal — </span>')
    expect(html).toContain('>Melebihi batas waktu — </span>')
    // Risiko untuk keduanya: "Tidak dapat dinilai", bukan "Tidak ada kecocokan data".
    // (label "Tidak ada kecocokan data" hanya muncul untuk provider no-match.)
    expect(html).toContain('Risiko: Tidak dapat dinilai')
    expect(html).toContain('Risiko: Tidak ada kecocokan data')
  })

  it('Agent 8 no-match tampil sebagai kecocokan kosong, bukan kegagalan', () => {
    const withAgent8 = (overrides: Partial<ProviderResult>) => ({
      ...report,
      providers: report.providers.map((entry) =>
        entry.id === 'safebrowsing'
          ? provider('safebrowsing', { label: 'Google Safe Browsing', ...overrides })
          : entry,
      ),
    })

    const baseline = renderToStaticMarkup(<MultiSourceReportPanel report={report} />)
    const noMatch = renderToStaticMarkup(
      <MultiSourceReportPanel
        report={withAgent8({
          status: 'not_found',
          verdict: 'inconclusive',
          score: null,
          summary: 'Google Safe Browsing tidak memiliki entri ancaman untuk URL ini.',
          reason:
            'Ketiadaan match hanya berarti URL belum tercatat pada list yang ditanyakan; BUKAN konfirmasi bahwa URL ini aman.',
        })}
      />,
    )

    // Tidak ada badge "Gagal" baru hanya karena provider tidak punya data.
    const failureBadges = (markup: string) => (markup.match(/Gagal/g) ?? []).length
    expect(failureBadges(noMatch)).toBe(failureBadges(baseline))
    expect(noMatch).toContain('Risiko: Tidak ada kecocokan data')
    expect(noMatch).not.toContain('Safe Browsing')

    // Galat reading tetap tampil dengan SATU sufiks HTTP, bukan dua.
    const failed = renderToStaticMarkup(
      <MultiSourceReportPanel
        report={withAgent8({
          status: 'error',
          verdict: 'inconclusive',
          score: null,
          summary: 'Pemeriksaan provider gagal.',
          reason: 'Respons provider tidak dapat dibaca. (HTTP 200)',
        })}
      />,
    )
    expect(failed).toContain('tidak dapat dibaca')
    expect((failed.match(/\(HTTP 200\)/g) ?? []).length).toBe(1)
    expect(failed).not.toContain('(HTTP 200) (HTTP 200)')
  })

  it('memakai label Agen 1-8 dan menyembunyikan nama penyedia', () => {
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={report} />)

    expect(html).toContain('Agen 1')
    expect(html).toContain('Agen 2')
    expect(html).toContain('Agen 3')
    expect(html).toContain('Agen 4')
    expect(html).toContain('Agen 5')
    expect(html).toContain('Agen 6')
    expect(html).toContain('Agen 7')
    expect(html).toContain('Agen 8')
    for (const name of [
      'VirusTotal',
      'URLScan',
      'urlscan.io',
      'OpenPhish',
      'ThreatFox',
      'abuse.ch',
      'Cloudflare',
      'AlienVault',
      'OTX',
      'Hybrid Analysis',
      'Google Safe Browsing',
      'Safe Browsing',
    ]) {
      expect(html).not.toContain(name)
    }
    // VGL-30K-R1: roster "Rincian agen" hanya agen eksternal. Baris internal yang masih ada di
    // riwayat lama dibuang saat render, jadi label penyamarannya tidak muncul lagi.
    expect(html).not.toContain('Analisis internal')
  })

  it('mengganti pesan perbedaan pendapat dengan bukti per agen', () => {
    const disagreeReport: MultiSourceReport = {
      ...report,
      providers: [
        provider('internal', { label: 'Analisis internal', verdict: 'inconclusive' }),
        provider('virustotal', {
          label: 'VirusTotal',
          verdict: 'malicious',
          score: 100,
          summary: '4/93 security engine mendeteksi berbahaya; 1 mencurigakan.',
        }),
        provider('urlscan', { label: 'URLScan.io' }),
        provider('openphish', { label: 'OpenPhish' }),
        provider('threatfox', { label: 'ThreatFox', status: 'not_found', score: null }),
        provider('radar', { label: 'Cloudflare Radar URL Scanner' }),
        provider('otx', { label: 'AlienVault OTX', verdict: 'suspicious', score: 45 }),
        provider('hybrid', {
          label: 'Hybrid Analysis',
          status: 'not_configured',
          verdict: 'inconclusive',
          score: null,
        }),
        provider('safebrowsing', { label: 'Google Safe Browsing' }),
      ],
      completeness: {
        ...report.completeness,
        checked: 7,
        percent: 88,
        success: 6,
        notFound: 1,
        notConfigured: 1,
        authFailed: 0,
        rateLimited: 0,
        error: 0,
      },
      conflicts: [
        'VirusTotal menandai risiko, sedangkan URLScan.io tidak menemukan indikasi.',
        'AlienVault OTX menandai risiko, sedangkan URLScan.io tidak menemukan indikasi.',
      ],
    }
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={disagreeReport} />)

    expect(html).not.toContain('Sumber tidak sepenuhnya sepakat')
    expect(html).not.toContain('sedangkan')
    expect(html).not.toContain('menandai risiko')
    expect(html).toContain('Bukti penilaian')
    expect(html).toContain('Agen 2 menandai indikasi berbahaya pada URL ini.')
    expect(html).toContain('Agen 6 menemukan indikasi yang perlu diperiksa lebih lanjut.')
    expect(html).not.toContain('Agen 1, Agen 3')
  })

  it('menampilkan pesan netral ketika tidak ada bukti yang relevan', () => {
    const emptyEvidenceReport: MultiSourceReport = {
      ...report,
      verdict: 'inconclusive',
      score: 0,
      providers: [
        provider('internal', { label: 'Analisis internal', verdict: 'inconclusive' }),
        ...EXTERNAL_PROVIDER_IDS.map((id) =>
          provider(id, { status: 'not_found', verdict: 'inconclusive', score: null }),
        ),
      ],
      completeness: {
        checked: 8,
        total: 8,
        percent: 100,
        success: 0,
        notFound: 8,
        notConfigured: 0,
        authFailed: 0,
        unavailable: 0,
        rateLimited: 0,
        skipped: 0,
        timeout: 0,
        error: 0,
      },
      conflicts: [],
    }
    const html = renderToStaticMarkup(
      <MultiSourceReportPanel report={emptyEvidenceReport} />,
    )

    expect(html).toContain('Bukti penilaian')
    // VGL-32A: no_match tetap hasil pemeriksaan yang sah — tampil sebagai "Tidak ada
    // kecocokan data", bukan kegagalan, tetapi juga bukan bukti bersih.
    expect(html).toContain('agen selesai diperiksa dengan hasil')
    expect(html).toContain('Tidak ada kecocokan data')
    expect(html).not.toContain('tidak menemukan indikasi ancaman')
  })

  it('mempertahankan statistik deteksi agen apa adanya', () => {
    const statsReport: MultiSourceReport = {
      ...report,
      providers: report.providers.map((item): ProviderResult =>
        item.id === 'virustotal'
          ? provider('virustotal', {
              label: 'VirusTotal',
              verdict: 'malicious',
              score: 100,
              summary: '3/93 engine mendeteksi berbahaya; 4 mencurigakan.',
              signals: [
                {
                  label: 'Detection ratio VirusTotal',
                  detail: '3/93 security engine menandai URL ini berbahaya (3.23%).',
                  severity: 'info',
                },
                {
                  label: 'Engine menandai berbahaya',
                  detail: '3 dari 93 engine menandai URL ini berbahaya.',
                  severity: 'danger',
                },
                {
                  label: 'Engine menandai mencurigakan',
                  detail: '4 dari 93 engine menandai URL ini mencurigakan.',
                  severity: 'warning',
                },
              ],
            })
          : item,
      ),
    }
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={statsReport} />)

    expect(html).toContain('3/93 mesin keamanan menandai URL ini berbahaya (3.23%).')
    expect(html).toContain('3 dari 93 mesin keamanan menandai URL ini berbahaya.')
    expect(html).toContain('4 dari 93 mesin keamanan menandai URL ini mencurigakan.')
    expect(html).toContain('Rasio deteksi')
    expect(html).toContain('3/93 mesin keamanan mendeteksi berbahaya; 4 mencurigakan.')
  })

  it('menjelaskan bukti dan kelengkapan tanpa menyebut probabilitas', () => {
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={report} />)

    expect(html).toContain('Bukti penilaian')
    // VGL-32A: baris clean tanpa penanda bukti negatif (seperti VirusTotal pada fixture
    // laporan v1 ini) tidak lagi ditampilkan sebagai bukti penilaian; hanya no_match yang
    // tampil, lengkap dengan penjelasan bahwa itu bukan kegagalan.
    expect(html).not.toContain('selesai diperiksa dan tidak menemukan indikasi ancaman')
    expect(html).toContain('agen selesai diperiksa dengan hasil')
    expect(html).toContain(
      '6 dari 8 agen tidak memberikan hasil; kondisi itu bukan bukti URL aman.',
    )
    expect(html).toContain('bukan probabilitas')
    expect(html).not.toContain('probabilitas situs berbahaya')
  })

  it('menghitung status independen tanpa skor bukti per provider', () => {
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={report} />)

    expect(html).toContain('1 selesai | 1 tanpa kecocokan | 3 belum dikonfigurasi')
    expect(html).toContain('1 gagal autentikasi | 1 dibatasi | 0 batas waktu habis')
    expect(html).toContain('0 tidak dijalankan | 1 gagal/tidak tersedia')
    expect(html).not.toContain('Skor bukti')
    expect(html).not.toContain('Risiko: Aman')
  })

  it('menampilkan alasan kegagalan pemeriksaan eksternal secara spesifik', () => {
    const failedReport: MultiSourceReport = {
      ...report,
      externalError: 'Worker tidak dapat dihubungi.',
      externalShared: false,
    }
    const html = renderToStaticMarkup(
      <MultiSourceReportPanel report={failedReport} />,
    )

    expect(html).toContain('Pemeriksaan eksternal tidak selesai')
    expect(html).toContain('layanan pemeriksaan tidak dapat dihubungi.')
    expect(html).toContain('pemeriksaan baru')
  })

  it('menampilkan status timeout dan dilewati secara terpisah', () => {
    const statusReport: MultiSourceReport = {
      ...report,
      completeness: {
        ...report.completeness,
        timeout: 1,
        skipped: 1,
      },
      providers: report.providers.map((item): ProviderResult => {
        if (item.id === 'urlscan') {
          return {
            ...item,
            status: 'timeout',
            summary: 'Provider melewati batas waktu.',
            reason: 'URLScan belum selesai.',
          }
        }
        if (item.id === 'radar') {
          return {
            ...item,
            status: 'skipped',
            summary: 'Provider tidak dijalankan.',
            reason: 'URL sensitif.',
          }
        }
        return item
      }),
    }
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={statusReport} />)

    expect(html).toContain('Melebihi batas waktu')
    expect(html).toContain('Tidak dijalankan')
    expect(html).toContain('1 batas waktu habis')
    expect(html).toContain('1 tidak dijalankan')
  })

  it('membedakan kuota satu agen dari batas pemeriksaan milik VERIGUARD', () => {
    const singleLimited: MultiSourceReport = {
      ...report,
      completeness: {
        ...report.completeness,
        checked: 5,
        percent: 83,
        success: 4,
        rateLimited: 1,
        notFound: 1,
        notConfigured: 0,
        authFailed: 0,
        error: 0,
      },
      providers: [
        provider('internal', { label: 'Analisis internal', verdict: 'inconclusive' }),
        provider('urlscan', {
          status: 'rate_limited',
          verdict: 'inconclusive',
          score: null,
          summary: 'Kuota provider tercapai.',
          reason: 'Kuota permintaan provider tercapai. (HTTP 429)',
        }),
        provider('virustotal'),
        provider('openphish'),
        provider('threatfox', { status: 'not_found', verdict: 'inconclusive', score: null }),
        provider('radar'),
        provider('otx'),
      ],
    }
    const limitedHtml = renderToStaticMarkup(
      <MultiSourceReportPanel report={singleLimited} />,
    )

    const internalLimited: MultiSourceReport = {
      ...singleLimited,
      externalShared: false,
      providers: singleLimited.providers.map((item): ProviderResult =>
        item.id === 'internal'
          ? item
          : {
              ...item,
              status: 'rate_limited',
              verdict: 'inconclusive',
              score: null,
              summary: 'Batas pemeriksaan eksternal tercapai.',
              reason: 'Batas pemeriksaan milik VERIGUARD tercapai, bukan kuota agen. Coba lagi dalam ±600 detik.',
              durationMs: 0,
            },
      ),
    }
    const internalHtml = renderToStaticMarkup(
      <MultiSourceReportPanel report={internalLimited} />,
    )

    expect(limitedHtml).toContain('HTTP 429')
    expect(limitedHtml).toContain('Risiko: Tidak dapat dinilai')
    expect(limitedHtml).not.toContain('Batas pemeriksaan eksternal tercapai')
    expect(internalHtml).toContain('Batas pemeriksaan eksternal tercapai')
    expect(internalHtml).toContain('bukan kuota agen')
    expect(internalHtml).not.toContain('HTTP 429')
    for (const html of [limitedHtml, internalHtml]) {
      expect(html).not.toContain('Indikasi Risiko Rendah')
    }
  })
})

describe('penanda laporan yang dipakai ulang', () => {
  const reusedReport: MultiSourceReport = {
    ...report,
    providers: report.providers.map((item) =>
      item.id === 'urlscan'
        ? {
            ...item,
            status: 'success',
            verdict: 'clean',
            score: 0,
            summary:
              'Menggunakan laporan URLScan yang sudah ada (dibuat 2 jam lalu). URLScan tidak menemukan indikasi berbahaya.',
            reason:
              'Vonis ini berasal dari laporan tersimpan URLScan, bukan pemindaian langsung pada pemeriksaan ini.',
            evidence: {
              source: 'existing_report',
              observedAt: '2026-01-01T00:00:00.000Z',
              ageMs: 2 * 60 * 60_000,
            },
          }
        : item,
    ),
  }

  it('membuang narasi laporan lama dari kartu agen tanpa mengubah vonis atau waktunya', () => {
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={reusedReport} />)

    // Kalimat cache yang tersimpan di laporan lama tidak lagi ikut ter-render.
    expect(html).not.toContain('Menggunakan laporan')
    expect(html).not.toContain('yang sudah ada')
    expect(html).not.toContain('bukan pemindaian langsung')
    expect(html).not.toContain('laporan tersimpan')
    // Vonis agen tetap utuh, dengan nama agen dan bukan nama provider.
    expect(html).toContain('Agen 1 tidak menemukan indikasi berbahaya.')
    // Waktu laporan yang sebenarnya tetap tampil, diambil dari metadata terstruktur.
    expect(html).toContain('Waktu laporan')
    expect(html).toContain('Risiko: Tidak ditemukan indikasi')
  })

  it('tidak memberi penanda laporan lama pada pemindaian langsung', () => {
    const freshReport: MultiSourceReport = {
      ...reusedReport,
      providers: reusedReport.providers.map((item) =>
        item.id === 'urlscan'
          ? {
              ...item,
              summary: 'URLScan tidak menemukan indikasi berbahaya.',
              reason: null,
              evidence: { source: 'new_scan', observedAt: null, ageMs: 0 },
            }
          : item,
      ),
    }
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={freshReport} />)

    expect(html).not.toContain('Menggunakan laporan yang sudah ada')
  })
})

describe('metadata cache tidak pernah tampil di panel hasil', () => {
  const reusedMeta = {
    status: 'partial' as const,
    hit: false,
    observedAt: '2026-01-01T00:00:00.000Z',
    ageMs: 5 * 60_000,
    reusedProviders: ['virustotal'] as ExternalProviderId[],
    refreshedProviders: ['urlscan'] as ExternalProviderId[],
    requestsAvoided: 1,
    deduplicated: true,
  }

  const cachedReport: MultiSourceReport = {
    ...report,
    cache: reusedMeta,
    providers: report.providers.map((item) =>
      item.id === 'virustotal'
        ? {
            ...item,
            cache: {
              hit: true,
              observedAt: '2026-01-01T00:00:00.000Z',
              ageMs: 5 * 60_000,
              stale: false,
            },
          }
        : item,
    ),
  }

  it('menyembunyikan badge hasil tersimpan, umur cache, dan keterangan permintaan yang dilewati', () => {
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={cachedReport} />)

    for (const hidden of [
      'Hasil tersimpan',
      'umur 5 menit',
      'Diperoleh ',
      'memakai hasil tersimpan',
      'permintaan ke agen-agen itu tidak diulang',
      'berbagi satu proses dengan pemeriksaan lain',
      'Bukti hulu lebih tua dari batas segarnya',
    ]) {
      expect(html).not.toContain(hidden)
    }
  })

  it('tetap menampilkan hasil agen seperti biasa ketika cache dipakai', () => {
    const cached = renderToStaticMarkup(<MultiSourceReportPanel report={cachedReport} />)
    const plain = renderToStaticMarkup(<MultiSourceReportPanel report={report} />)

    // Hasil, vonis, dan skor yang tampil identik dengan pemeriksaan tanpa cache.
    expect(cached.match(/Risiko: [^<]*/g)).toEqual(plain.match(/Risiko: [^<]*/g))
    expect(cached).toContain('0/93 mesin keamanan mendeteksi berbahaya.')
    expect(cached).toContain('Agen 2')
    expect(cachedReport.verdict).toBe(report.verdict)
    expect(cachedReport.score).toBe(report.score)
  })

  it('tidak menampilkan penanda apa pun untuk laporan backend lama', () => {
    const html = renderToStaticMarkup(<MultiSourceReportPanel report={report} />)

    expect(html).not.toContain('Hasil tersimpan')
    expect(html).not.toContain('memakai hasil tersimpan')
    expect(html).not.toContain('Bukti hulu')
  })

  it('menyaring catatan cache yang masih tersimpan di laporan lama', () => {
    const legacyReport: MultiSourceReport = {
      ...report,
      notes: [
        ...report.notes,
        'VirusTotal memakai hasil pemeriksaan 5 menit yang lalu; jawabannya masih dalam batas segar kebijakan, tetapi bukan pemindaian ulang pada permintaan ini.',
        'Semua agen yang ikut memeriksa memakai hasil yang masih segar, jadi tidak ada permintaan keluar untuk pemeriksaan ini.',
        'Pemeriksaan ini berbagi hasil dengan pemeriksaan lain yang sedang berjalan untuk URL yang sama; pekerjaan ganda tidak dilakukan.',
        'Sebagian hasil dibangun di atas data hulu yang lebih tua dari batas segarnya; baris agen terkait menandainya.',
        'Agen 4 memakai hasil tersimpan berumur 5 menit; permintaan ke agen-agen itu tidak diulang pada pemeriksaan ini.',
      ],
    }

    const html = renderToStaticMarkup(<MultiSourceReportPanel report={legacyReport} />)

    for (const hidden of [
      'memakai hasil pemeriksaan',
      'tidak ada permintaan keluar',
      'pekerjaan ganda',
      'batas segarnya',
      'memakai hasil tersimpan',
    ]) {
      expect(html).not.toContain(hidden)
    }
    // Catatan non-cache tetap ditampilkan apa adanya.
    expect(html).toContain('Skor gabungan adalah indikator bukti, bukan probabilitas.')
  })
})

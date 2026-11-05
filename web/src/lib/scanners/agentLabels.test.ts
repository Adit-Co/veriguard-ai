import { describe, expect, it } from 'vitest'
import {
  agentLabel,
  agentNumber,
  describeAgentProvider,
  isCacheNarrativeText,
  sanitizeAgentText,
} from './agentLabels'
import { EXTERNAL_PROVIDER_IDS, type ProviderResult } from './types'

function provider(overrides: Partial<ProviderResult> = {}): ProviderResult {
  return {
    id: 'virustotal',
    label: 'VirusTotal',
    status: 'success',
    verdict: 'malicious',
    score: 100,
    summary: '4/93 security engine mendeteksi berbahaya; 1 mencurigakan.',
    signals: [
      {
        label: 'Detection ratio VirusTotal',
        detail: '4/93 security engine menandai URL ini berbahaya (4.3%)',
        severity: 'danger',
      },
    ],
    reason: 'AlienVault OTX menghubungkan URL ini dengan keluarga malware.',
    durationMs: 1234,
    ...overrides,
  }
}

describe('label agen presentations', () => {
  it('memetakan delapan agen sesuai urutan registrasi adapter', () => {
    expect(EXTERNAL_PROVIDER_IDS.map((id) => agentLabel(id, id))).toEqual([
      'Agen 1',
      'Agen 2',
      'Agen 3',
      'Agen 4',
      'Agen 5',
      'Agen 6',
      'Agen 7',
      'Agen 8',
    ])
  })

  it('stabil lintas pemanggilan dan tidak bergantung pada status hasil', () => {
    expect(agentLabel('radar', 'Cloudflare Radar URL Scanner')).toBe('Agen 5')
    expect(agentLabel('otx', 'AlienVault OTX')).toBe('Agen 6')
    expect(agentNumber('otx')).toBe(6)
    expect(agentLabel('hybrid', 'Hybrid Analysis')).toBe('Agen 7')
    expect(agentNumber('hybrid')).toBe(7)
    expect(agentLabel('safebrowsing', 'Google Safe Browsing')).toBe('Agen 8')
    expect(agentNumber('safebrowsing')).toBe(8)

    for (const status of ['success', 'timeout', 'skipped', 'not_configured'] as const) {
      expect(describeAgentProvider(provider({ status })).label).toBe('Agen 2')
    }
  })

  it('mengganti semua nama penyedia di teks dengan label agen', () => {
    const texts = [
      'URLScan menilai URL ini berbahaya (skor 80/100).',
      'OpenPhish tidak menemukan URL ini di basis data phishing aktif.',
      'ThreatFox menemukan 2 IOC yang cocok dengan URL ini.',
      'Cloudflare URL Scanner selesai memindai tanpa menghasilkan vonis.',
      'Pencocokan exact-URL pada feed phishing aktif OpenPhish.',
      '1 pulse OTX menyebut URL ini.',
      'Tag URLScan',
      'Kategori URLScan',
      'Hasil pemindaian dapat dibuka di Cloudflare Radar.',
      'Google Safe Browsing menilai URL ini "clean" (skor provider 12).',
      'Provider Safe Browsing mengembalikan vonis yang tidak terdokumentasi.',
      'Hybrid Analysis (hybrid-analysis.com) belum dapat dipakai sebagai agen pemindai URL.',
    ]

    for (const text of texts) {
      const sanitized = sanitizeAgentText(text)
      for (const name of [
        'URLScan',
        'OpenPhish',
        'ThreatFox',
        'Cloudflare',
        'Radar',
        'OTX',
        'AlienVault',
        'VirusTotal',
        'Hybrid Analysis',
        'Falcon',
        'Google Safe Browsing',
        'Safe Browsing',
      ]) {
        expect(sanitized).not.toContain(name)
      }
      expect(sanitized).toMatch(/Agen \d/)
    }
  })

  it('memisahkan agen 1 (URLScan.io) dari agen 8 (Google Safe Browsing)', () => {
    expect(sanitizeAgentText('URLScan.io menyimpan hasil pemindaian.')).toBe(
      'Agen 1 menyimpan hasil pemindaian.',
    )
    expect(sanitizeAgentText('Umur domain versi Google Safe Browsing.')).toBe(
      'Umur domain versi Agen 8.',
    )
    expect(sanitizeAgentText('Hybrid Analysis belum dapat dipakai sebagai agen pemindai URL.')).toBe(
      'Agen 7 belum dapat dipakai sebagai agen pemindai URL.',
    )
  })

  it('generalisasi istilah teknis tanpa mengubah angka', () => {
    expect(
      sanitizeAgentText('3/93 security engine menandai URL ini berbahaya (3.23%).'),
    ).toBe('3/93 mesin keamanan menandai URL ini berbahaya (3.23%).')
    expect(sanitizeAgentText('Detection ratio VirusTotal')).toBe('Rasio deteksi')
    expect(sanitizeAgentText('0/93 engine mendeteksi berbahaya.')).toBe(
      '0/93 mesin keamanan mendeteksi berbahaya.',
    )
    expect(sanitizeAgentText('AlienVault OTX menemukan 2 pulse komunitas yang menyebut URL ini.')).toBe(
      'Agen 6 menemukan 2 laporan komunitas yang menyebut URL ini.',
    )
    expect(sanitizeAgentText('Provider tidak dijalankan.')).toBe('Agen tidak dijalankan.')
    expect(sanitizeAgentText('provider eksternal')).toBe('agen eksternal')
  })

  it('hanya mengubah teks, bukan status/verdict/skor/durasi', () => {
    const original = provider()
    const view = describeAgentProvider(original)

    expect(view.id).toBe(original.id)
    expect(view.status).toBe(original.status)
    expect(view.verdict).toBe(original.verdict)
    expect(view.score).toBe(original.score)
    expect(view.durationMs).toBe(original.durationMs)
    expect(view.signals[0]?.severity).toBe('danger')
    expect(original.label).toBe('VirusTotal')
    expect(view.label).toBe('Agen 2')
    expect(view.summary).toContain('mesin keamanan')
    expect(view.reason).toContain('Agen 6')
  })

  it('mempertahankan label analisis internal', () => {
    const internal = provider({ id: 'internal', label: 'Analisis internal' })
    expect(describeAgentProvider(internal).label).toBe('Analisis internal')
  })

  it('tidak mengarang teks ketika reason kosong', () => {
    expect(describeAgentProvider(provider({ reason: null })).reason).toBeNull()
  })
})

// Laporan yang tersimpan sebelum penarasiannya dihentikan masih memuat kalimat cara hasil
// diperoleh di dalam `summary`/`reason`/sinyal/`notes`. Kalimat itu tidak boleh sampai ke
// antarmuka, sedangkan bukti agen harus tetap utuh.
describe('narasi cara pengambilan hasil tidak pernah tampil', () => {
  const LEGACY_NARRATIVES: string[] = [
    // Sumber: adapter urlscan/radar versi lama (persis pesan yang dilaporkan pengguna).
    'Menggunakan laporan URLScan yang sudah ada (dibuat 4 menit lalu).',
    'Menggunakan laporan Cloudflare yang sudah ada (dibuat 2 jam lalu).',
    // Sumber: stamp withExistingReportEvidence versi lama.
    'Vonis ini berasal dari laporan tersimpan URLScan, bukan pemindaian langsung pada pemeriksaan ini.',
    'Vonis ini berasal dari laporan Cloudflare URL Scanner yang sudah ada, bukan pemindaian langsung pada pemeriksaan ini.',
    'Hasil dibaca dari laporan tersimpan VirusTotal; tidak ada pemindaian baru pada pemeriksaan ini.',
    'Umur laporan 8 hari melewati kebijakan kesegaran 168 jam, jadi vonis dibaca sebagai bukti lama; tidak ada pemindaian baru pada pemeriksaan ini.',
    'Hasil berasal dari laporan yang sudah ada di dataset provider; umurnya tidak dapat dipastikan, bukan pemindaian langsung.',
    'Hasil berasal dari laporan yang sudah ada (analisis terbaru 3 jam lalu), bukan pemindaian langsung pada pemeriksaan ini.',
    // Sumber: catatan laporan versi lama dan salinan progres langsung.
    'URLScan.io, VirusTotal mengembalikan laporan yang sudah ada; hasilnya bukan pemindaian langsung.',
    'Menggunakan laporan yang sudah ada; bukan pemindaian langsung.',
    'VirusTotal memakai hasil pemeriksaan 5 menit yang lalu; jawabannya masih dalam batas segar kebijakan, tetapi bukan pemindaian ulang pada permintaan ini.',
    'Semua agen yang ikut memeriksa memakai hasil yang masih segar, jadi tidak ada permintaan keluar untuk pemeriksaan ini.',
    'Pemeriksaan ini berbagi hasil dengan pemeriksaan lain yang sedang berjalan untuk URL yang sama; pekerjaan ganda tidak dilakukan.',
    'Sebagian hasil dibangun di atas data hulu yang lebih tua dari batas segarnya; baris agen terkait menandainya.',
    'Agen 4 memakai hasil tersimpan berumur 5 menit; permintaan ke agen-agen itu tidak diulang pada pemeriksaan ini.',
    // Sumber: sinyal feed basi OpenPhish versi lama.
    'Feed OpenPhish yang dipakai berumur 5 jam dan diperbarui 2026-01-01T00:00:00.000Z; unduhan ulang sedang gagal (503).',
  ]

  it.each(LEGACY_NARRATIVES)('membuang seluruh kalimat: %s', (text) => {
    expect(sanitizeAgentText(text).trim()).toBe('')
    expect(isCacheNarrativeText(text)).toBe(true)
  })

  it('mempertahankan vonis dan angkanya saat kalimat cache ikut terkirim', () => {
    const legacy =
      'Menggunakan laporan URLScan yang sudah ada (dibuat 4 menit lalu). URLScan menilai URL ini berbahaya (skor 100/100).'

    expect(sanitizeAgentText(legacy)).toBe('Agen 1 menilai URL ini berbahaya (skor 100/100).')
  })

  it('mempertahankan bukti provider saat alasan memuat dua klausa', () => {
    const legacy =
      'Laporan provider memberi vonis "whitelisted"/"clean"; ini berasal dari laporan yang sudah ada, bukan pemindaian langsung.'

    const cleaned = sanitizeAgentText(legacy)
    expect(cleaned).toContain('whitelisted')
    expect(cleaned).not.toContain('sudah ada')
    expect(cleaned).not.toMatch(/pemindaian/i)
  })

  it('membuang sinyal yang seluruh isinya narasi, bukan sinyal berisi temuan', () => {
    const view = describeAgentProvider(
      provider({
        summary:
          'Menggunakan laporan VirusTotal yang sudah ada (dibuat 2 jam lalu). 4/93 engine mendeteksi berbahaya.',
        signals: [
          {
            label: 'Sumber laporan VirusTotal',
            detail: 'Hasil dibaca dari laporan tersimpan VirusTotal; tidak ada pemindaian baru.',
            severity: 'info',
          },
          {
            label: 'Engine menandai berbahaya',
            detail: '4 dari 93 engine menandai URL ini berbahaya.',
            severity: 'danger',
          },
        ],
      }),
    )

    expect(view.summary).toBe('4/93 mesin keamanan mendeteksi berbahaya.')
    expect(view.signals).toHaveLength(1)
    expect(view.signals[0]?.detail).toContain('menandai URL ini berbahaya')
    // Angka, vonis, dan status tidak disentuh oleh pembersihan teks.
    expect(view.verdict).toBe('malicious')
    expect(view.score).toBe(100)
    expect(view.status).toBe('success')
  })

  it('tidak menyentuh teks hasil yang sah', () => {
    const untouched = [
      'Skor gabungan adalah indikator bukti, bukan probabilitas.',
      'Laporan ini direkonstruksi dari hasil analisis internal; rincian agen eksternal tidak tersimpan.',
      'URL tidak dikirim ke agen eksternal karena memuat data sensitif.',
      'Sebagian agen eksternal tidak memberi hasil; kelengkapan data belum penuh.',
      '0/93 security engine mendeteksi berbahaya; 1 mencurigakan.',
      'Analisis terakhir 12 Nov 2023 10:00 UTC, melewati batas umur laporan 168 jam yang diterima agen ini.',
      'Sumber data agen ini terakhir diperbarui 12 Nov 2023 10:00 UTC, jadi kecocokan yang ditemukan bisa lebih tua dari pemeriksaan ini.',
      'Batas pemeriksaan eksternal tercapai; URL tidak diproses oleh agen.',
      'AlienVault OTX menghubungkan URL ini dengan keluarga malware.',
      'Data feed belum terbaru.',
    ]

    for (const text of untouched) {
      // Pembersihan hanya berjalan bila polanya cocok; teks sah tidak boleh cocok sama sekali.
      expect(isCacheNarrativeText(text)).toBe(false)
      // Yang tersisa hanyalah generalisasi nama/istilah, tidak ada klausa yang hilang.
      const cleaned = sanitizeAgentText(text)
      expect(cleaned.split(/[.;]/).filter(Boolean).length).toBe(
        text.split(/[.;]/).filter(Boolean).length,
      )
      expect(cleaned).not.toBe('')
    }
  })
})

import { describe, expect, it } from 'vitest'
import { classifyWebsiteCategory } from '../src/website/category.js'
import { runSiteAnalysis } from '../src/website/service.js'
import type { HttpResponseInfo, LookupStatus, SiteAnalysisResponse } from '../src/website/types.js'

function lookup<T>(status: LookupStatus, detail: string | null, value: T | null) {
  return {
    status,
    source: 'unit-test',
    value,
    detail,
    queriedAt: '2026-10-26T00:00:00.000Z',
  }
}

function responseInfo(overrides: Partial<HttpResponseInfo> = {}): HttpResponseInfo {
  return {
    request: lookup<null>('success', null, null),
    status: 200,
    statusText: 'OK',
    finalUrl: 'https://contoh.com/',
    redirectCount: 0,
    elapsedMs: 120,
    contentType: 'text/html; charset=utf-8',
    bytes: 1024,
    truncated: false,
    headers: [],
    withheldHeaders: 0,
    ...overrides,
  }
}

function classify(
  hostname: string,
  html: string | null,
  responseOverrides: Partial<HttpResponseInfo> = {},
) {
  return classifyWebsiteCategory({
    hostname,
    html,
    response: responseInfo(responseOverrides),
  })
}

function page(title: string, description: string, body: string): string {
  return `<html><head><title>${title}</title><meta name="description" content="${description}"></head><body>${body}</body></html>`
}

describe('kategori website dari konten umum', () => {
  it('mengategorikan situs dokumentasi teknis sebagai teknologi', () => {
    const result = classify(
      'developers.example.com',
      page(
        'Dokumentasi API VERIGUARD',
        'Dokumentasi developer, referensi API, dan SDK open source.',
        'Pelajari cara memakai REST API, SDK, dan alat developer di sini.',
      ),
    )

    expect(result.status).toBe('complete')
    expect(result.primaryId).toBe('technology')
    expect(result.riskIndicated).toBe(false)
    // Seluruh bukti fixture berasal dari satu keluarga leksikon, jadi keyakinan tetap rendah.
    expect(result.confidence).toBe('low')
    expect(result.signals.length).toBeGreaterThan(0)
    expect(result.summary).not.toMatch(/pasti aman/i)
  })

  it('menyebut kategori bisnis untuk halaman perusahaan', () => {
    const result = classify(
      'www.mitra-kontruksi.co.id',
      page(
        'PT Mitra Konstruksi — Tentang Kami',
        'Layanan kami mencakup konstruksi dan infrastruktur. Kontak kami tersedia setiap hari kerja.',
        'PT. Mitra Konstruksi menyediakan layanan konsultansi. Hubungi kontak kami untuk layanan kami.',
      ),
    )

    expect(result.primaryId).toBe('business')
    expect(result.riskIndicated).toBe(false)
  })

  it('menaikkan keyakinan ketika dua keluarga bukti saling menguatkan', () => {
    const result = classify(
      'docs.example.com',
      page(
        'Dokumentasi platform',
        'Dokumentasi developer, referensi API, dan SDK open source untuk layanan cloud.',
        'Deploy ke server, jalankan container, lalu baca dokumentasi lainnya.',
      ),
    )

    expect(result.primaryId).toBe('technology')
    expect(['medium', 'high']).toContain(result.confidence)
    expect(result.signals.length).toBeGreaterThanOrEqual(2)
  })

  it('memakai domain tingkat kedua khusus sebagai bukti pemerintahan', () => {
    const result = classify('pelayanan.go.id', null)

    expect(result.primaryId).toBe('government')
    expect(result.riskIndicated).toBe(false)
    expect(result.confidence).toBe('low')
  })
})

describe('indikasi judi online', () => {
  it('mendeteksi judi online dari konten yang saling menguatkan', () => {
    const result = classify(
      'www.situs-gacor88.com',
      page(
        'Slot Gacor Hari Ini — Casino Online Terpercaya',
        'Judi online dengan bonus member baru, deposit dan withdraw cepat, serta jackpot maxwin.',
        'Main slot gacor setiap hari. Sportsbook dan togel juga tersedia. Lakukan deposit lalu withdraw.',
      ),
    )

    expect(result.primaryId).toBe('gambling')
    expect(result.riskIndicated).toBe(true)
    expect(['medium', 'high']).toContain(result.confidence)
    expect(result.signals.some((signal) => signal.source === 'content')).toBe(true)
  })

  it('tidak menyatakan judi online hanya karena nama domain mencurigakan', () => {
    const result = classify('slot-rekomendasi.info', null)

    expect(result.primaryId).toBe('unknown')
    expect(result.riskIndicated).toBe(false)
    expect(result.confidence).toBe('low')
  })

  it('tidak menyatakan judi online saat konten hanya menyebut hiburan biasa', () => {
    const result = classify(
      'www.kajian-harian.id',
      page(
        'Kajian Harian',
        'Artikel seputar pendidikan dan keluarga.',
        'Tulis ulasan dan komentar pembaca tentang buku bacaan.',
      ),
    )

    expect(result.primaryId).not.toBe('gambling')
    expect(result.riskIndicated).toBe(false)
  })
})

describe('indikasi phishing dan penipuan', () => {
  it('mendeteksi indikasi phishing dari permintaan kredensial dan ancaman akun', () => {
    const result = classify(
      'akun-verifikasi.example',
      page(
        'Verifikasi Akun Anda Sekarang',
        'Akun anda diblokir. Masukkan password dan kode OTP anda untuk mengaktifkan kembali.',
        'Segera konfirmasi identitas. Verifikasi akun sebelum dibekukan permanen.',
      ),
    )

    expect(result.primaryId).toBe('phishing')
    expect(result.riskIndicated).toBe(true)
    expect(result.confidence).not.toBe('low')
  })

  it('mendeteksi indikasi penipuan dari janji keuntungan finansial', () => {
    const result = classify(
      'www.salam-sejahtera.top',
      page(
        'Titip Dana Profit Terjamin 30% Per Bulan',
        'Investasikan dengan jaminan keuntungan terjamin. Guaranteed return setiap minggu.',
        'Bonus baru 100rb untuk member. Transfer sebesar sekarang juga dan klaim hadiah anda.',
      ),
    )

    expect(result.primaryId).toBe('scam')
    expect(result.riskIndicated).toBe(true)
  })

  it('mendeteksi distribusi berkas executable sebagai indikasi malware', () => {
    const result = classify(
      'files.download-zone.xyz',
      page(
        'Crack Keygen Patch Gratis',
        'Download free installer aplikasi premium tanpa lisensi.',
        'Ambil crack dan keygen terbaru di sini, lalu jalankan setup.',
      ),
      {
        finalUrl: 'https://files.download-zone.xyz/download/perangkat-crack.exe',
        contentType: 'application/octet-stream',
      },
    )

    expect(result.primaryId).toBe('malware')
    expect(result.riskIndicated).toBe(true)
  })

  it('menandai rantai redirect panjang sebagai sinyal, bukan vonis final', () => {
    const result = classify(
      'link-singkat.example',
      page('Halaman tidak ditemukan', '', 'Maaf, halaman yang kamu cari tidak tersedia.'),
      { redirectCount: 4, finalUrl: 'https://tujuan-asing.example/login' },
    )

    expect(result.riskIndicated).toBe(false)
    expect(result.primaryId).toBe('unknown')
  })
})

describe('data belum cukup', () => {
  it('mengembalikan tidak diketahui dengan keyakinan rendah saat halaman kosong', () => {
    const result = classify('kosong.example.com', page('', '', ''))

    expect(result.primaryId).toBe('unknown')
    expect(result.confidence).toBe('low')
    expect(result.riskIndicated).toBe(false)
    expect(result.summary).toMatch('belum cukup')
  })

  it('menandai status unavailable saat halaman tidak terbaca', () => {
    const result = classify('gagal.example.com', null, {
      status: null,
      contentType: null,
      finalUrl: null,
      request: lookup<null>('failed', 'koneksi gagal', null),
    })

    expect(result.status).toBe('unavailable')
    expect(result.primaryId).toBe('unknown')
    expect(result.confidence).toBe('low')
  })

  it('menandai status partial untuk dokumen non-HTML', () => {
    const result = classify('api.example.com', null, {
      contentType: 'application/json',
    })

    expect(result.status).toBe('partial')
    expect(result.evidenceBasis.documentInspected).toBe(false)
  })

  it('tidak mengarang kategori ketika bukti hanya berupa kata umum', () => {
    const result = classify(
      'serbaguna.example',
      page('Katalog', 'Berisi daftar barang.', 'Silakan buka tautan lain untuk rincian singkat.'),
    )

    expect(result.primaryId).toBe('unknown')
    expect(result.confidence).toBe('low')
  })
})

describe('SSRF protection tetap aktif pada alur analisis situs', () => {
  const blocked: Array<[string, RegExp]> = [
    ['http://127.0.0.1/', /Alamat lokal atau privat|internal/i],
    ['http://localhost/admin', /Alamat lokal atau privat|internal/i],
    ['http://0.0.0.0/', /Alamat lokal atau privat|internal/i],
    ['http://169.254.169.254/latest/meta-data/', /Alamat lokal atau privat|internal|metadata/i],
    ['http://10.0.0.5/', /Alamat lokal atau privat|internal/i],
    ['http://[::1]/', /Alamat lokal atau privat|internal/i],
  ]

  for (const [url, message] of blocked) {
    it(`menolak ${url} sebelum ada permintaan ke target`, async () => {
      const probeCalls: string[] = []
      const probe = {
        name: 'unit-test-probe',
        dnsSource: 'unit-test',
        resolve: async () => {
          probeCalls.push('resolve')
          return { ipv4: ['93.184.216.34'], ipv6: [], detail: null }
        },
        queryRecords: async () => ({ records: [], outcome: 'answered' as const, detail: null }),
        lookupAsn: async () => ({ info: null, outcome: 'answered' as const, detail: null }),
        inspectTls: async () => ({
          certificate: null,
          httpsReachable: false,
          outcome: 'answered' as const,
          detail: null,
        }),
        openOrigin: async () => {
          probeCalls.push('openOrigin')
          throw new Error('origin harus tidak dibuka')
        },
      }

      await expect(
        runSiteAnalysis({
          url,
          uid: 'unit-test',
          probe,
          now: () => Date.parse('2026-10-26T00:00:00.000Z'),
        }),
      ).rejects.toThrow(message)

      expect(probeCalls).toEqual([])
    })
  }
})

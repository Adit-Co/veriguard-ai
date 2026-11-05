import { describe, expect, it } from 'vitest'
import { virusTotalAdapter } from '../src/scanners/providers/virustotal.js'
import type { ProviderContext, ScannerConfig } from '../src/scanners/types.js'

// VGL-32B aturan 1 — laporan VirusTotal yang LENGKAP adalah pernyataan bersih eksplisit.
//
// VGL-31 memberi strength `limited` bila mesin mayoritas menjawab `undetected` alih-alih
// `harmless`. Untuk URL domain besar (mail.google.com) itu praktis selalu terjadi: engine
// menjawab `undetected` karena memang tidak menemukan apa pun pada alamat ini — sebuah
// vonis negatif per mesin, bukan ketiadaan jawaban. Konsekuensi VGL-31: VirusTotal tidak
// pernah menjadi confirmed_clean dan laporan mentok "Perlu Perhatian" walau dua agen
// berbeda (URLScan + VirusTotal) menyatakan bersih. VGL-32B mengoreksi kontraknya:
// 0 malicious + 0 suspicious + >= MIN_ENGINES melaporkan + 0 mesin gagal/timeout
// => `explicit`. Pagar pengaman lama tetap berdiri: mesin gagal/timeout menghapus bukti,
// dan laporan dengan sedikit mesin yang melaporkan tetap inconclusive.

const NOW_MS = 1_700_000_000_000
const TARGET_URL = 'https://mail.google.com/'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function fetchFor(routes: (url: string) => Response | null) {
  return (async (input: unknown) => {
    const url = String(input)
    const response = routes(url)
    if (response) return response
    throw new Error(`Fixture tidak menyiapkan rute: ${url}`)
  }) as unknown as typeof fetch
}

function makeConfig(overrides: Partial<ScannerConfig> = {}): ScannerConfig {
  return {
    urlscanApiKey: 'urlscan-key',
    virusTotalApiKey: 'vt-key',
    openPhishApiKey: null,
    threatFoxApiKey: 'tf-key',
    cloudflareApiToken: 'cf-token',
    cloudflareAccountId: 'cf-account',
    otxApiKey: 'otx-key',
    googleSafeBrowsingApiKey: 'sb-key',
    hybridAnalysisApiKey: 'ha-key',
    ...overrides,
  }
}

function contextFor(url: string, fetchImpl: typeof fetch): ProviderContext {
  return {
    url,
    hostname: new URL(url).hostname,
    fetchImpl,
    now: () => NOW_MS,
    sleep: async () => undefined,
  }
}

function vtReport(stats: Record<string, number>, ageSec: number) {
  return {
    data: {
      attributes: {
        last_analysis_date: Math.floor(NOW_MS / 1000) - ageSec,
        last_analysis_stats: {
          malicious: 0,
          suspicious: 0,
          harmless: 20,
          undetected: 0,
          ...stats,
        },
      },
    },
  }
}

function vtRoutes(body: unknown) {
  return fetchFor((url) => (url.includes('virustotal.com') ? jsonResponse(body) : null))
}

describe('VGL-32B aturan 1 — laporan lengkap VirusTotal = bukti bersih eksplisit', () => {
  it('0 ditandai, 25 mesin hanya undetected, tanpa mesin gagal -> explicit (bukan limited lagi)', async () => {
    const check = await virusTotalAdapter.check(
      contextFor(TARGET_URL, vtRoutes(vtReport({ harmless: 0, undetected: 25 }, 60))),
      makeConfig(),
    )

    expect(check.verdict).toBe('clean')
    expect(check.negative?.strength).toBe('explicit')
    expect(check.negative?.evidenceClass).toBe('engine_verdicts')
    expect(check.negative?.scope).toBe('url')
  })

  it('pola hidup mail.google.com: 2 harmless + 91 undetected + 0 failure -> explicit', async () => {
    const check = await virusTotalAdapter.check(
      contextFor(TARGET_URL, vtRoutes(vtReport({ harmless: 2, undetected: 91 }, 60))),
      makeConfig(),
    )

    expect(check.negative?.strength).toBe('explicit')
  })

  it('pagar lama tetap ada: mesin gagal/bisu menghapus bukti negatif', async () => {
    const check = await virusTotalAdapter.check(
      contextFor(TARGET_URL, vtRoutes(vtReport({ harmless: 20, failure: 4 }, 60))),
      makeConfig(),
    )

    expect(check.negative).toBeUndefined()
    expect(check.reason).toContain('tidak memberikan hasil')
  })

  it('pagar lama tetap ada: hanya sedikit mesin melapor -> inconclusive tanpa bukti', async () => {
    const check = await virusTotalAdapter.check(
      contextFor(TARGET_URL, vtRoutes(vtReport({ harmless: 1, undetected: 2 }, 60))),
      makeConfig(),
    )

    expect(check.verdict).toBe('inconclusive')
    expect(check.negative).toBeUndefined()
  })

  it('umur laporan memakai waktu analisis provider, bukan waktu respons adapter', async () => {
    const ageSec = 48 * 60 * 60
    const check = await virusTotalAdapter.check(
      contextFor(TARGET_URL, vtRoutes(vtReport({ harmless: 2, undetected: 91 }, ageSec))),
      makeConfig(),
    )

    expect(check.evidence?.source).toBe('existing_report')
    expect(check.evidence?.observedAt).toBe(new Date((Math.floor(NOW_MS / 1000) - ageSec) * 1000).toISOString())
    expect(check.evidence?.ageMs).toBe(ageSec * 1000)
  })
})

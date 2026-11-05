import { describe, expect, it } from 'vitest'
import { fuseEvidence, registrableOf, staticOnlyFusion } from '../src/website/risk.js'
import { analyzeUrlStructure } from '../src/website/urlSignals.js'
import { analyzeDomainAge } from '../src/website/registration.js'
import { analyzePageContent } from '../src/website/pageSignals.js'
import type {
  BehaviorAnalysis,
  PageAnalysis,
  RegistrationQueryResult,
  UrlStructureAnalysis,
  WebsiteCategoryAssessment,
  WebsiteIntelligence,
} from '../src/website/types.js'

const AT = '2026-10-30T12:00:00.000Z'
const NOW = () => Date.parse(AT)

function structure(url: string): UrlStructureAnalysis {
  return analyzeUrlStructure({ initialUrl: url, finalUrl: url, hostname: new URL(url).hostname, hops: [] })
}

function website(overrides: Partial<WebsiteIntelligence> = {}): WebsiteIntelligence {
  const lookup = (status: string) => ({ status, source: 'probe', value: null, detail: null, queriedAt: AT })
  return {
    status: 'complete',
    identity: {
      hostname: 'contoh.example',
      addresses: lookup('success') as never,
      withheldAddresses: 0,
      asn: lookup('success') as never,
      intermediary: { state: 'no_signal', signals: [], note: '' },
    },
    dns: [
      { type: 'A', lookup: lookup('success') as never },
      { type: 'AAAA', lookup: lookup('empty') as never },
    ],
    tls: {
      httpsAvailable: lookup('success') as never,
      certificate: lookup('success') as never,
      certificateSource: 'probe',
    },
    response: {
      request: lookup('success') as never,
      status: 200,
      statusText: 'OK',
      finalUrl: 'https://contoh.example/',
      redirectCount: 0,
      elapsedMs: 10,
      contentType: 'text/html',
      bytes: 100,
      truncated: false,
      headers: [],
      withheldHeaders: 0,
    },
    notes: [],
    ...overrides,
  }
}

function behavior(overrides: Partial<BehaviorAnalysis> = {}): BehaviorAnalysis {
  return {
    status: 'complete',
    initialUrl: 'https://contoh.example/',
    redirects: [],
    redirectCount: 0,
    redirectOutcome: 'final',
    hosts: [],
    resources: null,
    securityHeaders: [],
    cookies: [],
    cookiesCollected: false,
    structure: structure('https://contoh.example/'),
    forms: { inspected: true, forms: [], totals: { forms: 0, passwordFields: 0, externalActions: 0, insecureActions: 0 }, capped: false, detail: '' },
    observations: [],
    notes: [],
    ...overrides,
  }
}

function page(html: string | null, baseUrl: string | null): PageAnalysis {
  return analyzePageContent({
    html,
    baseUrl,
    pageHost: baseUrl ? new URL(baseUrl).hostname : 'contoh.example',
    pageSecure: true,
    registrableDomain: baseUrl ? registrableOf(new URL(baseUrl).hostname) : null,
  })
}

function category(overrides: Partial<WebsiteCategoryAssessment> = {}): WebsiteCategoryAssessment {
  return {
    status: 'complete',
    primaryId: 'unknown',
    primaryLabel: 'Tidak diketahui',
    confidence: 'low',
    riskIndicated: false,
    summary: '',
    signals: [],
    alternatives: [],
    evidenceBasis: { documentInspected: false, titleAvailable: false, descriptionAvailable: false, visibleTextBytes: 0, redirectHops: 0 },
    notes: [],
    ...overrides,
  }
}

function registration(result: RegistrationQueryResult, registrable = 'penipu.example') {
  return analyzeDomainAge({ registrableDomain: registrable, result, now: NOW })
}

const answered = (daysAgo: number): RegistrationQueryResult => ({
  registration: {
    domain: 'penipu.example',
    handle: null,
    registrar: null,
    createdAt: new Date(NOW() - daysAgo * 86_400_000).toISOString(),
    changedAt: null,
    expiresAt: null,
    statuses: [],
  },
  outcome: 'answered',
  source: 'rdap.test',
  detail: null,
})

function fuse(overrides: Partial<Parameters<typeof fuseEvidence>[0]> = {}) {
  return fuseEvidence({
    generatedAt: AT,
    structure: structure('https://contoh.example/'),
    registration: registration({ registration: null, outcome: 'unsupported', source: null, detail: 'TLD tanpa RDAP.' }),
    website: website(),
    behavior: behavior(),
    page: page('<p>halaman biasa</p>', 'https://contoh.example/'),
    category: category(),
    ...overrides,
  })
}

describe('fuseEvidence — bentuk bukti', () => {
  it('setiap bukti membawa id, kategori, nilai amatan, sumber, kekuatan, ketersediaan, dan waktu', () => {
    const fusion = fuse({
      structure: structure('https://paypal.com@penipu.example/masuk'),
    })
    expect(fusion.evidence.length).toBeGreaterThan(0)
    for (const item of fusion.evidence) {
      expect(item.id).toMatch(/^[a-z_]+:[a-z_]+$/)
      expect(item.source.length).toBeGreaterThan(0)
      expect(['strong', 'moderate', 'weak', 'mitigating']).toContain(item.strength)
      expect(['observed', 'unavailable', 'failed', 'not_applicable']).toContain(item.availability)
      expect(item.observedAt).toBe(AT)
      expect(item.detail.length).toBeGreaterThan(0)
    }
  })

  it('id bukti tidak pernah berulang', () => {
    const fusion = fuse({
      structure: structure('http://93.184.216.34:8080/%2540%252f%2540%252f%2540@paypal.com/x'),
      page: page('<img alt="PayPal"><form action="https://curi.example"><input type="password"></form>', 'https://contoh.example/'),
    })
    const ids = fusion.evidence.map((item) => item.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('memilah temuan merek ke kategori brand dan temuan skrip ke kategori script', () => {
    const fusion = fuse({
      structure: structure('https://paypa1.example/'),
      page: page('<script>eval("x")</script>', 'https://contoh.example/'),
    })
    expect(fusion.evidence.find((item) => item.id === 'brand:typosquat')?.category).toBe('brand')
    expect(fusion.evidence.find((item) => item.id === 'script:script_obfuscation')?.category).toBe('script')
  })
})

describe('fuseEvidence — anti penghitungan ganda', () => {
  const manyBrand = fuse({
    structure: structure('https://paypal-verify.paypaill.example/'),
    page: page('<img alt="PayPal"><a href="https://paypal.com/help">bantuan</a>', 'https://paypal-verify.paypaill.example/'),
  })

  const singleBrand = fuse({
    structure: structure('https://paypal-verify.example/'),
    page: page('<img alt="PayPal">', 'https://paypal-verify.example/'),
  })

  it('meruntuhkan banyak temuan merek menjadi satu butir bukti', () => {
    const brandItems = manyBrand.evidence.filter((item) => item.category === 'brand')
    expect(brandItems).toHaveLength(1)
    expect(brandItems[0]!.detail).toContain('dihitung satu kali')
  })

  it('skor naiknya kecil walau temuan merek banyak', () => {
    // Empat temuan merek berbobot sedang/lemah kalau dijumlah mentah menjadi 30+.
    expect(manyBrand.riskScore!).toBeLessThan(40)
    expect(manyBrand.riskScore!).toBeGreaterThanOrEqual(singleBrand.riskScore!)
  })

  it('bukti dari kategori berbeda tetap dihitung terpisah', () => {
    const fusion = fuse({
      structure: structure('http://93.184.216.34/login'),
      page: page('<form action="https://curi.example"><input type="password" name="otp"></form>', 'http://93.184.216.34/login'),
    })
    const categories = new Set(fusion.evidence.map((item) => item.category))
    expect(categories.has('url_structure')).toBe(true)
    expect(categories.has('form')).toBe(true)
  })
})

describe('fuseEvidence — bukti yang tidak tersedia', () => {
  it('RDAP yang gagal tidak mengubah skor apa pun', () => {
    const base = fuse()
    const withRdap = fuse({ registration: registration({ registration: null, outcome: 'failed', source: null, detail: 'gagal' }) })
    expect(withRdap.riskScore).toBe(base.riskScore)
    expect(withRdap.evidence.find((item) => item.category === 'registration')!.availability).toBe('failed')
    expect(withRdap.notEvaluated.join(' ')).toContain('RDAP')
  })

  it('domain tua dihitung sebagai bukti penurun, bukan pembersih', () => {
    const young = fuse({ registration: registration(answered(2)) })
    const old = fuse({ registration: registration(answered(1500)) })
    expect(old.evidence.some((item) => item.strength === 'mitigating')).toBe(true)
    expect(old.riskScore!).toBeLessThan(young.riskScore!)
  })

  it('penurun tidak pernah menghapus seluruh skor dan dibatasi', () => {
    const fusion = fuse({
      structure: structure('http://93.184.216.34:8080/@paypal'),
      registration: registration(answered(1500)),
    })
    expect(fusion.riskScore!).toBeGreaterThan(0)
    expect(fusion.riskScore!).toBeLessThanOrEqual(100)
  })

  it('halaman yang tidak dibuka tercatat sebagai tidak dinilai', () => {
    const fusion = fuse({ page: page(null, null) })
    expect(fusion.coverage.byCategory.find((entry) => entry.category === 'page_content')!.succeeded).toBe(0)
    expect(fusion.notEvaluated.join(' ')).toContain('HTML')
    expect(fusion.status).not.toBe('complete')
  })

  it('skor nol tetap dilaporkan nol, tidak dinaikkan', () => {
    const fusion = fuse()
    expect(fusion.riskScore).toBeLessThanOrEqual(10)
    expect(fusion.level).toBe('low')
  })
})

describe('fuseEvidence — cakupan dan keyakinan', () => {
  it('memisahkan skor, keyakinan, cakupan, dan status', () => {
    const fusion = fuse({ structure: structure('https://paypal.com@penipu.example/masuk') })
    expect(fusion).toHaveProperty('riskScore')
    expect(fusion).toHaveProperty('confidence')
    expect(fusion).toHaveProperty('coverage')
    expect(fusion).toHaveProperty('status')
    expect(fusion.coverage.totalChecks).toBeGreaterThan(0)
    expect(fusion.confidenceDetail).toContain('/')
  })

  it('keyakinan tinggi butuh cakupan lebar dan beberapa kategori bukti', () => {
    const thin = fuse({ structure: structure('https://paypa1.example/') })
    expect(['low', 'medium']).toContain(thin.confidence)
  })

  it('tanpa probe statusnya limited dan keyakinan tetap rendah', () => {
    const staticOnly = staticOnlyFusion({
      generatedAt: AT,
      structure: structure('https://paypal.com@penipu.example/masuk'),
      registrableDomain: 'penipu.example',
      hostname: 'penipu.example',
      reason: 'URL tidak dibuka karena memuat parameter sensitif.',
    })
    expect(staticOnly.status).toBe('limited')
    expect(staticOnly.confidence).toBe('low')
    expect(staticOnly.riskScore!).toBeLessThanOrEqual(60)
    expect(staticOnly.coverage.unavailable).toBeGreaterThan(staticOnly.coverage.succeeded)
  })

  it('penilaian hanya-teks tidak pernah menghasilkan level tinggi', () => {
    const staticOnly = staticOnlyFusion({
      generatedAt: AT,
      structure: structure('http://185.220.101.5:8080/%2540paypal@bank-bri.co.id/x'),
      registrableDomain: null,
      hostname: '185.220.101.5',
      reason: 'Target tidak dibuka.',
    })
    expect(['low', 'medium', 'unknown']).toContain(staticOnly.level)
  })
})

describe('fuseEvidence — peniruan merek butuh bukti dari sumbu lain', () => {
  function lexical(items: Array<[string, 'strong' | 'moderate' | 'weak']>): UrlStructureAnalysis {
    return {
      status: 'complete',
      findings: items.map(([code, strength]) => ({
        code: code as never,
        label: `${code} uji`,
        detail: `${code} uji untuk memeriksa aritmetika fusi.`,
        strength,
        evidence: code,
      })),
      hostname: 'penipu.example',
      scheme: 'https',
      port: null,
      labelCount: 2,
      registrableDomain: 'penipu.example',
      notes: [],
    }
  }

  const brandOnly = fuse({ structure: lexical([['brand_in_host', 'moderate']]) })
  const brandPlusOne = fuse({
    structure: lexical([
      ['brand_in_host', 'moderate'],
      ['risky_tld', 'weak'],
    ]),
  })
  const brandPlusTwo = fuse({
    structure: lexical([
      ['brand_in_host', 'moderate'],
      ['risky_tld', 'weak'],
      ['ip_literal', 'strong'],
    ]),
  })

  it('menambah sedikit hanya bila ada sumbu lain yang mendukung', () => {
    // 9, lalu 9+3+2, lalu 9+3+18+4: tambahan korelasi dibatasi dua tingkat.
    expect(brandOnly.riskScore).toBe(9)
    expect(brandPlusOne.riskScore).toBe(14)
    expect(brandPlusTwo.riskScore).toBe(34)
  })

  it('bukti non-merek yang berdiri sendiri tidak mendapat tambahan', () => {
    const solo = fuse({ structure: lexical([['risky_tld', 'weak'], ['ip_literal', 'strong']]) })
    expect(solo.riskScore).toBe(21)
  })

  it('menyatakan syarat peniruan merek pada catatan skor', () => {
    expect(brandPlusTwo.notes.join(' ')).toContain('hanya bila ada bukti dari sumbu lain')
  })
})

describe('registrableOf', () => {
  it('mengembalikan null untuk alamat IP dan host kosong', () => {
    expect(registrableOf('203.0.113.5')).toBeNull()
    expect(registrableOf('[2001:db8::1]')).toBeNull()
    expect(registrableOf('')).toBeNull()
  })

  it('memperkirakan domain registrable untuk nama host', () => {
    expect(registrableOf('login.secure.paypal.com')).toBe('paypal.com')
    expect(registrableOf('tokopedia.harapan-meja.co.id')).toBe('harapan-meja.co.id')
  })
})

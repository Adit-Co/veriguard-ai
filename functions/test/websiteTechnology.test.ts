import { describe, expect, it } from 'vitest'
import { detectTechnologies, technologyRuleCount } from '../src/website/technology.js'
import type { TechnologyAnalysis } from '../src/website/types.js'

type Input = Parameters<typeof detectTechnologies>[0]

function detect(overrides: Partial<Input> = {}): TechnologyAnalysis {
  return detectTechnologies({
    headers: [],
    html: null,
    contentType: null,
    inspected: false,
    truncated: false,
    bytesScanned: 0,
    detail: 'Dokumen HTML diperiksa.',
    ...overrides,
  })
}

function htmlPage(body: string): string {
  return `<!doctype html><html lang="id"><head><meta charset="utf-8"><title>Uji</title></head><body>${body}</body></html>`
}

describe('detectTechnologies dengan bukti yang cukup', () => {
  it('mendeteksi WordPress dari jalur berkas dan meta generator', () => {
    const result = detect({
      html: htmlPage(
        '<link rel="stylesheet" href="/wp-content/themes/x/style.css"><script src="/wp-includes/js/jquery.js"></script><meta name="generator" content="WordPress 6.5">',
      ),
      inspected: true,
      contentType: 'text/html',
      bytesScanned: 200,
    })
    const wordpress = result.findings.find((entry) => entry.name === 'WordPress')
    expect(wordpress).toMatchObject({ category: 'cms', state: 'detected', confidence: 'high' })
    expect(wordpress?.evidence.length).toBeGreaterThan(1)
    expect(result.categories.find((entry) => entry.category === 'cms')?.state).toBe('found')
  })

  it('mendeteksi server hanya dari header dan menyebutnya sebagai sinyal header', () => {
    const result = detect({ headers: [['server', 'nginx/1.27.0']], contentType: 'text/html' })
    const nginx = result.findings.find((entry) => entry.name === 'nginx')
    expect(nginx).toMatchObject({ category: 'server', state: 'detected' })
    expect(nginx?.evidence[0]).toContain('server: nginx/1.27.0')
  })

  it('menandai aturan berpola longgar sebagai possible, bukan detected', () => {
    const result = detect({ html: htmlPage('<link rel="stylesheet" href="/assets/tailwind.css">'), inspected: true })
    const tailwind = result.findings.find((entry) => entry.name === 'Tailwind CSS')
    expect(tailwind?.state).toBe('possible')
    expect(result.status).toBe('partial')
  })

  it('tidak mengarang versi teknologi pada nama temuan', () => {
    const result = detect({
      html: htmlPage('<script src="/_next/static/chunks/main-react-dom@18.2.0.js"></script>'),
      inspected: true,
    })
    expect(result.findings.map((entry) => entry.name).sort()).toEqual(['Next.js', 'React'])
    expect(result.findings.every((entry) => !/\d+\.\d+/.test(entry.name))).toBe(true)
  })
})

describe('regresi pola longgar yang pernah salah klaim', () => {
  const ambiguous = htmlPage(`
    <a href="https://www.cloudflare.com/case-studies/shopify">Studi kasus Shopify</a>
    <img src="/images/produck.png" alt="gambar produk">
    <p>Toko memakai platform shopify dan mage tema kustom.</p>
    <div class="image-wrap"><span data-value="1">statis</span></div>
  `)

  it('tidak menyebut Shopify atau Magento dari teks dan jalur gambar', () => {
    const result = detect({ html: ambiguous, inspected: true, contentType: 'text/html' })
    const names = result.findings.map((entry) => entry.name)
    expect(names).not.toContain('Shopify')
    expect(names).not.toContain('Magento')
    expect(result.categories.find((entry) => entry.category === 'cms')?.state).toBe('no_signal')
  })

  it('tetap menyebut Shopify ketika asetnya benar-benar dimuat', () => {
    const result = detect({
      html: htmlPage('<script src="https://cdn.shopify.com/s/storefront.js"></script>'),
      inspected: true,
      contentType: 'text/html',
    })
    expect(result.findings.find((entry) => entry.name === 'Shopify')).toMatchObject({ state: 'detected' })
  })

  it('mengenali Magento hanya dari direktif khasnya', () => {
    const result = detect({
      html: htmlPage('<div data-mage-init=\'{"gallery":{}}\' src="/static/version123/base.js"></div>'),
      inspected: true,
    })
    const magento = result.findings.find((entry) => entry.name === 'Magento')
    expect(magento).toMatchObject({ category: 'cms', confidence: 'high' })
    expect(magento?.evidence.some((entry) => entry.includes('data-mage-init'))).toBe(true)
  })
})

describe('state tanpa sinyal berbeda dari tidak dapat dinilai', () => {
  it('menghasilkan no_signal ketika dokumen HTML tersedia tanpa pola', () => {
    const result = detect({
      html: htmlPage('<p>halaman statis tanpa penanda</p>'),
      inspected: true,
      contentType: 'text/html',
      bytesScanned: 90,
    })
    expect(result.findings).toEqual([])
    expect(result.categories.every((entry) => entry.state === 'no_signal' || entry.state === 'unavailable')).toBe(true)
    const cms = result.categories.find((entry) => entry.category === 'cms')
    expect(cms?.state).toBe('no_signal')
    expect(cms?.detail).toContain('bukan bukti')
  })

  it('menghasilkan unavailable ketika dokumen tidak diambil', () => {
    const result = detect({
      html: null,
      inspected: false,
      detail: 'Halaman belum dibuka, jadi teknologi tidak dapat dinilai.',
    })
    expect(result.status).toBe('unavailable')
    expect(result.categories.every((entry) => entry.state === 'unavailable')).toBe(true)
    expect(result.notes.join(' ')).toContain('Halaman belum dibuka')
  })

  it('tidak melaporkan teknologi dari rujukan skrip ketika header kosong', () => {
    const result = detect({ html: null, headers: [], inspected: false })
    expect(result.findings).toEqual([])
    expect(result.document.inspected).toBe(false)
  })

  it('menyebutkan pemotongan dokumen pada catatan', () => {
    const result = detect({
      html: htmlPage('<script src="/wp-includes/x.js"></script>'),
      inspected: true,
      truncated: true,
      bytesScanned: 262144,
      contentType: 'text/html',
    })
    expect(result.notes.join(' ')).toContain('dipotong')
    expect(result.document.bytesScanned).toBe(262144)
  })
})

describe('batas hasil deteksi', () => {
  it('membatasi jumlah temuan dan bukti', () => {
    const page = htmlPage(
      [
        '<link href="/wp-content/a.css" rel="stylesheet"><script src="/wp-includes/b.js"></script>',
        '<script src="/media/system/js/c.js"></script><div class="drupal-settings-json"></div>',
        '<script src="https://cdn.shopify.com/x.js"></script><script src="https://static.wixstatic.com/y.js"></script>',
        '<script src="https://static1.squarespace.com/z.js"></script><div data-mage-init="{}"></div>',
        '<script src="/typo3conf/ext/a.js"></script><meta name="generator" content="Ghost">',
        '<meta name="generator" content="Blogger"><div data-reactroot></div>',
        '<script src="/_next/static/chunks/a.js"></script><script src="/_nuxt/app.js"></script>',
        '<app ng-version="17.0"></app><div data-v-1234 class="svelte-abc astro-cid"></div>',
        '<script src="/preact.js"></script><script src="/jquery.min.js"></script>',
        '<link href="/bootstrap.min.css" rel="stylesheet"><link href="/tailwind.css" rel="stylesheet">',
        '<link href="/font-awesome.min.css" rel="stylesheet"><link href="https://fonts.googleapis.com/css"></link>',
        '<script src="/mathjax.js"></script><div x-data="{}" hx-get="/a"></div>',
        '<script src="https://www.googletagmanager.com/gtm.js?id=X"></script>',
        '<script src="https://www.google-analytics.com/analytics.js"></script>',
        '<script src="https://connect.facebook.net/en_US/fbevents.js"></script>',
        '<script src="/matomo.js"></script><script src="https://static.hotjar.com/c/hotjar.js"></script>',
        '<script src="https://mc.yandex.ru/metrika/tag.js"></script><script src="https://plausible.io/js/p.js"></script>',
        '<script src="https://cloudflareinsights.com/beacon.js"></script>',
        '<script src="https://www.google.com/recaptcha/api.js"></script>',
        '<script src="https://hcaptcha.com/1/api.js"></script>',
        '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>',
        '<script src="https://js.stripe.com/v3/"></script>',
      ].join('\n'),
    )

    const result = detect({ html: page, inspected: true, contentType: 'text/html' })
    expect(technologyRuleCount()).toBeGreaterThan(40)
    expect(result.findings.length).toBeLessThanOrEqual(30)
    expect(result.findings.every((entry) => entry.evidence.length <= 3)).toBe(true)
    expect(result.findings.every((entry) => entry.evidence.every((text) => text.length <= 140))).toBe(true)
  })

  it('memotong nilai header yang sangat panjang pada bukti', () => {
    const result = detect({ headers: [['server', `nginx/${'x'.repeat(500)}`]], contentType: 'text/html' })
    const nginx = result.findings.find((entry) => entry.name === 'nginx')
    expect(nginx?.evidence[0]).toContain('nginx')
    expect(nginx?.evidence[0].length).toBeLessThanOrEqual(140)
    expect(JSON.stringify(result.findings)).not.toContain('x'.repeat(200))
  })
})

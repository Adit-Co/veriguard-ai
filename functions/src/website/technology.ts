import type {
  TechnologyAnalysis,
  TechnologyCategory,
  TechnologyCategorySignal,
  TechnologyConfidence,
  TechnologyFinding,
} from './types.js'

type HeaderSignal = { name: string; contains?: string }
type HtmlSignal = { pattern: string; label: string; inLoadAttribute?: boolean }

type TechRule = {
  name: string
  category: TechnologyCategory
  confidence: TechnologyConfidence
  headers?: HeaderSignal[]
  html?: HtmlSignal[]
  both?: Array<{ name: string; pattern: string; label: string }>
}

const MAX_FINDINGS = 30
const MAX_EVIDENCE_PER_FINDING = 3
const EVIDENCE_LENGTH = 120

const RULES: TechRule[] = [
  // Web server / platform
  { name: 'nginx', category: 'server', confidence: 'high', headers: [{ name: 'server', contains: 'nginx' }] },
  { name: 'Apache', category: 'server', confidence: 'high', headers: [{ name: 'server', contains: 'apache' }] },
  { name: 'LiteSpeed', category: 'server', confidence: 'high', headers: [{ name: 'server', contains: 'litespeed' }] },
  { name: 'Microsoft IIS', category: 'server', confidence: 'high', headers: [{ name: 'server', contains: 'microsoft-iis' }] },
  { name: 'Caddy', category: 'server', confidence: 'high', headers: [{ name: 'server', contains: 'caddy' }] },
  { name: 'OpenResty', category: 'server', confidence: 'high', headers: [{ name: 'server', contains: 'openresty' }] },
  { name: 'Tomcat', category: 'server', confidence: 'high', headers: [{ name: 'server', contains: 'tomcat' }] },
  { name: 'Varnish', category: 'server', confidence: 'high', headers: [{ name: 'via', contains: 'varnish' }] },
  { name: 'Cloudflare', category: 'server', confidence: 'high', headers: [{ name: 'server', contains: 'cloudflare' }] },
  { name: 'Vercel', category: 'server', confidence: 'high', headers: [{ name: 'x-vercel-id' }] },
  { name: 'PHP', category: 'server', confidence: 'high', headers: [{ name: 'x-powered-by', contains: 'php' }] },
  { name: 'Express', category: 'server', confidence: 'high', headers: [{ name: 'x-powered-by', contains: 'express' }] },
  {
    name: 'ASP.NET',
    category: 'server',
    confidence: 'high',
    headers: [{ name: 'x-aspnet-version' }, { name: 'x-powered-by', contains: 'asp.net' }],
  },

  // CMS
  {
    name: 'WordPress',
    category: 'cms',
    confidence: 'high',
    html: [
      { pattern: '/wp-content/', label: 'jalur berkas /wp-content/' },
      { pattern: '/wp-includes/', label: 'jalur berkas /wp-includes/' },
      { pattern: '/wp-json/', label: 'endpoint /wp-json/' },
    ],
    both: [{ name: 'meta name="generator"', pattern: 'generator" content="wordpress', label: 'meta generator WordPress' }],
  },
  {
    name: 'Joomla',
    category: 'cms',
    confidence: 'high',
    html: [
      { pattern: '/media/system/js/', label: 'jalur berkas Joomla' },
      { pattern: 'generator" content="joomla', label: 'meta generator Joomla' },
    ],
  },
  {
    name: 'Drupal',
    category: 'cms',
    confidence: 'high',
    headers: [{ name: 'x-drupal-cache' }, { name: 'x-drupal-dynamic-cache' }],
    html: [
      { pattern: 'drupal-settings-json', label: 'blok drupalSettings' },
      { pattern: '/core/misc/drupal', label: 'jalur berkas Drupal core' },
    ],
  },
  {
    name: 'Shopify',
    category: 'cms',
    confidence: 'high',
    html: [
      {
        pattern: 'cdn.shopify.com',
        label: 'aset dimuat dari cdn.shopify.com',
        inLoadAttribute: true,
      },
      { pattern: 'shopify.theme', label: 'objek Shopify.theme pada skrip halaman' },
      { pattern: 'shopify.checkout', label: 'objek Shopify.checkout pada skrip halaman' },
    ],
  },
  {
    name: 'Wix',
    category: 'cms',
    confidence: 'high',
    html: [
      {
        pattern: 'static.wixstatic.com',
        label: 'aset dimuat dari static.wixstatic.com',
        inLoadAttribute: true,
      },
      { pattern: 'warmupurl', label: 'penanda bootstrap Wix' },
    ],
  },
  {
    name: 'Squarespace',
    category: 'cms',
    confidence: 'high',
    html: [
      {
        pattern: 'static1.squarespace.com',
        label: 'aset dimuat dari static1.squarespace.com',
        inLoadAttribute: true,
      },
    ],
  },
  {
    name: 'Magento',
    category: 'cms',
    confidence: 'medium',
    html: [
      { pattern: 'data-mage-init', label: 'attribut direktif data-mage-init' },
      { pattern: '/static/version', label: 'konvensi jalur statis Magento' },
      { pattern: 'mage/gallery/gallery', label: 'jalur modul mage/gallery/gallery' },
    ],
  },
  {
    name: 'TYPO3',
    category: 'cms',
    confidence: 'high',
    html: [{ pattern: 'typo3conf/ext/', label: 'jalur ekstensi typo3conf' }],
  },
  {
    name: 'Ghost',
    category: 'cms',
    confidence: 'medium',
    html: [{ pattern: 'generator" content="ghost', label: 'meta generator Ghost' }],
  },
  {
    name: 'Blogger',
    category: 'cms',
    confidence: 'high',
    html: [{ pattern: 'generator" content="blogger', label: 'meta generator Blogger' }],
  },

  // Frontend framework / library
  {
    name: 'React',
    category: 'frontend',
    confidence: 'medium',
    html: [
      { pattern: 'data-reactroot', label: 'attribut data-reactroot' },
      { pattern: 'react-dom', label: 'nama berkas react-dom' },
      { pattern: '/react@', label: 'jalur bundel React' },
    ],
  },
  {
    name: 'Next.js',
    category: 'frontend',
    confidence: 'high',
    html: [
      { pattern: '/_next/static/', label: 'jalur aset /_next/static/' },
      { pattern: '__next_data__', label: 'blob state __NEXT_DATA__' },
    ],
  },
  {
    name: 'Nuxt',
    category: 'frontend',
    confidence: 'high',
    html: [
      { pattern: '/_nuxt/', label: 'jalur aset /_nuxt/' },
      { pattern: '__nuxt', label: 'objek state __NUXT' },
    ],
  },
  {
    name: 'Angular',
    category: 'frontend',
    confidence: 'high',
    html: [
      { pattern: 'ng-version', label: 'attribut ng-version' },
      { pattern: 'ng-server-context', label: 'attribut ng-server-context' },
    ],
  },
  {
    name: 'Vue',
    category: 'frontend',
    confidence: 'medium',
    html: [
      { pattern: 'data-v-', label: 'attribut scoped CSS Vue (data-v-)' },
      { pattern: 'vue@', label: 'jalur bundel Vue' },
      { pattern: '__vue__', label: 'penanda __vue__' },
    ],
  },
  {
    name: 'Svelte',
    category: 'frontend',
    confidence: 'medium',
    html: [
      { pattern: 'svelte-', label: 'kelas bertanda svelte-' },
      { pattern: 'data-svelte', label: 'attribut data-svelte' },
    ],
  },
  {
    name: 'Astro',
    category: 'frontend',
    confidence: 'medium',
    html: [{ pattern: 'astro-cid', label: 'kelas bertanda astro-cid' }],
  },
  {
    name: 'Preact',
    category: 'frontend',
    confidence: 'medium',
    html: [{ pattern: 'preact', label: 'nama berkas/bundel Preact' }],
  },
  {
    name: 'jQuery',
    category: 'library',
    confidence: 'high',
    html: [
      { pattern: 'jquery.min.js', label: 'berkas jquery.min.js' },
      { pattern: 'jquery.js', label: 'berkas jquery.js' },
    ],
  },
  {
    name: 'Bootstrap',
    category: 'css',
    confidence: 'high',
    html: [
      { pattern: 'bootstrap.min.css', label: 'berkas bootstrap.min.css' },
      { pattern: 'bootstrap.bundle', label: 'berkas bootstrap.bundle' },
    ],
  },
  {
    name: 'Tailwind CSS',
    category: 'css',
    confidence: 'low',
    html: [
      { pattern: 'tailwind', label: 'nama berkas/tautan memuat "tailwind"' },
      { pattern: 'cdn.tailwindcss.com', label: 'muat dari cdn.tailwindcss.com' },
    ],
  },
  {
    name: 'Font Awesome',
    category: 'css',
    confidence: 'high',
    html: [
      { pattern: 'font-awesome', label: 'nama berkas font-awesome' },
      { pattern: 'fa-solid', label: 'kelas ikon fa-solid' },
      { pattern: 'kit.fontawesome.com', label: 'muat dari kit.fontawesome.com' },
    ],
  },
  {
    name: 'Google Fonts',
    category: 'other',
    confidence: 'high',
    html: [{ pattern: 'fonts.googleapis.com', label: 'tautan ke fonts.googleapis.com' }],
  },
  {
    name: 'MathJax',
    category: 'library',
    confidence: 'high',
    html: [{ pattern: 'mathjax', label: 'nama berkas/bundel MathJax' }],
  },
  {
    name: 'Alpine.js',
    category: 'library',
    confidence: 'high',
    html: [{ pattern: 'x-data=', label: 'attribut direktif x-data=' }],
  },
  {
    name: 'HTMX',
    category: 'library',
    confidence: 'high',
    html: [{ pattern: 'hx-', label: 'attribut direktif hx-' }],
  },

  // Analytics / marketing
  {
    name: 'Google Tag Manager',
    category: 'analytics',
    confidence: 'high',
    html: [
      { pattern: 'googletagmanager.com/gtm.js', label: 'memuat googletagmanager.com/gtm.js' },
      { pattern: 'googletagmanager.com/gtag/js', label: 'memuat gtag.js' },
    ],
  },
  {
    name: 'Google Analytics',
    category: 'analytics',
    confidence: 'high',
    html: [
      { pattern: 'google-analytics.com/analytics.js', label: 'memuat analytics.js' },
      { pattern: 'gtag(', label: 'pemanggilan gtag() pada skrip inline' },
    ],
  },
  {
    name: 'Meta Pixel',
    category: 'analytics',
    confidence: 'high',
    html: [
      { pattern: 'connect.facebook.net', label: 'memuat connect.facebook.net' },
      { pattern: 'fbq(', label: 'pemanggilan fbq() pada skrip inline' },
    ],
  },
  {
    name: 'Matomo',
    category: 'analytics',
    confidence: 'high',
    html: [
      { pattern: 'matomo.js', label: 'memuat matomo.js' },
      { pattern: 'piwik.js', label: 'memuat piwik.js' },
    ],
  },
  {
    name: 'Hotjar',
    category: 'analytics',
    confidence: 'high',
    html: [{ pattern: 'static.hotjar.com', label: 'memuat static.hotjar.com' }],
  },
  {
    name: 'Yandex Metrica',
    category: 'analytics',
    confidence: 'high',
    html: [{ pattern: 'mc.yandex', label: 'memuat mc.yandex' }],
  },
  {
    name: 'Plausible',
    category: 'analytics',
    confidence: 'high',
    html: [{ pattern: 'plausible.io', label: 'memuat plausible.io' }],
  },
  {
    name: 'Cloudflare Web Analytics',
    category: 'analytics',
    confidence: 'high',
    html: [{ pattern: 'cloudflareinsights.com/beacon', label: 'memuat beacon Cloudflare Insights' }],
  },
  {
    name: 'reCAPTCHA',
    category: 'other',
    confidence: 'high',
    html: [
      { pattern: 'google.com/recaptcha', label: 'memuat google.com/recaptcha' },
      { pattern: 'grecaptcha', label: 'objek grecaptcha pada skrip' },
    ],
  },
  {
    name: 'hCaptcha',
    category: 'other',
    confidence: 'high',
    html: [{ pattern: 'hcaptcha.com', label: 'memuat hcaptcha.com' }],
  },
  {
    name: 'Turnstile',
    category: 'other',
    confidence: 'high',
    html: [{ pattern: 'challenges.cloudflare.com/turnstile', label: 'memuat skrip Turnstile' }],
  },
  {
    name: 'Stripe',
    category: 'other',
    confidence: 'high',
    html: [
      { pattern: 'js.stripe.com', label: 'memuat js.stripe.com' },
      { pattern: 'stripe.js', label: 'nama berkas stripe.js' },
    ],
  },
]

const CATEGORY_ORDER: TechnologyCategory[] = [
  'frontend',
  'library',
  'css',
  'cms',
  'server',
  'analytics',
  'other',
]

const CATEGORY_LABEL: Record<TechnologyCategory, string> = {
  frontend: 'framework antarmuka',
  library: 'pustaka JavaScript',
  css: 'framework CSS',
  cms: 'sistem manajemen konten',
  server: 'server dan platform',
  analytics: 'analitik dan pelacakan',
  other: 'teknologi lain',
}

// Pola bertanda inLoadAttribute hanya dihitung bila muncul di dalam atribut src/href,
// sehingga sekadar menyebut nama vendor di teks artikel tidak dianggap bukti.
const LOAD_ATTRIBUTE_MATCHERS = new Map<string, RegExp>()

function loadAttributeMatcher(pattern: string): RegExp {
  const cached = LOAD_ATTRIBUTE_MATCHERS.get(pattern)
  if (cached) return cached
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const matcher = new RegExp(`(?:src|href|data-src|data-href)\\s*=\\s*["'][^"'<>]*${escaped}`)
  LOAD_ATTRIBUTE_MATCHERS.set(pattern, matcher)
  return matcher
}

function matchesHtmlSignal(html: string, signal: HtmlSignal): boolean {
  const pattern = signal.pattern.toLowerCase()
  return signal.inLoadAttribute
    ? loadAttributeMatcher(pattern).test(html)
    : html.includes(pattern)
}

function cleanEvidence(value: string): string {
  return value.replace(/[\u0000-\u001f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, EVIDENCE_LENGTH)
}

function headerMap(headers: Array<[string, string]>): Map<string, string> {
  const map = new Map<string, string>()
  for (const [name, value] of headers) {
    const lower = name.toLowerCase()
    const existing = map.get(lower)
    map.set(lower, existing ? `${existing}, ${value}` : value)
  }
  return map
}

type DetectInput = {
  headers: Array<[string, string]>
  html: string | null
  contentType: string | null
  inspected: boolean
  truncated: boolean
  bytesScanned: number
  detail: string
}

export function detectTechnologies(input: DetectInput): TechnologyAnalysis {
  const headers = headerMap(input.headers)
  const headersAvailable = headers.size > 0
  const html = input.html === null ? null : input.html.toLowerCase()
  const htmlAvailable = html !== null && html.length > 0
  const findings: TechnologyFinding[] = []
  const usedCategories = new Map<TechnologyCategory, TechnologyCategorySignal>()

  for (const category of CATEGORY_ORDER) {
    usedCategories.set(category, {
      category,
      state: 'unavailable',
      detail: 'Sumber data untuk kategori ini belum tersedia.',
    })
  }

  const mark = (
    category: TechnologyCategory,
    state: TechnologyCategorySignal['state'],
    detail: string,
  ): void => {
    const current = usedCategories.get(category)
    if (!current) return
    if (state === 'found' || current.state === 'unavailable') {
      usedCategories.set(category, { category, state, detail })
    }
  }

  for (const rule of RULES) {
    const evidence: string[] = []

    for (const signal of rule.headers ?? []) {
      const value = headers.get(signal.name.toLowerCase())
      if (value === undefined) continue
      if (signal.contains && !value.toLowerCase().includes(signal.contains)) continue
      evidence.push(`Header \`${signal.name}: ${cleanEvidence(value)}\`.`)
    }

    if (htmlAvailable) {
      for (const signal of rule.html ?? []) {
        if (matchesHtmlSignal(html, signal)) {
          evidence.push(`Dokumen HTML memuat ${signal.label} (${signal.pattern}).`)
        }
      }

      for (const signal of rule.both ?? []) {
        if (html.includes(signal.pattern.toLowerCase())) {
          evidence.push(`Dokumen HTML memuat ${signal.label}.`)
        }
      }
    }

    if (evidence.length === 0) continue

    const headerOnly = (rule.headers ?? []).length > 0 && (rule.html ?? []).length === 0 && !(rule.both ?? []).length
    if (!headerOnly && !htmlAvailable) continue
    if (headerOnly && !headersAvailable) continue

    const strength: TechnologyConfidence =
      evidence.length > 1 && rule.confidence !== 'low' ? 'high' : rule.confidence

    mark(rule.category, 'found', `Terdeteksi: ${rule.name}.`)

    findings.push({
      name: rule.name,
      category: rule.category,
      evidence: evidence.slice(0, MAX_EVIDENCE_PER_FINDING),
      confidence: strength,
      state: strength === 'low' ? 'possible' : 'detected',
    })

    if (findings.length >= MAX_FINDINGS) break
  }

  for (const category of CATEGORY_ORDER) {
    const signal = usedCategories.get(category)
    if (!signal || signal.state === 'found') continue

    const rules = RULES.filter((rule) => rule.category === category)
    const needsHtml = rules.some((rule) => (rule.html ?? []).length > 0 || (rule.both ?? []).length > 0)
    const needsHeaders = rules.some((rule) => (rule.headers ?? []).length > 0)
    const assessable = (needsHtml && htmlAvailable) || (needsHeaders && headersAvailable)

    if (!assessable) {
      usedCategories.set(category, {
        category,
        state: 'unavailable',
        detail: htmlAvailable
          ? `Header respons tidak tersedia, jadi ${CATEGORY_LABEL[category]} yang hanya terlihat di header tidak dapat dinilai.`
          : `Dokumen ${CATEGORY_LABEL[category]} tidak dapat dinilai karena halaman tidak tersedia atau bukan HTML.`,
      })
      continue
    }

    usedCategories.set(category, {
      category,
      state: 'no_signal',
      detail: `Tidak ada sinyal pasif untuk ${CATEGORY_LABEL[category]}. Ini bukan bukti bahwa teknologi tersebut tidak dipakai.`,
    })
  }

  const notes = [
    'Deteksi hanya memakai sinyal pasif pada header respons dan teks HTML yang diterima; tidak ada skrip situs yang dijalankan.',
    'Daftar ini bukan daftar lengkap. Teknologi yang tidak muncul di sini tidak otomatis berarti tidak dipakai.',
    'Header seperti `server` dan `x-powered-by` dapat diubah atau disamarkan oleh pemilik situs, sehingga isinya bukan bukti mutlak.',
  ]

  if (input.truncated) {
    notes.push(
      `Dokumen HTML dipotong pada ${input.bytesScanned.toLocaleString('id-ID')} byte pertama; teknologi di luar potongan itu tidak dinilai.`,
    )
  }

  if (!htmlAvailable) {
    notes.push(input.detail)
  }

  const anyFound = findings.length > 0
  const anyUnavailable = [...usedCategories.values()].some((entry) => entry.state === 'unavailable')

  return {
    status: anyFound ? (anyUnavailable ? 'partial' : 'complete') : anyUnavailable ? 'unavailable' : 'partial',
    findings,
    categories: [...usedCategories.values()],
    document: {
      inspected: htmlAvailable,
      bytesScanned: input.bytesScanned,
      truncated: input.truncated,
      contentType: input.contentType,
      detail: input.detail,
    },
    notes,
  }
}

export function technologyRuleCount(): number {
  return RULES.length
}

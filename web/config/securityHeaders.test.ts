import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

// VGL: header keamanan disajikan Firebase Hosting dari firebase.json, bukan dari kode aplikasi,
// sehingga tidak ada test runtime yang menjaganya. Berkas ini mengunci isi CSP terhadap
// inventaris sumber daya yang benar-benar dipakai browser (lihat docs/LOCAL_DEVELOPMENT.md).
const FIREBASE_JSON = fileURLToPath(new URL('../../firebase.json', import.meta.url))

type HeaderEntry = { key: string; value: string }
type HeaderBlock = { source: string; headers: HeaderEntry[] }

function hostingHeaders(source: string): HeaderBlock {
  const config = JSON.parse(readFileSync(FIREBASE_JSON, 'utf8')) as {
    hosting: { headers: HeaderBlock[] }
  }
  const block = config.hosting.headers.find((entry) => entry.source === source)
  if (!block) throw new Error(`firebase.json tidak punya blok headers untuk ${source}`)
  return block
}

function csp(block: HeaderBlock): { key: string; value: string } | null {
  const entry = block.headers.find(
    (header) => header.key === 'Content-Security-Policy' || header.key === 'Content-Security-Policy-Report-Only',
  )
  return entry ? { key: entry.key, value: entry.value } : null
}

function directives(value: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const part of value.split(';')) {
    const trimmed = part.trim()
    if (!trimmed) continue
    const [name, ...rest] = trimmed.split(/\s+/)
    out[(name ?? '').toLowerCase()] = rest.join(' ')
  }
  return out
}

describe('header keamanan Firebase Hosting', () => {
  const block = hostingHeaders('**')

  it('menetapkan CSP tanpa unsafe-inline untuk skrip dan tanpa object-src', () => {
    const policy = csp(block)
    expect(policy).not.toBeNull()
    const parsed = directives(policy!.value)

    expect(parsed['default-src']).toContain("'self'")
    expect(parsed['script-src']).toBeDefined()
    expect(parsed['script-src']).not.toContain('unsafe-inline')
    expect(parsed['script-src']).not.toContain('unsafe-eval')
    expect(parsed['object-src']).toBe("'none'")
    expect(parsed['frame-ancestors']).toBe("'none'")
    expect(parsed['base-uri']).toBe("'self'")
  })

  it('mencakup setiap sumber daya yang dimuat aplikasi dari luar origin', () => {
    const parsed = directives(csp(block)!.value)
    const scriptSrc = parsed['script-src'] ?? ''
    const connectSrc = parsed['connect-src'] ?? ''

    // Turnstile (skrip widget + iframe verifikasi).
    expect(scriptSrc).toContain('https://challenges.cloudflare.com')
    expect(parsed['frame-src'] ?? connectSrc).toContain('challenges.cloudflare.com')
    // App Check / reCAPTCHA enterprise dipuat dari google.com bila site key diisi.
    expect(scriptSrc).toContain('https://www.google.com')
    // Firebase SDK: Auth, token, Firestore, App Check, dan Functions callables.
    for (const host of [
      'https://identitytoolkit.googleapis.com',
      'https://securetoken.googleapis.com',
      'https://firestore.googleapis.com',
      'https://firebaseappcheck.googleapis.com',
      'https://content-firebaseappcheck.googleapis.com',
      // Functions callables dikunci ke origin proyek sendiri, bukan wildcard. Klien memakai
      // getFunctions(app, region) dengan region asia-southeast2 dan proyek YOUR_FIREBASE_PROJECT_ID;
      // bila region atau proyek berubah, firebase.json harus ikut diubah.
      'https://asia-southeast2-YOUR_FIREBASE_PROJECT_ID.cloudfunctions.net',
    ]) {
      expect(connectSrc).toContain(host)
    }
    expect(connectSrc).not.toContain('https://*.cloudfunctions.net')
    // Backend pemeriksaan reputasi.
    expect(connectSrc).toContain('https://YOUR_CLOUDFLARE_WORKER_HOST')
  })

  it('header dasar anti-sniffing dan penyangkalan frame tetap ada', () => {
    const keys = block.headers.map((header) => header.key)
    expect(keys).toContain('X-Content-Type-Options')
    expect(keys).toContain('X-Frame-Options')
    expect(keys).toContain('Referrer-Policy')
    expect(keys).toContain('Permissions-Policy')
    expect(block.headers.find((header) => header.key === 'X-Frame-Options')?.value).toBe('DENY')
  })

  it('CSP tidak memakai wildcard yang membuka connect-src', () => {
    const parsed = directives(csp(block)!.value)
    expect(parsed['connect-src']).not.toMatch(/(^|\s)\*(\s|;|$)/)
    expect(parsed['connect-src']).not.toContain('https://* ')
    expect(parsed['default-src']).not.toContain('*')
  })
})

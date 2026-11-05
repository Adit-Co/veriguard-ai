import { useEffect, useState } from 'react'
import { demoLoginAvailability } from './demoLogin'

/**
 * VGL-41E — penyamaran alamat email milik akun demo.
 *
 * Penentunya BUKAN teks email yang tampil di layar: daftar pencocokan diambil dari dev-server
 * lokal (jalur yang sama yang memiliki `web/config/demoAccounts.ts`) dan isinya hanya SHA-256
 * dari email yang sudah dinormalkan. Email akun yang sedang masuk dicocokkan ke daftar itu.
 * Karena jalurnya hanya terdaftar pada dev server dengan Emulator Firebase, build produksi
 * selalu menjawab "bukan akun demo" — di produksi memang tidak ada akun demo.
 */

const DEMO_IDENTITIES_ENDPOINT = '/__veriguard-demo/identities'

/** Bentuk samaran: lebar tetap, struktur email dipertahankan, tidak ada huruf yang tersisa. */
const MASK_SEGMENT = '••••••••'

let digestCache: Promise<ReadonlySet<string>> | null = null

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function digestEmail(email: string): Promise<string | null> {
  // Normalisasi harus sama persis dengan sisi dev-server (web/config/demoAccounts.ts).
  const normalized = email.trim().toLowerCase()
  if (!globalThis.crypto?.subtle) return null
  return toHex(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(normalized)))
}

function demoIdentityDigests(): Promise<ReadonlySet<string>> {
  if (!demoLoginAvailability().available) return Promise.resolve(new Set<string>())

  digestCache ??= fetch(DEMO_IDENTITIES_ENDPOINT, { headers: { accept: 'application/json' } })
    .then(async (response) => {
      if (!response.ok) return new Set<string>()
      const payload = (await response.json()) as { digests?: unknown }
      const list = Array.isArray(payload?.digests) ? payload.digests : []
      return new Set(list.filter((item): item is string => typeof item === 'string'))
    })
    .catch(() => new Set<string>())

  return digestCache
}

export async function isDemoAccountEmail(email: string | null | undefined): Promise<boolean> {
  if (!email) return false
  if (!demoLoginAvailability().available) return false

  const digests = await demoIdentityDigests()
  if (digests.size === 0) return false

  const digest = await digestEmail(email)
  return digest !== null && digests.has(digest)
}

export function maskDemoEmail(email: string): string {
  return email.includes('@') ? `${MASK_SEGMENT}@${MASK_SEGMENT}` : MASK_SEGMENT
}

/**
 * Teks email yang aman ditampilkan untuk akun yang sedang masuk.
 * `null` artinya tidak ada email. Selama akun belum dipastikan akun biasa yang dikembalikan
 * adalah samaran, jadi alamat asli tidak pernah sempat tampil lebih dulu.
 */
export function useDemoEmailText(email: string | null | undefined): string | null {
  const [resolved, setResolved] = useState<{ email: string; isDemo: boolean } | null>(null)

  useEffect(() => {
    if (!email) return
    let active = true
    void isDemoAccountEmail(email).then((isDemo) => {
      if (active) setResolved({ email, isDemo })
    })
    return () => {
      active = false
    }
  }, [email])

  if (!email) return null
  // Hanya akun yang sudah dipastikan biasa yang menampilkan alamat aslinya.
  return resolved?.email === email && !resolved.isDemo ? email : maskDemoEmail(email)
}

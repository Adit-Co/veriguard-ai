// @vitest-environment jsdom

import { webcrypto } from 'node:crypto'
import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

/**
 * VGL-41E — penyamaran email akun demo.
 *
 * Yang ditiru hanya SUMBER PERCAYAAN sisi server: pagar ketersediaan demo dan daftar digest yang
 * dikeluarkan dev-server. Pencocokannya memakai Web Crypto asli, jadi yang diuji adalah alur
 * pencocokan sesungguhnya, bukan pembacaan teks di layar.
 *
 * Modul dimuat ulang per test (import dinamis) karena daftar digest sengaja dicached per muatan
 * halaman; tanpa itu test saling mewarisi cache.
 */

const mocks = vi.hoisted(() => ({
  availability: vi.fn(),
}))

vi.mock('./demoLogin', () => ({
  demoLoginAvailability: mocks.availability,
}))

const DEMO_EMAIL = 'aleksatya4@gmail.com'
const DEMO_EMAIL_TWO = 'akusipemain@gmail.com'
const REGULAR_EMAIL = 'sari@example.com'

const fetchMock = vi.fn()

async function loadModule() {
  return import('./demoIdentity')
}

async function digestOf(email: string): Promise<string> {
  const bytes = new TextEncoder().encode(email.trim().toLowerCase())
  const buffer = await webcrypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function serve(payload: unknown, ok = true): void {
  fetchMock.mockResolvedValue({
    ok,
    status: ok ? 200 : 404,
    json: async () => payload,
  })
}

beforeEach(() => {
  vi.resetModules()
  vi.stubGlobal('crypto', webcrypto)
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
  mocks.availability.mockReturnValue({ available: true, reason: null })
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.resetModules()
})

describe('VGL-41E — akun demo dikenali dari daftar identitas server', () => {
  it('digest milik akun demo cocok, termasuk untuk variasi spasi dan huruf besar', async () => {
    serve({ digests: [await digestOf(DEMO_EMAIL), await digestOf(DEMO_EMAIL_TWO)] })
    const { isDemoAccountEmail } = await loadModule()

    await expect(isDemoAccountEmail(DEMO_EMAIL)).resolves.toBe(true)
    await expect(isDemoAccountEmail(DEMO_EMAIL.toUpperCase())).resolves.toBe(true)
    await expect(isDemoAccountEmail(`  ${DEMO_EMAIL} `)).resolves.toBe(true)
    await expect(isDemoAccountEmail(DEMO_EMAIL_TWO)).resolves.toBe(true)
  })

  it('akun biasa tidak dikenali sebagai akun demo', async () => {
    serve({ digests: [await digestOf(DEMO_EMAIL), await digestOf(DEMO_EMAIL_TWO)] })
    const { isDemoAccountEmail } = await loadModule()

    await expect(isDemoAccountEmail(REGULAR_EMAIL)).resolves.toBe(false)
  })

  it('pagar tertutup: tidak ada permintaan jaringan dan tidak ada penyamaran', async () => {
    mocks.availability.mockReturnValue({ available: false, reason: 'Login demo tidak diaktifkan.' })
    const { isDemoAccountEmail } = await loadModule()

    await expect(isDemoAccountEmail(DEMO_EMAIL)).resolves.toBe(false)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('jalur identitas tidak ada atau dev-server mati: tampilan tidak berubah dan tidak crash', async () => {
    serve({ digests: [] }, false)
    const mod = await loadModule()
    await expect(mod.isDemoAccountEmail(DEMO_EMAIL)).resolves.toBe(false)

    vi.resetModules()
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    const fresh = await loadModule()
    await expect(fresh.isDemoAccountEmail(DEMO_EMAIL)).resolves.toBe(false)
  })

  it('daftar identitas diminta sekali per muatan halaman', async () => {
    serve({ digests: [await digestOf(DEMO_EMAIL)] })
    const { isDemoAccountEmail } = await loadModule()

    await isDemoAccountEmail(DEMO_EMAIL)
    await isDemoAccountEmail(REGULAR_EMAIL)

    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('tanpa email tidak ada pencocokan', async () => {
    serve({ digests: [await digestOf(DEMO_EMAIL)] })
    const { isDemoAccountEmail } = await loadModule()

    await expect(isDemoAccountEmail(null)).resolves.toBe(false)
    await expect(isDemoAccountEmail(undefined)).resolves.toBe(false)
    await expect(isDemoAccountEmail('')).resolves.toBe(false)
  })
})

describe('VGL-41E — bentuk samaran', () => {
  it('tidak menyisakan bagian alamat asli dan lebarnya tidak berubah per alamat', async () => {
    const { maskDemoEmail } = await loadModule()
    const masked = maskDemoEmail(DEMO_EMAIL)

    expect(masked).toBe('••••••••@••••••••')
    expect(masked).not.toContain('aleksatya4')
    expect(masked).not.toContain('gmail')
    // Lebar tidak bergantung panjang alamat: baris tidak bergeser dan panjangnya tidak bocor.
    expect(maskDemoEmail(DEMO_EMAIL_TWO)).toBe(masked)
    expect(maskDemoEmail('a@b')).toBe(masked)
  })

  it('email tanpa domain disamar tanpa tanda @ yang menyesatkan', async () => {
    const { maskDemoEmail } = await loadModule()
    expect(maskDemoEmail('abc')).toBe('••••••••')
  })
})

describe('VGL-41E — teks yang dipakai komponen', () => {
  it('alamat asli tidak sempat tampil selama identifikasi belum selesai', async () => {
    const { useDemoEmailText, maskDemoEmail } = await loadModule()
    const pending: Array<(value: unknown) => void> = []
    fetchMock.mockImplementation(
      () =>
        new Promise((resolve) => {
          pending.push(resolve)
        }),
    )

    const { result } = renderHook(() => useDemoEmailText(REGULAR_EMAIL))
    // Permintaan identitas belum dijawab: yang tampil samaran, bukan alamat. Sifat ini yang
    // membuat akun demo tidak pernah "kedip" lebih dulu sebelum tersamar.
    expect(result.current).toBe(maskDemoEmail(REGULAR_EMAIL))
    expect(result.current).not.toBe(REGULAR_EMAIL)

    pending.at(-1)?.({ ok: true, status: 200, json: async () => ({ digests: [] }) })
    // Setelah diketahui akun biasa, alamat aslinya tampil seperti sebelumnya.
    await waitFor(() => expect(result.current).toBe(REGULAR_EMAIL))
  })

  it('akun demo tersamar, akun biasa tetap normal', async () => {
    serve({ digests: [await digestOf(DEMO_EMAIL)] })
    const { useDemoEmailText, maskDemoEmail } = await loadModule()

    const demo = renderHook(() => useDemoEmailText(DEMO_EMAIL))
    await waitFor(() => expect(demo.result.current).toBe(maskDemoEmail(DEMO_EMAIL)))

    const regular = renderHook(() => useDemoEmailText(REGULAR_EMAIL))
    await waitFor(() => expect(regular.result.current).toBe(REGULAR_EMAIL))
  })

  it('penggantian akun mengikuti akun yang sedang masuk, keadaan lama tidak tertinggal', async () => {
    serve({ digests: [await digestOf(DEMO_EMAIL), await digestOf(DEMO_EMAIL_TWO)] })
    const { useDemoEmailText, maskDemoEmail } = await loadModule()

    const { result, rerender } = renderHook(
      ({ email }: { email: string | null }) => useDemoEmailText(email),
      { initialProps: { email: DEMO_EMAIL as string | null } },
    )
    await waitFor(() => expect(result.current).toBe(maskDemoEmail(DEMO_EMAIL)))

    // Beralih ke akun biasa: yang tampil alamat aslinya, bukan samaran sesi sebelumnya.
    rerender({ email: REGULAR_EMAIL })
    await waitFor(() => expect(result.current).toBe(REGULAR_EMAIL))

    // Beralih ke akun demo kedua.
    rerender({ email: DEMO_EMAIL_TWO })
    await waitFor(() => expect(result.current).toBe(maskDemoEmail(DEMO_EMAIL_TWO)))

    // Keluar: tidak ada email, tidak ada teks sisa.
    rerender({ email: null })
    await act(async () => undefined)
    expect(result.current).toBeNull()
  })

  it('setelah halaman dimuat ulang, identitas dibaca lagi dari server (tidak disimpan di perangkat)', async () => {
    const digests = [await digestOf(DEMO_EMAIL)]
    serve({ digests })
    const first = await loadModule()
    await expect(first.isDemoAccountEmail(DEMO_EMAIL)).resolves.toBe(true)
    expect(window.localStorage.length).toBe(0)

    // Muatan ulang: modul baru, jadi daftar identitas diminta lagi ke dev-server.
    vi.resetModules()
    serve({ digests })
    const reloaded = await loadModule()
    await expect(reloaded.isDemoAccountEmail(DEMO_EMAIL)).resolves.toBe(true)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

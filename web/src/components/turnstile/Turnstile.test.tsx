// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

type WidgetOptions = {
  sitekey: string
  action: string
  appearance: string
  callback: (token: string) => void
  'expired-callback': () => void
  'error-callback': () => void
}

const api = vi.hoisted(() => ({
  render: vi.fn((_element: HTMLElement, _options: WidgetOptions) => 'widget-1'),
  remove: vi.fn(),
  execute: vi.fn(),
  refresh: vi.fn(),
  // Bisa dialihkan per test untuk mensimulasikan skrip yang gagal dimuat.
  load: { failing: false },
}))

vi.mock('../../lib/turnstile/script', () => ({
  loadTurnstileApi: () =>
    api.load.failing
      ? Promise.reject(new Error('skrip gagal dimuat'))
      : Promise.resolve(api),
}))

import { Turnstile } from './Turnstile'

describe('widget Turnstile', () => {
  beforeEach(() => {
    api.render.mockReset().mockReturnValue('widget-1')
    api.remove.mockReset()
    api.execute.mockReset()
    vi.stubEnv('VITE_TURNSTILE_SITE_KEY', 'SITEKEY-UJI')
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllEnvs()
  })

  it('merender widget dengan kunci situs dan aksi, lalu meneruskan token ke pemanggil', async () => {
    const onToken = vi.fn()
    render(<Turnstile action="register" onToken={onToken} />)

    await waitFor(() => expect(api.render).toHaveBeenCalledTimes(1))

    const call = api.render.mock.calls[0]
    if (!call) throw new Error('Widget tidak pernah ter-render.')
    const [element, options] = call
    expect(element).toBeInstanceOf(HTMLDivElement)
    expect(options).toMatchObject({
      sitekey: 'SITEKEY-UJI',
      action: 'register',
      appearance: 'always',
    })

    // Cloudflare memanggil callback ini setelah pengguna menyelesaikan tantangan.
    options.callback('token-dari-cloudflare')
    expect(onToken).toHaveBeenCalledWith('token-dari-cloudflare')
  })

  it('tidak merender apa pun ketika kunci situs belum dikonfigurasi', () => {
    vi.stubEnv('VITE_TURNSTILE_SITE_KEY', '')
    const { container } = render(<Turnstile action="scan" onToken={vi.fn()} />)

    expect(container.textContent).toBe('')
    expect(api.render).not.toHaveBeenCalled()
  })

  it('meminta token baru setiap kali percobaan naik, dan melepas widget saat lepas', async () => {
    const onToken = vi.fn()
    const { rerender } = render(<Turnstile action="scan" onToken={onToken} attempt={0} />)
    await waitFor(() => expect(api.render).toHaveBeenCalledTimes(1))

    rerender(<Turnstile action="scan" onToken={onToken} attempt={1} />)
    await waitFor(() => expect(api.execute).toHaveBeenCalledWith('widget-1'))

    rerender(<Turnstile action="scan" onToken={onToken} attempt={2} />)
    await waitFor(() => expect(api.execute).toHaveBeenCalledTimes(2))

    cleanup()
    expect(api.remove).toHaveBeenCalledWith('widget-1')
    expect(onToken).not.toHaveBeenCalled()
  })

  it('menandai tantangan kedaluwarsa agar token lama tidak dipakai lagi', async () => {
    const onExpire = vi.fn()
    render(<Turnstile action="scan" onToken={vi.fn()} onExpire={onExpire} />)
    await waitFor(() => expect(api.render).toHaveBeenCalledTimes(1))

    const call = api.render.mock.calls[0]
    if (!call) throw new Error('Widget tidak pernah ter-render.')
    call[1]['expired-callback']()
    expect(onExpire).toHaveBeenCalledTimes(1)
  })

  it('memisahkan galat widget dari token kedaluwarsa', async () => {
    const onExpire = vi.fn()
    const onError = vi.fn()
    render(<Turnstile action="scan" onToken={vi.fn()} onExpire={onExpire} onError={onError} />)
    await waitFor(() => expect(api.render).toHaveBeenCalledTimes(1))

    const call = api.render.mock.calls[0]
    if (!call) throw new Error('Widget tidak pernah ter-render.')
    call[1]['error-callback']()

    // Widget yang gagal tidak boleh tinggal sebagai kotak kosong tanpa pesan, dan tidak
    // boleh dilaporkan sebagai token kedaluwarsa karena penyebabnya berbeda.
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(onError).toHaveBeenCalledTimes(1)
    expect(onExpire).not.toHaveBeenCalled()
  })

  it('tetap memakai satu instance widget meski token datang berkali-kali', async () => {
    const onToken = vi.fn()
    render(<Turnstile action="register" onToken={onToken} />)
    await waitFor(() => expect(api.render).toHaveBeenCalledTimes(1))

    const call = api.render.mock.calls[0]
    if (!call) throw new Error('Widget tidak pernah ter-render.')
    call[1].callback('token-pertama')
    call[1].callback('token-kedua')

    // Tidak ada render ulang: halaman hanya boleh menampilkan satu widget CAPTCHA.
    expect(api.render).toHaveBeenCalledTimes(1)
    expect(document.querySelectorAll('[data-turnstile-widget]')).toHaveLength(1)
    expect(onToken).toHaveBeenCalledTimes(2)
  })

  it('menampilkan peringatan bila skrip verifikasi gagal dimuat', async () => {
    api.load.failing = true
    try {
      render(<Turnstile action="scan" onToken={vi.fn()} />)
      await waitFor(() => {
        const alert = document.querySelector('[role="alert"]')
        expect(alert?.textContent).toContain('Verifikasi tidak dapat dimuat')
      })
      expect(api.render).not.toHaveBeenCalled()
    } finally {
      api.load.failing = false
      cleanup()
    }
  })
})

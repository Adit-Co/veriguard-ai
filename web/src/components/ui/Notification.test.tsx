// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { useState, type ComponentProps } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ShieldCheck } from 'lucide-react'

import { Notification } from './Notification'

const TITLE = 'Layanan akun'
const BODY =
  'Autentikasi email dan kata sandi terhubung ke layanan akun yang tersedia. Jangan gunakan kata sandi yang sama dengan akun lain.'

function renderNotification(props: Partial<ComponentProps<typeof Notification>> = {}) {
  return render(
    <Notification
      title={TITLE}
      icon={<ShieldCheck size={18} aria-hidden="true" />}
      closeLabel="Tutup notifikasi layanan akun"
      {...props}
    >
      {BODY}
    </Notification>,
  )
}

const visibleCount = () => screen.getAllByRole('status').length

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

describe('notifikasi layanan akun saat halaman dibuka', () => {
  it('muncul otomatis dan memuat judul serta isi aslinya', () => {
    renderNotification()

    const panel = screen.getByRole('status')
    expect(panel.textContent).toContain(TITLE)
    expect(panel.textContent).toContain(BODY)
    expect(panel.getAttribute('aria-live')).toBe('polite')
  })

  it('tidak menampilkan angka hitungan mundur apa pun', () => {
    renderNotification()

    expect(screen.getByRole('status').textContent).not.toMatch(/\d/)
  })

  it('menyediakan tombol X dengan label yang jelas', () => {
    renderNotification()

    expect(screen.getByRole('button', { name: 'Tutup notifikasi layanan akun' })).toBeTruthy()
  })
})

describe('toast mengambang di bawah navbar (VGL-37A)', () => {
  it('memuat nama aplikasi dan label informasi layanan akun', () => {
    renderNotification()

    const panel = screen.getByRole('status')
    expect(panel.textContent).toContain('VERIGUARD AI')
    expect(panel.textContent).toContain('Informasi layanan akun')
    expect(panel.textContent).toContain(TITLE)
    expect(panel.textContent).toContain(BODY)
  })

  it('diletakkan sebagai lapisan fixed di atas konten, bukan di dalam alur kartu', () => {
    const { container } = renderNotification()

    const layer = container.firstElementChild
    expect(layer?.className).toContain('fixed')
    expect(layer?.className).toContain('z-50')
    expect(layer?.className).toContain('pointer-events-none')

    const panel = screen.getByRole('status')
    expect(panel.className).toContain('pointer-events-auto')
    expect(panel.closest('section[class*="shadow-card"]')).toBeNull()
  })

  it('menyediakan tombol X di panel paling kanan atas', () => {
    renderNotification()

    const close = screen.getByRole('button', { name: 'Tutup notifikasi layanan akun' })
    const row = close.parentElement
    expect(row?.className).toContain('items-start')
    expect(row?.lastElementChild).toBe(close)
  })
})

describe('menutup notifikasi', () => {
  it('X menutup notifikasi setelah animasi keluar', () => {
    renderNotification()

    fireEvent.click(screen.getByRole('button', { name: 'Tutup notifikasi layanan akun' }))
    // Sisa animasi masih berjalan, lalu elemen benar-benar dilepas.
    act(() => {
      vi.advanceTimersByTime(100)
    })
    expect(screen.queryByRole('status')).toBeTruthy()
    act(() => {
      vi.advanceTimersByTime(200)
    })
    expect(screen.queryByRole('status')).toBeNull()
  })

  // VGL-37C mengubah kontrak durasi: bukan "30 detik lalu animasi keluar", melainkan
  // seluruh siklus (terlihat + animasi keluar + unmount) tuntas dalam batas 10 detik.
  it('siklus penuh selesai sebelum 10 detik', () => {
    renderNotification()

    act(() => {
      vi.advanceTimersByTime(9_600)
    })
    // 9,60 detik: masih terlihat penuh, animasi keluar belum dimulai.
    expect(visibleCount()).toBe(1)
    expect(screen.getByRole('status').className).toContain('opacity-100')

    act(() => {
      vi.advanceTimersByTime(150)
    })
    // 9,75 detik: animasi keluar sedang berjalan, elemen belum dilepas.
    expect(screen.getByRole('status').className).toContain('opacity-0')

    act(() => {
      vi.advanceTimersByTime(200)
    })
    // 9,95 detik: di bawah batas 10 detik, komponen sudah benar-benar hilang.
    expect(screen.queryByRole('status')).toBeNull()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('durasi 0 berarti tidak ada auto-dismiss', () => {
    renderNotification({ durationMs: 0 })

    act(() => {
      vi.advanceTimersByTime(120_000)
    })
    expect(visibleCount()).toBe(1)
  })

  it('tidak meninggalkan timer aktif saat komponen dilepas', () => {
    const { unmount } = renderNotification()

    act(() => {
      vi.advanceTimersByTime(1_000)
    })
    expect(vi.getTimerCount()).toBeGreaterThan(0)

    unmount()
    expect(vi.getTimerCount()).toBe(0)

    // Memajukan waktu setelah lepas tidak boleh memicu error setState.
    act(() => {
      vi.advanceTimersByTime(60_000)
    })
    expect(screen.queryByRole('status')).toBeNull()
  })
})

describe('notifikasi di tengah render ulang', () => {
  it('tetap satu instance ketika induknya render ulang', () => {
    function Parent() {
      const [, setTick] = useState(0)
      return (
        <div>
          <Notification title={TITLE} icon={<ShieldCheck size={18} aria-hidden="true" />}>
            {BODY}
          </Notification>
          <button type="button" onClick={() => setTick((tick) => tick + 1)}>
            Render ulang induk
          </button>
        </div>
      )
    }
    render(<Parent />)

    fireEvent.click(screen.getByRole('button', { name: 'Render ulang induk' }))
    fireEvent.click(screen.getByRole('button', { name: 'Render ulang induk' }))
    fireEvent.click(screen.getByRole('button', { name: 'Render ulang induk' }))

    expect(visibleCount()).toBe(1)
  })
})

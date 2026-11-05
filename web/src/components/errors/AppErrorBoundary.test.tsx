// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react'
import { RouterProvider, createMemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { RouteErrorPage } from '../../pages/RouteErrorPage'
import { AppErrorBoundary } from './AppErrorBoundary'

function Bomb(): never {
  throw new Error('pesan rahasia yang tidak boleh tampil')
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('batas kegagalan tampilan', () => {
  it('menampilkan fallback generik tanpa membocorkan detail error', () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined)

    render(
      <AppErrorBoundary>
        <Bomb />
      </AppErrorBoundary>,
    )

    expect(
      screen.getByRole('heading', { name: 'Halaman gagal ditampilkan' }),
    ).toBeTruthy()
    expect(screen.queryByText(/pesan rahasia/)).toBeNull()
    expect(
      screen.getByRole('button', { name: 'Muat ulang halaman' }),
    ).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Kembali ke beranda' })).toBeTruthy()
  })

  it('errorElement router menangkap kegagalan render halaman', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const router = createMemoryRouter(
      [{ path: '/', element: <Bomb />, errorElement: <RouteErrorPage /> }],
      { initialEntries: ['/'] },
    )

    render(<RouterProvider router={router} />)

    expect(
      await screen.findByRole('heading', { name: 'Halaman gagal ditampilkan' }),
    ).toBeTruthy()
  })
})

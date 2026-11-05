import { describe, expect, it } from 'vitest'
import { ExternalScanRequestError, externalScanErrorMessage } from './errors'

describe('pesan error pemeriksaan eksternal', () => {
  it('menerjemahkan kode Worker tanpa membocorkan pesan internal', () => {
    expect(
      externalScanErrorMessage(
        new ExternalScanRequestError('rate_limited', 'internal detail'),
      ),
    ).toBe('Batas pemeriksaan eksternal tercapai. Coba lagi nanti.')

    expect(
      externalScanErrorMessage(
        new ExternalScanRequestError('unauthenticated', 'internal detail'),
      ),
    ).toContain('Sesi akun tidak berlaku')

    expect(
      externalScanErrorMessage(
        new ExternalScanRequestError('worker_not_configured', 'internal detail'),
      ),
    ).toContain('belum tersedia pada versi ini')
  })

  it('membedakan pembatalan dari kegagalan layanan', () => {
    expect(
      externalScanErrorMessage(
        new ExternalScanRequestError('cancelled', 'internal detail'),
      ),
    ).toBe('Pemeriksaan eksternal dibatalkan.')
  })

  it('memakai pesan kode yang belum dikenal sebagai fallback', () => {
    expect(
      externalScanErrorMessage(
        new ExternalScanRequestError('provider_quota_reached', 'Kuota provider habis.'),
      ),
    ).toBe('Kuota provider habis.')
  })

  it('menjelaskan Anonymous Auth yang belum diaktifkan', () => {
    const error = Object.assign(new Error('admin only'), {
      code: 'auth/admin-restricted-operation',
    })
    expect(externalScanErrorMessage(error)).toContain('Sesi tamu belum tersedia')
  })

  it('tetap memetakan timeout dan error callable lama', () => {
    expect(externalScanErrorMessage(new Error('timeout'))).toBe(
      'Pemeriksaan eksternal melebihi batas waktu.',
    )

    const callableError = Object.assign(new Error('unauthenticated'), {
      code: 'functions/unauthenticated',
    })
    expect(externalScanErrorMessage(callableError)).toContain('Sesi akun tidak berlaku')
  })
})

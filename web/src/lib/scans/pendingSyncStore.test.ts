// @vitest-environment jsdom

import { beforeEach, describe, expect, it } from 'vitest'
import { MAX_SAVED_SCANS } from '../storage/scanStore'
import {
  clearPendingSync,
  forgetPendingScan,
  PENDING_SYNC_STORAGE_KEY,
  pendingScanIds,
  rememberPendingScan,
  retainPendingScans,
} from './pendingSyncStore'

function stored(): string | null {
  return window.localStorage.getItem(PENDING_SYNC_STORAGE_KEY)
}

describe('antrean sinkronisasi riwayat', () => {
  beforeEach(() => {
    window.localStorage.clear()
    clearPendingSync()
  })

  it('menyimpan hanya id pemeriksaan, tanpa URL atau isi pesan', () => {
    rememberPendingScan('user-a', 'scan-1')

    expect(stored()).toBe(JSON.stringify({ uid: 'user-a', scanIds: ['scan-1'] }))
    expect(pendingScanIds('user-a')).toEqual(['scan-1'])
  })

  it('menggabungkan ulang id yang sama tanpa membuatnya dobel', () => {
    rememberPendingScan('user-a', 'scan-1')
    rememberPendingScan('user-a', 'scan-2')
    rememberPendingScan('user-a', 'scan-1')

    expect(pendingScanIds('user-a')).toEqual(['scan-1', 'scan-2'])
  })

  it('membatasi antrean sebanyak riwayat yang dapat disimpan perangkat', () => {
    for (let index = 0; index < MAX_SAVED_SCANS + 10; index += 1) {
      rememberPendingScan('user-a', `scan-${index}`)
    }

    expect(pendingScanIds('user-a')).toHaveLength(MAX_SAVED_SCANS)
  })

  it('membuang antrean akun lain dan tidak pernah bocor ke uid berbeda', () => {
    rememberPendingScan('user-a', 'scan-milik-a')

    expect(pendingScanIds('user-b')).toEqual([])
    expect(stored()).toBeNull()
    expect(pendingScanIds('user-a')).toEqual([])
  })

  it('melupakan satu entri yang sudah berhasil terkirim', () => {
    rememberPendingScan('user-a', 'scan-1')
    rememberPendingScan('user-a', 'scan-2')

    forgetPendingScan('user-a', 'scan-1')

    expect(pendingScanIds('user-a')).toEqual(['scan-2'])

    forgetPendingScan('user-a', 'scan-2')

    expect(stored()).toBeNull()
  })

  it('membuang id yang sudah tidak ada di penyimpanan riwayat', () => {
    rememberPendingScan('user-a', 'scan-1')
    rememberPendingScan('user-a', 'scan-2')

    retainPendingScans('user-a', ['scan-2'])

    expect(pendingScanIds('user-a')).toEqual(['scan-2'])
  })

  it('tidak mengubah antrean akun lain saat membersihkan id', () => {
    rememberPendingScan('user-a', 'scan-1')

    retainPendingScans('user-b', [])

    expect(pendingScanIds('user-a')).toEqual(['scan-1'])
  })

  it('mengabaikan id atau uid kosong', () => {
    rememberPendingScan('', 'scan-1')
    rememberPendingScan('user-a', '')

    expect(pendingScanIds('user-a')).toEqual([])
    expect(stored()).toBeNull()
  })

  it('antrean yang rusak tidak membuat halaman gagal', () => {
    window.localStorage.setItem(PENDING_SYNC_STORAGE_KEY, '{"uid":42,"scanIds":"scan-1"}')

    expect(pendingScanIds('user-a')).toEqual([])
  })

  it('penghapusan total melepas kunci antrean', () => {
    rememberPendingScan('user-a', 'scan-1')

    clearPendingSync()

    expect(stored()).toBeNull()
    expect(pendingScanIds('user-a')).toEqual([])
  })
})

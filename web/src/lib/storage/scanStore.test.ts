import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ScanDraft } from '../analysis/types'
import { REDACTED_PATH_SEGMENT } from '../scanners/privacy'
import {
  clearScans,
  createScan,
  deleteScan,
  getScan,
  listScans,
  MAX_SAVED_SCANS,
  redactAllMessageContents,
  saveScan,
  SCAN_RETENTION_MS,
  SCAN_STORAGE_KEY,
  toStoredScan,
} from './scanStore'

function makeDraft(input: string): ScanDraft {
  return {
    mode: 'link',
    input,
    displayTarget: input,
    riskScore: 0,
    riskLevel: 'low',
    headline: 'Indikasi risiko rendah',
    summary: 'Tidak banyak indikator risiko ditemukan.',
    reasons: [],
    patterns: [],
    recommendations: ['Verifikasi melalui kanal resmi.'],
    technical: [],
    meta: {
      engineVersion: 'test',
      signalCount: 0,
      inputLength: input.length,
      aiStatus: 'not_used',
    },
  }
}

function makeMessageDraft(input: string): ScanDraft {
  return { ...makeDraft(input), mode: 'message' }
}

function createMemoryStorage(): Storage {
  const values = new Map<string, string>()

  return {
    get length() {
      return values.size
    },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => {
      values.delete(key)
    },
    setItem: (key, value) => {
      values.set(key, value)
    },
  }
}

describe('penyimpanan riwayat lokal', () => {
  beforeEach(() => {
    clearScans()
  })

  it('menyimpan hasil dan memberinya id serta waktu', () => {
    const saved = saveScan(makeDraft('https://contoh.com'))

    expect(saved.id.length).toBeGreaterThan(0)
    expect(Number.isNaN(Date.parse(saved.createdAt))).toBe(false)
    expect(listScans().map((scan) => scan.input)).toEqual(['https://contoh.com'])
    expect(getScan(saved.id)?.input).toBe('https://contoh.com')
  })

  it('mengganti pemeriksaan identik alih-alih menduplikasinya', () => {
    const first = saveScan(makeDraft('https://contoh.com'))
    const second = saveScan(makeDraft('https://contoh.com'))

    expect(listScans()).toHaveLength(1)
    expect(second.id).not.toBe(first.id)
    expect(listScans()[0]?.id).toBe(second.id)
  })

  it(`membatasi riwayat pada ${MAX_SAVED_SCANS} pemeriksaan terbaru`, () => {
    for (let index = 0; index < MAX_SAVED_SCANS + 5; index += 1) {
      saveScan(makeDraft(`https://contoh.com/${index}`))
    }

    const scans = listScans()
    expect(scans).toHaveLength(MAX_SAVED_SCANS)
    expect(scans[0]?.input).toBe(`https://contoh.com/${MAX_SAVED_SCANS + 4}`)
    expect(scans.some((scan) => scan.input === 'https://contoh.com/0')).toBe(false)
  })

  it('menghapus satu pemeriksaan dan seluruh riwayat', () => {
    const first = saveScan(makeDraft('https://satu.com'))
    const second = saveScan(makeDraft('https://dua.com'))

    deleteScan(first.id)
    expect(getScan(first.id)).toBeNull()
    expect(listScans().map((scan) => scan.id)).toEqual([second.id])

    clearScans()
    expect(listScans()).toHaveLength(0)
  })

  it('menyamarkan isi pesan saat izin penyimpanan lengkap tidak diberikan', () => {
    const saved = saveScan(
      makeMessageDraft('Kirim OTP 123456 ke 0812-3456-7890 atau https://evil.example/login.'),
      { redactMessageInput: true },
    )

    expect(saved.meta.inputStored).toBe('redacted')
    expect(saved.input).not.toContain('123456')
    expect(saved.input).not.toContain('0812-3456-7890')
    expect(saved.input).not.toContain('evil.example')
    expect(saved.displayTarget).toBe(saved.input)
  })

  it('menyimpan isi pesan lengkap hanya ketika diminta', () => {
    const saved = saveScan(makeMessageDraft('Isi lengkap pesan dengan kode 123456.'))

    expect(saved.meta.inputStored).toBe('full')
    expect(saved.input).toContain('123456')
  })

  it('menyamarkan semua isi pesan lengkap yang tersimpan', () => {
    saveScan(makeMessageDraft('Kode 778899 dan tautan bit.ly/klaim tersimpan lengkap.'))
    saveScan(
      makeMessageDraft('Pesan lain 112233 ke https://evil.example.'),
      { redactMessageInput: true },
    )
    saveScan(makeDraft('https://contoh.com'))

    expect(redactAllMessageContents()).toBe(1)

    const scans = listScans()
    const messageScans = scans.filter((scan) => scan.mode === 'message')

    expect(messageScans).toHaveLength(2)
    expect(messageScans.every((scan) => scan.meta.inputStored === 'redacted')).toBe(true)
    expect(messageScans.some((scan) => scan.input.includes('778899'))).toBe(false)
    expect(messageScans.some((scan) => scan.input.includes('bit.ly'))).toBe(false)
    expect(redactAllMessageContents()).toBe(0)
  })

  it('mengabaikan JSON lokal yang rusak tanpa melempar error', () => {
    const storage = createMemoryStorage()
    storage.setItem(SCAN_STORAGE_KEY, '{bukan json')

    Object.defineProperty(globalThis, 'window', {
      value: { localStorage: storage },
      configurable: true,
    })

    try {
      expect(() => listScans()).not.toThrow()
      expect(listScans()).toEqual([])
    } finally {
      Reflect.deleteProperty(globalThis, 'window')
    }
  })

  it('menyaring pemeriksaan dengan data bersarang yang tidak valid', () => {
    const storage = createMemoryStorage()
    const valid = createScan(makeDraft('https://valid.example'))
    const broken = {
      ...createScan(makeDraft('https://broken.example')),
      id: 'broken',
      reasons: [{ id: 'alasan-tanpa-field-lain' }],
    }
    const invalidDate = {
      ...createScan(makeDraft('https://tanggal.example')),
      id: 'tanggal-rusak',
      createdAt: 'bukan-tanggal',
    }
    storage.setItem(SCAN_STORAGE_KEY, JSON.stringify([broken, invalidDate, valid]))

    Object.defineProperty(globalThis, 'window', {
      value: { localStorage: storage },
      configurable: true,
    })

    try {
      expect(listScans().map((scan) => scan.id)).toEqual([valid.id])
      expect(getScan('broken')).toBeNull()
      expect(getScan('tanggal-rusak')).toBeNull()
    } finally {
      Reflect.deleteProperty(globalThis, 'window')
    }
  })

  it('menyamarkan pesan lama yang tersimpan tanpa status izin', () => {
    const storage = createMemoryStorage()
    Object.defineProperty(globalThis, 'window', {
      value: { localStorage: storage },
      configurable: true,
    })

    try {
      const legacy = createScan(
        makeMessageDraft('Kirim OTP 654321 ke 0812-3456-7890 sekarang.'),
      )
      delete legacy.meta.inputStored
      storage.setItem(SCAN_STORAGE_KEY, JSON.stringify([legacy]))

      const [migrated] = listScans()
      expect(migrated?.meta.inputStored).toBe('redacted')
      expect(migrated?.input).not.toContain('654321')
      expect(migrated?.input).not.toContain('0812-3456-7890')

      const persisted = JSON.parse(storage.getItem(SCAN_STORAGE_KEY) ?? '[]') as Array<{
        meta: { inputStored?: string }
      }>
      expect(persisted[0]?.meta.inputStored).toBe('redacted')
    } finally {
      Reflect.deleteProperty(globalThis, 'window')
    }
  })
})

describe('privasi dan retensi riwayat lokal', () => {
  const TOKEN_URL = 'https://contoh.com/masuk?token=abcdef1234567890&email=user@example.com'

  function withStorage(storage: Storage) {
    vi.stubGlobal('window', { localStorage: storage })
  }

  beforeEach(() => {
    clearScans()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('tidak mengubah pemeriksaan yang memang tidak sensitif', () => {
    const scan = createScan(makeDraft('https://contoh.com/artikel/penipuan-otp'))

    expect(toStoredScan(scan)).toBe(scan)
  })

  it('menyamarkan URL sensitif hanya pada salinan yang disimpan', () => {
    const saved = saveScan(makeDraft(TOKEN_URL))

    expect(saved.input).toContain('token=abcdef1234567890')
    expect(saved.meta.inputStored).toBe('full')

    const [stored] = listScans()
    expect(stored?.input).toBe('https://contoh.com/masuk')
    expect(stored?.displayTarget).toBe('contoh.com/masuk')
    expect(stored?.meta.inputStored).toBe('redacted')
  })

  it('menyamarkan potongan URL yang berulang di teks indikator dan rincian teknis', () => {
    const token = 'abcdefghijklmnop123456'
    const draft: ScanDraft = {
      ...makeDraft(`https://contoh.com/reset/${token}?email=user%40contoh.com`),
      reasons: [
        {
          id: 'alasan-uji',
          label: 'Jalur mencurigakan',
          detail: `Jalur URL memuat "${token}" yang berbentuk token sekali pakai.`,
          severity: 'warning',
          weight: 8,
          category: 'url-structure',
        },
      ],
      technical: [{ label: 'Alamat diperiksa', value: `contoh.com/reset/${token}` }],
    }

    saveScan(draft)

    const [stored] = listScans()
    const raw = JSON.stringify(stored)
    expect(raw).not.toContain(token)
    expect(raw).not.toContain('user@contoh.com')
    expect(stored?.technical[0]?.value).toBe(`contoh.com/reset/${REDACTED_PATH_SEGMENT}`)
    expect(stored?.reasons[0]?.detail).toContain(REDACTED_PATH_SEGMENT)
  })

  it('menyamarkan riwayat lama yang tersimpan lengkap saat dibaca', () => {    const storage = createMemoryStorage()
    const legacy = createScan(makeDraft(TOKEN_URL))
    storage.setItem(SCAN_STORAGE_KEY, JSON.stringify([legacy]))
    withStorage(storage)

    const [migrated] = listScans()
    expect(migrated?.input).toBe('https://contoh.com/masuk')

    const persisted = JSON.parse(storage.getItem(SCAN_STORAGE_KEY) ?? '[]') as Array<{
      input: string
      meta: { inputStored?: string }
    }>
    expect(persisted[0]?.input).toBe('https://contoh.com/masuk')
    expect(persisted[0]?.meta.inputStored).toBe('redacted')
  })

  it('tidak menulis ulang penyimpanan saat membaca riwayat yang sudah aman', () => {
    const storage = createMemoryStorage()
    withStorage(storage)

    expect(saveScan(makeDraft(TOKEN_URL)).input).toContain('token=')
    listScans()

    const writes = vi.spyOn(storage, 'setItem')
    expect(listScans()[0]?.input).toBe('https://contoh.com/masuk')
    expect(writes.mock.calls.filter(([key]) => key === SCAN_STORAGE_KEY)).toHaveLength(0)
  })

  it('membuang pemeriksaan yang melewati masa retensi 90 hari', () => {
    const storage = createMemoryStorage()
    const aged = createScan(makeDraft('https://contoh.com/lama'))
    aged.createdAt = new Date(Date.now() - SCAN_RETENTION_MS - 60_000).toISOString()
    const fresh = createScan(makeDraft('https://contoh.com/baru'))
    storage.setItem(SCAN_STORAGE_KEY, JSON.stringify([aged, fresh]))
    withStorage(storage)

    expect(listScans().map((scan) => scan.id)).toEqual([fresh.id])
    expect(JSON.parse(storage.getItem(SCAN_STORAGE_KEY) ?? '[]')).toHaveLength(1)
  })
})

import { HttpsError } from 'firebase-functions/v2/https'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// Callable AI diimpor lewat modul index yang juga memuat jalur komunitas; jalur komunitas
// memanggil getFirestore() saat modul dimuat. Uji di file ini tidak pernah membaca Firestore,
// jadi stub kosong cukup dan membuat urutan gerbang bisa diperiksa tanpa emulator.
vi.mock('firebase-admin/app', () => ({
  getApps: () => [{ name: '[DEFAULT]' }],
  initializeApp: () => undefined,
}))

vi.mock('firebase-admin/firestore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('firebase-admin/firestore')>()
  return { ...actual, getFirestore: () => ({}) }
})

const { analyzeContentHandler, consumeAiRateLimit, resetAiRateLimit } = await import(
  '../src/index.js'
)

const BASE_UTC = Date.parse('2026-11-04T03:00:00Z')
const MESSAGE = 'Halaman ini meminta kata sandi bank lewat formulir yang menyerupai asli.'

// Jumlah percobaan jaringan yang benar-benar terjadi selama satu kasus uji.
const networkAttempts: string[] = []

function accountCall(uid: string, token: Record<string, unknown> = { firebase: { sign_in_provider: 'password' }, email_verified: true }) {
  return { auth: { uid, token }, data: { mode: 'message', content: MESSAGE } }
}

function codeOf(error: unknown): string | undefined {
  return error instanceof HttpsError ? error.code : undefined
}

async function rejectionCode(action: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await action()
  } catch (error) {
    return codeOf(error)
  }
  throw new Error('Backend seharusnya menolak permintaan ini.')
}

beforeEach(() => {
  resetAiRateLimit()
  networkAttempts.length = 0
  vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
    // Penghitung percobaan jaringan, bukan sekadar "pernah dipanggil". Gerbang biaya diuji dari
    // akibatnya: permintaan yang melewati kuota tidak boleh menghasilkan percobaan keluar.
    networkAttempts.push(String(input))
    throw new Error('Analisis AI tidak boleh memanggil jaringan sebelum kuota diperiksa.')
  })
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('gerbang biaya callable analisis AI', () => {
  it('menolak permintaan tanpa sesi login', async () => {
    await expect(
      rejectionCode(() => analyzeContentHandler({ auth: null, data: { mode: 'message', content: MESSAGE } })),
    ).resolves.toBe('unauthenticated')
  })

  it('menolak sesi anonim karena sesi tamu tidak punya tagihan di belakangnya', async () => {
    const code = await rejectionCode(() =>
      analyzeContentHandler(
        accountCall('guest-1', { firebase: { sign_in_provider: 'anonymous' } }),
      ),
    )

    expect(code).toBe('permission-denied')
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })

  it('menolak permintaan melebihi kuota sebelum menyentuh jaringan', async () => {
    const codes: Array<string | undefined> = []
    for (let index = 0; index < 21; index += 1) {
      codes.push(
        await analyzeContentHandler(accountCall('uid-hemat')).then(
          () => 'resolved',
          (error: unknown) => codeOf(error),
        ),
      )
    }

    // 20 permintaan pertama memperoleh jatah dan berlanjut ke tahap AI; permintaan ke-21 ditolak
    // kuota. Yang diuji di sini adalah urutannya: penolakan kuota terjadi tanpa percobaan
    // jaringan, jadi permintaan berlebih tidak dapat menimbulkan tagihan.
    //
    // Kode galat tahap AI sengaja TIDAK dikunci. SecretParam.value() hanya melempar ketika
    // FUNCTIONS_CONTROL_API bernilai "true" (kondisi deployment), sehingga di lingkungan uji secret
    // yang belum diisi mengembalikan string kosong dan jalur lanjut ke fetch. Kunci persis di sini
    // akan menguji perilaku param library, bukan gerbang biaya.
    expect(codes.slice(0, 20).every((code) => code !== 'resource-exhausted')).toBe(true)
    expect(codes[20]).toBe('resource-exhausted')
    expect(networkAttempts).toHaveLength(20)
  })

  it('memakai kuota per akun, bukan satu global untuk semua akun', async () => {
    for (let index = 0; index < 20; index += 1) {
      await analyzeContentHandler(accountCall('uid-pemakan')).catch(() => undefined)
    }

    expect(await rejectionCode(() => analyzeContentHandler(accountCall('uid-pemakan')))).toBe(
      'resource-exhausted',
    )

    const freshAccount = await analyzeContentHandler(accountCall('uid-baru')).then(
      () => 'resolved',
      (error: unknown) => codeOf(error),
    )
    // Akun baru punya jatahnya sendiri: ia tidak ikut ditolak kuota, sedangkan akun yang sudah
    // habis tetap ditolak. Sama seperti kasus sebelumnya, kode tahap AI tidak dikunci.
    expect(freshAccount).not.toBe('resource-exhausted')
    expect(networkAttempts).toHaveLength(21)
  })

  it('pencacah mengembalikan retryAfterSeconds yang masuk akal saat penuh', () => {
    for (let index = 0; index < 20; index += 1) {
      expect(consumeAiRateLimit('uid-satu', BASE_UTC + index * 1_000).allowed).toBe(true)
    }

    const blocked = consumeAiRateLimit('uid-satu', BASE_UTC + 20_000)
    expect(blocked.allowed).toBe(false)
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0)
    expect(blocked.retryAfterSeconds).toBeLessThanOrEqual(3_600)
  })

  it('reset membersihkan kuota sehingga tes dapat mengulang dari nol', () => {
    for (let index = 0; index < 20; index += 1) {
      consumeAiRateLimit('uid-reset', BASE_UTC)
    }
    expect(consumeAiRateLimit('uid-reset', BASE_UTC + 1_000).allowed).toBe(false)

    resetAiRateLimit()

    expect(consumeAiRateLimit('uid-reset', BASE_UTC + 1_000).allowed).toBe(true)
  })
})

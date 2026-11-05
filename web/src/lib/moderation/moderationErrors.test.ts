import { describe, expect, it } from 'vitest'
import {
  describeModerationError,
  moderationErrorMessage,
} from './moderationService'

const INDEX_URL =
  'https://console.firebase.google.com/v1/r/project/YOUR_FIREBASE_PROJECT_ID/firestore/indexes?create_exemption=abc123'
const INDEX_MESSAGE =
  `The query requires a COLLECTION_GROUP_ASC index for collection reports and field reporterKey. You can create it here: ${INDEX_URL}`

function firestoreError(code: string, message: string): Error {
  return Object.assign(new Error(message), { code })
}

describe('diagnostik error moderasi', () => {
  it('menampilkan kode dan tautan indeks untuk failed-precondition', () => {
    const info = describeModerationError(
      firestoreError('failed-precondition', INDEX_MESSAGE),
    )

    expect(info.kind).toBe('configuration')
    expect(info.code).toBe('failed-precondition')
    expect(info.message).toContain('konfigurasi data belum lengkap')
    expect(info.detail).toContain('COLLECTION_GROUP_ASC')
    expect(info.indexUrl).toBe(INDEX_URL)
    expect(moderationErrorMessage(firestoreError('failed-precondition', INDEX_MESSAGE))).toBe(
      info.message,
    )
  })

  it('membuang tautan indeks yang bukan dari konsol Firebase', () => {
    const info = describeModerationError(
      firestoreError(
        'failed-precondition',
        'The query requires an index. You can create it here: https://evil.example/indexes?create=1',
      ),
    )

    expect(info.kind).toBe('configuration')
    expect(info.indexUrl).toBeNull()
    expect(info.detail).toContain('evil.example')
  })

  it('membedakan penolakan izin tanpa membocorkan detail internal', () => {
    const info = describeModerationError(
      firestoreError('permission-denied', 'Missing or insufficient permissions.'),
    )

    expect(info.kind).toBe('permission')
    expect(info.code).toBe('permission-denied')
    expect(info.message).toContain('ditolak oleh sistem penyimpanan')
    expect(info.detail).toBeNull()
    expect(info.indexUrl).toBeNull()
  })

  it('membedakan masalah koneksi dari masalah konfigurasi', () => {
    for (const code of ['unavailable', 'deadline-exceeded']) {
      const info = describeModerationError(firestoreError(code, 'network down'))
      expect(info.kind).toBe('connection')
      expect(info.code).toBe(code)
      expect(info.indexUrl).toBeNull()
    }
  })

  it('mempertahankan pesan galat lokal yang tidak memiliki kode Firestore', () => {
    const info = describeModerationError(
      new Error('Verifikasi email akun terlebih dahulu.'),
    )

    expect(info.kind).toBe('unknown')
    expect(info.code).toBeNull()
    expect(info.message).toBe('Verifikasi email akun terlebih dahulu.')
  })

  it('merapikan detail multi-baris dan membatasi panjangnya', () => {
    const info = describeModerationError(
      firestoreError('failed-precondition', `${'x'.repeat(700)}\n\nselesai`),
    )

    expect(info.detail).not.toMatch(/\s{2,}/)
    expect(info.detail?.length).toBeLessThanOrEqual(501)
  })
})

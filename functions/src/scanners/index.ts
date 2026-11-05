import { HttpsError, onCall } from 'firebase-functions/v2/https'
import { runMultiSourceScan } from './service.js'
import { ScanUrlError } from './url.js'

const CALLABLE_OPTIONS = {
  region: 'asia-southeast2',
  timeoutSeconds: 55,
  memory: '512MiB',
  maxInstances: 10,
} as const

export const scanUrlMultiSource = onCall(CALLABLE_OPTIONS, async (request) => {
  if (!request.auth) {
    throw new HttpsError('unauthenticated', 'Masuk ke akun Firebase untuk memeriksa reputasi URL.')
  }

  if (!request.data || typeof request.data !== 'object') {
    throw new HttpsError('invalid-argument', 'Permintaan pemeriksaan tidak valid.')
  }

  const payload = request.data as Record<string, unknown>
  if (payload.consent !== true) {
    throw new HttpsError(
      'failed-precondition',
      'Persetujuan untuk mengirim URL ke provider eksternal diperlukan.',
    )
  }

  if (typeof payload.url !== 'string') {
    throw new HttpsError('invalid-argument', 'URL harus berupa teks.')
  }

  try {
    return await runMultiSourceScan({ uid: request.auth.uid, url: payload.url })
  } catch (error) {
    if (error instanceof ScanUrlError) {
      throw new HttpsError('invalid-argument', error.message)
    }
    throw new HttpsError('internal', 'Pemeriksaan reputasi gagal diproses.')
  }
})

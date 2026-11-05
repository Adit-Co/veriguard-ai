import { createHash, randomBytes } from 'node:crypto'
import type { ServerResponse } from 'node:http'
import type { Plugin } from 'vite'
import {
  DEMO_ACCOUNTS,
  DEMO_IDENTITIES_PATH,
  DEMO_SESSION_PATH,
  MAX_DEMO_REQUEST_BYTES,
  demoLoginAvailability,
  demoRequestErrorText,
  emulatorCustomToken,
  normalizeDemoEmail,
  parseDemoSessionRequest,
  type DemoAccount,
} from './demoAccounts.ts'

/**
 * Penyedia sesi demo LOKAL. Plugin ini hanya mendaftar pada dev server (`apply: 'serve'`)
 * dan hanya ketika pagar konfigurasi di demoLoginAvailability() lolos, sehingga artefak
 * build produksi tidak pernah memuat jalur ini maupun alamat akun demo.
 *
 * Peran tidak pernah diambil dari isi permintaan. Sisi server yang:
 *   1. membuat akun demo di Auth Emulator (kata sandi acak per proses, tidak pernah dikirim
 *      ke klien dan tidak pernah dicatat),
 *   2. menulis emailVerified + customAttributes akun lewat jalur ISTIMEWA emulator
 *      (`Authorization: Bearer owner`, ops/operations.js:750-774) — klaim admin berasal dari
 *      keadaan akun di server, dan muncul di ID token lewat generateJwt():1750,
 *   3. menulis/menghapus dokumen allowlist `admins/{uid}` di Firestore Emulator dengan token
 *      privileges yang sama, dan
 *   4. mencetak token custom KHAS EMULATOR (JSON berisi uid) yang dikonsumsi klien lewat
 *      signInWithCustomToken.
 * Terhadap produksi, seluruh langkah ini mustahil: token custom produksi wajib JWT bertanda
 * tangan service account proyek, dan tidak ada jalur aturan yang mengizinkan klien menulis
 * `admins/{uid}` (firestore.rules:825 `allow write: if false`).
 */

const EMULATOR_TIMEOUT_MS = 5_000
const ADMIN_ROLE = 'admin'
// Token istimewa khas emulator (firebase-tools: Authorization "Bearer owner"). Tidak ada
// padanannya di layanan produksi.
const EMULATOR_ADMIN_HEADERS = { authorization: 'Bearer owner' } as const

type EmulatorTargets = {
  authBase: string
  firestoreBase: string
  projectId: string
  apiKey: string
}

function documentUrl(targets: EmulatorTargets, resourcePath: string): string {
  return (
    `${targets.firestoreBase}/v1/projects/${encodeURIComponent(targets.projectId)}` +
    `/databases/(default)/documents/${resourcePath}`
  )
}

function readTargets(env: Record<string, string | undefined>): EmulatorTargets {
  const authBase = (env.VITE_AUTH_EMULATOR_URL ?? '').trim().replace(/\/+$/, '')
  const firestoreHost = (env.VITE_FIRESTORE_EMULATOR_HOST ?? '').trim()
  return {
    authBase,
    firestoreBase: `http://${firestoreHost}`.replace(/\/+$/, ''),
    projectId: (env.VITE_FIREBASE_PROJECT_ID ?? '').trim(),
    apiKey: (env.VITE_FIREBASE_API_KEY ?? '').trim(),
  }
}

async function postJson(
  url: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<Record<string, unknown>> {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(EMULATOR_TIMEOUT_MS),
  })

  const text = await response.text()
  if (!response.ok) {
    throw new Error(`Emulator menolak permintaan (${response.status}).`)
  }

  try {
    return JSON.parse(text) as Record<string, unknown>
  } catch {
    throw new Error('Respons emulator tidak dapat dibaca.')
  }
}

function localIdOf(lookup: Record<string, unknown>): string | null {
  const users = Array.isArray(lookup.users) ? lookup.users : []
  const first = users[0] as { localId?: unknown } | undefined
  return typeof first?.localId === 'string' && first.localId ? first.localId : null
}

async function ensureAccount(
  targets: EmulatorTargets,
  account: DemoAccount,
): Promise<string> {
  const base = `${targets.authBase}/identitytoolkit.googleapis.com/v1`
  const key = encodeURIComponent(targets.apiKey)
  const privileged = { authorization: 'Bearer owner' }

  const lookup = await postJson(
    `${base}/accounts:lookup?key=${key}`,
    { email: [account.email] },
    privileged,
  )

  let localId = localIdOf(lookup)

  if (!localId) {
    // Kata sandi acak hanya ada di proses dev-server ini dan tidak pernah dikirim ke klien:
    // masuk demo memakai token custom, bukan kata sandi.
    const created = await postJson(`${base}/accounts:signUp?key=${key}`, {
      email: account.email,
      password: randomBytes(24).toString('base64url'),
      displayName: account.displayName,
    })

    const candidate = created.localId
    if (typeof candidate !== 'string' || !candidate) {
      throw new Error('Akun demo tidak dapat dibuat di Auth Emulator.')
    }
    localId = candidate
  }

  // Jalur istimewa: email diverifikasi dan klaim ditulis pada keadaan akun, bukan di token.
  await postJson(
    `${base}/accounts:update?key=${key}`,
    {
      localId,
      emailVerified: true,
      displayName: account.displayName,
      customAttributes: JSON.stringify(account.role === ADMIN_ROLE ? { admin: true } : {}),
    },
    privileged,
  )

  return localId
}

async function deleteDocument(targets: EmulatorTargets, resourcePath: string): Promise<void> {
  const response = await fetch(documentUrl(targets, resourcePath), {
    method: 'DELETE',
    headers: EMULATOR_ADMIN_HEADERS,
    signal: AbortSignal.timeout(EMULATOR_TIMEOUT_MS),
  })

  // DELETE Firestore bersifat idempoten: dokumen yang belum ada tetap sukses.
  if (!response.ok) {
    throw new Error(`Firestore Emulator menolak penghapusan (${response.status}).`)
  }
}

/**
 * Allowlist admin ditulis HANYA oleh proses dev-server ini, memakai kredensial istimewa
 * emulator (`Bearer owner`) — jalur yang sama dengan `withSecurityRulesDisabled` pada suite
 * rules. Klien tidak punya jalur ini: `firestore.rules` menutup tulis `admins/{adminId}`.
 * Bentuk POST + documentId dipakai karena PATCH REST Firestore mensyaratkan updateMask;
 * menghapus lebih dulu membuat pembuatan ulang menjadi deterministik saat login demo
 * dijalankan berulang.
 */
async function writeAdminAllowlist(
  targets: EmulatorTargets,
  account: DemoAccount,
  uid: string,
): Promise<void> {
  const path = `admins/${encodeURIComponent(uid)}`

  if (account.role !== ADMIN_ROLE) {
    await deleteDocument(targets, path)
    return
  }

  await deleteDocument(targets, path)

  const created = await fetch(
    `${documentUrl(targets, 'admins')}?documentId=${encodeURIComponent(uid)}`,
    {
      method: 'POST',
      headers: { ...EMULATOR_ADMIN_HEADERS, 'content-type': 'application/json' },
      body: JSON.stringify({
        fields: {
          uid: { stringValue: uid },
          email: { stringValue: account.email },
          role: { stringValue: ADMIN_ROLE },
          active: { booleanValue: true },
          provisionedBy: { stringValue: 'local-demo-plugin' },
        },
      }),
      signal: AbortSignal.timeout(EMULATOR_TIMEOUT_MS),
    },
  )

  if (!created.ok) {
    throw new Error('Dokumen allowlist admin tidak dapat disiapkan di Firestore Emulator.')
  }
}

async function startDemoSession(
  targets: EmulatorTargets,
  account: DemoAccount,
): Promise<string> {
  const uid = await ensureAccount(targets, account)
  await writeAdminAllowlist(targets, account, uid)
  return emulatorCustomToken(uid)
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.statusCode = status
  response.setHeader('content-type', 'application/json; charset=utf-8')
  response.setHeader('cache-control', 'no-store')
  response.end(JSON.stringify(body))
}

/**
 * VGL-41E — daftar pencocokan akun demo. Yang keluar hanyalah SHA-256 dari email yang sudah
 * dinormalkan: alamat aslinya tidak pernah dikirim ke peramban dan tidak pernah dibundel.
 * Sumber datanya tetap DEMO_ACCOUNTS, jadi identifikasi tidak bergantung pada teks yang tampil
 * di layar maupun pada uid yang berubah setiap emulator dijalankan ulang.
 */
function demoIdentityDigests(): string[] {
  return Object.values(DEMO_ACCOUNTS).map((account) =>
    createHash('sha256').update(normalizeDemoEmail(account.email)).digest('hex'),
  )
}

export function demoSessionPlugin(env: Record<string, string | undefined>): Plugin {
  return {
    name: 'veriguard-demo-session',
    apply: 'serve',

    configureServer(server) {
      // Pagar dibaca ulang di sini: dev server tanpa flag tidak pernah mendaftarkan jalur
      // ini, jadi permintaan login demo berbalik 404 alih-alih menghasilkan sesi.
      if (!demoLoginAvailability(env).available) return

      const targets = readTargets(env)

      // VGL-41E — daftar pencocokan akun demo untuk penyamaran alamat email. Hanya digest SHA-256
      // yang keluar, tidak ada alamat email, dan jalur ini tidak terdaftar bila pagar demo tertutup.
      server.middlewares.use(DEMO_IDENTITIES_PATH, (request, response) => {
        if (request.method !== 'GET' && request.method !== 'HEAD') {
          sendJson(response, 405, { error: 'Hanya GET yang diterima untuk daftar identitas demo.' })
          return
        }

        sendJson(response, 200, { digests: demoIdentityDigests() })
      })

      server.middlewares.use(DEMO_SESSION_PATH, (request, response) => {
        if (request.method !== 'POST') {
          sendJson(response, 405, { error: 'Hanya POST yang diterima untuk sesi demo.' })
          return
        }

        const chunks: Buffer[] = []
        let size = 0

        request.on('data', (piece: Buffer) => {
          size += piece.length
          // Batas dihitung dalam byte, sama seperti batas yang dibaca saat parsing.
          if (size > MAX_DEMO_REQUEST_BYTES) {
            sendJson(response, 413, { error: demoRequestErrorText('too-large') })
            request.destroy()
            return
          }
          chunks.push(Buffer.from(piece))
        })

        request.on('end', () => {
          void (async () => {
            if (response.writableEnded) return

            const parsed = parseDemoSessionRequest(Buffer.concat(chunks).toString('utf8'))
            if ('error' in parsed) {
              sendJson(response, 400, { error: demoRequestErrorText(parsed.error) })
              return
            }

            const token = await startDemoSession(targets, parsed.account)
            sendJson(response, 200, {
              account: parsed.account.key,
              email: parsed.account.email,
              role: parsed.account.role,
              token,
            })
          })().catch(() => {
            // Kegagalan emulator dilaporkan apa adanya. Tidak ada login parsial dan tidak ada
            // fallback yang diam-diam menaikkan peran.
            sendJson(response, 502, {
              error: 'Emulator lokal tidak dapat menyiapkan sesi demo. Jalankan firebase emulators:start lalu coba lagi.',
            })
          })
        })
      })
    },
  }
}

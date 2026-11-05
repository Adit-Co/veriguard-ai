import * as http from 'node:http'
import * as fs from 'node:fs'
import * as net from 'node:net'
import * as path from 'node:path'
import { createWorker } from '../../workers/src/index.js'
import { MAX_BODY_BYTES } from '../../workers/src/limits.js'
import type { Env as WorkerEnv } from '../../workers/src/index.js'
import { createNodeSiteProbe } from './website/nodeProbe.js'
import { buildLocalSettings, parseEnvFile } from './env.js'
import {
  createLoginGuardHandler,
  createLoginGuardStore,
  defaultLoginGuardStateFile,
  type LoginGuardStore,
} from './loginGuard.js'

// Batas buffer lokal diambil dari batas Worker supaya keduanya tidak dapat bergeser.
// Sisa body tetap dialirkan tanpa disimpan agar Worker dapat membalas 413 dengan benar.
const MAX_BUFFERED_BODY_BYTES = MAX_BODY_BYTES

type NodeRequestListener = (
  request: http.IncomingMessage,
  response: http.ServerResponse,
) => Promise<void>

type HandlerFn = (request: Request, env: WorkerEnv) => Promise<Response>

export async function convertNodeRequest(
  request: http.IncomingMessage,
  host: string,
  port: number,
  signal: AbortSignal,
): Promise<Request> {
  const headers = new Headers()
  for (const [key, value] of Object.entries(request.headers)) {
    if (typeof value === 'string') headers.set(key, value)
    else if (Array.isArray(value)) headers.set(key, value.join(', '))
  }

  const normalizedIp = resolveConnectingIp({
    socketAddress: request.socket.remoteAddress?.trim() ?? '',
    incomingHeader: request.headers['cf-connecting-ip']?.toString() ?? null,
    trustEdgeHeader: trustEdgeConnectingIp(),
  })
  if (normalizedIp) headers.set('cf-connecting-ip', normalizedIp)
  else headers.delete('cf-connecting-ip')

  let body: Uint8Array | undefined
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    const chunks: Buffer[] = []
    let captured = 0
    for await (const chunk of request) {
      const buffer = chunk as Buffer
      const remaining = MAX_BUFFERED_BODY_BYTES - captured
      if (remaining <= 0) continue
      chunks.push(buffer.byteLength <= remaining ? buffer : buffer.subarray(0, remaining))
      captured += Math.min(buffer.byteLength, remaining)
    }
    if (chunks.length > 0) body = new Uint8Array(Buffer.concat(chunks))
  }

  const hostHeader = request.headers.host?.trim() || `${host}:${port}`
  const target = request.url ?? '/'
  return new Request(`http://${hostHeader}${target}`, {
    method: request.method ?? 'GET',
    headers,
    ...(body === undefined ? {} : { body }),
    signal,
  })
}

function normalizeIp(value: string): string {
  return value.trim().replace(/^::ffff:/i, '')
}

function isLoopbackAddress(value: string): boolean {
  const ip = normalizeIp(value)
  if (!ip) return false
  if (net.isIP(ip) === 4) return ip.startsWith('127.')
  return ip === '::1'
}

/**
 * Sumber alamat klien untuk gerbang cooldown.
 *
 * Bawaan: alamat socket selalu menang. Host lokal ini bisa berjalan tanpa proxy di depan, dan
 * header `cf-connecting-ip` kiriman klien tidak punya jaminan apa pun — memakainya akan membuat
 * penyerang tinggal memutar-mutar nilai header untuk melewati lapis per-IP.
 *
 * Bila operator menempatkan proxy di mesin yang sama (Cloudflare Tunnel/nginx), alamat socket
 * adalah loopback dan semua pengguna sah tampak sebagai satu IP. `TRUST_EDGE_CONNECTING_IP=true`
 * mengizinkan header dari edge dipakai, HANYA ketika peer yang menghubungkan adalah loopback.
 * Bentuk bertingkat (`1.2.3.4, 5.6.7.8`) tetap ditolak karena siapa pun bisa menulisnya.
 */
export function resolveConnectingIp(input: {
  socketAddress: string
  incomingHeader: string | null
  trustEdgeHeader: boolean
}): string {
  const socketIp = normalizeIp(input.socketAddress)
  const peerIsLoopback = isLoopbackAddress(input.socketAddress)
  const incoming = input.incomingHeader?.trim() ?? ''

  if (input.trustEdgeHeader && peerIsLoopback && net.isIP(incoming) !== 0) {
    return normalizeIp(incoming)
  }

  return socketIp
}

function trustEdgeConnectingIp(): boolean {
  return process.env.TRUST_EDGE_CONNECTING_IP?.trim() === 'true'
}

async function pipeBody(
  response: Response,
  serverResponse: http.ServerResponse,
  signal: AbortSignal,
): Promise<void> {
  const bodyStream = response.body
  if (!bodyStream) {
    serverResponse.end()
    return
  }

  serverResponse.flushHeaders()
  const reader = bodyStream.getReader()
  try {
    while (true) {
      if (signal.aborted) {
        await reader.cancel().catch(() => undefined)
        break
      }
      const { done, value } = await reader.read()
      if (done) break
      if (!serverResponse.write(value)) {
        await new Promise<void>((resolve) => {
          serverResponse.once('drain', resolve)
        })
      }
    }
    serverResponse.end()
  } catch {
    serverResponse.end()
  }
}

async function replayResponse(
  response: Response,
  serverResponse: http.ServerResponse,
  signal: AbortSignal,
): Promise<void> {
  const outHeaders: Record<string, string | string[]> = {}
  response.headers.forEach((value, key) => {
    const existing = outHeaders[key]
    if (existing === undefined) outHeaders[key] = value
    else if (Array.isArray(existing)) existing.push(value)
    else outHeaders[key] = [existing, value]
  })
  serverResponse.writeHead(response.status, outHeaders)
  await pipeBody(response, serverResponse, signal)
}

export type LoginGuardHandler = (request: Request) => Promise<Response | null>

export function createNodeRequestListener(
  settings: { host: string; port: number },
  env: WorkerEnv,
  overrides: Record<string, unknown> = {},
  // VGL-38 — gerbang cooldown login ditegakkan SEBELUM permintaan diteruskan ke Worker.
  // Rutenya milik host lokal ini saja; Worker produksi tidak ikut berubah.
  loginGuard: LoginGuardHandler | null = createLoginGuardHandler({
    store: createLoginGuardStore(),
    allowedOrigins: env.ALLOWED_ORIGINS,
  }),
): NodeRequestListener {
  const fetched = createWorker(overrides as never).fetch as HandlerFn | undefined
  if (typeof fetched !== 'function') {
    throw new Error('Handler lokal tidak dapat diinisialisasi.')
  }
  const handler = fetched

  return async function requestListener(request, serverResponse) {
    const controller = new AbortController()
    serverResponse.on('close', () => {
      if (!serverResponse.writableEnded) controller.abort()
    })

    try {
      const parsedRequest = await convertNodeRequest(
        request,
        settings.host,
        settings.port,
        controller.signal,
      )
      if (loginGuard) {
        const guarded = await loginGuard(parsedRequest)
        if (guarded) {
          await replayResponse(guarded, serverResponse, controller.signal)
          return
        }
      }
      const response = await handler(parsedRequest, env)
      await replayResponse(response, serverResponse, controller.signal)
    } catch {
      if (!serverResponse.headersSent) {
        serverResponse.writeHead(500, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
        })
      }
      if (!serverResponse.writableEnded) {
        serverResponse.end(
          '{"error":{"code":"internal","message":"Server lokal gagal memproses permintaan."}}',
        )
      }
    }
  }
}

export function startLocalServer(
  settings: { env: WorkerEnv; port: number; host: string },
  overrides: Record<string, unknown> = {},
  loginGuard?: LoginGuardHandler | null,
): http.Server {
  const listener = createNodeRequestListener(
    { host: settings.host, port: settings.port },
    settings.env,
    overrides,
    loginGuard,
  )
  const server = http.createServer(listener)
  server.listen(settings.port, settings.host)
  return server
}

export function loadSettings(cwd: string): { env: WorkerEnv; port: number; host: string } {
  const readFileOrNull = (file: string): string | null => {
    try {
      return fs.readFileSync(file, 'utf8')
    } catch {
      return null
    }
  }
  const candidates = [path.join(cwd, '.env'), path.join(cwd, '..', 'workers', '.dev.vars')]
  const files: Array<Record<string, string>> = []
  for (const file of candidates) {
    const content = readFileOrNull(file)
    if (content !== null) files.push(parseEnvFile(content))
  }
  return buildLocalSettings({ files, processEnv: process.env as Record<string, string> })
}

function describeMisconfiguration(env: WorkerEnv): string[] {
  const problems: string[] = []
  if (!env.URLSCAN_API_KEY?.trim()) {
    problems.push('URLSCAN_API_KEY (URLScan.io tidak akan berjalan)')
  }
  if (!env.VIRUSTOTAL_API_KEY?.trim()) {
    problems.push('VIRUSTOTAL_API_KEY (VirusTotal tidak akan berjalan)')
  }
  if (!env.THREATFOX_API_KEY?.trim()) {
    problems.push('THREATFOX_API_KEY (ThreatFox tidak akan berjalan)')
  }
  return problems
}

const LOCAL_DEV_ORIGINS = [5173, 5174, 5175, 5176, 5177].flatMap((port) => [
  `http://localhost:${port}`,
  `http://127.0.0.1:${port}`,
])

export function withLocalDevOrigins(configured: string | undefined): string {
  const entries = (configured ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
  return [...new Set([...entries, ...LOCAL_DEV_ORIGINS])].join(',')
}

export async function main(cwd: string = process.cwd()): Promise<void> {
  const settings = loadSettings(cwd)

  settings.env.ALLOWED_ORIGINS = withLocalDevOrigins(settings.env.ALLOWED_ORIGINS)

  // VGL-38 — keadaan cooldown disimpan di berkas sehingga restart proses tidak menghapus
  // cooldown yang masih berjalan. Isi berkas hanya HMAC, bukan email atau IP mentah.
  // LOGIN_GUARD_STATE_FILE dipakai probe lokal agar tidak menimpa berkas keadaan dev.
  const stateFile = process.env.LOGIN_GUARD_STATE_FILE?.trim() || defaultLoginGuardStateFile(cwd)
  const guardStore: LoginGuardStore = createLoginGuardStore({ stateFile })
  const loginGuard = createLoginGuardHandler({
    store: guardStore,
    allowedOrigins: settings.env.ALLOWED_ORIGINS,
  })

  const server = startLocalServer(
    settings,
    { siteProbe: createNodeSiteProbe() },
    loginGuard,
  )

  try {
    await new Promise<void>((resolve, reject) => {
      server.once('listening', () => resolve())
      server.once('error', reject)
    })
  } catch (error) {
    console.error(
      `Server lokal VERIGUARD gagal berjalan di ${settings.host}:${settings.port}.`,
      error instanceof Error ? error.message : error,
    )
    process.exit(1)
  }

  const missing = describeMisconfiguration(settings.env)
  if (missing.length > 0) {
    console.warn('[perhatian] Konfigurasi server belum lengkap:')
    for (const item of missing) {
      console.warn(`  - ${item} (isi di server/.env)`)
    }
  }

  console.log(`Server lokal VERIGUARD berjalan di http://${settings.host}:${settings.port}`)
  console.log(
    'Gerbang cooldown login VGL-38/VGL-39A aktif (/auth/login/gate/*) — 3 kesempatan per tingkat, keadaan tersimpan di ' +
      stateFile,
  )
  console.log('Origin diizinkan:')
  for (const origin of (settings.env.ALLOWED_ORIGINS ?? '').split(',')) {
    if (origin.trim()) console.log(`  - ${origin.trim()}`)
  }
}

const isDirectRun = process.argv[1]?.replace(/\\/g, '/').endsWith('/dist/server/src/index.js')
if (isDirectRun) {
  void main()
}

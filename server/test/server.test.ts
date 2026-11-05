import { once } from 'node:events'
import type { Server } from 'node:http'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { startLocalServer } from '../src/index.js'

type AddressInfo = { port: number }

const WORKER_ENV = {
  ALLOWED_ORIGINS: 'http://localhost:5173',
  RATE_LIMIT_MAX_PER_IP: '1000',
  RATE_LIMIT_WINDOW_SECONDS: '60',
  PROVIDER_CONCURRENCY: '4',
  URLSCAN_API_KEY: 'urlscan-key',
  VIRUSTOTAL_API_KEY: 'vt-key',
  THREATFOX_API_KEY: 'tf-key',
} as const

type MultiSourceFixture = {
  providers: Array<{
    id: string
    label: string
    status: string
    verdict: string
    score: number | null
    summary: string
    signals: never[]
    reason: string | null
    durationMs: number
  }>
  sharedWithProviders: never[]
  sensitiveUrl: boolean
  privacyReasons: never[]
  generatedAt: string
  durationMs: number
}

function multiSourceResponseFixture(): MultiSourceFixture {
  const definitions: Array<[string, string, string]> = [
    ['urlscan', 'URLScan.io', 'success'],
    ['virustotal', 'VirusTotal', 'success'],
    ['openphish', 'OpenPhish', 'success'],
    ['threatfox', 'ThreatFox (abuse.ch)', 'not_found'],
    ['radar', 'Cloudflare Radar URL Scanner', 'not_configured'],
    ['otx', 'AlienVault OTX', 'not_configured'],
    ['hybrid', 'Hybrid Analysis', 'not_configured'],
    ['safebrowsing', 'Google Safe Browsing', 'not_configured'],
  ]

  return {
    providers: definitions.map(([id, label, status]) => ({
      id,
      label,
      status,
      verdict: 'inconclusive',
      score: null,
      summary: `Ringkasan ${label}.`,
      signals: [],
      reason: null,
      durationMs: 0,
    })),
    sharedWithProviders: [],
    sensitiveUrl: false,
    privacyReasons: [],
    generatedAt: new Date(0).toISOString(),
    durationMs: 0,
  }
}

const LISTENER_OVERRIDES = {
  runScan: async (input: {
    onEvent?: (event: Record<string, unknown>) => Promise<void> | void
  }) => {
    const fixture = multiSourceResponseFixture()
    await input.onEvent?.({
      type: 'init',
      scanId: 'abcdefgh12345678',
      startedAt: fixture.generatedAt,
      sensitiveUrl: false,
      privacyReasons: [],
      providers: [],
    })
    return fixture
  },
  state: {
    consumeCounter: async () => ({ allowed: true, retryAfterSeconds: 0 }),
    consumeSiteWindow: async () => ({ allowed: true, retryAfterSeconds: 0 }),
    hasClearance: async () => false,
    issueClearance: async () => undefined,
  },
}

let server: Server
let port: number

beforeAll(async () => {
  server = startLocalServer(
    { env: { ...(WORKER_ENV as unknown as Record<string, string>) }, port: 0, host: '127.0.0.1' },
    LISTENER_OVERRIDES as never,
  )
  await once(server, 'listening')
  const address = server.address() as AddressInfo
  port = address.port
})

afterAll(async () => {
  server.close()
  await once(server, 'close')
})

const base = () => `http://127.0.0.1:${port}`

describe('server lokal VERIGUARD', () => {
  it('menolak origin yang tidak diizinkan', async () => {
    const response = await fetch(`${base()}/scan`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://evil.example' },
    })
    expect(response.status).toBe(403)
  })

  it('menerima preflight origin yang diizinkan', async () => {
    const response = await fetch(`${base()}/scan`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'http://localhost:5173',
        'Access-Control-Request-Method': 'POST',
      },
    })
    expect(response.status).toBe(204)
    expect(response.headers.get('access-control-allow-origin')).toBe('http://localhost:5173')
  })

  it('menolak content-type selain JSON', async () => {
    const response = await fetch(`${base()}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        Origin: 'http://localhost:5173',
      },
      body: 'url=https://example.com',
    })
    expect(response.status).toBe(415)
  })

  it('mewajibkan persetujuan pengiriman ke provider', async () => {
    const response = await fetch(`${base()}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'http://localhost:5173',
      },
      body: JSON.stringify({ url: 'https://example.com', consent: false }),
    })
    expect(response.status).toBe(400)
    const payload = (await response.json()) as { error: { code: string } }
    expect(payload.error.code).toBe('consent_required')
  })

  it('menjalankan scan tanpa token dan mengembalikan seluruh provider', async () => {
    const response = await fetch(`${base()}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'http://localhost:5173',
      },
      body: JSON.stringify({ url: 'https://example.com', consent: true }),
    })
    expect(response.status).toBe(200)
    const payload = (await response.json()) as {
      providers: Array<{ id: string; status: string }>
    }
    expect(payload.providers).toHaveLength(8)
    expect(payload.providers.map((provider) => provider.id)).toEqual([
      'urlscan',
      'virustotal',
      'openphish',
      'threatfox',
      'radar',
      'otx',
      'hybrid',
      'safebrowsing',
    ])
    expect(payload.providers.find((provider) => provider.id === 'virustotal')?.status).toBe(
      'success',
    )
    expect(
      payload.providers.find((provider) => provider.id === 'radar')?.status,
    ).toBe('not_configured')
  })

  it('mengirim hasil stream SSE untuk /scan/stream', async () => {
    const response = await fetch(`${base()}/scan/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'http://localhost:5173',
      },
      body: JSON.stringify({
        url: 'https://example.com',
        consent: true,
        scanId: 'abcdefgh12345678',
      }),
    })
    expect(response.status).toBe(200)
    expect(response.headers.get('content-type')).toContain('text/event-stream')
    const text = await response.text()
    expect(text).toContain('event: init')
    expect(text).toContain('event: done')
  })

  it('menolak scanId tidak valid pada stream', async () => {
    const response = await fetch(`${base()}/scan/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'http://localhost:5173',
      },
      body: JSON.stringify({
        url: 'https://example.com',
        consent: true,
        scanId: 'id pendek',
      }),
    })
    expect(response.status).toBe(400)
  })

  it('menolak body JSON yang rusak', async () => {
    const response = await fetch(`${base()}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'http://localhost:5173',
      },
      body: '{ tidak json',
    })
    expect(response.status).toBe(400)
  })

  it('membatasi body agar buffer server lokal tidak tumbuh tanpa batas', async () => {
    const response = await fetch(`${base()}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'http://localhost:5173',
      },
      body: JSON.stringify({
        url: 'https://example.com',
        consent: true,
        padding: 'x'.repeat(17_000),
      }),
    })
    expect(response.status).toBe(413)
    const payload = (await response.json()) as { error: { code: string } }
    expect(payload.error.code).toBe('payload_too_large')
  })

  it('mengembalikan 404 untuk path tak dikenal', async () => {
    const response = await fetch(`${base()}/api/lain`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'http://localhost:5173',
      },
      body: '{}',
    })
    expect(response.status).toBe(404)
  })
})

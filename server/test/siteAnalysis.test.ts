import { once } from 'node:events'
import type { Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { OriginRequest, SiteProbe } from '../../functions/src/website/types.js'
import type { ScanStateStore } from '../../workers/src/state/store.js'
import { createNodeSiteProbe } from '../src/website/nodeProbe.js'
import { startLocalServer } from '../src/index.js'

// Integrasi HTTP memakai probe Node asli sehingga wiring server ikut terbukti.
// Semua target di bawah ditolak guard sebelum probe dipakai, jadi tidak ada
// permintaan keluar ke sistem internal maupun internet saat pengujian ini berjalan.
const ORIGIN = 'http://localhost:5173'
const ENV = {
  ALLOWED_ORIGINS: ORIGIN,
  RATE_LIMIT_MAX_PER_IP: '1000',
  RATE_LIMIT_WINDOW_SECONDS: '60',
  PROVIDER_CONCURRENCY: '4',
  URLSCAN_API_KEY: 'urlscan-key',
  VIRUSTOTAL_API_KEY: 'vt-key',
  THREATFOX_API_KEY: 'tf-key',
} as const

type ProbeCall = { resolve: number; records: number; asn: number; tls: number; origin: number }

// P1-3: seluruh batas laju kini masuk lewat satu objek state. Tes HTTP ini fokus pada guard
// URL dan wiring probe, jadi gerbangnya dibuka eksplisit supaya angka limit memori bersama
// tidak ikut menentukan hasil.
function stubState(siteWindow?: ScanStateStore['consumeSiteWindow']): ScanStateStore {
  return {
    consumeCounter: async () => ({ allowed: true, retryAfterSeconds: 0 }),
    consumeSiteWindow: siteWindow ?? (async () => ({ allowed: true, retryAfterSeconds: 0 })),
    hasClearance: async () => false,
    issueClearance: async () => undefined,
  }
}

let server: Server
let port: number
let calls: ProbeCall
let scanCalls = 0

function countingProbe(inner: SiteProbe): SiteProbe {
  return {
    ...inner,
    resolve: (hostname, signal) => {
      calls.resolve += 1
      return inner.resolve(hostname, signal)
    },
    queryRecords: (hostname, type, signal) => {
      calls.records += 1
      return inner.queryRecords(hostname, type, signal)
    },
    lookupAsn: (address, signal) => {
      calls.asn += 1
      return inner.lookupAsn(address, signal)
    },
    inspectTls: (hostname, address, kind, target, signal) => {
      calls.tls += 1
      return inner.inspectTls(hostname, address, kind, target, signal)
    },
    openOrigin: (request: OriginRequest, signal) => {
      calls.origin += 1
      return inner.openOrigin(request, signal)
    },
  }
}

async function sitePost(
  body: unknown,
  headers: Record<string, string> = {},
): Promise<Response> {
  return fetch(`http://127.0.0.1:${port}/site/analysis`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Origin: ORIGIN,
      ...headers,
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}

async function errorCodeOf(response: Response): Promise<string> {
  const payload = (await response.json()) as { error?: { code?: string } }
  return payload.error?.code ?? ''
}

beforeAll(async () => {
  calls = { resolve: 0, records: 0, asn: 0, tls: 0, origin: 0 }
  scanCalls = 0
  server = startLocalServer(
    { env: { ...(ENV as unknown as Record<string, string>) }, port: 0, host: '127.0.0.1' },
    {
      siteProbe: countingProbe(createNodeSiteProbe({ dnsTimeoutMs: 1_500, tlsTimeoutMs: 2_000 })),
      state: stubState(),
      runScan: async () => {
        scanCalls += 1
        throw new Error('Enam agen tidak boleh berjalan untuk analisis situs.')
      },
    } as never,
  )
  await once(server, 'listening')
  port = (server.address() as AddressInfo).port
})

afterAll(async () => {
  server.close()
  await once(server, 'close')
})

describe('endpoint /site/analysis pada server lokal', () => {
  it('menolak target loopback dan tautan lokal sebelum probe menyentuh jaringan', async () => {
    const before = { ...calls }
    for (const url of [
      'http://127.0.0.1:8080/html',
      'http://localhost:8080/html',
      'http://127.1/html',
      'http://[::1]:8080/html',
      'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.5/',
      'http://192.168.1.1/',
      'ftp://example.com/',
    ]) {
      const response = await sitePost({ url, consent: true })
      expect(response.status).toBe(400)
      expect(await errorCodeOf(response)).toBe('invalid_url')
    }
    expect(calls).toEqual(before)
    expect(scanCalls).toBe(0)
  })

  it('melaporkan tidak tersedia untuk nama host layanan metadata, bukan mengarang data', async () => {
    const before = { ...calls }
    const response = await sitePost({ url: 'http://metadata.goog/computeMetadata/v1/', consent: true })
    expect(response.status).toBe(200)
    const report = (await response.json()) as {
      probe: { available: boolean }
      website: { status: string; notes: Array<string> }
      behavior: { status: string }
    }
    expect(report.probe.available).toBe(false)
    expect(report.website.status).toBe('unavailable')
    expect(report.website.notes.join(' ')).toContain('Tidak ada permintaan yang dikirim ke target')
    expect(report.behavior.status).toBe('unavailable')
    expect(calls).toEqual(before)
  })

  it('mewajibkan persetujuan dan body JSON serta metode POST', async () => {
    const consent = await sitePost({ url: 'https://example.com', consent: false })
    expect(consent.status).toBe(400)
    expect(await errorCodeOf(consent)).toBe('consent_required')

    const malformed = await sitePost('url=https://example.com', {
      'Content-Type': 'text/plain',
    })
    expect(malformed.status).toBe(415)

    const wrongMethod = await fetch(`http://127.0.0.1:${port}/site/analysis`, {
      method: 'GET',
      headers: { Origin: ORIGIN },
    })
    expect(wrongMethod.status).toBe(405)
    expect(wrongMethod.headers.get('allow')).toContain('POST')
  })

  it('menolak origin di luar daftar tanpa menjalankan probe', async () => {
    const before = { ...calls }
    const response = await sitePost(
      { url: 'https://example.com', consent: true },
      { Origin: 'https://evil.example' },
    )
    expect(response.status).toBe(403)
    expect(await errorCodeOf(response)).toBe('origin_not_allowed')
    expect(calls).toEqual(before)
  })

  it('meneruskan batas analitis ke pemanggil lewat header Retry-After', async () => {
    const limited = startLocalServer(
      { env: { ...(ENV as unknown as Record<string, string>) }, port: 0, host: '127.0.0.1' },
      {
        siteProbe: countingProbe(createNodeSiteProbe({ dnsTimeoutMs: 1_000 })),
        state: stubState(async () => ({ allowed: false, retryAfterSeconds: 42 })),
      } as never,
    )
    await once(limited, 'listening')
    const limitedPort = (limited.address() as AddressInfo).port

    const response = await fetch(`http://127.0.0.1:${limitedPort}/site/analysis`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: ORIGIN },
      body: JSON.stringify({ url: 'https://example.com', consent: true }),
    })
    expect(response.status).toBe(429)
    expect(await errorCodeOf(response)).toBe('site_rate_limited')
    expect(response.headers.get('retry-after')).toBe('42')

    limited.close()
    await once(limited, 'close')
  })
})

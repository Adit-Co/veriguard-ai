import { once } from 'node:events'
import * as http from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { runSiteAnalysis } from '../../functions/src/website/service.js'
import type { OriginRequest, SiteProbe } from '../../functions/src/website/types.js'
import { createNodeSiteProbe } from '../src/website/nodeProbe.js'

// Probe diuji terhadap listener loopback milik proyek ini sendiri. Sengaja memanggil
// probe.openOrigin langsung agar jalur jaringan Node bisa diamati tanpa menembus
// internet; guard URL diuji terpisah di bawah untuk memastikan loopback ditolak.
const HOST = '127.0.0.1'
const LOGICAL_HOSTNAME = 'veriguard-target.test'
const HTML_BODY =
  '<!doctype html><html lang="en"><head><title>Veriguard fixture</title></head><body>' +
  '<h1>Veriguard fixture</h1>' +
  '<script src="/app.js"></script>' +
  '<img src="/logo.png" alt="logo">' +
  '</body></html>'

type Fixture = {
  server: http.Server
  port: number
  origin: SiteProbe
  requests: Array<{ method: string; path: string; host: string | undefined }>
}

let fixture: Fixture

function buildServer(): { server: http.Server; requests: Fixture['requests'] } {
  const requests: Fixture['requests'] = []
  const server = http.createServer((request, response) => {
    requests.push({
      method: request.method ?? '',
      path: request.url ?? '',
      host: request.headers['host'],
    })
    const path = (request.url ?? '/').split('?')[0] ?? '/'
    // Header x-request-target dipakai supaya pengujian bisa memisahkan alamat
    // yang benar-benar dihubungi (pin IP) dari nama host logis pada header Host.
    response.setHeader('x-request-target', path)
    response.setHeader('server', 'veriguard-fixture/1')

    if (path === '/html') {
      response.setHeader('content-type', 'text/html; charset=utf-8')
      response.setHeader('x-powered-by', 'Veriguard Fixture')
      response.setHeader('date', new Date(0).toUTCString())
      response.end(HTML_BODY)
      return
    }
    if (path === '/redirect') {
      response.statusCode = 302
      response.setHeader('location', '/html')
      response.end('moved')
      return
    }
    if (path === '/cookies') {
      response.setHeader('content-type', 'text/html; charset=utf-8')
      response.setHeader('set-cookie', [
        'session=rahasia-user; Path=/; HttpOnly; Secure',
        'theme=dark; Path=/; SameSite=Lax',
      ])
      response.end(HTML_BODY)
      return
    }
    if (path === '/json') {
      response.setHeader('content-type', 'application/json; charset=utf-8')
      response.end(JSON.stringify({ marker: 'veriguard-json-fixture', padding: 'x'.repeat(400) }))
      return
    }
    if (path === '/big') {
      response.setHeader('content-type', 'text/html; charset=utf-8')
      response.end(`<!doctype html><html><body><p>${'a'.repeat(4096)}</p></body></html>`)
      return
    }
    if (path === '/slow') {
      // Sengaja tidak menjawab: pengujian timeout/abort mengakhiri sisi klien lebih dulu.
      const hold = setTimeout(() => {
        if (response.writableEnded || !response.writable) return
        response.setHeader('content-type', 'text/html; charset=utf-8')
        response.end('terlambat')
      }, 5_000)
      response.on('close', () => clearTimeout(hold))
      return
    }
    response.statusCode = 404
    response.setHeader('content-type', 'text/html; charset=utf-8')
    response.end('<!doctype html><html><body>tidak ditemukan</body></html>')
  })
  return { server, requests }
}

function originRequest(overrides: Partial<OriginRequest> = {}): OriginRequest {
  const port = fixture?.port ?? 0
  return {
    url: `http://${LOGICAL_HOSTNAME}:${port}/html`,
    address: HOST,
    kind: 'ipv4',
    hostname: LOGICAL_HOSTNAME,
    port,
    secure: false,
    maxBytes: 64 * 1024,
    timeoutMs: 2_000,
    userAgent: 'VERIGUARD-AI/4.0 (+analisis teknis defensif)',
    ...overrides,
  }
}

beforeAll(async () => {
  const { server, requests } = buildServer()
  server.listen(0, HOST)
  await once(server, 'listening')
  const address = server.address() as AddressInfo
  fixture = {
    server,
    port: address.port,
    origin: createNodeSiteProbe({ dnsTimeoutMs: 1_500, tlsTimeoutMs: 2_000 }),
    requests,
  }
})

afterAll(async () => {
  fixture.server.close()
  await once(fixture.server, 'close')
})

describe('node site probe membaca respons origin', () => {
  it('menghubungi alamat yang dipin sementara header Host memakai nama host logis', async () => {
    const result = await fixture.origin.openOrigin(originRequest())
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error('Origin seharusnya menjawab.')

    expect(result.status).toBe(200)
    expect(result.tls).toBeNull()
    expect(result.truncated).toBe(false)
    expect(result.bytes).toBeGreaterThan(0)
    expect(result.body).toContain('Veriguard fixture')
    expect(result.body).toContain('<script src="/app.js">')

    const headerPairs = new Map(result.headers)
    expect(headerPairs.get('server')).toBe('veriguard-fixture/1')
    expect(headerPairs.get('content-type')).toContain('text/html')
    expect(headerPairs.get('x-powered-by')).toBe('Veriguard Fixture')

    // Pin IP: koneksi dibuat ke 127.0.0.1, tetapi header Host membawa nama host logis.
    expect(result.headers).toContainEqual(['x-request-target', '/html'])
    expect(fixture.requests.at(-1)?.host).toBe(`${LOGICAL_HOSTNAME}:${fixture.port}`)
    expect(fixture.requests.at(-1)?.method).toBe('GET')
  })

  it('menyimpan path dan query dari URL target saat request dipin ke alamat', async () => {
    const result = await fixture.origin.openOrigin(
      originRequest({ url: `http://${LOGICAL_HOSTNAME}:${fixture.port}/html?utm=1&a=2` }),
    )
    expect(result.ok).toBe(true)
    expect(fixture.requests.at(-1)?.path).toBe('/html?utm=1&a=2')
  })

  it('mencatat status dan header redirect tanpa mengikutinya sendiri', async () => {
    const result = await fixture.origin.openOrigin(originRequest({ url: `http://${LOGICAL_HOSTNAME}:${fixture.port}/redirect` }))
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error('Origin seharusnya menjawab.')
    expect(result.status).toBe(302)
    expect(new Map(result.headers).get('location')).toBe('/html')
  })

  it('membaca header set-cookie mentah tanpa pernah menyingkap isinya lewat probe', async () => {
    const result = await fixture.origin.openOrigin(originRequest({ url: `http://${LOGICAL_HOSTNAME}:${fixture.port}/cookies` }))
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error('Origin seharusnya menjawab.')
    const cookieHeaders = result.headers.filter(([name]) => name === 'set-cookie')
    expect(cookieHeaders.length).toBeGreaterThan(0)
    // Probe hanyalah transport: penyaringan nilai cookie terjadi di lapisan layanan.
    expect(cookieHeaders.some(([, value]) => value.startsWith('session='))).toBe(true)
  })

  it('tidak mengambil body untuk konten non-HTML', async () => {
    const result = await fixture.origin.openOrigin(originRequest({ url: `http://${LOGICAL_HOSTNAME}:${fixture.port}/json` }))
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error('Origin seharusnya menjawab.')
    expect(result.body).toBe('')
    expect(result.bytes).toBeGreaterThan(0)
    expect(result.truncated).toBe(false)
  })

  it('memotong body pada batas byte dan tetap melaporkan total yang diterima', async () => {
    const result = await fixture.origin.openOrigin(
      originRequest({ url: `http://${LOGICAL_HOSTNAME}:${fixture.port}/big`, maxBytes: 64 }),
    )
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error('Origin seharusnya menjawab.')
    expect(result.truncated).toBe(true)
    expect(result.body.length).toBeLessThanOrEqual(64)
    expect(result.body).toContain('<!doctype html>')
    expect(result.bytes).toBeGreaterThan(64)
  })

  it('melaporkan timeout ketika origin tidak menjawab dalam batas waktu', async () => {
    const result = await fixture.origin.openOrigin(
      originRequest({ url: `http://${LOGICAL_HOSTNAME}:${fixture.port}/slow`, timeoutMs: 250 }),
    )
    expect(result.ok).toBe(false)
    if (result.ok) throw new Error('Permintaan seharusnya gagal.')
    expect(result.kind).toBe('timeout')
    expect(result.detail).toMatch(/batas waktu/)
  })

  it('membatalkan permintaan yang sedang berjalan lewat AbortSignal', async () => {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 120)
    const result = await fixture.origin.openOrigin(
      originRequest({ url: `http://${LOGICAL_HOSTNAME}:${fixture.port}/slow`, timeoutMs: 5_000 }),
      controller.signal,
    )
    clearTimeout(timer)
    expect(result.ok).toBe(false)
    if (result.ok) throw new Error('Permintaan seharusnya dibatalkan.')
    expect(result.detail).toMatch(/dibatalkan/)
  })

  it('tidak menghubungi origin ketika sinyal sudah dibatalkan sebelum permintaan dibuat', async () => {
    const before = fixture.requests.length
    const controller = new AbortController()
    controller.abort()
    const result = await fixture.origin.openOrigin(
      originRequest({ url: `http://${LOGICAL_HOSTNAME}:${fixture.port}/slow` }),
      controller.signal,
    )
    expect(result.ok).toBe(false)
    if (result.ok) throw new Error('Permintaan seharusnya dibatalkan.')
    expect(result.detail).toMatch(/dibatalkan/)
    expect(fixture.requests).toHaveLength(before)
  })

  it('melaporkan koneksi yang ditolak sebagai galat, bukan sebagai situs aman', async () => {
    const refused = await new Promise<number>((resolve, reject) => {
      const closer = http.createServer()
      closer.once('error', reject)
      closer.listen(0, HOST, () => {
        const address = closer.address() as AddressInfo
        closer.close(() => resolve(address.port))
      })
    })
    const result = await fixture.origin.openOrigin(
      originRequest({ url: `http://${LOGICAL_HOSTNAME}:${refused}/html`, port: refused }),
    )
    expect(result.ok).toBe(false)
    if (result.ok) throw new Error('Koneksi seharusnya ditolak.')
    expect(result.kind).toBe('error')
    expect(result.detail).toContain('ditolak')
  })
})

describe('node site probe jujur saat sumber data tidak menghasilkan apa pun', () => {
  it('mengekspos identitas sumber data probe', () => {
    expect(fixture.origin.name).toBe('node-dns-tls-http')
    expect(fixture.origin.dnsSource).toContain('node:dns')
  })

  it('menolak resolusi nama host yang memang tidak ada', async () => {
    await expect(fixture.origin.resolve('nama-tidak-ada.veriguard-uji.invalid')).rejects.toThrow(
      /./,
    )
  })

  it('memisahkan hasil kosong dari hasil gagal tanpa mengarang record', async () => {
    const outcome = await fixture.origin
      .queryRecords('nama-tidak-ada.veriguard-uji.invalid', 'A')
      .then(
        (value) => ({ failed: false as const, value }),
        (error: unknown) => ({ failed: true as const, error }),
      )

    if (outcome.failed) {
      // Tanpa resolver yang menjawab, probe menyerah lewat error berkode waktu habis
      // dan lapisan layanan yang mengubahnya menjadi status timeout.
      const code = (outcome.error as { code?: string })?.code
      expect(code).toBe('ETIMEDOUT')
      return
    }

    expect(outcome.value.outcome).not.toBe('answered')
    expect(outcome.value.records).toEqual([])
    if (outcome.value.outcome !== 'empty') {
      expect(typeof outcome.value.detail).toBe('string')
      expect(outcome.value.detail?.length).toBeGreaterThan(0)
    }
  })

  it('tidak mengarang ASN bila kueri tidak berhasil', async () => {
    const outcome = await fixture.origin.lookupAsn('127.0.0.1').then(
      (value) => ({ failed: false as const, value }),
      (error: unknown) => ({ failed: true as const, error }),
    )
    if (outcome.failed) {
      expect((outcome.error as { code?: string })?.code).toBe('ETIMEDOUT')
      return
    }

    const result = outcome.value
    if (result.info === null) {
      expect(result.outcome).not.toBe('answered')
      expect(result.detail).toBeTruthy()
    } else {
      expect(result.outcome).toBe('answered')
      expect(typeof result.info.asn).toBe('string')
    }
    // Ruang loopback tidak punya organisasi publik, jadi nama tidak pernah dikarang.
    expect(result.info?.organization ?? null).toBeNull()
  })

  it('melaporkan kegagalan handshake TLS terhadap port yang bukan TLS', async () => {
    const result = await fixture.origin.inspectTls(
      LOGICAL_HOSTNAME,
      HOST,
      'ipv4',
      fixture.port,
      undefined,
    )
    expect(result.httpsReachable).toBe(false)
    expect(result.certificate).toBeNull()
    expect(result.outcome).not.toBe('answered')
    expect(result.detail).toBeTruthy()
  })

  it('membatalkan pemeriksaan TLS sebelum koneksi selesai', async () => {
    const controller = new AbortController()
    controller.abort()
    const result = await fixture.origin.inspectTls(
      LOGICAL_HOSTNAME,
      '192.0.2.1',
      'ipv4',
      443,
      controller.signal,
    )
    expect(result.outcome).toBe('failed')
    expect(result.detail).toMatch(/dibatalkan/)
    expect(result.certificate).toBeNull()
  })
})

describe('guard tetap berlaku untuk probe Node', () => {
  it('menolak target loopback tanpa mengirim permintaan apa pun', async () => {
    const calls: string[] = []
    const counting: SiteProbe = {
      ...fixture.origin,
      openOrigin: (request, signal) => {
        calls.push(request.url)
        return fixture.origin.openOrigin(request, signal)
      },
      resolve: (hostname, signal) => {
        calls.push(`resolve:${hostname}`)
        return fixture.origin.resolve(hostname, signal)
      },
    }

    for (const url of [
      `http://${HOST}:${fixture.port}/html`,
      `http://localhost:${fixture.port}/html`,
      `http://127.1:${fixture.port}/html`,
      'http://[::1]/html',
      'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.5/',
    ]) {
      await expect(runSiteAnalysis({ url, uid: 'uji', probe: counting })).rejects.toThrow()
    }
    expect(calls).toEqual([])
  })
})

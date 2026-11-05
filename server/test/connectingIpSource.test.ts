import type * as http from 'node:http'
import { afterEach, describe, expect, it } from 'vitest'
import { convertNodeRequest, resolveConnectingIp } from '../src/index.js'

// F3/W3 - sumber alamat IP untuk gerbang cooldown. Bawaan tetap alamat socket supaya klien yang
// terhubung langsung tidak dapat memilih IP palsunya sendiri. Header edge hanya dipercaya ketika
// operator menyalakannya DAN peer yang menghubungkan adalah loopback (proxy di mesin yang sama).

function incoming(socketAddress: string, connectingIp?: string | string[]): http.IncomingMessage {
  const headers: Record<string, string | string[]> = { host: 'localhost:8787' }
  if (connectingIp !== undefined) headers['cf-connecting-ip'] = connectingIp
  const raw = {
    socket: { remoteAddress: socketAddress },
    headers,
    method: 'GET',
    url: '/scan',
  }
  return raw as unknown as http.IncomingMessage
}

async function headerFor(socketAddress: string, connectingIp?: string | string[]): Promise<string | null> {
  const controller = new AbortController()
  const request = await convertNodeRequest(incoming(socketAddress, connectingIp), '127.0.0.1', 8787, controller.signal)
  return request.headers.get('cf-connecting-ip')
}

describe('resolveConnectingIp', () => {
  it('bawaan: alamat socket menang atas header kiriman klien', () => {
    const ip = resolveConnectingIp({
      socketAddress: '::ffff:203.0.113.9',
      incomingHeader: '198.51.100.7',
      trustEdgeHeader: false,
    })
    expect(ip).toBe('203.0.113.9')
  })

  it('bawaan: peer loopback pun tidak membuat header dipercaya tanpa flag', () => {
    const ip = resolveConnectingIp({
      socketAddress: '::1',
      incomingHeader: '198.51.100.7',
      trustEdgeHeader: false,
    })
    expect(ip).toBe('::1')
  })

  it('flag aktif dan peer loopback: header edge dipakai', () => {
    const v4 = resolveConnectingIp({
      socketAddress: '127.0.0.1',
      incomingHeader: '198.51.100.7',
      trustEdgeHeader: true,
    })
    const v6 = resolveConnectingIp({
      socketAddress: '::ffff:127.0.0.1',
      incomingHeader: '2001:4860:8::8',
      trustEdgeHeader: true,
    })
    expect(v4).toBe('198.51.100.7')
    expect(v6).toBe('2001:4860:8::8')
  })

  it('flag aktif tetapi peer bukan loopback: header diabaikan', () => {
    const ip = resolveConnectingIp({
      socketAddress: '203.0.113.9',
      incomingHeader: '198.51.100.7',
      trustEdgeHeader: true,
    })
    expect(ip).toBe('203.0.113.9')
  })

  it('bentuk yang bukan satu alamat IP ditolak walau flag aktif', () => {
    for (const junk of ['198.51.100.7, 203.0.113.9', '', ' ', 'not-an-ip', '1.2.3.4:8080']) {
      const ip = resolveConnectingIp({
        socketAddress: '::1',
        incomingHeader: junk,
        trustEdgeHeader: true,
      })
      expect(ip).toBe('::1')
    }
  })

  it('tidak ada alamat socket dan header tidak sah: hasilnya kosong', () => {
    const ip = resolveConnectingIp({
      socketAddress: '',
      incomingHeader: 'not-an-ip',
      trustEdgeHeader: true,
    })
    expect(ip).toBe('')
  })
})

describe('convertNodeRequest menyiapkan header untuk gerbang cooldown', () => {
  const original = process.env.TRUST_EDGE_CONNECTING_IP

  afterEach(() => {
    if (original === undefined) delete process.env.TRUST_EDGE_CONNECTING_IP
    else process.env.TRUST_EDGE_CONNECTING_IP = original
  })

  it('header kiriman klien dibuang ketika flag mati', async () => {
    delete process.env.TRUST_EDGE_CONNECTING_IP
    expect(await headerFor('::ffff:203.0.113.9', '198.51.100.7')).toBe('203.0.113.9')
  })

  it('header dihapus sama sekali ketika tidak ada alamat yang bisa dipercaya', async () => {
    delete process.env.TRUST_EDGE_CONNECTING_IP
    expect(await headerFor('', '198.51.100.7')).toBeNull()
  })

  it('header edge dipakai pada peer loopback ketika flag aktif', async () => {
    process.env.TRUST_EDGE_CONNECTING_IP = 'true'
    expect(await headerFor('::1', '198.51.100.7')).toBe('198.51.100.7')
  })

  it('header berbentuk daftar tidak dipakai walaupun flag aktif', async () => {
    process.env.TRUST_EDGE_CONNECTING_IP = 'true'
    expect(await headerFor('127.0.0.1', '198.51.100.7, 203.0.113.9')).toBe('127.0.0.1')
  })
})

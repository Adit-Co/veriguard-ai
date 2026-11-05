import { describe, expect, it } from 'vitest'
import { MAX_RESPONSE_BYTES, discardResponseBody, fetchJson, readBoundedJson } from '../src/scanners/http.js'

// F10: body provider tidak boleh berukuran tak terbatas. Reader berbatas dipakai sebelum status
// dianggap "data", dan body yang tidak terpakai dibatalkan supaya socket tidak menahan pekerjaan
// lain. Respons yang melebihi batas HARUS tetap terbaca sebagai kegagalan teknis, bukan sebagai
// "tidak ada data" (yang bisa berubah menjadi vonis clean).

const ENDPOINT = 'https://provider.test/scan'

type StreamCounts = { pulls: number; cancelled: boolean }

function streamedResponse(
  chunkBytes: number,
  maxChunks: number,
  options: { headers?: Record<string, string>; status?: number } = {},
): { response: Response; counts: StreamCounts } {
  const counts: StreamCounts = { pulls: 0, cancelled: false }
  const chunk = new Uint8Array(chunkBytes)
  let sent = 0

  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      counts.pulls += 1
      if (sent >= maxChunks) {
        controller.close()
        return
      }
      sent += 1
      controller.enqueue(chunk)
    },
    cancel() {
      counts.cancelled = true
    },
  })

  return { response: new Response(stream, options), counts }
}

function fetchReturning(response: Response): typeof fetch {
  return (async () => response) as unknown as typeof fetch
}

async function flush(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0))
}

describe('fetchJson dengan batas ukuran body', () => {
  it('menolak respons yang content-length-nya melebihi batas tanpa membaca body', async () => {
    const { response, counts } = streamedResponse(1024, 4, {
      headers: { 'content-length': String(MAX_RESPONSE_BYTES + 1) },
    })

    const result = await fetchJson(fetchReturning(response), ENDPOINT, {}, 5_000)

    expect(result.ok).toBe(false)
    expect(result.kind).toBe('error')
    expect(result.reason).toContain('melebihi batas ukuran')
    expect(counts.pulls).toBe(0)
  })

  it('memotong aliran yang melebihi batas saat dibaca lalu membatalkan body', async () => {
    const { response, counts } = streamedResponse(4_096, 100)

    const result = await fetchJson(fetchReturning(response), ENDPOINT, {}, 5_000, 'json', 8_192)

    expect(result.ok).toBe(false)
    expect(result.kind).toBe('error')
    expect(result.reason).toContain('melebihi batas ukuran')
    expect(counts.cancelled).toBe(true)
  })

  it('menolak aliran yang melebihi batas walaupun content-length menyatakan kecil', async () => {
    // Header boleh bohong. Batas yang sebenarnya ditegakkan adalah penghitung saat aliran
    // dibaca, jadi kasus ini membuktikan batas streaming dan bukan pemeriksaan header:
    // pemeriksaan declared tidak akan pernah memicu penolakan di sini.
    const { response, counts } = streamedResponse(4_096, 100, {
      headers: { 'content-length': '16' },
    })

    const result = await fetchJson(fetchReturning(response), ENDPOINT, {}, 5_000, 'json', 8_192)

    expect(result.ok).toBe(false)
    expect(result.kind).toBe('error')
    expect(result.reason).toContain('melebihi batas ukuran')
    expect(counts.cancelled).toBe(true)
    // Pembaca berhenti di 3 chunk (8 KiB terlampaui), tidak menghabiskan 100 chunk.
    expect(counts.pulls).toBeLessThan(10)
  })

  it('tetap membatasi mode text sehingga feed besar tidak masuk ke memori', async () => {
    const { response } = streamedResponse(4_096, 100)

    const result = await fetchJson(fetchReturning(response), ENDPOINT, {}, 5_000, 'text', 8_192)

    expect(result.ok).toBe(false)
    expect(result.reason).toContain('melebihi batas ukuran')
  })

  it('mode bytes tetap mengembalikan Uint8Array untuk respons di bawah batas', async () => {
    const { response } = streamedResponse(64, 2)

    const result = await fetchJson(fetchReturning(response), ENDPOINT, {}, 5_000, 'bytes', 4_096)

    expect(result.ok).toBe(true)
    expect(result.data).toBeInstanceOf(Uint8Array)
    expect((result.data as Uint8Array).byteLength).toBe(128)
  })

  it('respons JSON kecil tetap dikembalikan utuh apa adanya', async () => {
    const response = new Response(JSON.stringify({ verdicts: { overall: { malicious: false } } }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })

    const result = await fetchJson(fetchReturning(response), ENDPOINT, {}, 5_000)

    expect(result.ok).toBe(true)
    expect(result.data).toEqual({ verdicts: { overall: { malicious: false } } })
    expect(result.status).toBe(200)
  })

  it('status kegagalan tetap mengembalikan taksonomi yang sama meski body besar', async () => {
    const { response, counts } = streamedResponse(8_192, 50, { status: 503 })

    const result = await fetchJson(fetchReturning(response), ENDPOINT, {}, 5_000)

    expect(result.ok).toBe(false)
    expect(result.kind).toBe('unavailable')
    expect(result.reason).toBe('Layanan provider sedang tidak tersedia.')
    expect(counts.pulls).toBe(0)
  })
})

describe('readBoundedJson untuk adapter dengan permintaan sendiri', () => {
  it('mengangkat galat ketika body melebihi batas, bukan mengembalikan null', async () => {
    const { response } = streamedResponse(4_096, 100)

    await expect(readBoundedJson(response, 8_192)).rejects.toThrow(/exceeds size limit/)
  })

  it('mengangkat galat untuk aliran besar yang header-nya menyatakan kecil', async () => {
    // Jalur Radar memakai readBoundedJson; penolakan harus datang dari penghitung aliran,
    // bukan dari kepercayaan pada content-length.
    const { response, counts } = streamedResponse(4_096, 60, { headers: { 'content-length': '8' } })

    await expect(readBoundedJson(response, 8_192)).rejects.toThrow(/exceeds size limit/)
    expect(counts.cancelled).toBe(true)
    expect(counts.pulls).toBeLessThan(10)
  })

  it('mengembalikan null untuk body yang bukan JSON di bawah batas', async () => {
    const response = new Response('bukan json', { status: 200 })

    await expect(readBoundedJson(response)).resolves.toBeNull()
  })

  it('mengembalikan objek untuk body JSON yang sah', async () => {
    const response = new Response(JSON.stringify({ result: { uuid: 'aaaa1111-2222-4333-8444-555566667777' } }), {
      status: 200,
    })

    await expect(readBoundedJson(response)).resolves.toEqual({
      result: { uuid: 'aaaa1111-2222-4333-8444-555566667777' },
    })
  })
})

describe('discardResponseBody', () => {
  it('membatalkan body yang tidak akan dibaca', async () => {
    const { response, counts } = streamedResponse(128, 4)

    discardResponseBody(response)
    await flush()

    expect(counts.cancelled).toBe(true)
  })

  it('tidak mengangkat galat untuk respons tanpa body', () => {
    expect(() => discardResponseBody(new Response(null, { status: 204 }))).not.toThrow()
  })
})

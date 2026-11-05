import { beforeEach, describe, expect, it, vi } from 'vitest'
import { resetScanState } from './helpers/scanState.js'
import { runMultiSourceScan } from '../src/scanners/service.js'
import type {
  ProviderAdapter,
  ProviderCheck,
  ScanProgressEvent,
  ScannerProviderId,
} from '../src/scanners/types.js'

const CLEAN_CHECK: ProviderCheck = {
  status: 'success',
  verdict: 'clean',
  score: 0,
  summary: 'Tidak ditemukan indikasi.',
  signals: [],
  reason: null,
}

function adapter(
  id: ScannerProviderId,
  check: ProviderAdapter['check'],
  label = id,
): ProviderAdapter {
  return {
    id,
    label,
    isConfigured: () => true,
    check,
  }
}

function deferred() {
  let resolve: () => void = () => undefined
  const promise = new Promise<void>((next) => {
    resolve = next
  })
  return { promise, resolve }
}

async function tick(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0))
}

describe('orkestrasi event multi-sumber', () => {
  beforeEach(() => {
    resetScanState()
  })

  it('mengirim init, running, completed, lalu done', async () => {
    const events: ScanProgressEvent[] = []
    const result = await runMultiSourceScan({
      uid: 'events',
      url: 'https://contoh.com',
      scanId: 'scan-events',
      adapters: [
        adapter('urlscan', async () => CLEAN_CHECK),
        adapter('virustotal', async () => CLEAN_CHECK),
      ],
      onEvent: (event) => {
        events.push(event)
      },
    })

    expect(result.providers.map((provider) => provider.id)).toEqual([
      'urlscan',
      'virustotal',
    ])
    expect(events[0]).toMatchObject({
      type: 'init',
      scanId: 'scan-events',
      sensitiveUrl: false,
    })
    expect(events.at(-1)).toMatchObject({
      type: 'done',
      scanId: 'scan-events',
      response: result,
    })
    expect(
      events.filter(
        (event) => event.type === 'provider' && event.provider.state === 'running',
      ),
    ).toHaveLength(2)
    expect(
      events.filter(
        (event) =>
          event.type === 'provider' &&
          event.provider.state === 'completed' &&
          event.provider.result?.status === 'success',
      ),
    ).toHaveLength(2)
  })

  it('tidak pernah menandai provider belum dikonfigurasi sebagai running', async () => {
    const events: ScanProgressEvent[] = []
    const result = await runMultiSourceScan({
      uid: 'unconfigured-events',
      url: 'https://contoh.com',
      adapters: [
        {
          id: 'urlscan',
          label: 'URLScan.io',
          isConfigured: () => false,
          check: async () => CLEAN_CHECK,
        },
      ],
      onEvent: (event) => {
        events.push(event)
      },
    })

    expect(result.providers[0]?.status).toBe('not_configured')
    expect(
      events.some(
        (event) =>
          event.type === 'provider' && event.provider.state === 'running',
      ),
    ).toBe(false)
    expect(events.at(-1)?.type).toBe('done')
  })

  it('menyebut nama variabel konfigurasi yang kurang tanpa menampilkan nilainya', async () => {
    const result = await runMultiSourceScan({
      uid: 'unconfigured-names',
      url: 'https://contoh.com',
      adapters: [
        {
          id: 'virustotal',
          label: 'VirusTotal',
          requiredEnv: ['VIRUSTOTAL_API_KEY'],
          isConfigured: () => false,
          check: async () => CLEAN_CHECK,
        },
        {
          id: 'radar',
          label: 'Cloudflare Radar URL Scanner',
          requiredEnv: ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'],
          isConfigured: () => false,
          check: async () => CLEAN_CHECK,
        },
      ],
    })

    expect(result.providers[0]?.reason).toContain('VIRUSTOTAL_API_KEY')
    expect(result.providers[1]?.reason).toContain('CLOUDFLARE_API_TOKEN')
    expect(result.providers[1]?.reason).toContain('CLOUDFLARE_ACCOUNT_ID')
    expect(result.providers[0]?.status).toBe('not_configured')
  })

  it('membatasi jumlah provider yang berjalan bersamaan', async () => {
    let active = 0
    let maxActive = 0
    const gates = Array.from({ length: 6 }, () => deferred())
    const ids: ScannerProviderId[] = [
      'urlscan',
      'virustotal',
      'openphish',
      'threatfox',
      'radar',
      'otx',
    ]
    const adapters = ids.map((id, index) =>
      adapter(id, async () => {
        active += 1
        maxActive = Math.max(maxActive, active)
        await gates[index]?.promise
        active -= 1
        return CLEAN_CHECK
      }),
    )

    const scan = runMultiSourceScan({
      uid: 'concurrency',
      url: 'https://contoh.com',
      adapters,
      concurrency: 2,
    })

    await tick()
    expect(active).toBe(2)
    expect(maxActive).toBe(2)

    gates.forEach((gate) => gate.resolve())
    await scan

    expect(maxActive).toBe(2)
  })

  it('mengisolasi kegagalan satu provider dari provider lain', async () => {
    const result = await runMultiSourceScan({
      uid: 'failure-isolation',
      url: 'https://contoh.com',
      adapters: [
        adapter('urlscan', async () => {
          throw new Error('network down')
        }),
        adapter('virustotal', async () => CLEAN_CHECK),
      ],
    })

    expect(result.providers.find((provider) => provider.id === 'urlscan')?.status).toBe(
      'error',
    )
    expect(
      result.providers.find((provider) => provider.id === 'virustotal')?.status,
    ).toBe('success')
  })

  it('menandai provider yang melewati batas waktu', async () => {
    vi.useFakeTimers()
    try {
      const events: ScanProgressEvent[] = []
      const scan = runMultiSourceScan({
        uid: 'timeout',
        url: 'https://contoh.com',
        adapters: [
          adapter('urlscan', () => new Promise<ProviderCheck>(() => undefined)),
        ],
        providerTimeoutMs: 1_000,
        onEvent: (event) => {
          events.push(event)
        },
      })

      await vi.advanceTimersByTimeAsync(1_000)
      const result = await scan

      expect(result.providers[0]?.status).toBe('timeout')
      expect(result.providers[0]?.verdict).toBe('inconclusive')
      expect(
        events.some(
          (event) =>
            event.type === 'provider' &&
            event.provider.state === 'completed' &&
            event.provider.result?.status === 'timeout',
        ),
      ).toBe(true)
    } finally {
      vi.useRealTimers()
    }
  })

  it('menghentikan provider tanpa request saat sinyal sudah dibatalkan', async () => {
    const controller = new AbortController()
    controller.abort()
    const check = vi.fn(async () => CLEAN_CHECK)
    const events: ScanProgressEvent[] = []
    const result = await runMultiSourceScan({
      uid: 'aborted',
      url: 'https://contoh.com',
      adapters: [adapter('urlscan', check)],
      signal: controller.signal,
      onEvent: (event) => {
        events.push(event)
      },
    })

    expect(check).not.toHaveBeenCalled()
    expect(result.providers[0]?.status).toBe('skipped')
    expect(
      events.some(
        (event) =>
          event.type === 'provider' && event.provider.state === 'running',
      ),
    ).toBe(false)
  })

  it('mengirim status skipped dan done untuk URL sensitif', async () => {
    const check = vi.fn(async () => CLEAN_CHECK)
    const events: ScanProgressEvent[] = []
    const result = await runMultiSourceScan({
      uid: 'sensitive-events',
      url: 'https://contoh.com/?token=rahasia',
      adapters: [adapter('virustotal', check)],
      onEvent: (event) => {
        events.push(event)
      },
    })

    expect(check).not.toHaveBeenCalled()
    expect(result.sensitiveUrl).toBe(true)
    expect(events[0]).toMatchObject({ type: 'init', sensitiveUrl: true })
    expect(events.at(-1)?.type).toBe('done')
  })
})

describe('batas waktu keseluruhan scan dan pembatalan', () => {
  beforeEach(() => {
    resetScanState()
  })

  it('menghentikan provider berjalan dan tersisa saat batas waktu keseluruhan tercapai', async () => {
    vi.useFakeTimers()
    try {
      const scan = runMultiSourceScan({
        uid: 'scan-deadline',
        url: 'https://contoh.com',
        adapters: [
          adapter('urlscan', () => new Promise<ProviderCheck>(() => undefined)),
          adapter('virustotal', () => new Promise<ProviderCheck>(() => undefined)),
        ],
        concurrency: 1,
        scanTimeoutMs: 2_000,
      })

      await vi.advanceTimersByTimeAsync(2_500)
      const result = await scan

      expect(result.providers[0]?.status).toBe('timeout')
      expect(result.providers[0]?.reason).toBe(
        'Batas waktu keseluruhan proses scan tercapai.',
      )
      expect(result.providers[1]?.status).toBe('skipped')
      expect(result.providers[1]?.reason).toBe(
        'Batas waktu keseluruhan proses scan tercapai.',
      )
    } finally {
      vi.useRealTimers()
    }
  })

  it('membatalkan provider yang sedang berjalan saat pemanggil membatalkan request', async () => {
    const controller = new AbortController()
    const gate = deferred()
    const check = vi.fn(() => gate.promise)
    const scan = runMultiSourceScan({
      uid: 'abort-midway',
      url: 'https://contoh.com',
      adapters: [adapter('urlscan', check)],
      concurrency: 1,
      signal: controller.signal,
    })

    await tick()
    expect(check).toHaveBeenCalled()

    controller.abort()
    const result = await scan

    expect(result.providers[0]?.status).toBe('skipped')
    expect(result.providers[0]?.reason).toBe('Pemeriksaan dihentikan.')
  })

  it('tidak menandai provider lain sebagai timeout saat satu provider melampaui anggarannya', async () => {
    vi.useFakeTimers()
    try {
      const scan = runMultiSourceScan({
        uid: 'timeout-isolation',
        url: 'https://contoh.com',
        adapters: [
          adapter('urlscan', async () => CLEAN_CHECK),
          { ...adapter('openphish', () => new Promise<ProviderCheck>(() => undefined)), timeoutMs: 2_000 },
          adapter('threatfox', async () => CLEAN_CHECK),
          {
            ...adapter('radar', () => new Promise<ProviderCheck>(() => undefined)),
            timeoutMs: 2_000,
          },
          adapter('otx', async () => ({ ...CLEAN_CHECK, verdict: 'malicious', score: 85 })),
        ],
        concurrency: 5,
        providerTimeoutMs: 10_000,
        scanTimeoutMs: 80_000,
      })

      await vi.advanceTimersByTimeAsync(2_500)
      const result = await scan
      const byId = Object.fromEntries(result.providers.map((provider) => [provider.id, provider]))

      // Dua agen yang lambat timeout sendiri, tanpa mengubah status tiga agen lainnya.
      expect(byId.openphish?.status).toBe('timeout')
      expect(byId.radar?.status).toBe('timeout')
      expect(byId.urlscan?.status).toBe('success')
      expect(byId.threatfox?.status).toBe('success')
      expect(byId.otx?.status).toBe('success')
      expect(result.providers.filter((provider) => provider.status === 'timeout')).toHaveLength(2)
      // Keterlambatan satu agen tidak boleh melemahkan bukti agen lain.
      expect(byId.otx?.verdict).toBe('malicious')
      expect(byId.urlscan?.reason).toBeNull()
    } finally {
      vi.useRealTimers()
    }
  })

  it('tetap memuat seluruh slot provider saat sebagian provider gagal', async () => {
    const ids: ScannerProviderId[] = [
      'urlscan',
      'virustotal',
      'openphish',
      'threatfox',
      'radar',
      'otx',
    ]
    const result = await runMultiSourceScan({
      uid: 'partial-response',
      url: 'https://contoh.com',
      adapters: ids.map((id, index) =>
        adapter(
          id,
          index === 2
            ? async () => {
                throw new Error('boom')
              }
            : async () => CLEAN_CHECK,
        ),
      ),
      concurrency: 6,
    })

    expect(result.providers).toHaveLength(ids.length)
    expect(result.providers.map((provider) => provider.id)).toEqual(ids)
    expect(result.providers[2]?.status).toBe('error')
    expect(
      result.providers.filter((provider) => provider.status === 'success'),
    ).toHaveLength(5)
  })
})

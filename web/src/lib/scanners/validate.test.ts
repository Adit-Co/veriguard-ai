import { describe, expect, it } from 'vitest'
import { parseMultiSourceResponse, parseScanProgressEvent } from './validate'

const PROVIDERS = [
  ['virustotal', 'VirusTotal'],
  ['urlscan', 'URLScan.io'],
  ['openphish', 'OpenPhish'],
  ['threatfox', 'ThreatFox (abuse.ch)'],
  ['radar', 'Cloudflare Radar URL Scanner'],
  ['otx', 'AlienVault OTX'],
  ['hybrid', 'Hybrid Analysis'],
  ['safebrowsing', 'Google Safe Browsing'],
] as const

function response() {
  return {
    providers: PROVIDERS.map(([id, label]) => ({
      id,
      label,
      status: 'success',
      verdict: 'clean',
      score: 0,
      summary: 'Tidak ditemukan indikasi.',
      signals: [],
      reason: null,
      durationMs: 120,
    })),
    sharedWithProviders: PROVIDERS.map(([id]) => id),
    sensitiveUrl: false,
    privacyReasons: [],
    generatedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 250,
  }
}

describe('validasi respons pemeriksaan eksternal', () => {
  it('menerima respons dengan status dan verdict yang dikenal', () => {
    const parsed = parseMultiSourceResponse(response())

    expect(parsed.providers[0]?.id).toBe('virustotal')
    expect(parsed.sharedWithProviders).toHaveLength(8)
  })

  it('menerima status auth_failed, not_configured, skipped, dan timeout', () => {
    for (const status of ['auth_failed', 'not_configured', 'skipped', 'timeout']) {
      const valid = response()
      valid.providers[0]!.status = status
      expect(parseMultiSourceResponse(valid).providers[0]?.status).toBe(status)
    }
  })

  it('menolak status provider yang tidak dikenal', () => {
    const invalid = response()
    invalid.providers[0]!.status = 'unknown'

    expect(() => parseMultiSourceResponse(invalid)).toThrow(
      'Respons pemeriksaan eksternal tidak valid.',
    )
  })

  it('menolak provider internal pada respons eksternal', () => {
    const invalid = response()
    const first = invalid.providers[0] as { id: string }
    first.id = 'internal'

    expect(() => parseMultiSourceResponse(invalid)).toThrow(
      'Respons pemeriksaan eksternal tidak valid.',
    )
  })

  it('menerima respons backend lama yang roster agen-nya lebih sedikit', () => {
    // Deploy bertahap: frontend 8 agen dapat bertemu backend yang masih mengirim
    // 6 agen. Ini bukan layanan tak terhubung — hasil yang ada harus tetap dipakai.
    const legacy = response()
    legacy.providers = legacy.providers.slice(0, 6) as typeof legacy.providers
    legacy.sharedWithProviders = legacy.sharedWithProviders.slice(0, 6)

    expect(parseMultiSourceResponse(legacy).providers).toHaveLength(6)
  })

  it('menolak respons tanpa provider eksternal sama sekali', () => {
    const invalid = response()
    invalid.providers = [] as typeof invalid.providers

    expect(() => parseMultiSourceResponse(invalid)).toThrow(
      'Respons pemeriksaan eksternal tidak valid.',
    )
  })

  it('menolak id provider yang tidak ada pada roster aplikasi', () => {
    const invalid = response()
    invalid.providers[7] = {
      ...invalid.providers[7]!,
      id: 'penyedia-baru',
    } as unknown as typeof invalid.providers[7]

    expect(() => parseMultiSourceResponse(invalid)).toThrow(
      'Respons pemeriksaan eksternal tidak valid.',
    )
  })

  it('menolak provider ganda pada respons eksternal', () => {
    const invalid = response()
    invalid.providers[1] = { ...invalid.providers[1]!, id: 'virustotal' }

    expect(() => parseMultiSourceResponse(invalid)).toThrow(
      'Respons pemeriksaan eksternal tidak valid.',
    )
  })
})

function withEvidence(evidence: unknown) {
  const payload = response()
  const providers = payload.providers as unknown as Record<string, unknown>[]
  providers[0]!.evidence = evidence
  return payload
}

describe('validasi penanda sumber bukti agen', () => {
  it('menerima payload lama tanpa field evidence', () => {
    const parsed = parseMultiSourceResponse(response())

    expect(parsed.providers[0]?.evidence).toBeUndefined()
  })

  it('menerima laporan yang dipakai ulang beserta waktu laporan aslinya', () => {
    const parsed = parseMultiSourceResponse(
      withEvidence({ source: 'existing_report', observedAt: '2026-01-01T00:00:00.000Z', ageMs: 3_600_000 }),
    )

    expect(parsed.providers[0]?.evidence).toEqual({
      source: 'existing_report',
      observedAt: '2026-01-01T00:00:00.000Z',
      ageMs: 3_600_000,
    })
  })

  it('menerima pemindaian baru tanpa waktu laporan', () => {
    const parsed = parseMultiSourceResponse(
      withEvidence({ source: 'new_scan', observedAt: null, ageMs: 0 }),
    )

    expect(parsed.providers[0]?.evidence?.source).toBe('new_scan')
  })

  it('menolak penanda bukti yang tidak dikenal atau tidak masuk akal', () => {
    const rejected = [
      { source: 'cached_forever', observedAt: null, ageMs: 0 },
      { source: null, observedAt: null, ageMs: 0 },
      { source: 'existing_report', observedAt: 'bukan-tanggal', ageMs: 0 },
      { source: 'existing_report', observedAt: '2026-01-01T00:00:00.000Z', ageMs: -1 },
      { source: 'existing_report', observedAt: '2026-01-01T00:00:00.000Z', ageMs: Number.NaN },
      'existing_report',
      null,
    ]

    for (const evidence of rejected) {
      expect(() => parseMultiSourceResponse(withEvidence(evidence))).toThrow(
        'Respons pemeriksaan eksternal tidak valid.',
      )
    }
  })

  it('menolak event progres dengan bukti yang tidak valid', () => {
    const provider = withEvidence({
      source: 'existing_report',
      observedAt: '2026-01-01T00:00:00.000Z',
      ageMs: -5,
    }).providers[0]

    expect(() =>
      parseScanProgressEvent({
        type: 'provider',
        scanId: 'scan-1',
        provider: { id: provider!.id, label: provider!.label, state: 'completed', result: provider },
      }),
    ).toThrow('Event pemeriksaan eksternal tidak valid.')
  })

  it('menerima event progres dengan penanda laporan yang dipakai ulang', () => {
    const provider = withEvidence({
      source: 'existing_report',
      observedAt: '2026-01-01T00:00:00.000Z',
      ageMs: 60_000,
    }).providers[0]

    const event = parseScanProgressEvent({
      type: 'provider',
      scanId: 'scan-1',
      provider: { id: provider!.id, label: provider!.label, state: 'completed', result: provider },
    })

    expect(event.type).toBe('provider')
  })
})

function withProviderCache(cache: unknown) {
  const payload = response()
  const providers = payload.providers as unknown as Record<string, unknown>[]
  providers[0]!.cache = cache
  return payload
}

function withScanCache(cache: unknown) {
  const payload = response() as Record<string, unknown>
  payload.cache = cache
  return payload
}

const HIT_CACHE = {
  hit: true,
  observedAt: '2026-01-01T00:00:00.000Z',
  ageMs: 60_000,
  stale: false,
}

describe('validasi metadata cache hasil pemeriksaan', () => {
  it('menerima respons backend lama yang belum mengirim metadata cache', () => {
    const parsed = parseMultiSourceResponse(response())

    expect(parsed.cache).toBeUndefined()
    expect(parsed.providers[0]?.cache).toBeUndefined()
  })

  it('menandai hasil agen yang dipakai ulang beserta umur dan kebasian entry', () => {
    const parsed = parseMultiSourceResponse(
      withProviderCache({ ...HIT_CACHE, stale: true }),
    )

    expect(parsed.providers[0]?.cache).toEqual({ ...HIT_CACHE, stale: true })
  })

  it('menerima hasil segar yang tercatat waktunya saat ditulis', () => {
    const parsed = parseMultiSourceResponse(
      withProviderCache({ hit: false, observedAt: '2026-01-01T00:00:00.000Z', ageMs: 0, stale: false }),
    )

    expect(parsed.providers[0]?.cache?.hit).toBe(false)
  })

  it('menerima metadata tingkat pemeriksaan: hit penuh, partial, dan dedup berbagi', () => {
    const full = {
      status: 'hit',
      hit: true,
      observedAt: '2026-01-01T00:00:00.000Z',
      ageMs: 3_600_000,
      reusedProviders: PROVIDERS.map(([id]) => id),
      refreshedProviders: [],
      requestsAvoided: PROVIDERS.length,
    }
    const partial = {
      status: 'partial',
      hit: false,
      observedAt: '2026-01-01T00:00:00.000Z',
      ageMs: 1_800_000,
      reusedProviders: ['urlscan'],
      refreshedProviders: ['virustotal'],
      requestsAvoided: 1,
      deduplicated: true,
    }

    expect(parseMultiSourceResponse(withScanCache(full)).cache?.requestsAvoided).toBe(8)
    expect(parseMultiSourceResponse(withScanCache(partial)).cache?.deduplicated).toBe(true)
  })

  it('menolak metadata cache agen yang tidak masuk akal', () => {
    const rejected = [
      { ...HIT_CACHE, ageMs: -1 },
      { ...HIT_CACHE, ageMs: Number.NaN },
      { ...HIT_CACHE, observedAt: 'besok' },
      { ...HIT_CACHE, observedAt: null },
      { hit: 'ya', observedAt: HIT_CACHE.observedAt, ageMs: 0, stale: false },
      { hit: true, observedAt: HIT_CACHE.observedAt, ageMs: 0 },
      'tersimpan',
      null,
    ]

    for (const cache of rejected) {
      expect(() => parseMultiSourceResponse(withProviderCache(cache))).toThrow(
        'Respons pemeriksaan eksternal tidak valid.',
      )
    }
  })

  it('menolak klaim penghematan yang tidak didukung daftar agen', () => {
    const inflated = {
      status: 'partial',
      hit: false,
      observedAt: '2026-01-01T00:00:00.000Z',
      ageMs: 1_000,
      reusedProviders: ['urlscan'],
      refreshedProviders: ['virustotal'],
      requestsAvoided: 5,
    }

    expect(() => parseMultiSourceResponse(withScanCache(inflated))).toThrow(
      'Respons pemeriksaan eksternal tidak valid.',
    )
  })

  it('menolak status yang bertentangan dengan daftar agen', () => {
    const contradictory = [
      // mengklaim semua kena cache padahal ada agen yang periksa ulang
      {
        status: 'hit',
        hit: true,
        observedAt: '2026-01-01T00:00:00.000Z',
        ageMs: 1_000,
        reusedProviders: ['urlscan'],
        refreshedProviders: ['virustotal'],
        requestsAvoided: 1,
      },
      // mengaku tidak memakai apa pun padahal ada daftar hasil terpakai
      {
        status: 'miss',
        hit: false,
        observedAt: null,
        ageMs: 0,
        reusedProviders: ['urlscan'],
        refreshedProviders: [],
        requestsAvoided: 1,
      },
      // partial tanpa entri yang dipakai ulang
      {
        status: 'partial',
        hit: false,
        observedAt: '2026-01-01T00:00:00.000Z',
        ageMs: 1_000,
        reusedProviders: [],
        refreshedProviders: ['virustotal'],
        requestsAvoided: 0,
      },
    ]

    for (const cache of contradictory) {
      expect(() => parseMultiSourceResponse(withScanCache(cache))).toThrow(
        'Respons pemeriksaan eksternal tidak valid.',
      )
    }
  })

  it('menolak agen yang tidak ada pada roster di daftar cache', () => {
    const unknown = {
      status: 'partial',
      hit: false,
      observedAt: '2026-01-01T00:00:00.000Z',
      ageMs: 1_000,
      reusedProviders: ['agen-baru'],
      refreshedProviders: [],
      requestsAvoided: 1,
    }

    expect(() => parseMultiSourceResponse(withScanCache(unknown))).toThrow(
      'Respons pemeriksaan eksternal tidak valid.',
    )
  })

  it('menolak jumlah agen cache yang melebihi roster agen', () => {
    const overflow = {
      status: 'partial',
      hit: false,
      observedAt: '2026-01-01T00:00:00.000Z',
      ageMs: 1_000,
      reusedProviders: PROVIDERS.map(([id]) => id),
      refreshedProviders: ['urlscan'],
      requestsAvoided: PROVIDERS.length,
    }

    expect(() => parseMultiSourceResponse(withScanCache(overflow))).toThrow(
      'Respons pemeriksaan eksternal tidak valid.',
    )
  })

  it('menerima dan menolak metadata cache pada event progres', () => {
    const provider = withProviderCache(HIT_CACHE).providers[0]
    const event = {
      type: 'provider' as const,
      scanId: 'scan-1',
      provider: {
        id: provider!.id,
        label: provider!.label,
        state: 'completed' as const,
        result: provider,
      },
    }

    expect(parseScanProgressEvent(event).type).toBe('provider')

    const broken = withProviderCache({ ...HIT_CACHE, ageMs: -1 }).providers[0]
    expect(() =>
      parseScanProgressEvent({
        ...event,
        provider: { ...event.provider, result: broken },
      }),
    ).toThrow('Event pemeriksaan eksternal tidak valid.')
  })
})

describe('validasi hasil Agent 8 (Google Safe Browsing)', () => {
  const EIGHTH = PROVIDERS.length - 1

  function agent8(overrides: Record<string, unknown>) {
    const payload = response()
    payload.providers[EIGHTH] = { ...payload.providers[EIGHTH]!, ...overrides }
    return payload
  }

  it('menerima not_found no-match beserta status cache tanpa mengubahnya menjadi error', () => {
    const parsed = parseMultiSourceResponse(
      agent8({
        status: 'not_found',
        verdict: 'inconclusive',
        score: null,
        summary: 'Google Safe Browsing tidak memiliki entri ancaman untuk URL ini.',
        reason:
          'Ketiadaan match hanya berarti URL belum tercatat pada list yang ditanyakan; BUKAN konfirmasi bahwa URL ini aman.',
        cache: { hit: true, observedAt: '2026-01-01T00:00:00.000Z', ageMs: 20_000, stale: false },
      }),
    )
    const agent = parsed.providers[EIGHTH]

    expect(agent?.status).toBe('not_found')
    expect(agent?.verdict).toBe('inconclusive')
    expect(agent?.score).toBeNull()
    expect(agent?.cache?.hit).toBe(true)
  })

  it('menerima galat parsing dengan satu sufiks HTTP dan tidak menormalkannya menjadi no-match', () => {
    const parsed = parseMultiSourceResponse(
      agent8({
        status: 'error',
        verdict: 'inconclusive',
        score: null,
        summary: 'Pemeriksaan provider gagal.',
        reason: 'Respons provider tidak dapat dibaca. (HTTP 200)',
      }),
    )

    expect(parsed.providers[EIGHTH]?.status).toBe('error')
    expect(parsed.providers[EIGHTH]?.reason).toBe('Respons provider tidak dapat dibaca. (HTTP 200)')
  })

  it('memisahkan protobuf cacat, autentikasi, kuota, timeout, dan gangguan layanan', () => {
    for (const [status, reason] of [
      [
        'error',
        'Respons protobuf Google Safe Browsing cacat; struktur wire-format tidak dikenali.',
      ],
      ['auth_failed', 'Kredensial provider ditolak. (HTTP 401)'],
      ['rate_limited', 'Kuota permintaan provider tercapai. (HTTP 429)'],
      ['timeout', 'Permintaan ke provider melebihi batas waktu.'],
      ['unavailable', 'Layanan provider sedang tidak tersedia. (HTTP 503)'],
    ] as const) {
      const agent = parseMultiSourceResponse(
        agent8({ status, verdict: 'inconclusive', score: null, reason }),
      ).providers[EIGHTH]

      expect(agent?.status).toBe(status)
      expect(agent?.verdict).toBe('inconclusive')
      expect((agent?.reason?.match(/\(HTTP \d+\)/g) ?? []).length).toBeLessThanOrEqual(1)
    }
  })
})

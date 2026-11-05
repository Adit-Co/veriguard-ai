import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  SCAN_STATE_KEY_ACTIVE_VAR,
  SCAN_STATE_KEY_MAX_CHARS,
  SCAN_STATE_KEY_MIN_CHARS,
  SCAN_STATE_KEY_SALT_VAR,
  SCAN_STATE_KEY_VERSION_PREFIX,
  createStateKeyRing,
  isSubtleAvailable,
} from '../src/state/stateKeys.js'
import { SCAN_STATE_KINDS } from '../src/state/durableState.js'
import { TEST_LEGACY_SALT, TEST_LABELS, ringEnv, syntheticKey, makeRing } from './helpers/keyRings.js'

/**
 * VGL-30H K-1: cincin kunci HMAC sebagai satu-satunya sumber kebenaran untuk versi aktif dan
 * daftar versi yang tersedia.
 *
 * Matriks yang diwajibkan brief: aktif V1; aktif V2 dengan V1 hadir; kunci aktif tidak tersedia;
 * versi aktif tidak valid; versi lama tidak tersedia; dan tidak ada nilai kunci yang bocor ke
 * catatan/galat. Semua materi di berkas ini sintetis dan hanya ada di proses uji.
 */

const material = (version: number) => syntheticKey(version)

afterEach(() => {
  vi.restoreAllMocks()
})

describe('VGL-30H K-1: bentuk cincin', () => {
  it('aktif V1 saja: tersedia, menulis di v1, tanpa versi pensiun', async () => {
    const ring = makeRing({ active: 'v1', labels: ['v1'] })

    expect(ring.available).toBe(true)
    expect(ring.activeLabel).toBe('v1')
    expect(ring.readableLabels).toEqual(['v1'])

    const record = await ring.digestsFor(SCAN_STATE_KINDS.counter, 'ip:203.0.113.9')
    expect(record).not.toBeNull()
    expect(record!.activeHash).toMatch(/^v1:[0-9a-f]{64}$/)
    expect(record!.retiredHashes).toEqual([])
  })

  it('aktif V2 dengan V1 hadir: tulis di v2, V1 dibaca sebagai versi pensiun (lama→baru)', async () => {
    const ring = makeRing({ active: 'v2', labels: ['v1', 'v2'] })

    expect(ring.available).toBe(true)
    expect(ring.activeLabel).toBe('v2')
    expect(ring.readableLabels).toEqual(['v1', 'v2'])

    const record = await ring.digestsFor(SCAN_STATE_KINDS.token, 'fp:abc')
    expect(record!.activeHash).toMatch(/^v2:[0-9a-f]{64}$/)
    expect(record!.retiredHashes).toHaveLength(1)
    expect(record!.retiredHashes[0]).toMatch(/^v1:[0-9a-f]{64}$/)
  })

  it('tiga versi: pensiun berurutan lama→baru dan versi aktif tidak ikut dalam pencarian', async () => {
    const ring = makeRing({ active: 'v3', labels: [...TEST_LABELS] })
    const record = await ring.digestsFor(SCAN_STATE_KINDS.clearance, 'uid:1')

    expect(record!.retiredHashes.map((hash) => hash.slice(0, 2))).toEqual(['v1', 'v2'])
    expect(record!.retiredHashes).not.toContain(record!.activeHash)
  })

  it('digest versi lama stabil: hash v1 hari ini sama dengan hash v1 yang dipakai kemarin', async () => {
    // Ini dasar A′: baris lama dapat dicari TANPA membalik hash lama, karena HMAC dengan kunci yang
    // sama atas identitas asal yang sama menghasilkan digest yang sama.
    const asActive = await makeRing({ active: 'v1', labels: ['v1'] }).digestsFor(SCAN_STATE_KINDS.counter, 'ip:x')
    const asRetired = await makeRing({ active: 'v2', labels: ['v1', 'v2'] }).digestsFor(SCAN_STATE_KINDS.counter, 'ip:x')

    expect(asRetired!.retiredHashes[0]).toBe(asActive!.activeHash)
    expect(asRetired!.activeHash).not.toBe(asActive!.activeHash)
  })

  it('digest berbeda per kind dan per key, jadi tabel tidak saling menabrak', async () => {
    const ring = makeRing({ active: 'v1', labels: ['v1'] })
    const counter = await ring.digestsFor(SCAN_STATE_KINDS.counter, 'ip:x')
    const token = await ring.digestsFor(SCAN_STATE_KINDS.token, 'ip:x')
    const other = await ring.digestsFor(SCAN_STATE_KINDS.counter, 'ip:y')

    expect(counter!.activeHash).not.toBe(token!.activeHash)
    expect(counter!.activeHash).not.toBe(other!.activeHash)
  })

  it('salt legacy ikut dibaca sebagai digest tanpa prefiks, tanpa mengubah versi tulis', async () => {
    const ring = makeRing({ active: 'v2', labels: ['v1', 'v2'], legacySalt: TEST_LEGACY_SALT })
    const record = await ring.digestsFor(SCAN_STATE_KINDS.token, 'fp:abc')

    expect(record!.activeHash).toMatch(/^v2:[0-9a-f]{64}$/)
    // Urutan pencarian: legacy paling tua, lalu versi pensiun naik, aktif tidak ikut.
    expect(record!.retiredHashes[0]).toMatch(/^[0-9a-f]{64}$/)
    expect(record!.retiredHashes[1]).toMatch(/^v1:[0-9a-f]{64}$/)
    expect(ring.readableLabels).toEqual(['legacy', 'v1', 'v2'])
  })
})

describe('VGL-30H K-1: gagal konfigurasi harus eksplisit dan aman', () => {
  it('tidak ada kunci ber-versi sama sekali -> no_keys, jalur durable tetap inert', async () => {
    const ring = createStateKeyRing({})
    expect(ring.available).toBe(false)
    expect(ring.reason).toBe('no_keys')
    expect(await ring.digestsFor(SCAN_STATE_KINDS.counter, 'ip:x')).toBeNull()
  })

  it('hanya salt (tanpa ring) -> tetap no_keys: salt lama tidak mengaktifkan penulisan', async () => {
    const ring = createStateKeyRing({ [SCAN_STATE_KEY_SALT_VAR]: TEST_LEGACY_SALT })
    expect(ring.available).toBe(false)
    expect(ring.reason).toBe('no_keys')
    expect(ring.readableLabels).toEqual([])
    expect(await ring.digestsFor(SCAN_STATE_KINDS.counter, 'ip:x')).toBeNull()
  })

  it('kunci tersedia tetapi SCAN_STATE_KEY_ACTIVE tidak dipasang -> active_absent', () => {
    const ring = createStateKeyRing(ringEnv({ labels: ['v1', 'v2'] }))
    expect(ring.available).toBe(false)
    expect(ring.reason).toBe('active_absent')
    // Versi yang hadir tetap dilaporkan supaya operator tahu apa yang kurang, tanpa nilai kunci.
    expect(ring.readableLabels).toEqual(['v1', 'v2'])
  })

  it.each([
    ['v0', 'versi nol'],
    ['1', 'tanpa prefiks v'],
    ['v', 'tanpa angka'],
    ['v1x', 'belakang bukan angka'],
    ['v9999', 'versi di luar 1..999'],
    ['true', 'bukan label versi'],
    ['', 'kosong'],
  ])('versi aktif tidak valid (%s) ditolak', (label) => {
    const ring = createStateKeyRing({
      ...ringEnv({ labels: ['v1'] }),
      [SCAN_STATE_KEY_ACTIVE_VAR]: label,
    })
    expect(ring.available).toBe(false)
    // Nilai kosong berarti "tidak dipasang"; selain itu "bentuknya salah".
    expect(ring.reason).toBe(label === '' ? 'active_absent' : 'active_invalid')
    expect(ring.activeLabel).toBeUndefined()
  })

  it('label dinormalkan (huruf besar dan spasi) tetapi tidak pernah dianggap versi lain', async () => {
    const ring = createStateKeyRing({
      ...ringEnv({ labels: ['v1'] }),
      [SCAN_STATE_KEY_ACTIVE_VAR]: ' V1 ',
    })
    expect(ring.available).toBe(true)
    expect(ring.activeLabel).toBe('v1')
    const record = await ring.digestsFor(SCAN_STATE_KINDS.counter, 'ip:x')
    expect(record!.activeHash).toMatch(/^v1:[0-9a-f]{64}$/)
  })

  it('versi aktif menunjuk secret yang tidak dipasang -> active_version_absent, tanpa pindah diam-diam', () => {
    const ring = createStateKeyRing(ringEnv({ active: 'v3', labels: ['v1', 'v2'] }))
    expect(ring.available).toBe(false)
    expect(ring.reason).toBe('active_version_absent')
    expect(ring.activeLabel).toBe('v3')
    expect(ring.readableLabels).toEqual(['v1', 'v2'])
  })

  it('versi lama dengan materi tidak layak dikeluarkan sendiri, bukan seluruh cincin', () => {
    const short = 'pendek'.repeat(2) // < SCAN_STATE_KEY_MIN_CHARS
    expect(short.length).toBeLessThan(SCAN_STATE_KEY_MIN_CHARS)

    const ring = createStateKeyRing({
      ...ringEnv({ active: 'v2', labels: ['v1', 'v2'] }),
      [`${SCAN_STATE_KEY_VERSION_PREFIX}1`]: short,
    })

    expect(ring.available).toBe(true)
    expect(ring.activeLabel).toBe('v2')
    expect(ring.excludedLabels).toEqual(['v1'])
    expect(ring.readableLabels).toEqual(['v2'])
  })

  it('materi terlalu panjang atau kosong ditolak, dan cincin inert bila itu satu-satunya kunci', () => {
    const tooLong = 'a'.repeat(SCAN_STATE_KEY_MAX_CHARS + 1)
    const longRing = createStateKeyRing(ringEnv({ active: 'v1', labels: ['v1'], materialOverride: { v1: tooLong } }))
    expect(longRing.available).toBe(false)
    expect(longRing.excludedLabels).toEqual(['v1'])

    const emptyRing = createStateKeyRing(ringEnv({ active: 'v1', labels: ['v1'], materialOverride: { v1: '   ' } }))
    expect(emptyRing.available).toBe(false)
    expect(emptyRing.reason).toBe('no_keys')
  })

  it('nama secret yang tidak sesuai pola tidak pernah dibaca sebagai versi', () => {
    const ring = createStateKeyRing({
      SCAN_STATE_KEY_V1_ALIAS: material(1),
      SCAN_STATE_KEY_V01: material(1),
      SCAN_STATE_KEY_ACTIVE: 'v1',
    })
    expect(ring.available).toBe(false)
    expect(ring.reason).toBe('no_keys')
  })

  it('runtime tanpa crypto.subtle -> inert dengan alasan, bukan kunci statis', () => {
    // Batas yang diuji: tidak ada jalur cadangan ke hash non-kriptografis.
    expect(isSubtleAvailable()).toBe(true)
    // `crypto.subtle` accessor tanpa setter di host uji, jadi yang diganti adalah properti
    // `crypto` di globalThis dan kemudian dikembalikan pers seperti semula.
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
    if (!descriptor) throw new Error('uji ini butuh globalThis.crypto yang bisa didefinisikan ulang')
    const original = (globalThis as unknown as { crypto: { getRandomValues: (b: Uint8Array) => Uint8Array } }).crypto
    try {
      Object.defineProperty(globalThis, 'crypto', {
        configurable: true,
        value: { getRandomValues: original.getRandomValues.bind(original) },
      })
      expect(isSubtleAvailable()).toBe(false)
      const ring = makeRing({ active: 'v1', labels: ['v1'] })
      expect(ring.available).toBe(false)
      expect(ring.reason).toBe('subtle_unavailable')
      expect(ring.activeLabel).toBe('v1')
    } finally {
      Object.defineProperty(globalThis, 'crypto', descriptor)
    }
    expect(isSubtleAvailable()).toBe(true)
  })

  it('sign gagal menghasilkan digestsFor null, bukan digest palsu', async () => {
    const cryptoHolder = globalThis as unknown as { crypto: { subtle: { sign: unknown } } }
    const original = cryptoHolder.crypto.subtle.sign
    cryptoHolder.crypto.subtle.sign = () => Promise.reject(new Error('runtime menolak materi kunci'))
    try {
      const ring = makeRing({ active: 'v1', labels: ['v1'] })
      expect(ring.available).toBe(true)
      expect(await ring.digestsFor(SCAN_STATE_KINDS.counter, 'ip:x')).toBeNull()
    } finally {
      cryptoHolder.crypto.subtle.sign = original
    }
  })
})

describe('VGL-30H K-1: tidak ada materi kunci yang keluar', () => {
  it('nilai secret tidak muncul di catatan, di respons ring, maupun di galat', async () => {
    const warns: string[] = []
    vi.spyOn(console, 'warn').mockImplementation((...args: unknown[]) => {
      warns.push(args.map(String).join(' '))
    })

    const v1 = material(1)
    const v2 = material(2)
    const ring = makeRing({ active: 'v2', labels: ['v1', 'v2'], legacySalt: TEST_LEGACY_SALT })
    const record = await ring.digestsFor(SCAN_STATE_KINDS.token, 'fp:abc')
    const failure = createStateKeyRing(ringEnv({ active: 'v9', labels: ['v1'] }))

    const dump = JSON.stringify({
      record,
      ring: { ...ring, digestsFor: undefined },
      failure: { ...failure, digestsFor: undefined },
    })

    for (const secret of [v1, v2, TEST_LEGACY_SALT]) {
      expect(dump).not.toContain(secret)
      expect(dump).not.toContain(secret.slice(0, 12))
      expect(warns.join('\n')).not.toContain(secret)
    }
    // Digest memang satu arah: ia tidak memuat identitas asal di dalamnya.
    expect(record!.activeHash).not.toContain('fp:abc')
  })

  it('versi yang materialnya ditolak hanya mengeluarkan label', () => {
    const bad = 'cukup-panjang-untuk-tidak-ditolak-tetapi-sengaja-dibuang'
    const ring = createStateKeyRing({
      [SCAN_STATE_KEY_ACTIVE_VAR]: 'v1',
      [`${SCAN_STATE_KEY_VERSION_PREFIX}2`]: 'terlalu-pendek',
      [`${SCAN_STATE_KEY_VERSION_PREFIX}3`]: bad,
    })
    const dump = JSON.stringify({ ...ring, digestsFor: undefined })
    expect(dump).not.toContain('terlalu-pendek')
    expect(dump).not.toContain(bad)
    expect(ring.excludedLabels).toEqual(['v2'])
  })
})

import { describe, expect, it } from 'vitest'
import {
  COMMUNITY_DAILY_FEED_LIMIT,
  createReportId,
  createReporterKey,
  communityDailyFeedDayEndMs,
  communityDailyFeedDayId,
  communityDailyFeedDayIdFromIso,
  communityDailyFeedDayStartMs,
  communityDayId,
  communityDayIdFromIso,
  communityUrlHash,
  msUntilNextCommunityFeedDay,
  sha256Hex,
} from './sparkProtocol'
import { normalizeCommunityUrl } from './url'

// Vektor tetap untuk normalisasi + hash. Nilai ini stabil agar perubahan normalisasi
// yang tidak disengaja terdeteksi sebelum memecah partisi URL yang sudah ada.
const HASH_FIXTURES = [
  {
    raw: 'HTTPS://Example.COM:443/a/b?utm_source=x&b=2&a=1#frag',
    normalized: 'https://example.com/a/b?a=1&b=2',
    hash: '7fcf2ddd9ffd863b7dc472cab851ff1020360d27673a338c389d741e49f33b56',
  },
  {
    raw: 'http://contoh.id:80/login?q=Halo%20Dunia&fbclid=abc',
    normalized: 'http://contoh.id/login?q=Halo+Dunia',
    hash: 'cb06a7db6b0ecb348f48293ce7144f31ff349f2fe6292281fb030c11bc8a8854',
  },
  {
    raw: 'Contoh-Situs.id',
    normalized: 'https://contoh-situs.id/',
    hash: '85d8416f745e2162bcf18505913e4d924c54e6a99f1a2da46d40f66618860d71',
  },
  {
    raw: 'https://sub.contoh.id:8443/path/../admin?z=1&z=0',
    normalized: 'https://sub.contoh.id:8443/admin?z=0&z=1',
    hash: 'bed78bcfbf9656b441fb373c9b0241c7cf572a6d2c018e0744979b8e18d4dc09',
  },
  {
    raw: 'https://xn--bcher-kva.example/%7Euser?b=2&a=1',
    normalized: 'https://xn--bcher-kva.example/%7Euser?a=1&b=2',
    hash: 'd46cbe28d2de646002937898179dfd2fa007b38dda6152c192ebead6fcbd9268',
  },
  {
    raw: 'https://contoh.id/login?b=2&utm_medium=email&a=1',
    normalized: 'https://contoh.id/login?a=1&b=2',
    hash: '6c8694d71a36b9ac70a2196208db977a8c5460149d86636a627ff35564f5ddfa',
  },
] as const

describe('hari kalender WIB untuk ID laporan', () => {
  it('mengganti hari tepat pada tengah malam WIB, bukan UTC', () => {
    const justBefore = Date.parse('2026-10-24T16:59:59.999Z')
    const midnight = Date.parse('2026-10-24T17:00:00.000Z')

    expect(communityDayId(midnight)).toBe(communityDayId(justBefore) + 1)
    expect(communityDayId(Date.parse('2026-10-24T00:00:00.000Z'))).toBe(
      communityDayId(justBefore),
    )
    expect(communityDayId(Date.parse('2026-10-25T16:59:59.999Z'))).toBe(
      communityDayId(midnight),
    )
  })

  it('membaca waktu terbit token sebagai sumber hari yang konsisten', () => {
    expect(communityDayIdFromIso('2026-10-24T16:59:59Z')).toBe(
      communityDayIdFromIso('2026-10-24T17:00:00Z')! - 1,
    )
    expect(communityDayIdFromIso('bukan-tanggal')).toBeNull()
    expect(communityDayIdFromIso(null)).toBeNull()
  })
})

describe('partisi harian Laporan terbaru dalam WITA', () => {
  it('berganti hari tepat pada tengah malam WITA, termasuk bulan dan tahun', () => {
    const lastSecond = Date.parse('2026-12-31T15:59:59.999Z')
    const firstSecond = Date.parse('2026-12-31T16:00:00.000Z')

    expect(communityDailyFeedDayId(firstSecond)).toBe(
      String(Number(communityDailyFeedDayId(lastSecond)) + 1),
    )
    expect(communityDailyFeedDayId(lastSecond)).not.toBe(
      communityDailyFeedDayId(firstSecond),
    )
    expect(communityDailyFeedDayIdFromIso('2026-12-31T16:00:00Z')).toBe(
      communityDailyFeedDayId(firstSecond),
    )
    expect(communityDailyFeedDayIdFromIso('bukan-tanggal')).toBeNull()
    expect(communityDailyFeedDayIdFromIso(null)).toBeNull()
  })

  it('memakai jendela epoch penuh, bukan hanya angka hari', () => {
    const now = Date.parse('2026-10-25T06:00:00Z')
    const start = communityDailyFeedDayStartMs(now)
    const end = communityDailyFeedDayEndMs(now)

    expect(end - start).toBe(86_400_000)
    expect(start).toBe(Date.parse('2026-10-24T16:00:00.000Z'))
    expect(end).toBe(Date.parse('2026-10-25T16:00:00.000Z'))
    expect(communityDailyFeedDayStartMs(start)).toBe(start)
    expect(communityDailyFeedDayStartMs(end - 1)).toBe(start)
    expect(communityDailyFeedDayStartMs(end)).toBe(end)
  })

  it('menjadwalkan tepat satu pembaruan pada pergantian hari, bukan polling', () => {
    const now = Date.parse('2026-10-25T15:59:00Z')

    expect(msUntilNextCommunityFeedDay(now)).toBe(60_000)
    expect(msUntilNextCommunityFeedDay(Date.parse('2026-10-25T16:00:00Z'))).toBe(
      86_400_000,
    )
    expect(COMMUNITY_DAILY_FEED_LIMIT).toBe(6)
  })
})

describe('hash URL Spark', () => {
  it('menghasilkan vektor SHA-256 yang dikenal', async () => {
    await expect(sha256Hex('abc')).resolves.toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
  })

  it('menghasilkan hash yang stabil untuk normalisasi yang sama', async () => {
    for (const fixture of HASH_FIXTURES) {
      const normalized = normalizeCommunityUrl(fixture.raw)
      expect(normalized).toBe(fixture.normalized)
      expect(await communityUrlHash(normalized)).toBe(fixture.hash)
      expect(await communityUrlHash(normalized)).toMatch(/^[0-9a-f]{64}$/)
    }
  })

  it('parameter pelacak tidak mengubah identitas, path dan query nyata mengubahnya', async () => {
    const clean = await communityUrlHash(normalizeCommunityUrl('https://contoh.id/a?b=2'))
    const tracked = await communityUrlHash(
      normalizeCommunityUrl('https://contoh.id/a?b=2&utm_source=email'),
    )
    const otherPath = await communityUrlHash(normalizeCommunityUrl('https://contoh.id/b?b=2'))

    expect(tracked).toBe(clean)
    expect(otherPath).not.toBe(clean)
  })
})

describe('identitas acak Spark', () => {
  it('membuat ID laporan 128-bit dan pseudonim 256-bit dalam bentuk hex aman', () => {
    const ids = new Set<string>()
    const keys = new Set<string>()

    for (let index = 0; index < 64; index += 1) {
      const id = createReportId()
      const key = createReporterKey()
      expect(id).toMatch(/^[0-9a-f]{32}$/)
      expect(key).toMatch(/^[0-9a-f]{64}$/)
      ids.add(id)
      keys.add(key)
    }

    expect(ids.size).toBe(64)
    expect(keys.size).toBe(64)
  })

  it('tidak menurunkan pseudonim dari UID atau URL', () => {
    const first = createReporterKey()
    const second = createReporterKey()

    expect(first).not.toBe(second)
    expect(first).not.toContain('user')
    expect(first).not.toContain('contoh')
  })
})

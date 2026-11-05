import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  httpsCallable: vi.fn(),
  getFirebaseClient: vi.fn(),
}))

vi.mock('firebase/functions', () => ({ httpsCallable: mocks.httpsCallable }))
vi.mock('../firebase/config', () => ({ isFirebaseConfigured: true }))
vi.mock('../firebase/client', () => ({ getFirebaseClient: mocks.getFirebaseClient }))

import { CommunityServiceError } from './communityErrors'
import {
  getCommunityContext,
  listCommunityReports,
  submitCommunityReport,
} from './communityFunctionsService'
import {
  COMMUNITY_DAILY_LIMIT_MESSAGE,
  type CommunitySummary,
} from './types'

type Handler = (data: unknown) => Promise<unknown>
let handler: Handler

function summary(overrides: Partial<CommunitySummary> = {}): CommunitySummary {
  return {
    hostname: 'contoh-situs.id',
    reportCount: 2,
    reporterCount: 2,
    categoryCounts: { phishing: 2 },
    firstReportedAt: '2026-10-20T02:00:00.000Z',
    lastReportedAt: '2026-10-20T03:00:00.000Z',
    lastActivityAt: '2026-10-20T03:00:00.000Z',
    moderationStatus: 'community_reported',
    reviewRequired: false,
    reviewReason: null,
    verificationSource: null,
    verifiedAt: null,
    aggregatesComplete: true,
    ...overrides,
  }
}

function reportEntry(userName: string) {
  return {
    userName,
    reportText: `Laporan dari ${userName} tentang formulir palsu.`,
    category: 'phishing',
    hostname: 'contoh-situs.id',
    createdAt: '2026-10-20T02:00:00.000Z',
    updatedAt: '2026-10-20T02:00:00.000Z',
  }
}

function firebaseError(code: string, details?: unknown): Error {
  return Object.assign(new Error('permintaan gagal'), { code: `functions/${code}`, details })
}

beforeEach(() => {
  handler = async () => ({})
  mocks.getFirebaseClient.mockReturnValue({ functions: {} })
  mocks.httpsCallable.mockImplementation(
    (_functions: unknown, _name: string) => async (data: unknown) => ({ data: await handler(data) }),
  )
})

describe('pemetaan respons Community Reports', () => {
  it('membaca reporterCount dan laporan nyata untuk konteks URL', async () => {
    handler = async () => ({
      summary: { ...summary(), reporterCount: 2 },
      report: {
        userName: 'Rani Halim',
        category: 'phishing',
        reason: 'Formulir meminta kata sandi.',
        createdAt: '2026-10-20T02:00:00.000Z',
        updatedAt: '2026-10-20T02:00:00.000Z',
      },
      reports: [reportEntry('Rani Halim'), reportEntry('Bima Santosa')],
    })

    const context = await getCommunityContext('https://contoh-situs.id/login')

    expect(context.summary?.reportCount).toBe(2)
    expect(context.summary?.reporterCount).toBe(2)
    expect(context.report?.userName).toBe('Rani Halim')
    expect(context.reports.map((entry) => entry.userName)).toEqual([
      'Rani Halim',
      'Bima Santosa',
    ])
    expect(context.reports[0].reportText).toContain('formulir palsu')
  })

  it('memakai reportCount sebagai fallback untuk respons backend lama', async () => {
    const legacy = summary({ reportCount: 3, reporterCount: 3 }) as Record<string, unknown>
    delete legacy.reporterCount
    handler = async () => ({ summary: legacy, report: null, reports: [] })

    const context = await getCommunityContext('https://contoh-situs.id/login')

    expect(context.summary?.reporterCount).toBe(3)
  })

  it('menolak respons dengan kategori laporan yang tidak dikenal', async () => {
    handler = async () => ({
      summary: summary(),
      report: null,
      reports: [{ ...reportEntry('Rani'), category: 'kategori-palsu' }],
    })

    await expect(
      getCommunityContext('https://contoh-situs.id/login'),
    ).rejects.toMatchObject({ code: 'invalid-response' })
  })

  it('mengambil daftar laporan 24 jam tanpa mengubah field tampilan', async () => {
    handler = async () => ({ reports: [reportEntry('Rani Halim')] })

    const reports = await listCommunityReports()

    expect(reports).toHaveLength(1)
    expect(reports[0]).toMatchObject({
      userName: 'Rani Halim',
      hostname: 'contoh-situs.id',
      createdAt: '2026-10-20T02:00:00.000Z',
    })
  })
})

describe('pemisahan batas harian dari kegagalan layanan', () => {
  const input = {
    url: 'https://contoh-situs.id/login',
    category: 'phishing' as const,
    reason: 'Formulir meminta kata sandi dan kode OTP sekaligus.',
  }

  it('memakai pesan baku hanya ketika backend menandai batas harian', async () => {
    handler = async () => {
      throw firebaseError('resource-exhausted', { reason: 'daily_limit_reached' })
    }

    const error = (await submitCommunityReport(input).catch((caught) => caught)) as CommunityServiceError

    expect(error).toBeInstanceOf(CommunityServiceError)
    expect(error.dailyLimitReached).toBe(true)
    expect(error.message).toBe(COMMUNITY_DAILY_LIMIT_MESSAGE)
    expect(error.message).not.toMatch(/ditolak/i)
  })

  it('tidak menyamakan kuota layanan lain dengan pesan batas harian', async () => {
    handler = async () => {
      throw firebaseError('resource-exhausted', { reason: 'other_quota' })
    }

    const error = (await submitCommunityReport(input).catch((caught) => caught)) as CommunityServiceError

    expect(error.dailyLimitReached).toBe(false)
    expect(error.message).not.toBe(COMMUNITY_DAILY_LIMIT_MESSAGE)
  })

  it('kegagalan database tetap menjadi error, bukan hasil kosong atau sukses palsu', async () => {
    handler = async () => {
      throw firebaseError('unavailable')
    }

    await expect(listCommunityReports()).rejects.toMatchObject({
      code: 'unavailable',
      message: 'Layanan Community Reports tidak dapat dihubungi. Coba lagi nanti.',
    })
    await expect(
      getCommunityContext('https://contoh-situs.id/login'),
    ).rejects.toMatchObject({ code: 'unavailable' })
  })
})

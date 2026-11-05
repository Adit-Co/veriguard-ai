import { describe, expect, it } from 'vitest'
import {
  MODERATION_STATUS_META,
  allowedModerationActions,
  canTransitionModeration,
} from './types'

describe('status dan transisi moderasi', () => {
  it('memakai label status yang disepakati', () => {
    expect(MODERATION_STATUS_META.pending.label).toBe('Menunggu peninjauan')
    expect(MODERATION_STATUS_META.review.label).toBe('Sedang ditinjau')
    expect(MODERATION_STATUS_META.confirmed_malicious.label).toBe(
      'Terverifikasi berbahaya',
    )
    expect(MODERATION_STATUS_META.inconclusive.label).toBe('Belum cukup bukti')
    expect(MODERATION_STATUS_META.rejected.label).toBe('Ditolak')
  })

  it('hanya mengizinkan peninjauan atau keputusan akhir dari status awal', () => {
    expect(
      allowedModerationActions(null).map((action) => action.to),
    ).toEqual(['review', 'confirmed_malicious', 'inconclusive', 'rejected'])
    expect(
      allowedModerationActions('pending').map((action) => action.to),
    ).toEqual(['review', 'confirmed_malicious', 'inconclusive', 'rejected'])
    expect(
      allowedModerationActions('review').map((action) => action.to),
    ).toEqual(['confirmed_malicious', 'inconclusive', 'rejected'])
  })

  it('tidak membuka kembali status akhir', () => {
    for (const terminal of [
      'confirmed_malicious',
      'inconclusive',
      'rejected',
    ] as const) {
      expect(allowedModerationActions(terminal)).toEqual([])
      expect(canTransitionModeration(terminal, 'review')).toBe(false)
      expect(canTransitionModeration(terminal, 'pending')).toBe(false)
      expect(canTransitionModeration(terminal, 'confirmed_malicious')).toBe(false)
    }
  })

  it('menolak transisi mundur dan transisi tanpa perubahan', () => {
    expect(canTransitionModeration(null, 'pending')).toBe(false)
    expect(canTransitionModeration(null, 'review')).toBe(true)
    expect(canTransitionModeration('pending', 'pending')).toBe(false)
    expect(canTransitionModeration('review', 'review')).toBe(false)
    expect(canTransitionModeration('review', 'rejected')).toBe(true)
  })
})

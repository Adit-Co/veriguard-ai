import { describe, expect, it } from 'vitest'
import { safeRedirectTarget } from './redirect'

describe('safeRedirectTarget', () => {
  it('mempertahankan path internal beserta query dan hash', () => {
    expect(safeRedirectTarget('/komunitas?url=https%3A%2F%2Fcontoh.com#form')).toBe(
      '/komunitas?url=https%3A%2F%2Fcontoh.com#form',
    )
  })

  it('menolak tujuan eksternal dan protocol-relative', () => {
    expect(safeRedirectTarget('https://evil.example')).toBe('/dashboard')
    expect(safeRedirectTarget('//evil.example/path')).toBe('/dashboard')
    expect(safeRedirectTarget('/\\evil.example')).toBe('/dashboard')
    expect(safeRedirectTarget('///evil.example')).toBe('/dashboard')
  })

  it('memakai fallback untuk nilai yang tidak valid', () => {
    expect(safeRedirectTarget(undefined)).toBe('/dashboard')
    expect(safeRedirectTarget(null)).toBe('/dashboard')
    expect(safeRedirectTarget(42)).toBe('/dashboard')
    expect(safeRedirectTarget({ from: '/komunitas' })).toBe('/dashboard')
  })
})

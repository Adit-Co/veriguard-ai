import { describe, expect, it } from 'vitest'
import { canRunExternalScan, resolveExternalScanRequest } from './consent'

describe('keputusan pemeriksaan eksternal', () => {
  it('otomatis meneruskan URL link normal tanpa checkbox consent', () => {
    expect(
      resolveExternalScanRequest({
        mode: 'link',
        featureEnabled: true,
        sensitive: false,
      }),
    ).toEqual({ requested: true, send: true, blockedReason: null })
  })

  it('menahan pengiriman saat fitur eksternal mati', () => {
    expect(
      resolveExternalScanRequest({
        mode: 'link',
        featureEnabled: false,
        sensitive: false,
      }),
    ).toEqual({ requested: false, send: false, blockedReason: 'feature_disabled' })
  })

  it('tidak memakai pemeriksaan eksternal untuk mode pesan', () => {
    expect(
      resolveExternalScanRequest({
        mode: 'message',
        featureEnabled: true,
        sensitive: false,
      }),
    ).toEqual({ requested: false, send: false, blockedReason: 'not_link' })
  })

  it('tidak mengirim URL sensitif', () => {
    expect(
      resolveExternalScanRequest({
        mode: 'link',
        featureEnabled: true,
        sensitive: true,
      }),
    ).toEqual({ requested: false, send: false, blockedReason: 'sensitive_url' })
  })

  it('hanya mengizinkan eksternal untuk link normal', () => {
    expect(
      canRunExternalScan({
        mode: 'link',
        featureEnabled: true,
        sensitive: false,
      }),
    ).toBe(true)
    expect(
      canRunExternalScan({
        mode: 'link',
        featureEnabled: false,
        sensitive: false,
      }),
    ).toBe(false)
    expect(
      canRunExternalScan({
        mode: 'message',
        featureEnabled: true,
        sensitive: false,
      }),
    ).toBe(false)
    expect(
      canRunExternalScan({
        mode: 'link',
        featureEnabled: true,
        sensitive: true,
      }),
    ).toBe(false)
  })
})

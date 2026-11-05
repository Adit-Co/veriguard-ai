// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import type { ExternalProviderResult, ProviderProgress } from '../../lib/scanners/types'
import { LiveScanPanel } from './LiveScanPanel'

function completedResult(
  overrides: Partial<ExternalProviderResult> = {},
): ExternalProviderResult {
  return {
    id: 'virustotal',
    label: 'VirusTotal',
    status: 'success',
    verdict: 'malicious',
    score: 100,
    summary: '4/93 security engine mendeteksi berbahaya; 1 mencurigakan.',
    signals: [],
    reason: null,
    durationMs: 700,
    ...overrides,
  } as ExternalProviderResult
}

const providers: ProviderProgress[] = [
  { id: 'urlscan', label: 'URLScan.io', state: 'completed', result: completedResult({ id: 'urlscan', verdict: 'clean', score: 0, summary: 'URLScan tidak menemukan indikasi berbahaya.' }) },
  { id: 'virustotal', label: 'VirusTotal', state: 'completed', result: completedResult() },
  { id: 'openphish', label: 'OpenPhish', state: 'running' },
  { id: 'threatfox', label: 'ThreatFox (abuse.ch)', state: 'queued' },
  { id: 'radar', label: 'Cloudflare Radar URL Scanner', state: 'completed', result: completedResult({ id: 'radar', status: 'timeout', verdict: 'inconclusive', score: null, summary: 'Cloudflare URL Scanner belum selesai dalam batas waktu.' }) },
  { id: 'otx', label: 'AlienVault OTX', state: 'completed', result: completedResult({ id: 'otx', status: 'skipped', verdict: 'inconclusive', score: null, summary: 'Provider tidak dijalankan.' }) },
  { id: 'hybrid', label: 'Hybrid Analysis', state: 'completed', result: completedResult({ id: 'hybrid', status: 'not_configured', verdict: 'inconclusive', score: null, summary: 'Provider belum dikonfigurasi di backend.', reason: 'Hybrid Analysis belum dapat dipakai; HYBRID_ANALYSIS_API_KEY belum dikonfigurasi.' }) },
  { id: 'safebrowsing', label: 'Google Safe Browsing', state: 'completed', result: completedResult({ id: 'safebrowsing', status: 'success', verdict: 'suspicious', score: 45, summary: 'Google Safe Browsing menilai URL ini "low" (skor provider 45).', evidence: { source: 'new_scan', observedAt: null, ageMs: 0 } }) },
]

describe('panel progres pemeriksaan', () => {
  afterEach(cleanup)

  it('menampilkan delapan label agen tanpa nama penyedia', () => {
    const { container } = render(<LiveScanPanel providers={providers} />)

    for (const label of ['Agen 1', 'Agen 2', 'Agen 3', 'Agen 4', 'Agen 5', 'Agen 6', 'Agen 7', 'Agen 8']) {
      expect(screen.getByText(label)).toBeTruthy()
    }

    const html = container.innerHTML
    for (const name of ['URLScan', 'Safe Browsing', 'VirusTotal', 'OpenPhish', 'ThreatFox', 'Cloudflare', 'AlienVault', 'abuse.ch', 'Hybrid Analysis', 'Falcon']) {
      expect(html).not.toContain(name)
    }
    expect(html).toContain('4/93 mesin keamanan mendeteksi berbahaya; 1 mencurigakan.')
    expect(html).toContain('Agen 1 tidak menemukan indikasi berbahaya.')
    expect(html).toContain('Agen 5 belum selesai dalam batas waktu.')
    expect(html).toContain('Agen 8 menilai URL ini "low" (skor agen 45).')
  })

  it('memakai label agen pada status berjalan dan membedakan status', () => {
    const { container } = render(<LiveScanPanel providers={providers} />)
    const text = container.textContent ?? ''

    expect(screen.getByText('Memeriksa Agen 3')).toBeTruthy()
    expect(text).toContain('6/8 selesai')
    expect(text).toContain('Selesai')
    expect(text).toContain('Berjalan')
    expect(text).toContain('Menunggu')
    expect(text).toContain('Melebihi batas waktu')
    expect(text).toContain('Tidak dijalankan')
  })

  it('membedakan tidak ada kecocokan, belum dikonfigurasi, dan dibatasi', () => {
    const { container } = render(
      <LiveScanPanel
        providers={[
          {
            id: 'threatfox',
            label: 'ThreatFox (abuse.ch)',
            state: 'completed',
            result: completedResult({
              id: 'threatfox',
              status: 'not_found',
              verdict: 'inconclusive',
              score: null,
              summary: 'ThreatFox tidak menemukan IOC untuk URL ini.',
            }),
          },
          {
            id: 'openphish',
            label: 'OpenPhish',
            state: 'completed',
            result: completedResult({
              id: 'openphish',
              status: 'not_configured',
              verdict: 'inconclusive',
              score: null,
              summary: 'Provider belum dikonfigurasi di backend.',
            }),
          },
          {
            id: 'urlscan',
            label: 'URLScan.io',
            state: 'completed',
            result: completedResult({
              id: 'urlscan',
              status: 'rate_limited',
              verdict: 'inconclusive',
              score: null,
              summary: 'Kuota provider tercapai.',
              reason: 'Kuota permintaan provider tercapai. (HTTP 429)',
            }),
          },
        ]}
      />,
    )
    const text = container.textContent ?? ''

    expect(text).toContain('Tidak ada kecocokan')
    expect(text).toContain('Belum dikonfigurasi')
    expect(text).toContain('Dibatasi')
    expect(text).toContain('Agen 4 tidak menemukan IOC untuk URL ini.')
    expect(text).not.toContain('Risiko rendah')
  })

  it('membuang narasi laporan lama dari ringkasan progres tanpa menghilangkan vonisnya', () => {
    const { container } = render(
      <LiveScanPanel
        providers={[
          {
            id: 'urlscan',
            label: 'URLScan.io',
            state: 'completed',
            result: completedResult({
              id: 'urlscan',
              status: 'success',
              verdict: 'clean',
              score: 0,
              summary:
                'Menggunakan laporan URLScan yang sudah ada (dibuat 2 jam lalu). URLScan tidak menemukan indikasi berbahaya.',
              evidence: {
                source: 'existing_report',
                observedAt: '2026-01-01T00:00:00.000Z',
                ageMs: 2 * 60 * 60_000,
              },
            }),
          },
          {
            id: 'radar',
            label: 'Cloudflare Radar URL Scanner',
            state: 'completed',
            result: completedResult({
              id: 'radar',
              status: 'success',
              verdict: 'clean',
              score: 0,
              summary: 'Cloudflare URL Scanner memberikan vonis.',
              evidence: { source: 'new_scan', observedAt: null, ageMs: 0 },
            }),
          },
        ]}
      />,
    )
    const text = container.textContent ?? ''

    // Kalimat yang menjelaskan cara hasil diperoleh tidak pernah tampil di progres langsung,
    // sedangkan vonis agen dari laporan lama tetap terbaca apa adanya.
    expect(text).not.toContain('Menggunakan laporan')
    expect(text).not.toContain('bukan pemindaian langsung')
    expect(text).toContain('Agen 1 tidak menemukan indikasi berbahaya.')
    // Pemindaian langsung tidak diberi penanda apa pun.
    expect(text).toContain('Agen 5 memberikan vonis.')
  })

  it('tidak menampilkan agen sebagai berjalan sebelum permintaannya dimulai', () => {
    const { container } = render(<LiveScanPanel providers={providers} />)
    const text = container.textContent ?? ''

    expect(text.match(/Permintaan agen sedang berjalan/g)?.length).toBe(1)
    expect(text).toContain('Menunggu giliran.')
    expect(screen.getByText('Memeriksa Agen 3')).toBeTruthy()
  })

  it('tidak menganggap hasil tanpa data sebagai aman', () => {
    render(
      <LiveScanPanel
        providers={[
          {
            id: 'threatfox',
            label: 'ThreatFox (abuse.ch)',
            state: 'completed',
            result: completedResult({
              id: 'threatfox',
              status: 'not_found',
              verdict: 'inconclusive',
              score: null,
              summary: 'ThreatFox tidak menemukan IOC untuk URL ini.',
            }),
          },
        ]}
      />,
    )

    expect(screen.getByText('Agen 4')).toBeTruthy()
    expect(screen.getByText('Tidak ada kecocokan')).toBeTruthy()
    expect(screen.getByText('Agen 4 tidak menemukan IOC untuk URL ini.')).toBeTruthy()
  })

  it('tidak pernah menyebut hasil tersimpan ketika agen memakai cache', () => {
    const cached = render(
      <LiveScanPanel
        providers={[
          {
            id: 'urlscan',
            label: 'URLScan.io',
            state: 'completed',
            result: completedResult({
              id: 'urlscan',
              verdict: 'clean',
              score: 0,
              summary: 'URLScan tidak menemukan indikasi berbahaya.',
              cache: {
                hit: true,
                observedAt: '2026-01-01T00:00:00.000Z',
                ageMs: 600_000,
                stale: false,
              },
            }),
          },
        ]}
      />,
    )

    const text = cached.container.textContent ?? ''
    for (const hidden of [
      'Memakai hasil tersimpan',
      'hasil tersimpan',
      'tidak diulang',
      '2026-01-01',
      '600000',
    ]) {
      expect(text).not.toContain(hidden)
    }
    // Pengguna tetap melihat hasil agen dan status selesai seperti biasa.
    expect(text).toContain('tidak menemukan indikasi berbahaya.')
    expect(text).toContain('Selesai')

    const running = render(
      <LiveScanPanel
        providers={[{ id: 'urlscan', label: 'URLScan.io', state: 'running' }]}
      />,
    )
    expect(running.container.textContent).toContain('Permintaan agen sedang berjalan...')

    cached.unmount()
    running.unmount()
  })
})

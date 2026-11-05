import { useCallback, useEffect, useRef, useState } from 'react'
import { isSiteAnalysisAvailable, requestSiteAnalysis } from './client'
import { siteAnalysisErrorMessage } from './errors'
import { getSiteAnalysis, saveSiteAnalysis } from './analysisStore'
import type { SiteAnalysisResponse } from './types'

export type SiteAnalysisState = 'idle' | 'running' | 'ready' | 'failed'

export type UseSiteAnalysisOptions = {
  /** Jalankan analisis sendiri begitu URL hasil scan tersedia. */
  autoRun?: boolean
}

export type UseSiteAnalysisResult = {
  state: SiteAnalysisState
  data: SiteAnalysisResponse | null
  error: string | null
  available: boolean
  autoRun: boolean
  run: () => Promise<void>
  reset: () => void
}

export function useSiteAnalysis(
  scanId: string,
  url: string,
  options: UseSiteAnalysisOptions = {},
): UseSiteAnalysisResult {
  const { autoRun = false } = options
  const available = isSiteAnalysisAvailable()
  const [state, setState] = useState<SiteAnalysisState>('idle')
  const [data, setData] = useState<SiteAnalysisResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const controllerRef = useRef<AbortController | null>(null)
  const mountedRef = useRef(true)
  const autoRunForRef = useRef<string | null>(null)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      // React StrictMode melepas lalu memasang ulang komponen pada mount yang sama.
      // Membatalkan permintaan saat lepas sementara itu membuat analisis berhenti di
      // tengah jalan, jadi pembatalan ditunda satu tick dan hanya dijalankan bila
      // komponen benar-benar masih terlepas.
      globalThis.setTimeout(() => {
        if (!mountedRef.current) controllerRef.current?.abort()
      }, 0)
    }
  }, [])

  useEffect(() => {
    const cached = available ? getSiteAnalysis(scanId) : null
    // oxlint-disable-next-line react/set-state-in-effect -- sinkronisasi cache localStorage
    setData(cached)
    setState(cached ? 'ready' : 'idle')
    setError(null)
  }, [available, scanId])

  const run = useCallback(async () => {
    // Tanpa backend yang bisa membuka URL, permintaan hanya akan gagal di tengah jalan
    // dan tetap menyimpan status gagal yang tidak bisa dilihat pengguna.
    if (!available) return
    setState('running')
    setError(null)
    const controller = new AbortController()
    controllerRef.current = controller

    try {
      const report = await requestSiteAnalysis(url, { signal: controller.signal })
      if (!mountedRef.current) return
      setData(report)
      setState('ready')
      saveSiteAnalysis(scanId, report)
    } catch (cause) {
      // Sinyal dibatalkan saat halaman ditinggalkan atau saat React StrictMode
      // memasang ulang komponen. Itu bukan kegagalan layanan, jadi jangan tinggalkan
      // status gagal yang bisa dibaca sebagai "tidak dapat dihubungi".
      if (controller.signal.aborted) {
        autoRunForRef.current = null
        if (!mountedRef.current) return
        setData(null)
        setError(null)
        setState('idle')
        return
      }
      if (!mountedRef.current) return
      setData(null)
      setState('failed')
      setError(siteAnalysisErrorMessage(cause))
    } finally {
      controllerRef.current = null
    }
  }, [available, scanId, url])

  // Alur yang diminta: setelah agen eksternal selesai, analisis situs berjalan sendiri untuk
  // URL yang sama. Sekali percobaan per scan; kegagalan tidak diulang otomatis.
  useEffect(() => {
    if (!autoRun || !available || !scanId || !url) return
    if (state !== 'idle') return
    if (getSiteAnalysis(scanId)) return
    const key = `${scanId}|${url}`
    if (autoRunForRef.current === key) return
    autoRunForRef.current = key
    void run()
  }, [autoRun, available, scanId, url, state, run])

  function reset() {
    controllerRef.current?.abort()
    autoRunForRef.current = null
    setData(null)
    setError(null)
    setState('idle')
  }

  return {
    state: available ? state : 'idle',
    data,
    error,
    available,
    autoRun,
    run,
    reset,
  }
}

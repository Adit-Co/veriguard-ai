import { useEffect, useRef, useState } from 'react'
import { loadTurnstileApi } from '../../lib/turnstile/script'
import type { TurnstileApi } from '../../lib/turnstile/script'
import { turnstileSiteKey } from '../../lib/turnstile/client'
import { cn } from '../../lib/cn'

export type TurnstileStatus = 'loading' | 'ready' | 'failed'

type TurnstileProps = {
  /** Nilai `data-action` widget; server membandingkannya dengan aksi yang diharapkan. */
  action: string
  onToken: (token: string) => void
  onExpire?: () => void
  /** Widget gagal memuat atau menolak kunci situs; berbeda dari token yang kedaluwarsa. */
  onError?: () => void
  /** Status widget supaya halaman dapat memberi tahu bahwa verifikasi belum siap. */
  onStatusChange?: (status: TurnstileStatus) => void
  /** Naikkan nilai untuk meminta token baru; token lama tidak dipakai ulang. */
  attempt?: number
  className?: string
}

export function Turnstile({
  action,
  onToken,
  onExpire,
  onError,
  onStatusChange,
  attempt = 0,
  className,
}: TurnstileProps) {
  const siteKey = turnstileSiteKey()
  const containerRef = useRef<HTMLDivElement | null>(null)
  const widgetIdRef = useRef<string | null>(null)
  const apiRef = useRef<TurnstileApi | null>(null)
  const onTokenRef = useRef(onToken)
  const onExpireRef = useRef(onExpire)
  const onErrorRef = useRef(onError)
  const onStatusChangeRef = useRef(onStatusChange)
  const [status, setStatus] = useState<TurnstileStatus>('loading')

  // Callback disimpan di ref agar widget yang sudah terlanjur ter-render tidak membawa
  // closure lama. Penulisan terjadi di dalam effect, bukan di render.
  useEffect(() => {
    onTokenRef.current = onToken
    onExpireRef.current = onExpire
    onErrorRef.current = onError
    onStatusChangeRef.current = onStatusChange
  }, [onToken, onExpire, onError, onStatusChange])

  useEffect(() => {
    onStatusChangeRef.current?.(status)
  }, [status])

  useEffect(() => {
    if (!siteKey) return
    let cancelled = false

    void (async () => {
      try {
        const api = await loadTurnstileApi()
        if (cancelled || !containerRef.current) return
        apiRef.current = api
        widgetIdRef.current = api.render(containerRef.current, {
          sitekey: siteKey,
          action,
          appearance: 'always',
          callback: (token) => onTokenRef.current(token),
          'expired-callback': () => onExpireRef.current?.(),
          // Galat widget (misalnya kunci situs tidak cocok dengan hostname) harus terlihat
          // dan dipisah dari token kedaluwarsa: halaman tidak boleh menafsirkannya sebagai
          // verifikasi server yang gagal.
          'error-callback': () => {
            onErrorRef.current?.()
            setStatus('failed')
          },
        })
        setStatus('ready')
      } catch {
        if (!cancelled) setStatus('failed')
      }
    })()

    return () => {
      cancelled = true
      const api = apiRef.current
      const widgetId = widgetIdRef.current
      if (api && widgetId) {
        try {
          api.remove(widgetId)
        } catch {
          // Widget yang sudah tidak ada tidak perlu memicu galat baru saat lepas halaman.
        }
      }
      widgetIdRef.current = null
    }
  }, [action, siteKey])

  // Token Turnstile hanya berlaku sekali. Setiap percobaan baru harus meminta token baru,
  // termasuk saat percobaan sebelumnya ditolak server.
  useEffect(() => {
    if (attempt <= 0) return
    const api = apiRef.current
    const widgetId = widgetIdRef.current
    if (api && widgetId) api.execute(widgetId)
  }, [attempt])

  if (!siteKey) return null

  return (
    <div className={cn('mt-5', className)} data-turnstile-widget={action}>
      <div ref={containerRef} />
      {status === 'loading' ? (
        <p className="type-caption mt-2" role="status">
          Memuat verifikasi…
        </p>
      ) : null}
      {status === 'failed' ? (
        <p className="type-caption mt-2 text-risk-medium" role="alert">
          Verifikasi tidak dapat dimuat. Muat ulang halaman lalu coba lagi.
        </p>
      ) : null}
    </div>
  )
}

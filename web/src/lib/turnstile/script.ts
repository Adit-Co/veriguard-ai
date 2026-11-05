// Widget Cloudflare Turnstile dimuat dari skrip resminya, bukan dari paket npm, supaya
// tidak ada dependensi baru dan token tidak pernah dibuat di sisi klien.
export type TurnstileWidgetOptions = {
  sitekey: string
  action?: string
  appearance?: 'always' | 'auto' | 'execute' | 'interaction-only'
  execution?: 'render' | 'execute'
  theme?: 'light' | 'dark' | 'auto'
  size?: 'normal' | 'flexible' | 'compact' | 'invisible'
  callback?: (token: string) => void
  'error-callback'?: () => void
  'expired-callback'?: () => void
  'timeout-callback'?: () => void
}

export type TurnstileApi = {
  render: (element: HTMLElement, options: TurnstileWidgetOptions) => string
  remove: (widgetId: string) => void
  execute: (widgetId: string) => void
  refresh: (widgetId: string, options?: { execute?: boolean }) => void
}

declare global {
  interface Window {
    turnstile?: TurnstileApi
  }
}

// render=explicit diperlukan agar widget bisa dirender ke elemen yang sudah dibuat React.
const TURNSTILE_API_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'

let loader: Promise<TurnstileApi> | null = null

export function loadTurnstileApi(): Promise<TurnstileApi> {
  if (typeof window === 'undefined') {
    return Promise.reject(new Error('Verifikasi CAPTCHA hanya tersedia di browser.'))
  }
  if (window.turnstile) return Promise.resolve(window.turnstile)

  if (!loader) {
    loader = new Promise<TurnstileApi>((resolve, reject) => {
      const script = document.createElement('script')
      script.src = TURNSTILE_API_URL
      script.async = true
      script.defer = true

      const fail = (message: string) => {
        loader = null
        script.remove()
        reject(new Error(message))
      }

      script.onload = () => {
        if (window.turnstile) resolve(window.turnstile)
        else fail('Layanan verifikasi CAPTCHA tidak dapat dimuat.')
      }
      script.onerror = () => fail('Layanan verifikasi CAPTCHA tidak dapat dimuat.')

      document.head.appendChild(script)
    })
  }

  return loader
}

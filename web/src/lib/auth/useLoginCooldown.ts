import { useCallback, useEffect, useRef, useState } from 'react'
import {
  LOGIN_GUARD_ATTEMPTS_PER_LEVEL,
  readLoginCooldown,
  type LoginGuardCooldown,
  type LoginGuardOptions,
} from './loginGuard'

// VGL-38 — keadaan cooldown untuk halaman masuk. Hitungan detik hanya untuk tampilan: angka yang
// menahan tombol berasal dari gerbang (jam server) dan dibaca ulang berkala, jadi mengubah jam
// perangkat atau memuat ulang halaman tidak memperpendek pembatasan.
// VGL-39A — angka "sisa kesempatan" juga datang dari gerbang, bukan dari hitungan klien.

const IDLE: LoginGuardCooldown = {
  active: false,
  retryAfterMs: 0,
  level: 0,
  failures: 0,
  attemptsLeft: LOGIN_GUARD_ATTEMPTS_PER_LEVEL,
  attemptsPerLevel: LOGIN_GUARD_ATTEMPTS_PER_LEVEL,
  authority: 'none',
}

const POLLS: { underMs: number; everyMs: number }[] = [
  { underMs: 60_000, everyMs: 5_000 },
  { underMs: 10 * 60_000, everyMs: 15_000 },
  { underMs: Number.POSITIVE_INFINITY, everyMs: 60_000 },
]

function pollIntervalMs(retryAfterMs: number): number {
  const entry = POLLS.find((candidate) => retryAfterMs < candidate.underMs) ?? POLLS[POLLS.length - 1]
  return entry.everyMs
}

export type LoginCooldownView = {
  cooldown: LoginGuardCooldown
  secondsLeft: number
  refresh: () => void
}

export type LoginCooldownDeps = {
  now?: () => number
  read?: (options?: LoginGuardOptions) => Promise<LoginGuardCooldown>
}

export function useLoginCooldown(deps: LoginCooldownDeps = {}): LoginCooldownView {
  const [cooldown, setCooldown] = useState<LoginGuardCooldown>(IDLE)
  // endsAt ditulis dalam jam lokal saat keputusan diterima; selisih negatif (jam dimundurkan)
  // di-clamp ke 0 sehingga countdown tidak pernah melompat mundur lebih cepat.
  const endsAtRef = useRef<number | null>(null)

  const clock = deps.now ?? Date.now
  const read = deps.read ?? readLoginCooldown

  const apply = useCallback(
    (next: LoginGuardCooldown) => {
      setCooldown(next)
      endsAtRef.current = next.active ? clock() + next.retryAfterMs : null
    },
    [clock],
  )

  const refresh = useCallback(() => {
    void read().then(apply, () => undefined)
  }, [apply, read])

  useEffect(() => {
    refresh()

    const onVisibility = () => {
      if (document.visibilityState === 'visible') refresh()
    }
    document.addEventListener('visibilitychange', onVisibility)
    return () => document.removeEventListener('visibilitychange', onVisibility)
  }, [refresh])

  const [secondsLeft, setSecondsLeft] = useState(0)

  useEffect(() => {
    if (!cooldown.active) return

    let stopped = false
    const tick = () => {
      if (stopped) return
      const endsAt = endsAtRef.current
      const remaining = endsAt === null ? 0 : Math.max(0, endsAt - clock())
      setSecondsLeft(Math.ceil(remaining / 1_000))
      if (remaining <= 0) refresh()
    }

    tick()
    const timer = window.setInterval(tick, pollIntervalMs(cooldown.retryAfterMs))
    return () => {
      stopped = true
      window.clearInterval(timer)
    }
  }, [clock, cooldown, refresh])

  // Nilai 0 saat tidak aktif diturunkan saat render, bukan lewat setState di dalam effect.
  return { cooldown, secondsLeft: cooldown.active ? secondsLeft : 0, refresh }
}

/**
 * VGL-39A — baris kesempatan untuk UI. Kosong saat sumber sedang terkunci: angkanya datang dari
 * gerbang, dan selama cooldown tidak ada kesempatan yang bisa dipakai.
 */
export function formatAttemptsRemaining(cooldown: LoginGuardCooldown): string | null {
  const perLevel = cooldown.attemptsPerLevel || LOGIN_GUARD_ATTEMPTS_PER_LEVEL
  if (cooldown.active || perLevel <= 0) return null
  if (cooldown.attemptsLeft >= perLevel) return null
  return `Kesempatan login tersisa: ${cooldown.attemptsLeft} dari ${perLevel}`
}

export function formatCooldownRemaining(seconds: number): string {
  if (seconds <= 0) return '0 detik'
  const hours = Math.floor(seconds / 3_600)
  const minutes = Math.floor((seconds % 3_600) / 60)
  const rest = seconds % 60

  const parts: string[] = []
  if (hours > 0) parts.push(`${hours} jam`)
  if (minutes > 0) parts.push(`${minutes} menit`)
  if (hours === 0 && rest > 0) parts.push(`${rest} detik`)
  return parts.join(' ')
}

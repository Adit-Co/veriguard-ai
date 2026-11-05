import { AtSign } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Alert } from '../ui/Alert'
import { Button } from '../ui/Button'
import { Card } from '../ui/Card'
import { Input } from '../ui/Input'
import { useAuth } from '../../lib/auth/useAuth'
import { UsernameClaimError, usernameClaimErrorMessage } from '../../lib/firebase/usernames'
import {
  USERNAME_MAX_LENGTH,
  USERNAME_MIN_LENGTH,
  validateUsername,
} from '../../lib/usernames/policy'

export function AccountUsernameCard() {
  const auth = useAuth()
  const [value, setValue] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [claimed, setClaimed] = useState<string | null>(null)

  const username = auth.profile?.username ?? claimed
  if (auth.mode !== 'firebase') return null

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting) return

    setError(null)
    const checked = validateUsername(value)
    if (!checked.valid) {
      setError(checked.error)
      return
    }

    setSubmitting(true)
    try {
      const result = await auth.claimExistingUsername(checked.username)
      setClaimed(result.username)
      setValue('')
    } catch (cause) {
      setError(
        cause instanceof UsernameClaimError
          ? usernameClaimErrorMessage(cause)
          : 'Username belum dapat dipasang. Periksa koneksi lalu coba lagi.',
      )
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Card className="p-5">
      <div className="flex items-center gap-2.5">
        <span className="grid size-8 place-items-center rounded-lg bg-subtle text-ink-muted">
          <AtSign size={17} aria-hidden="true" />
        </span>
        <h2 className="text-sm font-semibold text-ink">Username akun</h2>
      </div>

      {username ? (
        <>
          <p className="text-sm font-medium mt-4 text-ink">@{username}</p>
          <p className="type-caption mt-2">
            Username hanya dapat dipasang satu kali dan tidak dapat diubah atau dipakai ulang oleh
            akun lain.
          </p>
        </>
      ) : (
        <>
          <p className="type-small mt-3 text-ink-soft">
            Akun ini dibuat sebelum username diwajibkan, jadi username belum terpasang. Satu username
            hanya untuk satu akun: bila nama sudah dipakai, klaim akan ditolak dan username tetap
            milik akun sebelumnya.
          </p>

          {error ? (
            <Alert tone="danger" role="alert" className="mt-4" title="Username gagal dipasang">
              {error}
            </Alert>
          ) : null}

          <form className="mt-4" onSubmit={handleSubmit}>
            <label htmlFor="claim-username" className="text-sm font-medium text-ink">
              Username
            </label>
            <Input
              id="claim-username"
              name="username"
              autoComplete="username"
              maxLength={40}
              required
              value={value}
              onChange={(event) => setValue(event.target.value)}
              className="mt-1.5"
            />
            <p className="type-caption mt-2">
              {USERNAME_MIN_LENGTH}-{USERNAME_MAX_LENGTH} karakter: huruf kecil, angka, dan garis
              bawah (_).
            </p>
            <Button type="submit" size="sm" className="mt-4" disabled={submitting}>
              {submitting ? 'Memasang username…' : 'Pasang username'}
            </Button>
          </form>
        </>
      )}
    </Card>
  )
}

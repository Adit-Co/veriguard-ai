import { Link } from 'react-router-dom'
import { Alert } from '../ui/Alert'
import { Button } from '../ui/Button'
import { buttonStyles } from '../ui/buttonStyles'
import { useAuth } from '../../lib/auth/useAuth'
import { isVerifiedAccount, VERIFICATION_EMAIL_PATH } from '../../lib/auth/verification'

const dateFormatter = new Intl.DateTimeFormat('id-ID', {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
})

function formatDate(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'waktu tidak diketahui' : dateFormatter.format(date)
}

export function ProfileSyncNotice({ showSynced = false }: { showSynced?: boolean }) {
  const auth = useAuth()

  if (auth.mode !== 'firebase' || !auth.user || auth.user.isAnonymous) return null

  if (!isVerifiedAccount(auth.user)) {
    return (
      <Alert tone="warning" className="mt-4" title="Email belum diverifikasi">
        <p>
          Akun sudah dibuat, tetapi alamat email belum dikonfirmasi. Fitur akun tetap terkunci
          sampai verifikasi selesai.
        </p>
        <Link
          to={VERIFICATION_EMAIL_PATH}
          className={buttonStyles({ variant: 'secondary', size: 'sm', className: 'mt-3' })}
        >
          Selesaikan verifikasi email
        </Link>
      </Alert>
    )
  }

  if (auth.profileStatus === 'error') {
    return (
      <Alert tone="warning" className="mt-4" title="Profil akun belum tersinkron">
        <p>
          {auth.profileError ??
            'Profil akun belum dapat disimpan. Periksa koneksi lalu coba lagi.'}
        </p>
        <Button
          variant="secondary"
          size="sm"
          className="mt-3"
          onClick={() => void auth.retryProfileSync()}
        >
          Coba sinkronkan ulang
        </Button>
      </Alert>
    )
  }

  if (auth.profileStatus === 'syncing') {
    return (
      <p role="status" className="type-caption mt-3">
        Menyinkronkan profil akun...
      </p>
    )
  }

  if (showSynced && auth.profileStatus === 'synced' && auth.profile) {
    return (
      <p role="status" className="type-caption mt-3">
        Profil akun tersinkron. Login terakhir{' '}
        {formatDate(auth.profile.lastLoginAt)}.
      </p>
    )
  }

  return null
}

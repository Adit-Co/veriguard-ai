import { ArrowRight, Check, UserPlus } from 'lucide-react'
import { useRef, useState, type FormEvent } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Alert } from '../components/ui/Alert'
import { Button } from '../components/ui/Button'
import { buttonStyles } from '../components/ui/buttonStyles'
import { Card } from '../components/ui/Card'
import { Container } from '../components/ui/Container'
import { Input } from '../components/ui/Input'
import { safeRedirectTarget } from '../lib/auth/redirect'
import { useAuth } from '../lib/auth/useAuth'
import { VERIFICATION_EMAIL_PATH } from '../lib/auth/verification'
import { authErrorMessage } from '../lib/firebase/errors'
import { UsernameClaimError, usernameClaimErrorMessage } from '../lib/firebase/usernames'
import { USERNAME_MAX_LENGTH, USERNAME_MIN_LENGTH, validateUsername } from '../lib/usernames/policy'
import { Turnstile } from '../components/turnstile/Turnstile'
import type { TurnstileStatus } from '../components/turnstile/Turnstile'
import {
  isTurnstileEnabled,
  requestTurnstileVerification,
  turnstileErrorMessage,
  turnstileSiteKey,
} from '../lib/turnstile/client'
import { TURNSTILE_ACTION } from '../lib/turnstile/action'

export function RegisterPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const auth = useAuth()
  const locationState = location.state as { from?: unknown } | null
  const redirectTo = safeRedirectTarget(locationState?.from)
  const [displayName, setDisplayName] = useState('')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  // Pendaftaran selalu mewajibkan CAPTCHA. Bila kunci situs atau layanan verifikasi belum
  // tersedia, tidak ada jalur alternatif: formulir berhenti sebagai galat konfigurasi.
  const captchaConfigured = isTurnstileEnabled(turnstileSiteKey())
  const [captchaToken, setCaptchaToken] = useState<string | null>(null)
  // Status widget dan status verifikasi server dipisah: widget yang sudah tampil belum
  // berarti token diterima server.
  const [widgetStatus, setWidgetStatus] = useState<TurnstileStatus>('loading')
  const [verifyPhase, setVerifyPhase] = useState<'idle' | 'verifying' | 'verified' | 'error'>(
    'idle',
  )
  const [captchaAttempt, setCaptchaAttempt] = useState(0)
  // Token Turnstile hanya bisa diverifikasi satu kali. Token yang sudah diterima server
  // dicatat di sini supaya percobaan mendaftar ulang tidak mengirimnya ke siteverify lagi.
  const verifiedTokenRef = useRef<string | null>(null)
  const currentTokenRef = useRef<string | null>(null)

  function handleCaptchaToken(token: string) {
    // Halaman dibuka tidak boleh memicu verifikasi apa pun: token hanya disimpan,
    // pengiriman ke server terjadi saat pengguna menekan tombol daftar.
    currentTokenRef.current = token
    setCaptchaToken(token)
    setVerifyPhase('idle')
    verifiedTokenRef.current = null
    setError(null)
    setNotice(null)
  }

  function handleCaptchaExpire() {
    // Token kedaluwarsa tanpa interaksi pengguna (widget terisi ulang) tidak boleh
    // memunculkan pesan gagal; token dibuang dan formulir kembali meminta verifikasi.
    currentTokenRef.current = null
    setCaptchaToken(null)
    setVerifyPhase('idle')
    verifiedTokenRef.current = null
  }

  function handleCaptchaError() {
    currentTokenRef.current = null
    setCaptchaToken(null)
    setVerifyPhase('idle')
    verifiedTokenRef.current = null
  }

  function requestFreshChallenge() {
    currentTokenRef.current = null
    setCaptchaToken(null)
    setVerifyPhase('idle')
    verifiedTokenRef.current = null
    setError(null)
    setNotice(null)
    setCaptchaAttempt((current) => current + 1)
  }

  async function handleRegister(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting || verifyPhase === 'verifying') return

    setError(null)
    setNotice(null)

    if (password.length < 8) {
      setError('Kata sandi minimal 8 karakter.')
      return
    }

    if (password !== confirmPassword) {
      setError('Konfirmasi kata sandi tidak cocok.')
      return
    }

    // Format username diperiksa sebelum CAPTCHA: token hanya boleh terpakai untuk
    // percobaan yang datanya sudah sah.
    const checkedUsername = validateUsername(username)
    if (!checkedUsername.valid) {
      setError(checkedUsername.error)
      return
    }

    if (!captchaConfigured) {
      setError(
        'Verifikasi CAPTCHA belum tersedia pada layanan ini, jadi pendaftaran dihentikan. Konfigurasi kunci situs dan layanan verifikasi harus lengkap terlebih dahulu.',
      )
      return
    }

    // Status widget diperiksa lebih dulu dan tidak disamakan dengan hasil verifikasi.
    if (widgetStatus === 'loading') {
      setNotice('Verifikasi CAPTCHA sedang dimuat. Tunggu sampai kotak verifikasi tampil.')
      return
    }
    if (widgetStatus === 'failed') {
      setError('Verifikasi CAPTCHA tidak dapat dimuat. Muat ulang halaman lalu coba lagi.')
      return
    }
    if (!captchaToken) {
      setError('Silakan selesaikan verifikasi CAPTCHA terlebih dahulu.')
      return
    }

    const token = captchaToken
    if (verifiedTokenRef.current !== token) {
      setVerifyPhase('verifying')
      try {
        await requestTurnstileVerification(token)
      } catch (cause) {
        setVerifyPhase('error')
        // Token yang ditolak tidak dipakai lagi. Bila pengguna sudah mendapat token baru
        // selama permintaan berjalan, token baru itu tidak ikut dibuang.
        verifiedTokenRef.current = null
        if (currentTokenRef.current === token) {
          currentTokenRef.current = null
          setCaptchaToken(null)
          setError(turnstileErrorMessage(cause))
        }
        return
      }
      verifiedTokenRef.current = token
    }
    setVerifyPhase('verified')

    setSubmitting(true)

    try {
      const result = await auth.signUp(displayName, email, password, checkedUsername.username)
      if (result.emailVerified) {
        navigate(redirectTo, { replace: true })
        return
      }

      navigate(VERIFICATION_EMAIL_PATH, {
        replace: true,
        state: {
          from: redirectTo,
          justRegistered: true,
          verificationSent: result.verificationSent,
        },
      })
    } catch (cause) {
      // Galat klaim username punya pesan sendiri; jangan disamarkan menjadi galat
      // autentikasi generik.
      setError(
        cause instanceof UsernameClaimError
          ? usernameClaimErrorMessage(cause)
          : authErrorMessage(cause),
      )
    } finally {
      setSubmitting(false)
    }
  }

  // Tombol tetap aktif supaya pengguna mendapat pesan yang jelas; yang ditahan hanya
  // saat permintaan sedang berjalan agar token tidak dikirim dua kali. Tanpa CAPTCHA yang
  // terkonfigurasi tombol ikut dikunci karena tidak ada jalur pendaftaran yang aman.
  const submitBlocked = submitting || verifyPhase === 'verifying' || !captchaConfigured

  return (
    <Container className="pb-16 sm:pb-20">
      <div className="grid gap-10 pt-12 sm:pt-16 lg:grid-cols-[minmax(0,1fr)_minmax(0,460px)] lg:gap-16 lg:pt-20">
        <div className="max-w-[560px]">
          <span className="grid size-11 place-items-center rounded-xl bg-accent-soft text-accent">
            <UserPlus size={20} aria-hidden="true" />
          </span>
          <h1 className="type-h1 mt-5">Buat akun VERIGUARD AI</h1>
          <p className="type-small mt-3 text-ink-soft">
            Dengan akun, hasil pemeriksaan tersimpan di riwayat dan dashboard dapat menampilkan
            ringkasan aktivitasmu.
          </p>

          <ul className="mt-8 flex flex-col gap-3 border-t border-line pt-6 text-sm">
            {[
              'Satu username hanya dipakai satu akun di seluruh aplikasi.',
              'Email dikonfirmasi lewat tautan verifikasi sebelum fitur akun terbuka.',
              'Kata sandi dikelola layanan akun, tidak disimpan di data pemeriksaan.',
            ].map((item) => (
              <li key={item} className="flex items-start gap-2.5 text-ink-soft">
                <Check size={16} className="mt-0.5 shrink-0 text-accent" aria-hidden="true" />
                {item}
              </li>
            ))}
          </ul>
        </div>

        <div className="min-w-0">
          {auth.status === 'loading' ? (
            <Card className="mt-6 p-6" role="status">
              <p className="text-sm font-semibold text-ink">Memeriksa layanan akun…</p>
            </Card>
          ) : null}

          {auth.status === 'error' ? (
            <Alert tone="danger" className="mt-4" title="Layanan akun gagal disiapkan">
              {auth.initializationError ??
                'Layanan akun belum dapat disiapkan. Muat ulang halaman atau hubungi pengelola layanan.'}
            </Alert>
          ) : null}

          {auth.mode === 'demo' ? (
            <>
              <Card className="mt-6 p-6">
                <p className="text-sm font-semibold text-ink">Pendaftaran akun belum tersedia</p>
                <p className="type-small mt-2 text-ink-soft">
                  Pendaftaran email dan Google menunggu layanan akun. Tidak ada formulir yang
                  membuat akun sungguhan pada versi ini.
                </p>
                <div className="mt-5 flex flex-wrap gap-3">
                  <Link to="/masuk" className={buttonStyles({ size: 'sm' })}>
                    Buka sesi demo lokal
                  </Link>
                  <Link to="/periksa" className={buttonStyles({ variant: 'ghost', size: 'sm' })}>
                    Periksa tanpa akun
                  </Link>
                </div>
              </Card>

              <Alert tone="info" className="mt-4">
                Data yang kamu masukkan untuk pemeriksaan tidak disimpan permanen tanpa persetujuan.
              </Alert>
            </>
          ) : null}

          {auth.mode === 'firebase' && auth.status === 'ready' ? (
            <>
              {/* VGL-37: pesan status ditaruh di atas kartu, sama seperti pola box login,
                  sehingga kartu hanya memuat judul + formulir. */}
              {error ? (
                <Alert tone="danger" role="alert" className="mt-4" title="Pendaftaran gagal">
                  {error}
                </Alert>
              ) : null}

              {notice ? (
                <Alert tone="info" role="status" className="mt-4">
                  {notice}
                </Alert>
              ) : null}

              {captchaConfigured ? null : (
                <Alert
                  tone="warning"
                  role="status"
                  className="mt-4"
                  title="Verifikasi CAPTCHA belum dikonfigurasi"
                >
                  Pendaftaran dihentikan sampai kunci situs dan layanan verifikasi disiapkan
                  oleh pengelola layanan. Nilai kunci tidak ditampilkan di halaman ini.
                </Alert>
              )}

              {auth.user && !auth.user.isAnonymous ? (
                <Card className="mt-6 p-6">
                  <p className="text-sm font-semibold text-ink">Kamu sudah masuk</p>
                  <p className="type-small mt-2 text-ink-soft">
                    {auth.user.emailVerified
                      ? `Akun ${auth.user.email} sedang aktif. Buka dashboard untuk melanjutkan.`
                      : `Akun ${auth.user.email} masuk tetapi emailnya belum terkonfirmasi. Fitur akun terbuka setelah verifikasi selesai.`}
                  </p>
                  <Link
                    to={auth.user.emailVerified ? '/dashboard' : VERIFICATION_EMAIL_PATH}
                    className={buttonStyles({ className: 'mt-5' })}
                  >
                    {auth.user.emailVerified ? 'Buka dashboard' : 'Selesaikan verifikasi email'}
                    <ArrowRight size={15} aria-hidden="true" />
                  </Link>
                </Card>
              ) : (
                <Card className="mt-6 p-6">
                  <p className="text-sm font-semibold text-ink">Buat akun dengan email</p>

                  <form className="mt-5" onSubmit={handleRegister}>
                    <label htmlFor="register-name" className="text-sm font-medium text-ink">
                      Nama tampilan
                    </label>
                    <Input
                      id="register-name"
                      name="displayName"
                      autoComplete="name"
                      maxLength={40}
                      required
                      value={displayName}
                      onChange={(event) => setDisplayName(event.target.value)}
                      className="mt-1.5"
                    />

                    <label
                      htmlFor="register-username"
                      className="mt-4 block text-sm font-medium text-ink"
                    >
                      Username
                    </label>
                    <Input
                      id="register-username"
                      name="username"
                      autoComplete="username"
                      maxLength={40}
                      required
                      value={username}
                      onChange={(event) => setUsername(event.target.value)}
                      className="mt-1.5"
                    />
                    <p className="type-caption mt-2">
                      Satu username hanya untuk satu akun, di seluruh aplikasi.{' '}
                      {USERNAME_MIN_LENGTH}-{USERNAME_MAX_LENGTH} karakter: huruf kecil, angka, dan
                      garis bawah (_). Otomatis diubah menjadi huruf kecil.
                    </p>

                    <label
                      htmlFor="register-email"
                      className="mt-4 block text-sm font-medium text-ink"
                    >
                      Email
                    </label>
                    <Input
                      id="register-email"
                      name="email"
                      type="email"
                      autoComplete="email"
                      required
                      value={email}
                      onChange={(event) => setEmail(event.target.value)}
                      className="mt-1.5"
                    />

                    <label
                      htmlFor="register-password"
                      className="mt-4 block text-sm font-medium text-ink"
                    >
                      Kata sandi
                    </label>
                    <Input
                      id="register-password"
                      name="password"
                      type="password"
                      autoComplete="new-password"
                      minLength={8}
                      required
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      className="mt-1.5"
                    />
                    <p className="type-caption mt-2">Minimal 8 karakter.</p>

                    <label
                      htmlFor="register-confirm-password"
                      className="mt-4 block text-sm font-medium text-ink"
                    >
                      Ulangi kata sandi
                    </label>
                    <Input
                      id="register-confirm-password"
                      name="confirmPassword"
                      type="password"
                      autoComplete="new-password"
                      minLength={8}
                      required
                      value={confirmPassword}
                      onChange={(event) => setConfirmPassword(event.target.value)}
                      className="mt-1.5"
                    />

                    {captchaConfigured ? (
                      <>
                        <Turnstile
                          action={TURNSTILE_ACTION.register}
                          attempt={captchaAttempt}
                          onToken={handleCaptchaToken}
                          onExpire={handleCaptchaExpire}
                          onError={handleCaptchaError}
                          onStatusChange={setWidgetStatus}
                        />
                        {verifyPhase === 'error' ? (
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            className="mt-2"
                            onClick={requestFreshChallenge}
                          >
                            Ambil token baru pada verifikasi ini
                          </Button>
                        ) : null}
                      </>
                    ) : null}

                    <Button type="submit" size="sm" className="mt-5 w-full" disabled={submitBlocked}>
                      {submitting
                        ? 'Membuat akun…'
                        : verifyPhase === 'verifying'
                          ? 'Memverifikasi CAPTCHA…'
                          : 'Daftar dengan email'}
                    </Button>
                  </form>

                  {/* VGL-37: tautan silang ke login memakai panel yang sama dengan yang ada di
                      box login, bukan kalimat telanjang, agar keduanya terasa satu sistem. */}
                  <div className="mt-5 rounded-card border border-line bg-subtle px-4 py-3">
                    <p className="type-small text-ink-soft">
                      Sudah punya akun?{' '}
                      <Link
                        to="/masuk"
                        state={location.state}
                        className="font-medium text-accent hover:underline focus-visible:outline-2 focus-visible:outline-accent"
                      >
                        Masuk
                      </Link>
                    </p>
                  </div>
                </Card>
              )}

              <Alert tone="info" className="mt-4">
                Layanan akun mengelola data masuk akun. VERIGUARD AI tidak menyimpan kata sandi di
                data pemeriksaan atau di browser ini.
              </Alert>
            </>
          ) : null}
        </div>
      </div>
    </Container>
  )
}

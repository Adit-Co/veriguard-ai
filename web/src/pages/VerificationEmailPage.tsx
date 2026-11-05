import {
  ArrowRight,
  Check,
  LogOut,
  Mail,
  MailCheck,
  RefreshCw,
  ShieldCheck,
  ShieldQuestion,
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Alert } from '../components/ui/Alert'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { buttonStyles } from '../components/ui/buttonStyles'
import { Card } from '../components/ui/Card'
import { Container } from '../components/ui/Container'
import { Spinner } from '../components/ui/Spinner'
import { safeRedirectTarget } from '../lib/auth/redirect'
import { useAuth } from '../lib/auth/useAuth'
import {
  parseVerificationAction,
  remainingCooldownSeconds,
  VERIFICATION_EMAIL_PATH,
  VERIFICATION_RESEND_COOLDOWN_SECONDS,
} from '../lib/auth/verification'
import {
  authErrorMessage,
  emailVerificationErrorMessage,
  getFirebaseErrorCode,
} from '../lib/firebase/errors'

type VerificationLocationState = {
  from?: unknown
  justRegistered?: unknown
  verificationSent?: unknown
}

type Feedback = {
  tone: 'info' | 'success' | 'warning' | 'danger'
  title: string
  message: string
}

type ActionState = 'idle' | 'applying' | 'success' | 'mismatch' | 'error'

export function VerificationEmailPage() {
  const auth = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const locationState = (location.state as VerificationLocationState | null) ?? null
  const continueTo = safeRedirectTarget(locationState?.from)
  const action = useMemo(() => parseVerificationAction(location.search), [location.search])
  const justRegistered = locationState?.justRegistered === true
  const verificationSent =
    typeof locationState?.verificationSent === 'boolean'
      ? locationState.verificationSent
      : null
  const [checking, setChecking] = useState(false)
  const [sending, setSending] = useState(false)
  const [signingOut, setSigningOut] = useState(false)
  const [feedback, setFeedback] = useState<Feedback | null>(null)
  const [actionState, setActionState] = useState<ActionState>('idle')
  const [actionMessage, setActionMessage] = useState<string | null>(null)
  const [cooldownUntil, setCooldownUntil] = useState(() =>
    justRegistered && verificationSent !== false
      ? Date.now() + VERIFICATION_RESEND_COOLDOWN_SECONDS * 1000
      : 0,
  )
  const [now, setNow] = useState(() => Date.now())
  const checkInFlight = useRef(false)
  const actionAppliedRef = useRef(false)
  const initialCheckRef = useRef(false)
  const mountedRef = useRef(true)
  const { applyVerificationCode, refreshEmailVerification, resendVerificationEmail } = auth
  const user = auth.mode === 'firebase' ? auth.user : null
  const verified = Boolean(user?.emailVerified) || actionState === 'success'
  const remainingCooldown = remainingCooldownSeconds(cooldownUntil, now)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  useEffect(() => {
    if (!cooldownUntil) return

    let timer = 0
    const tick = () => {
      const next = Date.now()
      setNow(next)
      if (next >= cooldownUntil) window.clearInterval(timer)
    }

    timer = window.setInterval(tick, 1000)
    tick()
    return () => window.clearInterval(timer)
  }, [cooldownUntil])

  const handleRefresh = useCallback(
    async (silent = false) => {
      if (checkInFlight.current) return
      checkInFlight.current = true
      setChecking(true)
      if (!silent) setFeedback(null)

      try {
        const result = await refreshEmailVerification()
        if (!mountedRef.current) return

        if (!result.signedIn) {
          setFeedback({
            tone: 'warning',
            title: 'Sesi akun tidak ditemukan',
            message: 'Masuk kembali dengan akun yang ingin diverifikasi, lalu buka halaman ini lagi.',
          })
          return
        }

        if (result.verified) {
          setFeedback({
            tone: 'success',
            title: 'Email berhasil diverifikasi',
            message: 'Status akun sudah diperbarui. Kamu dapat melanjutkan ke aplikasi.',
          })
          return
        }

        if (!silent) {
          setFeedback({
            tone: 'warning',
            title: 'Email belum terverifikasi',
            message:
              'Buka tautan verifikasi terbaru di kotak masuk atau folder spam, lalu tekan “Saya sudah verifikasi” lagi.',
          })
        }
      } catch (cause) {
        if (!mountedRef.current) return
        setFeedback({
          tone: 'danger',
          title: 'Status verifikasi belum dapat diperiksa',
          message: emailVerificationErrorMessage(cause),
        })
      } finally {
        checkInFlight.current = false
        if (mountedRef.current) setChecking(false)
      }
    },
    [refreshEmailVerification],
  )

  useEffect(() => {
    if (
      auth.mode !== 'firebase' ||
      auth.status !== 'ready' ||
      !user ||
      user.emailVerified ||
      action.canApply ||
      initialCheckRef.current
    ) {
      return
    }

    initialCheckRef.current = true
    void handleRefresh(true)
  }, [action.canApply, auth.mode, auth.status, handleRefresh, user])

  useEffect(() => {
    if (!user || user.emailVerified || auth.status !== 'ready') return

    const checkWhenVisible = () => {
      if (document.visibilityState === 'visible') void handleRefresh(true)
    }

    window.addEventListener('focus', checkWhenVisible)
    document.addEventListener('visibilitychange', checkWhenVisible)
    return () => {
      window.removeEventListener('focus', checkWhenVisible)
      document.removeEventListener('visibilitychange', checkWhenVisible)
    }
  }, [auth.status, handleRefresh, user])

  useEffect(() => {
    if (
      !action.canApply ||
      !action.oobCode ||
      actionAppliedRef.current ||
      auth.mode !== 'firebase' ||
      auth.status !== 'ready' ||
      user?.emailVerified
    ) {
      return
    }

    actionAppliedRef.current = true
    setActionState('applying')
    setActionMessage('Memproses tautan verifikasi...')

    void applyVerificationCode(action.oobCode)
      .then((result) => {
        if (!mountedRef.current) return

        if (result.verified || !result.signedIn) {
          setActionState('success')
          setActionMessage(
            result.signedIn
              ? 'Email berhasil diverifikasi. Status akun sudah diperbarui.'
              : 'Email berhasil diverifikasi. Masuk kembali untuk melanjutkan.',
          )
        } else {
          setActionState('mismatch')
          setActionMessage(
            'Tautan verifikasi sudah diproses, tetapi akun yang sedang masuk belum terverifikasi. Pastikan kamu memakai akun yang sesuai.',
          )
        }

        navigate(VERIFICATION_EMAIL_PATH, { replace: true, state: location.state })
      })
      .catch((cause) => {
        if (!mountedRef.current) return
        setActionState('error')
        setActionMessage(emailVerificationErrorMessage(cause))
        navigate(VERIFICATION_EMAIL_PATH, { replace: true, state: location.state })
      })
  }, [
    action.canApply,
    action.oobCode,
    applyVerificationCode,
    auth.mode,
    auth.status,
    location.state,
    navigate,
    user?.emailVerified,
  ])

  async function handleResend() {
    if (sending || remainingCooldown > 0) return

    setSending(true)
    setFeedback(null)

    try {
      await resendVerificationEmail()
      const until = Date.now() + VERIFICATION_RESEND_COOLDOWN_SECONDS * 1000
      setCooldownUntil(until)
      setNow(Date.now())
      setFeedback({
        tone: 'success',
        title: 'Email verifikasi dikirim',
        message: `Periksa kotak masuk ${user?.email ?? 'email akun ini'} dan folder spam. Tautan verifikasi berlaku terbatas.`,
      })
    } catch (cause) {
      if (getFirebaseErrorCode(cause) === 'auth/email-already-verified') {
        await handleRefresh()
        return
      }

      if (getFirebaseErrorCode(cause) === 'auth/too-many-requests') {
        setCooldownUntil(Date.now() + VERIFICATION_RESEND_COOLDOWN_SECONDS * 1000)
        setNow(Date.now())
      }

      setFeedback({
        tone: 'danger',
        title: 'Email verifikasi gagal dikirim',
        message: emailVerificationErrorMessage(cause),
      })
    } finally {
      if (mountedRef.current) setSending(false)
    }
  }

  async function handleSignOut() {
    if (signingOut) return

    setSigningOut(true)
    setFeedback(null)

    try {
      await auth.signOut()
      if (!mountedRef.current) return
      navigate('/masuk', { replace: true, state: { from: continueTo } })
    } catch (cause) {
      if (!mountedRef.current) return
      setFeedback({
        tone: 'danger',
        title: 'Akun gagal dikeluarkan',
        message: authErrorMessage(cause),
      })
    } finally {
      if (mountedRef.current) setSigningOut(false)
    }
  }

  return (
    <Container className="pb-16 sm:pb-20">
      <div className="mx-auto max-w-[720px] pt-12 sm:pt-16">
        <Card className="overflow-hidden">
          <div className="relative overflow-hidden border-b border-line bg-gradient-to-br from-accent-soft via-surface to-subtle p-6 sm:p-8">
            <div
              aria-hidden="true"
              className="absolute -right-10 -top-12 size-40 rounded-full border border-accent/10 bg-surface/40"
            />
            <div className="relative">
              <div className="flex flex-wrap items-center gap-3">
                <span className="grid size-12 place-items-center rounded-2xl border border-accent/15 bg-surface text-accent shadow-card">
                  <MailCheck size={23} aria-hidden="true" />
                </span>
                <Badge tone="accent">Keamanan akun</Badge>
              </div>
              <h1 className="type-h1 mt-6">
                {verified ? 'Email terverifikasi' : 'Verifikasi email'}
              </h1>
              <p className="type-small mt-3 max-w-[54ch] text-ink-soft">
                {verified
                  ? 'Alamat email akun ini sudah dikonfirmasi. Verifikasi membantu menjaga akses pemulihan dan komunikasi penting.'
                  : 'Konfirmasi alamat email untuk memperkuat keamanan akun. Proses ini tidak mengubah akun atau data pemeriksaanmu.'}
              </p>
            </div>
          </div>

          <div className="p-6 sm:p-8">
            {auth.mode === 'demo' ? (
              <>
                <Alert tone="warning" title="Verifikasi email belum tersedia">
                  Layanan akun belum terhubung pada versi ini. Tidak ada email
                  verifikasi yang dapat dikirim atau diperiksa. Jangan memasukkan data pribadi di
                  halaman ini.
                </Alert>
                <div className="mt-6 flex flex-wrap gap-3">
                  <Link to="/masuk" className={buttonStyles({ size: 'sm' })}>
                    Buka halaman masuk
                    <ArrowRight size={15} aria-hidden="true" />
                  </Link>
                  <Link
                    to="/periksa"
                    className={buttonStyles({ variant: 'secondary', size: 'sm' })}
                  >
                    Periksa tanpa akun
                  </Link>
                </div>
              </>
            ) : null}

            {auth.mode === 'firebase' && auth.status === 'loading' ? (
              <Card className="border-dashed bg-canvas p-5" role="status">
                <div className="flex items-center gap-3">
                  <Spinner label="Memulihkan sesi" />
                  <div>
                    <p className="text-sm font-semibold text-ink">Memulihkan sesi akun...</p>
                    <p className="type-caption mt-0.5">
                      Status verifikasi akan diperiksa setelah sesi siap.
                    </p>
                  </div>
                </div>
              </Card>
            ) : null}

            {auth.mode === 'firebase' && auth.status === 'error' ? (
              <Alert tone="danger" title="Layanan akun gagal disiapkan">
                {auth.initializationError ??
                  'Layanan akun belum dapat disiapkan. Muat ulang halaman atau hubungi pengelola layanan.'}
              </Alert>
            ) : null}

            {auth.mode === 'firebase' && auth.status === 'ready' ? (
              <>
                {actionState === 'applying' ? (
                  <Card className="border-accent/20 bg-accent-soft/60 p-5" role="status">
                    <div className="flex items-center gap-3">
                      <Spinner label="Memproses tautan verifikasi" />
                      <p className="text-sm font-semibold text-ink">{actionMessage}</p>
                    </div>
                  </Card>
                ) : null}

                {actionState === 'mismatch' ? (
                  <Alert tone="warning" className="mb-5" title="Akun aktif belum terverifikasi">
                    {actionMessage}
                  </Alert>
                ) : null}

                {actionState === 'error' ? (
                  <Alert tone="danger" className="mb-5" role="alert" title="Tautan tidak dapat dipakai">
                    {actionMessage}
                  </Alert>
                ) : null}

                {!user && !verified ? (
                  <>
                    <div className="flex flex-col items-center px-2 py-4 text-center">
                      <span className="grid size-12 place-items-center rounded-full bg-subtle text-ink-muted">
                        <ShieldQuestion size={23} aria-hidden="true" />
                      </span>
                      <h2 className="type-h3 mt-5">Masuk untuk memeriksa verifikasi</h2>
                      <p className="type-small mt-2 max-w-[46ch] text-ink-soft">
                        Sesi akun diperlukan untuk memeriksa status email dan mengirim ulang
                        tautan verifikasi.
                      </p>
                      <Link
                        to="/masuk"
                        state={{ from: VERIFICATION_EMAIL_PATH }}
                        className={buttonStyles({ className: 'mt-6' })}
                      >
                        Masuk ke akun
                        <ArrowRight size={15} aria-hidden="true" />
                      </Link>
                    </div>
                    {feedback ? (
                      <Alert
                        tone={feedback.tone}
                        role={feedback.tone === 'danger' ? 'alert' : 'status'}
                        className="mt-5"
                        title={feedback.title}
                      >
                        {feedback.message}
                      </Alert>
                    ) : null}
                  </>
                ) : null}

                {verified ? (
                  <>
                    <div className="rounded-card border border-risk-low-line bg-risk-low-bg p-5">
                      <div className="flex gap-3">
                        <span className="grid size-10 shrink-0 place-items-center rounded-full bg-surface text-risk-low">
                          <Check size={21} aria-hidden="true" />
                        </span>
                        <div>
                          <p className="text-sm font-semibold text-ink">
                            {user?.email ?? 'Email akun'} sudah terverifikasi
                          </p>
                          <p className="type-small mt-1 text-ink-soft">
                            {user
                              ? 'Status akun sudah diperbarui tanpa perlu masuk ulang.'
                              : 'Tautan verifikasi berhasil diproses. Masuk dengan akun tersebut untuk melanjutkan.'}
                          </p>
                        </div>
                      </div>
                    </div>

                    {feedback ? (
                      <Alert
                        tone={feedback.tone}
                        role={feedback.tone === 'danger' ? 'alert' : 'status'}
                        className="mt-5"
                        title={feedback.title}
                      >
                        {feedback.message}
                      </Alert>
                    ) : null}

                    <div className="mt-6 flex flex-wrap gap-3">
                      {user ? (
                        <Link to={continueTo} className={buttonStyles()}>
                          Lanjutkan ke aplikasi
                          <ArrowRight size={15} aria-hidden="true" />
                        </Link>
                      ) : (
                        <Link
                          to="/masuk"
                          state={{ from: continueTo }}
                          className={buttonStyles()}
                        >
                          Masuk untuk melanjutkan
                          <ArrowRight size={15} aria-hidden="true" />
                        </Link>
                      )}
                      <Link
                        to="/pengaturan"
                        className={buttonStyles({ variant: 'secondary' })}
                      >
                        Buka pengaturan akun
                      </Link>
                    </div>
                  </>
                ) : null}

                {user && !verified ? (
                  <>
                    <div className="rounded-card border border-line bg-canvas p-4">
                      <div className="flex items-start gap-3">
                        <span className="grid size-10 shrink-0 place-items-center rounded-lg bg-surface text-accent">
                          <Mail size={19} aria-hidden="true" />
                        </span>
                        <div className="min-w-0 flex-1">
                          <p className="type-caption font-medium">Email akun</p>
                          <p className="mt-0.5 break-all text-sm font-semibold text-ink">
                            {user.email ?? 'Email belum tersedia'}
                          </p>
                        </div>
                        <Badge tone="medium">Email belum diverifikasi</Badge>
                      </div>
                    </div>

                    {justRegistered ? (
                      <Alert
                        tone={verificationSent === false ? 'warning' : 'info'}
                        className="mt-4"
                        title={
                          verificationSent === false
                            ? 'Akun dibuat, email verifikasi belum terkirim'
                            : 'Akun berhasil dibuat'
                        }
                      >
                        {verificationSent === false
                          ? 'Kamu sudah masuk, tetapi email verifikasi gagal dikirim. Gunakan tombol kirim ulang di bawah.'
                          : 'Kami sudah mengirim tautan verifikasi. Periksa kotak masuk dan folder spam.'}
                      </Alert>
                    ) : null}

                    {feedback ? (
                      <Alert
                        tone={feedback.tone}
                        role={feedback.tone === 'danger' ? 'alert' : 'status'}
                        className="mt-4"
                        title={feedback.title}
                      >
                        {feedback.message}
                      </Alert>
                    ) : null}

                    <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:flex-wrap">
                      <Button onClick={() => void handleRefresh()} disabled={checking}>
                        {checking ? (
                          <Spinner label="Memeriksa status verifikasi" />
                        ) : (
                          <Check size={16} aria-hidden="true" />
                        )}
                        {checking ? 'Memeriksa status...' : 'Saya sudah verifikasi'}
                      </Button>
                      <Button
                        variant="secondary"
                        onClick={() => void handleResend()}
                        disabled={sending || remainingCooldown > 0}
                      >
                        {sending ? (
                          <Spinner label="Mengirim email verifikasi" />
                        ) : (
                          <RefreshCw size={15} aria-hidden="true" />
                        )}
                        {sending
                          ? 'Mengirim...'
                          : remainingCooldown > 0
                            ? `Kirim ulang dalam ${remainingCooldown} dtk`
                            : 'Kirim ulang email verifikasi'}
                      </Button>
                    </div>

                    <div className="mt-5 border-t border-line pt-5">
                      <p className="type-caption">
                        Belum menerima email? Periksa folder spam, pastikan alamat email benar,
                        lalu tunggu cooldown sebelum mengirim ulang.
                      </p>
                      <p className="type-caption mt-3">
                        Fitur akun dilindungi dan baru terbuka setelah email dikonfirmasi. Masuk ke
                        dashboard, riwayat, pemindaian, dan komunitas diarahkan kembali ke halaman
                        ini sampai verifikasi selesai.
                      </p>
                      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2">
                        <Link
                          to="/pengaturan"
                          className="text-xs font-medium text-ink-soft underline-offset-4 hover:text-ink hover:underline"
                        >
                          Periksa pengaturan akun
                        </Link>
                      </div>
                    </div>

                    <div className="mt-6 border-t border-line pt-5">
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        onClick={() => void handleSignOut()}
                        disabled={signingOut}
                      >
                        {signingOut ? (
                          <Spinner label="Mengeluarkan akun" />
                        ) : (
                          <LogOut size={15} aria-hidden="true" />
                        )}
                        {signingOut ? 'Keluar...' : 'Keluar dan pakai akun lain'}
                      </Button>
                      <p className="type-caption mt-2">
                        Keluar tidak menghapus akun. Kamu bisa masuk lagi setelah email terkonfirmasi.
                      </p>
                    </div>
                  </>
                ) : null}
              </>
            ) : null}
          </div>
        </Card>

        <div className="mt-5 flex items-start gap-3 rounded-card border border-line bg-surface/70 p-4 text-ink-soft">
          <ShieldCheck size={18} className="mt-0.5 shrink-0 text-risk-low" aria-hidden="true" />
          <p className="type-caption">
            VERIGUARD AI tidak pernah meminta kata sandi melalui email. Tautan verifikasi hanya
            membuka halaman resmi layanan akun untuk akun ini.
          </p>
        </div>
      </div>
    </Container>
  )
}

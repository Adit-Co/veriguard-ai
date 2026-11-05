import { ArrowRight, Check, KeyRound, LockKeyhole, Mail, ShieldAlert, ShieldCheck, UserRound } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Alert } from '../components/ui/Alert'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { buttonStyles } from '../components/ui/buttonStyles'
import { Card } from '../components/ui/Card'
import { Container } from '../components/ui/Container'
import { Input } from '../components/ui/Input'
import { Notification } from '../components/ui/Notification'
import { LoginCooldownError, readLoginCooldown } from '../lib/auth/loginGuard'
import {
  DemoLoginError,
  demoLoginAvailability,
  signInWithDemoAccount,
  type DemoAccountKey,
} from '../lib/auth/demoLogin'
import { safeRedirectTarget } from '../lib/auth/redirect'
import { formatAttemptsRemaining, formatCooldownRemaining, useLoginCooldown } from '../lib/auth/useLoginCooldown'
import { useAuth } from '../lib/auth/useAuth'
import { emailStateLabel, VERIFICATION_EMAIL_PATH } from '../lib/auth/verification'
import { authErrorMessage } from '../lib/firebase/errors'
import { getLocalDemoSession, MAX_DISPLAY_NAME_LENGTH } from '../lib/session/session'

const dateFormatter = new Intl.DateTimeFormat('id-ID', {
  day: 'numeric',
  month: 'long',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
})

export function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const auth = useAuth()
  const loginCooldown = useLoginCooldown()
  const locationState = location.state as { from?: unknown } | null
  const redirectTo = safeRedirectTarget(locationState?.from)
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [resetMode, setResetMode] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const localSession = auth.mode === 'demo' ? getLocalDemoSession() : null
  const demoAvailability = demoLoginAvailability()
  // VGL-39A: angka kesempatan datang dari gerbang (waktu server), tidak pernah dihitung di klien.
  const attemptsLabel = formatAttemptsRemaining(loginCooldown.cooldown)

  // Sesi pratinjau lokal: BUKAN autentikasi (lihat lib/session/session.ts) dan tetap ditolak
  // dari jalur admin. Dipertahankan apa adanya agar alur tanpa akun tidak berubah.
  function handleStartSession(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    auth.startDemoSession(displayName)
    navigate(redirectTo, { replace: true })
  }

  // Login demo memakai token custom yang dicetak dev server lokal dan ditukar lewat layanan
  // akun, jadi sesi yang dihasilkan nyata (bukan flag di localStorage) dan peran admin dibaca
  // dari keadaan akun di sisi server. Tidak ada kata sandi yang lewat ke browser.
  async function handleDemoSignIn(account: DemoAccountKey) {
    // Tombol demo tidak boleh menjadi jalan pintas di atas gerbang VGL-38: kondisi penolakan
    // dibaca ulang di sini, sama seperti handleSignIn, supaya pengiriman lewat keyboard saat
    // tombol dinonaktifkan tetap terblokir.
    if (submitting || loginCooldown.cooldown.active) return
    // VGL-41C: gerbang dibaca ulang pada sumbernya (jam server) karena kegagalan kredensial bisa
    // terjadi sejak polling terakhir. Penguncian permintaan dipasang SEBELUM pembacaan itu, jadi
    // dua klik berturut-turut tidak sama-sama lolos dan mengirim dua permintaan.
    setError(null)
    setNotice(null)
    setSubmitting(true)

    try {
      if ((await readLoginCooldown()).active) {
        loginCooldown.refresh()
        return
      }
      await signInWithDemoAccount(account)
      navigate(redirectTo, { replace: true })
    } catch (cause) {
      setError(
        cause instanceof DemoLoginError
          ? cause.message
          : 'Login demo gagal. Peran tidak diberikan tanpa verifikasi server.',
      )
    } finally {
      setSubmitting(false)
    }
  }

  function handleDemoAdmin() {
    void handleDemoSignIn('admin')
  }

  function handleDemoUser() {
    void handleDemoSignIn('user')
  }

  async function handleSignIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    // VGL-38: penolakan utama ada di gerbang (jam server), bukan di state React. Cek di sini
    // hanya mencegah pengiriman lewat keyboard (Enter) saat tombol sedang dinonaktifkan.
    if (submitting || loginCooldown.cooldown.active) return

    setError(null)
    setNotice(null)
    setSubmitting(true)

    try {
      const result = await auth.signIn(email, password)
      if (!result.emailVerified) {
        navigate(VERIFICATION_EMAIL_PATH, {
          replace: true,
          state: { from: redirectTo },
        })
        return
      }

      navigate(redirectTo, { replace: true })
    } catch (cause) {
      // Keadaan pembatasan dibaca ulang SETIAP kali: kegagalan kredensial bisa memicu cooldown
      // tingkat 1, dan penolakan gerbang tidak boleh tampil sebagai "email atau kata sandi salah".
      loginCooldown.refresh()
      if (!(cause instanceof LoginCooldownError)) setError(authErrorMessage(cause))
    } finally {
      setSubmitting(false)
    }
  }

  async function handlePasswordReset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting) return

    setError(null)
    setNotice(null)
    setSubmitting(true)

    try {
      await auth.resetPassword(email)
      setResetMode(false)
      setNotice(
        'Jika email tersebut terdaftar, tautan pemulihan kata sandi sudah dikirim. Periksa kotak masuk dan folder spam.',
      )
    } catch (cause) {
      setError(authErrorMessage(cause))
    } finally {
      setSubmitting(false)
    }
  }

  async function handleEndSession() {
    setError(null)
    try {
      await auth.signOut()
    } catch (cause) {
      setError(authErrorMessage(cause))
    }
  }

  const firebaseUser =
    auth.mode === 'firebase' && auth.user && !auth.user.isAnonymous ? auth.user : null

  return (
    <Container className="pb-16 sm:pb-20">
      <div className="grid gap-10 pt-12 sm:pt-16 lg:grid-cols-[minmax(0,1fr)_minmax(0,460px)] lg:gap-16 lg:pt-20">
        <div className="max-w-[560px]">
          <span className="grid size-11 place-items-center rounded-xl bg-accent-soft text-accent">
            <LockKeyhole size={20} aria-hidden="true" />
          </span>
          <h1 className="type-h1 mt-5">Masuk ke VERIGUARD AI</h1>
          <p className="type-small mt-3 text-ink-soft">
            Akun diperlukan untuk menyimpan riwayat secara permanen dan membuka dashboard.
            Pemeriksaan dasar tetap bisa dilakukan tanpa akun.
          </p>

          <ul className="mt-8 flex flex-col gap-3 border-t border-line pt-6 text-sm">
            {[
              'Periksa tautan atau pesan tanpa akun lebih dulu.',
              'Riwayat tersimpan permanen begitu akun aktif.',
              'Dashboard terbuka setelah email diverifikasi.',
            ].map((item) => (
              <li key={item} className="flex items-start gap-2.5 text-ink-soft">
                <Check size={16} className="mt-0.5 shrink-0 text-accent" aria-hidden="true" />
                {item}
              </li>
            ))}
          </ul>

          <Link
            to="/periksa"
            className={buttonStyles({
              variant: 'ghost',
              size: 'sm',
              className: 'mt-6 -ml-2',
            })}
          >
            Periksa tanpa akun
            <ArrowRight size={15} aria-hidden="true" />
          </Link>
        </div>

        <div className="min-w-0">
          {auth.status === 'loading' ? (
            <Card className="mt-6 p-6" role="status">
              <p className="text-sm font-semibold text-ink">Memulihkan sesi akun…</p>
              <p className="type-small mt-2 text-ink-soft">
                Tunggu sebentar. Formulir masuk akan tampil setelah status sesi diketahui.
              </p>
            </Card>
          ) : null}

          {auth.status === 'error' ? (
            <Alert tone="danger" className="mt-6" title="Layanan akun gagal disiapkan">
              {auth.initializationError ??
                'Layanan akun belum dapat disiapkan. Muat ulang halaman atau hubungi pengelola layanan.'}
            </Alert>
          ) : null}

          {auth.mode === 'demo' ? (
            <>
              <Alert tone="warning" className="mt-6" title="Autentikasi sungguhan belum aktif">
                Layanan akun belum terhubung. Jangan memasukkan kata sandi, email, atau data pribadi
                di halaman ini. Tidak ada akun yang benar-benar dibuat atau diverifikasi.
              </Alert>

              {localSession ? (
                <Card className="mt-6 p-6">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="grid size-8 place-items-center rounded-full bg-risk-low-bg text-risk-low">
                      <Check size={17} aria-hidden="true" />
                    </span>
                    <p className="text-sm font-semibold text-ink">Sesi demo lokal aktif</p>
                    <Badge tone="neutral">Bukan autentikasi</Badge>
                  </div>
                  <dl className="mt-4 grid gap-2 text-sm">
                    <div className="flex flex-wrap justify-between gap-2">
                      <dt className="text-ink-soft">Nama tampilan</dt>
                      <dd className="font-medium text-ink">{localSession.displayName}</dd>
                    </div>
                    <div className="flex flex-wrap justify-between gap-2">
                      <dt className="text-ink-soft">Dimulai</dt>
                      <dd className="text-ink">
                        {dateFormatter.format(new Date(localSession.startedAt))}
                      </dd>
                    </div>
                  </dl>
                  <p className="type-caption mt-4">
                    Sesi ini hanya berada di browser ini. Data tidak diamankan, tidak disinkronkan,
                    dan bukan bukti identitas.
                  </p>
                  <div className="mt-5 flex flex-wrap gap-3">
                    <Link to="/dashboard" className={buttonStyles({ size: 'sm' })}>
                      Buka dashboard
                      <ArrowRight size={15} aria-hidden="true" />
                    </Link>
                    <Button variant="secondary" size="sm" onClick={handleEndSession}>
                      Akhiri sesi demo
                    </Button>
                  </div>
                </Card>
              ) : (
                <Card className="mt-6 p-6">
                  <p className="text-sm font-semibold text-ink">Sesi demo lokal</p>
                  <p className="type-small mt-2 text-ink-soft">
                    Kamu dapat membuka dashboard di perangkat ini tanpa akun, sebagai pratinjau alur
                    produk. Sesi ini bukan login dan tidak melindungi data.
                  </p>

                  <form className="mt-5" onSubmit={handleStartSession}>
                    <label htmlFor="demo-name" className="text-sm font-medium text-ink">
                      Nama tampilan (opsional)
                    </label>
                    <Input
                      id="demo-name"
                      name="displayName"
                      autoComplete="off"
                      maxLength={MAX_DISPLAY_NAME_LENGTH}
                      placeholder="Pengguna demo"
                      value={displayName}
                      onChange={(event) => setDisplayName(event.target.value)}
                      className="mt-1.5"
                    />
                    <p className="type-caption mt-2">
                      Hanya dipakai di perangkat ini. Jangan gunakan nama lengkap atau data
                      sensitif.
                    </p>

                    <div className="mt-5 flex flex-wrap gap-3">
                      <Button type="submit" size="sm">
                        Mulai sesi demo lokal
                        <ArrowRight size={15} aria-hidden="true" />
                      </Button>
                      <Link
                        to="/periksa"
                        className={buttonStyles({ variant: 'ghost', size: 'sm' })}
                      >
                        Periksa tanpa akun
                      </Link>
                    </div>
                  </form>
                </Card>
              )}

              <Card className="mt-4 border-dashed bg-subtle/60 p-4">
                <div className="flex gap-3">
                  <ShieldAlert
                    size={18}
                    className="mt-0.5 shrink-0 text-risk-medium"
                    aria-hidden="true"
                  />
                  <p className="type-small text-ink-soft">
                    Masuk dengan email atau Google, serta sinkronisasi riwayat, menunggu integrasi
                    layanan akun. Halaman ini tidak menyediakan formulir autentikasi sungguhan.
                  </p>
                </div>
              </Card>
            </>
          ) : null}

          {auth.mode === 'firebase' && auth.status === 'ready' ? (
            <>
              {/* VGL-37/VGL-37A/VGL-37C: informasi layanan akun berupa toast mengambang — muncul
                  otomatis di bawah navbar, ditutup dengan X, dan hilang sendiri dalam batas 10 detik
                  tanpa menampilkan hitungan. Karena posisinya fixed, ia tidak ikut mendorong kartu
                  login ke bawah. Toast mundur ketika ada Alert pesan agar tidak menutupinya dan tidak ada
                  dua pengumuman status sekaligus. */}
              {error || notice || loginCooldown.cooldown.active ? null : (
                <Notification
                  title="Layanan akun"
                  icon={<ShieldCheck size={18} strokeWidth={2} aria-hidden="true" />}
                  closeLabel="Tutup notifikasi layanan akun"
                >
                  Autentikasi email dan kata sandi terhubung ke layanan akun yang tersedia. Jangan
                  gunakan kata sandi yang sama dengan akun lain.
                </Notification>
              )}

              {/* VGL-38: panel pembatasan. Hanya muncul saat cooldown aktif, jadi kartu tanpa
                  cooldown (dan metrik VGL-37C) tidak berubah. Form tetap tampil utuh: email dan
                  kata sandi masih terlihat, hanya tombol Masuk yang dinonaktifkan. */}
              {loginCooldown.cooldown.active ? (
                <Alert tone="warning" role="status" className="mt-4" title="Terlalu banyak percobaan login">
                  <p>
                    Percobaan login terlalu sering terdeteksi dari sumber ini. Silakan tunggu sebelum
                    mencoba kembali — sisa waktu {formatCooldownRemaining(loginCooldown.secondsLeft)}.
                  </p>
                  <p className="type-caption mt-2">
                    Hitungan diambil dari waktu layanan, bukan dari jam perangkat, sehingga memuat
                    ulang halaman tidak menghapus masa tunggu ini.
                  </p>
                </Alert>
              ) : null}

              {/* VGL-39A: baris kesempatan hanya muncul setelah ada kesempatan terpakai dan saat
                  sumber tidak terkunci. Letaknya di atas kartu (bukan di dalamnya), jadi geometri
                  kartu VGL-37C tetap identik saat keadaan bersih. */}
              {attemptsLabel ? (
                <p className="mt-4 type-small text-ink-soft" role="status">
                  {attemptsLabel}
                </p>
              ) : null}

              {error ? (
                <Alert tone="danger" role="alert" className="mt-4" title="Autentikasi gagal">
                  {error}
                </Alert>
              ) : null}
              {notice ? (
                <Alert tone="success" role="status" className="mt-4" title="Periksa email">
                  {notice}
                </Alert>
              ) : null}

              {firebaseUser ? (
                <Card className="mt-6 p-6">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="grid size-8 place-items-center rounded-full bg-risk-low-bg text-risk-low">
                      <Check size={17} aria-hidden="true" />
                    </span>
                    <p className="text-sm font-semibold text-ink">
                      {firebaseUser.emailVerified ? 'Akun aktif' : 'Sesi menunggu verifikasi'}
                    </p>
                    <Badge tone={firebaseUser.emailVerified ? 'low' : 'medium'}>
                      {emailStateLabel(firebaseUser)}
                    </Badge>
                  </div>
                  <dl className="mt-4 grid gap-2 text-sm">
                    <div className="flex flex-wrap justify-between gap-2">
                      <dt className="text-ink-soft">Nama tampilan</dt>
                      <dd className="font-medium text-ink">{firebaseUser.displayName}</dd>
                    </div>
                    <div className="flex flex-wrap justify-between gap-2">
                      <dt className="text-ink-soft">Email</dt>
                      <dd className="break-all text-ink">{firebaseUser.email}</dd>
                    </div>
                  </dl>
                  {!firebaseUser.emailVerified ? (
                    <p className="type-caption mt-4">
                      Akun sudah dibuat, tetapi email belum dikonfirmasi. Dashboard, riwayat,
                      pemindaian berakun, dan komunitas baru terbuka setelah verifikasi selesai.
                    </p>
                  ) : null}
                  <div className="mt-5 flex flex-wrap gap-3">
                    {firebaseUser.emailVerified ? (
                      <Link to="/dashboard" className={buttonStyles({ size: 'sm' })}>
                        Buka dashboard
                        <ArrowRight size={15} aria-hidden="true" />
                      </Link>
                    ) : null}
                    {!firebaseUser.emailVerified ? (
                      <Link
                        to={VERIFICATION_EMAIL_PATH}
                        state={{ from: redirectTo }}
                        className={buttonStyles({
                          variant: 'secondary',
                          size: 'sm',
                        })}
                      >
                        Buka verifikasi email
                      </Link>
                    ) : null}
                    <Button variant="ghost" size="sm" onClick={handleEndSession}>
                      Keluar
                    </Button>
                  </div>
                </Card>
              ) : (
                /* VGL-37A/VGL-37B: tinggi kartu dinaikkan ke taraf medium-tinggi lewat ritme
                  ruang dalam — padding atas/bawah dan jarak antar blok — bukan lewat tinggi
                  paksa, sehingga tidak ada ruang kosong yang muncul ketika isi berubah.
                  Padding samping sengaja tetap 32px agar lebar field tidak ikut menyusut. */
                <Card className="mt-6 px-8 py-10">
                  {resetMode ? (
                    <>
                      <p className="text-sm font-semibold text-ink">Pulihkan kata sandi</p>
                      <p className="type-small mt-2 text-ink-soft">
                        Masukkan email akun. Tautan pemulihan akan dikirim jika email tersebut
                        terdaftar.
                      </p>
                      <form className="mt-5" onSubmit={handlePasswordReset}>
                        <label htmlFor="reset-email" className="text-sm font-medium text-ink">
                          Email
                        </label>
                        <div className="relative mt-1.5">
                          <Mail
                            size={16}
                            aria-hidden="true"
                            className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-ink-muted"
                          />
                          <Input
                            id="reset-email"
                            name="email"
                            type="email"
                            autoComplete="email"
                            required
                            value={email}
                            onChange={(event) => setEmail(event.target.value)}
                            className="pl-10"
                          />
                        </div>
                        <div className="mt-5 flex flex-wrap gap-3">
                          <Button type="submit" size="sm" disabled={submitting}>
                            {submitting ? 'Mengirim…' : 'Kirim tautan reset'}
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setResetMode(false)
                              setError(null)
                            }}
                          >
                            Kembali
                          </Button>
                        </div>
                      </form>
                    </>
                  ) : (
                    <>
                      <p className="text-sm font-semibold text-ink">Masuk dengan email</p>
                      <form className="mt-10" onSubmit={handleSignIn}>
                        <label htmlFor="login-email" className="text-sm font-medium text-ink">
                          Email
                        </label>
                        <div className="relative mt-1.5">
                          <Mail
                            size={16}
                            aria-hidden="true"
                            className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-ink-muted"
                          />
                          <Input
                            id="login-email"
                            name="email"
                            type="email"
                            autoComplete="email"
                            required
                            value={email}
                            onChange={(event) => setEmail(event.target.value)}
                            className="pl-10"
                          />
                        </div>

                        <label
                          htmlFor="login-password"
                          className="mt-4 block text-sm font-medium text-ink"
                        >
                          Kata sandi
                        </label>
                        <div className="relative mt-1.5">
                          <KeyRound
                            size={16}
                            aria-hidden="true"
                            className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-ink-muted"
                          />
                          <Input
                            id="login-password"
                            name="password"
                            type="password"
                            autoComplete="current-password"
                            required
                            value={password}
                            onChange={(event) => setPassword(event.target.value)}
                            className="pl-10"
                          />
                        </div>

                        <div className="mt-10 flex flex-wrap items-center gap-3">
                          <Button
                            type="submit"
                            size="sm"
                            disabled={submitting || loginCooldown.cooldown.active}
                          >
                            {submitting
                              ? 'Memeriksa…'
                              : loginCooldown.cooldown.active
                                ? 'Menunggu'
                                : 'Masuk'}
                            <ArrowRight size={15} aria-hidden="true" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setResetMode(true)
                              setError(null)
                              setNotice(null)
                            }}
                          >
                            Lupa kata sandi?
                          </Button>
                        </div>
                      </form>

                      {/* Akun demo (BAGIAN 4): peran ditetapkan sisi server lewat emulator lokal,
                          jadi blok ini dirender HANYA bila pagar demoLoginAvailability() lolos —
                          build produksi, mode tanpa bendera, dan mode tanpa emulator loopback tidak
                          menampilkan apa pun. `import.meta.env.DEV` ditulis di sini supaya Vite
                          melipatnya menjadi false pada build produksi: seluruh blok demo ikut
                          terhapus dari bundle, bukan hanya dinonaktifkan saat runtime.
                          Bentuknya diminimalkan: teks pemisah + dua tombol kecil sejajar di bawah
                          tombol Masuk, tanpa kartu tambahan, sehingga ritme kartu login
                          VGL-37A/VGL-37B dan ukuran card tidak berubah drastis. */}
                      {import.meta.env.DEV && demoAvailability.available && !firebaseUser ? (
                        <div className="mt-6">
                          <p className="type-caption text-center text-ink-muted">atau coba akun demo</p>
                          <div className="mt-2.5 grid grid-cols-2 gap-2.5">
                            <Button
                              variant="secondary"
                              size="sm"
                              className="h-8 gap-1.5 px-2.5 text-xs"
                              disabled={submitting || loginCooldown.cooldown.active}
                              onClick={handleDemoAdmin}
                              title="Masuk memakai akun demo admin pada Emulator Firebase lokal"
                            >
                              <ShieldCheck size={14} aria-hidden="true" />
                              {submitting ? 'Menyiapkan…' : 'Demo Admin'}
                            </Button>
                            <Button
                              variant="secondary"
                              size="sm"
                              className="h-8 gap-1.5 px-2.5 text-xs"
                              disabled={submitting || loginCooldown.cooldown.active}
                              onClick={handleDemoUser}
                              title="Masuk memakai akun demo user pada Emulator Firebase lokal"
                            >
                              <UserRound size={14} aria-hidden="true" />
                              {submitting ? 'Menyiapkan…' : 'Demo User'}
                            </Button>
                          </div>
                        </div>
                      ) : null}

                      {/* VGL-34: satu-satunya entry point registrasi ada di halaman Masuk,
                        jadi blok ini dipertegas sebagai panel, bukan kalimat biasa. */}
                      <div className="mt-10 rounded-card border border-line bg-subtle px-4 py-3">
                        <p className="type-small text-ink-soft">
                          Belum punya akun?{' '}
                          <Link
                            to="/daftar"
                            state={location.state}
                            className="font-medium text-accent hover:underline focus-visible:outline-2 focus-visible:outline-accent"
                          >
                            Daftar dengan email
                          </Link>
                        </p>
                        <p className="type-caption mt-1 text-ink-muted">
                          Alamat email tetap harus dikonfirmasi setelah akun dibuat.
                        </p>
                      </div>
                    </>
                  )}
                </Card>
              )}

              <p className="type-caption mt-4">
                Sesi akun dipulihkan secara otomatis oleh layanan akun. Data riwayat hanya dimuat
                untuk pengguna yang sedang masuk.
              </p>
            </>
          ) : null}
        </div>
      </div>
    </Container>
  )
}

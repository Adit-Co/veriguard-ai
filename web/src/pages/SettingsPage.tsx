import {
  Check,
  Database,
  Download,
  Eraser,
  LogOut,
  MailWarning,
  Settings2,
  ShieldCheck,
  Trash2,
  UserRound,
} from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { AccountUsernameCard } from '../components/auth/AccountUsernameCard'
import { ProfileSyncNotice } from '../components/auth/ProfileSyncNotice'
import { Alert } from '../components/ui/Alert'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { buttonStyles } from '../components/ui/buttonStyles'
import { Card } from '../components/ui/Card'
import { Container } from '../components/ui/Container'
import { PageHeader } from '../components/ui/PageHeader'
import { SegmentedControl } from '../components/ui/SegmentedControl'
import { useAuth } from '../lib/auth/useAuth'
import { useDemoEmailText } from '../lib/auth/demoIdentity'
import { emailStateLabel } from '../lib/auth/verification'
import { downloadHistoryCsv } from '../lib/export/downloadHistory'
import { firestoreErrorMessage } from '../lib/firebase/errors'
import {
  applyPreferences,
  getPreferences,
  resetPreferences,
  updatePreferences,
  type Preferences,
} from '../lib/preferences/preferences'
import { useScanHistory } from '../lib/scans/useScanHistory'
import { clearLocalAppData } from '../lib/storage/localData'

const SCAN_MODE_OPTIONS = [
  { value: 'link', label: 'Tautan' },
  { value: 'message', label: 'Pesan' },
] as const

const dateFormatter = new Intl.DateTimeFormat('id-ID', {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
})

function formatDate(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'Waktu tidak diketahui' : dateFormatter.format(date)
}

export function SettingsPage() {
  const auth = useAuth()
  const { scans, loading, error: historyError, source, refresh, clear, redactAll } =
    useScanHistory()
  const [preferences, setPreferencesState] = useState<Preferences>(() => getPreferences())
  const [status, setStatus] = useState('')
  const session = auth.user
  // VGL-41E: kartu "Akun dan sesi" menyamar alamat email milik akun demo saja.
  const sessionEmailText = useDemoEmailText(session?.email)
  const cloud = source === 'cloud'
  const demo = auth.mode === 'demo'

  const messageScans = scans.filter((scan) => scan.mode === 'message')
  const fullMessageCount = messageScans.filter(
    (scan) => scan.meta.inputStored !== 'redacted',
  ).length
  const redactedMessageCount = messageScans.length - fullMessageCount

  function savePreference(patch: Partial<Preferences>) {
    const next = updatePreferences(patch)
    setPreferencesState(next)
    applyPreferences(next)
    setStatus('Preferensi disimpan di perangkat ini.')
  }

  function handleResetPreferences() {
    const next = resetPreferences()
    setPreferencesState(next)
    applyPreferences(next)
    setStatus('Preferensi dikembalikan ke pengaturan awal.')
  }

  async function handleEndSession() {
    setStatus('')
    try {
      await auth.signOut()
      setStatus(
        demo
          ? 'Sesi demo lokal diakhiri. Riwayat dan preferensi tetap tersimpan.'
          : 'Kamu sudah keluar dari akun.',
      )
    } catch (cause) {
      setStatus(
        cause instanceof Error ? cause.message : 'Gagal mengakhiri sesi. Coba lagi.',
      )
    }
  }

  function handleExport() {
    if (!downloadHistoryCsv(scans)) return
    setStatus(`${scans.length} pemeriksaan diekspor ke berkas CSV.`)
  }

  async function handleRedactMessages() {
    if (fullMessageCount === 0) return
    if (
      !window.confirm(
        cloud
          ? 'Samarkan isi lengkap semua pesan yang tersimpan di akun ini? Tautan, email, nomor telepon, dan deretan angka akan diganti.'
          : 'Samarkan isi lengkap semua pesan yang tersimpan? Tautan, email, nomor telepon, dan deretan angka akan diganti.',
      )
    ) {
      return
    }

    setStatus('')
    try {
      const count = await redactAll()
      setStatus(
        count > 0
          ? `${count} isi pesan disamarkan. Hasil pemeriksaan tetap tersimpan.`
          : 'Tidak ada isi pesan lengkap yang perlu disamarkan.',
      )
    } catch (cause) {
      setStatus(
        cloud
          ? firestoreErrorMessage(cause)
          : 'Isi pesan gagal disamarkan. Coba lagi.',
      )
    }
  }

  async function handleClearHistory() {
    if (scans.length === 0) return
    const target = cloud ? 'akun ini' : 'perangkat ini'
    if (!window.confirm(`Hapus seluruh riwayat pemeriksaan dari ${target}?`)) return

    setStatus('')
    try {
      await clear()
      setStatus(
        cloud
          ? 'Riwayat pemeriksaan dihapus dari akun ini.'
          : 'Riwayat pemeriksaan dihapus dari perangkat ini.',
      )
    } catch (cause) {
      setStatus(
        cloud ? firestoreErrorMessage(cause) : 'Riwayat pemeriksaan gagal dihapus.',
      )
    }
  }

  async function handleClearAllLocalData() {
    if (
      !window.confirm(
        'Hapus semua data aplikasi dari browser ini? Riwayat perangkat, laporan agen, analisis situs, antrean sinkronisasi, sesi demo, dan preferensi akan dihapus. Riwayat di akun TIDAK ikut terhapus — gunakan tombol "Hapus riwayat" untuk itu.',
      )
    ) {
      return
    }

    setStatus('')
    // VGL-17: penghapusan dijalankan lewat modul pemilik tiap kunci, tanpa memandang status
    // login atau sumber riwayat, dan tanpa localStorage.clear() yang bisa kena data SDK.
    clearLocalAppData()
    if (auth.mode === 'demo') auth.endDemoSession()
    const next = getPreferences()
    applyPreferences(next)
    setPreferencesState(next)
    await refresh()
    setStatus(
      cloud
        ? 'Semua data aplikasi di browser ini dihapus. Riwayat akun tidak disentuh.'
        : 'Semua data aplikasi di browser ini dihapus. Preferensi kembali ke pengaturan awal.',
    )
  }

  return (
    <Container className="pb-16 sm:pb-20">
      <PageHeader
        eyebrow="Pengaturan"
        title="Pengaturan perangkat"
        description={
          cloud
            ? 'Kontrol preferensi pemeriksaan, privasi, dan data akun yang tersimpan di penyimpanan data.'
            : 'Kontrol preferensi pemeriksaan, privasi, dan data lokal yang tersimpan di browser ini.'
        }
        actions={
          <Badge tone={cloud ? 'low' : 'neutral'}>
            {cloud ? 'Akun' : 'Penyimpanan lokal'}
          </Badge>
        }
      />

      <ProfileSyncNotice showSynced />

      <Alert
        tone={demo ? 'warning' : 'info'}
        className="mt-6"
        title={demo ? 'Profil akun dan sinkronisasi belum aktif' : 'Data akun'}
      >
        {demo
          ? 'Layanan akun belum terhubung. Tidak ada profil akun, email terverifikasi, atau sinkronisasi antarperangkat di halaman ini. Semua kontrol di bawah bekerja pada data lokal browser ini.'
          : session
            ? 'Kamu sedang masuk. Hasil pemeriksaan disimpan di penyimpanan data akun dan hanya dapat diakses oleh akun ini sesuai aturan akses.'
            : 'Layanan akun sudah tersedia, tetapi belum ada akun yang masuk. Riwayat yang terlihat saat ini berasal dari penyimpanan lokal browser; masuk untuk memakai data akun.'}
      </Alert>

      {historyError ? (
        <Alert tone="danger" className="mt-4" title="Riwayat akun gagal dimuat">
          <p>{historyError}</p>
          <Button variant="secondary" size="sm" className="mt-3" onClick={refresh}>
            Coba lagi
          </Button>
        </Alert>
      ) : null}

      <div className="mt-8 grid gap-4 lg:grid-cols-[minmax(0,1fr)_360px] lg:items-start">
        <div className="flex flex-col gap-4">
          <Card className="p-5 sm:p-6">
            <div className="flex items-center gap-2.5">
              <span className="grid size-8 place-items-center rounded-lg bg-accent-soft text-accent">
                <Settings2 size={17} aria-hidden="true" />
              </span>
              <h2 className="text-sm font-semibold text-ink">Preferensi pemeriksaan</h2>
            </div>

            <div className="mt-5">
              <span className="text-sm font-medium text-ink">Jenis pemeriksaan default</span>
              <p className="type-caption mt-0.5">
                Dipakai saat kamu membuka halaman periksa tanpa memilih mode.
              </p>
              <SegmentedControl
                options={SCAN_MODE_OPTIONS}
                value={preferences.defaultScanMode}
                onChange={(value) => savePreference({ defaultScanMode: value })}
                label="Jenis pemeriksaan default"
                className="mt-2"
              />
            </div>

            <div className="mt-6 border-t border-line pt-5">
              <label className="flex items-start gap-2.5">
                <input
                  type="checkbox"
                  checked={preferences.reduceMotion}
                  onChange={(event) => savePreference({ reduceMotion: event.target.checked })}
                  aria-describedby="reduce-motion-help"
                  className="mt-0.5 size-4 shrink-0 rounded border-line text-accent focus:ring-2 focus:ring-accent/20"
                />
                <span>
                  <span className="block text-sm font-medium text-ink">
                    Kurangi gerakan antarmuka
                  </span>
                  <span id="reduce-motion-help" className="type-caption mt-0.5 block">
                    Mengurangi animasi dan transisi. Pengaturan sistem operasi tetap dihormati.
                  </span>
                </span>
              </label>
            </div>

            <Button
              variant="ghost"
              size="sm"
              className="mt-5"
              onClick={handleResetPreferences}
            >
              Kembalikan preferensi awal
            </Button>
          </Card>

          <Card className="p-5 sm:p-6">
            <div className="flex items-center gap-2.5">
              <span className="grid size-8 place-items-center rounded-lg bg-accent-soft text-accent">
                <Database size={17} aria-hidden="true" />
              </span>
              <h2 className="text-sm font-semibold text-ink">
                {cloud ? 'Data pemeriksaan akun' : 'Data pemeriksaan lokal'}
              </h2>
            </div>
            <p className="type-caption mt-1">
              {cloud
                ? 'Riwayat disimpan di penyimpanan data akun ini. Maksimal 30 pemeriksaan terakhir dimuat.'
                : 'Riwayat tidak dikirim ke layanan mana pun. Maksimal 30 pemeriksaan terakhir disimpan di browser ini.'}
            </p>
            {loading ? (
              <p className="type-caption mt-3" role="status">
                Memuat riwayat akun…
              </p>
            ) : null}

            <dl className="mt-5 grid gap-3 sm:grid-cols-3">
              <div className="rounded-card border border-line bg-canvas p-3.5">
                <dt className="type-caption">Total pemeriksaan</dt>
                <dd className="mt-1 text-2xl font-semibold tabular-nums text-ink">
                  {scans.length}
                </dd>
              </div>
              <div className="rounded-card border border-line bg-canvas p-3.5">
                <dt className="type-caption">Pesan penuh</dt>
                <dd className="mt-1 text-2xl font-semibold tabular-nums text-ink">
                  {fullMessageCount}
                </dd>
              </div>
              <div className="rounded-card border border-line bg-canvas p-3.5">
                <dt className="type-caption">Cuplikan disamarkan</dt>
                <dd className="mt-1 text-2xl font-semibold tabular-nums text-ink">
                  {redactedMessageCount}
                </dd>
              </div>
            </dl>

            <div className="mt-5 flex flex-wrap gap-2">
              <Button
                variant="secondary"
                size="sm"
                onClick={handleRedactMessages}
                disabled={fullMessageCount === 0}
              >
                <Eraser size={15} aria-hidden="true" />
                Samarkan semua isi pesan
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={handleExport}
                disabled={scans.length === 0}
              >
                <Download size={15} aria-hidden="true" />
                Ekspor CSV
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={handleClearHistory}
                disabled={scans.length === 0}
              >
                <Trash2 size={15} aria-hidden="true" />
                Hapus riwayat
              </Button>
            </div>

            <p className="type-caption mt-4">
              {cloud
                ? 'Menyamarkan isi pesan memperbarui data akun ini tanpa menghapus hasil analisis, skor, atau pola. Data lengkap yang sudah disamarkan tidak dapat dipulihkan.'
                : 'Menyamarkan isi pesan tidak menghapus hasil analisis, skor, atau pola. Data lengkap yang sudah disamarkan tidak dapat dipulihkan dari browser ini.'}
            </p>
          </Card>
        </div>

        <aside className="flex flex-col gap-4">
          <Card className="p-5">
            <div className="flex items-center gap-2.5">
              <span className="grid size-8 place-items-center rounded-lg bg-subtle text-ink-muted">
                <UserRound size={17} aria-hidden="true" />
              </span>
              <h2 className="text-sm font-semibold text-ink">Akun dan sesi</h2>
            </div>

            {session ? (
              <>
                <div className="mt-4 flex flex-wrap items-center gap-2">
                  <p className="text-sm font-medium text-ink">{session.displayName}</p>
                  <Badge tone={demo ? 'neutral' : 'low'}>
                    {demo ? 'Sesi demo lokal' : 'Akun masuk'}
                  </Badge>
                  {!demo ? (
                    <Badge tone={session.emailVerified ? 'low' : 'medium'}>
                      {emailStateLabel(session)}
                    </Badge>
                  ) : null}
                </div>
                <p className="type-caption mt-1">
                  {demo
                    ? session.startedAt
                      ? `Dimulai ${formatDate(session.startedAt)} · bukan autentikasi`
                      : 'Sesi demo lokal · bukan autentikasi'
                    : sessionEmailText}
                </p>
                <p className="type-small mt-3 text-ink-soft">
                  {demo
                    ? 'Sesi ini hanya membuka alur dashboard di perangkat ini. Tidak ada sesi masuk, verifikasi email, atau sinkronisasi akun.'
                    : session.emailVerified
                      ? 'Email akun ini sudah terverifikasi. Hasil pemeriksaan tersinkronisasi di penyimpanan data akun yang sedang masuk.'
                      : 'Email akun ini belum diverifikasi. Fitur akun (dashboard, riwayat, pemindaian berakun, komunitas) terkunci sampai verifikasi selesai.'}
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  {!demo && !session.emailVerified ? (
                    <Link
                      to="/verifikasi-email"
                      className={buttonStyles({ size: 'sm' })}
                    >
                      <MailWarning size={15} aria-hidden="true" />
                      Verifikasi email
                    </Link>
                  ) : null}
                  <Button variant="secondary" size="sm" onClick={handleEndSession}>
                    <LogOut size={15} aria-hidden="true" />
                    {demo ? 'Akhiri sesi demo' : 'Keluar dari akun'}
                  </Button>
                </div>
              </>
            ) : (
              <>
                <p className="type-small mt-4 text-ink-soft">
                  {demo
                    ? 'Belum ada sesi lokal. Dashboard memerlukan sesi demo sampai autentikasi sungguhan tersedia.'
                    : 'Belum ada akun yang masuk. Masuk untuk membaca dan menyimpan riwayat di akun.'}
                </p>
                <Link to="/masuk" className={buttonStyles({ size: 'sm', className: 'mt-4' })}>
                  {demo ? 'Buka sesi demo lokal' : 'Masuk dengan email'}
                </Link>
              </>
            )}

            <div className="mt-5 border-t border-line pt-4">
              <p className="type-caption">
                {demo
                  ? 'Masuk dengan email atau Google, profil akun, dan sinkronisasi menunggu layanan akun.'
                  : 'Layanan akun mengelola sesi akun. Kata sandi dan verifikasi email tidak disimpan di aplikasi ini.'}
              </p>
            </div>
          </Card>

          <AccountUsernameCard />

          <Card className="border-risk-high-line bg-risk-high-bg/40 p-5">
            <div className="flex items-center gap-2.5">
              <span className="grid size-8 place-items-center rounded-lg bg-surface text-risk-high">
                <ShieldCheck size={17} aria-hidden="true" />
              </span>
              <h2 className="text-sm font-semibold text-ink">Hapus semua data lokal</h2>
            </div>
            <p className="type-small mt-3 text-ink-soft">
              Menghapus seluruh data aplikasi di browser ini: riwayat perangkat, laporan agen,
              analisis situs, antrean sinkronisasi, sesi demo, dan preferensi. Data milik layanan
              pihak ketiga (sesi akun Firebase, tantangan CAPTCHA) tidak disentuh. Tindakan ini
              tidak dapat dibatalkan dan tidak menghapus riwayat di akun. Untuk riwayat akun,
              gunakan tombol Hapus riwayat.
            </p>
            <Button variant="danger" size="sm" className="mt-4" onClick={handleClearAllLocalData}>
              <Trash2 size={15} aria-hidden="true" />
              Hapus semua data lokal
            </Button>
          </Card>

          <Card className="border-dashed bg-subtle/60 p-5">
            <div className="flex items-center gap-2">
              <Check size={16} className="text-risk-low" aria-hidden="true" />
              <h2 className="text-sm font-semibold text-ink">Yang berfungsi sekarang</h2>
            </div>
            <ul className="mt-3 flex flex-col gap-2 text-sm text-ink-soft">
              <li>Preferensi mode dan gerakan tersimpan di perangkat.</li>
              <li>Riwayat dapat diekspor, disamarkan, atau dihapus.</li>
              <li>
                {cloud
                  ? 'Riwayat akun dibaca dan diperbarui di penyimpanan data dengan akses pemilik.'
                  : 'Data tetap berada di browser dan tidak diunggah.'}
              </li>
            </ul>
          </Card>
        </aside>
      </div>

      <p role="status" aria-live="polite" className="type-small mt-5 min-h-5 text-ink-soft">
        {status}
      </p>
    </Container>
  )
}

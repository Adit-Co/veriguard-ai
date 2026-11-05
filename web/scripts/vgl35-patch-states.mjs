// @ts-check
/// <reference types="node" />
// VGL-35 — panel status sebaris-kiri menggantikan kartu terpusat yang berulang.
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * @param {string} rel
 * @param {Array<{ from: string, to: string, all?: boolean }>} edits
 */
function patch(rel, edits) {
  const file = resolve(process.cwd(), rel)
  const raw = readFileSync(file, 'utf8')
  const crlf = raw.includes('\r\n')
  let s = crlf ? raw.replace(/\r\n/g, '\n') : raw
  for (const { from, to, all } of edits) {
    const count = s.split(from).length - 1
    if (count === 0) throw new Error(`${rel}: tidak ditemukan ->\n${from}`)
    if (!all && count !== 1) throw new Error(`${rel}: tidak unik (${count}) ->\n${from}`)
    s = all ? s.split(from).join(to) : s.replace(from, to)
  }
  writeFileSync(file, crlf ? s.replace(/\n/g, '\r\n') : s, 'utf8')
  console.log(`patched ${rel} (CRLF=${crlf})`)
}

patch('src/pages/HistoryPage.tsx', [
  {
    from: "import { SegmentedControl } from '../components/ui/SegmentedControl'\n",
    to:
      "import { SegmentedControl } from '../components/ui/SegmentedControl'\nimport { StatePanel } from '../components/ui/StatePanel'\n",
  },
  {
    from: `        <Card className="mt-8 px-6 py-14 text-center" role="status">
          <h2 className="type-h3">Memeriksa sesi akun…</h2>
          <p className="type-small mt-2 text-ink-soft">
            Riwayat akun tidak ditampilkan sebelum status sesi akun diketahui.
          </p>
        </Card>
`,
    to: `        <StatePanel
          role="status"
          icon={History}
          tone="neutral"
          title="Memeriksa sesi akun…"
          description="Riwayat akun tidak ditampilkan sebelum status sesi akun diketahui."
          className="mt-8 max-w-[720px]"
        />
`,
  },
  {
    from: `          <Card className="flex flex-col items-center px-6 py-14 text-center" role="status">
            <span className="grid size-12 place-items-center rounded-full bg-subtle text-ink-muted">
              <History size={22} aria-hidden="true" />
            </span>
            <h2 className="type-h3 mt-5">Memuat riwayat akun…</h2>
            <p className="type-small mt-2 max-w-[46ch] text-ink-soft">
              Mengambil pemeriksaan milik akun yang sedang masuk.
            </p>
          </Card>
`,
    to: `          <StatePanel
            role="status"
            icon={History}
            tone="neutral"
            title="Memuat riwayat akun…"
            description="Mengambil pemeriksaan milik akun yang sedang masuk."
            className="max-w-[720px]"
          />
`,
  },
  {
    from: `            <Card className="flex flex-col items-center px-6 py-14 text-center">
              <span className="grid size-12 place-items-center rounded-full bg-subtle text-ink-muted">
                <History size={22} aria-hidden="true" />
              </span>
              <h2 className="type-h3 mt-5">Belum ada riwayat</h2>
              <p className="type-small mt-2 max-w-[46ch] text-ink-soft">
`,
    to: `            <StatePanel
              icon={History}
              tone="neutral"
              title="Belum ada riwayat"
              actions={
                <Link to="/periksa" className={buttonStyles()}>
                  Mulai pemeriksaan
                </Link>
              }
              className="max-w-[720px]"
            >
              <p className="type-small mt-2 max-w-[62ch] text-ink-soft">
`,
  },
  {
    from: `              <Link to="/periksa" className={buttonStyles({ className: 'mt-6' })}>
                Mulai pemeriksaan
              </Link>
            </Card>
`,
    to: `            </StatePanel>
`,
  },
  {
    from: `            <Card className="mt-4 flex flex-col items-center px-6 py-12 text-center">
              <span className="grid size-12 place-items-center rounded-full bg-subtle text-ink-muted">
                <SearchX size={22} aria-hidden="true" />
              </span>
              <h2 className="type-h3 mt-5">Tidak ada hasil yang cocok</h2>
              <p className="type-small mt-2 max-w-[44ch] text-ink-soft">
`,
    to: `            <StatePanel
              icon={SearchX}
              tone="neutral"
              title="Tidak ada hasil yang cocok"
              actions={<Button variant="secondary" onClick={resetFilters}>Reset filter</Button>}
              className="mt-4 max-w-[720px]"
            >
              <p className="type-small mt-2 max-w-[62ch] text-ink-soft">
`,
  },
  {
    from: `              <Button variant="secondary" className="mt-5" onClick={resetFilters}>
                Reset filter
              </Button>
            </Card>
`,
    to: `            </StatePanel>
`,
  },
  { from: '<Container className="pb-16">', to: '<Container className="pb-16 sm:pb-20">', all: true },
])

patch('src/pages/DashboardPage.tsx', [
  {
    from: "import { PageHeader } from '../components/ui/PageHeader'\n",
    to:
      "import { PageHeader } from '../components/ui/PageHeader'\nimport { StatePanel } from '../components/ui/StatePanel'\n",
  },
  {
    from: `        <Card className="mt-8 px-6 py-14 text-center" role="status">
          <h2 className="type-h3">Memulihkan sesi akun…</h2>
          <p className="type-small mt-2 text-ink-soft">
            Dashboard akan terbuka setelah status akun diketahui.
          </p>
        </Card>
`,
    to: `        <StatePanel
          role="status"
          icon={Activity}
          tone="neutral"
          title="Memulihkan sesi akun…"
          description="Dashboard akan terbuka setelah status akun diketahui."
          className="mt-8 max-w-[720px]"
        />
`,
  },
  {
    from: `        <Card className="mt-8 px-6 py-14 text-center" role="status">
          <h2 className="type-h3">Memuat riwayat akun…</h2>
          <p className="type-small mt-2 text-ink-soft">
            Statistik dihitung setelah pemeriksaan milik akun ini selesai dimuat.
          </p>
        </Card>
`,
    to: `        <StatePanel
          role="status"
          icon={History}
          tone="neutral"
          title="Memuat riwayat akun…"
          description="Statistik dihitung setelah pemeriksaan milik akun ini selesai dimuat."
          className="mt-8 max-w-[720px]"
        />
`,
  },
  {
    from: `        <Card className="mt-8 flex flex-col items-center px-6 py-14 text-center">
          <span className="grid size-12 place-items-center rounded-full bg-subtle text-ink-muted">
            <LockKeyhole size={22} aria-hidden="true" />
          </span>
          <h2 className="type-h3 mt-5">Dashboard memerlukan sesi</h2>
          <p className="type-small mt-2 max-w-[52ch] text-ink-soft">
`,
    to: `        <StatePanel
          icon={LockKeyhole}
          tone="neutral"
          title="Dashboard memerlukan sesi"
          actions={
            <>
              <Link to="/masuk" className={buttonStyles()}>
                {demo ? 'Buka sesi demo lokal' : 'Masuk dengan email'}
              </Link>
              <Link
                to={demo ? '/riwayat' : '/daftar'}
                className={buttonStyles({ variant: 'secondary' })}
              >
                {demo ? 'Buka riwayat' : 'Buat akun'}
              </Link>
            </>
          }
          className="mt-8 max-w-[720px]"
        >
          <p className="type-small mt-2 max-w-[62ch] text-ink-soft">
`,
  },
  {
    from: `          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <Link to="/masuk" className={buttonStyles()}>
              {demo ? 'Buka sesi demo lokal' : 'Masuk dengan email'}
            </Link>
            <Link
              to={demo ? '/riwayat' : '/daftar'}
              className={buttonStyles({ variant: 'secondary' })}
            >
              {demo ? 'Buka riwayat' : 'Buat akun'}
            </Link>
          </div>
        </Card>
`,
    to: `        </StatePanel>
`,
  },
  {
    from: `        <Card className="mt-6 flex flex-col items-center px-6 py-14 text-center">
          <span className="grid size-12 place-items-center rounded-full bg-accent-soft text-accent">
            <History size={22} aria-hidden="true" />
          </span>
          <h2 className="type-h3 mt-5">Belum ada pemeriksaan tersimpan</h2>
          <p className="type-small mt-2 max-w-[56ch] text-ink-soft">
`,
    to: `        <StatePanel
          icon={History}
          title="Belum ada pemeriksaan tersimpan"
          actions={
            <>
              <Link to="/periksa" className={buttonStyles()}>
                Mulai pemeriksaan
                <ArrowRight size={15} aria-hidden="true" />
              </Link>
              <Link to="/riwayat" className={buttonStyles({ variant: 'secondary' })}>
                Buka riwayat
              </Link>
            </>
          }
          className="mt-6 max-w-[720px]"
        >
          <p className="type-small mt-2 max-w-[62ch] text-ink-soft">
`,
  },
  {
    from: `          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <Link to="/periksa" className={buttonStyles()}>
              Mulai pemeriksaan
              <ArrowRight size={15} aria-hidden="true" />
            </Link>
            <Link to="/riwayat" className={buttonStyles({ variant: 'secondary' })}>
              Buka riwayat
            </Link>
          </div>
        </Card>
`,
    to: `        </StatePanel>
`,
  },
  { from: '<Container className="pb-16">', to: '<Container className="pb-16 sm:pb-20">', all: true },
])

patch('src/pages/ResultPage.tsx', [
  {
    from: "import { PageHeader } from '../components/ui/PageHeader'\n",
    to:
      "import { PageHeader } from '../components/ui/PageHeader'\nimport { StatePanel } from '../components/ui/StatePanel'\n",
  },
  {
    from: `        <Card className="mt-8 px-6 py-14 text-center" role="status">
          <p className="text-sm font-semibold text-ink">Memuat hasil pemeriksaan…</p>
          <p className="type-small mt-2 text-ink-soft">
            Hasil diambil dari penyimpanan lokal tamu atau akun yang sedang masuk.
          </p>
        </Card>
`,
    to: `        <StatePanel
          role="status"
          icon={Activity}
          tone="neutral"
          title="Memuat hasil pemeriksaan…"
          description="Hasil diambil dari penyimpanan lokal tamu atau akun yang sedang masuk."
          className="mt-8 max-w-[720px]"
        />
`,
  },
  {
    from: `        <Card className="mt-8 px-6 py-14 text-center">
          <h2 className="type-h3">Koneksi ke penyimpanan data gagal</h2>
          <p className="type-small mt-2 text-ink-soft">{error}</p>
          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <Button onClick={retry}>Coba lagi</Button>
            <Link to="/riwayat" className={buttonStyles({ variant: 'secondary', size: 'md' })}>
              Buka riwayat
            </Link>
          </div>
        </Card>
`,
    to: `        <StatePanel
          icon={TriangleAlert}
          tone="danger"
          title="Koneksi ke penyimpanan data gagal"
          description={error}
          actions={
            <>
              <Button onClick={retry}>Coba lagi</Button>
              <Link to="/riwayat" className={buttonStyles({ variant: 'secondary', size: 'md' })}>
                Buka riwayat
              </Link>
            </>
          }
          className="mt-8 max-w-[720px]"
        />
`,
  },
  {
    from: `        <Card className="mt-8 flex flex-col items-center px-6 py-14 text-center">
          <span className="grid size-12 place-items-center rounded-full bg-subtle text-ink-muted">
            <FileQuestion size={22} aria-hidden="true" />
          </span>
          <h2 className="type-h3 mt-5">Hasil mungkin sudah dihapus</h2>
          <p className="type-small mt-2 max-w-[48ch] text-ink-soft">
`,
    to: `        <StatePanel
          icon={FileQuestion}
          tone="neutral"
          title="Hasil mungkin sudah dihapus"
          actions={
            <div className="contents print:hidden">
              <Link to="/periksa" className={buttonStyles({ size: 'md' })}>
                Mulai pemeriksaan baru
              </Link>
              <Link to="/riwayat" className={buttonStyles({ variant: 'secondary', size: 'md' })}>
                Buka riwayat
              </Link>
            </div>
          }
          className="mt-8 max-w-[720px]"
        >
          <p className="type-small mt-2 max-w-[62ch] text-ink-soft">
`,
  },
  {
    from: `          <div className="mt-6 flex flex-wrap justify-center gap-3 print:hidden">
            <Link to="/periksa" className={buttonStyles({ size: 'md' })}>
              Mulai pemeriksaan baru
            </Link>
            <Link to="/riwayat" className={buttonStyles({ variant: 'secondary', size: 'md' })}>
              Buka riwayat
            </Link>
          </div>
        </Card>
`,
    to: `        </StatePanel>
`,
  },
  { from: '<Container className="pb-16">', to: '<Container className="pb-16 sm:pb-20">', all: true },
])

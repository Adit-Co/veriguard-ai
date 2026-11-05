export function AppCrashFallback() {
  return (
    <main className="grid min-h-screen place-items-center bg-canvas px-6 py-16">
      <section
        role="alert"
        aria-labelledby="app-crash-title"
        className="w-full max-w-xl rounded-card border border-line bg-surface p-6 shadow-sm sm:p-8"
      >
        <p className="type-eyebrow text-ink-muted">VERIGUARD AI</p>
        <h1 id="app-crash-title" className="mt-2 text-2xl font-semibold text-ink">
          Halaman gagal ditampilkan
        </h1>
        <p className="mt-3 text-sm leading-relaxed text-ink-soft">
          Terjadi kesalahan saat menampilkan halaman ini. Tidak ada data baru yang
          dikirim atau diubah karena kegagalan tampilan. Muat ulang halaman atau kembali
          ke beranda untuk melanjutkan.
        </p>
        <div className="mt-6 flex flex-wrap gap-3">
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="inline-flex h-11 items-center justify-center rounded-btn bg-accent px-4 text-sm font-medium text-on-accent transition-colors hover:bg-accent-hover focus-visible:outline-none"
          >
            Muat ulang halaman
          </button>
          <a
            href="/"
            className="inline-flex h-11 items-center justify-center rounded-btn border border-line bg-surface px-4 text-sm font-medium text-ink transition-colors hover:border-line-strong hover:bg-subtle focus-visible:outline-none"
          >
            Kembali ke beranda
          </a>
        </div>
      </section>
    </main>
  )
}

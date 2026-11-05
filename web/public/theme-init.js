// VGL-33B — inisialisasi tema SEBELUM paint pertama, tanpa inline script (CSP produksi
// melarang 'unsafe-inline' pada script-src; berkas EKSTERNAL dari origin sendiri diizinkan).
// Skrip ini adalah classic script (bukan module) sehingga berjalan sinkron saat HTML diparse.
// Hanya membaca localStorage milik aplikasi sendiri; tidak pernah memanggil jaringan.
(function () {
  var theme = 'light'
  try {
    var raw = window.localStorage.getItem('veriguard.preferences.v1')
    if (raw) {
      var parsed = JSON.parse(raw)
      if (parsed && parsed.theme === 'dark') theme = 'dark'
    }
  } catch {
    // Penyimpanan rusak/tertutup (mode privat): tetap ke default LIGHT, bukan menebak-nebak.
  }
  document.documentElement.dataset.theme = theme
  var meta = document.querySelector('meta[name="theme-color"]')
  if (meta) meta.setAttribute('content', theme === 'dark' ? '#0B1220' : '#F8FAFC')
})()

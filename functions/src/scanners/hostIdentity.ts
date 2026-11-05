// Perbandingan identitas host untuk bukti agen eksternal (VGL-30K-R4).
//
// Lapisan scanners tidak boleh mengimpor dari lapisan website — arah dependensi yang ada
// adalah website -> scanners (lihat `website/service.ts`), jadi aturan domain registrable
// diulang di sini secara mandiri. `test/hostIdentity.test.ts` membandingkan hasil modul ini
// dengan `website/urlSignals.ts` pada tabel host agar kedua daftar suffix tidak bercabang.
//
// Yang dibutuhkan agen 6 dan 7 bukan "dua host mirip", melainkan tiga pertanyaan berbeda:
// - host yang SAMA persis: subjek analisis / indikator yang benar-benar alamat yang diperiksa;
// - induk yang MASIH SATU domain registrable: bukti tingkat domain, bobotnya lebih rendah;
// - selain itu: host lain (lookalike, kesamaan hosting, public suffix) yang tidak pernah
//   boleh mewariskan reputasi ke alamat yang diperiksa.
const MULTI_LEVEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'net.uk', 'ltd.uk', 'plc.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
  'co.id', 'web.id', 'my.id', 'biz.id', 'or.id', 'go.id', 'sch.id', 'net.id', 'ac.id',
  'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.za', 'org.za', 'web.za',
  'com.mx', 'org.mx', 'gob.mx',
  'com.tr', 'org.tr', 'net.tr', 'gov.tr',
  'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg',
  'com.my', 'net.my', 'org.my', 'gov.my',
  'com.ph', 'net.ph', 'org.ph', 'gov.ph',
  'com.vn', 'net.vn', 'org.vn',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.kr', 'or.kr', 'ne.kr', 'go.kr',
  'com.sa', 'com.eg', 'com.pk', 'com.bd', 'com.ng', 'co.ke', 'com.gh', 'com.co',
  'com.ar', 'com.pe', 'com.cl', 'com.ve', 'com.ec',
  'fr.eu', 'com.eu',
])

export function normalizeHost(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/, '')
}

export function hostLabels(host: string): string[] {
  return normalizeHost(host).split('.').filter(Boolean)
}

// Domain registrable diperkirakan: suffix multi-level yang dikenali dipakai, selain itu dua
// label terakhir. Tidak ada layanan public-suffix eksternal yang dipanggil, jadi keterbatasan
// ini disengaja — dan justru karena itu kecocokan pada tingkat public suffix ditolak.
export function registrableDomain(host: string): string {
  const labels = hostLabels(host)
  if (labels.length <= 2) return labels.join('.')
  const tail = `${labels[labels.length - 2]}.${labels[labels.length - 1]}`
  if (MULTI_LEVEL_SUFFIXES.has(tail) && labels.length >= 3) {
    return `${labels[labels.length - 3]}.${tail}`
  }
  return tail
}

export function isSameHost(candidate: string, target: string): boolean {
  const host = normalizeHost(candidate)
  return host.length > 0 && host === normalizeHost(target)
}

/**
 * Apakah nilai indikator `candidate` berbicara tentang host `target`:
 * - host yang sama persis, atau
 * - induk dari target pada BATAS LABEL dan masih satu domain registrable.
 *
 * Batas label menolak kecocokan sebagian seperti `contoh.com` terhadap `notcontoh.com`, dan
 * syarat domain registrable menolak public suffix (`co.id`, `com`) sebagai indikator target.
 * Host yang lebih spesifik dari target (subdomain lain) TIDAK dipakai: itu alamat yang berbeda.
 */
export function hostIndicatorCovers(candidate: string, target: string): boolean {
  const host = normalizeHost(candidate)
  const wanted = normalizeHost(target)
  if (!host || !wanted) return false
  if (host === wanted) return true
  if (!wanted.endsWith(`.${host}`)) return false
  return registrableDomain(host) === registrableDomain(wanted)
}

/**
 * Host dari sebuah nilai indikator OTX / url laporan. Nilai boleh berupa domain, hostname,
 * URL lengkap, atau IP. Nilai yang tidak dapat diurai mengembalikan null sehingga caller
 * memperlakukannya sebagai "tidak terbaca", bukan sebagai kecocokan.
 */
export function hostOfIndicatorValue(value: string): string | null {
  const trimmed = value.trim()
  if (!trimmed) return null

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) return trimmed
  if (trimmed.startsWith('[')) return normalizeHost(trimmed.split(']')[0] + ']')

  if (trimmed.includes('://')) {
    try {
      const host = normalizeHost(new URL(trimmed).hostname)
      return host || null
    } catch {
      return null
    }
  }

  // Nilai tanpa scheme yang memuat kredensial bukan host: `user@host` dipakai orang, bukan
  // terdaftar sebagai indikator, jadi diperlakukan tidak terbaca alih-alih menebak sisinya.
  if (trimmed.includes('@')) return null

  const authority = trimmed.split(/[/?#]/)[0]
  const host = normalizeHost(authority.split(':')[0])
  return host || null
}

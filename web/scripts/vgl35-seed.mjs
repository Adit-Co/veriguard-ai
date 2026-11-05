// @ts-check
// VGL-35 — data rekam jejak sah untuk harness screenshot (lolos isScanResult).

/**
 * @param {string} theme
 */
export function seedScript(theme) {
  const scans = [
    {
      id: 'vgl35-sample',
      createdAt: new Date(Date.now() - 3_600_000).toISOString(),
      mode: 'link',
      riskLevel: 'high',
      riskScore: 86,
      input: 'https://tokokita-bayar.com/promo-undian',
      displayTarget: 'tokokita-bayar.com',
      headline: 'Pola penipuan sering muncul pada tautan ini',
      summary:
        'Struktur domain, kata kunci undian, dan permintaan data pribadi membentuk pola penipuan yang umum.',
      reasons: [
        {
          id: 'brand-lookalike',
          label: 'Domain menyerupai merek',
          detail: 'tokokita-bayar.com bukan domain resmi dan baru didaftarkan.',
          severity: 'danger',
          weight: 28,
          category: 'impersonation',
        },
        {
          id: 'urgency-word',
          label: 'Desakan segera klaim',
          detail: 'Frasa "segera klaim" memaksa keputusan cepat.',
          severity: 'warning',
          weight: 12,
          category: 'urgency',
        },
      ],
      patterns: [
        {
          id: 'giveaway',
          label: 'Pola undian palsu',
          description: 'Menawarkan hadiah yang harus diklaim lewat tautan.',
          confidence: 'high',
        },
      ],
      recommendations: [
        'Buka situs resmi merek lewat pencarian manual, bukan lewat tautan ini.',
        'Jangan isi data pribadi atau kode OTP di halaman yang diklik dari pesan.',
      ],
      technical: [
        { label: 'Panjang URL', value: '39 karakter', tone: 'neutral' },
        { label: 'Subdomain', value: 'tidak dipakai', tone: 'neutral' },
      ],
      meta: {
        engineVersion: 'vgl35-baseline',
        signalCount: 2,
        inputLength: 39,
        aiStatus: 'not_used',
        inputStored: 'full',
      },
    },
    {
      id: 'vgl35-message',
      createdAt: new Date(Date.now() - 7_200_000).toISOString(),
      mode: 'message',
      riskLevel: 'medium',
      riskScore: 44,
      input:
        'Selamat! Akun Anda terpilih menerima hadiah 5 juta. Kirim OTP yang masuk ke nomor Anda untuk klaim hari ini juga.',
      displayTarget: 'Pesan 118 karakter',
      headline: 'Pesan meminta kode OTP dan menekan waktu',
      summary: 'Permintaan OTP disertai desakan adalah pola pengambilan akun.',
      reasons: [
        {
          id: 'otp-request',
          label: 'Permintaan OTP',
          detail: 'Pengirim meminta kode sekali pakai melalui pesan.',
          severity: 'danger',
          weight: 24,
          category: 'request',
        },
        {
          id: 'gift-claim',
          label: 'Hadiah yang tidak diikuti',
          detail: 'Klaim hadiah tanpa ikut program sebelumnya.',
          severity: 'warning',
          weight: 14,
          category: 'transaction',
        },
      ],
      patterns: [
        {
          id: 'otp_theft',
          label: 'Pencurian OTP',
          description: 'Meminta kode verifikasi lewat pesan.',
          confidence: 'medium',
        },
      ],
      recommendations: ['Jangan pernah membagikan OTP.', 'Hubungi layanan resmi melalui nomor aplikasi.'],
      technical: [
        { label: 'Panjang pesan', value: '118 karakter', tone: 'neutral' },
        { label: 'Indikator bahasa', value: 'urgensi + hadiah', tone: 'warning' },
      ],
      meta: {
        engineVersion: 'vgl35-baseline',
        signalCount: 2,
        inputLength: 118,
        aiStatus: 'not_used',
        inputStored: 'full',
      },
    },
  ]

  return `
window.localStorage.setItem(
  'veriguard.preferences.v1',
  JSON.stringify({ defaultScanMode: 'link', reduceMotion: false, theme: ${JSON.stringify(theme)} }),
);
window.localStorage.setItem('veriguard.scans.v1', ${JSON.stringify(JSON.stringify(scans))});
`
}

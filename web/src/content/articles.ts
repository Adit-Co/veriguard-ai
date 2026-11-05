export type ArticleSection = {
  heading: string
  paragraphs: string[]
  bullets?: string[]
}

export type Article = {
  slug: string
  title: string
  summary: string
  readTime: string
  intro: string
  sections: ArticleSection[]
  takeaway: string
}

export const articles: Article[] = [
  {
    slug: 'mengenali-phishing',
    title: 'Mengenali phishing sebelum kamu mengeklik',
    summary:
      'Phishing menyamar sebagai layanan resmi untuk mencuri kata sandi, kode OTP, atau data kartu. Kenali ciri yang paling sering muncul.',
    readTime: '4 menit baca',
    intro:
      'Phishing adalah pesan atau halaman palsu yang dibuat menyerupai layanan resmi. Tujuannya satu: membuat kamu memasukkan data sensitif tanpa curiga.',
    sections: [
      {
        heading: 'Ciri yang paling sering muncul',
        paragraphs: [
          'Pesan phishing biasanya menciptakan rasa urgensi: akun akan diblokir, paket akan dikembalikan, atau hadiah akan hangus dalam hitungan jam. Tekanan waktu dipakai agar kamu bertindak sebelum sempat memeriksa.',
          'Selain itu, tautan yang dikirim sering tidak mengarah ke domain resmi. Pelaku memakai domain yang mirip, subdomain berlapis, atau pemendek tautan agar alamat aslinya tidak terlihat.',
        ],
        bullets: [
          'Permintaan kata sandi, PIN, kode OTP, atau foto kartu identitas.',
          'Alamat pengirim yang terlihat resmi tetapi berbeda satu atau dua huruf.',
          'Tautan dengan domain seperti “verifikasi-akun”, “login-secure”, atau nama merek di subdomain.',
          'Lampiran atau tombol yang meminta kamu masuk ulang ke akun.',
        ],
      },
      {
        heading: 'Contoh konkret',
        paragraphs: [
          'Pesan mengaku dari bank: “Akun Anda terdeteksi mencurigakan. Verifikasi dalam 30 menit melalui tautan berikut.” Tautan mengarah ke domain yang memuat nama bank, tetapi bukan domain resmi bank tersebut.',
          'Bank tidak akan meminta kata sandi atau kode OTP melalui pesan singkat. Jika kamu membuka tautan dan diminta data tersebut, hentikan prosesnya.',
        ],
      },
      {
        heading: 'Yang perlu dilakukan',
        paragraphs: [
          'Jangan mengeklik tautan dari pesan yang tidak diminta. Buka aplikasi atau situs resmi secara langsung, lalu cek notifikasi di sana. Jika tetap ragu, hubungi layanan pelanggan melalui nomor yang tertera di situs resmi.',
        ],
        bullets: [
          'Periksa domain sebelum memasukkan data apa pun.',
          'Jangan pernah membagikan kode OTP kepada siapa pun.',
          'Laporkan pesan ke penyedia layanan dan blokir pengirimnya.',
        ],
      },
    ],
    takeaway:
      'Urgensi palsu dan permintaan data sensitif adalah dua tanda paling kuat. Berhenti, buka layanan resmi secara mandiri, lalu verifikasi.',
  },
  {
    slug: 'modus-penipuan-digital',
    title: 'Modus penipuan digital yang paling sering terjadi',
    summary:
      'Dari hadiah palsu hingga lowongan kerja fiktif, pelaku memakai pola komunikasi yang berulang. Mengenali polanya membuat kamu lebih sulit dikelabui.',
    readTime: '5 menit baca',
    intro:
      'Modus penipuan berubah bentuk, tetapi pola dasarnya sering sama: menawarkan keuntungan, menciptakan ketakutan, atau menyamar sebagai pihak yang berwenang.',
    sections: [
      {
        heading: 'Lima modus yang perlu dikenali',
        paragraphs: [
          'Hadiah dan undian. Kamu diberi tahu memenangkan sesuatu yang tidak pernah diikuti, lalu diminta membayar biaya administrasi atau mengisi data rekening.',
          'Jual beli online. Penjual meminta pembayaran di luar platform, mengirim tautan pembayaran palsu, atau mengaku sebagai kurir yang meminta biaya tambahan.',
          'Penyamaran institusi. Pelaku mengaku sebagai bank, petugas pajak, kepolisian, atau layanan kurir, lalu meminta verifikasi data melalui tautan.',
          'Investasi dan crypto. Keuntungan dijanjikan besar dan cepat, dengan tekanan untuk segera menyetor dana atau mengunduh aplikasi tertentu.',
          'Lowongan kerja. Kandidat diminta membayar biaya pelatihan, memberikan data rekening, atau menerima uang dari sumber tidak jelas sebagai bagian dari “tugas”.',
        ],
      },
      {
        heading: 'Pola bahasa yang berulang',
        paragraphs: [
          'Pelaku biasanya menggabungkan pujian, ancaman, dan batas waktu. Kalimat seperti “khusus untuk Anda”, “jangan sampai hangus”, atau “tindakan hukum” dipakai untuk mempersempit ruang berpikir korban.',
          'Permintaan berpindah ke kanal pribadi juga perlu diwaspadai. Ajakan chat ke nomor pribadi sering dipakai agar percakapan tidak tercatat di platform resmi.',
        ],
        bullets: [
          'Keuntungan tidak wajar dalam waktu singkat.',
          'Permintaan pembayaran di muka untuk mendapatkan sesuatu.',
          'Desakan untuk segera bertindak atau merahasiakan transaksi.',
          'Permintaan data rekening, OTP, atau tangkapan layar aplikasi bank.',
        ],
      },
      {
        heading: 'Cara memutus rantai penipuan',
        paragraphs: [
          'Verifikasi melalui kanal resmi yang kamu cari sendiri, bukan melalui tautan atau nomor yang dikirim pelaku. Untuk transaksi, gunakan platform yang memiliki perlindungan pembeli dan simpan bukti percakapan.',
        ],
        bullets: [
          'Jangan mengirim uang sebelum identitas penerima terverifikasi.',
          'Bandingkan nomor rekening dengan data resmi penjual atau institusi.',
          'Diskusikan tawaran besar dengan orang lain sebelum memutuskan.',
        ],
      },
    ],
    takeaway:
      'Jika sebuah tawaran membutuhkan keputusan cepat, pembayaran di muka, atau data sensitif, anggap itu sebagai alarm—bukan peluang.',
  },
  {
    slug: 'langkah-aman-sebelum-menklik',
    title: 'Langkah aman sebelum mengeklik tautan',
    summary:
      'Tiga puluh detik untuk memeriksa alamat tautan bisa mencegah pencurian akun. Ini urutan pemeriksaan yang bisa kamu lakukan tanpa alat tambahan.',
    readTime: '3 menit baca',
    intro:
      'Sebagian besar serangan phishing bergantung pada satu klik. Membiasakan pemeriksaan singkat sebelum membuka tautan adalah pertahanan paling murah dan efektif.',
    sections: [
      {
        heading: 'Periksa alamatnya, bukan tampilannya',
        paragraphs: [
          'Tautan bisa menampilkan teks apa pun. Yang menentukan tujuan adalah alamat yang muncul setelah kamu menekan dan menahannya, atau setelah menyalinnya ke bilah alamat.',
          'Baca dari kanan ke kiri pada bagian domain. Pada “login.instagram.akun-aman.com”, domain utamanya adalah “akun-aman.com”, bukan Instagram.',
        ],
        bullets: [
          'Pastikan domain resmi, bukan sekadar memuat nama merek.',
          'Waspadai karakter pengganti seperti angka “1” untuk huruf “l”.',
          'Hindari tautan yang memakai pemendek seperti bit.ly tanpa kejelasan tujuan.',
        ],
      },
      {
        heading: 'Jangan lanjutkan jika diminta data sensitif',
        paragraphs: [
          'Halaman login palsu akan meminta kata sandi, PIN, kode OTP, atau data kartu. Layanan resmi tidak meminta kode OTP melalui halaman yang dibuka dari pesan.',
          'Jika kamu sudah terlanjur mengisi data, segera ganti kata sandi dari perangkat yang tepercaya dan hubungi layanan resmi. Aktifkan verifikasi dua langkah bila belum.',
        ],
      },
      {
        heading: 'Biasakan jalur yang aman',
        paragraphs: [
          'Untuk layanan yang sering kamu gunakan, buka melalui bookmark atau aplikasi resmi. Kebiasaan ini menghilangkan ketergantungan pada tautan yang dikirim orang lain.',
        ],
        bullets: [
          'Simpan alamat situs resmi di bookmark.',
          'Gunakan aplikasi resmi untuk transaksi dan perbankan.',
          'Perbarui perangkat dan peramban agar proteksi tetap aktif.',
        ],
      },
    ],
    takeaway:
      'Tahan klik, baca domain sebenarnya, dan jangan pernah menyerahkan OTP. Jika ragu, tutup tautan dan cari layanan resminya sendiri.',
  },
  {
    slug: 'otp-dan-verifikasi-dua-langkah',
    title: 'OTP dan verifikasi dua langkah: siapa yang boleh memintanya',
    summary:
      'Kode OTP adalah kunci sementara untuk akunmu. Memahami siapa yang boleh memintanya membantu mencegah pembajakan akun tanpa rasa panik.',
    readTime: '4 menit baca',
    intro:
      'Kode OTP dibuat untuk membuktikan bahwa kamu memegang perangkat atau nomor yang terdaftar. Karena itu, kode tersebut tidak boleh dibagikan kepada siapa pun, termasuk orang yang mengaku sebagai petugas resmi.',
    sections: [
      {
        heading: 'OTP adalah kunci, bukan bukti identitas',
        paragraphs: [
          'Saat kamu memasukkan kata sandi, layanan dapat mengirim kode tambahan sebagai lapisan keamanan. Kode itu hanya berguna jika tetap berada di tanganmu. Siapa pun yang memilikinya dapat menyelesaikan proses masuk dalam waktu singkat.',
          'Layanan resmi tidak akan meminta kamu meneruskan kode melalui chat, telepon, atau formulir baru. Jika seseorang meminta kode dengan alasan verifikasi, pembatalan transaksi, atau pengecekan akun, hentikan percakapan.',
        ],
        bullets: [
          'Jangan mengirim OTP lewat chat, email, atau tangkapan layar.',
          'Jangan memasukkan OTP pada halaman yang dibuka dari tautan pesan.',
          'Jangan membacakan kode kepada siapa pun yang menelepon lebih dulu.',
        ],
      },
      {
        heading: 'Bedakan proses masuk yang kamu mulai sendiri',
        paragraphs: [
          'Ada perbedaan penting antara kode yang kamu minta saat masuk ke aplikasi resmi dan kode yang diminta orang lain. Pada kasus pertama, kamu yang membuka aplikasi atau situs resmi dan memasukkan kode di sana.',
          'Pada kasus kedua, orang lain mendorongmu untuk bertindak cepat. Pola ini sering dipakai untuk mengambil alih akun, mengubah kata sandi, atau menyetujui transaksi.',
        ],
      },
      {
        heading: 'Perkuat akun dengan dua langkah',
        paragraphs: [
          'Aktifkan verifikasi dua langkah pada layanan penting. Aplikasi autentikator atau kunci keamanan fisik umumnya lebih tahan terhadap penyadapan dibanding kode SMS, meskipun SMS tetap lebih baik daripada tidak ada lapisan tambahan.',
          'Simpan kode pemulihan di tempat aman, bukan di percakapan atau catatan yang dapat dibaca orang lain. Jika kamu sudah terlanjur membagikan OTP, segera ganti kata sandi dan akhiri sesi yang tidak dikenal melalui pengaturan keamanan layanan.',
        ],
        bullets: [
          'Gunakan aplikasi autentikator untuk akun utama.',
          'Periksa perangkat dan sesi yang sedang masuk secara berkala.',
          'Jangan gunakan satu kode pemulihan untuk beberapa akun.',
        ],
      },
    ],
    takeaway:
      'OTP hanya untuk kamu masukkan sendiri di layanan resmi. Tidak ada petugas sah yang perlu mendengar atau menerima kode itu.',
  },
  {
    slug: 'kata-sandi-yang-kuat',
    title: 'Kata sandi yang kuat tidak harus sulit diingat',
    summary:
      'Kata sandi unik dan panjang lebih efektif daripada sandi rumit yang dipakai ulang. Pengelola kata sandi membantu tanpa harus menghafal semuanya.',
    readTime: '4 menit baca',
    intro:
      'Kebiasaan berbahaya bukan hanya memakai kata sandi yang pendek, tetapi memakai kata sandi yang sama di banyak layanan. Jika satu layanan bocor, pelaku dapat mencoba kombinasi yang sama di akun lain.',
    sections: [
      {
        heading: 'Panjang dan unik lebih penting',
        paragraphs: [
          'Gunakan kata sandi yang panjang dan tidak dipakai ulang. Ungkapan beberapa kata yang mudah kamu ingat dapat lebih kuat daripada satu kata pendek dengan simbol acak. Yang penting, frasa tersebut tidak umum dan tidak berkaitan dengan data yang mudah ditebak.',
          'Hindari nama lengkap, tanggal lahir, nomor telepon, nama hewan peliharaan, atau pola seperti “123456” dan “password”. Informasi semacam ini sering tersedia di media sosial atau sudah ada dalam daftar kebocoran.',
        ],
        bullets: [
          'Buat kata sandi berbeda untuk setiap akun penting.',
          'Utamakan panjang minimal 12 karakter atau frasa sandi.',
          'Jangan menambahkan satu angka di akhir untuk membuat sandi “baru”.',
        ],
      },
      {
        heading: 'Gunakan pengelola kata sandi',
        paragraphs: [
          'Pengelola kata sandi menghasilkan dan menyimpan kata sandi acak untuk setiap akun. Kamu hanya perlu mengingat satu kata sandi utama yang kuat. Aktifkan verifikasi dua langkah pada pengelola tersebut agar perlindungannya berlapis.',
          'Kata sandi utama jangan disimpan di dokumen biasa atau dikirim ke diri sendiri melalui chat. Jika perangkat dipakai bersama, kunci perangkat dan keluar dari akun pengelola saat tidak digunakan.',
        ],
      },
      {
        heading: 'Jika akun pernah terdampak',
        paragraphs: [
          'Ganti kata sandi dari perangkat yang tepercaya, lalu akhiri semua sesi yang tidak dikenal. Periksa alamat email pemulihan, nomor telepon, dan metode verifikasi dua langkah untuk memastikan tidak ada perubahan yang tidak kamu lakukan.',
          'Jika kata sandi yang sama dipakai di layanan lain, segera ganti juga di sana. Mengganti satu akun saja tidak cukup apabila sandinya dipakai ulang.',
        ],
        bullets: [
          'Periksa sesi aktif dan perangkat yang masuk.',
          'Aktifkan notifikasi untuk aktivitas masuk yang tidak dikenal.',
          'Simpan kode pemulihan di tempat aman yang terpisah.',
        ],
      },
    ],
    takeaway:
      'Kata sandi yang baik itu panjang, unik, dan dikelola dengan alat yang tepat. Bukan yang paling rumit untuk diketik.',
  },
  {
    slug: 'waspada-investasi-dan-lowongan-kerja',
    title: 'Waspadai tawaran investasi dan kerja yang terlalu menguntungkan',
    summary:
      'Keuntungan pasti dan pendapatan cepat sering dipakai untuk menarik korban. Periksa pihak yang menawarkan, bukan hanya tampilan aplikasi atau testimoni.',
    readTime: '5 menit baca',
    intro:
      'Penipuan investasi dan lowongan kerja memakai harapan yang wajar: ingin penghasilan tambahan atau masa depan lebih baik. Pelaku memanfaatkan harapan itu dengan janji yang terdengar meyakinkan.',
    sections: [
      {
        heading: 'Janji keuntungan pasti adalah tanda bahaya',
        paragraphs: [
          'Investasi yang sah memiliki risiko. Tidak ada pihak yang dapat menjamin keuntungan tetap, apalagi dalam waktu singkat. Grafik yang selalu naik, testimoni yang seragam, dan tekanan untuk menambah dana adalah pola yang perlu diwaspadai.',
          'Sebelum menyetor dana, pastikan pihak yang menawarkan memiliki izin dan identitas yang dapat diverifikasi melalui kanal resmi. Jangan hanya mengandalkan tautan, aplikasi, atau grup chat yang dikirim oleh penawarnya.',
        ],
        bullets: [
          'Jangan menyetor uang karena takut kehilangan “slot” atau bonus waktu terbatas.',
          'Periksa nama perusahaan dan izinnya melalui sumber resmi yang kamu cari sendiri.',
          'Waspadai permintaan transfer ke rekening pribadi atau dompet kripto tanpa kejelasan.',
        ],
      },
      {
        heading: 'Lowongan kerja yang meminta biaya',
        paragraphs: [
          'Lowongan yang sah tidak meminta pelamar membayar biaya pelatihan, deposit, atau jaminan sebelum bekerja. Permintaan uang, data rekening, atau transfer untuk “membeli peralatan” adalah alasan untuk berhenti.',
          'Tawaran kerja yang meminta kamu menerima dan memindahkan uang orang lain juga berisiko menjadikanmu bagian dari aliran dana ilegal. Jangan lanjutkan meskipun imbalannya terlihat besar.',
        ],
        bullets: [
          'Periksa alamat email dan domain perusahaan, bukan hanya logo pada pesan.',
          'Jangan menyerahkan foto KTP atau data bank sebelum proses rekrutmen jelas.',
          'Wawancara yang hanya berlangsung di chat pribadi perlu diverifikasi ulang.',
        ],
      },
      {
        heading: 'Berhenti sebelum uang berpindah',
        paragraphs: [
          'Jika kamu sudah diminta membayar, jangan menambah setoran untuk “membuka penarikan”. Pola ini sering dipakai untuk mengambil uang sebanyak mungkin. Simpan bukti percakapan, hentikan komunikasi, dan laporkan ke penyedia platform atau pihak berwenang.',
          'Bicarakan tawaran besar dengan orang yang kamu percaya sebelum memutuskan. Penipuan sering meminta korban merahasiakan transaksi agar tidak mendapat pendapat kedua.',
        ],
        bullets: [
          'Jangan pernah mengejar kerugian dengan setoran baru.',
          'Simpan bukti transfer dan percakapan untuk pelaporan.',
          'Hubungi bank atau penyedia dompet secepat mungkin jika dana sudah dikirim.',
        ],
      },
    ],
    takeaway:
      'Tawaran yang menjanjikan hasil pasti sambil meminta uang di muka perlu diperiksa dari sumber resmi. Jangan biarkan tekanan waktu mengambil alih keputusanmu.',
  },
  {
    slug: 'jual-beli-online-yang-aman',
    title: 'Jual beli online dan kurir: kapan harus berhenti',
    summary:
      'Transaksi di luar platform, bukti transfer palsu, dan tautan biaya kurir adalah pola yang sering muncul. Kenali titik hentinya sebelum uang berpindah.',
    readTime: '4 menit baca',
    intro:
      'Transaksi jual beli yang nyaman tetap memiliki risiko. Sebagian besar penipuan tidak dimulai dengan permintaan yang mencurigakan, tetapi dengan percakapan ramah dan tawaran yang terasa masuk akal.',
    sections: [
      {
        heading: 'Tetap di dalam platform',
        paragraphs: [
          'Platform menyediakan perlindungan pembeli, riwayat transaksi, dan jalur sengketa. Pelaku sering meminta pembayaran melalui transfer pribadi dengan alasan biaya lebih murah atau proses lebih cepat. Setelah pembayaran keluar dari platform, pemulihan menjadi jauh lebih sulit.',
          'Jangan mengikuti instruksi pembayaran dari tautan yang dikirim penjual. Buka aplikasi atau situs resmi secara mandiri, lalu periksa status pesanan di sana.',
        ],
        bullets: [
          'Jangan bertransaksi melalui chat pribadi jika platform menyediakan pembayaran resmi.',
          'Jangan mengirim uang ke rekening yang berbeda dari nama toko atau penjual terverifikasi.',
          'Jangan mengunduh aplikasi dari tautan yang dikirim pembeli atau penjual.',
        ],
      },
      {
        heading: 'Bukti transfer bukan bukti dana masuk',
        paragraphs: [
          'Tangkapan layar dapat diedit. Periksa saldo dan mutasi rekening melalui aplikasi resmi bankmu, bukan melalui tautan yang dikirim pihak lain. Untuk penjual, jangan mengirim barang hanya karena menerima gambar bukti transfer.',
          'Pada modus kurir, pelaku dapat mengaku paket tertahan dan meminta biaya tambahan melalui tautan. Cek nomor resi dan status pengiriman melalui aplikasi kurir resmi yang kamu buka sendiri.',
        ],
      },
      {
        heading: 'Batasi data dan hentikan tekanan',
        paragraphs: [
          'Jangan berikan kode OTP, PIN, atau foto kartu kepada pembeli, penjual, maupun kurir. Data tersebut tidak diperlukan untuk menyelesaikan transaksi biasa. Jika lawan bicara menekan, mengancam, atau meminta keputusan segera, hentikan percakapan.',
          'Laporkan akun ke platform dan simpan bukti percakapan, nomor rekening, serta tautan yang digunakan. Jika dana sudah dikirim, hubungi bank dan platform secepat mungkin.',
        ],
        bullets: [
          'Gunakan fitur pembayaran yang memiliki perlindungan pembeli.',
          'Periksa mutasi rekening langsung di aplikasi bank resmi.',
          'Laporkan tautan atau akun mencurigakan melalui kanal resmi platform.',
        ],
      },
    ],
    takeaway:
      'Jangan keluar dari jalur resmi, jangan percaya bukti transfer berupa gambar, dan jangan pernah menyerahkan kode keamanan kepada lawan transaksi.',
  },
  {
    slug: 'melindungi-data-pribadi',
    title: 'Melindungi data pribadi dan memulihkan akun yang terdampak',
    summary:
      'Data pribadi memiliki nilai bagi pelaku. Membatasi data yang dibagikan dan menyiapkan langkah pemulihan membantu mengurangi dampak ketika terjadi masalah.',
    readTime: '5 menit baca',
    intro:
      'Perlindungan data pribadi bukan berarti menyembunyikan semuanya. Prinsipnya sederhana: bagikan data yang benar-benar diperlukan, kepada pihak yang jelas, melalui kanal yang dapat diverifikasi.',
    sections: [
      {
        heading: 'Kurangi data yang tidak perlu',
        paragraphs: [
          'Sebelum mengisi formulir atau mengunggah dokumen, tanyakan apakah data itu benar-benar diperlukan. Foto KTP, selfie dengan KTP, nomor kartu, dan data rekening adalah data sensitif yang tidak perlu diberikan untuk pendaftaran biasa.',
          'Periksa pengaturan privasi akun media sosial. Batasi siapa yang dapat melihat nomor telepon, alamat, tanggal lahir, dan daftar kontak. Informasi ini dapat dipakai untuk menebak kata sandi atau meyakinkan orang lain bahwa pelaku mengenalmu.',
        ],
        bullets: [
          'Berikan data hanya melalui situs atau aplikasi resmi.',
          'Jangan mengirim foto dokumen melalui chat biasa.',
          'Matikan izin aplikasi yang tidak diperlukan.',
        ],
      },
      {
        heading: 'Kenali jalur pemulihan akun',
        paragraphs: [
          'Pastikan alamat email dan nomor pemulihan masih aktif. Simpan kode pemulihan verifikasi dua langkah di tempat aman. Jika akun diambil alih, gunakan fitur pemulihan resmi dari layanan tersebut, bukan jasa pemulihan yang ditemukan melalui iklan.',
          'Untuk akun keuangan, hubungi bank atau penyedia layanan melalui nomor resmi yang tertera di aplikasi atau situs mereka. Jangan memakai nomor yang dikirim oleh orang yang mengaku membantu.',
        ],
      },
      {
        heading: 'Jika data atau akun terdampak',
        paragraphs: [
          'Segera ganti kata sandi dari perangkat yang tepercaya dan akhiri sesi yang tidak dikenal. Periksa perubahan alamat email, nomor telepon, atau metode pembayaran. Jika data keuangan terlibat, blokir kartu atau rekening yang berisiko dan pantau mutasi.',
          'Simpan bukti kejadian dan laporkan melalui kanal resmi yang relevan. Kejadian seperti ini bukan alasan untuk mempermalukan korban; tekanan sosial justru membuat orang menunda melapor dan memperbesar kerugian.',
        ],
        bullets: [
          'Ganti kata sandi akun yang terdampak dan akun lain yang memakai sandi sama.',
          'Cabut akses aplikasi atau sesi yang tidak dikenal.',
          'Laporkan ke platform, bank, atau pihak berwenang melalui kanal resmi.',
        ],
      },
    ],
    takeaway:
      'Batasi data yang dibagikan, siapkan jalur pemulihan, dan bertindak cepat melalui kanal resmi jika akun atau data terdampak.',
  },
]

export function getArticle(slug: string) {
  return articles.find((article) => article.slug === slug)
}

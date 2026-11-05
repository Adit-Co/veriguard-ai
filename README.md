# VERIGUARD AI

Platform AI-powered digital trust & fraud detection untuk hackathon cybersecurity (Defensive Shield).

## Status

Tahap **T1-T10** selesai pada tingkat kode. **T8** mencakup Authentication, Firestore per pengguna,
security rules, Hosting SPA, serta Cloud Functions + Gemini. **T9** menambahkan Community Reports
dengan dua jalur yang tidak boleh dicampur: jalur **Spark bawaan** (Firestore + Security Rules) dan
jalur **Cloud Functions opsional** untuk Blaze. Jalur Spark mencakup laporan append-only terpartisi
per hash URL, batas satu laporan per akun per hari WIB, konteks per URL tanpa enumerasi lintas URL,
Skor Reputasi, dan panel konteks pada halaman hasil. **T10** menambahkan scanner multi-sumber dengan persetujuan saat submit, deteksi
URL sensitif, enam adapter provider, streaming status per provider, laporan gabungan, dan
penyimpanan lokal. Proyek diarahkan ke
Firebase project `YOUR_FIREBASE_PROJECT_ID` dan Hosting site `YOUR_FIREBASE_PROJECT_ID`; web config tersedia di
`web/.env.local` yang tidak di-commit.

Model komunitas Spark memakai partisi publik per hash URL ditambah dokumen privat per akun dan feed
global terbatas `communityLatestReports/global` (maksimal 8 laporan) yang hanya dapat dibaca satu
dokumen per `get`, tanpa `collectionGroup` atau `list` lintas partisi. Seluruh model diuji pada
Firebase Emulator Suite (Auth + Firestore, tanpa Functions): 85 pemeriksaan matriks Security Rules
(lintas URL, lintas akun, tamu/anonim/unverified, append-only, dua permintaan serentak, dan
enumerasi), 69 pemeriksaan khusus feed global, 18 pemeriksaan regresi profil/scan, serta 57
pemeriksaan browser. Aturan feed di repo ini **belum di-deploy** dalam pengerjaan ini; laporan lama
tidak di-backfill ke feed dan tetap berada di partisi URL masing-masing. Project tetap memakai paket
**Spark** dan Cloud Functions API masih nonaktif; jalur Functions komunitas lama tidak dipakai dan
tidak diaktifkan kembali. Aplikasi tidak mengaktifkan billing dan tidak melakukan deploy otomatis.
Pemindaian URL berjalan tanpa login apa pun; hasil guest disimpan lokal. Firebase tetap dipakai
fitur akun (profil, riwayat cloud, Community Reports). Google Sign-In **belum diaktifkan**, sehingga
akun permanen memakai login email. Sesi demo lokal tetap ditandai jelas sebagai bukan autentikasi.

Analisis internal berjalan di browser. Kode scanner multi-sumber untuk URLScan.io, VirusTotal,
OpenPhish, ThreatFox, Cloudflare Radar URL Scanner, AlienVault OTX, dan Google Safe Browsing dijalankan oleh backend lokal Node di
`server/`; frontend memakai `VITE_API_BASE_URL`. Cloudflare Worker di `workers/` tetap tersedia
sebagai alternatif, sedangkan callable `scanUrlMultiSource` lama bukan fallback UI. Provider
eksternal hanya berjalan jika backend URL, key backend, dan
persetujuan pengguna tersedia. Live check lokal berhasil untuk URLScan.io, VirusTotal, ThreatFox,
OpenPhish, Cloudflare Radar URL Scanner, AlienVault OTX, dan Google Safe Browsing. VERIGUARD tidak membuka tautan;
provider eksternal dapat membukanya setelah pengguna menekan Periksa tautan. Gemini belum dipanggil
oleh UI. Laporan komunitas tidak otomatis mengubah skor dan bukan bukti bahwa suatu URL berbahaya.
Hasil rendah bukan jaminan aman.

## Stack

- React 19 + Vite 8 + TypeScript (strict)
- Tailwind CSS v4 (token via `@theme`) dan React Router 7
- Firebase Web SDK 12.19 (Auth + Firestore + Functions opsional)
- Firebase Functions v2 (Node.js 22) + Firebase Admin SDK untuk callable AI dan jalur Community Reports opsional (Blaze)
- Node.js 22+ local scanner backend (`server/`) dengan rate limit, CORS, validasi consent, dan penolakan URL privat — tanpa login
- Cloudflare Workers + Web Crypto sebagai backend scanner alternatif tanpa Blaze
- Gemini API via secret server-side
- Vitest, Playwright, dan axe-core
- Lucide React, Inter Variable (self-host)

## Menjalankan

Runbook lengkap Windows (prasyarat, dua terminal, port fallback, EADDRINUSE, troubleshooting,
nama variabel env) ada di [`docs/LOCAL_DEVELOPMENT.md`](docs/LOCAL_DEVELOPMENT.md).

Jalankan backend scanner dan frontend di dua terminal terpisah.

Terminal 1 - backend lokal:

```powershell
Set-Location C:\AI-Projects\veriguard-ai\server
npm install
Copy-Item .env.example .env   # hanya bila server/.env belum ada; jangan menimpa file yang sudah diisi
notepad.exe .env
npm run typecheck
npm test
npm run live-check -- https://example.com
npm run dev
```

Terminal 2 - frontend:

```powershell
Set-Location C:\AI-Projects\veriguard-ai\web
npm install
npm run dev
```

`server/.env` dan `web/.env.local` diabaikan Git. Isi `server/.env` dengan key provider; jangan
pernah memakai variabel `VITE_*` untuk key. Untuk memakai backend lokal, isi `web/.env.local`:

```text
VITE_API_BASE_URL=http://127.0.0.1:8787
```

`npm run dev` di folder `server/` melakukan build lalu menjalankan server di foreground. Hentikan
dengan `Ctrl+C`. Jangan menjalankan server jangka panjang dan rangkaian build/test dalam satu
perintah yang sama; gunakan dua terminal atau proses terpisah.

Untuk pengembangan lokal, origin `http://localhost:5173`-`5177` dan padanannya di `127.0.0.1`
selalu digabungkan ke `ALLOWED_ORIGINS` oleh `withLocalDevOrigins()` di `server/src/index.ts`.
Ini membuat fallback port Vite (mis. `5174` ketika `5173` sudah dipakai) tidak lagi ditolak `403`,
tanpa menimpa nilai `ALLOWED_ORIGINS` produksi Anda. Perilaku ini hanya ada di server lokal, tidak
di Worker produksi.

Root repo hanya punya skrip alias: `npm run dev:server`, `npm run dev:web`, `npm run build:*`,
`npm run test:*`. Skrip root `dev` memakai `&` yang tidak paralel di cmd/PowerShell, jadi gunakan
dua terminal. Perintah detail tetap disarankan dari folder `server/` dan `web/` agar log dan
kontrol proses jelas.

Perintah verifikasi frontend:

```bash
npm test
npm run typecheck
npm run lint
npm run build
npm run verify:ui
npm run test:e2e
```

Perintah verifikasi functions:

```bash
cd functions
npm install
npm run build
npm run typecheck
npm test
npm audit
```

Perintah verifikasi backend lokal:

```powershell
Set-Location C:\AI-Projects\veriguard-ai\server
npm run build
npm run typecheck
npm test
npm run live-check -- https://example.com
```

Hasil verifikasi terakhir (2026-10-25):

- 345 unit test frontend (43 berkas), 39 unit test backend lokal, dan 27 unit test Cloudflare Worker
  lulus.
- 435 pemeriksaan UI dan 217 pemeriksaan E2E QA lulus.
- 85/85 pemeriksaan matriks Security Rules Spark, 69/69 pemeriksaan feed global, 18/18 regresi
  profil/scan, dan 57/57 pemeriksaan browser Spark lulus.
- Typecheck, lint (0 warning/0 error), dan build frontend lulus; inspeksi bundle memeriksa 36 berkas
  dan tidak menemukan endpoint API host lokal.
- Build dan unit test Functions **tidak dijalankan ulang** pada fase ini dan harus dianggap belum
  terverifikasi. Jalur Functions tidak dipakai UI dan tidak diaktifkan kembali.

`verify:ui` dan `test:e2e` membangun ulang bundle dengan mode `verify`, konfigurasi Firebase
dikosongkan, dan endpoint eksternal kosong agar alur demo deterministik. Build produksi
(`npm run build`) menghentikan build bila endpoint hilang, memakai HTTP, mengarah ke
localhost/loopback, atau mengaktifkan emulator; setelah itu `scripts/inspect-bundle.mjs` memindai
artefak dan gagal bila menemukan host lokal. Build deployment tetap memakai env produksi melalui
predeploy Hosting.

## Konfigurasi Firebase

Firebase dianggap aktif hanya jika `VITE_FIREBASE_API_KEY`, `VITE_FIREBASE_AUTH_DOMAIN`,
`VITE_FIREBASE_PROJECT_ID`, dan `VITE_FIREBASE_APP_ID` terisi. Jika salah satu kosong, aplikasi
memakai sesi demo lokal dan tidak menginisialisasi Firebase.

Konfigurasi saat ini:

- `.firebaserc` memakai project default `YOUR_FIREBASE_PROJECT_ID`.
- Hosting site: `YOUR_FIREBASE_PROJECT_ID` (`https://YOUR_FIREBASE_PROJECT_ID.web.app`).
- Web app: `VERIGUARD AI`, dengan config publik di `web/.env.local`.
- Firestore database `(default)` mode production terdeteksi ada.
- Authentication Email/Password dilaporkan aktif; uji satu akun masih diperlukan.
- Build Hosting memakai `web/dist`.
- Scanner multi-sumber aktif secara default; set `VITE_MULTI_SOURCE_ENABLED=false` untuk
  menonaktifkan pemeriksaan eksternal pada build tertentu. Endpoint dipisah per mode:
  `.env.development.local` memakai backend lokal `http://127.0.0.1:8787`, sedangkan build produksi
  memakai `VITE_SCANNER_WORKER_URL` HTTPS non-lokal dari `.env.production.local`. Tidak ada endpoint
  lokal bawaan di kode, dan build produksi gagal bila endpoint tidak diisi atau tidak aman.
  Key provider hanya dibaca backend dari `URLSCAN_API_KEY`, `VIRUSTOTAL_API_KEY`,
  `THREATFOX_API_KEY`, `OTX_API_KEY`, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, dan
  opsional `OPENPHISH_API_KEY`; tidak ada key di repo. Backend lokal memiliki keenam kredensial
  tersebut dan seluruh provider lolos live check. Pemeriksaan URL OpenPhish bersifat publik tanpa
  kunci; `OPENPHISH_API_KEY` hanya diteruskan sebagai header bila diisi.
- CAPTCHA adaptif Cloudflare Turnstile: `VITE_TURNSTILE_SITE_KEY` (kunci situs mode Managed, publik)
  di frontend dan `TURNSTILE_SECRET_KEY` (secret siteverify, backend only) di `server/.env`.
  Pendaftaran selalu diverifikasi; pemeriksaan URL hanya meminta CAPTCHA ketika pemakai sudah lewat
  separuh batas permintaan per IP (`RATE_LIMIT_MAX_PER_IP`), jadi pemeriksaan normal tidak pernah
  menampilkan CAPTCHA. Pendaftaran tidak punya jalur tanpa CAPTCHA: bila kunci situs atau layanan
  verifikasi belum tersedia, formulir berhenti dengan pesan konfigurasi dan backend menjawab
  `503 captcha_not_configured`. Pemeriksaan URL tetap mengikuti gerbang adaptif di atas.

Langkah manual yang masih diperlukan:

1. Pemindaian URL tidak lagi memakai Firebase Authentication, sehingga Anonymous Auth tidak wajib
   untuk scan. Aktifkan Anonymous hanya bila fitur lain membutuhkan sesi tamu. Atur
   **Authentication > Settings > Authorized domains** untuk `localhost`,
   `YOUR_FIREBASE_PROJECT_ID.firebaseapp.com`, dan `YOUR_FIREBASE_PROJECT_ID.web.app`.
2. Arahkan action URL template verifikasi email ke
   `https://YOUR_FIREBASE_PROJECT_ID.web.app/verifikasi-email` agar `mode` dan `oobCode` diproses
   aplikasi. Reset kata sandi tetap memakai halaman penanganan Firebase sampai alur reset khusus
   dibuat.
3. Project tetap di Spark. Jangan mengaktifkan Blaze tanpa persetujuan eksplisit pemilik proyek.
   Jalur Community Reports **bawaan** memakai Firestore + Security Rules dan tidak memerlukan
   Functions. Cloud Functions hanya diperlukan untuk AI, moderasi/retensi komunitas, dan callable
   lama; scanner eksternal dapat memakai backend lokal atau Cloudflare Worker tanpa Blaze.
4. Backend lokal membaca key dari `server/.env`; Worker membaca secret dari Cloudflare.
   `OTX_API_KEY`, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, dan `OPENPHISH_API_KEY` sudah
   diisi di `server/.env` lokal (tidak di-commit). Jangan
   memakai variabel `VITE_*` untuk key. Jika dan hanya jika upgrade Blaze disetujui, key provider
   juga dapat diisi pada environment Functions untuk callable lama.
5. Opsional: aktifkan Google provider sebelum menambahkan Google Sign-In. Jangan mengaktifkan UI
   Google selama provider masih mengembalikan `OPERATION_NOT_ALLOWED`.
6. Opsional: daftarkan App Check reCAPTCHA v3 dan isi `VITE_RECAPTCHA_SITE_KEY`. Enforcement harus
   diaktifkan manual setelah client berhasil mengirim token.
7. Moderasi admin hanya tersedia pada jalur Functions; berikan custom claim `admin: true` hanya
   kepada akun admin melalui Admin SDK. Callable `reviewCommunityReport` menolak akun tanpa claim
   tersebut. Jalur Spark tidak memiliki moderasi server dan menampilkan status "belum diverifikasi
   moderator".
8. Model komunitas Spark tidak membutuhkan composite/collection-group index; konteks hanya
   menyentuh satu partisi `communityReports/{urlHash}/reports` dengan single-field index otomatis,
   dan feed global hanya melakukan `get` langsung ke head serta entri, sehingga
   `firestore.indexes.json` tetap kosong. Indeks communityReports lama yang mungkin masih ada di
   produksi tidak dipakai kode baru; jangan menghapusnya tanpa persetujuan. Rules produksi memuat
   model Spark yang ada, sedangkan **aturan feed global di repo ini belum di-deploy** dan harus
   dideploy sebelum client baru. Tidak ada migrasi/backfill data. Deploy Hosting terpisah setelah
   build diverifikasi; deploy Functions hanya setelah Blaze disetujui.
9. Uji manual dengan satu akun: masuk, periksa satu tautan, lalu buka Firebase Console dan pastikan
   `users/{uid}` berisi `uid`, `email`, `displayName`, `createdAt`, dan `lastLoginAt`, serta
   `users/{uid}/scans/{scanId}` berisi scan tersebut. Login ulang dan pastikan `createdAt` profil
   tidak berubah serta riwayat tetap muncul.

Jangan menaruh `GEMINI_API_KEY`, service account, atau secret lain di `web/.env*` atau variabel
`VITE_*`. Web config Firebase memang publik; secret AI tidak.

### Emulator

```bash
firebase emulators:start --only auth,firestore --project demo-veriguard-rules
```

Isi URL emulator secara eksplisit, mis. `VITE_AUTH_EMULATOR_URL=http://127.0.0.1:9099`,
`VITE_FIRESTORE_EMULATOR_HOST=127.0.0.1:8082`, lalu jalankan **`npm run dev:emulators`** (VGL-42).
Bendera `VITE_USE_EMULATORS` di berkas `.env` saja tidak lagi mengaktifkan emulator pada dev server:
yang membukanya adalah proses peluncur, supaya login normal tidak pernah senyap dialihkan ke instance
emulator yang datanya kosong. `npm run dev` biasa selalu memakai Firebase Authentication asli sesuai
`VITE_FIREBASE_*`. Tidak ada default localhost yang tertanam di kode; nilai emulator hanya dibaca pada
mode development dan diabaikan pada build produksi. Port default Auth `9099` dan Firestore `8080`; lab
rules repo memakai `8082`. Community Reports jalur Spark tidak membutuhkan Functions. Scanner eksternal
memakai backend lokal; tanpa key, provider ditampilkan `not_configured` dan tidak dipanggil.

## Model data dan autentikasi

- Profil: `users/{uid}` dengan `uid`, `email` (boleh `null`), `displayName`, `username`, `createdAt`,
  dan `lastLoginAt`. Profil disinkronkan setelah sesi Firebase pulih atau login; `createdAt`
  dipertahankan dan `lastLoginAt` diperbarui. Tidak ada kata sandi atau token di dokumen ini.
- Username: registry keunikan `usernames/{username}` berisi `uid` dan `createdAt`, ditambah pointer
  milik akun `users/{uid}/username/current` berisi `username`, `uid`, dan `createdAt`. Nama
  dinormalisasi ke huruf kecil dengan 3–20 karakter `a–z`, `0–9`, dan `_`. Klaim dibuat dalam satu
  transaksi Firestore pada saat pendaftaran (sebelum email terverifikasi); aturan hanya mengizinkan
  `create`, tidak pernah `update` atau `delete`, sehingga nama yang sudah dipakai ditolak dan klaim
  lama tidak dapat dirampas. Nilai `username` pada profil hanyalah salinan baca-cepat; sumber
  kebenaran tetap pointer klaim.
- Bila klaim username gagal, akun yang baru saja dibuat dan belum dipakai dihapus kembali. Jika
  penghapusan itu sendiri tidak mungkin (misalnya galat jaringan), sesi ditutup dan pengguna
  diarahkan masuk ulang lalu memasang username di Pengaturan; tidak ada akun atau klaim orang lain
  yang dihapus.
- Jika sinkronisasi profil gagal, dashboard dan pengaturan menampilkan status kegagalan serta
  tombol coba ulang. Kegagalan profil tidak mengubah sesi Auth menjadi berhasil secara palsu.
- Dokumen scan: `users/{uid}/scans/{scanId}` dengan field `ownerId`.
- Maksimal 30 scan dimuat dan diurutkan berdasarkan `createdAt` menurun.
- Security rules bersifat default-deny. Profil hanya dapat dibaca lewat `get` oleh pemilik yang
  email-nya sudah terkonfirmasi (`isOwner` + `isVerifiedEmailUser`) dan divalidasi ketat saat
  dibuat/diperbarui; scan hanya dapat diakses pemilik terverifikasi; daftar profil tidak diizinkan.
  Subkoleksi memiliki aturan eksplisit sendiri. Dokumen `usernames/{username}` hanya dapat dibaca
  oleh pemiliknya (`resource.data.uid == request.auth.uid`), tidak dapat didaftar, diubah, atau
  dihapus; penulisan ke nama milik orang lain ditolak aturan, dan karena klien tidak pernah membaca
  registry milik akun lain, pemeriksaan ketersediaan tidak dapat dipakai untuk enumerasi akun.
- Pengguna Firebase yang masuk dan sudah terverifikasi menyimpan hasil ke Firestore. Tamu, sesi
  anonim, dan akun yang belum terverifikasi memakai localStorage di perangkat ini saja.
- Laporan multi-sumber disimpan lokal di `veriguard.multiSourceReports.v1` dan tidak menambah field
  pada dokumen scan Firestore. Laporan lokal tidak tersinkron ke perangkat lain; hasil scan tetap
  dapat dibuka tanpa rincian provider jika laporan lokal tidak ada.
- Registrasi mengirim verifikasi email lalu mengarahkan ke `/verifikasi-email`; halaman masuk
  mengarahkan akun yang belum terverifikasi ke halaman yang sama. Pengguna dapat memeriksa status,
  mengirim ulang dengan cooldown, memproses tautan verifikasi dari tab/perangkat lain tanpa login
  ulang, dan keluar dengan aman. Gerbang rute `RequireVerifiedEmail` memaksa ulang status
  `emailVerified` dari Firebase Auth dan mengalihkan `/periksa`, `/hasil/:id`, `/komunitas`,
  `/riwayat`, `/dashboard`, `/dashboard/admin` ke halaman verifikasi selama email belum
  dikonfirmasi; tidak ada tautan "lanjut tanpa verifikasi".
- Header reaktif terhadap sesi Firebase: menu akun hanya tampil setelah login, sedangkan tautan
  Masuk/Daftar disembunyikan. Saat sesi dipulihkan, header menampilkan placeholder agar tombol
  autentikasi tidak berkedip.
- Sesi demo lokal hanya dipakai saat Firebase belum dikonfigurasi dan tidak menyinkronkan data.

### Community Reports

Build produksi hanya menerima jalur **Spark** (`VITE_COMMUNITY_BACKEND=firestore`); nilai backend
lain menggagalkan build. Jalur Cloud Functions lama tetap tersimpan di `functions/` untuk referensi
Blaze, tetapi tidak dipakai UI dan tidak diaktifkan kembali.

**Model data Spark (bawaan, tanpa Blaze):**

- Laporan publik: `communityReports/{urlHash}/reports/{reportId}`. `urlHash` adalah 64 heksadesimal
  lowercase hasil SHA-256 URL ternormalisasi; `reportId` adalah 32 heksadesimal acak. Dokumen hanya
  berisi `reporterKey`, `userName`, `category`, `reason`, `createdAt`, dan `updatedAt`. Tidak ada
  UID, email, URL mentah, atau hostname di dokumen publik.
- Dokumen privat: `users/{uid}/communityReportDays/{dayId}` menegakkan satu laporan per akun per
  hari WIB (UTC+7), dan `users/{uid}/communityReporterKeys/{urlHash}` menyimpan pseudonim acak
  64 heksadesimal per akun per URL. Keduanya dapat dibaca pemilik yang emailnya terverifikasi dan
  tidak dapat diubah/dihapus.
- Feed global: `communityLatestReports/global` menyimpan `entries` berisi maksimal 8 `reportId`
  terbaru (urutan baru → lama) dan `updatedAt`. Setiap ID merujuk ke
  `communityLatestReports/global/entries/{reportId}` yang hanya berisi `reporterKey`, `userName`,
  `category`, `reason`, dan `createdAt`. Tidak ada UID, email, URL mentah, hostname, hash URL, atau
  data moderasi. Entri hanya dapat dibaca satu per satu dengan `get`; `list` dan
  `collectionGroup` ditolak, sehingga feed tidak menjadi pintu enumerasi.
- Feed bergulir berdasarkan jumlah, bukan umur: saat laporan kesembilan masuk, ID terlama keluar
  dari `entries`. Laporan aslinya **tidak dihapus** dari partisi URL dan tetap dapat dibaca dengan
  hash yang diketahui. Tidak ada filter 24 jam dan tidak ada backfill laporan lama.
- Pembuatan laporan bersifat atomik: rules mewajibkan laporan publik, penanda hari, kunci pseudonim,
  entri feed, dan pergeseran head feed dibuat dalam commit yang sama dengan
  `existsAfter`/`getAfter`, dengan `ownerId`, `reportId`, `urlHash`, `reporterKey`, kategori, dan
  waktu yang saling cocok. Laporan tanpa penanda, penanda tanpa laporan, entri feed tanpa laporan
  yang cocok, atau head yang tidak bergeser tepat satu entri ditolak.
- Skema publik divalidasi ketat: field persis, kategori dari daftar, alasan 20–500 karakter,
  `createdAt`/`updatedAt` sama dengan `request.time` server, dan nama pelapor berbentuk label
  netral atau berakhiran `(sensor)`. Timestamp klien tidak dipercaya.
- Laporan, penanda, kunci, dan entri feed hanya `create`; update dan delete ditolak, termasuk pada
  penanda dan kunci. Satu-satunya operasi ubah adalah `update` sempit pada head feed untuk
  menggeser daftar, dengan syarat head lama harus tetap utuh dan head baru menambah tepat satu
  entri di depan. Batas harian tidak dapat dilewati dengan tanggal klien atau permintaan
  serentak: ID penanda adalah hari WIB dari `request.time`, dan dua transaksi bersamaan berebut
  dokumen yang sama. Klien memetakan benturan tersebut ke pesan batas harian yang baku.
- Baca publik hanya diizinkan untuk akun email terverifikasi pada subkoleksi `reports` dengan
  `urlHash` yang valid. Root `communityReports/{urlHash}` menolak baca/tulis, sehingga URL hash
  tidak dapat dienumerasi lewat root atau path langsung. Tidak ada aturan collection-group untuk
  `reports`, sehingga query lintas URL ditolak. Akun terverifikasi tetap dapat membaca partisi URL
  lain bila hash-nya sudah diketahui; ini memang sifat data publik per URL, bukan izin enumerasi.
- Feed global juga hanya untuk akun email terverifikasi: head dan entri hanya `get` (bukan `list`),
  `list` pada `communityLatestReports/global` ditolak, dan tidak ada aturan collection-group untuk
  `entries`. Klien hanya dapat menemukan entri yang ID-nya tercantum di head.
- Tamu, sesi anonim, dan email belum terverifikasi ditolak untuk baca maupun tulis. Pengguna tidak
  dapat mengubah/menghapus laporan akun lain, memalsukan pemilik, timestamp, atau kategori di luar
  skema. Koleksi internal `communitySummaries`, `communityRateLimits`, dan
  `communityModerationAudit` ditolak untuk semua klien. Jalur lama `users/{uid}/communityReports`
  juga ditutup.
- **Batas integritas hash:** rules tidak dapat menghitung SHA-256 atau menormalkan URL. Hash adalah
  kunci partisi yang dibuat klien, bukan bukti kriptografis bahwa laporan berasal dari URL tertentu.
  Klien yang bermaksud buruk dapat memilih hash lain, dan variasi normalisasi dapat memecah laporan
  untuk URL yang sama. Model ini membatasi akses baca per partisi, bukan memverifikasi identitas URL.
- **Batas pseudonim:** `reporterKey` terlihat pada laporan publik dan dapat disalin akun lain ke
  kunci pseudonimnya sendiri. Karena itu `reporterCount` adalah heuristik berbasis pseudonim, bukan
  jumlah akun unik yang terjamin. UI menyatakan keterbatasan ini.
- Nama pelapor disamarkan di UI dengan mempertahankan maksimal lima grapheme dan akhiran
  `(sensor)`, mis. `anaksigma` → `anaks(sensor)`, serta tidak pernah menampilkan email atau UID.
  Penyamaran hanya perlindungan tampilan; kontrol akses tetap dilakukan Security Rules.
- **Baca dan cache:** konteks memakai count aggregation lebih dulu (1 read bila kosong), lalu
  maksimal 300 laporan terbaru dari satu partisi plus satu dokumen kunci privat (maksimal sekitar
  302 read untuk partisi berisi). Daftar “Laporan terbaru” tidak membutuhkan URL: satu `get` head
  dan maksimal 8 `get` entri (9 read) untuk seluruh feed global. Hasil di-cache 30 detik (maksimal
  32 entri) dengan deduplikasi permintaan yang sedang berjalan; tombol “Muat ulang” memaksa
  pembacaan baru tanpa menggandakan permintaan yang masih berjalan. Bila pemindaian 300 dokumen
  tidak lengkap, `aggregatesComplete=false` dan Skor Reputasi tidak ditampilkan; angka tidak
  dikarang. Batas ini menjaga biaya Spark tetap terbatas dan tidak mengubah Skor Indikasi Internal.
- **Batas feed Spark:** feed hanya berisi laporan yang dikirim klien versi ini; klien lama tetap
  dapat mengirim laporan tetapi tidak menulis feed, dan laporan lama tidak di-backfill. Head global
  adalah dokumen panas: setiap kiriman bersamaan memperebutkan head yang sama sehingga satu
  transaksi dapat gagal dengan pesan bentrok dan perlu dicoba lagi; tidak ada retry otomatis.
  Feed menampilkan maksimal 8 laporan dan tidak menyediakan halaman berikutnya.
- Moderasi, status tinjauan, retensi otomatis, dan pemeriksaan DNS tidak tersedia di jalur Spark.
  Laporan bersifat append-only; penghapusan hanya dapat dilakukan lewat alat admin terkontrol di
  luar aplikasi (belum disediakan). UI menyebut laporan belum diverifikasi moderator.
- **Skor Reputasi** (0–100) dihitung terpisah dari Skor Indikasi Internal: bobot pseudonim pelapor
  (`reporterCount`, maksimal lima), kebaruan laporan, kategori berdampak tinggi, dan status
  moderasi. Jumlah kiriman akun yang sama tidak menambah bobot bila pseudonimnya sama. Tanpa
  laporan aktif atau tanpa agregat lengkap, skor tidak ditampilkan (bukan 0). Rumusnya
  `clamp(0, 100, min(reporterCount, 5) × 8 + recency + highImpact + moderation)`, dengan
  `recency` 10/6/2 untuk laporan terbaru ≤30/≤90/>90 hari, `highImpact` 4/0, dan `moderation`
  +35/+10/0/−20 untuk `verified_malicious`/`under_review`/`community_reported`/`cleared`.

**Kesalahan dan privasi operasional:** layanan memetakan `permission-denied`, email belum
terverifikasi, `unauthenticated`, `unavailable`, `deadline-exceeded`, `failed-precondition`
(index/konfigurasi), `resource-exhausted` (kuota), `invalid-argument`, dan benturan batas harian ke
pesan yang berbeda. Log hanya menulis operasi dan kode error, tanpa email, UID, token, URL, atau isi
laporan. Refresh token sekali dilakukan pada penolakan permission yang dapat diperbarui, tanpa
retry storm.

**Jalur Functions opsional (Blaze, tidak dipakai):**

- Koleksi `communitySummaries`, `communityRateLimits`, dan `communityModerationAudit` hanya ditulis
  dan dibaca backend tepercaya; rules menutup akses klien.
- Callable `submitCommunityReport`, `getCommunityContext`, dan `listCommunityReports` melakukan
  validasi serta agregasi di server. `reviewCommunityReport` menyediakan moderasi admin, dan
  `communityReportRetentionCleanup` menjalankan retensi berbasis DNS. Jalur ini memerlukan Blaze,
  Cloud Scheduler, dan deploy Functions; tidak aktif pada project saat ini, tidak dipakai UI, dan
  tidak diaktifkan kembali.

Laporan komunitas tidak mengubah skor heuristik, verdict, atau hasil delapan agen. Status “belum ada
laporan” bukan jaminan aman.

## Cloud Functions

Folder `functions/` tetap tersedia untuk callable AI dan jalur Community Reports opsional. Paket
Spark tidak dapat menjalankannya. UI default memakai jalur Spark (Firestore + Security Rules) dan
tidak memanggil callable komunitas, sehingga Community Reports tetap berjalan tanpa Functions.
Selama project belum diupgrade secara eksplisit ke Blaze, callable AI dan jalur Functions komunitas
harus dianggap belum tersedia.

`functions/src/index.ts` menyediakan:

- `analyzeContent`: callable terautentikasi, region `asia-southeast2`, memvalidasi mode/panjang
  input, tidak membuka tautan, memakai prompt defensif, dan meminta JSON terstruktur dari Gemini.
- `healthCheck`: callable terautentikasi untuk smoke test deployment.
- `submitCommunityReport` (jalur functions): callable terautentikasi (sesi anonim ditolak);
  memvalidasi URL, kategori, dan alasan, lalu menulis laporan append-only, agregat, dan kuota
  harian dalam satu transaksi dengan stempel waktu server.
- `getCommunityContext` (jalur functions): callable terautentikasi (sesi anonim dan akun belum
  verifikasi email ditolak); konteks satu URL ternormalisasi berisi agregat, laporan terbaru milik
  pemanggil, dan laporan nyata dari akun lain untuk URL yang sama.
- `listCommunityReports` (jalur functions): callable terautentikasi dengan gerbang yang sama;
  laporan nyata dari rolling 24 jam terakhir, terbaru lebih dulu.
- `reviewCommunityReport` (jalur functions): admin-only; mengubah status moderasi dan menulis audit
  privat.
- `communityReportRetentionCleanup` (jalur functions): terjadwal harian; menghapus laporan tua
  hanya setelah ketidakhidupan host dikonfirmasi berulang. Memerlukan Cloud Scheduler dan paket
  Blaze.
- `scanUrlMultiSource`: callable terautentikasi dengan persetujuan eksplisit; memvalidasi URL,
  mendeteksi URL sensitif, menerapkan rate limit, dan menjalankan adapter URLScan.io, VirusTotal,
  OpenPhish, ThreatFox, Cloudflare Radar URL Scanner, AlienVault OTX, serta Google Safe Browsing. Status per provider:
  `success`, `not_found`, `not_configured`, `auth_failed`, `unavailable`, `rate_limited`,
  `skipped`, `timeout`, atau `error`.

Klien hanya menerima field laporan yang diperlukan untuk tampilan; UID pemilik, URL lengkap,
dokumen kuota, dan audit moderasi tidak pernah dikirim. `reviewCommunityReport` belum memiliki UI
admin; moderasi dilakukan melalui pemanggilan callable oleh akun admin atau alat internal.

`scanUrlMultiSource` tidak menyimpan laporan ke Firestore. UI menyimpan laporan gabungan secara
lokal per scan agar `firestore.rules` tidak perlu diubah. Key provider untuk UI saat ini dibaca
backend lokal dari `server/.env` yang diabaikan Git. Key tidak boleh masuk ke frontend, `VITE_*`,
log, atau file yang di-commit. Provider tanpa key tampil `not_configured`; kredensial ditolak tampil
`auth_failed` dan tidak dianggap aktif.

Frontend menolak respons backend yang tidak memuat keenam provider unik atau provider ganda. Bila
penyimpanan lokal gagal karena kuota, laporan tetap dipertahankan di memori dan tidak digantikan
oleh data lama. Untuk tautan normal, menekan Periksa tautan adalah persetujuan untuk mengirim URL;
sesi Firebase, fitur yang aktif, dan URL non-sensitif tetap diwajibkan. Laporan yang direkonstruksi
atau gagal memuat provider menampilkan alasan spesifik dan tautan scan ulang.

Fungsi AI **belum dipanggil oleh frontend**. Aktivasi memerlukan keputusan alur persetujuan
privasi karena isi pesan dapat dikirim ke Gemini. Jangan mengubah `VITE_ANALYSIS_MODE` menjadi
`firebase` sebelum alur tersebut diimplementasikan dan diuji.

## Backend lokal scanner

`server/` menjalankan handler scanner yang sama dengan Worker di Node.js, tanpa Cloudflare dan
tanpa Blaze. Pemindaian tidak memerlukan login atau token apa pun:

- `POST /scan` untuk JSON.
- `POST /scan/stream` untuk SSE (`init`, `provider`, `done`, `error`).
- Body `{ "url": "...", "consent": true }`; tanpa header `Authorization`.
- CORS hanya untuk origin di `ALLOWED_ORIGINS`; rate limit per IP disimpan di memori proses.
- Validasi URL tetap: hanya http/https, alamat lokal/privat ditolak, consent wajib.
- `server/.env` dibaca tanpa mencetak nilai secret.

```powershell
Set-Location C:\AI-Projects\veriguard-ai\server
npm run build
npm test
npm run live-check -- https://example.com
npm run dev
```

`live-check` memanggil adapter secara langsung dan hanya mencetak status, verdict, durasi, serta
alasan yang sudah disanitasi. Hasil lokal terakhir: URLScan.io `success`, VirusTotal `success`,
ThreatFox `not_found`, OpenPhish `success`, Radar `success` (vonis kosong dinilai `inconclusive`),
OTX `success`. `not_found` bukan `clean`.
Scan guest end-to-end dari browser ke backend lokal sudah terverifikasi tanpa Firebase.

Server lokal adalah proses jangka panjang. Jalankan di terminal sendiri; jangan menggabungkannya
dengan command build/test yang menunggu proses selesai.

## Cloudflare Worker scanner (alternatif)

Worker di `workers/` memakai ulang adapter dan orkestrasi di `functions/src/scanners/` tanpa
membutuhkan Blaze. Worker live: `https://YOUR_CLOUDFLARE_WORKER_HOST`. Worker
menerima `POST /scan` dengan body `{ "url": "...", "consent": true }` dan `POST /scan/stream`
dengan tambahan `scanId`, memakai header `Accept: text/event-stream`. Stream mengirim event
`init`, `provider`, `done`, dan
`error` dengan heartbeat berkala; klien lama tetap dapat memakai `/scan` JSON. Endpoint menolak
origin di luar `ALLOWED_ORIGINS`, URL non-http/https, alamat lokal/privat, body terlalu besar, dan
request tanpa consent. `PROVIDER_CONCURRENCY` membatasi provider paralel (default 4, maksimum 6).
Rate limit edge per IP bersifat best-effort per isolate; rate limit per akun tetap diterapkan oleh
core scanner. Untuk produksi, tambahkan Cloudflare Rate Limiting/WAF sebagai
lapisan tambahan. Pada Workers Free, sebagian besar waktu adalah I/O provider; batas CPU dan
subrequest perlu diuji saat live, dan kuota/key provider tetap menjadi batas utama.

Sesuaikan `ALLOWED_ORIGINS` di `workers/wrangler.toml` dengan domain Hosting/custom yang dipakai.
Secret provider tidak boleh masuk `wrangler.toml`, `VITE_*`, log, atau file yang di-commit.
`CLOUDFLARE_ACCOUNT_ID` bukan secret dan dapat ditempatkan di `[vars]`; `CLOUDFLARE_API_TOKEN`
tetap secret. Saat deploy Worker, isi secret `URLSCAN_API_KEY`, `VIRUSTOTAL_API_KEY`,
`THREATFOX_API_KEY`, `OTX_API_KEY`, `CLOUDFLARE_API_TOKEN`, dan `CLOUDFLARE_ACCOUNT_ID`;
`OPENPHISH_API_KEY` opsional karena endpoint periksa OpenPhish publik.

Setup lokal dan validasi (tidak melakukan deploy):

```powershell
Set-Location C:\AI-Projects\veriguard-ai\workers
npx wrangler login
npx wrangler whoami
Copy-Item .dev.vars.example .dev.vars
notepad.exe .dev.vars
git check-ignore -v .dev.vars
npm run typecheck
npm test
npm run build   # wrangler deploy --dry-run, tidak melakukan deploy
npm run dev     # server lokal wrangler di http://localhost:8787
```

Worker `veriguard-scanner` sudah ada. Tambahkan secret yang belum tersedia satu per satu secara
interaktif agar nilainya tidak masuk riwayat shell. Jangan mengubah secret yang sudah ada tanpa
persetujuan pemilik proyek:

```powershell
# sudah terpasang
npx wrangler secret put URLSCAN_API_KEY
npx wrangler secret put VIRUSTOTAL_API_KEY
npx wrangler secret put THREATFOX_API_KEY
# tambahkan saat deploy Worker (nilai hanya lewat prompt, bukan file repo)
npx wrangler secret put OTX_API_KEY
npx wrangler secret put CLOUDFLARE_API_TOKEN
npx wrangler secret put CLOUDFLARE_ACCOUNT_ID
npx wrangler secret put OPENPHISH_API_KEY
npx wrangler secret put TURNSTILE_SECRET_KEY
npx wrangler secret list   # hanya menampilkan nama, bukan nilai
```

`URLSCAN_API_KEY`, `VIRUSTOTAL_API_KEY`, dan `THREATFOX_API_KEY` adalah tiga kunci yang nilainya
pernah berada di objek Git lokal dan masih dipakai konfigurasi saat ini, jadi rotasinya adalah
tindakan pemilik akun (lihat `docs/LOCAL_DEVELOPMENT.md` bagian N dan `docs/RELEASE_GATE.md`
bagian 9.6). Untuk membuktikan rotasi tanpa pernah melihat isinya: `npm run check:keys` dari root
repo — ia mencetak nama, panjang, dan sidik-jari SHA-256 10 heksa per berkas konfigurasi.

URL Worker tersedia dari output `wrangler deploy` atau dashboard Cloudflare. Format `workers.dev`
adalah `https://veriguard-scanner.<account-subdomain>.workers.dev`. Untuk memakai Worker sebagai
backend, kosongkan `VITE_API_BASE_URL` lalu isi URL Worker tanpa akhiran `/scan`:

```text
VITE_API_BASE_URL=
VITE_SCANNER_WORKER_URL=https://veriguard-scanner.<account-subdomain>.workers.dev
```

`VITE_API_BASE_URL` selalu diprioritaskan. Pastikan origin frontend ada di `ALLOWED_ORIGINS`, lalu
restart Vite atau rebuild frontend. Jika kedua variabel kosong, opsi pemeriksaan eksternal tidak
dijalankan dan UI menampilkan pesan konfigurasi; frontend tidak memakai callable Firebase sebagai
fallback.

## Struktur

Folder utama: `functions/` (callable Firebase), `server/` (backend scanner lokal), `workers/`
(scanner Cloudflare alternatif), dan `web/` (frontend Vite).

```text
.
├─ firebase.json
├─ firestore.rules
├─ firestore.indexes.json
├─ .firebaserc.example
├─ functions/
│  ├─ src/index.ts
│  ├─ src/scanners/            # Adapter provider, validasi, privasi, orkestrasi
│  ├─ .env.example
│  ├─ package.json
│  └─ tsconfig.json
├─ server/
│  ├─ src/index.ts             # HTTP Node, CORS, auth, SSE, rate limit lokal
│  ├─ src/env.ts               # Parser .env tanpa mencetak secret
│  ├─ src/live-check.ts        # Uji provider langsung tanpa browser
│  ├─ test/                    # Test endpoint dan konfigurasi lokal
│  ├─ .env.example
│  ├─ package.json
│  └─ tsconfig.json
├─ workers/
│  ├─ src/index.ts             # HTTP endpoint, CORS, validasi, rate limit edge
│  ├─ src/rateLimit.ts         # Rate limit per isolate
│  ├─ .dev.vars.example
│  ├─ package.json
│  ├─ tsconfig.json
│  └─ wrangler.toml
└─ web/
   ├─ src/
   │  ├─ components/           # UI dan layout
   │  ├─ content/              # 8 artikel edukasi
   │  ├─ lib/analysis/         # Engine heuristik tautan dan pesan
   │  ├─ lib/auth/             # Auth context/provider + sesi demo
   │  ├─ lib/firebase/         # Config, client, auth, Firestore, error mapping
   │  ├─ lib/scanners/         # Agregasi laporan, privasi, client, local store
   │  ├─ lib/scans/            # Hook riwayat/scan dan penyimpanan per pengguna
   │  ├─ lib/storage/          # Riwayat lokal + fallback memori
   │  └─ pages/
   ├─ scripts/                 # verify-ui.mjs dan e2e.mjs
   └─ .env.example
```

## Route

| Route | Halaman |
|---|---|
| `/` | Landing |
| `/periksa` | Scanner tautan/pesan (butuh email terverifikasi untuk akun masuk) |
| `/hasil/:id` | Hasil analisis, laporan multi-sumber lokal, dan konteks komunitas (butuh email terverifikasi) |
| `/komunitas` | Community Reports: daftar publik dan form laporan (butuh email terverifikasi) |
| `/riwayat` | Riwayat lokal/akun, cari/filter/urut/ekspor CSV (butuh email terverifikasi) |
| `/edukasi` | Daftar 8 artikel edukasi |
| `/edukasi/:slug` | Artikel |
| `/masuk` | Login Firebase atau sesi demo |
| `/daftar` | Registrasi Firebase (username unik wajib) atau sesi demo |
| `/verifikasi-email` | Status, kirim ulang, pemrosesan tautan verifikasi email, dan keluar aman |
| `/dashboard` | Statistik lokal/akun setelah minimal 3 pemeriksaan (butuh email terverifikasi) |
| `/pengaturan` | Preferensi, privasi, ekspor, sesi, username akun, dan data |

## Mesin analisis

- **Tautan:** struktur URL, IP, Punycode, karakter `@`, pemendek URL, subdomain berlapis, TLD
  berisiko, kemiripan merek, kata terkait akun, port nonstandar, dan berkas executable.
- **Pesan:** urgensi, ancaman, hadiah, permintaan OTP/PIN, data pribadi, transaksi, investasi,
  lowongan kerja, konteks marketplace/kurir, dan tautan dalam pesan.
- **Skor:** jumlah bobot indikator (maksimal 100); rendah `<25`, sedang `25–59`, tinggi `≥60`.
  Skor adalah indikator, bukan probabilitas.
- **Validasi:** hanya http/https, alamat lokal/privat ditolak, tautan maksimal 2048 karakter, pesan
  12–4000 karakter.
- **Multi-sumber:** URL dikirim ke provider setelah fitur diaktifkan, backend scanner tersedia,
  dan pengguna menekan Periksa tautan. Backend lokal mengirim event
  SSE `init`, `provider`, dan `done`; UI menampilkan status provider secara real-time. URL dengan token,
  email, nomor telepon, atau tautan reset/verifikasi tidak dikirim. Verdict gabungan memakai bukti terkuat dan korelasi, bukan penjumlahan probabilitas.
  Kelengkapan provider dilaporkan terpisah; provider gagal tidak menurunkan indikasi risiko, dan
  verdict gabungan `clean` hanya dipakai bila semua provider eksternal selesai dengan hasil
  `clean`; `not_found` tetap `inconclusive`.
- **Status provider:** `success`, `not_found`, `not_configured`, `auth_failed`, `unavailable`,
  `rate_limited`, `skipped`, `timeout`, `error`. Provider tanpa key atau dengan kredensial ditolak
  tidak boleh dianggap aktif. URL sensitif memakai `skipped`; provider yang melewati batas waktu
  memakai `timeout`. `not_found` berarti tidak ada indikator, bukan jaminan aman.
- **Detection ratio VirusTotal:** dihitung dari `last_analysis_stats` asli, yaitu
  `malicious / (malicious + suspicious + harmless + undetected) × 100`, dibulatkan dua desimal.
  Rasio ditampilkan sebagai rasio deteksi engine, bukan probabilitas bahwa URL berbahaya, dan
  bila total 0 ditampilkan "tidak tersedia" alih-alih angka.
- **Verdict gabungan memakai label risiko teramati:** "Risiko tinggi teramati"
  (indikasi berbahaya), "Risiko menengah teramati" (perlu verifikasi), "Risiko rendah teramati"
  (tidak ditemukan indikasi), dan "Belum konklusif". Panel hasil menampilkan daftar Bukti penilaian
  yang menjelaskan provider mana yang menandai, mana yang gagal, dan kelengkapan data.
- **ThreatFox:** menampilkan IOC cocok, keluarga malware, jenis ancaman, confidence, dan
  `first_seen` bila tersedia. No-match tampil "Tidak menemukan IOC"; tidak ada catatan di basis IOC
  bukan bukti URL aman dan tidak menghasilkan persentase.

## Privasi

Isi pesan disimpan lengkap hanya jika pengguna memilih opsi penyimpanan (default nonaktif). Tanpa
izin, tautan, email, nomor telepon, dan deretan angka disamarkan sebelum masuk ke localStorage atau
Firestore. Ekspor CSV mengikuti filter aktif dan menetralkan formula injection. Pengguna dapat
menyamarkan semua isi pesan, mengekspor, menghapus riwayat, atau menghapus data lokal.

Laporan komunitas tidak menyertakan email atau UID pelapor. Nama tampilan akun (disamarkan) dan
teks alasan laporan **ditampilkan** pada konteks komunitas serta feed global “Laporan terbaru”,
tanpa URL atau hostname, jadi jangan menuliskan nama orang lain, kata sandi, OTP, nomor telepon,
atau data pribadi di alasan laporan. Laporan baru dapat muncul di feed yang terlihat akun
terverifikasi lain. Sesi demo lokal dan sesi Firebase anonim tidak dapat mengirim laporan.

Pemeriksaan reputasi eksternal dimulai saat pengguna menekan Periksa tautan, tanpa memerlukan
login, dan tidak tersedia untuk URL sensitif. Hasil guest disimpan lokal
dan tidak ditulis ke Firestore. VERIGUARD tidak membuka URL target; provider
eksternal dapat membukanya. Laporan gabungan hanya disimpan di perangkat, tanpa raw payload provider
dan tanpa menulis ke Firestore.

## QA dan keamanan klien

- Axe-core mencakup seluruh route inti dan state berisi data pada WCAG 2.1 A/AA.
- Navigasi keyboard, skip link, fokus menu seluler, error `role="alert"`, dan reduced motion diuji.
- Input dirender sebagai teks oleh React; E2E memastikan payload HTML tidak tereksekusi.
- E2E memastikan aplikasi tanpa konfigurasi Firebase tidak memanggil sumber jaringan eksternal.
- Unit test komunitas mencakup normalisasi URL, validasi skema, pemetaan error permission/kuota/
  index/jaringan, normalisasi nama dan penyamaran, batas harian, transaksi append-only, binding
  laporan–penanda–kunci–feed, hitungan pseudonim, cache/deduplikasi, formasi Skor Reputasi, dan
  regresi regangan baca. Matriks Security Rules Spark pada Emulator Suite menjalankan **85/85**
  pemeriksaan (termasuk tamu/anonim/unverified, lintas akun, lintas URL, collection-group, path
  langsung, append-only, dua permintaan serentak, dan koleksi internal), ditambah **69/69**
  pemeriksaan feed global (head/entri privat, tanpa `list`/collection-group, pergeseran head,
  pemalsuan entri, batas 8, dan laporan lama tetap ada), **18/18** regresi profil/scan, serta
  **57/57** pemeriksaan browser jalur Spark tanpa Functions. Regresi UI tanpa Firebase menjalankan
  435 pemeriksaan. Functions live di proyek produksi tidak dijalankan dan belum diverifikasi.
- Unit test scanner mencakup deteksi URL sensitif, status provider, rate limit, event orchestration,
  concurrency, timeout, pembatalan, parsing SSE/JSON, agregasi verdict/konflik, dan penyimpanan
  laporan lokal. Provider diuji dengan fetch tiruan; tidak ada permintaan eksternal saat test.
- Pemindaian dapat dibatalkan dari UI dan controller di-abort saat halaman ditinggalkan. Reader,
  listener, dan lock stream dibersihkan; timeout per panggilan dibedakan dari pembatalan pengguna,
  dan tidak ada retry otomatis. UI menyatakan bahwa pembatalan browser tidak menjamin pekerjaan di
  server/provider eksternal berhenti.
- Unit test profil memastikan `createdAt` dipertahankan, dokumen UID lain ditolak, kegagalan
  Firestore diteruskan, dan data scan lintas pemilik tidak ditampilkan. Test penyimpanan juga
  memastikan kegagalan cloud tidak diam-diam beralih ke localStorage.
- Unit test username memastikan normalisasi dan batas format, satu akun satu username, penolakan
  duplikat (juga beda huruf besar), klaim serentak yang hanya menghasilkan satu pemenang,
  idempotensi klaim ulang oleh pemilik, tidak tertinggal klaim saat pendaftaran gagal, serta
  penyalinan klaim ke dokumen profil tanpa menghapus nilai lama. Fake Firestore menjalankan
  klasifikasi create/update dan validasi bentuk sesuai `firestore.rules`; rules itu sendiri belum
  dapat dijalankan pada emulator di mesin tanpa Java.
- E2E mencakup route Community Reports, gate sesi demo, daftar laporan terbaru global tanpa URL,
  kegagalan backend tanpa konfigurasi, aksesibilitas route, header login/logout desktop dan mobile,
  serta overflow mobile.
- Build produksi diperiksa otomatis: endpoint wajib HTTPS non-loopback, emulator dilarang, backend
  komunitas harus `firestore`, dan bundle dipindai ulang untuk host lokal. Error boundary tingkat
  aplikasi menampilkan fallback generik tanpa detail internal; route non-landing dimuat lazy.
- Unit test verifikasi memastikan parsing kode aksi, penolakan kode kosong/terlalu panjang, cooldown
  kirim ulang, serta pemetaan tautan invalid/kedaluwarsa.
- Batas: pengujian browser hanya Chromium dan tema light mode. Uji Firebase nyata dilakukan pada
  emulator. Aktivasi feed global menunggu review dan deploy `firestore.rules` terbaru atas
  persetujuan pemilik proyek. Deploy rules harus dilakukan **sebelum** client baru: client baru
  menulis feed dan akan ditolak rules lama, sedangkan client lama tetap dapat mengirim laporan
  tanpa menulis feed. Tidak ada backfill; Functions/Cloud Scheduler hanya diperlukan untuk jalur
  opsional.

## Design token

`canvas #F8FAFC` · `ink #111827` · `accent #2563EB` · risiko rendah/sedang/tinggi
(`#047857` / `#B45309` / `#B91C1C`). Light mode saja, radius 10/14/20px, shadow minimal.

## Roadmap

- **T1** Fondasi antarmuka — selesai
- **T2** Landing lengkap — selesai
- **T3** Engine heuristik + form scanner — selesai
- **T4** Halaman hasil analisis + cetak — selesai
- **T5** Riwayat lanjutan — selesai
- **T6** Dashboard, pengaturan, dan artikel — selesai
- **T7** QA menyeluruh, audit a11y, E2E — selesai
- **T8** Firebase Auth, Firestore, Hosting, Functions + Gemini — kode terpasang, verifikasi live
  menunggu konfigurasi proyek
- **T9** Community Reports — jalur Spark bawaan (Firestore + Security Rules): laporan append-only
  terpartisi per hash URL, batas harian WIB, konteks per URL, Skor Reputasi, panel hasil, feed
  global terbatas maksimal 8 laporan tanpa `collectionGroup`, dan test emulator. Jalur callable
  Functions, moderasi admin, dan retensi tetap opsional untuk Blaze dan tidak dipakai UI. Rules
  feed di repo belum di-deploy dalam pengerjaan ini; laporan lama tidak di-backfill. Uji Firebase
  produksi belum dilakukan.
- **T10** Scanner multi-sumber — adapter, privasi, persetujuan, laporan gabungan, local store, dan
  test tersedia. SSE progress sudah diimplementasikan. Backend lokal memakai CORS, rate limit, dan
  validasi consent tanpa login Firebase; scan browser→backend terverifikasi end-to-end. URLScan.io,
  VirusTotal, ThreatFox, OpenPhish, Cloudflare Radar URL Scanner, dan AlienVault OTX
  sudah lolos live check. Google Safe Browsing (v5 `urls.search`) menggantikan URLScanner.online sebagai
  agen eksternal kedelapan (nomor UI "Agen 8"): endpoint resmi
  `https://safebrowsing.googleapis.com/v5/urls:search` dengan kunci pada query parameter
  `key=` dan URL target pada parameter `urls=` (metode GET, tanpa request body). Entri
  respons `{threats:[{url, threatTypes:[ThreatType]}]` dipetakan ke `malicious` (MALWARE,
  SOCIAL_ENGINEERING) atau `suspicious` (UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION,
  `THREAT_TYPE_UNSPECIFIED`, atau threatType tak dikenal), skor 85/55, bukti `new_scan`.
  Respons `{threats:[]}` (no-match pada v5, HTTP 200) TIDAK dibaca sebagai
  bukti aman: status `not_found`/`inconclusive` dengan alasan yang secara eksplisit menyatakan
  "BUKAN konfirmasi … aman". Migrasi dari v4 (halaman `/safe-browsing/v4` menandai Lookup API
  "non-recommended", banner deprecation 2026-03-10; panduan `/safe-browsing/v5/migrate` menghapus
  `platformTypes`/`threatEntryTypes`/`ClientInfo` body, mengganti POST `/v4/threatMatches:find`
  dengan GET `/v5/urls:search`, dan `matches:[{threatType,threat:{url}}]` menjadi
  `threats:[{url,threatTypes:[]}]`). Autentikasi tetap `?key=`; tidak ada perubahan kebutuhan
  environment variable. Kegagalan transport, 401/403, 429, dan 5xx tetap
  `unavailable`/`auth_failed`/`rate_limited` (bukan kunci salah, bukan situs aman), dan kunci
  tidak pernah muncul di log/reason/sumber frontend. Hybrid Analysis
  (hybrid-analysis.com, CrowdStrike Falcon Sandbox) menggantikan CypherScan sebagai Agen 7:
  kontrak API-nya diverifikasi dari konektor resmi penerbit (`hybrid-analysis/VxAPI`, `api_caller.py`)
  dan pemeriksaan langsung (2026-10-28) — basis CANONICAL `https://hybrid-analysis.com/api/v2`, kunci
  pada header `api-key`, dan `/search/terms` (level autentikasi `RESTRICTED`, dapat dipakai kunci
  publik). Catatan penting: `https://www.hybrid-analysis.com/...` menjawab HTTP 301 normalisasi host
  ke apex, yang dengan semantik `redirect: 'error'` runtime muncul sebagai galat "redirect not allowed";
  karena itu adapter mengarahkan permintaan LANGSUNG ke apex tanpa mengikuti redirect dan tanpa
  meneruskan kredensial ke host lain (terverifikasi langsung: POST apex tanpa kunci → HTTP 403, bukan 3xx).
  Agen ini hanya
  melakukan penelusuran reputasi read-only atas laporan yang sudah ada, tidak pernah mengirim URL
  untuk analisis sandbox, dan selalu menandai hasilnya sebagai laporan yang sudah ada. Bentuk respons
  `/search/terms` (terverifikasi langsung) adalah objek `{ search_terms, count, result: [...] }` — BUKAN
  array polos; tiap dokumen memakai field string `verdict` (mis. `malicious`/`suspicious`/`clean`/
  `whitelisted`/`no specific threat`) dengan `threat_score` dan `av_detect` sebagai sinyal pendukung
  (endpoint ini TIDAK punya `threat_level` numerik). Parser membaca `result[]`, memetakan `verdict`
  ke band, memakai vonis terburuk yang terbaca; `result` kosong dilaporkan `not_found` dan vonis
  tanpa ancaman spesifik tetap `inconclusive` — keduanya BUKAN bukti aman. Respons yang bentuknya tak
  terduga dilaporkan `error` dengan diagnostik yang disanitasi (hanya HTTP status + tipe/kunci
  level-teratas, tanpa nilai, header, kunci, maupun body mentah), bukan diubah menjadi vonis bersih.
  Kunci dibaca
  dari `HYBRID_ANALYSIS_API_KEY` (backend saja). Jalur redirect/host dan bentuk respons diverifikasi
  live (pencarian read-only dengan kunci pengguna); pemindaian terautentikasi penuh belum diuji untuk
  setiap varian vonis. Laporan lama perlu scan ulang agar memakai alur baru.

# Panduan Jalankan VERIGUARD AI di Lokal (Windows PowerShell)

Dokumen ini diverifikasi terhadap skrip di `package.json` tiap paket pada tanggal 2026-10-25.
Perintah di bawah adalah perintah yang benar-benar ada di repo; tidak ada skrip yang dikarang.

---

## A. Prasyarat

| Kebutuhan | Nilai | Cara cek |
| --- | --- | --- |
| Node.js | `>=22` (dinyatakan di `server/package.json`), `functions` memakai `"22"` | `node --version` |
| npm | ikut Node | `npm --version` |
| Dependency tiap paket | instal terpisah (tidak ada workspace root) | lihat langkah B |
| Kunci API provider | opsional per provider | lihat bagian H |

Akar proyek: `C:\AI-Projects\veriguard-ai`

Struktur penting:

```
veriguard-ai\
  web\       frontend React + Vite  (port 5173, bisa fallback ke 5174)
  server\    backend Node lokal      (port 8787) -> memakai kode workers\ dan functions\
  workers\   handler scanner (dipakai server lokal & Cloudflare Worker)
  functions\ engine scanner + Firebase
```

Install dependency (tiap paket punya `package-lock.json` sendiri — tidak ada workspace root,
jadi instal dilakukan per folder). Minimal yang wajib untuk menjalankan situs:

```powershell
Set-Location C:\AI-Projects\veriguard-ai\server
npm install

Set-Location C:\AI-Projects\veriguard-ai\web
npm install
```

Tambahkan bila ingin menjalankan seluruh test/engine:

```powershell
Set-Location C:\AI-Projects\veriguard-ai\functions
npm install

Set-Location C:\AI-Projects\veriguard-ai\workers
npm install
```

---

## B. Terminal 1 — Backend scanner (port 8787)

```powershell
Set-Location C:\AI-Projects\veriguard-ai\server
npm run dev
```

`npm run dev` = `npm run build && node dist/server/src/index.js`, jadi sumber selalu
dikompilasi dulu sebelum dijalankan. Baris yang menandakan backend siap (diikuti daftar
origin yang diizinkan):

```
Server lokal VERIGUARD berjalan di http://127.0.0.1:8787
Origin diizinkan:
  - http://localhost:5173
  ...
```

Cek hidup tidaknya backend (repo **tidak punya** endpoint `/health`):

```powershell
curl.exe -Uri http://127.0.0.1:8787/ -Method GET -UseBasicParsing `
  -Headers @{ Origin = 'http://localhost:5173' }
```

- `405` dengan header `allow: POST, OPTIONS` = backend hidup dan rute dikenali (ini hasil yang benar untuk GET).
- `403` `origin_not_allowed` = Origin tidak ada di daftar izin.
- koneksi ditolak = backend belum jalan / port salah.

Bila konfigurasi kurang, backend mencetak peringatan saat start (tanpa menampilkan nilai):

```
[perhatian] Konfigurasi server belum lengkap:
  - CLOUDFLARE_API_TOKEN (isi di server/.env)
```

### Gerbang cooldown login (VGL-38 + VGL-39A + VGL-39B)

Backend lokal juga melayani tiga rute yang diintersepsi **sebelum** dispatch Worker:

```
POST /auth/login/gate/acquire   # izin sebelum kredensial dikirim
POST /auth/login/gate/report    # laporkan hasil (credential-failure | success | network | rate-limited)
GET  /auth/login/gate/status    # sisa pembatasan untuk sumber yang bertanya
```

```powershell
curl.exe -Uri http://127.0.0.1:8787/auth/login/gate/status -Method GET -UseBasicParsing `
  -Headers @{ Origin = 'http://localhost:5173' }
```

- Cooldown disimpan di `server/.data/login-guard.json` (sudah di `.gitignore`). Isinya hanya
  pseudonim HMAC + angka: tidak pernah email, IP mentah, kata sandi, atau token. Restart proses
  tidak menghapus cooldown yang masih berjalan; reservasi in-flight sengaja tidak bertahan.
- `LOGIN_GUARD_STATE_FILE` memindahkan berkas keadaan ke lokasi lain — dipakai probe lokal supaya
  keadaan dev tidak tertimpa.
- Tangga pembatasan per sumber (IP + pengenal perangkat): 2 menit, 1 jam, 3 jam, 6 jam, 12 jam,
  lalu 24 jam maksimum. Lapisan per-IP hanya bergerak setelah 8 kegagalan dan dibatasi 2 menit
  agar pengguna sah di IP bersama (kafe/asrama) tidak ikut terkunci.
- VGL-39A — setiap tingkat memberi **tepat 3 kesempatan** (`LOGIN_GUARD_ATTEMPTS_PER_LEVEL`).
  Kegagalan ke-1 dan ke-2 hanya mengurangi `attemptsLeft`; kegagalan ke-3 mengaktifkan cooldown
  tingkat berjalan, lalu tingkat naik dan siklus kesempatan mulai lagi dari 3. Selama cooldown
  berlangsung, percobaan tambahan tidak mengurangi kesempatan dan tidak menaikkan tingkat. Login
  berhasil menghapus riwayat sumber DAN mengembalikan tingkat ke awal. Yang disimpan per bucket:
  `level` (indeks tangga tujuan), `failures` (0..2 dalam siklus berjalan), `total` (monoton,
  pemenuh ambang IP 8).
- VGL-39B — berkas keadaan lama versi 1 (VGL-38, kebijakan "1 kegagalan = 1 tingkat") dimigrasikan
  saat dibaca dengan **pemetaan semantik, bukan salin angka**: `level` = `floor(failures/3)` (setiap
  tiga kegagalan lama = satu siklus selesai), `failures` = `failures % 3` (sisa siklus berjalan),
  `total` = angka lama, dan **cooldown warisan dibuang**. Alasannya harus disebut jujur: cooldown
  v1 adalah durasi kebijakan yang sudah dihentikan — 3 kegagalan menghasilkan 3 jam, padahal aturan
  aktif hanya memberi 3 jam pada tingkat 2 (butuh 9 kegagalan). Memakainya kembali membuat sumber
  tetap terkunci tanpa dasar dan itu persis penyebab sesi dev yang tidak bisa login lagi. Riwayat
  kegagalan TIDAK dihapus: angka lama tetap menentukan tingkat, sehingga penyerang yang benar-benar
  gagal 9 kali tetap berada di tingkat 2 begitu migrasi selesai.
- Reset keadaan hanya lewat berkas lokal oleh orang yang memegang `server/.data/`. **Tidak ada
  endpoint HTTP untuk reset** (`store.reset()` tidak dirutekan ke mana pun), dan tidak ada
  `curl`/alat di dokumen ini yang mereset semua sumber. Alat reset terarah yang dipakai VGL-39B ada
  di `.veriguard/investigasi/vgl39b-targeted-reset.mjs`: ia memverifikasi cadangan, mengidentifikasi
  record dari kunci akun HMAC + tautan `account.sources` yang ditulis server, dan menolak bekerja
  kalau target tidak dapat dipastikan.
- Asumsi proses tunggal: satu berkas keadaan dipegang di memori oleh satu proses node. Dua proses
  yang menunjuk berkas yang sama akan saling menimpa saat tulis (last write wins) dan membuat
  batas in-flight tidak lagi berlaku lintas proses. Gerbang lokal sengaja tidak memakai lock file;
  jaga hanya satu instance pada satu port.
- UI `/masuk` menampilkan angka dari server: `Kesempatan login tersisa: N dari 3` (hanya muncul
  bila sebagian kesempatan sudah terpakai dan sumber tidak terkunci), di atas kartu sehingga
  geometri kartu VGL-37C tidak berubah.
- Aturan cermin klien ketika gerbang tidak menjawab (`web/src/lib/auth/loginGuard.ts`): status
  "endpoint tidak ada/tidak dapat dipakai" (`404/405/410/5xx`) menaikkan tangga cermin; penolakan
  valid (`400/403/413/415`) TIDAK mengubah cermin; kegagalan transport TIDAK menaikkan tangga
  (server mungkin sudah mencatatnya, dan jaringan yang tidak stabil tidak boleh mengunci pengguna
  sah sampai 24 jam). Cermin tetap lapisan cadangan, bukan penegakan.
- **Batasan yang harus jujur disebut**: aplikasi memanggil Firebase Auth langsung dari browser,
  jadi gerbang ini tidak bisa menghentikan permintaan langsung ke `identitytoolkit.googleapis.com`.
  Penegakan penuh membutuhkan perubahan batas autentikasi (verifikasi kredensial di sisi server)
  dan itu tidak dilakukan di fase lokal ini.
- **Dari mana server lokal mengambil alamat IP klien** (`server/src/index.ts` →
  `resolveConnectingIp`). Bawaan: alamat socket selalu dipakai dan header `cf-connecting-ip`
  kiriman klien dibuang. Tanpa proxy di depan, header itu bisa dipalsukan per permintaan, jadi
  memakainya akan membuat lapis per-IP tidak berarti. Konsekuensinya ikut disebut jujur: bila host
  ini dijalankan di belakang proxy di mesin lain, semua pengguna sah tampak sebagai satu IP —
  lapis per-IP sengaja proporsional (ambang 8, cooldown 2 menit) supaya kejadian itu tidak mengunci
  seluruh jaringan. `TRUST_EDGE_CONNECTING_IP=true` mengizinkan header edge dipakai, **hanya** bila
  peer yang menghubungkan adalah loopback (tunnel/nginx di mesin yang sama) dan nilainya satu
  alamat IP tunggal yang sah; bentuk daftar (`a, b`) tetap ditolak. Bawaan kosong berarti perilaku
  lama tidak berubah, jadi tidak ada konfigurasi produksi yang perlu disentuh untuk menjalankan
  panduan ini.
- **Ambang kunci-otomatis di sisi Google bukan bagian repo ini.** Tidak ada berkas di repo yang
  mengatur Identity Platform/reCAPTCHA Enterprise proyek, dan tidak ada yang boleh diklaim sudah
  diatur. Bila pemilik ingin pemblokiran yang tetap berlaku untuk permintaan langsung ke
  `identitytoolkit`, ambang itu ditetapkan di konsol Google Cloud oleh pemilik proyek — tindakan
  produksi yang tidak bisa dibuktikan dari kode di sini.

---

## C. Terminal 2 — Frontend (Vite)

```powershell
Set-Location C:\AI-Projects\veriguard-ai\web
npm run dev
```

Alamat yang disajikan Vite ada di baris `Local:`. Karena `web/vite.config.ts` tidak
mengunci port (`strictPort` tidak diset), maka jika **5173 sudah dipakai proses lain**,
Vite otomatis naik ke **5174**, lalu 5175, dst. Itu perilaku normal, bukan error.

Frontend memanggil backend dari `web\.env.local` (atau `.env.development.local`):

```
VITE_API_BASE_URL=http://127.0.0.1:8787
```

Pisahkan endpoint per mode. Build produksi **tidak boleh** memakai host lokal:
`.env.production.local` harus berisi `VITE_SCANNER_WORKER_URL=https://...` (HTTPS non-loopback)
atau `VITE_API_BASE_URL` HTTPS non-loopback. `npm run build` di `web\` gagal bila kedua endpoint
kosong, memakai HTTP, mengarah ke localhost/loopback, atau bila `VITE_USE_EMULATORS=true`. Setelah
build, `scripts/inspect-bundle.mjs` memindai artefak dan gagal bila menemukan host lokal. Tidak ada
endpoint pengganti yang dibuat otomatis. Build regresi `verify:ui`/`test:e2e` memakai
`vite build --mode verify` agar tidak tunduk pada guard produksi.

Prioritas: `VITE_API_BASE_URL` > `VITE_SCANNER_WORKER_URL`. Kalau `VITE_API_BASE_URL`
kosong pada build pengembangan, pemeriksaan eksternal tidak diarahkan ke backend lokal dan hasil
provider akan "Dilewati". Setelah mengubah `.env.local`, restart `npm run dev` Vite (env dibaca saat
start). Emulator Firebase hanya aktif di mode development dan URL-nya wajib diisi eksplisit
(`VITE_AUTH_EMULATOR_URL`, `VITE_FIRESTORE_EMULATOR_HOST`); tidak ada default localhost di kode.

---

## C0. Dua profil dev server — akun asli vs emulator (VGL-42)

Sejak VGL-42, `npm run dev` (profil **bawaan**) tidak pernah menyambung ke Emulator Firebase,
meskipun `web\.env.development.local` men-set `VITE_USE_EMULATORS=true`. Login normal selalu menuju
Firebase Authentication **asli** sesuai `VITE_FIREBASE_*` di `web\.env.local`, sehingga akun yang
sudah terdaftar di proyek itu dapat masuk dan datanya (profil, riwayat scan) tetap terbaca.

| Perintah | Layanan akun | Login demo (VGL-39A) | Dipakai untuk |
| --- | --- | --- | --- |
| `npm run dev` (root: `npm run dev:web`) | Firebase Auth asli sesuai `.env.local` | tidak muncul — emulator mati | memakai aplikasi dengan akun sungguhan |
| `npm run dev:emulators` (root: `npm run dev:web:emulators`) | Emulator Auth + Firestore loopback | aktif | pengujian terisolasi, data contoh, provisioning `admins/{uid}` |

Emulator kini diminta oleh **proses peluncur**, bukan oleh berkas `.env`: `web/scripts/dev-emulators.mjs`
men-set `VITE_USE_EMULATORS=true` di environment anak lalu menjalankan `vite`. Alasan desain: Vite
memuat `.env.development.local` pada setiap `vite dev`, dan kode tidak bisa membedakan nilai itu
ditulis seseorang yang sadar memakai emulator atau sekadar tertinggal dari sesi pengujian —
dampaknya seluruh login normal senyap dialihkan ke instance emulator yang datanya kosong.

Dev server selalu mencetak profil yang sedang aktif pada baris pertama:

```
[veriguard] Layanan akun: Firebase Authentication asli sesuai konfigurasi proyek.
[veriguard] Layanan akun: EMULATOR Firebase. Login akun asli TIDAK akan ditemukan di sini.
```

Berkas `.env` tidak diubah oleh perubahan ini dan tetap menjadi tempat konfigurasi proyek, URL
emulator, `VITE_ENABLE_DEMO_LOGIN`, serta `VITE_API_BASE_URL`. Lihat C1 untuk prasyarat profil emulator.

## C1. Login demo lokal (emulator Auth + Firestore)

Dua akun demo untuk uji alur di mesin sendiri: `aleksatya4@gmail.com` (admin) dan
`akusipemain@gmail.com` (user). Keduanya **hanya ada di Emulator Firebase lokal**. Tidak ada
kata sandi, private key, service account, atau perubahan apa pun pada Firebase Auth produksi.

Prasyarat (semuanya wajib; kalau satu kurang, tombol demo tidak muncul dan dev server menolak
jalurnya dengan `404`):

```powershell
# Terminal 3 — emulator lokal (butuh JDK pada PATH + Firebase CLI)
Set-Location C:\AI-Projects\veriguard-ai
firebase emulators:start --only auth,firestore --project demo-veriguard
```

`web\.env.development.local`:

```
VITE_FIREBASE_API_KEY=local-demo-key
VITE_FIREBASE_AUTH_DOMAIN=localhost
VITE_FIREBASE_PROJECT_ID=demo-veriguard
VITE_FIREBASE_APP_ID=1:0:local
VITE_USE_EMULATORS=true
VITE_AUTH_EMULATOR_URL=http://127.0.0.1:9099
VITE_FIRESTORE_EMULATOR_HOST=127.0.0.1:8080
VITE_ENABLE_DEMO_LOGIN=true
```

Lalu `npm run dev:emulators` di `web\` (lihat C0 — `npm run dev` biasa memakai layanan akun asli)
dan buka `/masuk`. Nilai Web SDK di atas adalah konfigurasi publik
emulator, bukan secret; ganti `demo-veriguard` hanya jika proyek emulator Anda berbeda.

Cara kerja (peran ditetapkan sisi server, bukan oleh peramban):

1. `web/config/demoSessionPlugin.ts` terdaftar hanya saat `vite` berjalan sebagai dev server
   (`apply: 'serve'` + `command === 'serve'` di `vite.config.ts`). Jalurnya `POST /__veriguard-demo/session`.
2. Permintaan hanya boleh berisi satu bidang: `{ "account": "admin" | "user" }`. Email, peran,
   `isAdmin`, atau `role` ditolak sebelum provisioning; badan permintaan dibatasi 2 KB.
3. Plugin mencari akun di Auth Emulator; bila belum ada, akun dibuat dengan kata sandi acak
   24 byte yang tidak pernah dikembalikan atau dicetak, lalu diperbarui lewat jalur privileged
   emulator (`Authorization: Bearer owner`) dengan `emailVerified: true` dan
   `customAttributes: {"admin":true}` untuk akun admin saja (`{}` untuk akun user).
4. Allowlist `admins/{uid}` di Firestore Emulator ditulis untuk admin dan **dihapus** untuk user,
   memakai kredensial `owner` emulator yang sama seperti `withSecurityRulesDisabled` pada suite
   rules. Aturan produksi `firestore.rules` tetap `allow write: if false`, jadi klien tidak bisa
   menuliskan peran untuk dirinya sendiri.
5. Yang dikembalikan ke peramban hanyalah token custom emulator (JSON `{uid}` tanpa klaim).
   Peramban menukarnya lewat `signInWithCustomToken`, lalu membaca ulang klaim dari ID token yang
   diterbitkan Auth Emulator. Sesi dikelola `onAuthStateChanged`, bukan `localStorage`.

Yang dijamin tidak terjadi:

- Build produksi menolak `VITE_ENABLE_DEMO_LOGIN=true` (`config/productionEnv.ts`), plugin tidak
  terdaftar (`command === 'serve'`), dan `import.meta.env.DEV` bernilai `false` sehingga kartu
  demo tidak dirender.
- Tanpa emulator loopback, fitur ini mati — URL Auth harus `http://127.0.0.1`/`localhost`/`::1`.
- Token custom "palsu" hanya diterima Auth Emulator; Auth produksi menolak token yang bukan
  tanda tangan Admin SDK, sehingga tidak ada jalur dari fitur demo ke proyek sungguhan.
- Catatan trust zone: siapa pun yang bisa menjangkau `127.0.0.1:9099` juga bisa membuat token
  dan klaim palsu di emulator. Itu memang sifat Auth Emulator dan hanya berlaku di mesin lokal.

Kartu **Akun Demo** di halaman `/masuk` terpisah dari form login reguler dan dari kartu
"sesi demo lokal" (pratinjau tanpa akun, yang bukan autentikasi dan tetap ditolak dari jalur
admin). Tombol demo ikut dikunci oleh gerbang cooldown VGL-38.

---

## D. URL yang benar

| Komponen | URL |
| --- | --- |
| Frontend, saat 5173 bebas | `http://localhost:5173/` |
| Frontend, saat 5173 terpakai | `http://localhost:5174/` (atau 5175, lihat terminal Vite) |
| Backend | `http://127.0.0.1:8787` |
| Endpoint scan | `POST /scan` dan `POST /scan/stream` |

Backend hanya menerima Origin yang tercantum di `ALLOWED_ORIGINS`. Untuk dev lokal,
origin `localhost`/`127.0.0.1` pada port **5173–5177** selalu ditambahkan otomatis oleh
`withLocalDevOrigins()` di `server/src/index.ts`, sehingga fallback port Vite tidak lagi
menyebabkan `403`. Nilai `ALLOWED_ORIGINS` produksi Anda tetap dipertahankan (digabung,
tidak ditimpa, tidak ada duplikat).

---

## E. Bangun ulang dan restart backend

Gunakan ini setiap kali kode `server\`, `workers\`, atau `functions\` berubah.

```powershell
Set-Location C:\AI-Projects\veriguard-ai\server
npm run build
npm run start
```

`npm run start` menjalankan hasil build (`node dist/server/src/index.js`), jadi jangan
menjalankan `node dist/...` dari folder lain agar tidak salah memakai artefak lama.
Atau gunakan `npm run dev` yang menggabungkan build + start.

Catatan penting: `tsc` **tidak menghapus** file hasil compile dari sumber yang sudah
dihapus. Bila Anda menghapus/rename provider, bersihkan artefak yatim lalu build ulang:

```powershell
Set-Location C:\AI-Projects\veriguard-ai\server
Remove-Item -Recurse -Force .\dist -ErrorAction SilentlyContinue
npm run build
npm run start
```

Pastikan yang berjalan adalah build terbaru: hentikan proses lama dengan bagian F, lalu
bandingkan tanggal file `dist\server\src\index.js` dengan waktu start.

---

## F. Port bertabrakan (EADDRINUSE)

Pesan error: `EADDRINUSE: address already in use 127.0.0.1:8787`.

**Jangan** menghentikan semua proses Node. Identifikasi pemilik port dulu:

```powershell
# Cari PID yang memegang port
Get-NetTCPConnection -LocalPort 8787 -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess

# Lihat identitas proses itu sebelum memutuskan
Get-CimInstance Win32_Process -Filter "ProcessId = <PID>" |
  Select-Object ProcessId,Name,CommandLine
```

Hentikan **hanya** PID yang terbukti merupakan backend VERIGUARD
(`CommandLine` memuat `dist/server/src/index.js` atau `dist\server\src\index.js`).
Satu perintah aman yang memeriksa dulu baru menghentikan:

```powershell
$owner = Get-NetTCPConnection -LocalPort 8787 -State Listen |
  Select-Object -First 1 -ExpandProperty OwningProcess
$proc = Get-CimInstance Win32_Process -Filter "ProcessId = $owner"
if ($proc.CommandLine -like '*index.js*') {
  Stop-Process -Id $owner -Force
  "backend PID $owner dihentikan"
} else {
  "PID $owner bukan backend VERIGUARD -- tidak dihentikan"
}
```

Untuk port Vite:

```powershell
Get-NetTCPConnection -LocalPort 5173 -State Listen | Select-Object OwningProcess
Get-CimInstance Win32_Process -Filter "ProcessId = <PID>" | Select-Object CommandLine
```

Kalau pemilik 5173 adalah proses VERIGUARD lain (Vite lama), hentikan PID itu. Kalau pemiliknya
aplikasi lain yang tidak boleh disentuh, biarkan Vite fallback ke 5174 — backend sudah mengizinkan
rentang 5173–5177. Alternatif eksplisit: `npm run dev -- --port 5180 --strictPort`
lalu tambahkan `http://localhost:5180` ke `ALLOWED_ORIGINS` di `server\.env`.

---

## G. Troubleshooting

| Gejala | Penyebab | Tindakan |
| --- | --- | --- |
| `npm error Missing script: "dev"` | dijalankan dari folder yang tidak punya skrip itu (`functions\` tidak punya `dev`; `workers\` punya `dev` berupa `wrangler dev` yang butuh login Cloudflare) | backend+frontend lokal cukup dari `server\` atau `web\`. Dari root tersedia alias `npm run dev:server` / `npm run dev:web` |
| `npm run dev` di root hanya menjalankan backend, frontend tidak start | skrip root memakai `&` yang tidak paralel di cmd/PowerShell Windows | gunakan dua terminal (bagian B dan C), jangan andalkan root `npm run dev` |
| `EADDRINUSE 8787` | backend lama masih hidup | bagian F, hentikan hanya PID terverifikasi |
| `405 Method Not Allowed` | `GET` pada `/` atau `/scan` | memang benar: endpoint scan hanya menerima `POST` (header `Allow` menyebutkan metode yang diizinkan). `405` = backend reachable |
| `403 origin_not_allowed` | Origin tidak terdaftar | pastikan akses lewat `localhost:517x` (5173–5177 otomatis diizinkan di dev), atau tambahkan origin Anda ke `ALLOWED_ORIGINS` |
| `Failed to fetch` / "Layanan pemeriksaan eksternal tidak dapat dihubungi" | backend mati, port salah, atau `VITE_API_BASE_URL` kosong | jalankan Terminal 1, cek `http://127.0.0.1:8787`, cek `web\.env.local` |
| Error CORS di konsol browser | backend bukan milik Anda / origin produksi | cek `ALLOWED_ORIGINS`, pastikan request ke 8787 bukan workers.dev |
| Semua provider "Dilewati — Provider tidak dijalankan." | **frontend** menandai skip karena backend tidak mengembalikan hasil sama sekali (`web/src/lib/scanners/report.ts:65-80` dan `:215-221`) | perbaiki koneksi backend lebih dulu; ini bukan kesimpulan dari provider |
| Satu provider "Dilewati" tapi yang lain berhasil | skip sisi backend: URL sensitif, batas provider, atau scan dihentikan | cek `reason` pada kartu provider; bedakan dari `not_configured` |
| "Belum dikonfigurasi" | kunci/variabel provider kosong | lihat bagian H |
| `timeout` | provider > 50s atau scan deadline 80s, client 90s | ulangi; kalau persisten cek jaringan/VPN/kuota |
| `unauthorized` / `auth_failed` (HTTP 401/403) | kunci salah, kadaluarsa, atau scope kurang | ganti kunci; jangan hardcode di kode |
| `rate_limited` (HTTP 429) | kuota provider habis | tunggu window kuota; jangan naikkan konversi hasil jadi "aman" |
| `not_found` | provider tidak punya data untuk URL itu | **bukan** bukti URL aman |
| `0 dari 6 provider eksternal memberi hasil` | backend tak terjangkau, consent belum dicentang, atau URL ditolak validasi/SSRF | cek Terminal 1 hidup, centang persetujuan, gunakan URL publik (bukan `localhost`/IP privat) |
| `400 invalid_url` | URL privat/invalid | validasi SSRF memang menolak alamat internal — jangan dilonggarkan |
| `400 consent_required` | `consent !== true` | setujui pengiriman URL di UI |
| `415` | Content-Type bukan JSON | klien mengirim `application/json` |

---

## H. Variabel environment provider (nama saja — jangan pernah menaruh nilai di log/report)

File: `server\.env` (contoh templat: `server\.env.example`).

| Variabel | Provider | Catatan |
| --- | --- | --- |
| `VIRUSTOTAL_API_KEY` | VirusTotal | |
| `URLSCAN_API_KEY` | urlscan.io | |
| `THREATFOX_API_KEY` | ThreatFox | |
| `OTX_API_KEY` | AlienVault OTX | |
| `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID` | Cloudflare Radar URL Scanner | **dua-duanya wajib**; token harus punya scope Radar/URL Scanner pada account tersebut |
| `OPENPHISH_API_KEY` | OpenPhish | opsional; endpoint check publik tanpa kunci |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing (Agen 8) | kunci Safe Browsing v5 `urls.search`; dibaca backend dan dikirim sebagai query parameter `key=` ke `GET https://safebrowsing.googleapis.com/v5/urls:search` (URL target pada `urls=`); v4 Lookup API sudah deprecated (banner 2026-03-10) dan tidak dipakai lagi; tanpa kunci agen tampil "belum dikonfigurasi" |
| `HYBRID_ANALYSIS_API_KEY` | Hybrid Analysis (Agen 7) | kunci API v2 (header `api-key`); penelusuran reputasi read-only via `POST /search/terms`, tidak pernah mengirim URL ke sandbox; tanpa kunci agen tampil "belum dikonfigurasi" |
| `ALLOWED_ORIGINS` | CORS | |
| `TURNSTILE_SECRET_KEY` | Cloudflare Turnstile | secret siteverify; hanya dibaca backend, tidak pernah dikirim ke browser atau di-log. Kosong = endpoint verifikasi menjawab `503 captcha_not_configured` dan gerbang adaptif pemeriksaan nonaktif |
| `TURNSTILE_HOSTNAMES` | Cloudflare Turnstile | opsional; daftar hostname terpisah koma. Bila diisi, hostname yang dilaporkan Cloudflare harus salah satunya (Firebase Hosting menyajikan `*.web.app` dan `*.firebaseapp.com`, jadi satu nilai saja menolak sebagian pengguna). `action` (register/scan) selalu dicocokkan |
| `FIREBASE_PROJECT_ID` | P1-2 identitas Worker | ID proyek (nilai publik). Isi agar Worker mengenali ID token dari browser yang sudah masuk; kosong = semua permintaan diperlakukan sebagai tamu |
| `SERVER_PORT` / `SERVER_HOST` | backend lokal | default 8787 / 127.0.0.1 |
| `RATE_LIMIT_MAX_PER_IP`, `RATE_LIMIT_WINDOW_SECONDS`, `PROVIDER_CONCURRENCY` | proteksi lokal | |

Cek keberadaan **tanpa menampilkan nilai**:

```powershell
Set-Location C:\AI-Projects\veriguard-ai\server
Select-String -Path .\.env -Pattern '^[A-Z_]+=' |
  ForEach-Object {
    $k, $v = $_.Line -split '=', 2
    '{0,-28} {1}' -f $k, $(if ($v) { 'TERISI' } else { 'KOSONG' })
  }
```

Output hanya berisi nama variabel dan status terisi/kosong. Inventaris lengkap (panjang, bentuk,
berkas sumber yang membaca, bukti riwayat Git) dan daftar rotasi manual ada di bagian **N**.

Baris lama seperti `SAFE_BROWSING_API_KEY` atau `URLHAUS_API_KEY` masih aman dibiarkan:
`server/src/env.ts` hanya membaca daftar `KNOWN_SERVER_KEYS`, sehingga kunci provider yang
sudah tidak dipakai diabaikan dan tidak memengaruhi hasil scan.

---

## I. Verifikasi

```powershell
Set-Location C:\AI-Projects\veriguard-ai
npm run test:all          # server + functions + workers + web
npm --prefix server run typecheck
npm --prefix workers run typecheck
npm --prefix web run typecheck
npm --prefix web run lint
npm run build:all
npm run verify:release
```

`npm --prefix functions test` ikut `npm run test:all` dan menjalankan mesin scanner bersama
(delapan agen) beserta uji rules-nya yang berupa fungsi murni. Suite `firestoreRules.test.ts`
berbeda: ia hanya berbicara ke emulator Firestore dan **di-skip bila emulator tidak ada**, jadi
hasil skip tidak boleh dilaporkan sebagai lulus.

Rules Firestore diverifikasi terhadap emulator dari root repo (butuh JDK pada `PATH` dan
Firebase CLI):

```powershell
Set-Location C:\AI-Projects\veriguard-ai
npm run test:rules
```

Tiga pemeriksaan tambahan yang hasilnya dicatat di bagian N dan O:

```powershell
npm run audit:credentials        # inventaris kredensial tersamar + bukti riwayat Git
npm run check:keys               # keberadaan 3 kunci provider, hanya nama/panjang/sidik-jari
npm --prefix web run verify:csp  # report-only pada 9 rute + syarat enforcement
```

Checklist terakhir sebelum staging/publik, termasuk hasil gerbang di atas dan daftar tindakan
manual, ada di `docs/RELEASE_GATE.md`.

### Durable Object: apa yang bisa dibuktikan lokal dan apa yang tidak

Dua jalur verifikasi, keduanya memakai workerd sungguhan dan tidak menyentuh produksi:

```powershell
Set-Location C:\AI-Projects\veriguard-ai\workers
npm test                                              # 115 uji, termasuk 13 uji integrasi DO
npx wrangler dev --ip 127.0.0.1 --port 8799           # mode lokal, tidak ada deploy
```

Uji integrasi `test/durableObjectRuntime.test.ts` menjalankan entry `test/support/doProbeWorker.ts`
lewat `createTestHarness` wrangler dengan konfigurasi DO yang sama bentuknya dengan produksi
(`test/support/doProbe.wrangler.toml`). Yang dibuktikan di runtime asli: binding `SCAN_STATE`
terkirim ke `env`, stub ter-instansiasi, RPC dijawab 200 dengan JSON yang lolos validasi, pencacah
bertahan antar permintaan Worker, satu actor id dipakai bersama oleh dua facade, anti-replay token
berlaku. Arah kegagalan dibaca per jenis state: kegagalan RPC batas laju jatuh ke memori isolate
(dokumen ini mencatatnya sebagai penurunan ketepatan, bukan penurunan ketersediaan), sedangkan
kegagalan RPC anti-replay token MENOLAK tantangan (`reused`) karena memori isolate bukan state
bersama dan akan membolehkan satu token dipakai ulang dari isolate lain.
Batasannya harus dibaca jujur: harness menjalankan SATU isolate, jadi "dua facade" menguji
pembagian state pada actor yang sama, bukan pembagian proses antar isolate fisik seperti produksi.

`wrangler dev` membuktikan hal yang berbeda, yaitu Worker produksi nyata (`src/index.ts`): 31
permintaan serentak dari satu IP dijawab tepat 30 lolos + 1 `429` dan lognya tidak memuat satu pun
baris `scan_state_rpc`. Sebelum VGL-28 perintah ini mati sejak start-up karena
`export const MAX_BODY_BYTES` di entry module (workerd: `Incorrect type for map entry
'MAX_BODY_BYTES'`); konstanta itu sekarang tinggal di `workers/src/limits.ts` dan diimpor oleh
`src/index.ts` serta `server/src/index.ts`.

Akar penyebab P1-3 yang ditemukan VGL-28: `createStateRpc` menyimpan SATU stub Durable Object di
closure builder, sementara workerd menolak I/O stub itu pada konteks permintaan berikutnya
(`Cannot perform I/O on behalf of a different request`). Galatnya dulu dibuang oleh `catch {}`, lalu
pemutus arus 30 detik membuat fallback memori menjadi lengket per isolate — DO terpicu dan menjawab
200, tetapi keputusannya tidak pernah dipakai. Sekarang stub dibuat per panggilan;
`test/durableObjectRuntime.test.ts` menyimpan kedua bentuk (facade yang sama dipakai ulang = lulus;
stub disimpan lintas permintaan = ditolak runtime) supaya tidak bisa kembali tanpa sadar.

Status P1-3 setelah perbaikan ini: `LOCAL FIXED — PRODUCTION NOT YET VERIFIED` (VGL-28 tidak
melakukan deployment).

### Batas sebenarnya dari state Durable Object pada konfigurasi saat ini

`workers/wrangler.toml` hanya memuat binding `SCAN_STATE`; ia **tidak** memuat
`SCAN_STATE_KEY_V1` maupun `SCAN_STATE_KEY_ACTIVE`. Tanpa keduanya, `createStateKeyRing()`
mengembalikan `unavailable('no_keys')` dan `resolveRouting()` di `scanState.ts` tidak aktif,
sehingga SEMUA aksi (termasuk `window`) dijawab dari struktur memori actor, bukan dari
`state.storage`. Konsekuensinya harus dibaca apa adanya:

- **Dibagi antar isolate: ya.** Satu actor adalah satu titik proses, jadi batas laju per IP/uid,
  jendela analisis situs, izin CAPTCHA, dan anti-replay token tidak lagi bergantung pada isolate
  mana permintaan tiba. Batas scan (`scan:<uid>`, 6/10 menit) ikut berpindah ke sini supaya
  angka yang sama tidak terbagi sebanyak jumlah isolate.
- **Bertahan setelah actor dipaksa tidur: tidak.** Eviction DO mengosalkan hitungan, jadi
  penyerang yang sabar dapat memulai jendela baru lebih cepat daripada 10 menit kalender.
  Angka ini adalah batas laju best-effort, bukan kuota akuntansi.
- **Yang diperlukan untuk menjadikannya persisten (tindakan pemilik, bukan perubahan repo):**
  `wrangler secret put SCAN_STATE_KEY_V1` lalu `SCAN_STATE_KEY_ACTIVE=v1` pada Worker
  `veriguard-scanner`, kemudian deploy. Menambah secret adalah perubahan konfigurasi produksi
  dan tidak pernah dilakukan dari jalur audit lokal ini.

### Membaca diagnostik `scan_state_rpc`

Setiap kali Worker TIDAK memakai keputusan Durable Object, ia menulis satu baris `console.warn`
berformat JSON — tampil di `wrangler tail` (produksi) maupun log `wrangler dev` (lokal):

- `category`: `rpc_timeout`, `rpc_http_error`, `rpc_parse_error`, `rpc_validation_error`,
  `rpc_exception`, atau `rpc_breaker_open`;
- `fallbackUsed: true` berarti angka yang menegakkan permintaan itu adalah memori isolate, BUKAN
  batas terdistribusi — selama kategori ini masih muncul, P1-3 wajib dibaca "fallback aktif";
- `operation`, `durationMs`, `httpStatus`, `errorName`, dan `detail` seperlunya. `detail` disaring:
  endpoint internal diganti `<do-endpoint>`, deretan panjang diganti `<redacted>`, dipotong 160
  karakter, dan tidak pernah memuat API key, ID token, token CAPTCHA, atau isi permintaan.

Cacahannya juga bisa dibaca dari dalam proses: `readScanStateRpcHealth()` mengembalikan
`durableSuccessCount`, `fallbackCount`, `lastFailureCategory`, dan `breakerOpen` per isolate.


### Rencana verifikasi staging DO (belum dijalankan)

Jalankan pada project Firebase/Cloudflare percobaan, bukan `YOUR_FIREBASE_PROJECT_ID`. Tidak ada
perubahan produksi yang diasumsikan.

1. `npx wrangler deploy --dry-run --config workers/wrangler.toml` lalu
   `npx wrangler deploy --config workers/wrangler.toml --name <worker-percobaan>` — `--name` wajib
   disebut karena target default konfigurasi ini adalah Worker produksi `veriguard-scanner`.
   **Jangan** memakai `--remote` pada langkah mana pun: bantuannya berbunyi "Run on the global
   Cloudflare network with access to production resources". migrations `v1` tidak boleh diubah.
   Alternatif tanpa menyentuh akun (bukti lokal saja, satu isolate): `npx wrangler dev --port 8799
   --persist-to .wrangler/state/<nama>` dari `workers/`, override konfigurasi uji lewat `--var`
   (bukan lewat perubahan `wrangler.toml`).
2. Konfirmasi provisi DO **tidak** bisa dilakukan lewat CLI pada wrangler 4.156.0: tidak ada perintah
   `wrangler durable-object` (dibuktikan dengan `npx wrangler --help` — daftar subcommand tidak
   memuatnya). Buktikan provisi secara fungsi di langkah 3 dan 4: jika actor tidak ter-instantiate,
   RPC gagal dan diagnostik `rpc_*` muncul; jika actor hidup, pencacah bertahan antar permintaan.
3. Saring tail pada diagnostiknya: `npx wrangler tail --format json --search scan_state_rpc`
   (opsi yang tersedia di versi ini: `--format json|pretty`, `--search`, `--header`, `--version-id`).
   Kriteria lulus tahap ini: nol catatan `rpc_*` selama trafik uji berjalan. Kalau ada, kategori
   itulah penyebabnya (lihat bagian di atas) — jangan lanjut ke kesimpulan "batas terdistribusi
   sudah aktif" sebelum daftar itu kosong.
4. Uji pembagian lintas isolate: dua klien di dua region berbeda (atau dua percobaan berurutan
   setelah `wrangler tail` menunjukkan isolate baru) mengirim lebih dari `RATE_LIMIT_MAX_PER_IP`
   permintaan dengan `cf-connecting-ip` yang sama. Kriteria lulus: yang lolos tidak pernah
   melebihi batas secara total, bukan per wilayah.
5. Uji anti-replay CAPTCHA: tukar satu token Turnstile dari dua wilayah; hanya satu yang boleh
   diterima.
6. Uji pemulihan: `npx wrangler tail --format json` (flag `--preview` tidak ada untuk `tail` di
   wrangler 4.156.0) selama DO di-evict (idle >10 menit). Kriteria lulus:
   tidak ada permintaan yang lolos tanpa batas; state kembali nol dan pengguna ditantang CAPTCHA
   ulang. Catat latensi tambahan saat RPC DO gagal (breaker 30 s harus menahan antrean).
7. Ukur beban DO: satu instance singleton memegang seluruh state. Bila `wrangler tail`
   menunjukkan waktu tunggu RPC atau timeout 1,5 s, pecah menjadi beberapa shard
   (`idFromName` berdasarkan hash kunci) sebelum menaikkan trafik. Pembagian per kunci menjaga
   atomisitas karena satu kunci selalu masuk ke shard yang sama.
8. Rollback aman: hapus binding `SCAN_STATE` dan deploy — Worker kembali ke memori isolate
   seperti sebelumnya tanpa mengubah fitur lain.

UI end-to-end (tanpa backend eksternal; suite membangun bundle mode `verify` sendiri):

```powershell
Set-Location C:\AI-Projects\veriguard-ai\web
npm run verify:ui
npm run test:e2e
```

`npm run build` menjalankan typecheck, build produksi, guard konfigurasi, dan inspeksi bundle.
Build produksi memerlukan endpoint HTTPS non-lokal yang valid sesuai bagian C; jangan mengisi nilai
palsu hanya agar build lolos.

Uji provider live (bukan mock) terhadap backend yang sedang berjalan:

```powershell
Set-Location C:\AI-Projects\veriguard-ai\web
node .verify\live-smoke.mjs
# target lain: $env:SMOKE_BASE_URL='http://localhost:5174'; node .verify\live-smoke.mjs
```

Perhatikan bahwa hasil uji terbagi tiga dan tidak boleh dicampur:
**mock/unit** (tidak menyentuh internet), **lokal** (backend Anda), dan **live provider**
(kuota dan respons layanan pihak ketiga dapat berbeda sewaktu-waktu).

---

## J. Status validasi dokumen ini

Dokumen ini ditulis dari working copy `C:\AI-Projects\veriguard-ai` pada 2026-10-25.
Yang **benar-benar dijalankan** pada fase validasi terakhir dan menghasilkan seperti yang tertulis:

| Bagian | Perintah | Hasil |
| --- | --- | --- |
| B | `npm run build`, `npm run start`, `node dist/server/src/index.js` | backend LISTENING di 127.0.0.1:8787 |
| B | `curl.exe -X GET http://127.0.0.1:8787/ -H 'Origin: http://localhost:5174'` | `405` + header `allow: POST, OPTIONS` |
| C | `npm run dev` (web), `npx vite --port 5180 --strictPort` | ready; `http://localhost:5180/` → `200` |
| C | `npm run build` dengan env produksi valid | guard lolos; inspeksi 36 berkas, tanpa endpoint API host lokal |
| C | Build dengan endpoint kosong / loopback / backend `functions`, dan inspeksi bundle palsu berisi host lokal | semuanya **gagal** dengan pesan guard/pemeriksaan yang sesuai |
| E | `Remove-Item -Recurse -Force .\dist` lalu `npm run build` | dist hilang lalu terbentuk ulang (`functions`, `server`, `workers`) |
| F | `Get-NetTCPConnection`, `Get-CimInstance Win32_Process`, `Stop-Process -Id` | PID teridentifikasi; hanya proses `index.js` yang dihentikan; port kembali bebas |
| H | snippet `Select-String` tersembunyi nilai | mencetak nama variabel + `TERISI`/`KOSONG` saja |
| I | `npm --prefix server test`, `npm --prefix workers test`, `npm --prefix web test`, `verify:ui`, `test:e2e` | server 39, Worker 27, web 345 lulus; UI 435 lulus; E2E 217 lulus; typecheck dan lint web lulus (0 warning/0 error) |
| J | `firebase emulators:start --only auth,firestore --project demo-veriguard-rules` + `node .verify/rules-lab/matrix-spark.mjs`, `latest-feed.mjs`, `regression-profile-scan.mjs`, `node .verify/ui-community-spark-v2.mjs` | **85/85** matriks rules Spark, **69/69** feed global, **18/18** regresi profil/scan, dan **57/57** browser Spark lulus (2026-10-25): auth gate, kuota harian lintas URL, dua permintaan serentak, append-only, binding laporan–penanda–kunci–feed, pergeseran head maksimal 8, penolakan `list`/collection-group, skema, koleksi internal, lintas akun/URL, dan UI tersamar. **Catatan 2026-10-31: harness `.verify/rules-lab` sudah tidak ada di repository, jadi baris ini tidak dapat diulang. Penggantinya adalah baris K.** |
| K | `npm run test:rules` (dari root repo; butuh JDK pada `PATH` + Firebase CLI) | **21/21 lulus** (2026-10-31) terhadap emulator Firestore `demo-veriguard`. Suite ini ikut dilacak Git, jadi hasil dapat direproduksi: isolasi data per akun, penolakan sesi anonim berserta `email_verified` palsu, append-only pseudonim/username, eskalasi admin, batch kirim laporan yang sah, `reportedUrl` yang authority-nya berbeda dari `hostname` yang dideklarasikan (termasuk imbuhan subdomain), pengecualian host IPv6, dan penolakan collection-group `reports` untuk non-admin |
| L | `npm --prefix web test`, `npm --prefix web run typecheck`, `npm --prefix web run lint`, `node web/scripts/e2e.mjs`, `npm --prefix web run verify:ui` | web **769/769** lulus, typecheck lulus, lint 0 warning/0 error, E2E **228** lulus (skenario: URL sensitif tersamar di localStorage), UI **438** lulus — semuanya dijalankan 2026-10-31 setelah perubahan bagian VGL-12 dan pemeriksaan integritas laporan komunitas. `server`, `workers`, dan `functions` (kecuali suite rules) tidak diubah pada fase ini |
| N | `npm run audit:credentials`, `npm run check:keys` | inventaris tersamar 6 berkas environment (nama/panjang/bentuk saja), tidak ada berkas environment nyata di HEAD, dan seluruh objek terjangkau ref **plus 117 blob longgar** dipindai: **0 nilai environment aktif di objek Git mana pun** sejak blob `8317d39d…` dibuang pada VGL-19. Jumlah objek sengaja tidak dikutip karena berubah setiap commit dan akan basi. `check:keys` memvalidasi keberadaan tiga kunci provider (nama + panjang + sidik-jari, tanpa nilai) dan saat ini melaporkan sidik-jari masih identik di `server/.env`, `functions/.env`, `workers/.dev.vars` — tanda rotasi belum masuk — dirinci di bagian N |
| O | `npm --prefix web run verify:csp` | **0 pelanggaran** pada 9 rute dengan report-only saat ini; sejak VGL-20 pemeriksaan statis **tidak menemukan lagi** atribut `style={{ … }}` di sumber, sehingga satu-satunya syarat yang tersisa untuk enforcement adalah pembacaan laporan di produksi — dirinci di bagian O |
| P | `curl.exe -sI https://YOUR_FIREBASE_PROJECT_ID.web.app/…` (baca saja, dengan cache-buster) | `/` dan `/periksa` → `max-age=3600` (Firebase mencocokkan header pada jalur asli, bukan hasil rewrite), `/index.html` → `no-cache`, aset hash → `immutable`, `/assets/x.js` tak dikenal → 200 HTML `immutable`, dan **tidak ada** header `Content-Security-Policy` di produksi — dirinci di bagian P |

Yang **belum** dijalankan pada fase validasi terakhir: build/unit test `functions/` (tidak
dijalankan ulang; anggap belum terverifikasi), `wrangler dev` / `wrangler deploy --dry-run`,
`npm install` ulang per folder, dan `live-check` provider ulang. Hasil scan live 6/6 pada
2026-10-24 tetap catatan historis, bukan hasil fase ini. Tidak ada deploy rules, Functions, Worker,
atau Hosting; tidak ada penulisan data produksi.

Batas penting: penulis dokumen tidak punya akses ke komputer Anda. Semua angka di atas
dihasilkan di mesin penulis; di mesin Anda hasilnya bisa berbeda bila dependency belum
diinstal, port dipakai aplikasi lain, atau jaringan/kunci API berbeda.

Catatan: angka di tabel J adalah fase validasi sebelumnya. Hasil V6 (dashboard admin, moderasi
komunitas, riwayat per akun) dijalankan ulang pada hari yang sama dan dicatat di bagian L.

---

## K. Community Reports (Spark default + Functions optional)

Build produksi hanya menerima jalur **Spark** (`VITE_COMMUNITY_BACKEND=firestore`); nilai backend
lain menggagalkan build. Jalur Functions lama tetap tersimpan untuk referensi Blaze, tetapi tidak
dipakai UI dan tidak diaktifkan kembali.

### Model Spark (bawaan, tanpa Blaze)

Struktur dokumen:

```
communityReports/{urlHash}/reports/{reportId}             publik, append-only, per hash URL
users/{uid}/communityReportDays/{dayId}                   privat, satu penanda per akun per hari WIB
users/{uid}/communityReporterKeys/{urlHash}               privat, pseudonim acak per akun per URL
communityLatestReports/global                             head feed, maksimal 8 ID laporan
communityLatestReports/global/entries/{reportId}          publik terbatas, satu dokumen per laporan
```

- `urlHash` = 64 heksadesimal lowercase hasil SHA-256 URL ternormalisasi; `reportId` = 32
  heksadesimal acak. Laporan publik hanya berisi `reporterKey`, `userName`, `category`, `reason`,
  `createdAt`, dan `updatedAt`. Tidak ada UID, email, URL mentah, atau hostname.
- `communityReportDays` menyimpan `ownerId`, `reportId`, `urlHash`, `reporterKey`, `category`, dan
  `createdAt`. ID dokumen adalah hari WIB dari `request.time`; dua permintaan serentak bertabrakan
  pada dokumen yang sama.
- `communityReporterKeys/{urlHash}` menyimpan `ownerId`, `reporterKey`, dan `createdAt`, dibuat
  sekali dan tidak dapat diubah/dihapus.
- Head `communityLatestReports/global` hanya menyimpan `entries` (maksimal 8 `reportId`, baru →
  lama) dan `updatedAt`. Entri `communityLatestReports/global/entries/{reportId}` hanya berisi
  `reporterKey`, `userName`, `category`, `reason`, dan `createdAt`, tanpa UID, email, URL, hostname,
  hash URL, atau data moderasi.
- Feed bergulir berdasarkan jumlah, bukan waktu: laporan kesembilan menggeser ID terlama keluar
  dari head, tetapi dokumen laporan di partisi URL **tidak dihapus**. Tidak ada filter 24 jam dan
  tidak ada backfill laporan lama.

Ketentuan yang ditegakkan Security Rules:

- Hanya akun dengan email terverifikasi yang dapat membaca partisi URL dan menulis. Tamu, sesi
  anonim, dan email belum terverifikasi ditolak untuk baca maupun tulis.
- Skema publik harus persis, kategori dari daftar, alasan 20–500 karakter, nama berbentuk
  `Pengguna` atau berakhiran `(sensor)`, `reportId`/`urlHash`/`reporterKey` sesuai pola, dan
  `createdAt`/`updatedAt` sama dengan `request.time` server. Timestamp dan ID hari dari klien tidak
  dipercaya.
- Laporan publik, penanda hari, kunci pseudonim, entri feed, dan pergeseran head feed harus dibuat
  dalam satu commit yang saling cocok (`existsAfter`/`getAfter`). Laporan tanpa penanda, penanda
  tanpa laporan, entri feed tanpa laporan yang cocok, atau binding yang tidak cocok ditolak.
- Laporan, penanda, kunci, dan entri feed hanya `create`; update dan delete ditolak (append-only),
  sehingga pengguna tidak dapat mengubah/menghapus laporan atau entri akun lain atau memalsukan
  pemilik. Head feed hanya boleh di-`update` untuk menambah tepat satu entri baru di depan, dengan
  sisa daftar lama harus tetap sama; head tidak dapat dihapus atau dibuat kedua.
- Root `communityReports/{urlHash}` menolak baca/tulis, sehingga hash tak dikenal tidak dapat
  dienumerasi lewat root/path langsung. Tidak ada aturan collection-group untuk `reports`, sehingga
  query lintas URL ditolak. Akun terverifikasi tetap dapat membaca partisi lain bila hash-nya sudah
  diketahui; itu sifat data publik per URL, bukan izin enumerasi.
- Head dan entri feed hanya dapat dibaca dengan `get` oleh akun terverifikasi; `list` pada head
  ditolak, dan tidak ada aturan collection-group untuk `entries`. Feed tidak membuka UID/email dan
  tidak menjadi jalur enumerasi laporan di luar 8 ID yang tercantum.
- Koleksi internal `communitySummaries`, `communityRateLimits`, dan `communityModerationAudit`
  ditolak untuk semua klien. Jalur Spark lama `users/{uid}/communityReports` juga ditutup.

Baca, cache, dan batas:

- Konteks memakai count aggregation lebih dulu (1 read bila kosong), lalu maksimal 300 laporan
  terbaru dari satu partisi plus satu dokumen kunci privat. Jika pemindaian 300 tidak lengkap,
  `aggregatesComplete=false` dan Skor Reputasi tidak ditampilkan; tidak ada angka pengganti.
- Daftar “Laporan terbaru” bersifat global dan tidak membutuhkan URL: satu `get` head dan maksimal
  8 `get` entri (9 read). Tidak ada filter 24 jam; urutan ditentukan head. Cache 30 detik (maksimal
  32 entri) dengan deduplikasi permintaan berjalan; “Muat ulang” memaksa pembacaan baru tetapi
  tidak menggandakan permintaan yang masih berjalan. Daftar tidak direset saat URL formulir
  berubah.
- Log hanya memuat nama operasi dan kode error; email, UID, token, URL, dan isi laporan tidak
  dicatat. Token di-refresh sekali pada penolakan permission yang dapat diperbarui, tanpa retry
  storm.

Keterbatasan Spark yang harus disampaikan:

- Rules tidak dapat menghitung SHA-256 atau menormalkan URL. Hash adalah kunci partisi dari klien,
  **bukan bukti kriptografis** bahwa laporan berasal dari URL tersebut. Klien dapat memilih hash
  lain, dan variasi normalisasi dapat memecah laporan dari URL yang sama.
- `reporterKey` terlihat di laporan publik dan dapat disalin akun lain. `reporterCount` adalah
  heuristik pseudonim, bukan jumlah akun unik yang terjamin.
- Nama disamarkan di UI (maksimal lima grapheme, akhiran `(sensor)`, mis. `anaksigma` →
  `anaks(sensor)`). Penyamaran hanya tampilan; kontrol akses tetap dilakukan rules.
- Moderasi tersedia mulai V6 lewat dashboard admin berbasis rules (bagian L). Retensi otomatis
  dan pemeriksaan DNS tetap tidak tersedia di Spark. Laporan publik append-only; penghapusan
  hanya lewat alat admin terkontrol di luar aplikasi (belum disediakan).
- Feed hanya memuat laporan yang dikirim klien versi ini. Klien lama tetap dapat mengirim laporan
  tanpa menulis feed; laporan lama tidak di-backfill. Head global adalah dokumen panas, sehingga
  dua kiriman bersamaan dapat membuat satu transaksi gagal dengan pesan bentrok (tanpa retry
  otomatis). Feed hanya menampilkan maksimal 8 laporan dan tidak punya halaman berikutnya.
- Feed bukan moderasi: entri tidak dapat dihapus atau diubah pengguna, termasuk oleh pelapor
  sendiri. Bila diperlukan penghapusan darurat, hanya alat admin terkontrol di luar aplikasi yang
  dapat melakukannya (belum disediakan).

**Skor Reputasi** (0–100) dihitung terpisah dari Skor Indikasi Internal memakai `reporterCount`
(bukan jumlah kiriman), kebaruan laporan, kategori berdampak tinggi, dan status moderasi. Rumus:
`clamp(0, 100, min(reporterCount, 5) × 8 + recency + highImpact + moderation)`; `recency` 10/6/2
untuk ≤30/≤90/>90 hari, `highImpact` 4/0, dan `moderation` +35/+10/0/−20 untuk
`verified_malicious`/`under_review`/`community_reported`/`cleared`. Tanpa laporan aktif atau tanpa
agregat lengkap, skor tidak ditampilkan (bukan 0).

### Indeks, deploy, dan status produksi

1. Model ini tidak membutuhkan composite/collection-group index. `firestore.indexes.json` tetap
   kosong; konteks hanya menyentuh satu partisi dengan single-field index otomatis, dan feed hanya
   melakukan `get` langsung. Indeks communityReports lama yang mungkin masih ada di produksi tidak
   dipakai kode baru; jangan menghapusnya tanpa persetujuan.
2. Rules produksi memuat model Spark yang ada, sedangkan **aturan feed global di repo ini belum
   di-deploy** dan menunggu persetujuan eksplisit. Deploy rules harus **sebelum** client baru:
   client baru menulis lima dokumen (laporan, penanda, kunci, entri feed, head) dan akan ditolak
   rules lama. Client lama tetap dapat mengirim laporan tanpa menulis feed. **Tidak ada migrasi
   atau backfill**; laporan lama tetap di partisi URL masing-masing dan hanya muncul di feed bila
   dikirim ulang (tunduk pada batas harian).
3. Jalur Functions opsional membutuhkan Blaze, Cloud Scheduler, dan deploy Functions; jalur ini
   tidak aktif, tidak dipakai UI, dan tidak diaktifkan kembali. Jangan menggabungkan deploy rules
   dengan Functions.
4. Firebase Emulator Suite membutuhkan Java. Validasi jalur Spark memakai Auth `9099` + Firestore
   `8082` (proyek `demo-veriguard-rules`), tanpa Functions dan tanpa data produksi. Perintah:
   `firebase emulators:start --only auth,firestore --project demo-veriguard-rules`, lalu
   `node .verify/rules-lab/matrix-spark.mjs`, `node .verify/rules-lab/latest-feed.mjs`,
   `node .verify/rules-lab/regression-profile-scan.mjs`, dan
   `node .verify/ui-community-spark-v2.mjs`. Hasil: **85/85** matriks rules, **69/69** feed global,
   **18/18** regresi profil/scan, dan **57/57** browser. Regresi UI tanpa Firebase **435/435** dan
   E2E **217/217**. Functions live di produksi belum diverifikasi.

### Integritas laporan komunitas: apa yang bisa dan tidak bisa dibuktikan rules

`urlHash`, `reportedUrl`, `hostname`, dan `reporterKey` semuanya dibuat oleh klien. Security Rules
(Firebase Spark, v2) tidak dapat menghitung SHA-256, dan URL yang di-hash (`normalizeCommunityUrl`)
tidak sama dengan URL yang disimpan untuk ditampilkan (`sanitizeCommunityUrlForDisplay` membuang
query/fragment). Karena itu **tidak ada aturan yang dapat membuktikan `urlHash` adalah hash dari
URL laporan ini**. Klien yang dimodifikasi tetap dapat menulis ke partisi hash mana pun selama
bentuk dokumennya sah.

Yang ditutup sekarang (bukan redesign, hanya ikatan bentuk tambahan):

1. `reportedUrlMatchesDeclaredHost(data)` di `firestore.rules` — `reportedUrl` harus memakai
   `hostname` yang dideklarasikan sebagai authority (skema http/https, port opsional, path
   tanpa query/fragment). Ini menolak label brand-only seperti `hostname: "bank-resmi.test"`
   pada URL `https://contoh-penipuan.test/x`, dan menolak imbuhan subdomain
   (`contoh-penipuan.test.evil.net`). Host IPv6 berkurung siku dilewati karena kurung akan
   dibaca regex sebagai character class.
2. `hostnameMatchesUrl()` di `communityFirestoreService.ts` melakukan pemeriksaan yang sama saat
   membaca. Aturan tidak dapat dihitung ulang untuk dokumen lama, jadi label yang tidak cocok
   dibuang (`hostname: null`) tanpa menyembunyikan laporan atau URL-nya.
3. Paritas regex: `COMMUNITY_REPORTED_URL_PATTERN` (web) dan `reportedUrlMatchesDeclaredHost`
   (rules) keduanya membatasi bentuk yang sama; regex rules dibangun dari string `hostname`
   tersimpan sehingga titik yang tidak di-escape memberi kelonggaran satu karakter. Itu
   disengaja dan tetap menolak pemalsuan authority; jangan memindahkan pola ke konstanta bersama
   tanpa memverifikasi kompilasi rules.

Batas yang tersisa dan tidak dapat ditutup rules Spark:

- Partisi `urlHash` dan isi `reportedUrl`/`hostname` tetap pilihan klien; agregat "berapa banyak
  orang melaporkan URL ini" hanya sekuat kepatuhan klien pada normalisasi yang sama.
- `reporterKey` adalah pseudonim bearer yang dapat dibaca dan disalin dari dokumen publik;
  uniqueness lintas akun tidak dapat ditegakkan rules. Pemalsuan jumlah pelapor independen
  (framing/dilution) tetap mungkin dan sudah diakui di komentar `reputation.ts`.
- Penanganan yang tepat adalah penulis tepercaya (Cloud Function dengan service account, atau
  Admin SDK di server) yang menghitung `urlHash` dari URL yang dikirim dan menormalkan sendiri,
  dengan field verifikasi opsional sehingga dokumen lama tetap valid. **Belum diimplementasikan,
  belum di-deploy, dan membutukan Blaze**; tidak diaktifkan sebagai bagian pekerjaan ini.

---

## L. Dashboard Admin & Moderasi Komunitas (V6, Spark)

V6 menambahkan Dashboard Saya untuk semua akun dan Dashboard Admin untuk moderator yang
tercantum di allowlist Firestore. Tidak ada situs atau alur login terpisah; admin memakai
halaman masuk yang sama.

### Model data dan batas keamanan

```
admins/{uid}                                       allowlist admin; hanya Console/Admin SDK
communityReports/{urlHash}/reports/{reportId}      laporan publik; tetap append-only
communityModeration/{reportId}                     status + catatan privat moderator
communityModeration/{reportId}/history/{eventId}   audit append-only
communityModerationPublic/{reportId}               proyeksi status minimum untuk publik
```

- Laporan publik tidak pernah diubah moderator. Keputusan moderasi ditulis ke dokumen privat,
  proyeksi status publik, dan entri audit dalam satu `writeBatch` yang saling diikat rules
  (`existsAfter`/`getAfter`). Batch yang tidak lengkap atau tidak cocok ditolak.
- `communityModerationPublic/{reportId}` hanya berisi `status` dan `updatedAt`; catatan moderator,
  UID pelaku, dan audit tidak pernah disalin ke sana. Pembacaan publik hanya `get` per ID; `list`
  dan collection-group ditolak. Pembaca harus akun dengan email terverifikasi.
- Laporan publik `communityReports/...` tetap tidak dapat di-update/delete oleh klien mana pun.
- Hanya UID dengan email terverifikasi yang dokumen `admins/{uid}`-nya berisi `active: true`
  dan `role: "admin"` yang lolos `isAdmin()`. Klien tidak dapat membaca daftar admin dan tidak
  dapat menulis/mengubah/menghapus dokumen allowlist. Peran di UI hanya untuk navigasi; Rules
  tetap menolak baca/tulis walaupun UI atau devtools dipakai untuk membuka `/dashboard/admin`.
- Admin tetap memiliki Dashboard Saya dan riwayat pribadinya.

### Label status (persis)

| Status | Label UI |
| --- | --- |
| `pending` | Menunggu peninjauan |
| `review` | Sedang ditinjau |
| `confirmed_malicious` | Terverifikasi berbahaya |
| `inconclusive` | Belum cukup bukti |
| `rejected` | Ditolak |

Transisi: `pending` → `review` atau status akhir; `review` → `confirmed_malicious`,
`inconclusive`, atau `rejected`. Status akhir tidak dapat dibuka kembali. Setiap perubahan
memerlukan konfirmasi eksplisit di UI dan dapat disertai catatan internal maksimal 1000
karakter. Laporan tidak pernah otomatis dianggap berbahaya hanya karena dikirim pengguna atau
satu pemindai mencurigakan. Hanya status `confirmed_malicious` yang berarti terverifikasi;
status lain bukan jaminan keamanan.

### Provisioning admin manual (wajib, belum dilakukan di repo ini)

Tidak ada UID admin bawaan dan tidak ada cara mendaftar sebagai admin lewat aplikasi.
Lakukan langkah berikut di Firebase Console project yang dipakai build:

1. Deploy `firestore.rules` versi ini secara manual (belum dideploy oleh sesi ini).
   Tanpa aturan baru, dashboard admin dan status publik akan ditolak.
2. Masuk ke aplikasi memakai halaman masuk yang ada dengan akun calon admin, lalu
   verifikasi emailnya. Registrasi biasa tetap membuat akun pengguna biasa.
3. Buka Firebase Console → Authentication → Users, cari akun tersebut, dan salin **UID**-nya.
   Jangan memakai email sebagai identitas otorisasi dan jangan mengarang UID.
4. Buka Firestore Database → koleksi `admins` → buat dokumen dengan ID = UID tadi dan field
   persis:
   - `active` (boolean): `true`
   - `role` (string): `"admin"`
5. Muat ulang aplikasi. Tab “Dashboard Admin” muncul setelah pembacaan allowlist berhasil.
6. Untuk mencabut akses, ubah `active` menjadi `false` atau hapus dokumen lewat Console.
   Aplikasi tidak menyediakan UI untuk memberikan atau mencabut peran admin.

Jangan menambahkan aturan yang mengizinkan semua akun dengan email tertentu, dan jangan
mengisi UID contoh. Bila langkah 1–4 belum dilakukan, UI akan menampilkan penolakan akses
(yang memang benar) dan tidak ada data moderasi yang dimuat.

### Gerbang verifikasi email (access control)

- Sumber kebenaran tunggal adalah `emailVerified` pada objek user Firebase Auth. `user != null`
  tidak dianggap selesai registrasi, dan boolean dari klien tidak pernah dipercaya.
- `web/src/components/auth/RequireVerifiedEmail.tsx` membungkus rute fitur akun: `/periksa`,
  `/hasil/:id`, `/komunitas`, `/riwayat`, `/dashboard`, `/dashboard/admin`. Akun masuk yang belum
  terkonfirmasi dialihkan (dengan `replace`) ke `/verifikasi-email` dan alamat tujuan disimpan di
  `state.from`. Tamu/sesi anonim dan mode demo tidak digerbangi; `/verifikasi-email`, `/masuk`,
  `/daftar`, `/pengaturan`, dan jalur publik tetap terbuka.
- Halaman verifikasi tidak lagi menawarkan "Lanjutkan tanpa verifikasi"; tersedia tombol keluar
  aman. Label status akun memakai `Belum verifikasi email` / `Terverifikasi`.
- Status diperbarui lewat `user.reload()` (tombol periksa status, pemeriksaan senyap saat
  dibuka/muncul tab lain) dan `applyActionCode` untuk tautan verifikasi. Setelah terverifikasi,
  `getIdToken(true)` diminta ulang agar klaim `email_verified` di token ikut diperbarui.
- Sisi server: `firestore.rules` kini menuntut `isOwner(userId) && isVerifiedEmailUser()` untuk
  `users/{userId}` dan `users/{userId}/scans/{scanId}`; `requireAccount()` di `functions/`
  menolak token tanpa `email_verified == true`. **Rules harus di-deploy** sebelum client ini;
  tanpa rules baru, pemilik yang terverifikasi tetap aman tetapi akun belum terverifikasi masih
  bisa membaca dokumennya sendiri dari klien yang dimodifikasi.

### Username unik per akun

- Sumber kebenaran keunikan adalah Firestore, bukan klien. Pendaftaran membuat klaim dalam satu
  `runTransaction`: `usernames/{username}` (`uid`, `createdAt`) dan `users/{uid}/username/current`
  (`username`, `uid`, `createdAt`). Kedua tulisan saling mengikat lewat `existsAfter`/`getAfter`,
  sehingga tidak ada registry tanpa pointer maupun pointer tanpa registry.
- Kebijakan format ada di `web/src/lib/usernames/policy.ts`: dipangkas, huruf kecil, 3–20 karakter
  `a–z 0–9 _`, tanpa spasi. Spasi dan simbol menghasilkan pesan yang spesifik.
- Urutan pendaftaran dipertahankan: validasi field → validasi username → verifikasi token
  Turnstile di backend → buat akun Firebase Auth → klaim username atomik → kirim email verifikasi →
  tetap di `/verifikasi-email` sampai email terkonfirmasi. Profil (`users/{uid}`) baru ditulis
  setelah terverifikasi; nilai `username` di profil disalin dari pointer klaim saat sinkron.
- Kegagalan klaim memicu rollback akun yang baru saja dibuat (`deleteUser` hanya untuk sesi yang
  sama, akun belum terverifikasi, dan klaim belum terpasang). Bila rollback gagal, sesi ditutup dan
  pengguna diminta masuk ulang untuk memasang username di `/pengaturan`.
- Akun lama (sebelum fitur ini) tidak diberi username otomatis. `/pengaturan` menampilkan kartu
  "Username akun": kosong → formulir pasang mandiri; sudah ada → hanya dibaca. Nama tidak dapat
  diganti atau dilepas melalui klien (rules menolak `update` dan `delete`).
- Migrasi data yang diperlukan: tidak ada penulisan massal yang wajib. `usernames/*` dan
  `users/{uid}/username/current` tumbuh sesuai akun yang mendaftar atau memasang username sendiri.
  Fields `username` pada profil lama tidak wajib; sinkron berikutnya mengisinya dari pointer, dan
  aturan `validProfileDocument` kini mengizinkan key `username` (harus `null` atau nama kanonis).
- **Deploy rules sebelum client versi ini:** `firebase deploy --only firestore:rules`. Tanpa rules
  baru, penulisan `usernames/{username}` akan ditolak total (jalur default-deny) sehingga
  pendaftaran gagal — itu perilaku aman, bukan celah. Suite rules yang dapat direproduksi ada di
  `functions/test/firestoreRules.test.ts` dan dijalankan dengan `npm run test:rules` dari root repo.
  Perintah itu membutuhkan JDK (Java 11+) pada `PATH` dan Firebase CLI; tanpanya seluruh test
  di-skip dan statusnya harus dicatat **belum diverifikasi**, bukan lulus.

### Riwayat per akun

- `/riwayat` hanya membaca dokumen Firestore milik UID yang sedang masuk. Tamu dan sesi anonim
  dialihkan ke `/masuk` dengan alamat balik; setelah masuk, pengguna kembali ke halaman yang
  diminta.- Saat keluar atau berganti akun, data akun sebelumnya langsung disembunyikan; tidak ada
  riwayat akun lama yang tersisa di tampilan.
- Riwayat lokal yang dibuat sebelum masuk tetap berada di perangkat dan **tidak** otomatis
  dipindahkan, diatribusikan, atau dihapus saat masuk ke akun Firebase. Riwayat akun hanya
  berisi pemeriksaan yang tersimpan setelah masuk. Tidak ada migrasi otomatis.

### Batas operasional

- Metrik dan tren dashboard admin dihitung hanya dari data yang benar-benar dimuat: antrean
  maksimal 500 laporan dan 500 dokumen moderasi; UI memberi peringatan bila batas tercapai.
  Tren tujuh hari memakai timestamp `createdAt` asli dalam zona WITA; tanggal tidak valid
  diabaikan, bukan diisi angka palsu.
- Dashboard Saya tidak memakai ambang minimum pemeriksaan; total, distribusi risiko, pola, dan
  riwayat terbaru berasal dari riwayat akun yang dimuat.
- Antrean memakai collection-group query `reports` dengan filter `reporterKey`. Bila project
  produksi meminta indeks collection-group saat pertama dipakai, buat indeks yang ditawarkan
  Console; `firestore.indexes.json` di repo tetap kosong dan emulator tidak menegakkan indeks.
- Tidak ada Blaze, Functions, Cloud Scheduler, atau layanan berbayar lain pada jalur ini.
  Tidak ada penghapusan laporan publik dari aplikasi; moderasi hanya mengubah status.

### Hasil verifikasi V6 (2026-10-25–26, mesin penulis)

- `npm --prefix web run typecheck`: lulus.
- `npm --prefix web run lint`: 0 warning, 0 error.
- `npm --prefix web test`: 48 berkas, **422 tes** lulus (termasuk tes baru dashboard, admin,
  riwayat, label/transisi, dan statistik).
- `npm --prefix web run build`: lulus; inspeksi bundle lulus.
- Lab rules V6 terisolasi: **44/44** lulus (izin admin, allowlist, isolasi publik/privat,
  binding batch, transisi, append-only, penolakan non-admin).
- Regresi rules URL laporan V5 pada port terpisah: **38/38** lulus.
- `npm run verify:ui`: **438** pemeriksaan lulus.
- `npm run test:e2e`: **221** pemeriksaan lulus.
- Harness browser admin dengan emulator Auth + Firestore: **20/20** lulus, termasuk keputusan
  moderasi nyata, audit/privat/publik, pengalihan riwayat, URL panjang di ponsel, dan salin URL.
- Tidak ada deploy Hosting, rules, Functions, Worker, atau penulisan data produksi.

---

## M. Penyimpanan lokal browser (delapan kunci localStorage)

Semua kunci ditulis melalui pembungkus yang sama: bila `localStorage` tidak tersedia atau kuota
penuh, data tetap hidup di memori tab tersebut dan antarmuka tidak error. Tidak ada nilai
rahasia perangkat, token Firebase, atau isi clipboard yang masuk ke delapan kunci ini.

| Kunci | Isi | Batas | Musnah ketika |
| --- | --- | --- | --- |
| `veriguard.scans.v1` | hasil pemeriksaan (mode tautan/pesan) + indikator | 30 entri **dan 90 hari** (`SCAN_RETENTION_MS`) | hapus satu/hapus semua di Riwayat & Pengaturan, data situs dibersihkan |
| `veriguard.multiSourceReports.v1` | laporan gabungan 8 agen per `scanId` | 30 laporan terbaru | hapus riwayat (`clearScanReports`) atau bersihkan data situs |
| `veriguard.websiteAnalyses.v1` | hasil analisis situs per `scanId`; `target`, `behavior.initialUrl`, dan rincian probe yang sensitif disamarkan lebih dulu | 20 analisis terbaru | hapus riwayat (`clearSiteAnalyses`) atau bersihkan data situs |
| `veriguard.local-session.v1` | `displayName` sesi demo lokal + waktu mulai | 1 sesi | keluar dari sesi demo |
| `veriguard.preferences.v1` | `defaultScanMode` dan `reduceMotion` | 1 objek | "Hapus semua data lokal" di Pengaturan (`resetPreferences`) |
| `veriguard.pendingSync.v1` | **hanya** `uid` pemilik + daftar `scanId` yang belum sampai ke akun (tidak ada URL, tidak ada isi pesan) | 30 ID terbaru | terkirim ke akun, dihapus pengguna, atau "Hapus semua data lokal" |
| `veriguard.login-client.v1` (VGL-38) | pengenal sumber acak per perangkat (`web-` + 32 heksadesimal); bukan identitas, bisa diganti atau dihapus | 1 nilai | "Hapus semua data lokal" (`clearLoginGuardLocalState`) |
| `veriguard.login-cooldown.v2` (VGL-38 → VGL-39A) | cermin cadangan keputusan gerbang: `endsAt` (jam server), tingkat, kegagalan dalam siklus berjalan 0..2 — tanpa email, tanpa IP. Kunci lama `veriguard.login-cooldown.v1` ditinggalkan (semantik berubah, tidak ditafsirkan ulang) | 1 sumber | cooldown habis, login berhasil, atau "Hapus semua data lokal" |

Belum ada retensi waktu untuk laporan agen, analisis situs, sesi demo, dan preferensi; hanya
riwayat pemeriksaan yang punya batas 90 hari, di samping pemangkasan berdasarkan jumlah pada
semua penyimpanan. "Hapus seluruh riwayat" memanggil `clearScans`/`clearScanReports`/
`clearSiteAnalyses` (atau penghapusan dokumen akun), sedangkan "Hapus semua data lokal"
menambah `resetPreferences()`, pengakhiran sesi demo, `clearPendingSync()`, dan
`clearLoginGuardLocalState()` — jadi delapan kunci ikut bersih. Penghapusan itu dijalankan
`web/src/lib/storage/localData.ts` lewat modul
pemilik tiap kunci, **tanpa** `localStorage.clear()`, tanpa memandang status login atau sumber
riwayat yang sedang aktif, dan tanpa menyentuh penyimpanan milik SDK (IndexedDB
`firebaseLocalStorageDb`, cookie tantangan Turnstile) maupun dokumen Firestore.

### Penggabungan riwayat perangkat dan retensi akun (VGL-17)

Empat perilaku yang sebelumnya merugikan pengguna, sekarang:

1. **Riwayat tamu ikut naik ke akun setelah email terverifikasi.**
   `web/src/lib/scans/localHistoryMigration.ts` dijalankan `useScanHistory` **sebelum**
   `listCloudScans`, sehingga daftar pertama yang dilihat pengguna sudah lengkap. ID dokumen
   dipertahankan (`setDoc` pada `users/{uid}/scans/{scanId}` memakai `scan.id` perangkat) sehingga
   tautan `/hasil/:id` yang sudah dibagikan atau di-markah tetap sah. Sekali jalan per UID per
   sesi (janji disimpan di `Map`), dan entri yang sudah naik dilepas dari perangkat **hanya
   setelah** Firestore menerima; kegagalan sebagian menahan sisanya di antrean dan dapat diulang
   lewat tombol "Sinkronkan sekarang" di Riwayat. Riwayat lokal UID lain tidak pernah dibaca atau
   dikirim, dan antrean dengan UID berbeda dibuang.
2. **"Hapus semua data lokal" benar-benar menghapus semua kunci aplikasi** (lihat tabel di atas);
   kartu tindakannya tidak lagi disembunyikan untuk akun terverifikasi, dan teks konfirmasinya
   menegaskan bahwa riwayat akun tidak ikut terhapus.
3. **Kegagalan tulis Firestore tidak menghilangkan hasil.** `saveScanForUser()` sekarang
   mengembalikan `{ scan, source, syncError }`. Bila dokumen akun gagal ditulis, salinan tersamar
   tetap masuk `veriguard.scans.v1`, ID-nya diantrekan, dan `ScanPage` membawa `syncNotice` ke
   `ResultPage` (peringatan "Hasil tersimpan di perangkat ini"). Status sukses sinkronisasi tidak
   pernah ditampilkan saat Firestore menolak; `useScan` hanya membaca salinan perangkat untuk ID
   yang memang ada di antrean UID tersebut.
4. **Retensi riwayat akun** — lihat bagian berikutnya.

### Kebijakan retensi riwayat akun (VGL-17, belum diterapkan di produksi)

Periode yang dipakai **sama dengan retensi perangkat yang sudah ada dan sudah didokumentasikan
sejak VGL-12**: maksimal **30 entri** dan **90 hari** per pengguna. Tidak ada periode baru yang
diputuskan diam-diam; konsekuensinya sengaja identik dengan apa yang sudah berlaku di perangkat
agar satu angka berlaku untuk dua-duanya.

- Mekanisme: **delete-on-write**, dijalankan dari klien. `pruneCloudScans(uid)` di
  `web/src/lib/firebase/scans.ts` membaca riwayat pemilik (sudah diurutkan `createdAt` desc),
  menandai entri ke-31 dan seterusnya serta entri yang `createdAt`-nya lebih tua dari 90 hari,
  lalu menghapusnya dalam `writeBatch` (maks 450 operasi per batch). `scheduleRetentionPass(uid)`
  memanggilnya sekali per UID per sesi, tanpa menunggu hasil (`fire-and-forget`) sehingga hasil
  pemeriksaan tidak melambat.
- `limit(30)` **bukan** mekanisme penghapusan: `listCloudScans` memang hanya menampilkan 30
  terbaru, tetapi dokumen lama tidak pernah terhapus hanya karena tak terbaca. Justru itu alasan
  `pruneCloudScans` membaca tanpa `limit` dan menghapus berdasarkan usia maupun jumlah.
- Rules tidak diubah. `users/{uid}/scans/{scanId}` sudah memberi `allow read, delete` kepada
  pemilik yang emailnya terverifikasi, jadi penghapusan oleh klien sah dan tetap tidak dapat
  menyentuh dokumen milik UID lain.
- Alternatif **Scheduled Functions / Firestore TTL belum diaktifkan**: keduanya membutuhkan paket
  Blaze (billing). Sesuai batasan tugas, tidak ada billing, tidak ada deploy Functions, dan tidak
  ada penghapusan massal terhadap Firestore produksi. Yang tersedia sekarang hanya rancangan ini,
  implementasi klien, dan tes lokal.
- Batas yang perlu disetujui sebelum publik: pemangkasan hanya terjadi ketika pengguna membuat
  pemeriksaan baru atau membuka riwayat saat terverifikasi. Akun yang berhenti memakai aplikasi
  menyimpan dokumennya selamanya sampai rules/automasi pihak server diberlakukan (butuh Blaze
  untuk Scheduled Functions). Kebijakan ini juga berarti riwayat lama hilang tanpa pemberitahuan
  sebelumnya — sama seperti di perangkat, dan bukan fitur yang bisa dimatikan per pengguna.


### Penyamaran saat disimpan (VGL-12)

Riwayat mode pesan sudah lama menyamarkan isi pesan kecuali pengguna mengizinkan penyimpanan
penuh. Mode tautan sebelumnya menyimpan **URL apa adanya**, termasuk parameter `?token=...`,
kredensial di `user:pass@host`, dan jalur reset/undangan, padahal `displayTarget` di layar hanya
menampilkan host+path. Sekarang:

- `web/src/lib/scanners/privacy.ts` — `redactSensitiveUrlForStorage()` membuang userinfo,
  seluruh query, dan fragment, serta mengganti segmen jalur yang berbentuk JWT/token;
  `sensitiveUrlFragments()` + `redactSecretFragments()` menyapu potongan sensitif yang ikut
  tertulis di teks lain (indikator, rincian teknis, ringkasan).
- `web/src/lib/storage/scanStore.ts` — `toStoredScan()` hanya mengubah **salinan yang disimpan**;
  objek yang dipakai sesi berjalan tetap memegang teks asli, jadi skor, indikator, dan
  pemeriksaan yang sedang berlangsung tidak berubah. Entri lama yang terlanjur lengkap
  disamarkan saat riwayat dibaca dan langsung ditulis ulang sekali (cek bentuk titik-tetap
  mencegah penulisan berulang).
- `web/src/lib/scans/saveScan.ts` — salinan yang dikirim ke dokumen Firestore milik akun lewat
  `saveScanForUser()` memakai `toStoredScan()` yang sama.
- `web/src/lib/scanners/reportStore.ts` — laporan dengan `sensitiveUrl: true` disimpan dengan
  `target` yang sudah disamarkan, dan `notes`/`conflicts` disapu dari potongan sensitif.
- `web/src/lib/website/analysisStore.ts` — analisis situs yang terlanjur dijalankan pada URL
  sensitif disimpan dengan `target`, `behavior.initialUrl`, dan rincian probe yang sudah
  disamarkan (hex/redirect lain tidak dijamin bersih — lihat batas di bawah).
- `web/src/pages/ResultPage.tsx` — pesan "Sebagian alamat disamarkan sebelum disimpan" muncul di
  halaman hasil. Selama halaman dibuka tepat setelah pemeriksaan berjalan, target analisis situs
  masih diambil dari laporan navigasi (`stateReport.target`); hasil yang dibuka kembali dari
  riwayat memakai salinan yang sudah disamarkan.

Batas yang tersisa dan belum diselesaikan: penyamaran terjadi **setelah** analisis heuristik,
sehingga URL asli pernah singgah di memori tab (tidak pernah ke jaringan bila agen eksternal
tidak diminta); riwayat yang dibuka kembali tidak dapat dipakai untuk menganalisis ulang jalur
yang sudah dipotong, pengguna harus memeriksa ulang URL-nya; pemotongan 90 karakter pada
`displayTarget` dapat menyisakan sebagian awal token bila jalur sangat panjang (potongan utuh
sudah disapu); dan rantai redirect pada hasil analisis situs tidak ikut disapu, hanya
`target`, `behavior.initialUrl`, dan rincian probe. Retensi 90 hari berarti hasil lama hilang
dari perangkat tanpa pemberitahuan sebelumnya — bukan fitur yang bisa dimatikan per pengguna.

---

## N. Inventaris kredensial (tersamar) dan daftar rotasi manual

Perintah: `npm run audit:credentials` (skrip `scripts/audit-credentials.mjs`). Skrip hanya
mencetak **nama variabel, panjang, bentuk, berkas sumber yang membaca, dan ID objek Git**.
Nilai, sebagian nilai, maupun prefix tidak pernah dicetak. Tambahkan `-- --no-history` untuk
melewati pemindaian objek Git (pemindaian penuh ± 1 menit untuk 1.150 objek).

### Berkas yang memuat nilai

| Berkas | Dilacak Git? | Isi |
| --- | --- | --- |
| `functions/.env` | tidak (`.gitignore`) | 3 kunci provider terisi, 4 kosong/legacy |
| `server/.env` | tidak | 13 variabel rahasia terisi + konfigurasi non-rahasia |
| `web/.env.local` | tidak | konfigurasi klien Firebase + site key Turnstile (nilai publik) |
| `web/.env.development.local` | tidak | hanya URL emulator |
| `web/.env.production.local` | tidak | URL Worker + site key Turnstile |
| `workers/.dev.vars` | tidak | salinan kunci provider untuk `wrangler dev` |

Yang dilacak Git hanyalah templat `*.example`. `git ls-files` pada HEAD tidak memuat satu pun
berkas environment nyata.

### Bukti riwayat Git (di mesin ini, 2026-10-31)

Dipindai: 1.032 blob terjangkau ref + 118 blob dangling = 1.150 objek. Hasil:

- **Tidak ada** nilai environment aktif yang terjangkau dari `master`,
  `release/v6-security-hardening`, maupun `backup/pre-remediation-20261031`.
- Satu blob dangling `8317d39d6db97899d380158e88f90f4c47fe9584` (576 byte, snapshot lama
  `workers/.dev.vars`) memuat nilai **URLSCAN_API_KEY**, **VIRUSTOTAL_API_KEY**, dan
  **THREATFOX_API_KEY** yang sama dengan nilai yang masih dipakai sekarang. Blob itu tidak
  terjangkau ref mana pun (`git log --all --find-object` kosong) tetapi masih ada di objek
  lokal.
- Rantai uji `functions/test/*.test.ts` memuat deretan berpola `AIza…` sepanjang 40 karakter;
  sudah dibandingkan dengan seluruh nilai nyata dan **tidak sama** — itu fixture sintetis.

### Temuan tambahan

- `CYBERSCAN_API_KEY` dan `URLSCANNER_API_KEY` dulu terisi di `server/.env` dan `workers/.dev.vars`
  tanpa dibaca sumber aktif mana pun. Sejak VGL-26 (2026-11-01) kedua baris itu **sudah dihapus dari
  permukaan lokal**; `server/src/env.ts` memang selalu mengabaikan nama di luar `KNOWN_SERVER_KEYS`,
  dan Worker produksi tidak pernah memuat binding dengan kedua nama itu. Entri pada daftar nama
  terlarang `web/scripts/inspect-bundle.mjs` **sengaja dipertahankan** sebagai penjaga kebocoran
  (kalau nama itu muncul lagi di bundle, uji tetap gagal). Pencabutan di sisi penyedia masih
  tindakan pemilik. Penyedia `URLSCANNER_API_KEY` teridentifikasi: **URLScanner.online**
  (`urlscanner.online`, header `X-API-Key`) — adaptor `urlscanner.ts` pernah ada di working tree,
  tidak pernah ter-commit, dan `README.md` mencatat Google Safe Browsing menggantikannya. Penyedia
  `CYBERSCAN_API_KEY` **tidak dapat dipastikan dari repo**: yang tersisa hanya nama variabel, dan
  bentuknya (45 karakter base64url polos) tidak cocok dengan penerbit mana pun yang dikenal proyek.
- `SAFE_BROWSING_API_KEY` dan `URLHAUS_API_KEY` kosong dan tidak dipakai; `server/src/env.ts`
  mengabaikan nama di luar `KNOWN_SERVER_KEYS`, jadi aman dibiarkan.
- `VITE_FIREBASE_API_KEY` dan `VITE_TURNSTILE_SITE_KEY` adalah nilai klien publik by design;
  bukan item rotasi untuk kerahasiaan, tetapi jangan dianggap sebagai otentikasi.

### Daftar tindakan manual (belum dilakukan oleh kode atau agen)

Rotasi/cabut, urut dari yang paling beralasan:

1. **urlscan.io API key** — pernah masuk objek Git lokal yang masih dapat dibaca.
2. **VirusTotal API key** — sama seperti di atas.
3. **ThreatFox API key** — sama seperti di atas.
4. **Cloudflare Turnstile secret key** (`TURNSTILE_SECRET_KEY`) — tidak ditemukan di objek Git;
   rotasi hanya bila ada dugaan kebocoran jalur lain (log, CI, berbagi terminal).
5. **Cloudflare API token + account id** (Radar URL Scanner) — cek scope token: idealnya hanya
   Radar/URL Scanner, bukan account-wide; cabut bila scope lebih lebar dari kebutuhan.
6. **AlienVault OTX**, **OpenPhish**, **Hybrid Analysis**, **Google Safe Browsing v5** — tidak
   ditemukan di objek Git; rotasi berkala sesuai kebijakan provider, bukan karena temuan ini.
7. **CYBERSCAN_API_KEY / URLSCANNER_API_KEY** — kedua baris deklarasi sudah dihapus dari permukaan
   lokal oleh VGL-26 (2026-11-01), jadi tidak ada lagi nilai yang tersimpan di repo. Pencabutan di
   dashboard provider tetap tindakan pemilik: penghapusan deklarasi lokal **bukan** pencabutan, dan
   kunci itu baru benar-benar mati setelah penyedia mencabutnya.
8. **Sebelum dan sesudah rotasi 1–3:** `npm run check:keys`. Sebelum, catat sidik-jari yang tampil
   (itulah nilai lama). Sesudah, sidik-jari lama harus hilang dari ketiga permukaan. Skrip tidak
   pernah mencetak nilai, hanya nama, panjang, dan 10 heksa pertama SHA-256 — cukup untuk membuktikan
   rotasi tanpa membocorkan. Secret runtime Worker dan Functions diperiksa dengan
   `npx wrangler secret list` (nama saja); `wrangler secret get` sengaja tidak dipakai.

Luar repo yang perlu diperiksa manual (tidak dapat diaudit dari working copy):

- Token login Firebase CLI di `%USERPROFILE%\.config\configstore\firebase-tools.json` (akun
  Google pemilik proyek).
- Token OAuth `wrangler`/Cloudflare pada profil `%APPDATA%`/`%USERPROFILE%`.
- Isi secret runtime Worker (`wrangler secret list`) — membutuhkan jaringan dan autentikasi,
  jadi **tidak dijalankan** pada fase ini. Nilai yang sama bisa saja terpasang di runtime
  sementara berkas lokalnya tidak pernah di-commit.
- Web API key lama di Firebase Console, dan kunci yang pernah dibagikan lewat chat/CI.

Pembersihan lokal opsional: `git gc --prune=now` membuang blob dangling dari `.git`. Itu **tidak**
membatalkan kebocoran (nilai tetap harus dirotasi) dan termasuk operasi repo yang merusak, jadi
sengaja tidak dijalankan.

## O. CSP: status report-only dan rencana enforcement bertahap

Perintah: `npm --prefix web run verify:csp` (skrip `web/scripts/verify-csp.mjs`). Skrip menyajikan
build produksi **lokal** dengan header persis seperti `firebase.json`, memakai Chromium Playwright
pada 9 rute (`/`, `/periksa`, `/daftar`, `/komunitas`, `/riwayat`, `/edukasi`, `/hasil`,
`/dashboard`, `/dashboard/admin`), mencatat setiap peristiwa `securitypolicyviolation`, lalu
menambah pemeriksaan statis syarat enforcement. Tidak ada layanan produksi yang disentuh.

Hasil 2026-10-31: **0 pelanggaran** pada 9 rute dengan policy report-only saat ini, dan
`upgrade-insecure-requests` memang diabaikan browser selama policy masih report-only (10 pesan
konsol, semuanya directive itu).

### Rencana bertahap (belum ada yang dijalankan di produksi)

| Tahap | Tindakan | Gerbang lolos |
| --- | --- | --- |
| 0 (sekarang) | `Content-Security-Policy-Report-Only` di `firebase.json` | `verify:csp` 0 pelanggaran — tercapai |
| 1 | Putuskan nasib `upgrade-insecure-requests`: pindahkan ke policy enforced, atau ganti `block-all-mixed-content` selama report-only | catatan decision log; tanpa perubahan produksi |
| 2 | **Selesai VGL-20 (2026-11-01).** Kesebelas `style={{ … }}` itu nilainya bergantung data (lebar bar, tinggi batang, `flexGrow`) sehingga tidak ada kelas statis yang identik; solusinya ditulis lewat CSSOM oleh `web/src/lib/styleValue.ts` (ref callback), bukan dipindah ke kelas dan bukan `'unsafe-inline'` | `verify:csp` mencetak "tidak ada atribut style…" — tercapai |
| 2b | Uji enforcement **lokal**: build mode-verify disajikan dan policy yang sama dikirim sebagai `Content-Security-Policy` (bukan report-only) pada 8 rute termasuk `/dashboard` dan `/hasil/<id>` dengan sesi demo | 0 pelanggaran + bar tetap punya lebar benar (rasio 0,5 untuk `width: 50%;` dan 0,72 untuk skor 72) — tercapai; bukan bukti produksi |
| 3 | Pasang header `Content-Security-Policy` (enforced) pada **saluran pratinjau** Firebase Hosting (`hosting:channel:deploy`), bukan situs produksi | 0 pelanggaran pada 9 rute pratinjau + kunjungan nyata |
| 4 | Setelah tahap 3 bersih, pindahkan ke `firebase.json` untuk produksi, tetap dengan report-only sebagai cadangan selama satu rilis | tidak ada laporan pelanggaran dari pengguna |

Penjelasan `verify:csp` menolak (exit 1): pelanggaran runtime apa pun, **atau** header enforced
terpasang sementara masih ada atribut `style={{ … }}` dan policy tidak mengizinkan inline style.
Selama hanya report-only yang terpasang, skrip sengaja lulus — itulah keadaan yang benar hari ini.

Catatan penting dari VGL-20: penulisan gaya lewat CSSOM (`element.style.width = '55%'`,
`style.setProperty(…)`) **tidak** dibatasi `style-src`, sedangkan atribut `style` dari markup dan
`setAttribute('style', …)` **ditolak** peramban. Karena CSSOM menulis serialisasinya kembali ke
atribut `style`, jumlah elemen `[style]` di DOM tidak lagi menjadi proxy yang berguna — yang harus
dipercaya adalah peristiwa `securitypolicyviolation`. Skrip emulasi juga diubah agar mencocokkan
header dengan **jalur permintaan asli** (sama seperti Firebase Hosting), bukan jalur hasil rewrite.

Ada kunci kedua selain `verify:csp`: `web/config/securityHeaders.test.ts` membaca `firebase.json`
dan menuntut setiap host yang benar-benar dimuat peramban tercantum di direktifnya. Ketika
VGL-20 mempersempit `connect-src` dari `https://*.cloudfunctions.net` ke origin proyek sendiri,
battery penuh menangkap bahwa test itu masih mengunci bentuk lama. Perbaikannya mengarah ke
ketat: daftar inventaris diperbarui (plus `content-firebaseappcheck.googleapis.com` yang sebelumnya
belum disebut), dan satu assertion baru menuntut wildcard itu **tidak** muncul lagi. Tidak ada
assertion yang dihapus atau dilemahkan. Artinya perubahan region `asia-southeast2` atau id proyek
di `web/.env*` sekarang akan diingatkan oleh test, bukan oleh pengguna yang gagal memanggil
callable di produksi.

## P. Cache header Hosting dan jalur yang menghasilkan HTML

Fakta yang dibuktikan probe produksi (GET biasa dengan cache-buster): `Content-Security-Policy`
tidak pernah dikirim ke browser — yang ada hanya `…-Report-Only` setelah deploy berikutnya — dan
`Cache-Control` untuk `/` serta `/periksa` adalah `max-age=3600` padahal `/index.html` `no-cache`.
Selisih itu muncul karena Firebase mencocokkan blok `headers` dengan **jalur permintaan asli**,
sebelum rewrite `** → /index.html` berlaku. Konsekuensinya nyata: setelah deploy, pengguna yang
membuka rute SPA bisa memegang HTML lama sampai satu jam, dan HTML itu menunjuk hash aset versi
lama.

`firebase.json` (VGL-20) menambahkan blokir `no-cache` untuk setiap jalur SPA yang dikenal router
(`/`, `/periksa`, `/hasil/**`, `/komunitas`, `/riwayat`, `/edukasi`, `/edukasi/**`, `/masuk`,
`/daftar`, `/verifikasi-email`, `/dashboard`, `/dashboard/**`, `/pengaturan`) alih-alih menaruh
`Cache-Control` di `**`. Alasannya: urutan presedens antar blokir header tidak bisa dibuktikan dari
repo (membutuhkan deploy), sedangkan dengan daftar eksplisit tidak ada satu jalur pun yang cocok ke
`**` dan `/assets/**` sekaligus, jadi tidak ada tebakan tentang blok mana yang menang.

Cara memeriksa sendiri setelah deploy (semua hanya baca):

```powershell
curl.exe -sI "https://YOUR_FIREBASE_PROJECT_ID.web.app/?bust=1"        | Select-String -Pattern "cache-control|content-type|content-security"
curl.exe -sI "https://YOUR_FIREBASE_PROJECT_ID.web.app/periksa?bust=1" | Select-String -Pattern "cache-control"
curl.exe -sI "https://YOUR_FIREBASE_PROJECT_ID.web.app/assets/<hash>.js"| Select-String -Pattern "cache-control"
```

Dua sisa yang sengaja **tidak** ditutup karena menuntut perubahan routing/perilaku SPA: berkas yang
tidak ada di bawah `/assets/` tetap dijawab HTML dengan `immutable` (rewrite menelan permintaan itu),
dan rute tak dikenal (halaman `*`) tetap memakai default satu jam. Pilihan penutupnya adalah
mempersempit rewrite atau menyediakan `404.html`, dan keduanya harus diverifikasi di saluran
pratinjau lebih dulu.

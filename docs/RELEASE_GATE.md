# Gerbang Rilis VERIGUARD AI

Dokumen ini adalah checklist terakhir sebelum aplikasi dianggap siap staging atau publik.
Isinya hanya yang **terbukti oleh perintah yang dijalankan** dan yang **masih menunggu
tindakan manusia**. Tidak ada bagian dari berkas ini yang boleh dibaca sebagai "sudah siap
produksi": build hijau tidak membuktikan kredensial sudah dirotasi, rules sudah di-deploy,
atau policy CSP sudah berlaku.

Diperbarui 2026-11-01 pada branch `release/v6-security-hardening`, mesin penulis. Snapshot tabel
bagian 1 diambil 2026-10-31 di HEAD `3c3affc`; bagian 9 mencatat remediasi keamanan tahap 2
(VGL-20) yang paling baru. Produksi `https://YOUR_FIREBASE_PROJECT_ID.web.app` dan Worker
`https://YOUR_CLOUDFLARE_WORKER_HOST` **tidak disentuh** oleh pekerjaan ini — hanya
pembacaan hanya-baca (`curl -sI`) dan build/saji lokal.

## 1. Gerbang otomatis

Jalankan dari root repo. Hasil di bawah adalah hasil nyata yang dijalankan pada 2026-10-31.

| # | Perintah | Hasil terakhir | Apa yang dibuktikan | Apa yang TIDAK dibuktikan |
| --- | --- | --- | --- | --- |
| 1 | `npm run test:all` | **1.523 lulus, 21 dilewati** — server 41 (5 berkas), functions 611 lulus + 21 skip (23 berkas), workers 102 (9), web 769 (67) | mesin scanner 8 agen dan urutannya, rules-only murni, Worker, UI | `functions/test/firestoreRules.test.ts` **di-skip** tanpa emulator; lihat baris 3 |
| 2 | `npm --prefix web run typecheck`, `npm --prefix server run typecheck`, `npm --prefix workers run typecheck`, `npm --prefix functions run build` | semua lulus | tipe sumber + sumber uji web ikut diperiksa | kebenaran runtime di browser nyata |
| 3 | `npm run test:rules` (butuh JDK di `PATH` + Firebase CLI) | **21/21 lulus** terhadap emulator `demo-veriguard` | `firestore.rules` yang ada di repo ini benar-benar menolak/mengizinkan seperti ditulis: isolasi akun, append-only, batch kirim laporan sah, ikatan `hostname`–authority `reportedUrl`, collection-group hanya admin | rules **produksi**; proyek demo, tanpa data nyata |
| 4 | `node web/scripts/e2e.mjs` | **228 pemeriksaan lulus** | alur browser nyata termasuk URL sensitif tersamar di localStorage | layanan Firebase produksi, pengiriman email |
| 5 | `npm --prefix web run verify:ui` | **438 pemeriksaan lulus** | navigasi, konten, font, responsivitas build produksi lokal | kebijakan header saat enforced |
| 6 | `npm --prefix web run verify:csp` | **0 pelanggaran** pada 9 rute; **tidak ada hambatan inline style lagi** di sumber sejak VGL-20 | policy report-only saat ini tidak memblokir sumber daya yang dipakai aplikasi | bahwa policy enforced aman di produksi — uji enforcement lokal ada di bagian 2.6, bukan bukti produksi |
| 7 | `npm run audit:credentials` | lulus | tidak ada berkas environment nyata di HEAD; 1.263 objek Git dipindai; 0 nilai terjangkau ref; **tidak ada nilai environment aktif di objek Git mana pun** setelah blob `8317d39d…` dibuang lokal (VGL-19) | isi secret runtime Worker (butuh jaringan + login) |
| 8 | `npm run build:all` lalu `npm run verify:release` | build lulus; guard **LULUS** | sumber rilis terlacak Git dan output build tidak tertinggal dari sumber | deploy apa pun |
| 9 | `npm run check:keys` | lulus (ketiga kunci terisi di 3 permukaan lokal); **sidik-jari masih sama di ketiganya** | keberadaan kunci provider valid tanpa nilainya dicetak — hanya nama, panjang, dan sidik-jari SHA-256 10 heksa | bahwa kunci sudah dirotasi; secret runtime Worker dan Functions |

Pembaruan 2026-11-01 (audit VGL-16, hanya berkas web dan rules yang disentuh ulang): suite web
**773 lulus / 67 berkas**, `tsc -b` lulus, `oxlint src` 0 peringatan pada 193 berkas, dan
`npm run test:rules` **22/22 lulus** (satu uji dokumen hasil penyamaran ditambahkan). Angka
`test:all` di baris 1 adalah snapshot 2026-10-31 dan belum dihitung ulang sejak web bertambah
empat uji.

Pembaruan 2026-11-01 (VGL-17, empat perbaikan perilaku penyimpanan — hasil dihitung ulang di
HEAD branch ini setelah kode dan uji baru masuk): `npm run test:all` **1.584 lulus, 22 dilewati**
— server 41 (5 berkas), functions 611 lulus + 22 skip (23 berkas), workers 102 (9 berkas), web
**830 lulus / 72 berkas**; `npm --prefix web run typecheck` lulus, `oxlint` **0 peringatan / 0
kesalahan pada 210 berkas**, `npm run test:rules` **22/22 lulus** terhadap emulator
`demo-veriguard` (uji "riwayat scan adalah milik pemiliknya saja" diperkuat tiga penolakan hapus,
jumlah uji tetap 22), `node web/scripts/e2e.mjs` **228 pemeriksaan lulus**, dan
`npm --prefix web run verify:ui` **438 pemeriksaan lulus**. Tidak ada angka produksi yang berubah:
rules, Hosting, Functions, dan Worker tidak di-deploy.

## 2. Temuan yang sudah ditutup pada fase ini

| Ref | Temuan | Penutup | Commit |
| --- | --- | --- | --- |
| P2 | Rules Firestore diklaim terverifikasi padahal tidak ada yang menjalankan emulator | suite rules dijalankan terhadap emulator dan masuk Git; hasil 21/21 | `f680ec5` |
| VGL-12 | URL lengkap dengan token/parameter rahasia ikut tersimpan di localStorage dan dokumen Firestore milik akun | penyamaran saat disimpan di keempat penyimpanan (`scanStore`, `reportStore`, `saveScan`, `analysisStore`) + retensi 90 hari untuk riwayat pemindaian | `54197d8`, `cd2980d` |
| VGL-13 | Laporan komunitas dapat melabeli dirinya dengan hostname situs lain | `reportedUrlMatchesDeclaredHost()` di rules + `hostnameMatchesUrl()` saat pembacaan; batas jujur didokumentasikan | `bba7a0d` |
| VGL-14 | Inventaris kredensial dan kesiapan CSP tidak dapat diulang dari repo | `scripts/audit-credentials.mjs` (tersamar) dan perluasan `verify-csp.mjs` (9 rute + pemeriksaan statis inline style) | `3c3affc` |
| P1-3 | Batas laju per-IP/per-uid hanya hidup di satu isolate | DO `SCAN_STATE` memang sudah ter-deploy (`238613d`), tetapi VGL-27 membuktikan keputusannya tidak pernah dipakai: `createStateRpc` menyimpan satu stub di closure dan workerd menolak I/O stub itu pada konteks permintaan berikutnya, sementara `catch {}` membuang galatnya dan pemutus arus 30 detik membuat fallback memori lengket per isolate. VGL-28 memperbaiki penyebabnya (stub dibuat per panggilan), menambahkan diagnostik `scan_state_rpc` yang tersanitasi, dan menguji kontrak DO pada workerd sungguhan (`workers/test/durableObjectRuntime.test.ts`, 13 uji). Status: `LOCAL FIXED — PRODUCTION NOT YET VERIFIED` — VGL-28 tidak melakukan deployment | `238613d`; perubahan VGL-28 masih di working tree |
| VGL-16a | Uji retry riwayat yang baru ditambahkan kadang gagal (772/773) tanpa sebab di aplikasi | penyebabnya uji, bukan aplikasi — `waitFor(loading === false)` langsung lolos setelah `retry()` karena status `loading` sudah `false` dari error sebelumnya, jadi error lama ikut terbaca; diganti `act()` + tunggu hasil, dan antrean `mockResolvedValueOnce` diganti implementasi yang dapat dibaca ulang | `435f4de` |

| VGL-17 | Empat perilaku penyimpanan merugikan pengguna sebelum publik: riwayat perangkat tidak pernah masuk akun, "Hapus semua data lokal" tidak tuntas, kegagalan tulis Firestore membuang hasil, dan riwayat cloud tidak punya retensi | penggabungan riwayat per UID dengan ID dipertahankan + antrean `veriguard.pendingSync.v1` (hanya id); `localData.ts` membersihkan enam kunci tanpa `localStorage.clear()`; `saveScanForUser` mengembalikan `{ scan, source, syncError }` dan hasil tetap tampil; `pruneCloudScans` menegakkan 30 entri/90 hari delete-on-write milik pemilik — **tanpa Scheduled Functions, tanpa Blaze** (lihat bagian 8) | `c29c623`, `4e735db`, `3ee4ff9`, `a0b6477` |

| VGL-18 | Nilai analisis internal (fusi risiko layanan situs) tampil sebagai kartu terpisah di setiap menu analisis situs, bukan di blok Internal Reputasi Ancaman | `RiskFusionSummary` diekspor dan dirender satu kali di dalam blok Internal yang sudah ada; pemanggilan di `SiteAnalysisArea` dihapus sehingga nilai tidak dobel. Algoritma, skor, confidence, coverage, tingkat risiko, urutan delapan agen, dan keempat menu situs tidak berubah | `4b3ee3e` |
| VGL-19 | Audit kebersihan repo: kredensial di objek Git lokal, export tak terpakai, duplikasi lintas lapisan, dependency mati, kerja berulang per pemeriksaan/prender | blob rahasia dibuang terarah (bagian 2.5); 12 export/fungsi mati dihapus; tipe `RateLimitDecision` dan batas 16 KiB disatukan; `axe-core` semula dilepas lalu dikembalikan karena ternyata dipakai e2e lewat jalur berkas; indeks feed OpenPhish + bentuk IOC ThreatFox dihitung sekali; `readAll` laporan tidak lagi mengurai JSON di setiap render — rinciannya bagian 2.5 | setelah `4b3ee3e` |

## 2.5 Rincian cleanup lokal (VGL-19)

**Objek Git.** Blob `8317d39d…` (576 B, salinan lama `workers/.dev.vars`) adalah satu-satunya
objek tak terjangkau yang memuat nilai rahasia; ia dihapus sebagai berkas longgar tunggal,
bukan lewat `git gc`. Bukti: 1147 objek terjangkau ref+reflog identik (sha256 daftar objek)
sebelum dan sesudah, `git fsck` 118 → 117 dangling blob, dan `audit:credentials` melaporkan
"tidak ada nilai environment aktif yang ditemukan di objek Git mana pun". Lima blob dangling
lain hanya berisi nama kunci dengan nilai kosong (varian `*.example`).

**Kode mati yang dihapus (12 export).** `web`: `CardHeader`, `CardContent`, `CardFooter`,
`hostnameFromTextLink`, `describeAgentProviders`, `communityBackend`, `type TurnstileAction`.
`functions`: `describeAddressKind`, `categoryLabelOf`, `PAGE_LIMITS`, `formatAge`,
`unavailableCheck`. Masing-masing dibuktikan dengan `grep -rnw` di seluruh `src`, `test`,
`scripts`, dan `docs`: satu-satunya hit adalah baris definisinya.

**Sengaja dipertahankan meski tidak dipakai kode produksi.** `communityFunctionsService.ts`
(alternatif backend dengan uji perilaku sendiri; status jalan-jalan belum pasti),
`web/src/lib/analysis/index.ts` (barrel yang dipakai dua berkas uji), seluruh helper
`reset*/Count*` di Worker dan scanner (dipakai uji), dan skrip `typecheck`/`test:watch`/
`preview` (kemudahan manual). Skrip root `dev` memakai `&` sehingga tidak paralel di
cmd/PowerShell — sudah didokumentasikan, tidak diubah.

**Duplikasi yang disatukan.** Tipe `RateLimitDecision` versi `workers/src/rateLimit.ts`
(identik bidangnya) diganti impor dari `functions/src/state/stores.js`; batas body 16 KiB
diimpor dari Worker (`MAX_BODY_BYTES`) supaya server lokal tidak bisa bergeser dari Worker;
`SERVER_PORT_LOCAL` (ditulis server ke env Worker, tidak pernah dibaca) dihapus.

**Duplikasi yang TIDAK disatukan, dengan alasan.** `functions/src/community/url.ts` vs
`functions/src/scanners/url.ts` (kontrak berbeda: melempar vs mengembalikan `{ok,error}`, batas
panjang berbeda); `riskLevelFromScore` vs `LEVEL_THRESHOLDS` (dua skala level untuk dua objek
risiko yang berbeda — menyatukan berarti mengubah vonis); `formatDuration` di
`MultiSourceReportPanel` vs `siteFormat` (identik, tetapi menggabungkannya mengikat komponen
hasil ke util menu situs tanpa keuntungan terukur); lima formatter tanggal (teks fallback
berbeda-beda dan ikut diuji).

**Dependency.** `axe-core` **tetap dipakai dan tidak jadi dilepas**: audit awal melaporkan
paket itu tanpa pembaca karena pencariannya hanya pola `import`, padahal
`web/scripts/e2e.mjs:12` memuatnya lewat jalur berkas (`node_modules/axe-core/axe.min.js`,
dipakai `page.addScriptTag` di tujuh titik uji aksesibilitas). Kesalahannya tertangkap oleh
`npm --prefix web run test:e2e` yang gagal `ENOENT`, paket dikembalikan, dan
`package.json`/`package-lock.json` kembali identik dengan HEAD. Audit produksi:
`web`/`server`/`workers` 0 kerentanan; `functions` 6 moderat berupa rantai transitif
`firebase-admin → @google-cloud/firestore-api → google-gax/gaxios → rimraf → glob → minimatch`
(GHSA-3g3m-2fjr-6pw4, GHSA-g3hv-75wg-m249) plus `@grpc/grpc-js` (2 tinggi) di bawah dependensi
uji `firebase`. `npm audit fix` tidak dapat memperbaiki apa pun (lockfile tidak berubah);
`--force` berarti menaikkan mayor `firebase-admin`/`firebase-functions` dan tidak dijalankan.

**Performa yang diubah dan terukur.** Pencocokan feed OpenPhish: dari mengurai setiap baris
pada SETIAP pemeriksaan menjadi indeks `Set`+`Map` yang dibangun sekali per unduhan —
40 pemeriksaan pada feed 4.000 baris: 52,9 ms → 2,2 ms, dengan kesamaan hasil ditegakkan di
skrip pengukur dan kini dijaga uji `OpenPhish menghitung kecocokan tingkat hostname…`.
ThreatFox: bentuk IOC (`withoutScheme`/`hostnameOf`) dihitung sekali per istilah, bukan per
baris. `reportStore.readAll`: hasil urai dikunci pada isi penyimpanan, jadi membaca laporan
yang sama tidak lagi memanggil `JSON.parse` pada setiap render.

**Performa yang ditemukan tetapi TIDAK diubah.** Chunk `firebase` 571 kB (±150 kB gzip) dimuat
pada render pertama bahkan untuk pengunjung anonim tanpa konfigurasi, karena
`AuthProvider.tsx` mengimpor `lib/firebase/client.ts` secara statis dan `vite.config.ts`
menempuh semua modul firebase ke satu chunk (`manualChunks`); memecahnya berarti mengubah
alur bootstrap autentikasi dan butuh perubahan + pengujian tersendiri. Sumber daya font
`@fontsource-variable/inter` 7 berkas (220 kB) dipakai penuh dengan `unicode-range`, jadi
peramban hanya mengambil yang dibutuhkan; memangkas ke latin saja mengubah tampilan pengguna
situs lain skrip. `ResultPage.tsx` (699 baris) memang besar, tetapi memecahnya berarti
merombak susunan UI yang sudah disepakati.

## 3. Temuan yang masih terbuka

1. **`urlHash` tidak dapat dibuktikan server.** Security Rules Spark tidak bisa menghitung
   SHA-256, dan URL yang di-hash tidak sama dengan URL yang ditampilkan. Verifikasi sejati
   menuntut penulis tepercaya (Cloud Function/Admin SDK dengan service account) dan field
   verifikasi opsional agar dokumen lama tetap valid. Belum diimplementasikan, belum di-deploy,
   membutuhkan Blaze.
2. **`reporterKey` dapat disalin.** Pseudonim itu terbaca publik di dokumen laporan, jadi
   pemalsuan "jumlah pelapor independen" (framing/dilution) tetap mungkin dan tidak dapat
   ditutup rules.
3. **Rules di repo lebih baru daripada rules produksi.** Aturan feed global dan ikatan
   hostname–authority belum pernah di-deploy. Urutan wajib: rules **sebelum** klien baru,
   karena klien baru menulis lima dokumen yang akan ditolak rules lama.
4. **CSP masih report-only dan belum pernah ditegakkan di produksi.** Penghambat inline style
   sudah ditutup VGL-20 (bagian 9.1): tidak ada lagi `style={{ … }}` di sumber, dan policy yang sama
   divalidasi lokal sebagai enforced tanpa pelanggaran. Yang masih terbuka adalah sisi produksi:
   header produksi hari ini tidak memuat CSP sama sekali, `upgrade-insecure-requests` baru berlaku
   setelah enforcement, dan enforcement belum dicoba di channel preview.
5. **Tiga kunci provider pernah masuk objek Git lokal** (blob dangling `8317d39d…`, tidak
   terjangkau ref maupun reflog mana pun): urlscan.io, VirusTotal, ThreatFox. Sejak VGL-19
   (2026-11-01) objek longgar itu **sudah dibuang dari repositori lokal** secara terarah
   (`rm .git/objects/83/17d39d…`, tanpa `gc`, tanpa rewrite riwayat; 1147 objek terjangkau
   diverifikasi identik sebelum/sesudah) dan `audit:credentials` kini melaporkan nol nilai di
   objek Git. **Rotasi tetap wajib** karena nilai yang sama masih dipakai `server/.env`,
   `functions/.env`, dan `workers/.dev.vars` — objek itu salinan lamanya, bukan sumber tunggal.
6. **Dua kunci terisi tanpa pembaca:** `CYBERSCAN_API_KEY`, `URLSCANNER_API_KEY` di
   `server/.env` dan `workers/.dev.vars`. VGL-26 (2026-11-01) sudah menghapus kedua barisnya dari
   permukaan lokal; pencabutan di sisi penyedia masih tindakan pemilik (belum terjadi).
7. **Retensi 90 hari bersifat senyap.** Entri riwayat lama hilang tanpa pemberitahuan dan tidak
   dapat dimatikan per pengguna; riwayat lama tidak dapat dipakai menganalisis ulang jalur yang
   sudah dipotong. Sejak VGL-17 angka yang sama juga berlaku untuk dokumen akun (30 entri + 90
   hari, dipangkas dari klien saat pengguna menulis/membuka riwayat), sehingga akun yang berhenti
   aktif tetap menyimpan dokumennya sampai automasi sisi server — yang menuntut Blaze — diputuskan.
8. **Provisioning admin manual belum dilakukan** (bagian L `LOCAL_DEVELOPMENT.md`), jadi
   dashboard moderasi belum dapat dipakai di proyek nyata.
9. **Pemeriksaan provider live tidak dijalankan ulang** pada fase ini (butuh jaringan dan
   kunci); angka 6/6 yang lama adalah catatan historis.

## 4. Tindakan manual sebelum staging

- [ ] Rotasi **urlscan.io**, **VirusTotal**, **ThreatFox** di dashboard provider; cabut yang lama.
- [ ] `npm run check:keys` sebelum dan sesudah rotasi: sebelum sebagai catatan sidik-jari lama,
      sesudah sebagai bukti bahwa ketiga permukaan lokal tidak lagi memegang nilai lama. Skrip ini
      hanya mencetak nama, panjang, dan sidik-jari — nilainya tidak pernah keluar.
- [ ] Cabut `CYBERSCAN_API_KEY` dan `URLSCANNER_API_KEY` di dashboard provider. Barisnya di
      `server/.env` dan `workers/.dev.vars` sudah dihapus oleh VGL-26 (2026-11-01), tetapi hapus
      deklarasi lokal **bukan** pencabutan — kotak ini baru boleh dicentang setelah penyedia
      mengonfirmasi kedua kunci tidak aktif lagi.
- [ ] Periksa scope `CLOUDFLARE_API_TOKEN` (idealnya hanya Radar/URL Scanner) dan
      `TURNSTILE_SECRET_KEY`; rotasi bila ada dugaan jalur bocor lain.
- [ ] `wrangler secret list` pada Worker dan sinkronkan nilainya dengan kunci hasil rotasi.
      Pemeriksaan ini butuh login Cloudflare, jadi tidak bisa dilakukan dari repo.
- [ ] Deploy rules ke **proyek staging**, jalankan ulang `npm run test:rules` terhadap proyek itu,
      dan baru kemudian uji klien.
- [ ] Gerbang DO untuk deploy Worker berikutnya: perbaikan VGL-28 (stub per panggilan + diagnostik
      `scan_state_rpc`) baru terbukti di lokal. Setelah deploy, `wrangler tail` **tidak boleh**
      memuat satu pun catatan `rpc_*`, dan uji batas laju 31 permintaan/satu IP harus menghasilkan
      tepat satu `429`. Migrasi `v1` di `workers/wrangler.toml` sudah terpakai dan tidak boleh
      diubah; rollback bila perlu: hapus binding `SCAN_STATE` (Worker kembali ke memori isolate
      tanpa mengubah fitur lain).
- [ ] Provisioning satu UID admin (`admins/{uid}` dengan `active: true`, `role: "admin"`) untuk
      uji moderasi.
- [x] Blob dangling `8317d39d…` dibuang dari objek lokal pada VGL-19 (2026-11-01) dengan
      penghapusan satu berkas objek longgar; `git gc --prune=now` tidak dipakai karena akan
      menghapus 117 blob dangling lain yang tidak berbahaya dan tidak perlu disentuh. Nilai
      di dalam tetap harus dirotasi pemilik akun.

## 5. Tindakan manual sebelum publik

- [ ] Semua kotak pada bagian 4 selesai dan tercatat tanggal/pelaksananya.
- [ ] Pindahkan CSP ke enforced sesuai tahapan bagian O `LOCAL_DEVELOPMENT.md`: hambatan inline
      style **sudah dibereskan VGL-20** (bagian 9.1), sisa tugasnya membaca laporan report-only di
      produksi, enforcement di saluran pratinjau, baru produksi.
- [ ] Setelah deploy Hosting pertama dengan `firebase.json` VGL-20, ulangi probe cache bagian 9.6
      butir 6: semua jalur SPA `no-cache`, aset hash `immutable`, header report-only hadir.
- [ ] Verifikasi email, kuota Spark, dan batas harian diuji dengan akun nyata di proyek produksi.
- [ ] Halaman kebijakan privasi/retensi menyebut penyimpanan lokal 90 hari dan penyamaran URL.
- [ ] Tidak ada data uji emulator/`demo-*` yang tersisa di konfigurasi produksi
      (`VITE_USE_EMULATORS` mati, `ALLOWED_ORIGINS` hanya domain publik).

## 6. Status kesiapan

- **Siap staging secara teknis:** gerbang otomatis hijau dan dapat diulang dari repo.
- **Belum siap publik:** tiga kunci masih harus dirotasi, rules dan klien belum pernah di-deploy
  dari perubahan ini, DO belum diverifikasi di edge nyata, dan CSP masih report-only.
- Tambahan setelah VGL-20: penghambat inline style untuk enforcement **sudah hilang dari sumber**
  dan policy yang sama lolos uji enforced di build lokal (bagian 9.1) — tetapi produksi sampai hari
  ini **tidak mengirim header CSP sama sekali** dan masih meng-cache cangkang SPA rute mana pun
  selama satu jam (bagian 9.2). Keduanya baru nyata setelah deploy, jadi status tetap WARNING
  sampai bukti bagian 9.6 butir 2, 3, 4, 6, dan 7 tertulis.
- Pernyataan "siap rilis publik" **tidak** boleh dibuat hanya karena build dan uji otomatis lulus.

## 7. Temuan audit migrasi penyimpanan (VGL-16, 2026-11-01)

Dua sumber bukti dipisah tegas. **Lokal** = kode di branch ini yang dijalankan di mesin penulis.
**Produksi** = hasil pembacaan hanya-baca (`curl -s`/`curl -sI`) terhadap
`https://YOUR_FIREBASE_PROJECT_ID.web.app/` dan seluruh chunk yang direferensikannya. Tidak ada
perubahan produksi yang dilakukan atau dibuktikan dari luar.

### Status produksi hari ini (pemeriksaan jarak jauh)

- Riwayat akun **sudah** pindah ke Firestore di produksi: chunk `useScanHistory-*` memuat jalur
  cloud/lokal, dan `veriguard.scans.v1` masih ada untuk pengguna tanpa akun terverifikasi.
  Jadi migrasi localStorage→Firestore sebagian sudah live; yang belum live adalah penyamaran.
- **Penyamaran URL VGL-12 belum terpasang.** Mark `[dirahasiakan]` tidak muncul di 42 chunk
  produksi, sedangkan build lokal memuatnya; konstanta retensi 90 hari (`7776…`) juga hanya ada
  di build lokal. Konsekuensinya produksi masih menyimpan URL sensitif utuh di localStorage
  **dan** di dokumen `users/{uid}/scans/{id}`.
- Aturan `hostname`–authority (VGL-13) belum bisa disimpulkan dari bundel; rules produksi tidak
  dapat dibaca tanpa Console, jadi statusnya **belum diverifikasi**.
- Header `Content-Security-Policy-Report-Only` **tidak ada sama sekali** di produksi (0 pada `/`,
  `/index.html`, `/periksa`), padahal `firebase.json` sudah memuatnya. Header keamanan lain
  (X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, HST) sudah live.
- `Cache-Control`: `/` dihidangkan `max-age=3600` sementara `/index.html` `no-cache`. Blok
  `source: "/index.html"` di `firebase.json` tidak cocok untuk permintaan `/`, jadi HTML masuk
  titik masuk SPA dapat bertahan satu jam di peramban setelah deploy.

17 dari 43 chunk punya nama hash identik antara produksi dan build lokal (isi sama); sisanya
berbeda karena perubahan aplikasi. Tidak ada tanda produksi berasal dari cabang lain.

### Urutan deploy yang aman untuk perubahan penyimpanan

1. Deploy **rules** lebih dulu ke proyek staging dan jalankan `npm run test:rules` di sana; rules
   produksi hari ini belum terbukti menolak/menerima bentuk dokumen terbaru. Rules baru hanya
   memperketat (ikatan hostname–authority, `inputStored` sudah dipakai klien produksi), jadi
   klien lama tetap dapat menulis.
2. Deploy **klien** ke saluran pratinjau, lalu jalankan `verify:ui` + `verify:csp` terhadap URL
   pratinjau itu, bukan hanya localhost.
3. Setelah klien ter-deploy, entri lama yang masih berisi URL utuh akan tersamar **saat dibaca
   ulang** (migrasi malas di `readAll` milik `scanStore`, `reportStore`, dan `analysisStore`).
   Tidak ada backfill otomatis; jika
   ingin semua entri dibersihkan tanpa menunggu pengguna membuka riwayat, itu butuh keputusan
   terpisah karena menyentuh data pengguna.
4. Baru setelah itu putuskan header: tambahkan CSP report-only ke produksi (perubahan konfigurasi)
   dan cocokkan blok cache dengan titik masuk `/`.

### Diusulkan, belum diterapkan (butuh persetujuan karena mengubah perilaku pengguna)

> **Diterapkan pada 2026-11-01 lewat VGL-17** — lihat bagian 8. Keempat butir di bawah ini
> dibiarkan apa adanya sebagai catatan temuan; teksnya menggambarkan kondisi sebelum perbaikan.

1. **Riwayat pra-masuk tidak pernah muncul lagi setelah email terverifikasi.** `useScanHistory`
   dan `useScan` memilih satu sumber (`cloud` XOR `local`). Skenario: pengguna memeriksa 20 URL
   sebagai tamu, lalu masuk dan memverifikasi email — riwayat lokal tetap ada di perangkat tetapi
   tidak pernah ditampilkan, dan periksa-ulang ID lokal dari halaman riwayat cloud gagal.
   Opsi: (a) tetap satu sumber dan tambahkan pilihan "gabungkan riwayat perangkat ini"; (b) saat
   verifikasi email pertama, tawarkan mengunggah entri lokal ke `users/{uid}/scans` dengan
   penormalan yang sama seperti penulisan biasa. Keduanya butuh keputusan produk + uji baru.
2. **"Hapus semua data lokal" tidak menghapus riwayat lokal saat pengguna sudah terverifikasi.**
   `clear()` memanggil `clearCloudScans(uid)` dan **tidak** memanggil `clearScans()`, sehingga
   entri pra-masuk tetap tertinggal di `veriguard.scans.v1` padahal tombol menjanjikan penghapusan
   total. Perbaikannya satu baris (panggil `clearScans()` tanpa syarat) tetapi menambah data yang
   benar-benar dihapus, jadi butuh persetujuan.
3. **Kegagalan tulis Firestore menghilangkan hasil.** `saveScanForUser` melempar, `ScanPage`
   menampilkan error, dan hasil analisis (plus kueri 8 provider yang sudah berjalan) dibuang;
   uji `meneruskan kegagalan cloud tanpa diam-diam menyimpan ke lokal` mengunci perilaku ini.
   Alternatif: tampilkan hasil + peringatan "riwayat gagal disimpan" dan antrekan tulis ulang.
4. **Retensi cloud tidak ada.** Riwayat lokal dipangkas 30 entri + 90 hari; dokumen cloud hanya
   dibatasi saat dibaca (`limit(30)`), dokumen lama tidak pernah dihapus. Menambah pemangkasan
   saat tulis mengubah riwayat yang bisa dilihat pengguna; pekerjaan terjadwal butuh Blaze.

## 8. Empat perbaikan perilaku sebelum publik (VGL-17, 2026-11-01)

Kode ditulis dan diuji **lokal saja** di branch `release/v6-security-hardening`. Tidak ada push,
tidak ada deploy Hosting/Rules/Functions/Worker, tidak ada billing atau paket Blaze, dan tidak ada
penghapusan data Firestore produksi. Alur pemindaian, algoritma deteksi, dan 8 provider beserta
urutannya (URLScan, VirusTotal, OpenPhish, ThreatFox, CrowdSec Radar, AlienVault OTX, Hybrid
Analysis, Google Safe Browsing) tidak disentuh.

| # | Masalah | Penutup | Kunci uji |
| --- | --- | --- | --- |
| 1 | Riwayat perangkat tidak pernah masuk ke akun setelah email terverifikasi | `localHistoryMigration.ts` dijalankan sebelum `listCloudScans`; ID dokumen dipertahankan (`setDoc` pada `scan.id`), sekali jalan per UID per sesi, entri lokal dilepas hanya setelah Firestore menerima, sisanya diantre dan bisa diulang lewat tombol "Sinkronkan sekarang" | `localHistoryMigration.test.ts` (10), `useScanHistory.test.ts` (16), `pendingSyncStore.test.ts` (10) |
| 2 | "Hapus semua data lokal" menyisakan riwayat perangkat untuk akun terverifikasi | `localData.ts` menghapus enam kunci lewat modul pemiliknya — tanpa `localStorage.clear()`, tanpa bergantung status login/sumber riwayat; kartu tindakannya tidak lagi disembunyikan; teks konfirmasi menegaskan riwayat akun tidak ikut terhapus | `localData.test.ts` (4), `SettingsPage.test.tsx` (5) |
| 3 | Kegagalan tulis Firestore membuat hasil pemeriksaan hilang | `saveScanForUser()` mengembalikan `{ scan, source, syncError }`; salinan tersamar ditahan di perangkat + diantre, hasil tetap ditampilkan, `ResultPage` memberi peringatan "Hasil tersimpan di perangkat ini", dan status sukses sinkronisasi tidak pernah dipalsukan | `saveScan.test.ts` (13), `ScanPage.test.tsx` (+1), `ResultPage.test.tsx` (4) |
| 4 | Tidak ada retensi riwayat cloud | `pruneCloudScans(uid)` (delete-on-write dari klien) memakai periode yang **sudah** dipakai dan didokumentasikan di perangkat: **30 entri dan 90 hari**; dijadwalkan sekali per UID per sesi; rules tidak diubah karena pemilik terverifikasi sudah punya `allow delete` atas dokumennya sendiri | `scans.test.ts` retensi (5), rules "riwayat scan adalah milik pemiliknya saja" diperkuat dengan tiga penolakan hapus |

**Yang sengaja tidak dibuat:** Scheduled Functions / Firestore TTL untuk pemangkasan, karena
keduanya menuntut paket Blaze. Batas retensi yang berlaku sekarang hanya menyapu akun yang masih
aktif menulis/membuka riwayat; pemangkasan sisi server masih butuh keputusan + billing terpisah,
jadi statusnya rancangan + uji lokal/emulator. `limit(30)` tidak pernah dipakai sebagai mekanisme
penghapusan — `pruneCloudScans` membaca penuh lalu menghapus berdasarkan usia dan jumlah.

**Temuan di luar lingkup, tidak diperbaiki:** `ResultPage.tsx` masih menulis "setelah enam agen
selesai" padahal provider yang berjalan ada delapan. Copy tersebut tidak terkait empat masalah di
atas, jadi dicatat saja untuk persetujuan terpisah.

## 9. Remediasi keamanan tahap 2 dan kesiapan verifikasi produksi (VGL-20, 2026-11-01)

Fase ini tidak melakukan push, deploy, rotasi, atau perubahan secret. Battery penuh dijalankan
dua kali: di HEAD `29abf88` (angka di tabel) dan sekali lagi di HEAD `3127395` setelah test
kunci inventaris CSP ikut diperketat; hasil kedua identik kecuali berkas test yang berubah.
Backup ref `72fad30` tetap utuh.

| Perintah | Hasil VGL-20 |
| --- | --- |
| `npm run test:all` | **1.593 lulus, 22 dilewati** — server 41 (5 berkas), functions 612 lulus + 22 skip (23 berkas), workers 102 (9), web **838 (73)** |
| `npm run test:rules` | **22/22 lulus** (emulator `demo-veriguard`, JDK 26 di `PATH`) |
| `tsc`/`build` per paket | lulus semua; `oxlint src` **0 peringatan / 0 kesalahan pada 203 berkas** |
| `npm run build:all` → `npm run verify:release` | build exit 0; guard **LULUS** |
| `node web/scripts/e2e.mjs` / `verify-ui.mjs` | **228 lulus** / **438 lulus** |
| `npm --prefix web run verify:csp` | **0 pelanggaran**, tanpa hambatan inline style lagi, exit 0 |
| `npm run check:keys` | LULUS — ketiga kunci terisi di setiap permukaan lokal yang ada di disk (nama/panjang/bentuk/sidik saja). LULUS berarti keberadaannya valid, **bukan** sudah dirotasi |
| `npm run inspect:bundle` | LULUS 45 berkas JS; **1.385.466 B** sebelum (VGL-19) 1.385.202 B pada 44 berkas → **+264 B (+0,019 %)**; `ResultPage` 92.909 B (+55 B); chunk baru `styleValue-*.js` |
| `npm run audit:credentials` | lulus; seluruh objek terjangkau ref + 117 blob longgar dipindai (jumlah total sengaja tidak dikutip karena berubah tiap commit) dan **0 nilai environment aktif** di objek Git mana pun |

### 9.1 Sebelas gaya inline menjadi CSSOM (penghambat CSP dihapus)

Kesebelas `style={{ … }}` adalah nilai yang bergantung data — lebar bar skor/kelengkapan, tinggi
batang tren, dan `flexGrow` — jadi tidak ada kelas statis yang bisa menggantikannya secara identik.
Solusinya `web/src/lib/styleValue.ts`: ref callback menulis properti lewat CSSOM. Mekanismenya
diverifikasi lebih dulu dengan pembanding lokal (build halaman uji, policy `style-src 'self'`
ditegakkan): atribut `style` dari markup **ditolak** dan tidak diterapkan, `setAttribute('style', …)`
**ditolak**, sedangkan `element.style.width` dan `style.setProperty(…)` **diterapkan tanpa
pelanggaran**. Itulah alasan `verify:csp` tidak lagi mencetak hambatan.

Uji enforcement menyeluruh (tetap lokal, `firebase.json` tidak diubah menjadi enforced): build
mode-verify disajikan, policy yang sama persis dikirim sebagai `Content-Security-Policy` pada
dokumen, lalu 8 rute dibuka dengan sesi demo + dua riwayat tersimpan. Hasil: **0 pelanggaran,
0 galat konsol**, dan bar benar-benar terisi — `/dashboard` rasio 0,5 dengan serialisasi
`width: 50%;`, `/hasil/csp-high` rasio 0,72 untuk skor 72. Serialisasi CSSOM memang muncul di
atribut `style`; yang dinilai CSP adalah ** parsing inline style dari markup**, bukan keberadaan
atribut, dan itu tidak terjadi. Tiga uji regresi ditambahkan di `web/src/lib/styleValue.test.tsx`
(lebar diterapkan, nilai ikut berubah saat render ulang, elemen `null` ditoleransi).

### 9.2 Cache-Control untuk jalur yang menghasilkan HTML

Probe produksi (GET biasa, bukan perubahan apa pun) membuktikan Firebase mencocokkan `headers`
dengan **jalur permintaan asli**: `/` dan `/periksa` memakai default `max-age=3600` sedangkan
`/index.html` sudah `no-cache`. Rewrite `** → /index.html` akibatnya membuat cangkang aplikasi
semua rute SPA ter-cache satu jam — setelah deploy, pengguna bisa memegang HTML yang menunjuk
hash aset lama. `firebase.json` kini punya blok `no-cache` eksplisit per jalur SPA (`/`,
`/periksa`, `/hasil/**`, `/komunitas`, `/riwayat`, `/edukasi`, `/edukasi/**`, `/masuk`, `/daftar`,
`/verifikasi-email`, `/dashboard`, `/dashboard/**`, `/pengaturan`) sehingga tidak bergantung pada
urutan presedens antar blokir — `/assets/**` tetap immutable dan tidak ada jalur yang cocok ke
keduanya. `web/scripts/verify-csp.mjs` diperbaiki agar meniru pencocokan jalur-asli itu; sebelumnya
ia menormalkan `/` menjadi `/index.html` sehingga bug header kelas ini tidak mungkin terlihat lokal.

Sisa yang **tidak** diubah: aset yang tidak ada (`/assets/x.js`) masih dijawab HTML dengan
`immutable`, dan rute `*` (typo/URL basi) tetap satu jam. Keduanya hanya bisa ditutup dengan
mempersempit rewrite atau menambahkan `404.html` — itu perubahan perilaku SPA, dan menuntut
verifikasi staging yang tidak boleh dilakukan fase ini.

### 9.3 Dependensi: nol perubahan, karena tidak ada jalur patch/minor

`web`, `workers`, `server` bersih (0 kerentanan). `functions` melaporkan 11 (5 high, 6 moderate):

- **5 high** berada di `firebase@13.1.0 → @firebase/firestore@4.19.0 → @grpc/grpc-js@1.9.16`.
  Rantai ini **dev-only** (`--omit=dev` tidak menampilkan `firebase` sama sekali;
  `npm audit --omit=dev` menyisakan 6 moderate, 0 high) sehingga tidak ikut ter-deploy ke Cloud
  Functions. `@firebase/firestore` mem-pin `~1.9.0`, jadi npm tidak boleh menaikkan ke 1.13.6;
  auditor menyarankan `firebase@9.14.0` yang justru **downgrade** dua major.
- **6 moderate** adalah `rimraf@5.0.10 → glob@10.5.0 → minimatch@9.0.9` lewat
  `google-gax@5.0.8` yang diunduh `@google-cloud/firestore-api@0.2.0` (transitif `firebase-admin`).
  Rantai ini ada di pohon produksi. `google-gax@5.0.8` adalah rilis 5.x terakhir dan tetap
  mem-pin `rimraf ^5.0.1`; `rimraf` 5 terakhir (5.0.10) mem-pin `glob ^10`; `glob ^10` mem-pin
  `minimatch ^9` sedangkan perbaikan advisory ada di 11.0.1. Hulu sudah memperbaikinya
  (`@google-cloud/firestore-api@0.7.1` memakai `google-gax ^6` yang tidak bergantung rimraf),
  tetapi `@google-cloud/firestore@9.3.1` dan `9.4.0` sama-sama mem-pin `^0.2.0` — caret pada 0.x
  tidak pernah menyeberang ke 0.4+. `firebase-admin@14.5.0` sudah rilis terbaru.
- `npm audit fix --dry-run` **tidak mengubah apa pun** (added/removed/changed kosong), dan
  `npm update @grpc/grpc-js --dry-run` hanya menggeser salinan dedupe 1.14.6 → 1.14.7 yang tidak
  tersentuh advisory.

Rencana migrasi (butuh persetujuan, tidak dijalankan): (1) tunggu `firebase-admin` membawa
`@google-cloud/firestore` dengan rentang `firestore-api >=0.7` — satu-satunya perbaikan bersih
untuk 6 moderate; (2) untuk 5 high, upgrade major `firebase` devDependency ke rilis yang
mem-pin `@grpc/grpc-js >=1.13.6`, jalankan ulang `test:rules`; (3) `overrides` (`@grpc/grpc-js`,
`minimatch`, `glob`) sengaja **tidak** dipasang: ia memaksa penulisan ulang pin upstream,
berpotensi merusak driver pengujian rules, dan keuntungan nyata nol untuk artefak produksi.
Dampak praktis hari ini juga rendah dan terbatas: advisory grpc-js menyangkut sisi server gRPC
(repo ini tidak pernah menjalankan server gRPC) dan advisory glob/minimatch menuntut pola glob
dari pihak luar — tidak ada satu pun berkas sumber yang mengimpor `glob`/`minimatch`/`rimraf`, dan
SDK `firebase` hanya dipakai `functions/test/firestoreRules.test.ts`, tidak oleh kode `functions/src`.

### 9.4 Kesiapan rotasi tiga kunci (belum ada yang dirotasi)

Pembaca `URLSCAN_API_KEY` / `VIRUSTOTAL_API_KEY` / `THREATFOX_API_KEY` di sumber aktif:
`functions/src/scanners/config.ts` (satu-satunya tempat nilai dibaca menjadi
`urlscanApiKey`/`virusTotalApiKey`/`threatFoxApiKey`), adapter provider
`providers/urlscan.ts` (`requiredEnv` + pesan `not_configured`), `providers/virustotal.ts`,
`providers/threatfox.ts`, tip environment `workers/src/index.ts`, daftar allowlist
`server/src/env.ts` (`KNOWN_SERVER_KEYS`), diagnosis start `server/src/index.ts` dan
`server/src/live-check.ts`. Frontend **tidak** pernah membacanya; `web/scripts/inspect-bundle.mjs`
justru menolak bila nama kunci muncul di hasil build. `wrangler.toml [vars]` bersih dari ketiga
nama (hanya variabel non-rahasia), jadi rotasi tidak menyentuh konfigurasi yang di-commit.

Permukaan yang harus diperbarui manual setelah kunci lama dicabut: `server/.env`, `functions/.env`,
`workers/.dev.vars`, lalu secret Worker produksi (`cd workers && npx wrangler secret put
<NAMA>`). Berkas `functions/.env` tidak punya pemuat konfigurasi sendiri — `functions/src` hanya
membaca `process.env`, dan satu-satunya secret yang dideklarasikan `defineSecret` adalah
`GEMINI_API_KEY`; karena itu produksi Functions **tidak** memegang tiga kunci ini. `npm run
check:keys` memvalidasi keberadaannya lewat nama + panjang + sidik-jari SHA-256 10 heksa, tanpa
pernah mencetak nilai. Status saat ini: ketiga kunci terisi di tiga permukaan dan **sidik-jarinya
masih identik antar permukaan** — artinya rotasi belum masuk; setelah rotasi, sidik-jari harus
berbeda satu per satu dan `check:keys` akan menampilkannya.

### 9.5 Hygiene environment (rekomendasi, tidak ada berkas rahasia yang diubah)

- `SAFE_BROWSING_TERMS_ACCEPTED` ada di `wrangler.toml [vars]` = `"false"` dan di ketiga berkas
  environment, tetapi **nol pembaca di sumber**. Ia memberi rasa aman palsu: siapa pun yang
  mengira variabel ini menjadi gerbang persetujuan Terms Google akan salah. Rekomendasi: hapus
  dari `[vars]` pada deploy berikutnya, atau implementasikan gerbangnya secara nyata — yang kedua
  mengubah perilaku agen 8 dan karena itu di luar lingkup "perubahan sekecil mungkin".
- `SAFE_BROWSING_API_KEY` (nama lama v4) dan `URLHAUS_API_KEY` kosong di semua berkas; `server/src/env.ts`
  tidak mendaftarkannya sehingga tidak pernah sampai ke runtime. Aman dibiarkan, membingungkan
  saat dibaca. Rekomendasi: hapus barisnya manual.
- `CYBERSCAN_API_KEY` dan `URLSCANNER_API_KEY` dulu **terisi tetapi tidak dipakai kode mana pun** dan
  hanya ada di berkas rahasia lokal (tidak ada di `.example`). VGL-26 (2026-11-01) sudah **menghapus
  kedua baris deklarasi itu** dari `server/.env` dan `workers/.dev.vars`, dan `wrangler secret list`
  pada Worker produksi mengonfirmasi kedua nama tidak pernah menjadi binding — jadi tidak ada nilai
  yang tersisa di permukaan repo maupun produksi. Yang **belum** terjadi: pencabutan di sisi penyedia.
  `URLSCANNER_API_KEY` teridentifikasi berasal dari **URLScanner.online** (`urlscanner.online`,
  header `X-API-Key`; adaptor pensiunannya tidak pernah ter-commit dan `README.md` mencatat Google
  Safe Browsing menggantikannya). `CYBERSCAN_API_KEY` **tidak** bisa dipastikan penerbitnya dari repo:
  bentuknya (45 karakter base64url polos) tidak cocok dengan urlscan.io, Google, VirusTotal, ThreatFox,
  maupun token Cloudflare, dan tidak ada catatan layanan di dokumentasi. Rekomendasi tetap: pemilik
  mencabut di dashboard provider masing-masing — untuk CyberScan hanya pemilik yang bisa mengenali
  kuncinya. Catatan kejujuran (tidak dihapus): saat inventarisasi, satu perintah mencetak 3 karakter
  pertama kedua kunci itu ke terminal sebelum penyamaran diterapkan; nilai lengkapnya tidak pernah
  ditampilkan, tidak pernah masuk berkas atau laporan. Karena prefix 3 karakter itu pernah keluar dan
  kunci belum dicabut penyedia, perlakukan kedua nilai sebagai "sebagian terekspos, tidak terpakai".
- Berkas template (`server/.env.example`, `functions/.env.example`, `workers/.dev.vars.example`)
  bersih dari nama-nama mati di atas; tidak ada yang perlu dikoreksi di sana.

### 9.6 Rencana verifikasi produksi (10 butir, dijalankan pemilik akun)

Tidak ada satu pun butir di bawah yang bisa dibuktikan dari repo. Aturan untuk semuanya: jangan
menempel nilai secret ke terminal, log, tangkapan layar, atau percakapan; jangan jalankan
`wrangler secret get` atau `firebase functions:secrets:access <NAMA>` untuk melihat isi — daftar
nama dan sidik-jari sudah cukup.

1. **Inventaris secret Worker.** `cd workers && npx wrangler secret list` harus menampilkan nama
   `URLSCAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `THREATFOX_API_KEY` beserta `OPENPHISH_API_KEY`,
   `OTX_API_KEY`, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `HYBRID_ANALYSIS_API_KEY`,
   `GOOGLE_SAFE_BROWSING_API_KEY`, `TURNSTILE_SECRET_KEY`. Bukti yang cukup: daftar nama.
2. **Rotasi tiga kunci** (urlscan.io, VirusTotal, ThreatFox) di dashboard provider, lalu cabut yang
   lama. Bukti: provider menampilkan kunci baru aktif dan kunci lama berstatus dicabut.
3. **Salin kunci baru ke tiga permukaan lokal** (`server/.env`, `functions/.env`,
   `workers/.dev.vars`), lalu `npm run check:keys`. Sidik-jari lama yang harus lenyap: urlscan
   `dacf54602f`, VirusTotal `265f2d3736`, ThreatFox `4583aa6fc3`. Setelah rotasi, ketiga permukaan
   boleh (dan sebaiknya) memakai nilai yang sama, tetapi tidak boleh lagi cocok dengan sidik-jari
   lama.
4. **Deploy Worker** (`cd workers && npx wrangler deploy`) sambil `npx wrangler tail` di terminal
   lain, lalu jalankan satu pemeriksaan tautan sungguhan. Bukti: log menunjukkan kedelapan agen
   dipanggil dan tidak ada `auth_failed`/403 dari provider — sinyal bahwa kunci lama masih dipakai
   atau rotasi belum tersalin.
5. **Perilaku Worker produksi** pasca-deploy: `curl -s -X POST -H 'content-type: application/json'
   --data '{}' https://YOUR_CLOUDFLARE_WORKER_HOST/` membalas `consent_required`;
   `curl -s -X OPTIONS -H 'origin: https://example.com' -D -` ditolak 403; body >16 kB dibalas 413.
   Ketiga bentuk ini sudah diverifikasi hari ini dan harus tetap sama.
6. **Deploy Hosting** (`firebase deploy --only hosting`) agar `firebase.json` yang sekarang berlaku,
   lalu probe header: `curl -sI https://YOUR_FIREBASE_PROJECT_ID.web.app/?bust=1` dan untuk
   `/periksa`, `/dashboard` → `Cache-Control: no-cache`; `/assets/<hash>.js` asli →
   `public, max-age=31536000, immutable`. Hari ini produksi **tidak mengirim header CSP sama sekali**
   (dibuktikan dengan cache-buster); setelah deploy harus ada `Content-Security-Policy-Report-Only`.
7. **Baca laporan report-only sebelum menegakkan.** Tunggu 24–48 jam pemakaian nyata, kumpulkan
   pelanggaran (console/DevTools atau `report-to` bila ditambahkan), baru pindahkan policy ke
   enforced di **channel preview** (`firebase hosting:channel:deploy <nama>`) dan ulangi
   `npm --prefix web run verify:csp` + perjalanan manual. `web/scripts/verify-csp.mjs` sudah
   membuktikan bahwa sumber saat ini tidak menyisakan inline style, tetapi itu lingkungan lokal.
8. **Urutan rules–klien.** `firestore.rules` di repo lebih baru daripada rules produksi
   (bagian 3 nomor 3). Wajib `firebase deploy --only firestore:rules` **sebelum** klien versi ini
   naik, karena klien menulis lima dokumen yang ditolak rules lama.
9. **Nasib Functions.** `firebase functions:list` untuk memastikan `analyzeContent`, `healthCheck`,
   dan `scanUrlMultiSource` benar-benar ter-deploy atau tidak. Bila `scanUrlMultiSource` aktif,
   ia membaca `process.env` dan satu-satunya secret yang dideklarasikan kode Functions adalah
   `GEMINI_API_KEY` — jadi jawaban yang diharapkan adalah seluruh agen `not_configured`.
   Keputusan yang diperlukan: pasang secret Functions, atau hapus jalur duplikat itu.
10. **Bukti akhir fase.** Setelah rotasi dan deploy: `npm run audit:credentials` (nol nilai aktif di
    objek Git, dan nilai lama tidak muncul lagi di permukaan mana pun), `npm --prefix web run
    inspect:bundle` + cocokkan hash di `index.html` produksi dengan hasil build, lalu satu
    pemeriksaan tautan ujung ke ujung dari domain produksi. Status "aman" hanya boleh dinyatakan sesudah
    butir 2, 3, 4, 6, dan 7 punya bukti tertulis.

### 9.7 Audit per direktif CSP

Policy dibaca baris per baris, bukan dinilai dari kelulusan build.

| Direktif | Isi | Putusan VGL-20 |
| --- | --- | --- |
| `default-src` | `'self'` | tetap — jaring pengaman untuk direktif yang tidak disebut |
| `base-uri`, `object-src`, `frame-ancestors`, `manifest-src`, `form-action` | `'self'` / `'none'` | tetap; konsisten dengan `X-Frame-Options: DENY` yang sudah dikirim |
| `script-src` | `'self'` + challenges.cloudflare.com + www.google.com + apis.google.com | tetap; dibuktikan 0 pelanggaran di 9 rute. Tidak ada `'unsafe-inline'` dan tidak perlu `'wasm-unsafe-eval'` (tidak ada WASM di bundle) |
| `style-src` | `'self'` | **kini terpenuhi tanpa inline style** (9.1); tidak perlu `style-src-attr 'unsafe-inline'` |
| `img-src` | `'self' data:` | tetap; tidak ada gambar jarak jauh di aplikasi |
| `font-src` | `'self'` | tetap |
| `worker-src` | `'self' blob:` | **tidak diubah** meski tidak ada `new Worker(` di sumber. Satu-satunya `createObjectURL` dipakai tautan unduhan riwayat, bukan Worker. `blob:` dibiarkan karena fungsi ekspor bukan rute yang dibuka `verify:csp`; menghapusnya tanpa bukti pratinjau adalah contoh pengencangan yang tidak jelas manfaatnya |
| `frame-src` | `'self'` + dua host Google + Cloudflare Turnstile | tetap; diperlukan widget CAPTCHA dan App Check reCAPTCHA |
| `connect-src` | origin Firebase (identitytoolkit, securetoken, firestore, appcheck ×2, www/apis.google) + Worker | **wildcard `https://*.cloudfunctions.net` dipersempit** menjadi `https://asia-southeast2-YOUR_FIREBASE_PROJECT_ID.cloudfunctions.net`. Alasannya: `getFunctions(app, region)` di klien memakai region `asia-southeast2` (`.env.local` dan fallback kode sama) dan proyek `YOUR_FIREBASE_PROJECT_ID`, jadi callable sah tetap dicakup, sementara jalur exfiltrasi ke domain fungsi proyek lain tertutup. Konsekuensi yang harus diingat: bila region atau proyek berubah, `firebase.json` ikut diubah |
| `upgrade-insecure-requests` | ada | tetap; diabaikan browser selama report-only dan baru diuji saat enforcement |
| `report-to` / `report-uri` | **tidak ada** | dicatat sebagai pekerjaan rumah: tanpa keduanya, pelanggaran hanya terlihat dari console pengguna dan tidak terkumpul di mana pun. Sebelum enforcement, tambahkan `report-to` (dengan `Group` yang didefinisikan lewat header `Report-To`) ke endpoint yang pemilik pilih, supaya tahap 3 punya bukti kuantitatif, bukan hanya tangkapan layar |

Cara pembacaan bukti: `npm --prefix web run verify:csp` (report-only lokal, 9 rute), uji enforced
lokal di bagian 9.1, dan untuk jalur callable Functions satu panggilan nyata di channel pratinjau
sebelum policy produksi ditegakkan.

Cara policy dikunci di repo: `web/config/securityHeaders.test.ts` membaca `firebase.json` dan
menginventarisasi host yang benar-benar dimuat browser. Daftar `connect-src` di test itu semula
menyebut wildcard `https://*.cloudfunctions.net`; setelah persempitannya, battery penuh
menangkap bahwa kunci itu masih menuntut bentuk lama. Assertions **tidak** dilemahkan atau
dihapus — daftar diperbarui ke origin proyek sendiri, `content-firebaseappcheck.googleapis.com`
ikut dimasukkan ke inventaris, dan satu assertion baru menuntut `connect-src` *tidak* memuat
wildcard lagi. Jadi test kini menolak baik pemanggilan callable yang hilang maupun perluasan
kembali ke `*.cloudfunctions.net`. Konsekuensinya tercatat di tabel di atas: region proyek berubah
maka `firebase.json` dan test ini dua-duanya harus ikut diubah.

## 10. Remediasi gabungan audit Qoder + OpenCode (2026-11-04, lokal saja)

Satu rangkaian perbaikan untuk temuan kedua audit. Tidak ada deploy, tidak ada perubahan secret,
tidak ada request ke layanan produksi, dan tidak ada perubahan Git (commit/push/reset) pada fase ini.

### 10.1 Yang ditutup di source code

| Ref | Root cause yang terbukti di sumber | Penutup lokal | Uji yang ditulis |
| --- | --- | --- | --- |
| F1 | Jalur BACA data komunitas (`getCommunityContext`, `listCommunityReports`) memanggil layanan Firestore tanpa `requireAccount`, padahal jalur tulis sudah memakainya; `reviewCommunityReport` tidak menuntut klaim admin | ketiga callable dibungkus handler yang menegakkan `requireAccount` (non-anon + email terverifikasi) dan `token.admin === true` untuk moderasi; handler diekspor supaya diuji tanpa emulator | `functions/test/communityService.test.ts` (+6) |
| F2 | `analyzeContent` memanggil Gemini begitu API key ada: tanpa pemeriksaan auth, tanpa batas per akun, sehingga satu kunci proyek berarti biaya tak terbatas | urutan gerbang: auth, bukan anonim, validasi bentuk, kuota sliding-window 20/jam per UID, kehadiran kunci, baru `fetch` ke origin tetap Gemini | `functions/test/aiCostGuard.test.ts` (5) |
| F4 | Kuota pemindaian hanya dihitung di memori proses Functions; Worker punya store bersama tetapi tidak pernah dipakai untuk kuota | `runMultiSourceScan`/`executeScan` menerima `consumeRateLimit`, dan Worker menyuntik `state.consumeCounter` dengan kunci `scan:<uid>` untuk jalur stream maupun non-stream | `functions/test/scanQuotaInjection.test.ts` (5), `workers/test/worker.test.ts` (+2) |
| F6 | `createDurableTokenRegistry` memperlakukan kegagalan RPC sebagai token baru, jadi anti-replay justru terbuka saat penyimpanan bersama bermasalah | `reserve` mengembalikan `reused` untuk kegagalan storage atau tanpa jawaban, dan `release` tidak apa-apa saat gagal: arah gagalnya menutup, bukan membuka | `workers/test/scanState.test.ts` (harapan dibalik ke `reused`) |
| F7 | `kid` asing memicu satu perbaikan paksa JWKS per permintaan, yaitu amplifier terhadap endpoint JWKS milik pihak lain | satu perbaikan paksa per jendela cooldown untuk token dengan `kid` yang tidak dikenal; keadaan direset antar-uji lewat `resetFirebaseSigningKeys()` | `workers/test/firebaseToken.test.ts` (+2) |
| F9 | Pemeriksaan port hanya berlaku untuk hop redirect, sehingga URL tulisan pengguna boleh menunjuk port layanan (6379/3306/22) dan analysis situs menjadi primitive probe port | hop pertama dibatasi 80/443/8080/8443 lewat `isAllowedInitialPort`; redirect tetap 80/443; hop yang ditolak dicatat sebagai sinyal, bukan dihubungi | `functions/test/websiteGuards.test.ts` (+4), `functions/test/websiteService.test.ts` (+1) |
| F10 | Body provider dibaca tanpa batas (`response.json()` / `.text()`), dan Radar mengurai body SEBELUM status diperiksa | `fetchJson` membaca lewat `readCapped` (cek `content-length`, lalu hitung mengalir dan batalkan saat lewat) dengan batas 2 MiB; `readBoundedJson` untuk Radar; semua jalur dini memakai `discardResponseBody`; oversized berarti kegagalan teknis, bukan tidak ada data | `functions/test/providerResponseLimits.test.ts` (11) |
| W8 | Daftar alamat terlarang punya tiga salinan; salinan `scanners/url.ts` dan `community/url.ts` tertinggal dari tabel prefiks `website/guards.ts` (192.0.0/24, 192.88.99/24, 198.18/15, TEST-NET, IPv4-mapped, Teredo, discard 100::/64, `.internal`, nama metadata) | kedua modul memakai `isBlockedHostname()` dari satu tabel dan salinan lokalnya dihapus; pesan penolakan tidak berubah | `functions/test/addressPolicyConsistency.test.ts` |
| F3 | Teks dokumentasi lama menyiratkan gerbang cooldown adalah penegakan penuh, dan sumber alamat IP untuk server lokal belum punya aturan trust yang eksplisit | `resolveConnectingIp()` (bawaan alamat socket; header edge hanya saat `TRUST_EDGE_CONNECTING_IP=true` DAN peer loopback; bentuk daftar ditolak), App Check init tidak lagi menelan error, komentar `loginGuard.ts` dan `siteProbe.ts` diluruskan | `server/test/connectingIpSource.test.ts` (10) |
| F5 | Keyring state DO tanpa kunci menjawab dari memori actor, dan itu selama ini bisa terbaca sebagai state bersama | dokumentasi batas sebenarnya plus langkah manual pemilik (lihat 10.3) | — |

### 10.2 Temuan yang tidak diubah karena terbantahkan

- **F8, disclosure nama environment.** Yang dikirim ke klien adalah NAMA variabel (misalnya
  `URLSCAN_API_KEY belum dikonfigurasi`), tanpa nilai. `web/scripts/inspect-bundle.mjs` sudah
  menegakkan garis yang sama: yang dianggap bocor adalah `NAMA = nilai` atau objek config
  hasil inlining, bukan nama saja. Status REFUTED; mengubah pesan hanya mengurangi keterbacaan
  bagi operator.
- **`vgl-ssrf-urlscan-redirect-ssrf-001` (OpenCode).** Agen provider tidak pernah menghubungkan
  URL pengguna: origin-nya tetap, `redirect: error`, dan kecocokan laporan memakai field identitas
  `task.url`. Untuk jalur yang benar-benar menghubungkan (analysis situs), jalur Node memasang
  alamat hasil validasi (`host=pin` dan lookup kustom), jadi rebinding tertutup di sumber. Status
  REFUTED untuk klaim SSRF lewat agen urlscan; sisa yang nyata adalah W1 di bagian 10.3.
- **Kueri pencarian urlscan (`q=task.url:"..."`).** Kandidat injeksi kutip terbantahkan oleh bentuk
  keluaran normalisasi: `context.url` selalu hasil `normalizeScanUrl()`, dan serialisasi WHATWG
  mengubah `"` menjadi `%22` serta `\` menjadi `/`. Tidak ada jalur membawa kutip mentah ke kueri,
  jadi tidak ada guard tambahan (Radar sudah memilikinya sebagai penjaga ganda).
- **Syarat token untuk `/auth/login/gate/report`.** Tidak diterapkan: kunci eskalasi adalah
  `ip|clientId`, bukan email, sehingga laporan palsu untuk email korban tidak mengunci siapa pun;
  menuntut token justru membuang pencatatan bagi klien yang `acquire`-nya gagal, dan jalur itu
  sengaja ditangani cermin klien. Alasannya ditulis di `server/src/loginGuard.ts` dekat `report()`.

### 10.3 Sisa pekerjaan yang hanya bisa dijalankan pemilik akun

| Butir | Yang belum bisa dibuktikan dari source | Tindakan pemilik (bukan bagian fase ini) |
| --- | --- | --- |
| W1 | Koneksi Worker tetap dibuka by hostname; resolver runtime bukan resolver DoH yang memvalidasi. `assertStillPinned` hanya mempersempit jendela | egress proxy/pinning di luar runtime, atau konfirmasi daftar blokir egress di platform; setelah itu baru klaim rebinding tertutup bisa dinyatakan |
| W2 | Seberapa sering instance DO `veriguard-scan-state` didaur ulang (menentukan bobot F5 dan F6) | `wrangler tail` atau metrik: `actor_instance_started` dengan `out: volatile` |
| W3 | App Check enforcement dan ambang kunci-otomatis Identity Platform | konsol Google Cloud/Cloudflare; repo ini tidak memuat konfigurasi itu dan tidak ada yang boleh diklaim sudah diatur |
| W4 | CSP produksi masih `Content-Security-Policy-Report-Only` (`firebase.json:68`) dan `report-to` belum ada | tahap enforcement bertahap (bagian 9.7) setelah bukti report terkumpul |
| W5 | Apakah callable komunitas lama dan `analyzeContent` masih dipakai klien | saat ini tidak ada pemanggil di `web/src`; callable tetap ter-deploy dan sudah digembok server-side (F1, F2). Menhapusnya keputusan pemilik |
| W6 | Kuota dan cap billing Gemini proyek | konsol Vertex/Gemini; batas lokal 20/jam per UID tidak memotong tagihan lintas proyek |
| W7 | Klaim admin `token.admin` versus allowlist `admins/{uid}` | pemilik membandingkan UID yang ber-claim dengan dokumen `admins/*`; drift provisioning tidak terlihat dari kode |
| W8 | Perilaku `TRUST_EDGE_CONNECTING_IP` hanya relevan bila proxy berada di mesin yang sama | nyalakan flag hanya untuk topologi itu; bawaannya tetap alamat socket |
| Kunci | Keyring state DO inert tanpa kunci: `SCAN_STATE_KEY_V1` dan `SCAN_STATE_KEY_ACTIVE=v1` lalu deploy | `wrangler secret put` oleh pemilik; tanpa itu DO menjawab dari memori actor |

### 10.4 Status pengujian fase ini (jujur)

Seluruh berkas uji di bagian 10.1 ditulis tetapi BELUM dijalankan di mesin ini. Skill audit
Cloudflare mewajibkan eksekusi target-controlled di dalam sandbox yang ditegakkan sistem operasi;
di Windows (Git Bash) `fs.constants.O_NOFOLLOW` dan `O_NONBLOCK` tidak tersedia sehingga kedua
validator skill keluar dengan kode 1, dan WSL2/container Linux belum terpasang. Sesuai aturan fase
ini, tidak ada perintah test atau build proyek yang dijalankan. Karena itu: **PASS = 0** untuk
perubahan di bagian 10.1, dan `npm run test:all`, typecheck per paket, `verify:csp`, `e2e`, serta
`verify:ui` harus dijalankan ulang di lingkungan yang sesuai sebelum ada klaim apa pun. Angka yang
tercantum di bagian 1 adalah hasil VGL-20, yaitu sebelum fase ini.

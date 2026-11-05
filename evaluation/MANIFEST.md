# Dataset evaluasi — asal-usul, lisensi, dan batas yang harus dibaca dulu

Dataset di folder ini dipakai harness evaluasi (`functions/test/websiteEvaluation.test.ts`
dan `web/src/lib/analysis/messageEvaluation.test.ts`) untuk mengukur lapisan deteksi
internal. Angka yang dihasilkan **tidak** boleh dibaca sebagai akurasi dunia nyata.

## Asal-usul data

| Berkas | Asal | Catatan |
| --- | --- | --- |
| `datasets/urls.jsonl` | disusun tangan untuk repo ini | 49 catatan. Seluruh URL phishing adalah **konstruk sintetis** yang meniru bentuk yang umum didokumentasikan (merek di host, hipon + TLD berisiko, typosquat satu karakter, literal IP, parameter redirect ter-encode, shortener). Tidak ada satu pun yang diambil dari umpan kampanye nyata, dan harness tidak pernah menghubungi host apa pun. |
| `datasets/urls.jsonl` (`html`, `redirectChain`, `registration`) | fixture sintetis | halaman, rantai Location, dan jawaban RDAP yang disajikan probe tiruan; dipakai supaya lapisan isi halaman dan umur registrasi ikut terukur tanpa jaringan. |
| `datasets/messages-id.jsonl` | disusun tangan | 27 catatan. Pesan Bahasa Indonesia yang meniru pola yang umum dilaporkan (undian, biaya admin, OTP/PIN, pinjaman, W2H) dan pesan biasa yang memakai kata kunci serupa. |

Entri berlabel `legitimate` memakai nama domain publik yang dikenal **hanya sebagai teks**.
Harness menjalankan analisis tanpa akses platform (`probe` tiruan berisi data fixture),
sehingga tidak ada permintaan jaringan yang dibuat ke domain tersebut.

Nama merek (BCA, Mandiri, BRI, Tokopedia, Shopee, DANA, OVO, Gojek, PayPal, Google, dll.)
adalah merek milik pemiliknya masing-masing; kemunculannya di sini hanya sebagai teks uji
deteksi peniruan merek.

## Riwayat penyusunan (dibuka supaya terukur tidak dibaca sebagai cherry-pick)

- Pengukuran pertama (45 catatan, tanpa fixture registrasi) memberi recall 45,2% pada
  ambang 15 dengan satu false positive: `https://www.ovo.id/masuk` (halaman masuk sah).
- Setelah itu dataset dilengkapi, **bukan** dengan menghapus entri yang salah:
  1. fixture umur registrasi ditambahkan ke catatan phishing yang domainnya memang
     bentuk sekali pakai (`.xyz`, `.click`, `.loan`, `.top`, `.info`, `.store`, `.biz`,
     `.digital`) karena itulah kondisi yang sebenarnya di lapangan;
  2. empat catatan baru ditambahkan untuk menguji sisi yang bisa jebol:
     `u044` (shortener dengan rantai redirect yang benar-benar teramati),
     `u045` (tautan kampanye di domain resmi merek), `u074` (situs usaha kecil yang
     domainnya baru berumur beberapa hari), `u075` (halaman masuk SaaS baru ber-domain
     muda). Tiga yang terakhir berlabel legitimate dan sengaja mirip bentuknya dengan
     phishing; ketiganya berubah menjadi salah positif jika ambang diturunkan sampai
     9, dan itulah yang menahan ambang tetap di batas level `medium`.
  3. dua rantai redirect fixture diperbaiki (`u044`, `u052`) karena sebelumnya
     menyinggung URL-nya sendiri sehingga harness mengarang bukti "rantai berulang".
- Perubahan engine yang mengikuti pengukuran pertama (bukan sebaliknya): nama merek
  pendek (OVO/BCA/BRI/PLN/DANA) tidak lagi dinilai moderat hanya karena muncul sebagai
  label host, digraf yang mudah tertukar (`rn`→`m`, `vv`→`w`) dilipat sebelum jarak edit
  dihitung, peniruan merek mendapat tambahan terbatas hanya bila ada bukti dari sumbu
  lain yang mendukung, dan kolom `name="password"` pada halaman masuk yang mengirim ke
  domainnya sendiri tidak lagi dibaca sebagai permintaan kredensial — yang dinilai
  adalah tujuan form yang keluar domain atau kolom OTP/PIN/kartu. Keempat perubahan itu
  masing-masing punya uji unit (`websiteUrlSignals.test.ts`, `websiteRisk.test.ts`,
  `websitePageSignals.test.ts`), bukan hanya mengandalkan harness ini.

## Lisensi

Berkas dataset dan harness adalah karya orisinal yang dibuat untuk proyek ini dan
di redistribute bersama repositori yang sama (tidak ada konten pihak ketiga yang disalin,
tidak ada daftar URL dari feed eksternal). Tidak ada dependensi lisensi baru yang ditambahkan.

## Pembagian dev / holdout

- `split: "dev"` dipakai saat menyetel ambang dan bobot.
- `split: "holdout"` tidak dipakai saat penyetelan; harness melaporkan metrik keduanya
  secara terpisah supaya efek overfitting pada fixture dev terlihat.
- Holdout sengaja berisi bentuk yang tidak identik dengan dev (mis. literal IP dengan
  port, typosquat dengan digit di ujung, pesan berteriak seluruh kapital).

## Batas yang harus dinyatakan lewat

1. Jumlah sampel kecil (49 URL, 27 pesan). Selisih satu entri sudah menggeser persen.
2. Dataset sintetis: recall yang tinggi di sini berarti lapisan leksikal/fusi mengenali
   bentuk yang *dikonstruksikan sama*, bukan bukti mengenali kampanye baru.
3. Harness memakai probe deterministik, jadi DNS/TLS/registry asli tidak diukur.
   Pemeriksaan yang tidak tersedia di jalur itu dihitung **netral**, bukan negatif.
4. Ambang prediksi diambil dari batas level engine sendiri (URL: ambang `medium` = 15;
   pesan: ambang `high` = 60), bukan angka yang dipilih setelah metriknya terlihat.
   Trade-off pada ambang lain dilaporkan lewat sapuan ambang.
5. Tidak ada klaim 100%. Yang dilaporkan adalah angka mentah beserta contoh salah
   positif dan salah negatif.
6. Kategori yang belum terdeteksi tidak dihapus dari dataset. Tautan shortener tanpa
   tujuan yang teramati (`u040`, `u042`, `u043`) tetap tercatat sebagai salah negatif
   dengan skor 3, karena dari teks URL saja memang tidak ada yang bisa disimpulkan.

## Hasil terukur (2026-10-30, mesin pasca-upgrade)

Harness URL — 49 catatan, ambang utama 15 (level `medium` engine):

| sumber | presisi | recall | F1 | FP-rate | FN-rate |
| --- | --- | --- | --- | --- | --- |
| semua | 100.0% | 71.9% | 83.6% | 0.0% | 28.1% |
| dev | 100.0% | 78.3% | 87.8% | 0.0% | 21.7% |
| holdout | 100.0% | 55.6% | 71.4% | 0.0% | 44.4% |

Sapuan ambang: 9 → P 90.6% / R 90.6% / FP-rate 17.6%; 12 → P 100.0% / R 87.5% / FP-rate 0.0%;
15 → P 100.0% / R 71.9% / FP-rate 0.0%; 25 → P 100.0% / R 37.5%; 35 → P 100.0% / R 12.5%.
Ambang 12 mengukur lebih baik pada dataset ini, tapi tidak diadopsi sebagai ambang utama
karena 15 adalah batas level `medium` yang sudah ditetapkan engine lebih dulu; mengubah
batas setelah metriknya terlihat akan melebih-lebihkan hasil. Diffnya dilaporkan di sini
supaya pilihan itu bisa dipertanyakan.
Ablation (lapisan baru dimatikan): 23/49 ditandai menjadi 8/49 ditandai.

Satu-satunya salah positif yang tersisa pada ambang rendah berasal dari umur registrasi:
`u045`, `u074`, `u075` (domain sah yang baru berumur beberapa hari) hanya membawa bukti
`registration:domain_young(moderate)` = skor 9. Sebelum diperbaiki, `u071`
(`https://www.ovo.id/masuk`) juga salah positif karena kolom `name="password"` pada
halaman masuk sah dihitung sebagai permintaan OTP/PIN; permintaan kredensial sekarang
hanya dinilai dari tujuan form yang keluar domain atau dari kolom OTP/PIN/kartu.

Harness pesan — 27 catatan, ambang utama 60 (level `high` engine):

| sumber | presisi | recall | F1 | FP-rate | FN-rate |
| --- | --- | --- | --- | --- | --- |
| semua | 100.0% | 76.9% | 87.0% | 0.0% | 23.1% |
| dev | 100.0% | 75.0% | 85.7% | 0.0% | 25.0% |
| holdout | 100.0% | 80.0% | 88.9% | 0.0% | 20.0% |

Sapuan ambang: 25 → P 72.2% / R 100.0% / FP-rate 35.7%; 40 → P 84.6% / R 84.6% / FP-rate 14.3%;
60 → P 100% / R 76.9% / FP 0.

## Menjalankan

```
npm --prefix functions test -- websiteEvaluation      # metrik URL + halaman + fusi
npm --prefix web test -- messageEvaluation            # metrik pesan Bahasa Indonesia
```

Hasil (termasuk tabel metrik dan daftar entri yang salah) dicetak ke stdout saat test
berjalan. Test juga mengunci floor yang sudah diukur: jika perubahan kode menurunkan
recall atau menaikkan false-positive di bawah batas yang terdokumentasi, suite gagal.

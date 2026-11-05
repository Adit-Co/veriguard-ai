/**
 * Batas ukuran body yang boleh ditampung Worker.
 *
 * Konstanta ini dulu diekspor dari modul entry (`src/index.ts`). workerd memvalidasi ekspor
 * modul entry dan menolak nilai yang bukan fungsi/ExportedHandler, sehingga `wrangler dev`
 * gagal start dan satu-satunya jalur verifikasi Durable Object tanpa produksi tertutup
 * (VGL-27 §3.4). Modul ini tidak dipakai sebagai entry point, jadi keduanya bisa hidup
 * berdampingan: host Node (`server/`) mengimpornya dari sini, Worker mengimpornya seperti
 * modul biasa, dan nilainya tetap satu sumber.
 */
export const MAX_BODY_BYTES = 16 * 1_024

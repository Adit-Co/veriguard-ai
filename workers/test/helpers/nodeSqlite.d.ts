/**
 * Deklarasi MINIMAL untuk `node:sqlite`, khusus fixture uji unit R1 (lihat
 * `test/helpers/durableSqlite.ts`). Berkas ini bukan bagian dari kode produksi dan bukan
 * pengganti `@cloudflare/workers-types`: paket `workers/` tidak memasang tipe Node, sementara
 * penyimpanan Durable Object memakai SQLite di runtime workerd. Yang dideklarasikan di sini
 * hanya metode yang benar-benar dipakai tes, supaya permukaan palsu tidak melebar.
 */
declare module 'node:sqlite' {
  export class DatabaseSync {
    constructor(location: string, options?: { open?: boolean })
    exec(sql: string): void
    prepare(sql: string): {
      all(...bindings: unknown[]): Record<string, unknown>[]
      run(...bindings: unknown[]): unknown
    }
  }
}

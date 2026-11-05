import { DatabaseSync } from 'node:sqlite'
import type { DurableSqlCursor, DurableStorageSurface } from '../../src/state/durableState.js'

/**
 * Fixture penyimpanan untuk uji unit R1 + VGL-30H K-3.
 *
 * Ini BUKAN tiruan berperilaku-baik: `node:sqlite` adalah SQLite sungguhan, jadi pernyataan yang
 * dipakai `durableState.ts` (PRAGMA, `WITHOUT ROWID`, `INSERT OR REPLACE`, `transactionSync`)
 * dieksekusi apa adanya. Bedanya dengan workerd hanya pada permukaan `state.storage`, dan itu
 * sengaja dibuat seluas yang dibutuhkan kode produksi.
 *
 * `reopen()` memakai koneksi database yang sama: persis seperti actor restart — instance baru,
 * penyimpanan lama.
 *
 * Sejak VGL-30H fixture juga mencatat MARKER TRANSAKSI (`tx:BEGIN`, `tx:COMMIT`, `tx:ROLLBACK`) di
 * antara pernyataan SQL. Itu yang membuat uji bisa membuktikan "salin dan hapus terjadi di dalam
 * SATU transaksi" dan "kegagalan di tengah rollback", bukan sekadar menebaknya dari jumlah baris.
 */
export type DurableStorageProbe = {
  storage: DurableStorageSurface
  db: DatabaseSync
  /** Jejak pernyataan + marker transaksi, dalam urutan eksekusi. */
  queries(): string[]
  /** Membuat eksekusi pernyataan berikutnya melempar, seperti kegagalan penyimpanan. */
  failNext(message?: string): void
  /**
   * Membuat pernyataan BERIKUTNYA yang cocok dengan `prefix` (setelah spasi dinormalkan,
   * tanpa membedakan besar huruf) melempar. Ini yang dipakai untuk menjatuhkan transaksi tepat di
   * antara `INSERT OR REPLACE` dan `DELETE` migrasi.
   */
  failNextMatching(prefix: string, message?: string): void
  /** Menolak selamanya setiap pernyataan PRAGMA versi, seperti runtime yang tidak mendukungnya. */
  rejectVersionPragma(): void
  rowsFor(kind: string): Record<string, unknown>[]
  /** Satu baris per `key_hash`, untuk memeriksa hasil migrasi secara presisi. */
  rowFor(kind: string, keyHash: string): Record<string, unknown> | undefined
  reopen(): DurableStorageProbe
}

const BEGIN_MARKER = 'tx:BEGIN'
const COMMIT_MARKER = 'tx:COMMIT'
const ROLLBACK_MARKER = 'tx:ROLLBACK'

type ProbeState = {
  db: DatabaseSync
  queries: string[]
  failNextWith: string | undefined
  failMatchWith: { prefix: string; message: string } | undefined
  versionPragmaRejected: boolean
}

function normalize(query: string): string {
  return query.replace(/\s+/g, ' ').trim()
}

export function createDurableStorageProbe(
  dbOrPath: DatabaseSync | string = new DatabaseSync(':memory:'),
): DurableStorageProbe {
  const shared: ProbeState = {
    db: typeof dbOrPath === 'string' ? new DatabaseSync(dbOrPath) : dbOrPath,
    queries: [],
    failNextWith: undefined,
    failMatchWith: undefined,
    versionPragmaRejected: false,
  }

  const surface: DurableStorageSurface = {
    sql: {
      exec(query: string, ...bindings: unknown[]): DurableSqlCursor {
        const flat = normalize(query)
        shared.queries.push(flat.slice(0, 120))
        if (shared.versionPragmaRejected && /^PRAGMA user_version/i.test(flat)) {
          throw new Error('PRAGMA user_version tidak didukung runtime ini')
        }
        if (shared.failNextWith !== undefined) {
          const message = shared.failNextWith
          shared.failNextWith = undefined
          throw new Error(message)
        }
        if (shared.failMatchWith && flat.toUpperCase().startsWith(shared.failMatchWith.prefix.toUpperCase())) {
          const message = shared.failMatchWith.message
          shared.failMatchWith = undefined
          throw new Error(message)
        }
        const rows = shared.db.prepare(query).all(...(bindings as never[]))
        const columnNames = rows.length > 0 ? Object.keys(rows[0] as object) : []
        return {
          columnNames,
          toArray: () => rows.map((row) => ({ ...row })) as Record<string, unknown>[],
          *raw() {
            for (const row of rows) {
              yield columnNames.map((name) => (row as Record<string, unknown>)[name])
            }
          },
        }
      },
    },
    transactionSync<T>(closure: () => T): T {
      // DO memakai satu tulis-per-transaction; BEGIN/COMMIT/ROLLBACK menirunya dan sekaligus
      // membuktikan tidak ada `transactionSync` bersarang di jalur keputusan.
      shared.db.exec('BEGIN IMMEDIATE')
      shared.queries.push(BEGIN_MARKER)
      let committed = false
      try {
        const result = closure()
        shared.db.exec('COMMIT')
        committed = true
        shared.queries.push(COMMIT_MARKER)
        return result
      } catch (error) {
        shared.queries.push(ROLLBACK_MARKER)
        if (!committed) shared.db.exec('ROLLBACK')
        throw error
      }
    },
  }

  const probe: DurableStorageProbe = {
    storage: surface,
    db: shared.db,
    queries: () => shared.queries.slice(),
    failNext(message) {
      shared.failNextWith = message ?? 'kegagalan penyimpanan disuntikkan'
    },
    failNextMatching(prefix, message) {
      shared.failMatchWith = { prefix, message: message ?? 'kegagalan disuntikkan pada pernyataan tertentu' }
    },
    rejectVersionPragma() {
      shared.versionPragmaRejected = true
    },
    rowsFor(kind) {
      return shared.db
        .prepare('SELECT kind, key_hash, used, window_start, expires_at, updated_at FROM vgl_state WHERE kind = ?')
        .all(kind)
        .map((row) => ({ ...row })) as Record<string, unknown>[]
    },
    rowFor(kind, keyHash) {
      const rows = shared.db
        .prepare(
          'SELECT kind, key_hash, used, window_start, expires_at, updated_at FROM vgl_state WHERE kind = ? AND key_hash = ?',
        )
        .all(kind, keyHash)
      const row = rows[0]
      return row === undefined ? undefined : ({ ...row } as Record<string, unknown>)
    },
    reopen: () => createDurableStorageProbe(shared.db),
  }

  return probe
}

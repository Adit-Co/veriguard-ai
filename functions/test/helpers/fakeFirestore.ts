import { Timestamp } from 'firebase-admin/firestore'

/**
 * Firestore tiruan untuk pengujian layanan komunitas. Sengaja meniru semantik yang diuji:
 * transaksi dengan optimistic concurrency (baca lalu batalkan bila ada commit lain di
 * antaranya), query collection-group dengan where/orderBy/limit, dan merge-set. Tidak ada
 * jaringan maupun data produksi yang tersentuh.
 */

export type DocData = Record<string, unknown>

export type FakeSnapshot = {
  exists: boolean
  data: () => DocData | undefined
  ref: FakeDocRef
}

type StoredDoc = { data: DocData; version: number }

type PendingWrite = { path: string; data: DocData; merge: boolean } | { path: string; remove: true }

function parentPath(path: string): string {
  const index = path.lastIndexOf('/')
  return index === -1 ? '' : path.slice(0, index)
}

function collectionIdOf(path: string): string {
  const parent = parentPath(path)
  if (!parent) return ''
  const segments = parent.split('/')
  return segments[segments.length - 1] ?? ''
}

function comparable(value: unknown): number | string | undefined {
  if (value instanceof Timestamp) return value.toMillis()
  if (typeof value === 'number' || typeof value === 'string' || typeof value === 'boolean') {
    return value
  }
  return undefined
}

function orderValue(value: unknown): number | string {
  const raw = comparable(value)
  if (typeof raw === 'number') return raw
  if (typeof raw === 'boolean') return raw ? 1 : 0
  if (raw === undefined) return ''
  return String(raw)
}

function matches(op: string, actual: unknown, expected: unknown): boolean {
  const left = comparable(actual)
  const right = comparable(expected)
  if (left === undefined || right === undefined) return false

  switch (op) {
    case '==':
      return left === right
    case '!=':
      return left !== right
    case '<':
      return left < right
    case '<=':
      return left <= right
    case '>':
      return left > right
    case '>=':
      return left >= right
    default:
      throw new Error(`Operator query tidak dikenal: ${op}`)
  }
}

export class FakeDocRef {
  constructor(
    private readonly store: FakeFirestore,
    readonly path: string,
  ) {}

  get id(): string {
    return this.path.split('/').pop()!
  }

  collection(name: string): FakeCollectionRef {
    return new FakeCollectionRef(this.store, `${this.path}/${name}`)
  }

  async get(): Promise<FakeSnapshot> {
    await this.store.tick()
    return this.store.snapshotFor(this.path)
  }

  async set(data: DocData, options?: { merge?: boolean }): Promise<void> {
    await this.store.tick()
    this.store.applyWrite({ path: this.path, data, merge: options?.merge === true })
  }

  async update(data: DocData): Promise<void> {
    await this.store.tick()
    this.store.applyWrite({ path: this.path, data, merge: true })
  }

  async delete(): Promise<void> {
    await this.store.tick()
    this.store.applyWrite({ path: this.path, remove: true })
  }
}

export class FakeQuery {
  private readonly filters: { field: string; op: string; value: unknown }[] = []
  private readonly orders: { field: string; direction: 'asc' | 'desc' }[] = []
  private limitCount = Infinity

  constructor(
    private readonly store: FakeFirestore,
    private readonly collectionGroupId: string | null,
    private readonly collectionPath: string | null = null,
  ) {}

  where(field: string, op: string, value: unknown): FakeQuery {
    this.filters.push({ field, op, value })
    return this
  }

  orderBy(field: string, direction: 'asc' | 'desc' = 'asc'): FakeQuery {
    this.orders.push({ field, direction })
    return this
  }

  limit(count: number): FakeQuery {
    this.limitCount = count
    return this
  }

  async get(): Promise<{ docs: FakeSnapshot[] }> {
    await this.store.tick()

    const paths = this.store
      .paths()
      .filter((path) =>
        this.collectionPath !== null
          ? parentPath(path) === this.collectionPath
          : collectionIdOf(path) === this.collectionGroupId,
      )
      .filter((path) => {
        const data = this.store.peek(path)
        if (!data) return false
        return this.filters.every((filter) => matches(filter.op, data[filter.field], filter.value))
      })

    paths.sort((left, right) => {
      for (const order of this.orders) {
        const a = orderValue(this.store.peek(left)?.[order.field])
        const b = orderValue(this.store.peek(right)?.[order.field])
        if (a < b) return order.direction === 'asc' ? -1 : 1
        if (a > b) return order.direction === 'asc' ? 1 : -1
      }
      return left.localeCompare(right)
    })

    const docs = paths.slice(0, this.limitCount).map((path) => this.store.snapshotFor(path))
    return { docs }
  }
}

export class FakeCollectionRef {
  constructor(
    private readonly store: FakeFirestore,
    readonly path: string,
  ) {}

  doc(id?: string): FakeDocRef {
    const resolved = id ?? this.store.nextAutoId(this.path)
    return new FakeDocRef(this.store, `${this.path}/${resolved}`)
  }

  where(field: string, op: string, value: unknown): FakeQuery {
    return new FakeQuery(this.store, null, this.path).where(field, op, value)
  }

  orderBy(field: string, direction: 'asc' | 'desc' = 'asc'): FakeQuery {
    return new FakeQuery(this.store, null, this.path).orderBy(field, direction)
  }

  limit(count: number): FakeQuery {
    return new FakeQuery(this.store, null, this.path).limit(count)
  }
}

export class FakeFirestore {
  private docs = new Map<string, StoredDoc>()
  private commitSeq = 0
  private autoId = 0
  readonly events: string[] = []

  /** Membuat setiap operasi await benar-benar bergiliran seperti I/O nyata. */
  async tick(): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, 0))
  }

  reset(): void {
    this.docs = new Map()
    this.commitSeq = 0
    this.autoId = 0
    this.events.length = 0
  }

  seed(path: string, data: DocData): void {
    this.docs.set(path, { data: { ...data }, version: (this.docs.get(path)?.version ?? 0) + 1 })
  }

  peek(path: string): DocData | undefined {
    return this.docs.get(path)?.data
  }

  has(path: string): boolean {
    return this.docs.has(path)
  }

  paths(): string[] {
    return [...this.docs.keys()]
  }

  snapshotFor(path: string): FakeSnapshot {
    const stored = this.docs.get(path)
    return {
      exists: Boolean(stored),
      data: () => (stored ? { ...stored.data } : undefined),
      ref: new FakeDocRef(this, path),
    }
  }

  nextAutoId(collectionPath: string): string {
    this.autoId += 1
    return `auto-${this.autoId}-${collectionPath.length}`
  }

  applyWrite(write: PendingWrite): void {
    if ('remove' in write) {
      this.docs.delete(write.path)
      this.commitSeq += 1
      return
    }

    const current = this.docs.get(write.path)
    const data = write.merge ? { ...current?.data, ...write.data } : { ...write.data }
    this.docs.set(write.path, { data, version: (current?.version ?? 0) + 1 })
    this.commitSeq += 1
  }

  versionOf(path: string): number {
    return this.docs.get(path)?.version ?? 0
  }

  async runTransaction<T>(work: (transaction: FakeTransaction) => Promise<T>): Promise<T> {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const transaction = new FakeTransaction(this)
      const startedAt = this.commitSeq
      const result = await work(transaction)

      const readChanged = [...transaction.reads].some(
        ([path, version]) => this.versionOf(path) !== version,
      )
      const concurrentCommit = transaction.reads.size > 0 && this.commitSeq !== startedAt
      if (readChanged || concurrentCommit) {
        this.events.push('transaction-aborted-retry')
        if (attempt === 4) throw new Error('Transaksi Firestore dibatalkan terlalu sering.')
        continue
      }

      for (const write of transaction.writes) {
        this.applyWrite(write)
      }
      this.events.push('transaction-commit')
      return result
    }

    throw new Error('Transaksi Firestore tidak dapat selesai.')
  }

  collection(name: string): FakeCollectionRef {
    return new FakeCollectionRef(this, name)
  }

  collectionGroup(name: string): FakeQuery {
    return new FakeQuery(this, name, null)
  }
}

export class FakeTransaction {
  readonly reads = new Map<string, number>()
  readonly writes: PendingWrite[] = []

  constructor(private readonly store: FakeFirestore) {}

  async get(ref: FakeDocRef): Promise<FakeSnapshot>
  async get(query: FakeQuery): Promise<{ docs: FakeSnapshot[] }>
  async get(target: FakeDocRef | FakeQuery): Promise<FakeSnapshot | { docs: FakeSnapshot[] }> {
    // Firestore menolak baca setelah tulis di dalam transaksi. Tiruan ini menegakkannya
    // supaya urutan salah tidak lolos hanya karena pengujian memakai objek palsu.
    if (this.writes.length > 0) {
      throw new Error('Firestore transactions require all reads before all writes.')
    }

    await this.store.tick()

    if (target instanceof FakeQuery) {
      const snapshot = await target.get()
      for (const doc of snapshot.docs) {
        this.reads.set(doc.ref.path, this.store.versionOf(doc.ref.path))
      }
      return snapshot
    }

    const snapshot = this.store.snapshotFor(target.path)
    this.reads.set(target.path, this.store.versionOf(target.path))
    return snapshot
  }

  set(ref: FakeDocRef, data: DocData, options?: { merge?: boolean }): void {
    this.writes.push({ path: ref.path, data, merge: options?.merge === true })
  }

  delete(ref: FakeDocRef): void {
    this.writes.push({ path: ref.path, remove: true })
  }
}

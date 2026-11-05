import { ScanStateDurableObject } from '../../src/state/scanState.js'
import {
  SCAN_STATE_DO_NAME,
  createDurableStateStore,
  createDurableTokenRegistry,
  createMemoryStateStore,
  createStateRpc,
  readScanStateRpcHealth,
} from '../../src/state/store.js'
import type {
  ScanStateNamespace,
  ScanStateRpcDiagnostic,
  ScanStateRpcReporter,
  ScanStateStore,
  ScanStateStub,
} from '../../src/state/store.js'

/**
 * VGL-28 R5: entry point Worker khusus uji runtime.
 *
 * Berkas ini di-bundle dan dijalankan oleh workerd melalui `createTestHarness` dari wrangler
 * (konfigurasi `test/support/doProbe.wrangler.toml`), jadi yang diuji adalah registrasi actor,
 * pengiriman binding `SCAN_STATE`, dan kontrak RPC sungguhan — bukan namespace tiruan seperti di
 * `test/scanState.test.ts`. Isinya sengaja tipis: dia memanggil ulang kode produksi
 * (`src/state/store.ts`, `src/state/scanState.ts`) tanpa meniru perilakunya.
 */
export { ScanStateDurableObject }

const DO_URL = 'https://veriguard-scan-state.internal/state'

type ProbeEnv = { SCAN_STATE?: unknown }

function asNamespace(value: unknown): ScanStateNamespace | undefined {
  if (!value || typeof value !== 'object') return undefined
  const candidate = value as Record<string, unknown>
  if (typeof candidate.idFromName !== 'function' || typeof candidate.get !== 'function') {
    return undefined
  }
  return candidate as unknown as ScanStateNamespace
}

function collectingReporter(): { records: ScanStateRpcDiagnostic[]; report: ScanStateRpcReporter } {
  const records: ScanStateRpcDiagnostic[] = []
  return {
    records,
    report: (diagnostic) => {
      records.push(diagnostic)
    },
  }
}

async function probeRegistration(namespace: ScanStateNamespace | undefined) {
  if (!namespace) return { bindingPresent: false }
  const id = namespace.idFromName(SCAN_STATE_DO_NAME)
  const stub = namespace.get(id)
  return {
    bindingPresent: true,
    idIsString: typeof id.toString() === 'string' && id.toString().length > 0,
    stubHasFetch: typeof stub.fetch === 'function',
  }
}

async function probeRaw(namespace: ScanStateNamespace | undefined, body: string) {
  if (!namespace) return { bindingPresent: false }
  const stub = namespace.get(namespace.idFromName(SCAN_STATE_DO_NAME))
  const response = await stub.fetch(DO_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  })
  const text = await response.text()
  return {
    bindingPresent: true,
    status: response.status,
    contentType: response.headers.get('content-type'),
    text,
  }
}

async function probeCounter(namespace: ScanStateNamespace | undefined, key: string, limit: number) {
  if (!namespace) return { bindingPresent: false }
  const collectorA = collectingReporter()
  const collectorB = collectingReporter()
  // Dua facade = dua "isolate": masing-masing membangun RPC-nya sendiri tetapi menunjuk ke
  // actor id yang sama, persis seperti dua Worker isolate di produksi.
  const isolateA = createDurableStateStore(
    createStateRpc(namespace, collectorA.report),
    createMemoryStateStore(),
  )
  const isolateB = createDurableStateStore(
    createStateRpc(namespace, collectorB.report),
    createMemoryStateStore(),
  )

  const decisions: Array<{ facade: 'A' | 'B'; allowed: boolean; used?: number }> = []
  const facades = [isolateA, isolateB] as const
  for (let index = 0; index < limit + 1; index += 1) {
    const facade = facades[index % 2]!
    const decision = await facade.consumeCounter(key, limit, 60_000, Date.now())
    decisions.push({
      facade: facade === isolateA ? 'A' : 'B',
      allowed: decision.allowed,
      used: decision.used,
    })
  }

  return {
    bindingPresent: true,
    decisions,
    allowed: decisions.filter((entry) => entry.allowed).length,
    blocked: decisions.filter((entry) => !entry.allowed).length,
    diagnostics: [...collectorA.records, ...collectorB.records],
    health: readScanStateRpcHealth(),
  }
}

async function probePersist(namespace: ScanStateNamespace | undefined, key: string) {
  if (!namespace) return { bindingPresent: false }
  const collector = collectingReporter()
  const store = createDurableStateStore(createStateRpc(namespace, collector.report), createMemoryStateStore())
  const decision = await store.consumeCounter(key, 100, 60_000, Date.now())
  return { bindingPresent: true, decision, diagnostics: collector.records }
}

async function probeRejected(namespace: ScanStateNamespace | undefined) {
  if (!namespace) return { bindingPresent: false }
  const collector = collectingReporter()
  const call = createStateRpc(namespace, collector.report)
  const store = createDurableStateStore(call, createMemoryStateStore())

  // `limit` dikirim sebagai string: DO membacanya dengan readNumber() dan menjawab HTTP 400.
  // Ini jalur yang dulu habis-habisan ditelan `catch {}`.
  const rejected = await call({
    action: 'counter',
    key: 'probe:reject',
    limit: 'tiga' as unknown as number,
    windowMs: 60_000,
  })
  const afterFailure = await call({ action: 'counter', key: 'probe:reject', limit: 3, windowMs: 60_000 })
  // Kunci fallback dibuat unik per panggilan: memori isolate bertahan antar permintaan harness,
  // jadi kunci tetap akan membuat uji ini bergantung pada urutan.
  const fallbackKey = `probe:reject:fallback:${Date.now()}`
  const memoryDecision = await store.consumeCounter(fallbackKey, 1, 60_000, Date.now())
  const memoryDecisionAgain = await store.consumeCounter(fallbackKey, 1, 60_000, Date.now())

  return {
    bindingPresent: true,
    rejectedIsNull: rejected === null,
    breakerShortCircuitIsNull: afterFailure === null,
    // Bukti bahwa fallback tetap menegangkan batas (bukan membuka gerbang): 1 lolos, lalu menolak.
    fallbackFirst: memoryDecision.allowed,
    fallbackSecond: memoryDecisionAgain.allowed,
    diagnostics: collector.records,
    health: readScanStateRpcHealth(),
  }
}

async function probeParallel(namespace: ScanStateNamespace | undefined, key: string, limit: number) {
  if (!namespace) return { bindingPresent: false }
  const collector = collectingReporter()
  const store = createDurableStateStore(createStateRpc(namespace, collector.report), createMemoryStateStore())

  // Stand-in lokal untuk eksperimen E1 VGL-27 (31 permintaan serentak, batas 30/60s). KUNCI-nya
  // sama karena dikirim dari satu Worker; kalau jalur DO sehat, hasilnya harus 30 lolos + 1 tolak.
  const concurrency = limit + 1
  const decisions = await Promise.all(
    Array.from({ length: concurrency }, () => store.consumeCounter(key, limit, 60_000, Date.now())),
  )

  return {
    bindingPresent: true,
    allowed: decisions.filter((decision) => decision.allowed).length,
    blocked: decisions.filter((decision) => !decision.allowed).length,
    usages: decisions.map((decision) => decision.used ?? -1).sort((left, right) => left - right),
    diagnostics: collector.records,
  }
}

async function probeTokens(namespace: ScanStateNamespace | undefined, fingerprint: string) {
  if (!namespace) return { bindingPresent: false }
  const collector = collectingReporter()
  const call = createStateRpc(namespace, collector.report)
  const isolateA = createDurableTokenRegistry(call)
  const isolateB = createDurableTokenRegistry(call)

  const first = await isolateA.reserve(fingerprint, Date.now())
  const second = await isolateB.reserve(fingerprint, Date.now())
  await isolateA.release(fingerprint)
  const third = await isolateB.reserve(fingerprint, Date.now())

  return {
    bindingPresent: true,
    first,
    second,
    third,
    diagnostics: collector.records,
  }
}

/**
 * VGL-30F §6: satu operasi state per permintaan, supaya tes bisa menyisipkan `evictDurableObject()`
 * DI ANTARA dua permintaan. Semua cabang lain menyelesaikan seluruh rangkaian dalam satu permintaan,
 * jadi tidak bisa dipakai membuktikan apa yang bertahan setelah actor di-evict.
 */
async function probeStep(
  namespace: ScanStateNamespace | undefined,
  operation: string,
  key: string,
  limit: number,
) {
  if (!namespace) return { bindingPresent: false }
  const collector = collectingReporter()
  const call = createStateRpc(namespace, collector.report)
  const store = createDurableStateStore(call, createMemoryStateStore())
  const registry = createDurableTokenRegistry(call)

  switch (operation) {
    case 'counter':
      return {
        bindingPresent: true,
        decision: await store.consumeCounter(key, limit, 60_000, Date.now()),
        diagnostics: collector.records,
      }
    case 'issue':
      await store.issueClearance(key, Date.now())
      return { bindingPresent: true, diagnostics: collector.records }
    case 'has':
      return { bindingPresent: true, cleared: await store.hasClearance(key, Date.now()), diagnostics: collector.records }
    case 'reserve':
      return { bindingPresent: true, reservation: await registry.reserve(key, Date.now()), diagnostics: collector.records }
    case 'release':
      await registry.release(key)
      return { bindingPresent: true, diagnostics: collector.records }
    default:
      return { bindingPresent: true, error: `operasi tidak dikenal: ${operation}` }
  }
}

async function probeClearance(namespace: ScanStateNamespace | undefined, key: string) {
  if (!namespace) return { bindingPresent: false }
  const collector = collectingReporter()
  const isolateA = createDurableStateStore(createStateRpc(namespace, collector.report), createMemoryStateStore())
  const isolateB = createDurableStateStore(createStateRpc(namespace, collector.report), createMemoryStateStore())

  const before = await isolateA.hasClearance(key, Date.now())
  await isolateA.issueClearance(key, Date.now())
  const after = await isolateB.hasClearance(key, Date.now())

  return { bindingPresent: true, before, after, diagnostics: collector.records }
}

type LatchedFacade = {
  store: ScanStateStore
  records: ScanStateRpcDiagnostic[]
}

// Dua pencacah modul ini meniru bentuk pemakaian di produksi (`resolveWorkerState` menyimpan
// satu facade per isolate) dan bentuk sebelum perbaikan VGL-28 (stub disimpan di closure
// builder). Keduanya dipakai untuk membuktikan bahwa yang tidak boleh melewati batas konteks
// permintaan adalah stub-nya, bukan facade-nya.
let latchedFacade: LatchedFacade | undefined
let latchedStub: ScanStateStub | undefined
let latchedStubUses = 0

async function probeSharedFacade(namespace: ScanStateNamespace | undefined, key: string) {
  if (!namespace) return { bindingPresent: false }
  const createdNow = !latchedFacade
  if (!latchedFacade) {
    const collector = collectingReporter()
    latchedFacade = {
      records: collector.records,
      store: createDurableStateStore(createStateRpc(namespace, collector.report), createMemoryStateStore()),
    }
  }
  const before = latchedFacade.records.length
  const decision = await latchedFacade.store.consumeCounter(key, 100, 60_000, Date.now())
  return {
    bindingPresent: true,
    facadeCreatedThisRequest: createdNow,
    decision,
    diagnostics: latchedFacade.records.slice(before),
    health: readScanStateRpcHealth(),
  }
}

async function probeLatchedStub(namespace: ScanStateNamespace | undefined, key: string) {
  if (!namespace) return { bindingPresent: false }
  if (!latchedStub) latchedStub = namespace.get(namespace.idFromName(SCAN_STATE_DO_NAME))
  latchedStubUses += 1

  // Persis bentuk lama `createStateRpc`: satu stub yang dibuat sekali lalu dipakai lagi pada
  // permintaan berikutnya. Kalau workerd menolak, tahap yang gagal ikut tercatat.
  let stage = 'fetch'
  try {
    const response = await latchedStub.fetch(DO_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'counter', key, limit: 100, windowMs: 60_000 }),
    })
    stage = 'read'
    const payload = (await response.json()) as Record<string, unknown>
    return {
      bindingPresent: true,
      use: latchedStubUses,
      status: response.status,
      ok: payload.ok === true,
      used: typeof payload.used === 'number' ? payload.used : null,
    }
  } catch (error) {
    return {
      bindingPresent: true,
      use: latchedStubUses,
      failedStage: stage,
      errorName: error instanceof Error ? error.name : typeof error,
      // Prefix pendek: cukup untuk mengenali galatnya, tanpa menyalin seluruh pesan runtime.
      errorHead: error instanceof Error ? error.message.slice(0, 52) : String(error).slice(0, 52),
    }
  }
}

export default {
  async fetch(request: Request, env: ProbeEnv): Promise<Response> {
    const url = new URL(request.url)
    const namespace = asNamespace(env.SCAN_STATE)
    const probe = url.searchParams.get('probe') ?? 'registration'
    const key = url.searchParams.get('key') ?? `probe:${probe}`
    const limit = Number.parseInt(url.searchParams.get('limit') ?? '3', 10)

    let body: Record<string, unknown>
    switch (probe) {
      case 'registration':
        body = await probeRegistration(namespace)
        break
      case 'raw':
        body = await probeRaw(namespace, url.searchParams.get('payload') ?? '{}')
        break
      case 'counter':
        body = await probeCounter(namespace, key, Number.isFinite(limit) ? limit : 3)
        break
      case 'persist':
        body = await probePersist(namespace, key)
        break
      case 'rejected':
        body = await probeRejected(namespace)
        break
      case 'parallel':
        body = await probeParallel(namespace, key, Number.isFinite(limit) ? limit : 30)
        break
      case 'tokens':
        body = await probeTokens(namespace, key)
        break
      case 'clearance':
        body = await probeClearance(namespace, key)
        break
      case 'step':
        body = await probeStep(namespace, url.searchParams.get('op') ?? 'counter', key, Number.isFinite(limit) ? limit : 3)
        break
      case 'sharedFacade':
        body = await probeSharedFacade(namespace, key)
        break
      case 'latchedStub':
        body = await probeLatchedStub(namespace, key)
        break
      default:
        body = { error: 'probe tidak dikenal' }
    }

    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    })
  },
}

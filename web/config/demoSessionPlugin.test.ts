import type { Plugin, ViteDevServer } from 'vite'
import { describe, expect, it, vi } from 'vitest'
import { DEMO_ACCOUNTS, DEMO_LOGIN_ENV_FLAG } from './demoAccounts.ts'
import { demoSessionPlugin } from './demoSessionPlugin.ts'

// Jaminan struktural bahwa jalur sesi demo tidak pernah ada di luar dev server ber-flag.
// Bagian dari pembuktian "demo login tidak aktif pada production build".

const COMPLETE_ENV = {
  [DEMO_LOGIN_ENV_FLAG]: 'true',
  NODE_ENV: 'development',
  VITE_USE_EMULATORS: 'true',
  VITE_AUTH_EMULATOR_URL: 'http://127.0.0.1:9099',
  VITE_FIRESTORE_EMULATOR_HOST: '127.0.0.1:8080',
  VITE_FIREBASE_PROJECT_ID: 'demo-project',
  VITE_FIREBASE_API_KEY: 'demo-web-key',
}

function register(plugin: Plugin): ReturnType<typeof vi.fn> {
  const use = vi.fn()
  const server = { middlewares: { use } } as unknown as ViteDevServer
  // configureServer bertipe ObjectHook (fungsi langsung atau { handler }) dan fungsi aslinya
  // membawa parameter `this: ResolvedConfig` dari tipe Vite. Plugin ini mendaftarkannya sebagai
  // fungsi langsung, jadi cukup dipanggil lewat cast tanpa menyentuh ikatan this.
  const hook = plugin.configureServer as unknown as ((server: ViteDevServer) => void) | undefined
  if (!hook) throw new Error('Plugin demo harus punya configureServer.')
  hook(server)
  return use
}

describe('pendaftaran jalur sesi demo', () => {
  it('hanya berlaku untuk dev server', () => {
    expect(demoSessionPlugin(COMPLETE_ENV).apply).toBe('serve')
  })

  it('tidak mendaftarkan jalur apa pun tanpa flag', () => {
    expect(register(demoSessionPlugin({ ...COMPLETE_ENV, [DEMO_LOGIN_ENV_FLAG]: '' }))).not.toHaveBeenCalled()
  })

  it('tidak mendaftarkan jalur pada production meskipun flag ter-set', () => {
    expect(register(demoSessionPlugin({ ...COMPLETE_ENV, NODE_ENV: 'production' }))).not.toHaveBeenCalled()
  })

  it('tidak mendaftarkan jalur bila emulator tidak aktif atau bukan loopback', () => {
    for (const env of [
      { ...COMPLETE_ENV, VITE_USE_EMULATORS: 'false' },
      { ...COMPLETE_ENV, VITE_AUTH_EMULATOR_URL: 'https://demo.firebaseapp.com' },
      { ...COMPLETE_ENV, VITE_FIRESTORE_EMULATOR_HOST: '' },
      { ...COMPLETE_ENV, VITE_FIREBASE_PROJECT_ID: '' },
    ]) {
      expect(register(demoSessionPlugin(env))).not.toHaveBeenCalled()
    }
  })

  it('mendaftarkan jalur sesi demo dan daftar identitas demo, tidak lebih', () => {
    const use = register(demoSessionPlugin(COMPLETE_ENV))
    // Nilai literal dikunci di sini dan di sisi klien (src/lib/auth/demoLogin.ts serta
    // src/lib/auth/demoIdentity.ts), supaya pergeseran salah satu sisi terlihat sebagai kegagalan
    // test, bukan sebagai jalur mati. Yang dikunci adalah KEANGGOTAANNYA: tidak boleh ada jalur
    // lain yang terdaftar, urutan pendaftarannya tidak berarti karena keduanya prefix berbeda.
    expect(use.mock.calls.map(([path]) => path).sort()).toEqual([
      '/__veriguard-demo/identities',
      '/__veriguard-demo/session',
    ])
  })
})

// VGL-41E — jalur pencocokan akun demo hanya boleh mengeluarkan digest. Alamat aslinya tidak
// pernah masuk ke bundel maupun respons, jadi penyamaran tidak bisa dibalik dari jaringan.
type RouteHandler = (request: { method?: string }, response: unknown) => void

function identitiesRoute(env = COMPLETE_ENV): RouteHandler | undefined {
  const routes = new Map<string, RouteHandler>()
  const server = {
    middlewares: {
      use: (path: string, handler: RouteHandler) => {
        routes.set(path, handler)
      },
    },
  } as unknown as ViteDevServer
  const hook = pluginHook(demoSessionPlugin(env))
  hook(server)
  return routes.get('/__veriguard-demo/identities')
}

function pluginHook(plugin: Plugin) {
  return plugin.configureServer as unknown as (server: ViteDevServer) => void
}

function invoke(handler: RouteHandler, method = 'GET'): { status: number; body: string } {
  const written: { status: number; body: string } = { status: 0, body: '' }
  const response = {
    setHeader: () => undefined,
    end: (payload: string) => {
      written.body = payload
    },
    set statusCode(value: number) {
      written.status = value
    },
  }
  handler({ method }, response)
  return written
}

describe('daftar identitas demo hanya berupa digest', () => {
  it('menjawab 200 dengan digest 64 heksadesimal per akun demo, tanpa alamat email', () => {
    const handler = identitiesRoute()
    expect(handler).toBeTypeOf('function')
    const result = invoke(handler as RouteHandler)
    expect(result.status).toBe(200)
    const payload = JSON.parse(result.body) as { digests: string[] }
    expect(payload.digests).toHaveLength(Object.keys(DEMO_ACCOUNTS).length)
    for (const digest of payload.digests) expect(digest).toMatch(/^[0-9a-f]{64}$/)
    for (const account of Object.values(DEMO_ACCOUNTS)) {
      expect(result.body).not.toContain(account.email)
      expect(result.body).not.toContain(account.email.split('@')[0] as string)
    }
  })

  it('menolak metode selain GET/HEAD', () => {
    const handler = identitiesRoute()
    for (const method of ['POST', 'DELETE']) {
      const result = invoke(handler as RouteHandler, method)
      expect(result.status).toBe(405)
      expect(JSON.parse(result.body) as { error: string }).toHaveProperty('error')
    }
  })

  it('tidak mendaftar jalur identitas ketika pagar demo tertutup', () => {
    expect(identitiesRoute({ ...COMPLETE_ENV, [DEMO_LOGIN_ENV_FLAG]: '' })).toBeUndefined()
    expect(identitiesRoute({ ...COMPLETE_ENV, NODE_ENV: 'production' })).toBeUndefined()
  })
})

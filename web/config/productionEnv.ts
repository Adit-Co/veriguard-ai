export type ProductionEnv = Record<string, string | undefined>

export type ProductionEnvIssue = {
  variable: string
  message: string
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]'])

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '')
  return (
    LOOPBACK_HOSTS.has(normalized) ||
    normalized.endsWith('.localhost') ||
    normalized.startsWith('127.')
  )
}

export function validateProductionEnv(env: ProductionEnv): ProductionEnvIssue[] {
  const issues: ProductionEnvIssue[] = []
  const apiBase = env.VITE_API_BASE_URL?.trim()
  const workerUrl = env.VITE_SCANNER_WORKER_URL?.trim()
  const endpointVariable = apiBase ? 'VITE_API_BASE_URL' : 'VITE_SCANNER_WORKER_URL'
  const endpoint = apiBase || workerUrl

  if (!endpoint) {
    issues.push({
      variable: 'VITE_API_BASE_URL / VITE_SCANNER_WORKER_URL',
      message:
        'Endpoint backend wajib diisi untuk build produksi. Tidak ada endpoint pengganti yang dibuat otomatis.',
    })
  } else {
    let parsed: URL
    try {
      parsed = new URL(endpoint)
    } catch {
      issues.push({
        variable: endpointVariable,
        message: 'Endpoint bukan URL absolut yang valid.',
      })
      return issues
    }

    if (parsed.protocol !== 'https:') {
      issues.push({
        variable: endpointVariable,
        message: 'Endpoint produksi wajib memakai HTTPS.',
      })
    }

    if (isLoopbackHost(parsed.hostname)) {
      issues.push({
        variable: endpointVariable,
        message: 'Endpoint produksi tidak boleh mengarah ke host lokal atau loopback.',
      })
    }

    if (parsed.username || parsed.password) {
      issues.push({
        variable: endpointVariable,
        message: 'Endpoint produksi tidak boleh memuat kredensial di URL.',
      })
    }
  }

  if (env.VITE_USE_EMULATORS?.trim().toLowerCase() === 'true') {
    issues.push({
      variable: 'VITE_USE_EMULATORS',
      message: 'Emulator Firebase hanya boleh aktif pada mode pengembangan.',
    })
  }

  // Login demo mengandalkan Emulator Firebase dan jalur dev-server. Bendera yang sama
  // tidak boleh terbawa ke build produksi, jadi build dihentikan lebih dulu.
  const demoLogin = env.VITE_ENABLE_DEMO_LOGIN?.trim().toLowerCase()
  if (demoLogin === 'true' || demoLogin === '1') {
    issues.push({
      variable: 'VITE_ENABLE_DEMO_LOGIN',
      message:
        'Login demo hanya tersedia pada dev server dengan emulator; build produksi ditolak.',
    })
  }

  const communityBackend = env.VITE_COMMUNITY_BACKEND?.trim().toLowerCase()
  if (communityBackend && communityBackend !== 'firestore') {
    issues.push({
      variable: 'VITE_COMMUNITY_BACKEND',
      message:
        'Build produksi hanya mendukung jalur Firestore Spark. Jalur Cloud Functions lama tidak boleh diaktifkan.',
    })
  }

  return issues
}

export function formatProductionEnvIssues(issues: ProductionEnvIssue[]): string {
  return [
    'Build produksi dihentikan karena konfigurasi environment tidak aman:',
    ...issues.map((issue) => `- ${issue.variable}: ${issue.message}`),
    'Perbaiki environment produksi; build tidak akan memakai endpoint lokal atau placeholder.',
  ].join('\n')
}

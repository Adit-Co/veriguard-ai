import { readScannerConfig } from '../../functions/src/scanners/config.js'
import { resetScanRateLimit } from '../../functions/src/scanners/rateLimit.js'
import { runMultiSourceScan } from '../../functions/src/scanners/service.js'
import { loadSettings } from './index.js'

const targetArg = process.argv[2]?.trim() ?? ''

async function main(): Promise<void> {
  const settings = loadSettings(process.cwd())
  const missing = [
    settings.env.URLSCAN_API_KEY ? null : 'URLSCAN_API_KEY',
    settings.env.VIRUSTOTAL_API_KEY ? null : 'VIRUSTOTAL_API_KEY',
    settings.env.THREATFOX_API_KEY ? null : 'THREATFOX_API_KEY',
  ].filter((item): item is string => item !== null)

  if (missing.length > 0) {
    console.warn('[perhatian] Secret belum diisi di server/.env:')
    for (const item of missing) console.warn(`  - ${item}`)
  }

  if (!targetArg) {
    console.warn('Penggunaan: npm run live-check -- <url>')
    process.exit(1)
  }

  let normalized: URL
  try {
    normalized = new URL(targetArg)
  } catch {
    console.error('URL target tidak valid.')
    process.exit(1)
    return
  }

  console.log(`Target: ${normalized.hostname}`)

  resetScanRateLimit()
  try {
    const result = await runMultiSourceScan({
      uid: 'local-live-check',
      url: targetArg,
      config: readScannerConfig(settings.env as Record<string, string | undefined>),
    })

    for (const provider of result.providers) {
      console.log(
        [
          `provider=${provider.id}`,
          `status=${provider.status}`,
          `verdict=${provider.verdict}`,
          `score=${provider.score === null ? 'null' : provider.score}`,
          `duration=${provider.durationMs}ms`,
          provider.reason ? `alasan=${provider.reason}` : `ringkasan=${provider.summary}`,
        ].join(' | '),
      )
    }
  } catch (error) {
    console.error(
      'Pemeriksaan gagal:',
      error instanceof Error ? error.message : error,
    )
    process.exit(1)
  }
}

void main()

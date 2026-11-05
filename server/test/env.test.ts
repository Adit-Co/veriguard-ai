import { describe, expect, it } from 'vitest'
import { buildLocalSettings, parseEnvFile } from '../src/env.js'

describe('konfigurasi server lokal', () => {
  it('mem-parse file .env dengan kutip dan komentar', () => {
    const parsed = parseEnvFile(
      '# komentar\nURLSCAN_API_KEY="nila i\"\nVIRUSTOTAL_API_KEY= nilai2 \nSERVER_PORT=9000\nexport THREATFOX_API_KEY=nilai3',
    )
    expect(parsed.URLSCAN_API_KEY).toBe('nila i')
    expect(parsed.VIRUSTOTAL_API_KEY).toBe('nilai2')
    expect(parsed.SERVER_PORT).toBe('9000')
    expect(parsed.THREATFOX_API_KEY).toBe('nilai3')
  })

  it('proses env mengalahkan file, file pertama mengalahkan fallback', () => {
    const settings = buildLocalSettings({
      files: [
        { URLSCAN_API_KEY: 'dari-file', ALLOWED_ORIGINS: 'http://localhost:5173', SERVER_PORT: '9001' },
        { URLSCAN_API_KEY: 'dari-fallback', ALLOWED_ORIGINS: 'http://fallback.test' },
      ],
      processEnv: { URLSCAN_API_KEY: 'dari-process' },
    })
    expect(settings.env.URLSCAN_API_KEY).toBe('dari-process')
    expect(settings.env.ALLOWED_ORIGINS).toBe('http://localhost:5173')
    expect(settings.port).toBe(9001)
  })

  it('setiap kunci agen yang dikenal adapter dibaca dari file env', () => {
    // Kunci yang tidak terdaftar pada KNOWN_SERVER_KEYS tidak pernah mencapai backend,
    // sehingga agen terkait diam-diam selalu tampil "belum dikonfigurasi".
    const settings = buildLocalSettings({
      files: [
        {
          URLSCAN_API_KEY: 'k-1',
          VIRUSTOTAL_API_KEY: 'k-2',
          OPENPHISH_API_KEY: 'k-3',
          THREATFOX_API_KEY: 'k-4',
          CLOUDFLARE_API_TOKEN: 'k-5',
          CLOUDFLARE_ACCOUNT_ID: 'k-6',
          OTX_API_KEY: 'k-7',
          GOOGLE_SAFE_BROWSING_API_KEY: 'k-8',
          HYBRID_ANALYSIS_API_KEY: 'k-7h',
          TURNSTILE_SECRET_KEY: 'k-9',
          TURNSTILE_HOSTNAMES: 'veriguard.example,veriguard.firebaseapp.com',
          FIREBASE_PROJECT_ID: 'veriguard-uji',
        },
      ],
      processEnv: {},
    })

    expect(Object.keys(settings.env).sort()).toEqual(
      [
        'ALLOWED_ORIGINS',
        'CLOUDFLARE_ACCOUNT_ID',
        'CLOUDFLARE_API_TOKEN',
        'OPENPHISH_API_KEY',
        'OTX_API_KEY',
        'PROVIDER_CONCURRENCY',
        'RATE_LIMIT_MAX_PER_IP',
        'RATE_LIMIT_WINDOW_SECONDS',
        'THREATFOX_API_KEY',
        'URLSCAN_API_KEY',
        'GOOGLE_SAFE_BROWSING_API_KEY',
        'VIRUSTOTAL_API_KEY',
        'HYBRID_ANALYSIS_API_KEY',
        // Kunci verifikasi Turnstile ikut didaftarkan: tanpa keduanya, nilai di server/.env
        // tidak pernah mencapai runtime dan gerbang CAPTCHA diam-diam tidak pernah aktif.
        'TURNSTILE_SECRET_KEY',
        'TURNSTILE_HOSTNAMES',
        'FIREBASE_PROJECT_ID',
        // VGL-40: host Auth Emulator juga harus diteruskan. Tanpa kunci ini backend lokal
        // tidak pernah tahu bahwa ia bicara dengan emulator, dan sesi lokal ditolak scanner.
        'FIREBASE_AUTH_EMULATOR_HOST',
        // Kebijakan umur laporan + cache ikut disaring; sebelumnya knob ini tertulis di
        // .env tetapi tidak pernah mencapai readScannerConfig pada backend lokal.
        'URLSCAN_MAX_REPORT_AGE_HOURS',
        'VIRUSTOTAL_MAX_REPORT_AGE_HOURS',
        'RADAR_MAX_REPORT_AGE_HOURS',
        'SCAN_CACHE_ENABLED',
        'SCAN_CACHE_MAX_ENTRIES',
        'PROVIDER_FAILURE_TTL_SECONDS',
        'URLSCAN_RESULT_TTL_MINUTES',
        'VIRUSTOTAL_RESULT_TTL_MINUTES',
        'OPENPHISH_RESULT_TTL_MINUTES',
        'THREATFOX_RESULT_TTL_MINUTES',
        'RADAR_RESULT_TTL_MINUTES',
        'OTX_RESULT_TTL_MINUTES',
        'HYBRID_RESULT_TTL_MINUTES',
        'SAFEBROWSING_RESULT_TTL_MINUTES',
        'OPENPHISH_FEED_TTL_MINUTES',
        'OPENPHISH_FEED_STALE_TTL_MINUTES',
      ].sort(),
    )
    expect(settings.env.GOOGLE_SAFE_BROWSING_API_KEY).toBe('k-8')
    expect(settings.env.HYBRID_ANALYSIS_API_KEY).toBe('k-7h')
    expect(settings.env.TURNSTILE_SECRET_KEY).toBe('k-9')
    expect(settings.env.TURNSTILE_HOSTNAMES).toBe('veriguard.example,veriguard.firebaseapp.com')
    expect(settings.env.FIREBASE_PROJECT_ID).toBe('veriguard-uji')
  })

  it('meneruskan kebijakan cache dari file env ke backend lokal', () => {
    const settings = buildLocalSettings({
      files: [
        {
          URLSCAN_MAX_REPORT_AGE_HOURS: '12',
          SCAN_CACHE_ENABLED: 'false',
          SAFEBROWSING_RESULT_TTL_MINUTES: '5',
          OPENPHISH_FEED_TTL_MINUTES: '30',
        },
      ],
      processEnv: {},
    })

    expect(settings.env.URLSCAN_MAX_REPORT_AGE_HOURS).toBe('12')
    expect(settings.env.SCAN_CACHE_ENABLED).toBe('false')
    expect(settings.env.SAFEBROWSING_RESULT_TTL_MINUTES).toBe('5')
    expect(settings.env.OPENPHISH_FEED_TTL_MINUTES).toBe('30')
  })

  it('memakai nilai default port dan host', () => {
    const settings = buildLocalSettings({ files: [{}], processEnv: {} })
    expect(settings.port).toBe(8787)
    expect(settings.host).toBe('127.0.0.1')
  })

  it('port di luar rentang kembali ke default', () => {
    const settings = buildLocalSettings({
      files: [{ SERVER_PORT: '70000' }],
      processEnv: {},
    })
    expect(settings.port).toBe(8787)
  })
})

import { getApp, getApps, initializeApp, type FirebaseApp } from 'firebase/app'
import { getAuth, connectAuthEmulator, type Auth } from 'firebase/auth'
import { getFirestore, connectFirestoreEmulator, type Firestore } from 'firebase/firestore'
import {
  connectFunctionsEmulator,
  getFunctions,
  type Functions,
} from 'firebase/functions'
import { initializeAppCheck, ReCaptchaV3Provider } from 'firebase/app-check'
import {
  authEmulatorUrl,
  firebaseConfigState,
  firestoreEmulatorHost,
  functionsEmulatorHost,
  useFirebaseEmulators,
} from './config'

type FirebaseClient = {
  app: FirebaseApp
  auth: Auth
  db: Firestore
  functions: Functions
}

let client: FirebaseClient | null = null
let appCheckInitialized = false

function parseEmulatorHost(value: string): { host: string; port: number } {
  const separator = value.lastIndexOf(':')
  const host = separator > 0 ? value.slice(0, separator) : ''
  const port = Number.parseInt(separator > 0 ? value.slice(separator + 1) : '', 10)

  if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(
      'Konfigurasi host emulator tidak valid. Gunakan format host:port.',
    )
  }

  return { host, port }
}

function requireEmulatorValue(value: string, variable: string): string {
  if (!value) {
    throw new Error(`${variable} wajib diisi saat emulator Firebase diaktifkan.`)
  }
  return value
}

function initializeOptionalAppCheck(app: FirebaseApp): void {
  const siteKey = import.meta.env.VITE_RECAPTCHA_SITE_KEY?.trim()
  if (!siteKey || useFirebaseEmulators || appCheckInitialized) return

  try {
    initializeAppCheck(app, {
      provider: new ReCaptchaV3Provider(siteKey),
      isTokenAutoRefreshEnabled: true,
    })
    appCheckInitialized = true
  } catch (error) {
    // App Check tetap opsional sampai enforcement diaktifkan di backend, tapi kegagalannya
    // tidak boleh senyap: tanpa token App Check, enforcement yang dinyalakan nanti menolak
    // seluruh permintaan dan penyebabnya hanya bisa ditebak dari console.
    console.warn(
      'App Check gagal diinisialisasi; permintaan akan dikirim tanpa token App Check.',
      error instanceof Error ? error.name : error,
    )
  }
}

export function getFunctionsRegion(): string {
  return import.meta.env.VITE_FUNCTIONS_REGION?.trim() || 'asia-southeast2'
}

function connectFunctionsToEmulator(functionsInstance: Functions): void {
  const value = requireEmulatorValue(
    functionsEmulatorHost,
    'VITE_FUNCTIONS_EMULATOR_HOST',
  )
  const emulator = parseEmulatorHost(value)
  connectFunctionsEmulator(functionsInstance, emulator.host, emulator.port)
}

export function getFirebaseClient(): FirebaseClient {
  if (!firebaseConfigState.configured || !firebaseConfigState.config) {
    throw new Error('Konfigurasi layanan akun belum lengkap.')
  }

  if (client) return client

  const app = getApps().length > 0 ? getApp() : initializeApp(firebaseConfigState.config)
  initializeOptionalAppCheck(app)

  const auth = getAuth(app)
  const db = getFirestore(app)
  const functions = getFunctions(app, getFunctionsRegion())

  if (useFirebaseEmulators) {
    connectAuthEmulator(
      auth,
      requireEmulatorValue(authEmulatorUrl, 'VITE_AUTH_EMULATOR_URL'),
      { disableWarnings: true },
    )
    const emulator = parseEmulatorHost(
      requireEmulatorValue(firestoreEmulatorHost, 'VITE_FIRESTORE_EMULATOR_HOST'),
    )
    connectFirestoreEmulator(db, emulator.host, emulator.port)
    connectFunctionsToEmulator(functions)
  }

  client = { app, auth, db, functions }
  return client
}

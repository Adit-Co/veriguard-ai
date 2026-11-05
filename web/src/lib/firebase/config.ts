export type FirebaseEnv = Record<string, string | undefined>

export type FirebaseClientConfig = {
  apiKey: string
  authDomain: string
  projectId: string
  appId: string
  storageBucket?: string
  messagingSenderId?: string
}

const REQUIRED_ENV = [
  ['VITE_FIREBASE_API_KEY', 'apiKey'],
  ['VITE_FIREBASE_AUTH_DOMAIN', 'authDomain'],
  ['VITE_FIREBASE_PROJECT_ID', 'projectId'],
  ['VITE_FIREBASE_APP_ID', 'appId'],
] as const

const OPTIONAL_ENV = [
  ['VITE_FIREBASE_STORAGE_BUCKET', 'storageBucket'],
  ['VITE_FIREBASE_MESSAGING_SENDER_ID', 'messagingSenderId'],
] as const

export type FirebaseConfigState = {
  configured: boolean
  config: FirebaseClientConfig | null
  missingKeys: string[]
}

export function resolveFirebaseConfig(env: FirebaseEnv): FirebaseConfigState {
  const missingKeys = REQUIRED_ENV.map(([envKey]) => envKey).filter(
    (envKey) => !env[envKey]?.trim(),
  )

  if (missingKeys.length > 0) {
    return { configured: false, config: null, missingKeys }
  }

  const config: FirebaseClientConfig = {
    apiKey: env.VITE_FIREBASE_API_KEY!.trim(),
    authDomain: env.VITE_FIREBASE_AUTH_DOMAIN!.trim(),
    projectId: env.VITE_FIREBASE_PROJECT_ID!.trim(),
    appId: env.VITE_FIREBASE_APP_ID!.trim(),
  }

  for (const [envKey, configKey] of OPTIONAL_ENV) {
    const value = env[envKey]?.trim()
    if (value) config[configKey] = value
  }

  return { configured: true, config, missingKeys: [] }
}

export const firebaseConfigState = resolveFirebaseConfig(import.meta.env as FirebaseEnv)
export const isFirebaseConfigured = firebaseConfigState.configured

const requestedEmulators =
  import.meta.env.VITE_USE_EMULATORS?.trim().toLowerCase() === 'true'
export const useFirebaseEmulators = import.meta.env.DEV && requestedEmulators
export const authEmulatorUrl = import.meta.env.VITE_AUTH_EMULATOR_URL?.trim() || ''
export const firestoreEmulatorHost =
  import.meta.env.VITE_FIRESTORE_EMULATOR_HOST?.trim() || ''
export const functionsEmulatorHost =
  import.meta.env.VITE_FUNCTIONS_EMULATOR_HOST?.trim() || ''

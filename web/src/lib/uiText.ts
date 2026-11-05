const INFRASTRUCTURE_TERMS: ReadonlyArray<readonly [RegExp, string]> = [
  [/\bVITE_FIREBASE_\*/g, 'konfigurasi layanan akun'],
  [/\bFirebase Console\b/gi, 'konsol admin'],
  [/\bproject Firebase\b/gi, 'lingkungan layanan'],
  [/\bFirebase Authentication\b/gi, 'layanan akun'],
  [/\bFirebase SDK\b/gi, 'layanan akun'],
  [/\bakun Firebase\b/gi, 'akun'],
  [/\bFirebase-mu\b/gi, 'akunmu'],
  [/\bCloud Firestore\b/gi, 'penyimpanan data'],
  [/\bFirestore Rules\b/gi, 'aturan akses data'],
  [/\bsecurity rules\b/gi, 'aturan akses data'],
  [/\bFirestore\b/gi, 'penyimpanan data'],
  [/\bFirebase\b/gi, 'layanan akun'],
  [/\bruntime Cloudflare Workers\b/gi, 'layanan pemeriksaan'],
  [/\bCloudflare Workers\b/gi, 'layanan pemeriksaan'],
  [/\bCloud Functions\b/gi, 'layanan pemeriksaan'],
  [/\bWorker\b/gi, 'layanan pemeriksaan'],
  [/\bALLOWED_ORIGINS\b/gi, 'konfigurasi alamat aplikasi'],
  [/\bdi backend\b/gi, 'pada layanan pemeriksaan'],
  [/\bbackend\b/gi, 'layanan pemeriksaan'],
  [/\b(?:[A-Z][A-Z0-9]*_)+(?:API_KEY|API_TOKEN|ACCOUNT_ID)\b/g, 'kredensial layanan'],
  [/\bAPI key\b/gi, 'kredensial layanan'],
  [/\bToken API\b/gi, 'kredensial layanan'],
]

export function userFacingText(text: string): string {
  return INFRASTRUCTURE_TERMS.reduce(
    (value, [pattern, replacement]) => value.replace(pattern, replacement),
    text,
  )
}

export function lookupSourceLabel(source: string): string {
  if (/DNS-over-HTTPS Cloudflare\/Google/i.test(source)) return 'resolver publik'
  if (/node:dns/i.test(source)) return 'resolver DNS sistem'
  return userFacingText(source)
}

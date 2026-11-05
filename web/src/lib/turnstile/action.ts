// Cermin kecil dari TURNSTILE_ACTION di functions/src/turnstile/verify.ts. Browser hanya
// boleh tahu nama aksinya, tidak pernah kunci rahasianya.
export const TURNSTILE_ACTION = {
  register: 'register',
  scan: 'scan',
} as const

import { Navigate, useLocation } from 'react-router-dom'
import type { ReactNode } from 'react'
import { useAuth } from '../../lib/auth/useAuth'
import { VERIFICATION_EMAIL_PATH, verificationGate } from '../../lib/auth/verification'

export function RequireVerifiedEmail({ children }: { children: ReactNode }) {
  const auth = useAuth()
  const location = useLocation()

  if (verificationGate(auth) === 'redirect') {
    return (
      <Navigate
        to={VERIFICATION_EMAIL_PATH}
        replace
        state={{ from: `${location.pathname}${location.search}` }}
      />
    )
  }

  return <>{children}</>
}

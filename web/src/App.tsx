import { RouterProvider } from 'react-router-dom'
import { AppErrorBoundary } from './components/errors/AppErrorBoundary'
import { AuthProvider } from './lib/auth/AuthProvider'
import { router } from './router'

export default function App() {
  return (
    <AppErrorBoundary>
      <AuthProvider>
        <RouterProvider router={router} />
      </AuthProvider>
    </AppErrorBoundary>
  )
}

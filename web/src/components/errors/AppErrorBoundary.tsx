import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AppCrashFallback } from './AppCrashFallback'

type AppErrorBoundaryProps = {
  children: ReactNode
}

type AppErrorBoundaryState = {
  failed: boolean
}

export class AppErrorBoundary extends Component<
  AppErrorBoundaryProps,
  AppErrorBoundaryState
> {
  state: AppErrorBoundaryState = { failed: false }

  static getDerivedStateFromError(): AppErrorBoundaryState {
    return { failed: true }
  }

  componentDidCatch(_error: Error, _info: ErrorInfo): void {
    // Detail error tidak dicatat karena dapat memuat input pengguna.
    if (import.meta.env.DEV) {
      console.error('[app] render error tertangkap')
    }
  }

  render() {
    if (this.state.failed) return <AppCrashFallback />
    return this.props.children
  }
}

import { lazy, Suspense, type ComponentType } from 'react'

// oxlint-disable-next-line react/only-export-components -- komponen fallback internal, bukan halaman
function RouteLoading() {
  return (
    <div
      role="status"
      aria-live="polite"
      className="mx-auto flex min-h-[45vh] max-w-3xl items-center justify-center px-4 py-16"
    >
      <p className="type-caption">Memuat halaman…</p>
    </div>
  )
}

export function lazyPage(loader: () => Promise<{ default: ComponentType }>) {
  const Page = lazy(loader)
  return (
    <Suspense fallback={<RouteLoading />}>
      <Page />
    </Suspense>
  )
}

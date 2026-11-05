import type { HTMLAttributes } from 'react'
import { cn } from '../../lib/cn'

export function Container({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        // Rongga samping baru dilebarkan pada xl. Di 1024 baris navbar sudah penuh oleh menu
        // dan aksi akun, sehingga padding 32px mendorong dokumen melebar melewati viewport.
        'mx-auto w-full max-w-[1120px] px-5 sm:px-6 xl:px-8',
        className,
      )}
      {...props}
    />
  )
}

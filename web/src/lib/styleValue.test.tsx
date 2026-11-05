// @vitest-environment jsdom

import { cleanup, render } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { styleValue } from './styleValue'

afterEach(cleanup)

describe('styleValue', () => {
  it('menerapkan lebar melalui CSSOM, bukan atribut style dari markup', () => {
    const { container } = render(<div className="h-full" ref={styleValue('width', '62%')} />)
    const bar = container.firstElementChild as HTMLElement
    expect(bar.style.width).toBe('62%')
  })

  it('memperbarui nilai ketika komponen render ulang dengan angka baru', () => {
    const first = styleValue('width', '40%')
    const { container, rerender } = render(<div ref={first} />)
    expect((container.firstElementChild as HTMLElement).style.width).toBe('40%')

    rerender(<div ref={styleValue('width', '75%')} />)
    expect((container.firstElementChild as HTMLElement).style.width).toBe('75%')
  })

  it('menolerir elemen yang dilepas dan menulis flexGrow sebagai string', () => {
    const ref = styleValue('flexGrow', 3)
    expect(() => ref(null)).not.toThrow()

    const { container } = render(<div ref={ref} />)
    expect((container.firstElementChild as HTMLElement).style.flexGrow).toBe('3')
  })
})

import { forwardRef, type ButtonHTMLAttributes } from 'react'
import { cn } from '../../lib/cn'
import { buttonStyles, type ButtonStyleProps } from './buttonStyles'

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & ButtonStyleProps

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant, size, type = 'button', ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      className={cn(buttonStyles({ variant, size }), className)}
      {...props}
    />
  )
})

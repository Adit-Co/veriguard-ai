import { splitReporterName } from '../../lib/community/reporterName'

export function MaskedReporterName({ value }: { value: unknown }) {
  const { visible, masked, mode } = splitReporterName(value)

  const parts = (
    <>
      <span className="min-w-0 [overflow-wrap:anywhere]">{visible}</span>
      {masked ? (
        <span
          className={
            mode === 'blur'
              ? 'inline-block min-w-0 select-none [overflow-wrap:anywhere]'
              : undefined
          }
          style={mode === 'blur' ? { filter: 'blur(4px)' } : undefined}
        >
          {masked}
        </span>
      ) : null}
    </>
  )

  if (mode !== 'blur') return parts

  return (
    <span className="inline-flex max-w-full flex-wrap items-baseline gap-x-2">
      {parts}
    </span>
  )
}

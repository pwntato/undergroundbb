// The outcome of the last designate/claim action, shown under the successor
// screen. The page is vertically centred, so a message in the normal flow
// would grow the content and move the buttons the person just pressed. It is
// positioned out of flow below the column instead, at the column's width, and
// scrolled into view if a tall column or a short viewport leaves it below the
// fold.

import { useEffect, useRef } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'

export function SuccessorMessages({
  message,
  error,
}: {
  readonly message: string | null
  readonly error: string | null
}) {
  const holder = useRef<HTMLDivElement>(null)
  const shown = message !== null || error !== null
  useEffect(() => {
    if (shown) holder.current?.scrollIntoView({ block: 'nearest' })
  }, [shown, message, error])
  if (!shown) return null
  return (
    <div ref={holder} className="absolute top-full right-0 left-0 mt-4 flex flex-col gap-2">
      {message !== null && (
        <Alert>
          <AlertDescription>{message}</AlertDescription>
        </Alert>
      )}
      {error !== null && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
    </div>
  )
}

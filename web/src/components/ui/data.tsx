import * as React from 'react'
import { cn } from '@/lib/utils'

/**
 * Data as opposed to prose: handles, counts, timestamps and keys. Refined Terminal keeps monospace
 * for these and nothing else, and figures line up (tabular-nums). A theme that wants no mono sets
 * `font-mono` to its sans stack and every one of these follows.
 */
function Data({ className, ...props }: React.ComponentProps<'span'>) {
  return <span data-slot="data" className={cn('font-mono tabular-nums', className)} {...props} />
}

export { Data }

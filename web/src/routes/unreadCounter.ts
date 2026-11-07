// The header's unread count (#145), as one object per signed-in user so the decisions about WHICH
// answer to show live here, where a test can pin them, and not in the component's effects.
//
// - A refresh that is not forced is skipped when the last attempt STARTED less than 30 seconds
//   ago, whether it worked, failed or is still in flight: the header sits on every screen, so a
//   read of up to 1000 rows per click would be too much, and a slow or failing count must not be
//   retried on every navigation. A failed count shows no badge for up to that long.
// - A forced refresh (a mark-read just finished) always runs.
// - Every refresh waits for any mark-read in flight, so it never counts rows just read.
// - Only the newest refresh to have STARTED is shown: an older answer landing last is dropped, and
//   a skipped refresh never invalidates a live one. Navigating does not cancel a count.

import type { UnreadTotal } from '@/lib/api/notifications'

/** How soon after the last attempt an unforced refresh is skipped. */
export const UNREAD_MIN_GAP_MS = 30_000

export interface UnreadCounter {
  /** Counts again; `force` is for a finished mark-read. */
  readonly refresh: (force: boolean) => Promise<void>
  /** After this nothing is shown from this counter. */
  readonly dispose: () => void
}

export function createUnreadCounter(deps: {
  readonly now: () => number
  readonly settled: () => Promise<void>
  readonly fetchTotal: () => Promise<UnreadTotal>
  /** Shows the newest answer: the total, or null (no badge) when the count failed. */
  readonly apply: (total: UnreadTotal | null) => void
}): UnreadCounter {
  let lastAttemptAt: number | undefined
  let newest = 0
  let disposed = false

  const refresh = async (force: boolean): Promise<void> => {
    if (disposed) return
    if (!force && lastAttemptAt !== undefined && deps.now() - lastAttemptAt < UNREAD_MIN_GAP_MS) {
      return
    }
    lastAttemptAt = deps.now()
    const mine = ++newest
    let total: UnreadTotal | null
    try {
      await deps.settled()
      total = await deps.fetchTotal()
    } catch {
      total = null
    }
    if (disposed || mine !== newest) return
    deps.apply(total)
  }

  return {
    refresh,
    dispose: () => {
      disposed = true
    },
  }
}

// One refresh of the header's unread count (#145). The header sits on every screen, so a refresh on
// each navigation would be a read of up to 1000 rows per click: a refresh is skipped when the last
// one was recent, unless `force` (a mark-read just finished, or the user changed). It waits for any
// mark-read in flight first, so it never counts rows the user has just read.

import type { UnreadTotal } from '@/lib/api/notifications'

/** How long a count is trusted when nothing known has changed it. */
export const UNREAD_MIN_GAP_MS = 30_000

export type RefreshResult =
  | { readonly status: 'skipped' }
  | { readonly status: 'ok'; readonly value: UnreadTotal }
  | { readonly status: 'failed' }

export async function refreshUnreadTotal(deps: {
  readonly force: boolean
  /** When the last successful refresh happened, in ms; undefined when none has. */
  readonly lastAt: number | undefined
  readonly now: () => number
  readonly settled: () => Promise<void>
  readonly fetchTotal: () => Promise<UnreadTotal>
}): Promise<RefreshResult> {
  if (!deps.force && deps.lastAt !== undefined && deps.now() - deps.lastAt < UNREAD_MIN_GAP_MS) {
    return { status: 'skipped' }
  }
  try {
    await deps.settled()
    return { status: 'ok', value: await deps.fetchTotal() }
  } catch {
    return { status: 'failed' }
  }
}

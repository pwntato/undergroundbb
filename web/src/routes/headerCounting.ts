// The header's two effects, as plain functions so a test can drive them without a DOM (#145).
// `startHeaderCounting` is the per-user setup AppHeader runs when the signed-in user changes: one
// counter, and a listener that counts again (forced) whenever a mark-read finishes on ANY screen.
// `refreshWhenShown` is the navigation effect.

import type { UnreadTotal } from '@/lib/api/notifications'
import { createUnreadCounter, type UnreadCounter } from './unreadCounter'

export interface HeaderCounting {
  readonly counter: UnreadCounter
  /** Unsubscribes from finished mark-reads and stops the counter showing anything more. */
  readonly stop: () => void
}

export function startHeaderCounting(deps: {
  readonly now: () => number
  readonly settled: () => Promise<void>
  readonly fetchTotal: () => Promise<UnreadTotal>
  readonly onMarksSettled: (cb: () => void) => () => void
  readonly apply: (total: UnreadTotal | null) => void
}): HeaderCounting {
  const counter = createUnreadCounter({
    now: deps.now,
    settled: deps.settled,
    fetchTotal: deps.fetchTotal,
    apply: deps.apply,
  })
  const off = deps.onMarksSettled(() => void counter.refresh(true))
  return {
    counter,
    stop: () => {
      off()
      counter.dispose()
    },
  }
}

/** Counts (unforced: the counter skips it after a recent attempt) only while the header shows. */
export function refreshWhenShown(shown: boolean, counter: UnreadCounter | null): void {
  if (shown) void counter?.refresh(false)
}

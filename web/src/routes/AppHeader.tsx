// The one piece of chrome the signed-in screens share (#69): a link to the notification list, on
// every screen except the ones in appHeaderPaths.ts, which hold a one-time recovery code a link out
// would lose. Absolutely placed so it does not push the centred screens down. The link carries the
// unread count (#145), fetched from GET /api/notifications/unread by the counter in
// unreadCounter.ts (which decides when to count and which answer to show), when the header appears
// and on navigation, and again whenever a mark-read finishes. A failed fetch shows no badge, never
// a stale or zero one. A dropdown is not built.

import { useEffect, useRef, useState } from 'react'
import { Link, useLocation } from 'react-router'
import { getUnreadTotal, type UnreadTotal } from '@/lib/api/notifications'
import { useSession } from '@/lib/session/useSession'
import { headerShownOn } from './appHeaderPaths'
import { marksSettled, onMarksSettled } from './markReadTracker'
import { refreshWhenShown, startHeaderCounting } from './headerCounting'
import type { UnreadCounter } from './unreadCounter'
import { unreadAriaLabel, unreadLabel } from './unreadLabel'

export function AppHeaderLink({ total }: { readonly total?: UnreadTotal | null }) {
  const label = total ? unreadLabel(total.unread, total.unreadMore) : null
  return (
    <Link to="/notifications" className="text-sm text-primary underline-offset-4 hover:underline">
      Notifications
      {label !== null && (
        <>
          <span
            aria-hidden="true"
            className="ml-2 inline-block rounded-full bg-primary px-2 py-0.5 text-xs font-normal text-primary-foreground no-underline"
          >
            {label}
          </span>
          <span className="sr-only">{` (${unreadAriaLabel(label)})`}</span>
        </>
      )}
    </Link>
  )
}

export function AppHeader() {
  const session = useSession()
  const { pathname } = useLocation()
  const userId = session.status === 'loading' ? null : session.userId
  const shown = userId !== null && headerShownOn(pathname)
  // The count belongs to the user it was fetched for: a different user starts with none.
  const [counted, setCounted] = useState<{ userId: string; total: UnreadTotal | null } | null>(null)
  const counter = useRef<UnreadCounter | null>(null)

  // One counter per user, listening for finished mark-reads on every screen (a mark that finishes
  // on a screen with no header still has to be counted).
  useEffect(() => {
    if (userId === null) return
    const started = startHeaderCounting({
      now: Date.now,
      settled: marksSettled,
      fetchTotal: getUnreadTotal,
      onMarksSettled,
      apply: (total) => setCounted({ userId, total }),
    })
    counter.current = started.counter
    return () => {
      started.stop()
      if (counter.current === started.counter) counter.current = null
    }
  }, [userId])

  // On appearing and on navigation; the counter skips it when an attempt is recent.
  useEffect(() => {
    refreshWhenShown(shown, counter.current)
  }, [shown, pathname, userId])

  if (!shown) return null
  return (
    <header className="absolute right-4 top-3">
      <AppHeaderLink total={counted !== null && counted.userId === userId ? counted.total : null} />
    </header>
  )
}

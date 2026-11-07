// The one piece of chrome the signed-in screens share (#69): a link to the notification list, on
// every screen except the ones in appHeaderPaths.ts, which hold a one-time recovery code a link out
// would lose. Absolutely placed so it does not push the centred screens down. The link carries the
// unread count (#145): fetched from GET /api/notifications/unread when the header appears and on
// navigation (not more often than every 30 seconds), and again whenever a mark-read finishes. A
// failed fetch shows no badge, never a stale or zero one. A dropdown is not built.

import { useEffect, useRef, useState } from 'react'
import { Link, useLocation } from 'react-router'
import { getUnreadTotal, type UnreadTotal } from '@/lib/api/notifications'
import { useSession } from '@/lib/session/useSession'
import { headerShownOn } from './appHeaderPaths'
import { marksSettled, onMarksSettled } from './markReadTracker'
import { refreshUnreadTotal } from './refreshUnreadTotal'
import { unreadLabel } from './unreadLabel'

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
          <span className="sr-only">
            {` (${label} unread ${label === '1' ? 'notification' : 'notifications'})`}
          </span>
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
  const lastAt = useRef<{ userId: string; at: number } | null>(null)

  useEffect(() => {
    if (!shown || userId === null) return
    let cancelled = false
    const refresh = async (force: boolean) => {
      const last = lastAt.current
      const r = await refreshUnreadTotal({
        force,
        lastAt: last !== null && last.userId === userId ? last.at : undefined,
        now: Date.now,
        settled: marksSettled,
        fetchTotal: getUnreadTotal,
      })
      if (cancelled || r.status === 'skipped') return
      if (r.status === 'ok') lastAt.current = { userId, at: Date.now() }
      setCounted({ userId, total: r.status === 'ok' ? r.value : null })
    }
    // On appearing and on navigation (skipped when a count is recent), and whenever a mark-read
    // finishes.
    void refresh(false)
    const off = onMarksSettled(() => void refresh(true))
    return () => {
      cancelled = true
      off()
    }
  }, [shown, pathname, userId])

  if (!shown) return null
  return (
    <header className="absolute right-4 top-3">
      <AppHeaderLink total={counted !== null && counted.userId === userId ? counted.total : null} />
    </header>
  )
}

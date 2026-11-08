// #69: the caller's notifications at /notifications. The server lists them (replies newest first,
// then reactions, with rows for groups left and posts gone already dropped); this screen names the
// groups and actors, renders the sentences, and marks rows read: one when its link is followed, all
// the loaded ones on request. A private group's name needs this tab's keys, so after a reload it
// reads "(private group)" until the user signs in again from Home.

import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router'
import { Button } from '@/components/ui/button'
import { getKeychain, listGroups } from '@/lib/api/groups'
import { listNotifications, markNotificationsRead } from '@/lib/api/notifications'
import { decryptGroupNames } from '@/lib/crypto/worker-client'
import { getCachedGroupName, setCachedGroupName } from '@/lib/groups/groupNameCache'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { useSession } from '@/lib/session/useSession'
import { groupLabel } from './groupLabel'
import { NotificationsPanel, type NotificationsLoad } from './NotificationsPanel'
import { runListGroups } from './runListGroups'
import { markFailedAfter, runTrackedMarkRead } from './runMarkRead'
import { useUsernames } from './useUsernames'

export function NotificationsScreen() {
  const session = useSession()
  const [load, setLoad] = useState<NotificationsLoad>({ status: 'loading' })
  const [cursor, setCursor] = useState<string | undefined>(undefined)
  const [loadingMore, setLoadingMore] = useState(false)
  const [moreFailed, setMoreFailed] = useState(false)
  const [markFailed, setMarkFailed] = useState(false)
  const [groupLabels, setGroupLabels] = useState<ReadonlyMap<string, string>>(new Map())

  const items = load.status === 'ready' ? load.items : []
  const usernames = useUsernames(items.map((n) => n.actorUserId))

  useEffect(() => {
    if (!session.userId) return
    let cancelled = false
    void (async () => {
      try {
        const page = await listNotifications()
        if (cancelled) return
        setLoad({
          status: 'ready',
          items: page.notifications,
          hasMore: page.nextCursor !== undefined,
        })
        setCursor(page.nextCursor)
      } catch {
        if (!cancelled) setLoad({ status: 'error' })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [session.userId])

  // Group names come from the same list Home shows; the server already dropped notifications for
  // groups the caller left, so every group id here is one in this list.
  useEffect(() => {
    if (!session.userId) return
    let cancelled = false
    void (async () => {
      try {
        const groups = await runListGroups({
          listGroups,
          decryptGroupNames,
          getNameChain: (gid, nameGen, gen) => fetchNameChain(getKeychain, gid, nameGen, gen),
          getCachedGroupName,
          setCachedGroupName,
          userId: session.userId as string,
        })
        if (!cancelled) setGroupLabels(new Map(groups.map((g) => [g.groupId, groupLabel(g)])))
      } catch {
        // Names are best effort; the sentences say "a group".
      }
    })()
    return () => {
      cancelled = true
    }
  }, [session.userId])

  const markRead = useCallback(async (ids: readonly string[], fresh: boolean) => {
    const result = await runTrackedMarkRead(ids, markNotificationsRead)
    const done = new Set(result.marked)
    setLoad((prev) =>
      prev.status === 'ready'
        ? { ...prev, items: prev.items.map((n) => (done.has(n.id) ? { ...n, read: true } : n)) }
        : prev,
    )
    setMarkFailed((prev) => markFailedAfter(prev, result.failed, fresh))
  }, [])

  const onLoadMore = useCallback(() => {
    if (cursor === undefined) return
    setLoadingMore(true)
    setMoreFailed(false)
    void (async () => {
      try {
        const page = await listNotifications(cursor)
        setLoad((prev) => {
          if (prev.status !== 'ready') return prev
          const have = new Set(prev.items.map((n) => n.id))
          return {
            status: 'ready',
            items: [...prev.items, ...page.notifications.filter((n) => !have.has(n.id))],
            hasMore: page.nextCursor !== undefined,
          }
        })
        setCursor(page.nextCursor)
      } catch {
        setMoreFailed(true)
      } finally {
        setLoadingMore(false)
      }
    })()
  }, [cursor])

  if (session.status === 'loading') return null

  return (
    <div className="flex w-full max-w-md flex-col items-center gap-4 text-center">
      <h1 className="font-mono text-2xl font-bold tracking-tight text-primary">Notifications</h1>
      <NotificationsPanel
        load={load}
        usernames={usernames}
        groupLabels={groupLabels}
        loadingMore={loadingMore}
        moreFailed={moreFailed}
        markFailed={markFailed}
        onLoadMore={onLoadMore}
        onMarkAllRead={() => {
          void markRead(
            items.filter((n) => !n.read).map((n) => n.id),
            true,
          )
        }}
        onOpen={(n) => {
          if (!n.read) void markRead([n.id], false)
        }}
      />
      <Button asChild variant="outline">
        <Link to="/">Back</Link>
      </Button>
    </div>
  )
}

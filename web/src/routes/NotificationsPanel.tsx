// The presentational half of the notification list (#69): a plain state in, markup out, tested with
// renderToStaticMarkup like GroupList. NotificationsScreen owns fetching and marking read.

import { Link } from 'react-router'
import { Button } from '@/components/ui/button'
import type { WireNotification } from '@/lib/api/notifications'
import { notificationHref, notificationText } from './notificationText'

export type NotificationsLoad =
  | { readonly status: 'loading' }
  | { readonly status: 'error' }
  | {
      readonly status: 'ready'
      readonly items: readonly WireNotification[]
      readonly hasMore: boolean
    }

export function NotificationsPanel({
  load,
  usernames,
  groupLabels,
  loadingMore,
  moreFailed,
  markFailed,
  onLoadMore,
  onMarkAllRead,
  onOpen,
}: {
  readonly load: NotificationsLoad
  readonly usernames: ReadonlyMap<string, string>
  /** Group id to label; a group with no entry is shown as "a group". */
  readonly groupLabels: ReadonlyMap<string, string>
  readonly loadingMore: boolean
  readonly moreFailed: boolean
  readonly markFailed: boolean
  readonly onLoadMore: () => void
  readonly onMarkAllRead: () => void
  /** Called when a notification's link is followed, to mark that one read. */
  readonly onOpen: (n: WireNotification) => void
}) {
  if (load.status === 'loading') {
    return <p className="text-sm text-muted-foreground">Loading your notifications…</p>
  }
  if (load.status === 'error') {
    return (
      <p className="text-sm text-destructive">
        Couldn&apos;t load your notifications. Try reloading the page.
      </p>
    )
  }
  const anyUnread = load.items.some((n) => !n.read)
  return (
    <div className="flex w-full flex-col gap-3 text-left">
      {load.items.length === 0 && (
        <p className="text-center text-sm text-muted-foreground">
          {load.hasMore ? 'Nothing to show yet.' : 'Nothing new.'}
        </p>
      )}
      {load.items.length > 0 && (
        <ul className="flex flex-col gap-2">
          {load.items.map((n) => (
            <li
              key={n.id}
              data-unread={n.read ? undefined : 'true'}
              className={`rounded-md border px-3 py-2 text-sm ${n.read ? 'text-muted-foreground' : 'font-medium'}`}
            >
              <Link
                to={notificationHref(n)}
                onClick={() => {
                  onOpen(n)
                }}
                className="underline-offset-4 hover:underline"
              >
                {notificationText(
                  n,
                  usernames.get(n.actorUserId),
                  groupLabels.get(n.groupId) ?? 'a group',
                )}
              </Link>
              {!n.read && <span className="ml-2 text-xs text-primary">new</span>}
            </li>
          ))}
        </ul>
      )}
      {markFailed && (
        <p role="alert" className="text-sm text-destructive">
          Couldn&apos;t mark those as read. Try again.
        </p>
      )}
      {moreFailed && (
        <p role="alert" className="text-sm text-destructive">
          Couldn&apos;t load more. Try again.
        </p>
      )}
      <div className="flex flex-wrap justify-center gap-2">
        {anyUnread && (
          <Button variant="outline" onClick={onMarkAllRead}>
            Mark these read
          </Button>
        )}
        {load.hasMore && (
          <Button variant="outline" disabled={loadingMore} onClick={onLoadMore}>
            {loadingMore ? 'Loading…' : 'Load more'}
          </Button>
        )}
      </div>
    </div>
  )
}

// What a notification says and where it goes (#69). The server stores identifiers only, so the
// sentence is built here from the actor's username and the group's label.

import type { WireNotification } from '@/lib/api/notifications'

/** "alice replied in Roof Group" / "alice reacted in Roof Group". An unresolved actor is "Someone". */
export function notificationText(
  n: Pick<WireNotification, 'kind' | 'cmtPath'>,
  actor: string | undefined,
  groupLabelText: string,
): string {
  const who = actor === undefined || actor === '' ? 'Someone' : actor
  // A reply's cmtPath is the reply's own path (never 0000), and the server sent it to whoever the
  // path names: a path with no dot is top-level, so it went to the post's author. A reaction's
  // cmtPath is its target, 0000 for the post.
  const onPost = n.kind === 'reply' ? !n.cmtPath.includes('.') : n.cmtPath === '0000'
  const where = onPost ? 'your post' : 'your comment'
  const verb = n.kind === 'reply' ? 'replied to' : 'reacted to'
  return `${who} ${verb} ${where} in ${groupLabelText}`
}

/** The thread the notification lands in (the post; comments carry no anchor yet). */
export function notificationHref(n: Pick<WireNotification, 'groupId' | 'postId'>): string {
  return `/groups/${n.groupId}/posts/${encodeURIComponent(n.postId)}`
}

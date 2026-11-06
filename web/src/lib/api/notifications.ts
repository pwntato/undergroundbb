// Typed client for GET /api/notifications and PUT /api/notifications/read (#69); the server side is
// internal/handlers/notification.go. A notification is identifiers only: the client writes the
// sentence (docs/DESIGN.md, "Notification items hold identifiers, not text").

import { ApiError } from './auth.js'

export interface WireNotification {
  /** The row's sort key; what mark-read takes. */
  readonly id: string
  readonly kind: 'reply' | 'reaction'
  readonly actorUserId: string
  readonly groupId: string
  readonly postId: string
  /** Where it lands: the new reply's path, or the comment a reaction is on (0000 for the post). */
  readonly cmtPath: string
  readonly read: boolean
}

export interface NotificationPage {
  readonly notifications: readonly WireNotification[]
  /** Opaque; absent when the list ends. */
  readonly nextCursor?: string
}

/** Ids per mark-read request; the server refuses more (maxMarkRead). */
export const MARK_READ_BATCH = 25

async function readJSON(res: Response): Promise<unknown> {
  let data: unknown
  try {
    data = await res.json()
  } catch {
    throw new ApiError(res.status, res.statusText || 'malformed response')
  }
  if (!res.ok) {
    const message =
      typeof data === 'object' && data !== null && 'error' in data && typeof data.error === 'string'
        ? data.error
        : res.statusText || 'request failed'
    throw new ApiError(res.status, message)
  }
  return data
}

/** One page of the caller's notifications, from `cursor` (omit for the first page). */
export async function listNotifications(cursor?: string): Promise<NotificationPage> {
  const query = cursor === undefined ? '' : `?cursor=${encodeURIComponent(cursor)}`
  const res = await fetch(`/api/notifications${query}`, { credentials: 'same-origin' })
  const data = (await readJSON(res)) as NotificationPage
  if (!Array.isArray(data.notifications)) throw new ApiError(res.status, 'malformed response')
  return data
}

/** Marks up to MARK_READ_BATCH of the caller's notifications read. */
export async function markNotificationsRead(ids: readonly string[]): Promise<void> {
  const res = await fetch('/api/notifications/read', {
    method: 'PUT',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ids }),
  })
  if (!res.ok) await readJSON(res)
}

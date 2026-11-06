// renderToStaticMarkup, like GroupList.test.tsx: the panel takes plain state and has no effects.
import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router'
import type { WireNotification } from '@/lib/api/notifications'
import { NotificationsPanel, type NotificationsLoad } from './NotificationsPanel'

const note = (over: Partial<WireNotification> = {}): WireNotification => ({
  id: 'NOTIF#2026-10-20#' + '0'.repeat(32),
  kind: 'reply',
  actorUserId: 'u1',
  groupId: 'g1',
  postId: 'g1#2026-10-01#00112233445566a1',
  cmtPath: '0000',
  read: false,
  ...over,
})

function render(
  load: NotificationsLoad,
  over: Partial<Parameters<typeof NotificationsPanel>[0]> = {},
): string {
  return renderToStaticMarkup(
    createElement(
      MemoryRouter,
      null,
      createElement(NotificationsPanel, {
        load,
        usernames: new Map([['u1', 'alice']]),
        groupLabels: new Map([['g1', 'Roof Group']]),
        loadingMore: false,
        moreFailed: false,
        markFailed: false,
        onLoadMore: () => {},
        onMarkAllRead: () => {},
        onOpen: () => {},
        ...over,
      }),
    ),
  )
}

describe('NotificationsPanel', () => {
  it('says loading and error plainly', () => {
    expect(render({ status: 'loading' })).toContain('Loading your notifications')
    expect(render({ status: 'error' })).toContain('Couldn&#x27;t load your notifications')
  })

  it('shows an empty list as nothing new, with no buttons', () => {
    const html = render({ status: 'ready', items: [], hasMore: false })
    expect(html).toContain('Nothing new.')
    expect(html).not.toContain('Mark all read')
    expect(html).not.toContain('Load more')
  })

  it('renders the sentence, the thread link and the unread marker', () => {
    const html = render({ status: 'ready', items: [note()], hasMore: false })
    expect(html).toContain('alice replied to your post in Roof Group')
    expect(html).toContain('href="/groups/g1/posts/g1%232026-10-01%2300112233445566a1"')
    expect(html).toContain('data-unread="true"')
    expect(html).toContain('Mark all read')
  })

  it('shows a read notification without the marker, and no Mark all read when none are unread', () => {
    const html = render({ status: 'ready', items: [note({ read: true })], hasMore: false })
    expect(html).not.toContain('data-unread')
    expect(html).not.toContain('Mark all read')
  })

  it('falls back to Someone and a group when the names did not resolve', () => {
    const html = render(
      { status: 'ready', items: [note()], hasMore: false },
      { usernames: new Map(), groupLabels: new Map() },
    )
    expect(html).toContain('Someone replied to your post in a group')
  })

  it('offers Load more only when the server has another page, and disables it while loading', () => {
    expect(render({ status: 'ready', items: [note()], hasMore: true })).toContain('Load more')
    const busy = render({ status: 'ready', items: [note()], hasMore: true }, { loadingMore: true })
    expect(busy).toMatch(/<button[^>]*disabled[^>]*>Loading…/)
  })

  it('reports a failed mark and a failed page', () => {
    const html = render(
      { status: 'ready', items: [note()], hasMore: true },
      { markFailed: true, moreFailed: true },
    )
    expect(html).toContain('mark those as read')
    expect(html).toContain('load more')
  })
})

// Markup tests for InvitesPanel (renderToStaticMarkup, per
// GroupList.test.tsx's reasoning).

import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import type { ReceivedInvite, SentInvite } from '@/lib/api/invites'
import { InvitesPanel } from './InvitesPanel'

const pending: SentInvite = {
  inviteId: 'i-pending',
  groupId: 'g1',
  expiresAt: '2026-10-05T23:59:59Z',
  accepted: false,
}
const accepted: SentInvite = {
  inviteId: 'i-accepted',
  groupId: 'g2',
  expiresAt: '2026-10-05T23:59:59Z',
  accepted: true,
  completionDeadline: '2026-10-08T23:59:59Z',
}
const received: ReceivedInvite = {
  inviteId: 'i-recv',
  groupId: 'g3',
  inviterUserId: 'abcd1234-0000-4000-8000-000000000000',
  completionDeadline: '2026-10-09T23:59:59Z',
}

function render(
  view: { sent?: SentInvite[]; received?: ReceivedInvite[] },
  busyInviteId: string | null = null,
): string {
  return renderToStaticMarkup(
    createElement(InvitesPanel, {
      view: { sent: view.sent ?? [], received: view.received ?? [] },
      groupLabels: new Map([['g1', 'Book Club']]),
      busyInviteId,
      onRevoke: () => undefined,
    }),
  )
}

describe('InvitesPanel', () => {
  it('shows empty states for both lists', () => {
    const html = render({})
    expect(html).toContain('no outstanding invites')
    expect(html).toContain('no accepted invites waiting')
  })

  it('offers Revoke on a pending invite only, with its expiry date', () => {
    const html = render({ sent: [pending, accepted] })
    expect(html.match(/Revoke/g)).toHaveLength(1)
    expect(html).toContain('Book Club')
    expect(html).toContain('Expires 2026-10-05')
  })

  it('shows an accepted invite as owed work with its completion deadline, not revocable', () => {
    const html = render({ sent: [accepted] })
    expect(html).not.toContain('Revoke')
    expect(html).toContain('Accepted. Completes the next time you log in')
    expect(html).toContain('2026-10-08')
    // A group the caller has no label for renders generically.
    expect(html).toContain('a group')
  })

  it('shows a received invite as waiting on the inviter', () => {
    const html = render({ received: [received] })
    expect(html).toContain('abcd1234')
    expect(html).toContain('2026-10-09')
    expect(html).toContain('You join once they next log in')
  })

  it('locks every revoke button while one is in flight and labels the busy one', () => {
    const other = { ...pending, inviteId: 'i-other' }
    const html = render({ sent: [pending, other] }, 'i-pending')
    expect(html.match(/disabled=""/g)).toHaveLength(2)
    expect(html).toContain('Revoking…')
  })
})

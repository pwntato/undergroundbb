import { describe, expect, it, vi } from 'vitest'
import { createElement } from 'react'
import { MemoryRouter } from 'react-router'
import { renderToStaticMarkup } from 'react-dom/server'
import type { JoinRequestEntry, MyJoinRequest } from '@/lib/api/joinRequests'
import { elementsOf } from './elementTree.testkit'
import {
  JoinGroupPanel,
  MyJoinRequestsPanel,
  PendingJoinRequestsPanel,
  type ReviewPrompt,
} from './JoinRequestPanels'

const html = (el: React.ReactElement) => renderToStaticMarkup(createElement(MemoryRouter, null, el))

function click(el: { props: Record<string, unknown> } | undefined): void {
  if (el === undefined) throw new Error('element not found')
  ;(el.props['onClick'] as () => void)()
}

const FP = '11111-22222-33333-44444-55555-66666-77777-88888-99999-00000-11111-22222'

describe('JoinGroupPanel', () => {
  const base = {
    groupName: 'Book Club',
    busy: false,
    isMember: false,
    sent: false,
    onRequest: () => undefined,
  }

  it('offers the request and says what the admin will see', () => {
    const out = html(createElement(JoinGroupPanel, base))
    expect(out).toContain('Book Club')
    expect(out).toContain('Ask to join')
    expect(out).toContain('approve you')
  })

  it('offers nothing to a member, and links to the requests once sent', () => {
    expect(html(createElement(JoinGroupPanel, { ...base, isMember: true }))).not.toContain(
      '<button',
    )
    const sent = html(createElement(JoinGroupPanel, { ...base, sent: true }))
    expect(sent).not.toContain('<button')
    expect(sent).toContain('/join-requests')
  })

  it('calls onRequest from the real button, and disables it while sending', () => {
    const onRequest = vi.fn()
    const el = JoinGroupPanel({ ...base, onRequest })
    const button = elementsOf(el).find((e) => (e.type as { name?: string }).name === 'Button')
    expect(button).toBeDefined()
    click(button)
    expect(onRequest).toHaveBeenCalledOnce()
    const busy = JoinGroupPanel({ ...base, busy: true })
    const busyButton = elementsOf(busy).find((e) => (e.type as { name?: string }).name === 'Button')
    expect(busyButton?.props['disabled']).toBe(true)
  })
})

describe('MyJoinRequestsPanel', () => {
  const pending: MyJoinRequest = {
    groupId: 'g1',
    groupName: 'Book Club',
    requestId: 'r1',
    status: 'pending',
    day: '2026-11-08',
  }
  const denied: MyJoinRequest = {
    groupId: 'g2',
    groupName: 'Chess',
    requestId: 'r2',
    status: 'denied',
    day: '2026-11-01',
    retryAfter: '2026-11-08',
  }
  const props = {
    requests: [pending, denied],
    busyGroupId: null,
    hasMore: false,
    onWithdraw: () => undefined,
    onLoadMore: () => undefined,
  }

  it('lets a pending request be withdrawn and tells a declined one when to ask again', () => {
    const out = html(createElement(MyJoinRequestsPanel, props))
    expect(out).toContain('Waiting since 2026-11-08')
    expect(out).toContain('Withdraw')
    expect(out).toContain('Declined. You can ask again after 2026-11-08.')
    expect(out.match(/Withdraw/g)).toHaveLength(1)
    expect(out).toContain('/groups/g2/join')
  })

  it('withdraws the right group from the real button', () => {
    const onWithdraw = vi.fn()
    const el = MyJoinRequestsPanel({ ...props, onWithdraw })
    const button = elementsOf(el).find((e) => (e.type as { name?: string }).name === 'Button')
    click(button)
    expect(onWithdraw).toHaveBeenCalledWith('g1')
  })

  it('says so when there are none', () => {
    expect(html(createElement(MyJoinRequestsPanel, { ...props, requests: [] }))).toContain(
      'no requests',
    )
  })
})

describe('PendingJoinRequestsPanel', () => {
  const req: JoinRequestEntry = {
    userId: 'aaaaaaaa-1111-4222-8333-444444444444',
    requestId: 'r1',
    ed25519PublicKey: 'e',
    x25519PublicKey: 'x',
    signature: 's',
    day: '2026-11-08',
  }
  const props = {
    requests: [req],
    usernames: new Map([[req.userId, 'rex']]),
    review: null as ReviewPrompt | null,
    busyUserId: null as string | null,
    hasMore: false,
    onReview: () => undefined,
    onCancelReview: () => undefined,
    onApprove: () => undefined,
    onDeny: () => undefined,
    onLoadMore: () => undefined,
  }

  it('offers Review and Decline but never a bare Approve', () => {
    const out = html(createElement(PendingJoinRequestsPanel, props))
    expect(out).toContain('rex')
    expect(out).toContain('Review')
    expect(out).toContain('Decline')
    expect(out).not.toContain('approve')
  })

  it('shows the fingerprint and a trust-on-first-use warning before Approve', () => {
    const out = html(
      createElement(PendingJoinRequestsPanel, {
        ...props,
        review: { userId: req.userId, fingerprint: FP, firstSight: true },
      }),
    )
    expect(out).toContain('11111-22222-33333-44444')
    expect(out).toContain('trusted on first sight')
    expect(out).toContain('It matches, approve')
    expect(out).not.toContain('>Review<')
  })

  it('does not call a saved-copy match a first sight', () => {
    const out = html(
      createElement(PendingJoinRequestsPanel, {
        ...props,
        review: { userId: req.userId, fingerprint: FP, firstSight: false },
      }),
    )
    expect(out).toContain('match the copy you saved')
    expect(out).not.toContain('first sight')
  })

  it('wires Review, Approve and Decline to the right user', () => {
    const onReview = vi.fn()
    const onDeny = vi.fn()
    const buttons = (el: React.ReactElement) =>
      elementsOf(el).filter((e) => (e.type as { name?: string }).name === 'Button')
    const list = buttons(PendingJoinRequestsPanel({ ...props, onReview, onDeny }))
    click(list[0])
    click(list[1])
    expect(onReview).toHaveBeenCalledWith(req.userId)
    expect(onDeny).toHaveBeenCalledWith(req.userId)

    const onApprove = vi.fn()
    const reviewing = buttons(
      PendingJoinRequestsPanel({
        ...props,
        onApprove,
        review: { userId: req.userId, fingerprint: FP, firstSight: true },
      }),
    )
    click(reviewing[0])
    expect(onApprove).toHaveBeenCalledWith(req.userId)
  })

  it('locks every button while one request is being handled', () => {
    const el = PendingJoinRequestsPanel({ ...props, busyUserId: req.userId })
    const buttons = elementsOf(el).filter((e) => (e.type as { name?: string }).name === 'Button')
    expect(buttons.length).toBeGreaterThan(0)
    expect(buttons.every((b) => b.props['disabled'] === true)).toBe(true)
  })
})

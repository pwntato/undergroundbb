import { describe, expect, it, vi } from 'vitest'
import { createElement } from 'react'
import { MemoryRouter } from 'react-router'
import { renderToStaticMarkup } from 'react-dom/server'
import type { IncomingDM } from '@/lib/api/dms'
import { IncomingDMsPanel, NewDMPanel, type DMReviewPrompt, type NewDMState } from './DMPanels'
import { elementsOf } from './elementTree.testkit'

const html = (el: React.ReactElement) => renderToStaticMarkup(createElement(MemoryRouter, null, el))

const FP = '11111-22222-33333-44444-55555-66666-77777-88888-99999-00000-11111-22222'

function buttons(el: React.ReactNode) {
  return elementsOf(el).filter((e) => (e.type as { name?: string }).name === 'Button')
}
function labelOf(button: { props: Record<string, unknown> }): string {
  return String(button.props['children'])
}
function click(el: { props: Record<string, unknown> } | undefined): void {
  if (el === undefined) throw new Error('element not found')
  ;(el.props['onClick'] as () => void)()
}

describe('NewDMPanel', () => {
  const ready: NewDMState = { status: 'ready', fingerprint: FP, firstSight: true }
  const base = { username: 'rex', state: ready, busy: false, onSend: () => undefined }

  it('shows their fingerprint and what it is for BEFORE the send button', () => {
    const out = html(createElement(NewDMPanel, base))
    expect(out).toContain('Message rex')
    expect(out).toContain('11111-22222-33333-44444')
    expect(out).toContain('trusted on first sight')
    expect(out).toContain('in person or on a call')
    expect(out.indexOf('11111-22222')).toBeLessThan(out.indexOf('It matches, start'))
  })

  it('says the keys match the saved copy when they do', () => {
    const out = html(createElement(NewDMPanel, { ...base, state: { ...ready, firstSight: false } }))
    expect(out).toContain('match the copy you saved')
    expect(out).not.toContain('trusted on first sight')
  })

  it('offers no send button while checking or when blocked, and says why', () => {
    const checking = html(createElement(NewDMPanel, { ...base, state: { status: 'checking' } }))
    expect(checking).not.toContain('<button')
    expect(checking).toContain('Checking')
    const blocked = html(
      createElement(NewDMPanel, {
        ...base,
        state: { status: 'blocked', message: 'The keys shown do not match.' },
      }),
    )
    expect(blocked).not.toContain('<button')
    expect(blocked).toContain('The keys shown do not match.')
    expect(blocked).not.toContain('11111-22222')
  })

  it('calls onSend from the real button, and disables it while sending', () => {
    const onSend = vi.fn()
    const only = buttons(NewDMPanel({ ...base, onSend }))
    expect(only).toHaveLength(1)
    click(only[0])
    expect(onSend).toHaveBeenCalledOnce()
    const busy = buttons(NewDMPanel({ ...base, busy: true }))
    expect(busy[0]?.props['disabled']).toBe(true)
  })
})

describe('IncomingDMsPanel', () => {
  const dm = (over: Partial<IncomingDM> = {}): IncomingDM => ({
    groupId: 'g1',
    senderUserId: 'aaaaaaaa-1111-4222-8333-444444444444',
    requestId: 'r1',
    recipientEd25519PublicKey: 'e',
    recipientX25519PublicKey: 'x',
    wrappedGroupKey: { ephemeralPub: 'a', nonce: 'b', ciphertext: 'c' },
    admissionDay: '2026-11-09',
    admissionGrantRef: 'GRANT#x',
    admissionSignature: 's',
    ...over,
  })
  const first = dm()
  const second = dm({ groupId: 'g2', senderUserId: 'bbbbbbbb-1111-4222-8333-444444444444' })
  const props = {
    dms: [first, second],
    usernames: new Map([
      [first.senderUserId, 'rex'],
      [second.senderUserId, 'sam'],
    ]),
    review: null as DMReviewPrompt | null,
    busyGroupId: null as string | null,
    onReview: () => undefined,
    onCancelReview: () => undefined,
    onAccept: () => undefined,
    onDecline: () => undefined,
  }

  it('lists each sender and offers Review and Decline, never a bare open', () => {
    const out = html(createElement(IncomingDMsPanel, props))
    expect(out).toContain('rex')
    expect(out).toContain('sam')
    expect(out).toContain('Review')
    expect(out).toContain('Decline')
    expect(out).not.toContain('open it')
    expect(out).not.toContain('11111-22222')
  })

  it('says so when no one is waiting', () => {
    expect(html(createElement(IncomingDMsPanel, { ...props, dms: [] }))).toContain(
      'No one is waiting',
    )
  })

  it('shows only the reviewed sender’s fingerprint, with the first-sight warning', () => {
    const out = html(
      createElement(IncomingDMsPanel, {
        ...props,
        review: { groupId: 'g2', fingerprint: FP, firstSight: true },
      }),
    )
    expect(out.match(/11111-22222-33333-44444/g)).toHaveLength(1)
    expect(out).toContain('trusted on first sight')
    expect(out).toContain('It matches, open it')
    // The unreviewed row keeps its own Review button.
    expect(out.match(/>Review</g)).toHaveLength(1)
    expect(out.indexOf('11111-22222')).toBeLessThan(out.indexOf('It matches, open it'))
  })

  it('routes each button to the right conversation', () => {
    const onReview = vi.fn()
    const onDecline = vi.fn()
    const el = IncomingDMsPanel({ ...props, onReview, onDecline })
    const all = buttons(el)
    // Row order: first Review, first Decline, second Review, second Decline.
    expect(all.map(labelOf)).toEqual(['Review', 'Decline', 'Review', 'Decline'])
    click(all[2])
    expect(onReview).toHaveBeenCalledWith('g2')
    click(all[1])
    expect(onDecline).toHaveBeenCalledWith('g1')
  })

  it('opens, declines and cancels the reviewed conversation from the real buttons', () => {
    const onAccept = vi.fn()
    const onDecline = vi.fn()
    const onCancelReview = vi.fn()
    const el = IncomingDMsPanel({
      ...props,
      review: { groupId: 'g1', fingerprint: FP, firstSight: false },
      onAccept,
      onDecline,
      onCancelReview,
    })
    // The reviewed row's own three buttons come first; the other row only has Review and Decline.
    const reviewing = buttons(el).slice(0, 3)
    expect(reviewing.map(labelOf)).toEqual(['It matches, open it', 'Decline', 'Cancel'])
    click(reviewing[0])
    click(reviewing[1])
    click(reviewing[2])
    expect(onAccept).toHaveBeenCalledWith('g1')
    expect(onDecline).toHaveBeenCalledWith('g1')
    expect(onCancelReview).toHaveBeenCalledOnce()
  })

  it('disables every button while one conversation is busy', () => {
    const el = IncomingDMsPanel({ ...props, busyGroupId: 'g1' })
    for (const b of buttons(el)) expect(b.props['disabled']).toBe(true)
    const out = html(createElement(IncomingDMsPanel, { ...props, busyGroupId: 'g1' }))
    expect(out).toContain('Checking…')
  })
})

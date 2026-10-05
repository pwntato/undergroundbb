import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { LeaveGroupPanel } from './LeaveGroupPanel'
import type { LeavePlan } from './runLeaveGroup'

const BOB = 'bbbbbbbb-2222-4222-8222-222222222222'
const CAT = 'cccccccc-3333-4333-8333-333333333333'

function render(
  plan: LeavePlan,
  extra: { confirming?: boolean; busy?: boolean; usernames?: ReadonlyMap<string, string> } = {},
): string {
  return renderToStaticMarkup(
    createElement(LeaveGroupPanel, {
      plan,
      confirming: extra.confirming ?? true,
      busy: extra.busy ?? false,
      usernames: extra.usernames ?? new Map([[BOB, 'bob_the_member']]),
      onStart: () => undefined,
      onCancel: () => undefined,
      onConfirm: () => undefined,
    }),
  )
}

describe('LeaveGroupPanel', () => {
  it('shows only a Leave button until the user starts, so leaving is never one click', () => {
    const html = render({ kind: 'plain' }, { confirming: false })
    expect(html.match(/<button/g)).toHaveLength(1)
    expect(html).toContain('Leave group')
    expect(html).not.toContain('lose access')
  })

  it('warns that leaving as the only member deletes the group', () => {
    const html = render({ kind: 'deletesGroup' })
    expect(html).toContain('only member')
    expect(html).toContain('deletes this group')
    expect(html).toContain('Delete group')
  })

  it('does not offer a deleted account as a successor', () => {
    const html = render(
      { kind: 'needsSuccessor', candidates: [BOB, CAT] },
      {
        usernames: new Map([
          [BOB, 'bob_the_member'],
          [CAT, ''],
        ]),
      },
    )
    expect(html).toContain('bob_the_member')
    expect(html).not.toContain('deleted user')
    expect(html.match(/Make admin and leave/g)).toHaveLength(1)
  })

  it('tells a sole admin whose every other member was deleted to remove them first', () => {
    const html = render(
      { kind: 'needsSuccessor', candidates: [BOB, CAT] },
      {
        usernames: new Map([
          [BOB, ''],
          [CAT, ''],
        ]),
      },
    )
    expect(html).toContain('every other member')
    expect(html).toContain('Remove them from the members list')
    expect(html).not.toContain('Make admin and leave')
    expect(html).not.toContain('>Leave group<')
  })

  it('makes the last admin pick a successor and offers no plain leave', () => {
    const html = render({ kind: 'needsSuccessor', candidates: [BOB, CAT] })
    expect(html).toContain('only admin')
    expect(html).toContain('bob_the_member')
    expect(html).toContain('cccccccc')
    expect(html.match(/Make admin and leave/g)).toHaveLength(2)
    expect(html).not.toContain('>Leave group<')
  })

  it('confirms a plain leave', () => {
    const html = render({ kind: 'plain' })
    expect(html).toContain('lose access')
    expect(html).toContain('>Leave group<')
  })

  it('locks every control while a leave is in flight', () => {
    const html = render({ kind: 'needsSuccessor', candidates: [BOB] }, { busy: true })
    expect(html.match(/<button[^>]*disabled/g)).toHaveLength(html.match(/<button/g)?.length ?? -1)
  })
})

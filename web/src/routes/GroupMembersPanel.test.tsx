// Markup tests for GroupMembersPanel (renderToStaticMarkup, per
// GroupList.test.tsx's reasoning).

import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import type { MemberEntry } from '@/lib/api/groups'
import { GroupMembersPanel, MembersFeedback } from './GroupMembersPanel'
import { memberLabel } from './memberLabel'
import type { MembersView } from './runGroupMembers'

const ME = 'aaaaaaaa-1111-4111-8111-111111111111'
const BOB = 'bbbbbbbb-2222-4222-8222-222222222222'

const member = (userId: string, role: MemberEntry['role']): MemberEntry => ({
  userId,
  role,
  generation: 0,
})

function render(
  view: Partial<MembersView>,
  extra: { busyUserId?: string | null; usernames?: ReadonlyMap<string, string> } = {},
): string {
  return renderToStaticMarkup(
    createElement(GroupMembersPanel, {
      view: {
        groupId: 'g1',
        members: [member(ME, 'admin'), member(BOB, 'member')],
        myRole: 'admin',
        myGrantSortKey: 'GRANT#x',
        ...view,
      },
      userId: ME,
      busyUserId: extra.busyUserId ?? null,
      onChangeRole: () => undefined,
      ...(extra.usernames !== undefined && { usernames: extra.usernames }),
    }),
  )
}

describe('GroupMembersPanel', () => {
  it('labels members by the first block of their id and marks the caller', () => {
    const html = render({})
    expect(html).toContain('aaaaaaaa')
    expect(html).toContain('bbbbbbbb')
    expect(html.match(/>you</g)).toHaveLength(1)
    expect(memberLabel(ME)).toBe('aaaaaaaa')
  })

  it('labels members by username once the projection has resolved, and by short id otherwise', () => {
    const usernames = new Map([[BOB, 'bob_the_member']])
    const html = render({}, { usernames })
    expect(html).toContain('bob_the_member')
    // ME is not in the map yet: falls back rather than going blank.
    expect(html).toContain('aaaaaaaa')
    expect(html).not.toContain('>bbbbbbbb<')
    expect(memberLabel(BOB, usernames)).toBe('bob_the_member')
    expect(memberLabel(BOB)).toBe('bbbbbbbb')
    // Mono marks only the unresolved fallback.
    expect(html).toMatch(/font-mono[^>]*>aaaaaaaa</)
    expect(html).not.toMatch(/font-mono[^>]*>bob_the_member</)
  })

  it("offers an admin the roles a member doesn't already have, and none on their own row", () => {
    const html = render({})
    expect(html).toContain('Make admin')
    expect(html).toContain('Make ambassador')
    // Bob is a member, so "Make member" is not offered for him; the admin's
    // own row has no controls at all.
    expect(html).not.toContain('Make member')
    expect(html.match(/<button/g)).toHaveLength(2)
  })

  it('offers no controls to an ambassador or a member', () => {
    for (const myRole of ['ambassador', 'member'] as const) {
      const html = render({ myRole })
      expect(html).not.toContain('<button')
      expect(html).toContain('bbbbbbbb')
    }
  })

  it('disables every control while a change is in flight and marks the row', () => {
    const html = render({}, { busyUserId: BOB })
    expect(html).toContain('Saving…')
    expect(html.match(/<button[^>]*disabled/g)).toHaveLength(2)
  })

  it('offers no buttons to an admin whose own grant is missing, and says why', () => {
    for (const myGrantSortKey of [undefined, ''] as const) {
      const html = render({ myGrantSortKey })
      expect(html).not.toContain('<button')
      expect(html).toContain('not on record')
    }
  })

  it("explains itself when an admin's own grant is missing", () => {
    expect(render({ myGrantSortKey: undefined })).toContain('not on record')
    expect(render({})).not.toContain('not on record')
  })
})

describe('MembersFeedback', () => {
  it('shows a message and an error', () => {
    const html = renderToStaticMarkup(
      createElement(MembersFeedback, { message: 'It worked.', error: 'It failed.' }),
    )
    expect(html).toContain('It worked.')
    expect(html).toContain('It failed.')
  })

  it('renders nothing when there is neither', () => {
    expect(
      renderToStaticMarkup(createElement(MembersFeedback, { message: null, error: null })),
    ).toBe('')
  })
})

describe('GroupMembersPanel grant check marks', () => {
  const checkedWith = (
    anchor: 'pinned' | 'first-seen' | 'unpinned' | 'changed',
    statuses: [string, import('@/lib/crypto/grant-chain').RoleStatus][],
  ): import('./runGrantCheck').GrantCheck => ({
    state: 'checked',
    anchor,
    statuses: new Map(statuses),
  })
  const renderChecked = (check: import('./runGrantCheck').GrantCheck | null | undefined) =>
    renderToStaticMarkup(
      createElement(GroupMembersPanel, {
        view: {
          groupId: 'g1',
          members: [member(ME, 'admin'), member(BOB, 'member')],
          myRole: 'admin',
          myGrantSortKey: 'GRANT#x',
        },
        userId: ME,
        busyUserId: null,
        onChangeRole: () => undefined,
        check,
      }),
    )

  it('shows no marks and no footnote while the check is loading or unavailable', () => {
    for (const check of [null, undefined, { state: 'unavailable' } as const]) {
      const html = renderChecked(check)
      expect(html).not.toContain('chain consistent')
      expect(html).not.toContain('not confirmed')
      expect(html).not.toContain('signed grant history')
    }
  })

  it('marks a backed role as consistent and never as verified', () => {
    const html = renderChecked(
      checkedWith('pinned', [
        [ME, { status: 'verified' }],
        [BOB, { status: 'verified' }],
      ]),
    )
    expect(html.match(/chain consistent/g)).toHaveLength(2)
    expect(html.toLowerCase()).not.toContain('verified')
    expect(html).toContain('can&#x27;t rule out a dishonest server')
  })

  it('marks an unbacked role as not confirmed, with the reason in the tooltip', () => {
    const html = renderChecked(
      checkedWith('pinned', [
        [ME, { status: 'verified' }],
        [BOB, { status: 'unverified', reason: 'no grant backs role admin' }],
      ]),
    )
    expect(html.match(/Role not confirmed/g)).toHaveLength(1)
    expect(html).toContain('Not confirmed: no grant backs role admin.')
  })

  it('shows a destructive anchor-changed alert when the anchor differs from the pin', () => {
    const html = renderChecked(
      checkedWith('changed', [
        [ME, { status: 'unverified', reason: 'the group anchor changed since you first saw it' }],
        [BOB, { status: 'unverified', reason: 'the group anchor changed since you first saw it' }],
      ]),
    )
    expect(html).toContain('trust anchor is different')
    expect(html.match(/Role not confirmed/g)).toHaveLength(2)
  })

  it('says when the browser could not remember the creator, and only then', () => {
    const statuses: [string, import('@/lib/crypto/grant-chain').RoleStatus][] = [
      [ME, { status: 'verified' }],
    ]
    expect(renderChecked(checkedWith('unpinned', statuses))).toContain('couldn&#x27;t remember')
    expect(renderChecked(checkedWith('first-seen', statuses))).not.toContain('remember')
    expect(renderChecked(checkedWith('pinned', statuses))).not.toContain('remember')
  })
})

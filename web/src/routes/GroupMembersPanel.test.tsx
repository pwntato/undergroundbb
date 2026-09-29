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

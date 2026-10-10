// Markup tests for GroupMembersPanel (renderToStaticMarkup, per
// GroupList.test.tsx's reasoning).

import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import type { MemberEntry } from '@/lib/api/groups'
import { GroupMembersPanel, MembersFeedback, RotationBanner } from './GroupMembersPanel'
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
  extra: {
    busyUserId?: string | null
    usernames?: ReadonlyMap<string, string>
    confirmRemoveUserId?: string | null
    locked?: boolean
    readmittableIds?: ReadonlySet<string>
    readmitPrompt?: { userId: string; fingerprint: string } | null
  } = {},
): string {
  return renderToStaticMarkup(
    createElement(GroupMembersPanel, {
      view: {
        groupId: 'g1',
        members: [member(ME, 'admin'), member(BOB, 'member')],
        myRole: 'admin',
        myGrantSortKey: 'GRANT#x',
        revocationMode: 'open',
        myGeneration: 0,
        ...view,
      },
      userId: ME,
      busyUserId: extra.busyUserId ?? null,
      onChangeRole: () => undefined,
      locked: extra.locked ?? false,
      confirmRemoveUserId: extra.confirmRemoveUserId ?? null,
      onStartRemove: () => undefined,
      onCancelRemove: () => undefined,
      onConfirmRemove: () => undefined,
      onStartReadmit: () => undefined,
      onCancelReadmit: () => undefined,
      onConfirmReadmit: () => undefined,
      ...(extra.readmittableIds !== undefined && { readmittableIds: extra.readmittableIds }),
      ...(extra.readmitPrompt !== undefined && { readmitPrompt: extra.readmitPrompt }),
      ...(extra.usernames !== undefined && { usernames: extra.usernames }),
    }),
  )
}

describe('GroupMembersPanel', () => {
  it('offers Remove to an admin on other members only, never on their own row', () => {
    const html = render({})
    expect(html.match(/>Remove</g)).toHaveLength(1)
  })

  it('lets a deleted member be demoted or removed but never made admin or ambassador', () => {
    const alive = render({ members: [member(ME, 'admin'), member(BOB, 'ambassador')] })
    expect(alive).toContain('Make admin')
    const gone = render(
      { members: [member(ME, 'admin'), member(BOB, 'ambassador')] },
      { usernames: new Map([[BOB, '']]) },
    )
    expect(gone).toContain('Make member')
    expect(gone).toContain('>Remove<')
    expect(gone).not.toContain('Make admin')
    expect(gone).not.toContain('Make ambassador')
  })

  it('offers no Remove to a non-admin or to an admin without a grant on record', () => {
    expect(render({ myRole: 'member' })).not.toContain('>Remove<')
    expect(render({ myGrantSortKey: undefined })).not.toContain('>Remove<')
  })

  it('asks for confirmation, and says a Rotating group also rotates the key', () => {
    const open = render({}, { confirmRemoveUserId: BOB })
    expect(open).toContain('Confirm remove')
    expect(open).toContain('Cancel')
    expect(open).not.toContain('rotates the group key')
    // Role buttons give way to the confirmation on that row.
    expect(open).not.toContain('>Remove<')

    const rotating = render({ revocationMode: 'rotating' }, { confirmRemoveUserId: BOB })
    expect(rotating).toContain('rotates the group key')
  })

  it('disables every control while a rotation job runs, even with nothing in flight', () => {
    const idle = render({})
    expect(idle).not.toMatch(/<button[^>]*\sdisabled=""/)
    const locked = render({}, { locked: true })
    expect(locked.match(/<button[^>]*\sdisabled=""/g)).toHaveLength(3)
    const confirming = render({}, { locked: true, confirmRemoveUserId: BOB })
    expect(confirming.match(/<button[^>]*\sdisabled=""/g)).toHaveLength(2) // Confirm and Cancel
  })

  it('locks the confirmation while a removal is in flight', () => {
    const html = render({}, { confirmRemoveUserId: BOB, busyUserId: BOB })
    expect(html).toContain('Removing…')
    expect(html).toMatch(/<button[^>]*\sdisabled=""[^>]*>Removing…/)
  })

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
    // own row has no controls at all. The third button is Remove.
    expect(html).not.toContain('Make member')
    expect(html.match(/<button/g)).toHaveLength(3)
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
    expect(html.match(/<button[^>]*\sdisabled=""/g)).toHaveLength(3) // two roles and Remove
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
    anchor: 'pinned' | 'first-seen' | 'unpinned' | 'changed' | 'root-unverified',
    statuses: [string, import('@/lib/crypto/grant-chain').RoleStatus][],
    keys: import('./runGrantCheck').KeyState = 'first-seen',
    blockedKeyUsers: string[] = [],
  ): import('./runGrantCheck').GrantCheck => ({
    state: 'checked',
    anchor,
    keys,
    blockedKeyUsers,
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
          revocationMode: 'open',
          myGeneration: 0,
        },
        userId: ME,
        busyUserId: null,
        onChangeRole: () => undefined,
        confirmRemoveUserId: null,
        onStartRemove: () => undefined,
        onCancelRemove: () => undefined,
        onConfirmRemove: () => undefined,
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

  const both: [string, import('@/lib/crypto/grant-chain').RoleStatus][] = [
    [ME, { status: 'verified' }],
    [BOB, { status: 'verified' }],
  ]

  it('marks a backed role as consistent, not verified, when any key was only just saved', () => {
    for (const [anchor, keys] of [
      ['pinned', 'first-seen'],
      ['first-seen', 'pinned'],
      ['first-seen', 'first-seen'],
      ['pinned', 'unchecked'],
    ] as const) {
      const html = renderChecked(checkedWith(anchor, both, keys))
      expect(html.match(/chain consistent/g)).toHaveLength(2)
      expect(html.toLowerCase()).not.toContain('verified')
      expect(html).toContain('can&#x27;t rule out')
    }
  })

  it('says verified only when both the anchor and every key matched something saved earlier', () => {
    const html = renderChecked(checkedWith('pinned', both, 'pinned'))
    expect(html.match(/✓ verified/g)).toHaveLength(2)
    expect(html).not.toContain('chain consistent')
    expect(html).toContain('matched the copy this browser saved earlier')
  })

  it('explains an unchecked run instead of implying the keys were checked', () => {
    const html = renderChecked(checkedWith('pinned', both, 'unchecked'))
    expect(html).toContain('couldn&#x27;t be checked against your saved copies')
  })

  it("does not claim anything was saved just now when only the anchor couldn't be remembered", () => {
    const html = renderChecked(checkedWith('unpinned', both, 'pinned'))
    expect(html).not.toContain('saved just now')
    expect(html).toContain('couldn&#x27;t remember the group&#x27;s creator')
    expect(html.toLowerCase()).not.toContain('✓ verified')
  })

  it('does not claim keys were saved on first sight when the check found a problem', () => {
    const blocked = renderChecked(checkedWith('pinned', both, 'blocked', [BOB]))
    const changed = renderChecked(checkedWith('changed', both, 'pinned'))
    const rootBad = renderChecked(checkedWith('root-unverified', both, 'pinned'))
    for (const html of [blocked, changed, rootBad]) {
      expect(html).not.toContain('saved just now on first sight')
      expect(html).toContain('found a problem')
    }
  })

  it('warns by name when a key was blocked, and never says verified', () => {
    const html = renderChecked(
      checkedWith(
        'pinned',
        [
          [ME, { status: 'verified' }],
          [BOB, { status: 'unverified', reason: 'no key history' }],
        ],
        'blocked',
        [BOB],
      ),
    )
    expect(html).toContain('don&#x27;t')
    expect(html).toContain('match the copy you saved earlier')
    expect(html.toLowerCase()).not.toContain('✓ verified')
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

  it('explains an unchecked root as a possibly temporary failure, not a storage problem or a tamper alert', () => {
    const reason = "the group's root grant could not be checked (not served)"
    const html = renderChecked(
      checkedWith('root-unverified', [
        [ME, { status: 'unverified', reason }],
        [BOB, { status: 'unverified', reason }],
      ]),
    )
    expect(html).toContain('root grant couldn&#x27;t be checked')
    expect(html).toContain('try reloading')
    expect(html.match(/Role not confirmed/g)).toHaveLength(2)
    expect(html).not.toContain('chain consistent')
    expect(html).not.toContain('remember')
    expect(html).not.toContain('trust anchor is different')
    expect(html).not.toContain('role="alert"')
  })
})

describe('GroupMembersPanel re-admit (#178)', () => {
  const PRINT = '12345-67890-12345-67890-12345-67890-12345-67890-12345-67890-12345-67890'
  const two = { members: [member(ME, 'admin'), member(BOB, 'member')] }

  it('shows Re-admit only on members named readmittable', () => {
    expect(render(two, { readmittableIds: new Set([BOB]) })).toContain('>Re-admit<')
    expect(render(two)).not.toContain('Re-admit')
    expect(render(two, { readmittableIds: new Set() })).not.toContain('Re-admit')
    // Someone the rotation did not name gets none, whatever else is in the set.
    expect(
      render(two, { readmittableIds: new Set(['cccccccc-3333-4333-8333-333333333333']) }),
    ).not.toContain('Re-admit')
  })

  it('never offers it on your own row', () => {
    expect(render(two, { readmittableIds: new Set([ME]) })).not.toContain('Re-admit')
  })

  it('offers it to an ambassador with a grant, and to nobody who cannot sign', () => {
    const ids = { readmittableIds: new Set([BOB]) }
    expect(render({ ...two, myRole: 'ambassador' }, ids)).toContain('>Re-admit<')
    expect(render({ ...two, myRole: 'member' }, ids)).not.toContain('Re-admit')
    expect(render({ ...two, myGrantSortKey: '' }, ids)).not.toContain('Re-admit')
  })

  it('shows the fingerprint and an explicit confirm, not a bare button, once started', () => {
    const html = render(two, {
      readmittableIds: new Set([BOB]),
      readmitPrompt: { userId: BOB, fingerprint: PRINT },
    })
    expect(html).toContain(PRINT)
    expect(html).toContain('It matches, re-admit')
    expect(html).toContain('Cancel')
    expect(html).toContain('in person or on a call')
    expect(html).not.toContain('>Re-admit<')
  })

  it('ignores a prompt for someone who is not readmittable', () => {
    const html = render(two, { readmitPrompt: { userId: BOB, fingerprint: PRINT } })
    expect(html).not.toContain(PRINT)
    expect(html).not.toContain('It matches')
  })

  it('locks the buttons while another job runs', () => {
    const html = render(two, { readmittableIds: new Set([BOB]), locked: true })
    expect(html).toMatch(/<button[^>]*disabled[^>]*>Re-admit</)
  })
})

describe('MembersFeedback rotation status', () => {
  const render = (rotating?: boolean) =>
    renderToStaticMarkup(
      createElement(MembersFeedback, {
        message: null,
        error: null,
        ...(rotating === undefined ? {} : { rotating }),
      }),
    )

  it('tells the admin to keep the page open while a rotation job runs', () => {
    expect(render(true)).toContain('Keep this page open')
  })

  it('says nothing otherwise', () => {
    expect(render(false)).not.toContain('Keep this page open')
    expect(render()).not.toContain('Keep this page open')
  })
})

describe('RotationBanner', () => {
  const html = (notice: Parameters<typeof RotationBanner>[0]['notice']) =>
    renderToStaticMarkup(createElement(RotationBanner, { notice, startedByLabel: 'alice' }))

  it('renders nothing without a notice', () => {
    expect(html(null)).toBe('')
  })

  it.each([
    ['needs-other-admin', 'Ask one to open this group'],
    ['ahead', 'Reload the page'],
    ['stopped', 'Reopening this group tries again'],
    ['blocked', 'keys no longer match the copy you saved'],
  ] as const)('a %s notice names the starter and the age, with its own next step', (kind, next) => {
    const out = html({ kind, startedBy: 'u1', ageMs: 2 * 3_600_000 })
    expect(out).toContain('about 2 hours ago by alice')
    expect(out).toContain(next)
  })

  it('never tells the admin to keep the page open, because nothing is running when it shows', () => {
    for (const kind of ['needs-other-admin', 'ahead', 'stopped', 'blocked'] as const) {
      expect(html({ kind, startedBy: 'u1', ageMs: 3_600_000 })).not.toContain('Keep this page open')
    }
  })
})

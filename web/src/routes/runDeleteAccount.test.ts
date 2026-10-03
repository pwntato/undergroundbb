import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { MemberEntry } from '@/lib/api/groups'
import type { MembersView } from './runGroupMembers'
import {
  deleteFailureMessage,
  deletionBlockers,
  groupsThatWillBeDeleted,
  leaveOrder,
  planAccountDeletion,
  runDeleteAccount,
  type AccountPlanEntry,
  type DeleteAccountDeps,
} from './runDeleteAccount'
import { leavePlan } from './runLeaveGroup'

const ME = 'aaaaaaaa-1111-4111-8111-111111111111'
const BOB = 'bbbbbbbb-2222-4222-8222-222222222222'

const m = (userId: string, role: MemberEntry['role']): MemberEntry => ({
  userId,
  role,
  generation: 0,
})
const view = (
  groupId: string,
  myRole: MembersView['myRole'],
  members: MemberEntry[],
  hasGrant = true,
): MembersView => ({
  groupId,
  members,
  myRole,
  myGrantSortKey: hasGrant ? 'GRANT#x' : undefined,
  revocationMode: 'open',
  myGeneration: 0,
})
const entry = (v: MembersView): AccountPlanEntry => ({
  groupId: v.groupId,
  view: v,
  plan: leavePlan(v, ME),
})

// Plain member of g-member, one of two admins of g-admin, only member of g-solo.
const memberGroup = entry(view('g-member', 'member', [m(ME, 'member'), m(BOB, 'admin')], false))
const adminGroup = entry(view('g-admin', 'admin', [m(ME, 'admin'), m(BOB, 'admin')]))
const soloGroup = entry(view('g-solo', 'admin', [m(ME, 'admin')]))
const lastAdminGroup = entry(view('g-last', 'admin', [m(ME, 'admin'), m(BOB, 'member')]))

function deps(over: Partial<DeleteAccountDeps> = {}): DeleteAccountDeps & { calls: string[] } {
  const calls: string[] = []
  return {
    calls,
    userId: ME,
    leaveGroup: vi.fn((groupId: string) => {
      calls.push(`leave:${groupId}`)
      return Promise.resolve({ groupDeleted: groupId === 'g-solo' })
    }),
    signRoleGrant: vi.fn(() => Promise.resolve({ grantSortKey: 'GRANT#new', signature: 'sig' })),
    deleteAccount: vi.fn(() => {
      calls.push('delete')
      return Promise.resolve()
    }),
    ...over,
  }
}

describe('leaveOrder', () => {
  it('runs signed demotions first, plain leaves next, and group-deleting leaves last', () => {
    const order = leaveOrder([soloGroup, memberGroup, adminGroup]).map((e) => e.groupId)
    expect(order).toEqual(['g-admin', 'g-member', 'g-solo'])
  })
})

describe('deletionBlockers / groupsThatWillBeDeleted', () => {
  it('blocks on the last admin of a group with other members', () => {
    expect(
      deletionBlockers([memberGroup, adminGroup, lastAdminGroup]).map((e) => e.groupId),
    ).toEqual(['g-last'])
  })

  it('blocks on an admin whose own grant is not on record', () => {
    const noGrant = entry(view('g-nogrant', 'admin', [m(ME, 'admin'), m(BOB, 'admin')], false))
    expect(deletionBlockers([noGrant]).map((e) => e.groupId)).toEqual(['g-nogrant'])
  })

  it('does not block on a sole member, but reports the group as one that will be deleted', () => {
    expect(deletionBlockers([soloGroup])).toEqual([])
    expect(groupsThatWillBeDeleted([soloGroup, memberGroup]).map((e) => e.groupId)).toEqual([
      'g-solo',
    ])
  })
})

describe('runDeleteAccount', () => {
  it('leaves every group in order, then deletes the account', async () => {
    const d = deps()
    const res = await runDeleteAccount(d, [soloGroup, memberGroup, adminGroup])
    expect(res).toEqual({ ok: true, left: 3 })
    expect(d.calls).toEqual(['leave:g-admin', 'leave:g-member', 'leave:g-solo', 'delete'])
  })

  it('signs the demotion for an admin and sends none for a plain member', async () => {
    const d = deps()
    await runDeleteAccount(d, [memberGroup, adminGroup])
    expect(d.signRoleGrant).toHaveBeenCalledTimes(1)
    expect(d.signRoleGrant).toHaveBeenCalledWith(
      expect.objectContaining({ groupId: 'g-admin', subjectUserId: ME, role: 'member' }),
    )
  })

  it('changes nothing when any group blocks', async () => {
    const d = deps()
    const res = await runDeleteAccount(d, [memberGroup, lastAdminGroup])
    expect(res).toEqual({ ok: false, kind: 'blocked', groupIds: ['g-last'] })
    expect(d.calls).toEqual([])
  })

  it('fails before leaving anything when this browser cannot sign (cold keys)', async () => {
    const d = deps({
      signRoleGrant: vi.fn(() => Promise.reject(new Error('no live keys'))),
    })
    const res = await runDeleteAccount(d, [memberGroup, adminGroup])
    expect(res.ok).toBe(false)
    // The admin group ran first, so the plain member group was never left.
    expect(d.calls).toEqual([])
  })

  it('stops at the first failed leave and never deletes the account', async () => {
    const d = deps({
      leaveGroup: vi.fn((groupId: string) => {
        if (groupId === 'g-member') {
          return Promise.reject(new ApiError(500, 'boom'))
        }
        return Promise.resolve({ groupDeleted: false })
      }),
    })
    const res = await runDeleteAccount(d, [adminGroup, memberGroup, soloGroup])
    expect(res).toEqual({
      ok: false,
      kind: 'leaveFailed',
      groupId: 'g-member',
      reason: 'ambiguous',
      left: 1,
    })
    expect(d.deleteAccount).not.toHaveBeenCalled()
  })

  it('counts a group that no longer lists the caller as already left', async () => {
    const d = deps({
      leaveGroup: vi.fn(() => Promise.reject(new ApiError(404, 'not found'))),
    })
    const res = await runDeleteAccount(d, [memberGroup])
    expect(res).toEqual({ ok: true, left: 1 })
    expect(d.deleteAccount).toHaveBeenCalledTimes(1)
  })

  it('reports an invite that completed in between, as stillMember', async () => {
    const d = deps({
      deleteAccount: vi.fn(() => Promise.reject(new ApiError(409, 'x', 'still_member'))),
    })
    expect(await runDeleteAccount(d, [memberGroup])).toEqual({
      ok: false,
      kind: 'stillMember',
      left: 1,
    })
  })

  it('maps a 401 on the final delete to authRequired and a 5xx to ambiguous', async () => {
    const auth = deps({ deleteAccount: vi.fn(() => Promise.reject(new ApiError(401, 'x'))) })
    expect(await runDeleteAccount(auth, [])).toEqual({ ok: false, kind: 'authRequired', left: 0 })
    const flaky = deps({ deleteAccount: vi.fn(() => Promise.reject(new ApiError(503, 'x'))) })
    expect(await runDeleteAccount(flaky, [])).toEqual({ ok: false, kind: 'ambiguous', left: 0 })
  })

  it('deletes straight away for an account in no groups', async () => {
    const d = deps()
    expect(await runDeleteAccount(d, [])).toEqual({ ok: true, left: 0 })
    expect(d.calls).toEqual(['delete'])
  })
})

describe('planAccountDeletion', () => {
  const planDeps = (getGroup: (id: string) => Promise<unknown>) => ({
    userId: ME,
    getGroup: getGroup as never,
    listMembers: () => Promise.resolve({ members: [m(ME, 'member'), m(BOB, 'admin')] }),
  })
  const detail = { role: 'member', revocationMode: 'open', generation: 0 }

  it('plans every group and writes nothing', async () => {
    const res = await planAccountDeletion(
      planDeps(() => Promise.resolve(detail)),
      ['g1', 'g2'],
    )
    expect(res.ok && res.entries.map((e) => e.groupId)).toEqual(['g1', 'g2'])
  })

  it('skips a group that has vanished but fails if a roster cannot be read', async () => {
    const gone = await planAccountDeletion(
      planDeps((id) =>
        id === 'g1' ? Promise.reject(new ApiError(404, 'nf')) : Promise.resolve(detail),
      ),
      ['g1', 'g2'],
    )
    expect(gone.ok && gone.entries.map((e) => e.groupId)).toEqual(['g2'])

    const broken = await planAccountDeletion(
      planDeps(() => Promise.reject(new ApiError(500, 'boom'))),
      ['g1'],
    )
    expect(broken).toEqual({ ok: false, kind: 'failed' })
  })
})

describe('deleteFailureMessage', () => {
  const label = (id: string) => `"${id}"`

  it('says how many groups were already left, and that nothing changed when none were', () => {
    expect(deleteFailureMessage({ ok: false, kind: 'stillMember', left: 2 }, label)).toContain(
      'already left 2 groups',
    )
    expect(deleteFailureMessage({ ok: false, kind: 'ambiguous', left: 0 }, label)).toContain(
      'Nothing was changed',
    )
  })

  it('names the group that blocked or failed', () => {
    expect(
      deleteFailureMessage({ ok: false, kind: 'blocked', groupIds: ['g-last'] }, label),
    ).toContain('"g-last"')
    expect(
      deleteFailureMessage(
        { ok: false, kind: 'leaveFailed', groupId: 'g-x', reason: 'coldKeys', left: 0 },
        label,
      ),
    ).toContain('log in again')
  })
})

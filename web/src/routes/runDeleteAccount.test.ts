import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { MemberEntry } from '@/lib/api/groups'
import type { MembersView } from './runGroupMembers'
import {
  deleteFailureMessage,
  blockerReason,
  deletionBlockers,
  groupsThatWillBeDeleted,
  leaveOrder,
  planAccountDeletion,
  planFingerprint,
  runConfirmedDeletion,
  runDeleteAccount,
  type AccountPlanEntry,
  type DeleteAccountDeps,
} from './runDeleteAccount'
import { leavePlan, type LeaveDeps } from './runLeaveGroup'

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

/** These tests use Open groups, which never rotate: any use of the rotation deps is a bug. */
const noRotation: LeaveDeps['rotation'] = {
  rotationDeps: new Proxy({} as never, {
    get: (_t, name) => {
      throw new Error(`an Open group must not touch rotation deps (${String(name)})`)
    },
  }),
  signLeaveRotationStart: () =>
    Promise.reject(new Error('an Open group must not start a rotation')),
}

function deps(over: Partial<DeleteAccountDeps> = {}): DeleteAccountDeps & { calls: string[] } {
  const calls: string[] = []
  return {
    calls,
    userId: ME,
    rotation: noRotation,
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
    resolveUsernames: () => Promise.resolve(new Map<string, string>()),
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

describe('planAccountDeletion with a deleted co-admin', () => {
  const CAROL = 'cccccccc-3333-4333-8333-333333333333'
  const rosters: Record<string, MemberEntry[]> = {
    // Bob is the only other admin and is deleted: leaving would strand the group.
    'g-dead-co-admin': [m(ME, 'admin'), m(BOB, 'admin'), m(CAROL, 'member')],
    'g-live-co-admin': [m(ME, 'admin'), m(CAROL, 'admin')],
    'g-member': [m(ME, 'member'), m(BOB, 'admin')],
  }
  const roles: Record<string, string> = {
    'g-dead-co-admin': 'admin',
    'g-live-co-admin': 'admin',
    'g-member': 'member',
  }
  const run = (names: Map<string, string>, resolve = vi.fn(() => Promise.resolve(names))) =>
    planAccountDeletion(
      {
        userId: ME,
        getGroup: ((id: string) =>
          Promise.resolve({ role: roles[id], revocationMode: 'open', generation: 0 })) as never,
        listMembers: ((id: string) => Promise.resolve({ members: rosters[id] })) as never,
        resolveUsernames: resolve,
      },
      Object.keys(rosters),
    ).then((res) => ({ res, resolve }))

  it('plans a group whose only co-admin is deleted as needsSuccessor, so it blocks up front', async () => {
    const { res } = await run(
      new Map([
        [BOB, ''],
        [CAROL, 'carol'],
      ]),
    )
    expect(res.ok).toBe(true)
    if (!res.ok) return
    const kinds = Object.fromEntries(res.entries.map((e) => [e.groupId, e.plan.kind]))
    expect(kinds).toEqual({
      'g-dead-co-admin': 'needsSuccessor',
      'g-live-co-admin': 'plain',
      'g-member': 'plain',
    })
    // (g-live-co-admin also blocks here, as grantMissing: this fixture has no grant on record.)
    const blocked = deletionBlockers(res.entries).filter(
      (e) => blockerReason(e) === 'needsSuccessor',
    )
    expect(blocked.map((e) => e.groupId)).toEqual(['g-dead-co-admin'])
  })

  it('resolves only the other admins of groups the caller admins', async () => {
    const { resolve } = await run(new Map())
    // The first read; a second one, for the blocking group's members, is pinned
    // in the #193 tests below.
    expect([...(resolve.mock.calls[0] as unknown as [string[]])[0]].sort()).toEqual(
      [BOB, CAROL].sort(),
    )
  })

  it('stays optimistic for an admin whose name did not resolve', async () => {
    const { res } = await run(new Map())
    expect(res.ok && res.entries.find((e) => e.groupId === 'g-dead-co-admin')?.plan.kind).toBe(
      'plain',
    )
  })

  it('does not call the resolver when the caller admins nothing with other admins', async () => {
    const resolve = vi.fn(() => Promise.resolve(new Map<string, string>()))
    await planAccountDeletion(
      {
        userId: ME,
        getGroup: (() =>
          Promise.resolve({ role: 'member', revocationMode: 'open', generation: 0 })) as never,
        listMembers: (() => Promise.resolve({ members: rosters['g-member'] })) as never,
        resolveUsernames: resolve,
      },
      ['g-member'],
    )
    expect(resolve).not.toHaveBeenCalled()
  })
})

describe('planAccountDeletion when no member can be promoted (#193)', () => {
  const DAVE = 'dddddddd-4444-4444-8444-444444444444'
  const CAROL = 'cccccccc-3333-4333-8333-333333333333'
  const rosters: Record<string, MemberEntry[]> = {
    // Everyone else is deleted: there is no one to make an admin.
    'g-all-dead': [m(ME, 'admin'), m(BOB, 'admin'), m(DAVE, 'member')],
    // One live member remains, so picking a successor still works.
    'g-one-live': [m(ME, 'admin'), m(BOB, 'admin'), m(CAROL, 'member')],
  }
  const run = (names: Map<string, string>) => {
    const resolve = vi.fn(() => Promise.resolve(names))
    return planAccountDeletion(
      {
        userId: ME,
        getGroup: (() =>
          Promise.resolve({ role: 'admin', revocationMode: 'open', generation: 0 })) as never,
        listMembers: ((id: string) => Promise.resolve({ members: rosters[id] })) as never,
        resolveUsernames: resolve,
      },
      Object.keys(rosters),
    ).then((res) => ({ res, resolve }))
  }
  const reasons = (res: Awaited<ReturnType<typeof run>>['res']) =>
    res.ok
      ? Object.fromEntries(deletionBlockers(res.entries).map((e) => [e.groupId, blockerReason(e)]))
      : {}

  it('says noSuccessor only where every other member is deleted', async () => {
    const { res } = await run(
      new Map([
        [BOB, ''],
        [DAVE, ''],
        [CAROL, 'carol'],
      ]),
    )
    expect(reasons(res)).toEqual({ 'g-all-dead': 'noSuccessor', 'g-one-live': 'needsSuccessor' })
  })

  it('keeps the optimistic wording while a member name is unresolved', async () => {
    const { res } = await run(
      new Map([
        [BOB, ''],
        // DAVE did not resolve: he may be live, so a successor may exist.
      ]),
    )
    expect(reasons(res)['g-all-dead']).toBe('needsSuccessor')
  })

  it('resolves the members of a blocking group in a second read, and nothing more', async () => {
    // Bob is deleted, so both groups block and their members are read.
    const { resolve } = await run(new Map([[BOB, '']]))
    expect(resolve).toHaveBeenCalledTimes(2)
    const second = [...(resolve.mock.calls[1] as unknown as [string[]])[0]].sort()
    expect(second).toEqual([BOB, CAROL, DAVE].sort())
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

describe('runConfirmedDeletion (review of #183: the plan on screen can be stale)', () => {
  // The user was shown g-shared under "You will leave"; Bob has left since, so
  // leaving it now would delete the group.
  const sharedShown = entry(view('g-shared', 'member', [m(ME, 'member'), m(BOB, 'member')]))
  const sharedNowSolo = entry(view('g-shared', 'member', [m(ME, 'member')]))

  function confirmedDeps(
    fresh: AccountPlanEntry[],
    over: Partial<DeleteAccountDeps> = {},
  ): ReturnType<typeof deps> & { replan: () => Promise<never> } {
    const d = deps(over)
    return { ...d, replan: () => Promise.resolve({ ok: true, entries: fresh }) as never }
  }

  it('refuses, changes nothing and returns the fresh plan when a group became a group-deleting leave', async () => {
    const d = confirmedDeps([sharedNowSolo])
    const res = await runConfirmedDeletion(d, [sharedShown])
    expect(res).toEqual({ ok: false, kind: 'planChanged', entries: [sharedNowSolo] })
    expect(d.calls).toEqual([])
  })

  it('refuses when a new group appeared, a group vanished, or a role moved', async () => {
    const extra = entry(view('g-new', 'member', [m(ME, 'member'), m(BOB, 'admin')]))
    for (const fresh of [
      [sharedShown, extra],
      [],
      [entry(view('g-shared', 'admin', [m(ME, 'admin'), m(BOB, 'admin')]))],
    ]) {
      const d = confirmedDeps(fresh)
      const res = await runConfirmedDeletion(d, [sharedShown])
      expect(res.ok === false && res.kind).toBe('planChanged')
      expect(d.calls).toEqual([])
    }
  })

  it('runs against the FRESH views when the plan still matches', async () => {
    const fresh = entry(view('g-shared', 'member', [m(ME, 'member'), m(BOB, 'member')]))
    const d = confirmedDeps([fresh])
    const res = await runConfirmedDeletion(d, [sharedShown])
    expect(res).toEqual({ ok: true, left: 1 })
    expect(d.calls).toEqual(['leave:g-shared', 'delete'])
  })

  it('ignores roster churn that does not change what leaving does', () => {
    const more = entry(view('g1', 'member', [m(ME, 'member'), m(BOB, 'admin'), m('zz', 'member')]))
    const less = entry(view('g1', 'member', [m(ME, 'member'), m(BOB, 'admin')]))
    expect(planFingerprint([more])).toBe(planFingerprint([less]))
  })

  it('changes nothing when the groups cannot be re-read', async () => {
    const d = deps()
    const failing = {
      ...d,
      replan: () => Promise.resolve({ ok: false as const, kind: 'failed' as const }),
    }
    expect(await runConfirmedDeletion(failing, [sharedShown])).toEqual({
      ok: false,
      kind: 'replanFailed',
    })
    const auth = {
      ...d,
      replan: () => Promise.resolve({ ok: false as const, kind: 'authRequired' as const }),
    }
    expect(await runConfirmedDeletion(auth, [sharedShown])).toEqual({
      ok: false,
      kind: 'authRequired',
      left: 0,
    })
    expect(d.calls).toEqual([])
  })
})

describe('blockerReason', () => {
  it('tells a missing successor from a missing grant', () => {
    expect(blockerReason(lastAdminGroup)).toBe('needsSuccessor')
    const noGrant = entry(view('g-nogrant', 'admin', [m(ME, 'admin'), m(BOB, 'admin')], false))
    expect(blockerReason(noGrant)).toBe('grantMissing')
  })
})

describe('planAccountDeletion concurrency', () => {
  it('never has more than a handful of rosters loading at once, and keeps group order', async () => {
    let inFlight = 0
    let peak = 0
    const ids = Array.from({ length: 30 }, (_, i) => `g${i}`)
    const res = await planAccountDeletion(
      {
        userId: ME,
        getGroup: (async () => {
          inFlight++
          peak = Math.max(peak, inFlight)
          await new Promise((r) => setTimeout(r, 2))
          inFlight--
          return { role: 'member', revocationMode: 'open', generation: 0 }
        }) as never,
        listMembers: () => Promise.resolve({ members: [m(ME, 'member'), m(BOB, 'admin')] }),
        resolveUsernames: () => Promise.resolve(new Map<string, string>()),
      },
      ids,
    )
    expect(peak).toBeLessThanOrEqual(4)
    expect(res.ok && res.entries.map((e) => e.groupId)).toEqual(ids)
  })
})

describe('deleteFailureMessage for the re-plan outcomes', () => {
  it('asks for a fresh confirmation and says nothing was changed', () => {
    const msg = deleteFailureMessage({ ok: false, kind: 'planChanged', entries: [] }, (id) => id)
    expect(msg).toContain('confirm again')
    expect(msg).toContain('Nothing was changed')
    expect(deleteFailureMessage({ ok: false, kind: 'replanFailed' }, (id) => id)).toContain(
      'nothing was changed',
    )
  })
})

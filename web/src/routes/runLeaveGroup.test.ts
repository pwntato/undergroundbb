import { describe, expect, it } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { MemberEntry } from '@/lib/api/groups'
import { leavePlan, runLeave } from './runLeaveGroup'
import type { MembersView } from './runGroupMembers'

const ME = 'aaaaaaaa-1111-4111-8111-111111111111'
const BOB = 'bbbbbbbb-2222-4222-8222-222222222222'
const CAT = 'cccccccc-3333-4333-8333-333333333333'

const m = (userId: string, role: MemberEntry['role']): MemberEntry => ({
  userId,
  role,
  generation: 0,
})
const view = (myRole: MembersView['myRole'], members: MemberEntry[]): MembersView => ({
  groupId: 'g1',
  members,
  myRole,
  myGrantSortKey: 'GRANT#x',
})

describe('leavePlan', () => {
  it('deletes the group when the caller is the only member', () => {
    expect(leavePlan(view('admin', [m(ME, 'admin')]), ME)).toEqual({ kind: 'deletesGroup' })
  })

  it('makes the last admin choose a successor from everyone else', () => {
    expect(
      leavePlan(view('admin', [m(ME, 'admin'), m(BOB, 'member'), m(CAT, 'ambassador')]), ME),
    ).toEqual({ kind: 'needsSuccessor', candidates: [BOB, CAT] })
  })

  it('lets an admin leave plainly when another admin exists', () => {
    expect(leavePlan(view('admin', [m(ME, 'admin'), m(BOB, 'admin')]), ME)).toEqual({
      kind: 'plain',
    })
  })

  it('lets a non-admin leave plainly', () => {
    for (const role of ['member', 'ambassador'] as const) {
      expect(leavePlan(view(role, [m(BOB, 'admin'), m(ME, role)]), ME)).toEqual({ kind: 'plain' })
    }
  })
})

describe('runLeave', () => {
  const failing = (status: number, code?: string) => () =>
    Promise.reject(new ApiError(status, 'x', code))

  it('reports success and whether the group was deleted', async () => {
    expect(
      await runLeave({ leaveGroup: () => Promise.resolve({ groupDeleted: true }) }, 'g'),
    ).toEqual({
      ok: true,
      groupDeleted: true,
    })
  })

  it('tells last_admin apart from other 409s', async () => {
    expect(await runLeave({ leaveGroup: failing(409, 'last_admin') }, 'g')).toEqual({
      ok: false,
      kind: 'lastAdmin',
    })
    expect(await runLeave({ leaveGroup: failing(409, 'conflict_retry') }, 'g')).toEqual({
      ok: false,
      kind: 'stale',
    })
  })

  it('maps 401 and 404, and treats everything else as ambiguous', async () => {
    expect(await runLeave({ leaveGroup: failing(401) }, 'g')).toEqual({
      ok: false,
      kind: 'authRequired',
    })
    expect(await runLeave({ leaveGroup: failing(404) }, 'g')).toEqual({
      ok: false,
      kind: 'notFound',
    })
    expect(await runLeave({ leaveGroup: failing(500) }, 'g')).toEqual({
      ok: false,
      kind: 'ambiguous',
    })
    expect(
      await runLeave({ leaveGroup: () => Promise.reject(new TypeError('network')) }, 'g'),
    ).toEqual({
      ok: false,
      kind: 'ambiguous',
    })
  })
})

import { describe, expect, it } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { MemberEntry } from '@/lib/api/groups'
import { leaveFailureMessage, leavePlan, runLeave, type LeaveDeps } from './runLeaveGroup'
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
  const neverSign = () => Promise.reject(new Error('must not sign'))
  const memberView = view('member', [m(ME, 'member'), m(BOB, 'admin')])
  const adminView = view('admin', [m(ME, 'admin'), m(BOB, 'admin')])

  const run = (
    leave: LeaveDeps['leaveGroup'],
    v: MembersView = memberView,
    plan: 'plain' | 'deletesGroup' | 'needsSuccessor' = 'plain',
    signRoleGrant: LeaveDeps['signRoleGrant'] = neverSign,
  ) => runLeave({ leaveGroup: leave, signRoleGrant, userId: ME }, v, plan)

  it('reports success and whether the group was deleted', async () => {
    expect(await run(() => Promise.resolve({ groupDeleted: true }))).toEqual({
      ok: true,
      groupDeleted: true,
    })
  })

  it('tells last_admin apart from other 409s', async () => {
    expect(await run(failing(409, 'last_admin'))).toEqual({ ok: false, kind: 'lastAdmin' })
    expect(await run(failing(409, 'conflict_retry'))).toEqual({ ok: false, kind: 'stale' })
  })

  it('maps 401 and 404, and treats everything else as ambiguous', async () => {
    expect(await run(failing(401))).toEqual({ ok: false, kind: 'authRequired' })
    expect(await run(failing(404))).toEqual({ ok: false, kind: 'notFound' })
    expect(await run(failing(500))).toEqual({ ok: false, kind: 'ambiguous' })
    expect(await run(() => Promise.reject(new TypeError('network')))).toEqual({
      ok: false,
      kind: 'ambiguous',
    })
  })

  describe('signed demotion (issue #55)', () => {
    const signer = (calls: object[] = []): LeaveDeps['signRoleGrant'] => {
      let n = 0
      return (req) => {
        calls.push(req)
        n++
        return Promise.resolve({ grantSortKey: `GRANT#${ME}#d#${n}`, signature: `sig${n}` })
      }
    }

    it('sends nothing for a plain member or the only member of a group', async () => {
      const sent: unknown[] = []
      const leave: LeaveDeps['leaveGroup'] = (_g, d) => {
        sent.push(d)
        return Promise.resolve({ groupDeleted: false })
      }
      await run(leave, memberView, 'plain')
      await run(leave, view('admin', [m(ME, 'admin')]), 'deletesGroup')
      expect(sent).toEqual([undefined, undefined])
    })

    it("signs a self-demotion to member over the caller's current grant and sends it", async () => {
      const calls: object[] = []
      let sent: unknown
      const res = await run(
        (_g, d) => {
          sent = d
          return Promise.resolve({ groupDeleted: false })
        },
        adminView,
        'plain',
        signer(calls),
      )
      expect(res.ok).toBe(true)
      expect(calls).toEqual([
        {
          userId: ME,
          groupId: 'g1',
          subjectUserId: ME,
          role: 'member',
          grantorGrantRef: 'GRANT#x',
        },
      ])
      expect(sent).toEqual({
        grantSortKey: `GRANT#${ME}#d#1`,
        grantorGrantRef: 'GRANT#x',
        signature: 'sig1',
      })
    })

    it('signs for an ambassador too, and for a last admin who has named a successor', async () => {
      for (const [v, plan] of [
        [view('ambassador', [m(ME, 'ambassador'), m(BOB, 'admin')]), 'plain'],
        [view('admin', [m(ME, 'admin'), m(BOB, 'admin')]), 'needsSuccessor'],
      ] as const) {
        const calls: object[] = []
        await run(() => Promise.resolve({ groupDeleted: false }), v, plan, signer(calls))
        expect(calls).toHaveLength(1)
      }
    })

    it('re-signs once with a fresh address on grant_key_taken, and gives up after that', async () => {
      const seen: (string | undefined)[] = []
      const ok = await run(
        (_g, d) => {
          seen.push(d?.grantSortKey)
          return seen.length === 1
            ? failing(409, 'grant_key_taken')()
            : Promise.resolve({ groupDeleted: false })
        },
        adminView,
        'plain',
        signer(),
      )
      expect(ok.ok).toBe(true)
      expect(seen).toEqual([`GRANT#${ME}#d#1`, `GRANT#${ME}#d#2`])

      const twice = await run(failing(409, 'grant_key_taken'), adminView, 'plain', signer())
      expect(twice).toEqual({ ok: false, kind: 'stale' })
    })

    it('treats demotion_required as a stale roster', async () => {
      expect(await run(failing(400, 'demotion_required'))).toEqual({ ok: false, kind: 'stale' })
    })

    it('does not send anything when the worker has no live keys', async () => {
      let called = false
      const res = await run(
        () => {
          called = true
          return Promise.resolve({ groupDeleted: false })
        },
        adminView,
        'plain',
        () => Promise.reject(new Error('no live keys cached')),
      )
      expect(res).toEqual({ ok: false, kind: 'coldKeys' })
      expect(called).toBe(false)
    })

    it('reports a missing own grant instead of sending an unsigned leave', async () => {
      let called = false
      const res = await run(
        () => {
          called = true
          return Promise.resolve({ groupDeleted: false })
        },
        { ...adminView, myGrantSortKey: undefined },
        'plain',
        signer(),
      )
      expect(res).toEqual({ ok: false, kind: 'grantMissing' })
      expect(called).toBe(false)
    })
  })
})

describe('leaveFailureMessage', () => {
  it("does not claim nothing was saved once the successor's promotion has committed", () => {
    for (const kind of ['stale', 'ambiguous', 'lastAdmin'] as const) {
      const msg = leaveFailureMessage(kind, 'bob')
      expect(msg).toContain('bob is now an admin')
      expect(msg).not.toContain('nothing was saved')
    }
  })

  it('does not claim the leave failed when it is unknown whether it committed', () => {
    const msg = leaveFailureMessage('ambiguous', 'bob')
    expect(msg).toContain("couldn't confirm")
    expect(msg).not.toContain("didn't go through")
    expect(leaveFailureMessage('stale', 'bob')).toContain("didn't go through")
  })

  it('has a message for every failure kind, none claiming a leave that did not happen', () => {
    expect(leaveFailureMessage('coldKeys')).toContain('Log in again')
    expect(leaveFailureMessage('grantMissing')).toContain('Nothing was changed')
  })

  it('keeps the plain messages when no promotion happened, and for session errors', () => {
    expect(leaveFailureMessage('stale')).toContain('nothing was saved')
    expect(leaveFailureMessage('authRequired', 'bob')).toContain('session has expired')
  })
})

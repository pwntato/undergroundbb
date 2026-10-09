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
  revocationMode: 'open',
  myGeneration: 0,
})

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

  it('does not count a deleted admin as another admin', () => {
    const v = view('admin', [m(ME, 'admin'), m(BOB, 'admin'), m(CAT, 'member')])
    expect(leavePlan(v, ME, new Map([[BOB, '']]))).toEqual({
      kind: 'needsSuccessor',
      candidates: [BOB, CAT],
    })
    // Unresolved or live names leave the optimistic plan, which the server re-checks.
    expect(leavePlan(v, ME, new Map())).toEqual({ kind: 'plain' })
    expect(leavePlan(v, ME, new Map([[BOB, 'bob']]))).toEqual({ kind: 'plain' })
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
  ) => runLeave({ leaveGroup: leave, signRoleGrant, userId: ME, rotation: noRotation }, v, plan)

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

// Leaving a private Rotating group starts a re-key (#178). The leaver signs only
// that they are the member removed: they mint no key and wrap nothing, so a
// hostile leaver never holds the next one. An admin takes the marker over
// (runRotation.test.ts).
describe('runLeave in a Rotating group (#178)', () => {
  const wrapped = { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' }
  const rotatingView = (myRole: MembersView['myRole'], members: MemberEntry[]): MembersView => ({
    ...view(myRole, members),
    revocationMode: 'rotating',
    myGeneration: 2,
  })
  const at2 = (userId: string, role: MemberEntry['role'], generation = 2): MemberEntry => ({
    userId,
    role,
    generation,
  })

  interface Harness {
    sent: unknown[]
    signed: unknown[]
    deps: LeaveDeps
  }
  function harness(
    o: {
      detail?: Record<string, unknown>
      members?: MemberEntry[]
      leave?: LeaveDeps['leaveGroup']
      signError?: Error
      getGroupError?: Error
    } = {},
  ): Harness {
    const sent: unknown[] = []
    const signed: unknown[] = []
    const detail = {
      role: 'member',
      visibility: 'private',
      revocationMode: 'rotating',
      generation: 2,
      wrappedGroupKey: wrapped,
      ...o.detail,
    }
    const deps: LeaveDeps = {
      userId: ME,
      leaveGroup:
        o.leave ??
        ((_g, body) => {
          sent.push(body)
          return Promise.resolve({ groupDeleted: false })
        }),
      signRoleGrant: () => Promise.resolve({ grantSortKey: `GRANT#${ME}#d#1`, signature: 'sig' }),
      rotation: {
        rotationDeps: {
          getGroup: () =>
            o.getGroupError ? Promise.reject(o.getGroupError) : Promise.resolve(detail),
          listAllMembers: () =>
            Promise.resolve(o.members ?? [at2(ME, 'member'), at2(BOB, 'admin'), at2(CAT, 'admin')]),
        } as never,
        signLeaveRotationStart: (req) => {
          signed.push(req)
          if (o.signError) return Promise.reject(o.signError)
          return Promise.resolve({ generation: req.ownGeneration + 1, startSignature: 'start-sig' })
        },
      },
    }
    return { sent, signed, deps }
  }
  const plain = rotatingView('member', [at2(ME, 'member'), at2(BOB, 'admin'), at2(CAT, 'admin')])

  it('signs the start naming the leaver and sends it with the leave, and nothing else', async () => {
    const h = harness()
    expect(await runLeave(h.deps, plain, 'plain')).toEqual({ ok: true, groupDeleted: false })

    // Signed from the caller's own generation as the server reports it.
    expect(h.signed).toEqual([{ userId: ME, groupId: 'g1', ownGeneration: 2 }])
    // No link, no holders, no wrapped key: a leaver supplies no key material.
    expect(h.sent).toEqual([{ rotation: { generation: 3, startSignature: 'start-sig' } }])
  })

  it('needs no group key in this browser, since it mints none', async () => {
    const h = harness({ detail: { wrappedGroupKey: undefined } })
    expect(await runLeave(h.deps, plain, 'plain')).toEqual({ ok: true, groupDeleted: false })
    expect(h.sent).toHaveLength(1)
  })

  it('carries the demotion and the rotation together, signing the start only once across a re-sign', async () => {
    let calls = 0
    const bodies: unknown[] = []
    const h = harness({
      leave: (_g, body) => {
        bodies.push(body)
        calls++
        return calls === 1
          ? Promise.reject(new ApiError(409, 'x', 'grant_key_taken'))
          : Promise.resolve({ groupDeleted: false })
      },
    })
    const adminView = rotatingView('admin', [at2(ME, 'admin'), at2(BOB, 'admin')])
    expect(await runLeave(h.deps, adminView, 'plain')).toEqual({ ok: true, groupDeleted: false })
    expect(h.signed).toHaveLength(1)
    expect(bodies).toHaveLength(2)
    for (const b of bodies as { grantSortKey?: string; rotation?: { generation: number } }[]) {
      expect(b.grantSortKey).toBeDefined()
      expect(b.rotation?.generation).toBe(3)
    }
  })

  it('touches nothing when the only member leaves, or the group is not private', async () => {
    const solo = harness()
    expect(
      await runLeave(solo.deps, rotatingView('admin', [at2(ME, 'admin')]), 'deletesGroup'),
    ).toEqual({
      ok: true,
      groupDeleted: false,
    })
    expect(solo.signed).toEqual([])

    const pub = harness({ detail: { visibility: 'public' } })
    await runLeave(pub.deps, plain, 'plain')
    expect(pub.signed).toEqual([])
    expect(pub.sent).toEqual([undefined])

    // The roster the caller looked at was stale: they are in fact alone now.
    const alone = harness({ members: [at2(ME, 'member')] })
    await runLeave(alone.deps, plain, 'plain')
    expect(alone.signed).toEqual([])
    expect(alone.sent).toEqual([undefined])
  })

  const stops: [string, Parameters<typeof harness>[0], string][] = [
    [
      'a rotation is already running',
      { detail: { rotation: { generation: 3 } } },
      'rotationInProgress',
    ],
    ['the group cannot be read', { getGroupError: new Error('network') }, 'cannotCheck'],
    [
      'the worker has no live keys',
      { signError: Object.assign(new Error('x'), { name: 'LiveKeysError' }) },
      'ambiguous',
    ],
  ]
  for (const [name, opts, kind] of stops) {
    it(`sends nothing when ${name}`, async () => {
      const h = harness(opts)
      const out = await runLeave(h.deps, plain, 'plain')
      expect(out).toMatchObject({ ok: false })
      if (!out.ok && kind !== 'ambiguous') expect(out.kind).toBe(kind)
      expect(h.sent).toEqual([])
    })
  }

  it("maps the server's rotation refusals", async () => {
    const refuse = (status: number, code: string) =>
      harness({ leave: () => Promise.reject(new ApiError(status, 'x', code)) })
    for (const [status, code, kind] of [
      [409, 'rotation_in_progress', 'rotationInProgress'],
      [400, 'rotation_required', 'stale'],
    ] as const) {
      const h = refuse(status, code)
      expect(await runLeave(h.deps, plain, 'plain')).toEqual({ ok: false, kind })
    }
  })

  it('reports a 4xx refusal as nothing changed, not as an unconfirmed leave (PR #209 review)', async () => {
    for (const [status, code] of [
      [400, 'bad_signature'],
      [400, 'rotation_not_applicable'],
      [403, 'forbidden'],
      [422, 'whatever'],
    ] as const) {
      const h = harness({ leave: () => Promise.reject(new ApiError(status, 'x', code)) })
      expect(await runLeave(h.deps, plain, 'plain')).toEqual({ ok: false, kind: 'refused' })
    }
    // ...while a server error or a dropped connection still may have committed.
    for (const err of [new ApiError(500, 'x', 'internal'), new TypeError('network')]) {
      const h = harness({ leave: () => Promise.reject(err) })
      expect(await runLeave(h.deps, plain, 'plain')).toEqual({ ok: false, kind: 'ambiguous' })
    }
    expect(leaveFailureMessage('refused')).toContain('nothing was changed')
    expect(leaveFailureMessage('refused')).not.toContain("couldn't confirm")
    expect(leaveFailureMessage('refused', 'bob')).toContain("didn't go through")
  })

  it('has a message for every new failure', () => {
    for (const kind of ['rotationInProgress', 'cannotCheck'] as const) {
      expect(leaveFailureMessage(kind)).toMatch(/Nothing was changed|nothing was changed/)
    }
  })
})

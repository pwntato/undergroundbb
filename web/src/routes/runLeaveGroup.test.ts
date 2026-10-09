import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { MemberEntry } from '@/lib/api/groups'
import { leaveFailureMessage, leavePlan, runLeave, type LeaveDeps } from './runLeaveGroup'
import { selectKeyHolders, type HolderSelection } from './runRotation'
import type { MembersView } from './runGroupMembers'

vi.mock('./runRotation', () => ({ selectKeyHolders: vi.fn() }))

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
  startGroupRotation: () => Promise.reject(new Error('an Open group must not start a rotation')),
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

// Leaving a private Rotating group re-keys it, handing the new key to other
// admins (#178). The holder CHECKS live in runRotation.test.ts (selectKeyHolders);
// this is what runLeave builds from their answer.
describe('runLeave in a Rotating group (#178)', () => {
  const holderOf = (userId: string) => ({ userId, wrappingPublicKey: `wk-${userId}` })
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
    minted: unknown[]
    deps: LeaveDeps
    selected: ReturnType<typeof vi.fn>
  }
  function harness(
    o: {
      detail?: Record<string, unknown>
      members?: MemberEntry[]
      selection?: HolderSelection
      leave?: LeaveDeps['leaveGroup']
      mintError?: Error
      getGroupError?: Error
    } = {},
  ): Harness {
    const sent: unknown[] = []
    const minted: unknown[] = []
    const selected = vi.mocked(selectKeyHolders)
    selected.mockReset()
    selected.mockResolvedValue(
      o.selection ?? { ok: true, holders: [holderOf(BOB)], blocked: [], unadmitted: [] },
    )
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
        startGroupRotation: (req) => {
          minted.push(req)
          if (o.mintError) return Promise.reject(o.mintError)
          return Promise.resolve({
            generation: 3,
            link: { nonce: 'ln', ciphertext: 'lc' },
            removerWrappedKey: wrapped,
            startSignature: 'start-sig',
            holderWraps: (req.holders ?? []).map((h) => ({
              userId: h.userId,
              wrappedKey: wrapped,
            })),
          })
        },
      },
    }
    return { sent, minted, deps, selected }
  }
  const plain = rotatingView('member', [at2(ME, 'member'), at2(BOB, 'admin'), at2(CAT, 'admin')])

  it('mints the next key for the holders and sends the rotation with the leave', async () => {
    const h = harness({
      selection: { ok: true, holders: [holderOf(BOB), holderOf(CAT)], blocked: [], unadmitted: [] },
    })
    expect(await runLeave(h.deps, plain, 'plain')).toEqual({ ok: true, groupDeleted: false })

    // The new key is minted from our own entry, naming ourselves as the removed member.
    expect(h.minted).toEqual([
      {
        userId: ME,
        groupId: 'g1',
        ownWrappedGroupKey: wrapped,
        ownGeneration: 2,
        subjectUserId: ME,
        holders: [
          { userId: BOB, x25519PublicKey: `wk-${BOB}` },
          { userId: CAT, x25519PublicKey: `wk-${CAT}` },
        ],
      },
    ])
    expect(h.sent).toEqual([
      {
        rotation: {
          generation: 3,
          link: { nonce: 'ln', ciphertext: 'lc' },
          startSignature: 'start-sig',
          holders: [
            { userId: BOB, wrappedKey: wrapped },
            { userId: CAT, wrappedKey: wrapped },
          ],
        },
      },
    ])
  })

  it("offers only other admins at the caller's generation as holders", async () => {
    const dan = 'dddddddd-4444-4444-8444-444444444444'
    const eve = 'eeeeeeee-5555-4555-8555-555555555555'
    const h = harness({
      members: [
        at2(ME, 'admin'),
        at2(BOB, 'admin'),
        at2(CAT, 'admin', 1), // behind: cannot take the new key forward
        at2(dan, 'member'),
        at2(eve, 'ambassador'),
      ],
    })
    await runLeave(h.deps, rotatingView('admin', []), 'plain')
    const candidates = h.selected.mock.calls[0]?.[3] as MemberEntry[]
    expect(candidates.map((c) => c.userId)).toEqual([BOB])
    expect(h.selected.mock.calls[0]?.[2]).toBe(2)
  })

  it('sends at most 50 holders', async () => {
    const many = Array.from({ length: 60 }, (_, i) => holderOf(`holder-${String(i)}`))
    const h = harness({ selection: { ok: true, holders: many, blocked: [], unadmitted: [] } })
    await runLeave(h.deps, plain, 'plain')
    const body = h.sent[0] as { rotation: { holders: unknown[] } }
    expect(body.rotation.holders).toHaveLength(50)
  })

  it('carries the demotion and the rotation together, minting the key only once across a re-sign', async () => {
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
    expect(h.minted).toHaveLength(1)
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
    expect(solo.minted).toEqual([])
    expect(solo.selected).not.toHaveBeenCalled()

    const pub = harness({ detail: { visibility: 'public' } })
    await runLeave(pub.deps, plain, 'plain')
    expect(pub.minted).toEqual([])
    expect(pub.sent).toEqual([undefined])
  })

  const stops: [string, Parameters<typeof harness>[0], string][] = [
    [
      'a rotation is already running',
      { detail: { rotation: { generation: 3 } } },
      'rotationInProgress',
    ],
    ['this browser holds no group key', { detail: { wrappedGroupKey: undefined } }, 'noGroupKey'],
    [
      'no admin passes the checks',
      { selection: { ok: true, holders: [], blocked: [BOB], unadmitted: [CAT] } },
      'noHolder',
    ],
    ['the checks cannot be run', { selection: { ok: false, reason: 'no chain' } }, 'cannotCheck'],
    ['the group cannot be read', { getGroupError: new Error('network') }, 'cannotCheck'],
    [
      'the worker has no live keys',
      { mintError: Object.assign(new Error('x'), { name: 'LiveKeysError' }) },
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
      [409, 'holder_changed', 'stale'],
      [409, 'rotation_stale_generation', 'stale'],
      [400, 'rotation_required', 'stale'],
      [400, 'bad_holders', 'stale'],
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
    for (const kind of ['rotationInProgress', 'noGroupKey', 'noHolder', 'cannotCheck'] as const) {
      expect(leaveFailureMessage(kind)).toMatch(/Nothing was changed|nothing was changed/)
    }
  })
})

import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, MemberRole, RemoveMemberRequest } from '@/lib/api/groups'
import {
  removeFailureMessage,
  runRemoveMember,
  shouldReloadAfterRemove,
  type RemoveDeps,
} from './runRemoveMember'

const ME = 'a0000000-0000-4000-8000-000000000001'
const SUBJECT = 'b0000000-0000-4000-8000-000000000002'
const GROUP = 'g0000000-0000-4000-8000-000000000009'
const MY_GRANT = `GRANT#2026-10-02T00:00:00Z#${ME}`
const OWN_KEY = { ephemeralPub: 'e0', nonce: 'n0', ciphertext: 'c0' }
const MINTED = {
  generation: 4,
  link: { nonce: 'ln', ciphertext: 'lc' },
  removerWrappedKey: { ephemeralPub: 'e1', nonce: 'n1', ciphertext: 'c1' },
  startSignature: 'start-sig',
}

function detail(overrides: Partial<GroupDetail> = {}): GroupDetail {
  return {
    groupId: GROUP,
    visibility: 'private',
    role: 'admin',
    generation: 3,
    nameGeneration: 0,
    revocationMode: 'open',
    expirationDays: 0,
    version: 0,
    myGrantSortKey: MY_GRANT,
    wrappedGroupKey: OWN_KEY,
    ...overrides,
  } as GroupDetail
}

function setup(d: GroupDetail = detail()) {
  const calls: { groupId: string; userId: string; body: RemoveMemberRequest | undefined }[] = []
  const deps = {
    userId: ME,
    getGroup: vi.fn().mockResolvedValue(d),
    signRoleGrant: vi.fn().mockResolvedValue({
      grantSortKey: `GRANT#2026-10-02T00:00:00Z#${SUBJECT}`,
      signature: 'sig',
    }),
    startGroupRotation: vi.fn().mockResolvedValue(MINTED),
    removeMember: vi.fn(async (groupId: string, userId: string, body?: RemoveMemberRequest) => {
      calls.push({ groupId, userId, body })
    }),
  }
  return { deps: deps as unknown as RemoveDeps & typeof deps, calls }
}

const run = (deps: RemoveDeps, role: MemberRole = 'member') =>
  runRemoveMember(deps, GROUP, SUBJECT, role)

describe('runRemoveMember: what the request carries', () => {
  it('sends no body for a plain member of an Open group, and mints and signs nothing', async () => {
    const { deps, calls } = setup()
    expect(await run(deps)).toEqual({ ok: true, rotating: false })
    expect(calls).toEqual([{ groupId: GROUP, userId: SUBJECT, body: undefined }])
    expect(deps.startGroupRotation).not.toHaveBeenCalled()
    expect(deps.signRoleGrant).not.toHaveBeenCalled()
  })

  it("signs the REMOVER's demotion of an admin or ambassador subject", async () => {
    for (const role of ['admin', 'ambassador'] as const) {
      const { deps, calls } = setup()
      expect(await run(deps, role)).toEqual({ ok: true, rotating: false })
      expect(deps.signRoleGrant).toHaveBeenCalledWith({
        userId: ME,
        groupId: GROUP,
        subjectUserId: SUBJECT,
        role: 'member',
        grantorGrantRef: MY_GRANT,
      })
      expect(calls[0]?.body).toEqual({
        grantSortKey: `GRANT#2026-10-02T00:00:00Z#${SUBJECT}`,
        grantorGrantRef: MY_GRANT,
        signature: 'sig',
      })
    }
  })

  it('starts the rotation for a Rotating group: generation, link and own wrap from the fresh read', async () => {
    const { deps, calls } = setup(detail({ revocationMode: 'rotating' }))
    expect(await run(deps)).toEqual({ ok: true, rotating: true })
    expect(deps.startGroupRotation).toHaveBeenCalledWith({
      userId: ME,
      groupId: GROUP,
      ownWrappedGroupKey: OWN_KEY,
      ownGeneration: 3,
      subjectUserId: SUBJECT,
    })
    expect(calls[0]?.body).toEqual({
      rotation: {
        generation: 4,
        link: MINTED.link,
        removerWrappedKey: MINTED.removerWrappedKey,
        startSignature: MINTED.startSignature,
      },
    })
  })

  it('carries both the demotion and the rotation for an elevated subject of a Rotating group', async () => {
    const { deps, calls } = setup(detail({ revocationMode: 'rotating' }))
    await run(deps, 'admin')
    expect(calls[0]?.body).toMatchObject({
      grantorGrantRef: MY_GRANT,
      signature: 'sig',
      rotation: { generation: 4 },
    })
  })

  it('mints the new key once and re-signs when the grant address was taken', async () => {
    const { deps, calls } = setup(detail({ revocationMode: 'rotating' }))
    deps.removeMember.mockRejectedValueOnce(new ApiError(409, 'taken', 'grant_key_taken'))
    expect(await run(deps, 'admin')).toEqual({ ok: true, rotating: true })
    expect(deps.signRoleGrant).toHaveBeenCalledTimes(2)
    expect(deps.startGroupRotation).toHaveBeenCalledTimes(1)
    expect(deps.removeMember).toHaveBeenCalledTimes(2)
    expect(calls).toHaveLength(1)
  })

  it('reports a second address collision with the server message instead of looping', async () => {
    const { deps } = setup()
    deps.removeMember.mockRejectedValue(new ApiError(409, 'taken twice', 'grant_key_taken'))
    expect(await run(deps, 'admin')).toEqual({
      ok: false,
      kind: 'rejected',
      message: 'taken twice',
    })
    expect(deps.removeMember).toHaveBeenCalledTimes(2)
  })
})

describe('runRemoveMember: refuses before sending', () => {
  it('does nothing when a rotation is already running', async () => {
    const { deps } = setup(
      detail({
        revocationMode: 'rotating',
        rotation: { generation: 3, startedAt: 't', startedBy: ME },
      }),
    )
    expect(await run(deps)).toEqual({ ok: false, kind: 'rotationInProgress' })
    expect(deps.startGroupRotation).not.toHaveBeenCalled()
    expect(deps.removeMember).not.toHaveBeenCalled()
  })

  it('is forbidden for a non-admin, per the fresh read and not the roster', async () => {
    const { deps } = setup(detail({ role: 'member' }))
    expect(await run(deps)).toEqual({ ok: false, kind: 'forbidden' })
    expect(deps.removeMember).not.toHaveBeenCalled()
  })

  it('needs the caller own grant on record', async () => {
    const { deps } = setup(detail({ myGrantSortKey: '' }))
    expect(await run(deps)).toEqual({ ok: false, kind: 'grantMissing' })
    expect(deps.removeMember).not.toHaveBeenCalled()
  })

  it('needs a group key to rotate from in a Rotating group', async () => {
    const d = detail({ revocationMode: 'rotating' })
    delete (d as { wrappedGroupKey?: unknown }).wrappedGroupKey
    const { deps } = setup(d)
    expect(await run(deps)).toEqual({ ok: false, kind: 'noGroupKey' })
    expect(deps.removeMember).not.toHaveBeenCalled()
  })

  it('reports cold keys, sending nothing, when minting or signing needs live keys', async () => {
    const cold = new Error('no live keys cached')
    const rot = setup(detail({ revocationMode: 'rotating' }))
    rot.deps.startGroupRotation.mockRejectedValue(cold)
    expect(await run(rot.deps)).toEqual({ ok: false, kind: 'coldKeys' })
    expect(rot.deps.removeMember).not.toHaveBeenCalled()

    const sign = setup()
    sign.deps.signRoleGrant.mockRejectedValue(cold)
    expect(await run(sign.deps, 'admin')).toEqual({ ok: false, kind: 'coldKeys' })
    expect(sign.deps.removeMember).not.toHaveBeenCalled()
  })

  it('reports another worker failure as rejected, without sending', async () => {
    const { deps } = setup(detail({ revocationMode: 'rotating' }))
    deps.startGroupRotation.mockRejectedValue(new Error('boom'))
    expect(await run(deps)).toMatchObject({ ok: false, kind: 'rejected' })
    expect(deps.removeMember).not.toHaveBeenCalled()
  })

  it('maps a failed group read', async () => {
    const { deps } = setup()
    deps.getGroup.mockRejectedValue(new ApiError(404, 'gone'))
    expect(await run(deps)).toEqual({ ok: false, kind: 'notFound' })
    deps.getGroup.mockRejectedValue(new TypeError('network'))
    expect(await run(deps)).toEqual({ ok: false, kind: 'ambiguous' })
  })
})

describe('runRemoveMember: server answers', () => {
  const answer = async (err: unknown) => {
    const { deps } = setup()
    deps.removeMember.mockRejectedValue(err)
    return run(deps)
  }

  it('names a running rotation', async () => {
    expect(await answer(new ApiError(409, 'm', 'rotation_in_progress'))).toEqual({
      ok: false,
      kind: 'rotationInProgress',
    })
  })

  it('treats every "the group moved" answer as stale, 409 or 400', async () => {
    for (const [status, code] of [
      [409, 'grantor_ref_stale'],
      [409, 'grantor_changed'],
      [409, 'subject_role_changed'],
      [409, 'conflict_retry'],
      [409, 'rotation_stale_generation'],
      [400, 'demotion_required'],
      [400, 'rotation_required'],
      [400, 'rotation_not_applicable'],
    ] as const) {
      expect(await answer(new ApiError(status, 'm', code))).toEqual({ ok: false, kind: 'stale' })
    }
  })

  it('does not call grantor_grant_missing stale, since reloading cannot fix it', async () => {
    expect(await answer(new ApiError(409, 'no grant', 'grantor_grant_missing'))).toEqual({
      ok: false,
      kind: 'rejected',
      message: 'no grant',
    })
  })

  it('maps auth, permission and missing statuses', async () => {
    expect(await answer(new ApiError(401, 'm'))).toEqual({ ok: false, kind: 'authRequired' })
    expect(await answer(new ApiError(403, 'm'))).toEqual({ ok: false, kind: 'forbidden' })
    expect(await answer(new ApiError(404, 'm'))).toEqual({ ok: false, kind: 'notFound' })
    expect(await answer(new ApiError(400, 'bad thing'))).toEqual({
      ok: false,
      kind: 'rejected',
      message: 'bad thing',
    })
  })

  it('treats a network failure or 5xx as ambiguous: it may have committed', async () => {
    expect(await answer(new TypeError('network'))).toEqual({ ok: false, kind: 'ambiguous' })
    expect(await answer(new ApiError(500, 'oops'))).toEqual({ ok: false, kind: 'ambiguous' })
  })
})

describe('outcome helpers', () => {
  it('reloads after everything except cold keys and an expired session', () => {
    expect(shouldReloadAfterRemove({ ok: true, rotating: false })).toBe(true)
    expect(shouldReloadAfterRemove({ ok: false, kind: 'stale' })).toBe(true)
    expect(shouldReloadAfterRemove({ ok: false, kind: 'ambiguous' })).toBe(true)
    expect(shouldReloadAfterRemove({ ok: false, kind: 'coldKeys' })).toBe(false)
    expect(shouldReloadAfterRemove({ ok: false, kind: 'authRequired' })).toBe(false)
  })

  it('shows the server message for rejected and a fixed message otherwise', () => {
    expect(removeFailureMessage({ ok: false, kind: 'rejected', message: 'because' })).toBe(
      'because',
    )
    expect(removeFailureMessage({ ok: false, kind: 'stale' })).toMatch(/nobody was removed/)
  })
})

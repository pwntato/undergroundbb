// Dependency-injected tests for runGroupMembers.ts -- same structure and
// reasoning as runGroupSettings.test.ts (node environment, no jsdom).

import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, MemberEntry } from '@/lib/api/groups'
import {
  changeRole,
  loadMembers,
  shouldReloadAfter,
  type ChangeRoleDeps,
  type LoadMembersDeps,
  type ChangeRoleResult,
  type MembersView,
} from './runGroupMembers'

const ME = 'me-uuid'
const BOB = 'bob-uuid'
const MY_GRANT = 'GRANT#me-uuid#2026-09-29#aaaa'

function detail(overrides: Partial<GroupDetail> = {}): GroupDetail {
  return {
    groupId: 'g1',
    visibility: 'public',
    role: 'admin',
    generation: 0,
    nameGeneration: 0,
    revocationMode: 'open',
    expirationDays: 30,
    version: 1,
    myGrantSortKey: MY_GRANT,
    ...overrides,
  }
}

function member(userId: string, role: MemberEntry['role'] = 'member'): MemberEntry {
  return { userId, role, generation: 0 }
}

function view(overrides: Partial<MembersView> = {}): MembersView {
  return {
    groupId: 'g1',
    members: [member(ME, 'admin'), member(BOB)],
    myRole: 'admin',
    myGrantSortKey: MY_GRANT,
    revocationMode: 'open',
    myGeneration: 0,
    ...overrides,
  }
}

describe('loadMembers', () => {
  it('returns the roster with the caller role and grant ref', async () => {
    const deps: LoadMembersDeps = {
      getGroup: vi.fn().mockResolvedValue(detail()),
      listMembers: vi.fn().mockResolvedValue({ members: [member(ME, 'admin'), member(BOB)] }),
    }
    const result = await loadMembers(deps, 'g1')
    expect(result).toEqual({
      ok: true,
      view: {
        groupId: 'g1',
        members: [member(ME, 'admin'), member(BOB)],
        myRole: 'admin',
        myGrantSortKey: MY_GRANT,
        revocationMode: 'open',
        myGeneration: 0,
      },
    })
  })

  it("carries the caller's generation and a running rotation's marker", async () => {
    const rotation = { generation: 3, startedAt: '2026-10-03T00:00:00Z', startedBy: 'u9' }
    const deps: LoadMembersDeps = {
      getGroup: vi.fn().mockResolvedValue(detail({ generation: 2, rotation })),
      listMembers: vi.fn().mockResolvedValue({ members: [member(ME, 'admin')] }),
    }
    const result = await loadMembers(deps, 'g1')
    expect(result.ok && result.view).toMatchObject({ myGeneration: 2, rotation })
  })

  it('follows nextCursor across pages, in order', async () => {
    const listMembers = vi
      .fn()
      .mockResolvedValueOnce({ members: [member('a')], nextCursor: 'c1' })
      .mockResolvedValueOnce({ members: [member('b')], nextCursor: 'c2' })
      .mockResolvedValueOnce({ members: [member('c')] })
    const result = await loadMembers(
      { getGroup: vi.fn().mockResolvedValue(detail()), listMembers },
      'g1',
    )
    expect(result.ok && result.view.members.map((m) => m.userId)).toEqual(['a', 'b', 'c'])
    expect(listMembers.mock.calls.map((c) => c[1])).toEqual([undefined, 'c1', 'c2'])
  })

  it('gives up rather than loop when the cursor never ends', async () => {
    const listMembers = vi.fn().mockResolvedValue({ members: [member('a')], nextCursor: 'again' })
    const result = await loadMembers(
      { getGroup: vi.fn().mockResolvedValue(detail()), listMembers },
      'g1',
    )
    expect(result).toEqual({ ok: false, kind: 'failed' })
    expect(listMembers.mock.calls.length).toBeLessThanOrEqual(100)
  })

  it.each([
    [404, 'notFound'],
    [401, 'authRequired'],
    [500, 'failed'],
  ])('maps a %i from the roster to %s', async (status, kind) => {
    const deps: LoadMembersDeps = {
      getGroup: vi.fn().mockResolvedValue(detail()),
      listMembers: vi.fn().mockRejectedValue(new ApiError(status, 'nope')),
    }
    expect(await loadMembers(deps, 'g1')).toEqual({ ok: false, kind })
  })

  it('maps a network failure to failed', async () => {
    const deps: LoadMembersDeps = {
      getGroup: vi.fn().mockRejectedValue(new TypeError('network')),
      listMembers: vi.fn().mockResolvedValue({ members: [] }),
    }
    expect(await loadMembers(deps, 'g1')).toEqual({ ok: false, kind: 'failed' })
  })
})

function changeDeps(overrides: Partial<ChangeRoleDeps> = {}): ChangeRoleDeps {
  let n = 0
  return {
    signRoleGrant: vi.fn().mockImplementation(async () => {
      n += 1
      return { grantSortKey: `GRANT#bob-uuid#2026-09-29#k${n}`, signature: `sig${n}` }
    }),
    changeMemberRole: vi.fn().mockResolvedValue({ role: 'ambassador', grantSortKey: 'x' }),
    userId: ME,
    ...overrides,
  }
}

describe('changeRole', () => {
  it("signs on the caller's own grant and sends exactly what was signed", async () => {
    const deps = changeDeps()
    expect(await changeRole(deps, view(), BOB, 'ambassador')).toEqual({ ok: true })
    expect(deps.signRoleGrant).toHaveBeenCalledWith({
      userId: ME,
      groupId: 'g1',
      subjectUserId: BOB,
      role: 'ambassador',
      grantorGrantRef: MY_GRANT,
    })
    expect(deps.changeMemberRole).toHaveBeenCalledWith('g1', BOB, {
      role: 'ambassador',
      grantSortKey: 'GRANT#bob-uuid#2026-09-29#k1',
      grantorGrantRef: MY_GRANT,
      signature: 'sig1',
    })
  })

  it.each([
    ['a non-admin', view({ myRole: 'member' })],
    ['an admin with no grant on record', view({ myGrantSortKey: undefined })],
  ])('refuses %s without signing or sending anything', async (_label, v) => {
    const deps = changeDeps()
    expect(await changeRole(deps, v, BOB, 'admin')).toEqual({ ok: false, kind: 'forbidden' })
    expect(deps.signRoleGrant).not.toHaveBeenCalled()
    expect(deps.changeMemberRole).not.toHaveBeenCalled()
  })

  it('re-signs with a fresh address after grant_key_taken', async () => {
    const changeMemberRole = vi
      .fn()
      .mockRejectedValueOnce(new ApiError(409, 'taken', 'grant_key_taken'))
      .mockResolvedValueOnce({ role: 'admin', grantSortKey: 'x' })
    const deps = changeDeps({ changeMemberRole })
    expect(await changeRole(deps, view(), BOB, 'admin')).toEqual({ ok: true })
    expect(deps.signRoleGrant).toHaveBeenCalledTimes(2)
    // The retry must carry the second signature with the second address,
    // never the first signature reused.
    expect(changeMemberRole.mock.calls[1]?.[2]).toMatchObject({
      grantSortKey: 'GRANT#bob-uuid#2026-09-29#k2',
      signature: 'sig2',
    })
  })

  it('reports a second grant_key_taken instead of looping', async () => {
    const changeMemberRole = vi
      .fn()
      .mockRejectedValue(new ApiError(409, 'taken', 'grant_key_taken'))
    const deps = changeDeps({ changeMemberRole })
    expect(await changeRole(deps, view(), BOB, 'admin')).toEqual({
      ok: false,
      kind: 'rejected',
      message: 'taken',
    })
    expect(changeMemberRole).toHaveBeenCalledTimes(2)
  })

  it('does not call grantor_grant_missing stale: reloading cannot fix it, so the server text is shown', async () => {
    const deps = changeDeps({
      changeMemberRole: vi
        .fn()
        .mockRejectedValue(
          new ApiError(409, 'your own admin grant is not on record', 'grantor_grant_missing'),
        ),
    })
    expect(await changeRole(deps, view(), BOB, 'admin')).toEqual({
      ok: false,
      kind: 'rejected',
      message: 'your own admin grant is not on record',
    })
  })

  it('does not call grantor_granted_today stale: reloading cannot fix it, so the server text is shown', async () => {
    const message =
      'your own admin grant is dated the same UTC day as this grant, so it could never verify; try again after 00:00 UTC'
    const changeMemberRole = vi
      .fn()
      .mockRejectedValue(new ApiError(409, message, 'grantor_granted_today'))
    expect(await changeRole(changeDeps({ changeMemberRole }), view(), BOB, 'admin')).toEqual({
      ok: false,
      kind: 'rejected',
      message,
    })
    expect(changeMemberRole).toHaveBeenCalledTimes(1)
  })

  it.each(['grantor_ref_stale', 'grantor_changed', 'subject_role_changed', 'conflict_retry'])(
    'maps 409 %s to stale without resending',
    async (code) => {
      const changeMemberRole = vi.fn().mockRejectedValue(new ApiError(409, 'moved', code))
      const deps = changeDeps({ changeMemberRole })
      expect(await changeRole(deps, view(), BOB, 'admin')).toEqual({ ok: false, kind: 'stale' })
      expect(changeMemberRole).toHaveBeenCalledTimes(1)
    },
  )

  it.each([
    [401, 'authRequired'],
    [403, 'forbidden'],
    [404, 'notFound'],
  ])('maps a %i to %s', async (status, kind) => {
    const deps = changeDeps({
      changeMemberRole: vi.fn().mockRejectedValue(new ApiError(status, 'no')),
    })
    expect(await changeRole(deps, view(), BOB, 'admin')).toEqual({ ok: false, kind })
  })

  it('surfaces the server message for a 400', async () => {
    const deps = changeDeps({
      changeMemberRole: vi
        .fn()
        .mockRejectedValue(new ApiError(400, 'you cannot change your own role')),
    })
    expect(await changeRole(deps, view(), ME, 'member')).toEqual({
      ok: false,
      kind: 'rejected',
      message: 'you cannot change your own role',
    })
  })

  it.each([
    ['a 5xx', new ApiError(500, 'boom')],
    ['a network failure', new TypeError('network')],
  ])('treats %s as ambiguous, since the change may have committed', async (_label, err) => {
    const deps = changeDeps({ changeMemberRole: vi.fn().mockRejectedValue(err) })
    expect(await changeRole(deps, view(), BOB, 'admin')).toEqual({ ok: false, kind: 'ambiguous' })
  })

  it('maps a cold worker to coldKeys and sends nothing', async () => {
    const deps = changeDeps({
      signRoleGrant: vi
        .fn()
        .mockRejectedValue(new Error('worker: no live keys cached -- log in again')),
    })
    expect(await changeRole(deps, view(), BOB, 'admin')).toEqual({ ok: false, kind: 'coldKeys' })
    expect(deps.changeMemberRole).not.toHaveBeenCalled()
  })

  it('maps any other signing failure to rejected and sends nothing', async () => {
    const deps = changeDeps({ signRoleGrant: vi.fn().mockRejectedValue(new Error('boom')) })
    const result = await changeRole(deps, view(), BOB, 'admin')
    expect(result).toMatchObject({ ok: false, kind: 'rejected' })
    expect(deps.changeMemberRole).not.toHaveBeenCalled()
  })
})

describe('shouldReloadAfter', () => {
  it.each<[string, ChangeRoleResult, boolean]>([
    ['success', { ok: true }, true],
    ['stale', { ok: false, kind: 'stale' }, true],
    ['ambiguous', { ok: false, kind: 'ambiguous' }, true],
    ['rejected', { ok: false, kind: 'rejected', message: 'x' }, true],
    // The view is stale (demoted by another admin / member removed), and
    // without a reload every button keeps failing the same way.
    ['forbidden', { ok: false, kind: 'forbidden' }, true],
    ['notFound', { ok: false, kind: 'notFound' }, true],
    // A reload cannot help either of these.
    ['coldKeys', { ok: false, kind: 'coldKeys' }, false],
    ['authRequired', { ok: false, kind: 'authRequired' }, false],
  ])('%s -> %s', (_label, outcome, want) => {
    expect(shouldReloadAfter(outcome)).toBe(want)
  })
})

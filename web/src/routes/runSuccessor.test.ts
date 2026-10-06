// Dependency-injected tests for runSuccessor.ts -- same structure as
// runGroupMembers.test.ts (node environment, no jsdom, no worker).

import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail } from '@/lib/api/groups'
import type { DesignationRecord, GrantRecord } from '@/lib/crypto/grant-chain'
import {
  claim,
  claimBlocker,
  designate,
  loadSuccessorView,
  shouldReloadAfterSuccessor,
  type ClaimDeps,
  type DesignateDeps,
  type SuccessorView,
} from './runSuccessor'

const ADMIN = 'aaaaaaaa-1111-4111-8111-111111111111'
const BOB = 'bbbbbbbb-2222-4222-8222-222222222222'
const GROUP = 'g1'
const ADMIN_GRANT = `GRANT#${ADMIN}#2026-01-01#0123456789abcdef`
const RAND = '0123456789abcdef'
const day = (iso: string) => Date.parse(`${iso}T00:00:00Z`)
const at = (iso: string) => Date.parse(`${iso}T12:00:00Z`)

function adminView(overrides: Partial<SuccessorView> = {}): SuccessorView {
  return {
    groupId: GROUP,
    myRole: 'admin',
    myGrantSortKey: ADMIN_GRANT,
    members: [
      { userId: ADMIN, role: 'admin', generation: 0 },
      { userId: BOB, role: 'member', generation: 0 },
    ],
    designations: [],
    grants: [],
    ...overrides,
  }
}

describe('designate', () => {
  function deps(overrides: Partial<DesignateDeps> = {}): DesignateDeps {
    return {
      signSuccessorDesignation: vi.fn().mockResolvedValue({
        designationSortKey: `DESIGNATION#${ADMIN}#2026-09-01#${RAND}`,
        signature: 'sig',
      }),
      putDesignation: vi.fn().mockResolvedValue({ sortKey: 'k' }),
      userId: ADMIN,
      ...overrides,
    }
  }

  it('signs against the admin own current grant and submits exactly what was signed', async () => {
    const d = deps()
    expect(await designate(d, adminView(), BOB, 90)).toEqual({ ok: true })
    expect(d.signSuccessorDesignation).toHaveBeenCalledWith({
      userId: ADMIN,
      groupId: GROUP,
      successorUserId: BOB,
      periodDays: 90,
      adminGrantRef: ADMIN_GRANT,
    })
    expect(d.putDesignation).toHaveBeenCalledWith(GROUP, {
      designationSortKey: `DESIGNATION#${ADMIN}#2026-09-01#${RAND}`,
      successorUserId: BOB,
      periodDays: 90,
      adminGrantRef: ADMIN_GRANT,
      signature: 'sig',
    })
  })

  it('revokes with an empty successor', async () => {
    const d = deps()
    expect(await designate(d, adminView(), '', 90)).toEqual({ ok: true })
    expect(vi.mocked(d.putDesignation).mock.calls[0]?.[1]).toMatchObject({ successorUserId: '' })
  })

  it('signs nothing for a non-admin, a missing grant, yourself, or a period out of range', async () => {
    const d = deps()
    expect(await designate(d, adminView({ myRole: 'member' }), BOB, 90)).toEqual({
      ok: false,
      kind: 'forbidden',
    })
    expect(await designate(d, adminView({ myGrantSortKey: undefined }), BOB, 90)).toEqual({
      ok: false,
      kind: 'forbidden',
    })
    expect(await designate(d, adminView(), ADMIN, 90)).toMatchObject({ kind: 'rejected' })
    for (const bad of [29, 366, 90.5, Number.NaN]) {
      expect(await designate(d, adminView(), BOB, bad)).toMatchObject({ kind: 'rejected' })
    }
    expect(await designate(d, adminView(), BOB, 30)).toEqual({ ok: true })
    expect(await designate(d, adminView(), BOB, 365)).toEqual({ ok: true })
    // Only the two valid calls got as far as signing.
    expect(d.signSuccessorDesignation).toHaveBeenCalledTimes(2)
  })

  it('re-signs once with a fresh key after designation_key_taken, then reports a second', async () => {
    const put = vi
      .fn()
      .mockRejectedValueOnce(new ApiError(409, 'taken', 'designation_key_taken'))
      .mockResolvedValueOnce({ sortKey: 'k' })
    const d = deps({ putDesignation: put })
    expect(await designate(d, adminView(), BOB, 90)).toEqual({ ok: true })
    expect(d.signSuccessorDesignation).toHaveBeenCalledTimes(2)

    const always = deps({
      putDesignation: vi
        .fn()
        .mockRejectedValue(new ApiError(409, 'taken', 'designation_key_taken')),
    })
    expect(await designate(always, adminView(), BOB, 90)).toMatchObject({ kind: 'rejected' })
    expect(always.signSuccessorDesignation).toHaveBeenCalledTimes(2)
  })

  it('maps server answers: stale for a moved grant, the server message for a same-day refusal', async () => {
    const fail = (e: unknown) =>
      designate(deps({ putDesignation: vi.fn().mockRejectedValue(e) }), adminView(), BOB, 90)
    expect(await fail(new ApiError(409, 'm', 'grantor_ref_stale'))).toEqual({
      ok: false,
      kind: 'stale',
    })
    expect(await fail(new ApiError(409, 'm', 'conflict_retry'))).toEqual({
      ok: false,
      kind: 'stale',
    })
    // Reloading cannot fix a same-day refusal, so these carry the server's words.
    expect(await fail(new ApiError(409, 'try after 00:00 UTC', 'designation_today'))).toEqual({
      ok: false,
      kind: 'rejected',
      message: 'try after 00:00 UTC',
    })
    expect(await fail(new ApiError(409, 'granted today', 'grantor_granted_today'))).toMatchObject({
      kind: 'rejected',
      message: 'granted today',
    })
    expect(await fail(new ApiError(410, 'deleted', 'subject_deleted'))).toMatchObject({
      kind: 'rejected',
    })
    expect(await fail(new ApiError(401, 'x'))).toEqual({ ok: false, kind: 'authRequired' })
    expect(await fail(new ApiError(403, 'x'))).toEqual({ ok: false, kind: 'forbidden' })
    expect(await fail(new ApiError(404, 'x'))).toEqual({ ok: false, kind: 'notFound' })
    expect(await fail(new ApiError(500, 'x'))).toEqual({ ok: false, kind: 'ambiguous' })
    expect(await fail(new TypeError('network'))).toEqual({ ok: false, kind: 'ambiguous' })
  })

  it('reports cold keys when the worker has none, and sends nothing', async () => {
    const d = deps({
      signSuccessorDesignation: vi
        .fn()
        .mockRejectedValue(new Error('worker: no live keys cached -- log in again')),
    })
    expect(await designate(d, adminView(), BOB, 90)).toEqual({ ok: false, kind: 'coldKeys' })
    expect(d.putDesignation).not.toHaveBeenCalled()
  })
})

describe('claim', () => {
  const D_KEY = `DESIGNATION#${ADMIN}#2026-06-01#${RAND}`
  const designation: DesignationRecord = {
    sortKey: D_KEY,
    adminUserId: ADMIN,
    successorUserId: BOB,
    periodDays: 90,
    adminGrantRef: ADMIN_GRANT,
    signature: 'sig',
  }

  // What the server serves for the group, as BOB sees it.
  function served(
    overrides: {
      designations?: DesignationRecord[]
      grants?: GrantRecord[]
      role?: GroupDetail['role']
    } = {},
  ) {
    return {
      getGroup: vi.fn().mockResolvedValue({
        role: overrides.role ?? 'member',
        myGrantSortKey: `GRANT#${BOB}#2026-02-01#${RAND}`,
      }),
      listMembers: vi.fn().mockResolvedValue({
        members: [
          { userId: ADMIN, role: 'admin', generation: 0 },
          { userId: BOB, role: overrides.role ?? 'member', generation: 0 },
        ],
      }),
      listDesignations: vi
        .fn()
        .mockResolvedValue({ designations: overrides.designations ?? [designation] }),
      listGrants: vi.fn().mockResolvedValue({ anchor: {}, grants: overrides.grants ?? [] }),
    }
  }

  function deps(nowIso: string, overrides: Partial<ClaimDeps> = {}, signedDay = nowIso): ClaimDeps {
    return {
      ...served(),
      signSuccessorClaim: vi.fn().mockResolvedValue({
        claimSortKey: `GRANT#${BOB}#${signedDay}#${RAND}`,
        signature: 'claimsig',
      }),
      claimDesignation: vi.fn().mockResolvedValue({ role: 'admin', grantSortKey: 'k' }),
      userId: BOB,
      now: () => at(nowIso),
      ...overrides,
    } as ClaimDeps
  }

  it('signs and submits the claim once the period has elapsed', async () => {
    const d = deps('2026-09-01')
    expect(await claim(d, GROUP, D_KEY)).toEqual({ ok: true })
    expect(d.signSuccessorClaim).toHaveBeenCalledWith({
      userId: BOB,
      groupId: GROUP,
      designationSortKey: D_KEY,
    })
    expect(d.claimDesignation).toHaveBeenCalledWith(GROUP, {
      designationSortKey: D_KEY,
      claimSortKey: `GRANT#${BOB}#2026-09-01#${RAND}`,
      signature: 'claimsig',
    })
  })

  it('refuses before the period has elapsed, saying when, and signs nothing', async () => {
    const d = deps('2026-08-29')
    const out = await claim(d, GROUP, D_KEY)
    expect(out).toMatchObject({ ok: false, kind: 'rejected' })
    expect(JSON.stringify(out)).toContain('2026-08-30')
    expect(d.signSuccessorClaim).not.toHaveBeenCalled()
  })

  it('re-checks against the day the claim is signed on, not the day the screen loaded', async () => {
    // Today by the clock is the last day it would not work; the worker's clock has
    // crossed midnight, so the signed day is the first day it works... and the
    // reverse: a signed day BEFORE the period elapsed must not be sent.
    const d = deps('2026-08-30', {}, '2026-08-29')
    const out = await claim(d, GROUP, D_KEY)
    expect(out).toMatchObject({ ok: false, kind: 'rejected' })
    expect(d.signSuccessorClaim).toHaveBeenCalledTimes(1)
    expect(d.claimDesignation).not.toHaveBeenCalled()
  })

  it('refuses a designation that lapsed since the screen loaded (reads fresh data)', async () => {
    const lapse: GrantRecord = {
      sortKey: `GRANT#${ADMIN}#2026-07-01#${RAND}`,
      subjectUserId: ADMIN,
      grantedRole: 'admin',
      grantorUserId: BOB,
      signature: 's',
    }
    const d = deps('2026-09-01', served({ grants: [lapse] }))
    expect(await claim(d, GROUP, D_KEY)).toMatchObject({ ok: false, kind: 'rejected' })
    expect(d.signSuccessorClaim).not.toHaveBeenCalled()
  })

  it('refuses an admin, and a designation that was replaced', async () => {
    expect(
      claimBlocker({ ...adminView(), myRole: 'admin' }, BOB, D_KEY, day('2026-09-01')),
    ).toMatch(/already an admin/)
    const newer: DesignationRecord = {
      ...designation,
      sortKey: `DESIGNATION#${ADMIN}#2026-07-01#${RAND}`,
    }
    const view: SuccessorView = {
      ...adminView({ myRole: 'member', designations: [designation, newer] }),
    }
    expect(claimBlocker(view, BOB, D_KEY, day('2026-09-01'))).toMatch(/no longer applies/)
  })

  it('re-signs once after grant_key_taken', async () => {
    const claimFn = vi
      .fn()
      .mockRejectedValueOnce(new ApiError(409, 'taken', 'grant_key_taken'))
      .mockResolvedValueOnce({ role: 'admin', grantSortKey: 'k' })
    const d = deps('2026-09-01', { claimDesignation: claimFn })
    expect(await claim(d, GROUP, D_KEY)).toEqual({ ok: true })
    expect(d.signSuccessorClaim).toHaveBeenCalledTimes(2)
  })

  it('shows the server message for not_inactive and treats a changed situation as stale', async () => {
    const fail = (e: unknown) =>
      claim(deps('2026-09-01', { claimDesignation: vi.fn().mockRejectedValue(e) }), GROUP, D_KEY)
    expect(
      await fail(new ApiError(409, 'an admin logged in on 2026-08-31', 'not_inactive')),
    ).toEqual({
      ok: false,
      kind: 'rejected',
      message: 'an admin logged in on 2026-08-31',
    })
    for (const code of [
      'designation_superseded',
      'designation_lapsed',
      'admin_changed',
      'already_claimed',
      'already_admin',
    ]) {
      expect(await fail(new ApiError(409, 'm', code))).toEqual({ ok: false, kind: 'stale' })
    }
    expect(await fail(new ApiError(409, 'joined later', 'designation_before_join'))).toMatchObject({
      kind: 'rejected',
      message: 'joined later',
    })
    expect(await fail(new ApiError(502, 'x'))).toEqual({ ok: false, kind: 'ambiguous' })
  })

  it('reports an unreadable group without signing', async () => {
    const d = deps('2026-09-01', { getGroup: vi.fn().mockRejectedValue(new ApiError(404, 'x')) })
    expect(await claim(d, GROUP, D_KEY)).toEqual({ ok: false, kind: 'notFound' })
    expect(d.signSuccessorClaim).not.toHaveBeenCalled()
  })
})

describe('loadSuccessorView', () => {
  it('reads every page of designations and grants', async () => {
    const d1 = {
      sortKey: `DESIGNATION#${ADMIN}#2026-06-01#${RAND}`,
      adminUserId: ADMIN,
      periodDays: 90,
      adminGrantRef: '',
      signature: '',
    }
    const d2 = { ...d1, sortKey: `DESIGNATION#${ADMIN}#2026-06-02#${RAND}` }
    const result = await loadSuccessorView(
      {
        getGroup: vi.fn().mockResolvedValue({ role: 'admin', myGrantSortKey: ADMIN_GRANT }),
        listMembers: vi.fn().mockResolvedValue({ members: [] }),
        listDesignations: vi
          .fn()
          .mockResolvedValueOnce({ designations: [d1], nextCursor: 'c' })
          .mockResolvedValueOnce({ designations: [d2] }),
        listGrants: vi.fn().mockResolvedValue({ anchor: {}, grants: [] }),
      },
      GROUP,
    )
    expect(result.ok && result.view.designations).toEqual([d1, d2])
  })

  it('maps 404 and 401, and everything else is failed', async () => {
    const withGroup = (e: unknown) =>
      loadSuccessorView(
        {
          getGroup: vi.fn().mockRejectedValue(e),
          listMembers: vi.fn().mockResolvedValue({ members: [] }),
          listDesignations: vi.fn().mockResolvedValue({ designations: [] }),
          listGrants: vi.fn().mockResolvedValue({ anchor: {}, grants: [] }),
        },
        GROUP,
      )
    expect(await withGroup(new ApiError(404, 'x'))).toEqual({ ok: false, kind: 'notFound' })
    expect(await withGroup(new ApiError(401, 'x'))).toEqual({ ok: false, kind: 'authRequired' })
    expect(await withGroup(new Error('boom'))).toEqual({ ok: false, kind: 'failed' })
  })
})

describe('shouldReloadAfterSuccessor', () => {
  it('reloads except when a reload cannot help', () => {
    expect(shouldReloadAfterSuccessor({ ok: true })).toBe(true)
    expect(shouldReloadAfterSuccessor({ ok: false, kind: 'stale' })).toBe(true)
    expect(shouldReloadAfterSuccessor({ ok: false, kind: 'rejected', message: 'm' })).toBe(true)
    expect(shouldReloadAfterSuccessor({ ok: false, kind: 'coldKeys' })).toBe(false)
    expect(shouldReloadAfterSuccessor({ ok: false, kind: 'authRequired' })).toBe(false)
  })
})

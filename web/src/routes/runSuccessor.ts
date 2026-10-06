// The async bodies behind SuccessorScreen -- #161. Plain functions over
// injected network/worker calls, the same split runGroupMembers.ts makes, so
// they are unit-testable without jsdom or a real worker.
//
// Two jobs: an admin signs and submits a successor designation (or a
// revocation), and a designated successor signs and submits a claim. A claim
// re-checks eligibility against the day it is about to be signed on, since the
// screen may have sat open across midnight.

import { ApiError } from '@/lib/api/auth'
import type {
  ClaimDesignationRequest,
  GroupDetail,
  ListDesignationsResponse,
  ListGrantsResponse,
  ListMembersResponse,
  MemberEntry,
  MemberRole,
  PutDesignationRequest,
} from '@/lib/api/groups'
import type { DesignationRecord, GrantRecord } from '@/lib/crypto/grant-chain'
import {
  formatDay,
  keyDayMs,
  MAX_PERIOD_DAYS,
  MIN_PERIOD_DAYS,
  successorOffers,
  type SuccessorOffer,
  utcDayMs,
} from '@/lib/groups/designation'
import { isLiveKeysError } from './runListGroups'
import { listAllMembers } from './runGroupMembers'

export interface SuccessorView {
  readonly groupId: string
  readonly myRole: GroupDetail['role']
  /** The caller's own current grant; what a designation must be signed against. */
  readonly myGrantSortKey: string | undefined
  readonly members: readonly MemberEntry[]
  readonly designations: readonly DesignationRecord[]
  readonly grants: readonly GrantRecord[]
}

export interface LoadSuccessorDeps {
  readonly getGroup: (groupId: string) => Promise<GroupDetail>
  readonly listMembers: (groupId: string, cursor?: string) => Promise<ListMembersResponse>
  readonly listDesignations: (groupId: string, cursor?: string) => Promise<ListDesignationsResponse>
  readonly listGrants: (groupId: string, cursor?: string) => Promise<ListGrantsResponse>
}

export type LoadSuccessorResult =
  | { readonly ok: true; readonly view: SuccessorView }
  | { readonly ok: false; readonly kind: 'notFound' | 'authRequired' | 'failed' }

// A history this deep means the server is not honoring nextCursor; stop.
const MAX_PAGES = 100

async function readAll<T, R extends { readonly nextCursor?: string }>(
  read: (cursor?: string) => Promise<R>,
  items: (res: R) => readonly T[],
): Promise<T[]> {
  const all: T[] = []
  let cursor: string | undefined
  for (let page = 0; page < MAX_PAGES; page++) {
    const res = await read(cursor)
    all.push(...items(res))
    if (!res.nextCursor) return all
    cursor = res.nextCursor
  }
  throw new Error('pagination did not terminate')
}

/** Reads the group, its roster, every designation and every grant. Never throws. */
export async function loadSuccessorView(
  deps: LoadSuccessorDeps,
  groupId: string,
): Promise<LoadSuccessorResult> {
  try {
    const [detail, members, designations, grants] = await Promise.all([
      deps.getGroup(groupId),
      listAllMembers(deps, groupId),
      readAll(
        (c) => deps.listDesignations(groupId, c),
        (r) => r.designations,
      ),
      readAll(
        (c) => deps.listGrants(groupId, c),
        (r) => r.grants,
      ),
    ])
    return {
      ok: true,
      view: {
        groupId,
        myRole: detail.role,
        myGrantSortKey: detail.myGrantSortKey,
        members,
        designations,
        grants,
      },
    }
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return { ok: false, kind: 'notFound' }
    if (err instanceof ApiError && err.status === 401) return { ok: false, kind: 'authRequired' }
    return { ok: false, kind: 'failed' }
  }
}

export type SuccessorActionResult =
  | { readonly ok: true }
  // A 409 that means the situation moved under the user: reload and decide again.
  | { readonly ok: false; readonly kind: 'stale' }
  | { readonly ok: false; readonly kind: 'forbidden' | 'authRequired' | 'coldKeys' | 'notFound' }
  // A refusal with the server's (or this module's) own words; reloading does not help.
  | { readonly ok: false; readonly kind: 'rejected'; readonly message: string }
  // Network failure or 5xx: the request may or may not have committed.
  | { readonly ok: false; readonly kind: 'ambiguous' }

// Two attempts: a collision on a fresh random address is vanishingly rare, so
// one re-sign is plenty and a second collision is reported, not looped on.
const MAX_SIGN_ATTEMPTS = 2

const DESIGNATE_STALE_CODES = new Set(['grantor_ref_stale', 'grantor_changed', 'conflict_retry'])

// 'not_inactive', 'designation_before_join' and 'designation_invalid' are
// absent on purpose: reloading cannot change them, so the server's message,
// which says what to do, is what the user sees.
const CLAIM_STALE_CODES = new Set([
  'designation_superseded',
  'designation_lapsed',
  'designation_not_found',
  'designation_not_yours',
  'admin_changed',
  'already_claimed',
  'already_admin',
  'subject_role_changed',
  'conflict_retry',
])

function mapApiError(
  err: unknown,
  staleCodes: ReadonlySet<string>,
): Exclude<SuccessorActionResult, { ok: true }> {
  if (err instanceof ApiError) {
    if (err.status === 409) {
      return err.code !== undefined && staleCodes.has(err.code)
        ? { ok: false, kind: 'stale' }
        : { ok: false, kind: 'rejected', message: err.message }
    }
    if (err.status === 401) return { ok: false, kind: 'authRequired' }
    if (err.status === 403) return { ok: false, kind: 'forbidden' }
    if (err.status === 404) return { ok: false, kind: 'notFound' }
    if (err.status < 500) return { ok: false, kind: 'rejected', message: err.message }
  }
  return { ok: false, kind: 'ambiguous' }
}

function signFailure(err: unknown): Exclude<SuccessorActionResult, { ok: true }> {
  // A worker call, not a request: nothing was sent.
  return isLiveKeysError(err)
    ? { ok: false, kind: 'coldKeys' }
    : { ok: false, kind: 'rejected', message: "Couldn't sign this. Try again." }
}

export interface DesignateDeps {
  readonly signSuccessorDesignation: (req: {
    readonly userId: string
    readonly groupId: string
    readonly successorUserId: string
    readonly periodDays: number
    readonly adminGrantRef: string
  }) => Promise<{ designationSortKey: string; signature: string }>
  readonly putDesignation: (groupId: string, req: PutDesignationRequest) => Promise<unknown>
  readonly userId: string
}

/**
 * Signs and submits a designation naming `successorUserId`, or a revocation
 * when it is ''. The period is validated here as well as by the server, so a
 * bad value is never signed.
 */
export async function designate(
  deps: DesignateDeps,
  view: SuccessorView,
  successorUserId: string,
  periodDays: number,
): Promise<SuccessorActionResult> {
  if (view.myRole !== 'admin' || view.myGrantSortKey === undefined || view.myGrantSortKey === '') {
    return { ok: false, kind: 'forbidden' }
  }
  if (
    !Number.isInteger(periodDays) ||
    periodDays < MIN_PERIOD_DAYS ||
    periodDays > MAX_PERIOD_DAYS
  ) {
    return {
      ok: false,
      kind: 'rejected',
      message: `Choose a period between ${String(MIN_PERIOD_DAYS)} and ${String(MAX_PERIOD_DAYS)} days.`,
    }
  }
  if (successorUserId === deps.userId) {
    return { ok: false, kind: 'rejected', message: 'You cannot designate yourself.' }
  }
  const adminGrantRef = view.myGrantSortKey

  for (let attempt = 1; attempt <= MAX_SIGN_ATTEMPTS; attempt++) {
    let signed: { designationSortKey: string; signature: string }
    try {
      signed = await deps.signSuccessorDesignation({
        userId: deps.userId,
        groupId: view.groupId,
        successorUserId,
        periodDays,
        adminGrantRef,
      })
    } catch (err) {
      return signFailure(err)
    }
    try {
      await deps.putDesignation(view.groupId, {
        designationSortKey: signed.designationSortKey,
        successorUserId,
        periodDays,
        adminGrantRef,
        signature: signed.signature,
      })
      return { ok: true }
    } catch (err) {
      if (
        err instanceof ApiError &&
        err.status === 409 &&
        err.code === 'designation_key_taken' &&
        attempt < MAX_SIGN_ATTEMPTS
      ) {
        continue
      }
      return mapApiError(err, DESIGNATE_STALE_CODES)
    }
  }
  return { ok: false, kind: 'ambiguous' }
}

/**
 * Why a designation cannot be claimed on a given day, in words for the user,
 * or null if it can (as far as the client can tell: the server also needs the
 * admins to have been inactive, which only it can see).
 */
export function claimBlocker(
  view: SuccessorView,
  userId: string,
  designationSortKey: string,
  claimDayMs: number,
): string | null {
  if (view.myRole === 'admin') return 'You are already an admin of this group.'
  const offer = successorOffers(
    userId,
    view.designations,
    view.grants,
    view.members,
    claimDayMs,
  ).find((o) => o.designation.sortKey === designationSortKey)
  if (offer === undefined) {
    return 'This designation no longer applies: the admin changed it, was replaced, or it was already used.'
  }
  if (!offer.periodElapsed) {
    return `You can claim from ${formatDay(offer.claimableFrom)} (UTC), when ${String(offer.periodDays)} days have passed since the admin named you.`
  }
  return null
}

export interface ClaimDeps extends LoadSuccessorDeps {
  readonly signSuccessorClaim: (req: {
    readonly userId: string
    readonly groupId: string
    readonly designationSortKey: string
  }) => Promise<{ claimSortKey: string; signature: string }>
  readonly claimDesignation: (
    groupId: string,
    req: ClaimDesignationRequest,
  ) => Promise<{ role: MemberRole; grantSortKey: string }>
  readonly userId: string
  /** The clock, ms since the epoch. Defaults to Date.now. */
  readonly now?: () => number
}

/**
 * Claims the admin role the designation offers. Reloads the group first and
 * checks eligibility against today's UTC day; signs; then checks again against
 * the day the signed claim row is actually dated (the worker dates it from its
 * own clock, which may have passed midnight since), and sends only if both
 * pass. The server is the final gate and may still refuse (not_inactive).
 */
export async function claim(
  deps: ClaimDeps,
  groupId: string,
  designationSortKey: string,
): Promise<SuccessorActionResult> {
  const fresh = await loadSuccessorView(deps, groupId)
  if (!fresh.ok) {
    return fresh.kind === 'failed'
      ? { ok: false, kind: 'ambiguous' }
      : { ok: false, kind: fresh.kind }
  }
  const { view } = fresh
  const today = utcDayMs((deps.now ?? Date.now)())
  const early = claimBlocker(view, deps.userId, designationSortKey, today)
  if (early !== null) return { ok: false, kind: 'rejected', message: early }

  for (let attempt = 1; attempt <= MAX_SIGN_ATTEMPTS; attempt++) {
    let signed: { claimSortKey: string; signature: string }
    try {
      signed = await deps.signSuccessorClaim({
        userId: deps.userId,
        groupId,
        designationSortKey,
      })
    } catch (err) {
      return signFailure(err)
    }
    const signedDay = keyDayMs(signed.claimSortKey)
    if (signedDay === null) {
      return { ok: false, kind: 'rejected', message: "Couldn't sign this. Try again." }
    }
    const late = claimBlocker(view, deps.userId, designationSortKey, signedDay)
    if (late !== null) return { ok: false, kind: 'rejected', message: late }
    try {
      await deps.claimDesignation(groupId, {
        designationSortKey,
        claimSortKey: signed.claimSortKey,
        signature: signed.signature,
      })
      return { ok: true }
    } catch (err) {
      if (
        err instanceof ApiError &&
        err.status === 409 &&
        err.code === 'grant_key_taken' &&
        attempt < MAX_SIGN_ATTEMPTS
      ) {
        continue
      }
      return mapApiError(err, CLAIM_STALE_CODES)
    }
  }
  return { ok: false, kind: 'ambiguous' }
}

/** Whether to reload the view after an action: everything except outcomes a reload cannot help. */
export function shouldReloadAfterSuccessor(outcome: SuccessorActionResult): boolean {
  return outcome.ok || (outcome.kind !== 'coldKeys' && outcome.kind !== 'authRequired')
}

export type { SuccessorOffer }

// The async body and the pure rules behind leaving a group -- issue #66. Same
// split as runGroupMembers.ts: dependencies come in as arguments so it is
// unit-testable under vitest's node environment.

import { ApiError } from '@/lib/api/auth'
import type { LeaveGroupRequest, LeaveRotationRequest } from '@/lib/api/groups'
import type {
  StartGroupRotationRequest,
  StartGroupRotationResult,
} from '@/lib/crypto/worker-protocol'
import type { MembersView } from './runGroupMembers'
import { isDeletedUser } from './memberLabel'
import { isLiveKeysError } from './runListGroups'
import { selectKeyHolders, type RotationDeps } from './runRotation'

/** The most admins one leave hands the new key to; the server caps it the same (db.MaxLeaveHolders). */
const MAX_HOLDERS = 50

/** What leaving means for this caller, from the roster they are looking at. */
export type LeavePlan =
  /** Only member: leaving deletes the group. */
  | { readonly kind: 'deletesGroup' }
  /** Last Admin with others remaining: must name a successor first. */
  | { readonly kind: 'needsSuccessor'; readonly candidates: readonly string[] }
  | { readonly kind: 'plain' }

/**
 * Computed from the loaded roster, so it can be stale; the server re-checks
 * and answers 409 last_admin if this plan was optimistic.
 */
export function leavePlan(
  view: MembersView,
  userId: string,
  usernames?: ReadonlyMap<string, string>,
): LeavePlan {
  const others = view.members.filter((m) => m.userId !== userId)
  if (others.length === 0) {
    return { kind: 'deletesGroup' }
  }
  // A deleted admin is not another admin (#77): nobody can sign in as them, so
  // leaving would strand the group. `usernames` says which are deleted; while
  // they are unresolved the plan is optimistic and the server (last_admin) decides.
  if (
    view.myRole === 'admin' &&
    !others.some((m) => m.role === 'admin' && !isDeletedUser(m.userId, usernames))
  ) {
    return { kind: 'needsSuccessor', candidates: others.map((m) => m.userId) }
  }
  return { kind: 'plain' }
}

export type LeaveResult =
  | { readonly ok: true; readonly groupDeleted: boolean }
  // The plan was stale: the roster or the caller's role moved. Reload.
  | { readonly ok: false; readonly kind: 'lastAdmin' | 'stale' }
  | { readonly ok: false; readonly kind: 'authRequired' }
  // The worker has no live keys to sign the demotion (fresh page load):
  // nothing was sent. Log in again.
  | { readonly ok: false; readonly kind: 'coldKeys' }
  // An admin or ambassador whose own grant is not on record cannot sign a
  // demotion, and reloading will not fix that.
  | { readonly ok: false; readonly kind: 'grantMissing' }
  // Not a member any more (already left, or removed): nothing to leave.
  | { readonly ok: false; readonly kind: 'notFound' }
  // A key rotation is already running; the server refuses a second one. Nothing changed.
  | { readonly ok: false; readonly kind: 'rotationInProgress' }
  // This browser has no copy of the group key to mint the next one from. Nothing changed.
  | { readonly ok: false; readonly kind: 'noGroupKey' }
  // No other admin could be trusted with the new key (none up to date, or their
  // keys or invitations did not check out). Nothing changed.
  | { readonly ok: false; readonly kind: 'noHolder' }
  // The group or its admins' keys could not be read to check them. Nothing changed.
  | { readonly ok: false; readonly kind: 'cannotCheck' }
  // The server refused the request outright (a 4xx the cases above do not name,
  // e.g. a signature it could not verify). Nothing was written.
  | { readonly ok: false; readonly kind: 'refused' }
  // Network failure or 5xx: the leave may or may not have committed.
  | { readonly ok: false; readonly kind: 'ambiguous' }

export interface LeaveDeps {
  readonly leaveGroup: (
    groupId: string,
    demotion?: LeaveGroupRequest,
  ) => Promise<{ groupDeleted: boolean }>
  /** Signs a role grant; used with the caller as subject and role "member". */
  readonly signRoleGrant: (req: {
    readonly userId: string
    readonly groupId: string
    readonly subjectUserId: string
    readonly role: 'member'
    readonly grantorGrantRef: string
  }) => Promise<{ grantSortKey: string; signature: string }>
  /** The signed-in user's own id. */
  readonly userId: string
  /** Leaving a private Rotating group re-keys it (#178); what that needs. */
  readonly rotation: LeaveRotationDeps
}

export interface LeaveRotationDeps {
  /** The rotation job's own deps: the same reads and checks pick who gets the new key. */
  readonly rotationDeps: RotationDeps
  /** Mints the next key and wraps it to the holders (credential-material.ts's startGroupRotation). */
  readonly startGroupRotation: (
    req: Omit<StartGroupRotationRequest, 'kind' | 'id'>,
  ) => Promise<StartGroupRotationResult>
}

// Same reasoning as runGroupMembers: a collision on a fresh random address is
// vanishingly rare, so one re-sign is plenty.
const MAX_SIGN_ATTEMPTS = 2

/**
 * Leaves the group. An admin or ambassador of a group that survives signs a
 * demotion to member on top of their own current grant first, so the grant
 * chain shows they left (issue #55). Everyone else, and the only member of a
 * group (whose leave deletes it), sends nothing to sign.
 */
export async function runLeave(
  deps: LeaveDeps,
  view: MembersView,
  plan: LeavePlan['kind'],
): Promise<LeaveResult> {
  const needsDemotion = view.myRole !== 'member' && plan !== 'deletesGroup'
  const ref = view.myGrantSortKey ?? ''
  if (needsDemotion && ref === '') {
    return { ok: false, kind: 'grantMissing' }
  }

  // Minted once: a re-sign after grant_key_taken resends the same material.
  let rotation: LeaveRotationRequest | undefined
  if (plan !== 'deletesGroup' && view.revocationMode === 'rotating') {
    const prepared = await prepareLeaveRotation(deps, view.groupId)
    if (!prepared.ok) return prepared
    rotation = prepared.rotation
  }

  for (let attempt = 1; attempt <= MAX_SIGN_ATTEMPTS; attempt++) {
    let demotion: LeaveGroupRequest | undefined
    if (needsDemotion) {
      try {
        const signed = await deps.signRoleGrant({
          userId: deps.userId,
          groupId: view.groupId,
          subjectUserId: deps.userId,
          role: 'member',
          grantorGrantRef: ref,
        })
        demotion = {
          grantSortKey: signed.grantSortKey,
          grantorGrantRef: ref,
          signature: signed.signature,
        }
      } catch (err) {
        // A worker call, not a request: nothing was sent.
        return isLiveKeysError(err)
          ? { ok: false, kind: 'coldKeys' }
          : { ok: false, kind: 'ambiguous' }
      }
    }

    try {
      const body: LeaveGroupRequest | undefined =
        rotation === undefined ? demotion : { ...demotion, rotation }
      const res = await deps.leaveGroup(view.groupId, body)
      return { ok: true, groupDeleted: res.groupDeleted }
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 409 && err.code === 'grant_key_taken' && attempt < MAX_SIGN_ATTEMPTS) {
          continue
        }
        if (err.status === 409 && err.code === 'rotation_in_progress') {
          return { ok: false, kind: 'rotationInProgress' }
        }
        if (err.status === 409) {
          return { ok: false, kind: err.code === 'last_admin' ? 'lastAdmin' : 'stale' }
        }
        if (
          err.status === 400 &&
          (err.code === 'demotion_required' ||
            err.code === 'rotation_required' ||
            err.code === 'bad_holders')
        ) {
          // Promoted since the roster loaded; reload and sign next time.
          return { ok: false, kind: 'stale' }
        }
        if (err.status === 401) {
          return { ok: false, kind: 'authRequired' }
        }
        if (err.status === 404) {
          return { ok: false, kind: 'notFound' }
        }
        // Any other 4xx is a definite refusal: nothing was written, so it must
        // not read as "we couldn't confirm whether you left".
        if (err.status >= 400 && err.status < 500) {
          return { ok: false, kind: 'refused' }
        }
      }
      return { ok: false, kind: 'ambiguous' }
    }
  }
  return { ok: false, kind: 'ambiguous' }
}

type PreparedRotation =
  | { readonly ok: true; readonly rotation: LeaveRotationRequest | undefined }
  | Exclude<LeaveResult, { ok: true }>

/**
 * Mints the next group key for a leave in a private Rotating group and wraps it
 * to other admins (#178). Re-reads the group first, because the roster the
 * caller is looking at can be stale and the generation, the running rotation
 * and the key all decide what can be built. Anything that stops it changes
 * nothing: the key is minted inside the worker and only sent with the leave.
 */
async function prepareLeaveRotation(deps: LeaveDeps, groupId: string): Promise<PreparedRotation> {
  const rd = deps.rotation.rotationDeps
  let detail
  let members
  try {
    detail = await rd.getGroup(groupId)
    if (detail.visibility !== 'private' || detail.revocationMode !== 'rotating') {
      return { ok: true, rotation: undefined }
    }
    members = await rd.listAllMembers(groupId)
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) return { ok: false, kind: 'authRequired' }
    if (err instanceof ApiError && err.status === 404) return { ok: false, kind: 'notFound' }
    return { ok: false, kind: 'cannotCheck' }
  }
  if (members.every((m) => m.userId === deps.userId)) {
    return { ok: true, rotation: undefined } // the only member: leaving deletes the group
  }
  if (detail.rotation !== undefined) return { ok: false, kind: 'rotationInProgress' }
  if (!detail.wrappedGroupKey) return { ok: false, kind: 'noGroupKey' }

  // Only an admin at OUR generation can take the new key forward and finish it.
  const candidates = members.filter(
    (m) => m.role === 'admin' && m.userId !== deps.userId && m.generation === detail.generation,
  )
  const selection = await selectKeyHolders(rd, groupId, detail.generation, candidates)
  if (!selection.ok) return { ok: false, kind: 'cannotCheck' }
  const holders = selection.holders.slice(0, MAX_HOLDERS)
  if (holders.length === 0) return { ok: false, kind: 'noHolder' }

  try {
    const minted = await deps.rotation.startGroupRotation({
      userId: deps.userId,
      groupId,
      ownWrappedGroupKey: detail.wrappedGroupKey,
      ownGeneration: detail.generation,
      subjectUserId: deps.userId,
      holders: holders.map((h) => ({ userId: h.userId, x25519PublicKey: h.wrappingPublicKey })),
    })
    return {
      ok: true,
      rotation: {
        generation: minted.generation,
        link: minted.link,
        startSignature: minted.startSignature,
        holders: minted.holderWraps.map((w) => ({ userId: w.userId, wrappedKey: w.wrappedKey })),
      },
    }
  } catch (err) {
    // A worker call, not a request: nothing was sent.
    return isLiveKeysError(err) ? { ok: false, kind: 'coldKeys' } : { ok: false, kind: 'ambiguous' }
  }
}

const LEAVE_ERRORS: Record<Exclude<LeaveResult, { ok: true }>['kind'], string> = {
  lastAdmin:
    'You are the last admin, so you cannot leave yet. The latest roster is shown; choose a successor.',
  stale: 'The group changed while you were working, so nothing was saved. Try again.',
  authRequired: 'Your session has expired. Log in again and retry.',
  coldKeys: 'Log in again so this browser can sign your leaving, then retry. Nothing was changed.',
  grantMissing:
    "Your own role isn't on record for this group, so you can't leave from here yet. Nothing was changed.",
  rotationInProgress:
    'A key rotation is still running, so you cannot leave yet. Nothing was changed. Try again once it has finished.',
  noGroupKey:
    "This browser doesn't hold the group's key, so it can't re-key the group for you to leave. Nothing was changed.",
  noHolder:
    "No other admin could be trusted with the group's new key (none is up to date, or their keys or invitations did not check out), so you cannot leave yet. Nothing was changed.",
  cannotCheck:
    "We couldn't read the group or its admins' keys to check them, so nothing was changed. Try again.",
  refused:
    'The server refused this request, so nothing was changed. Reload the page and try again.',
  notFound: 'You are no longer a member of this group.',
  ambiguous: "We couldn't confirm whether you left. Check your group list before trying again.",
}

/**
 * The message for a failed leave. When `promotedName` is set the successor's
 * promotion had already committed, so "nothing was saved" would be false:
 * they are an admin now and a retry is a plain leave.
 */
export function leaveFailureMessage(
  kind: Exclude<LeaveResult, { ok: true }>['kind'],
  promotedName?: string,
): string {
  if (promotedName !== undefined) {
    if (kind === 'ambiguous') {
      // The leave may have committed; do not claim it did not.
      return `${promotedName} is now an admin, but we couldn't confirm whether you left. Check your group list before trying again.`
    }
    if (kind === 'stale' || kind === 'lastAdmin' || kind === 'refused') {
      return `${promotedName} is now an admin, but leaving didn't go through. Try Leave again.`
    }
  }
  return LEAVE_ERRORS[kind]
}

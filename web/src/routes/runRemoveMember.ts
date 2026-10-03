// The async body behind removing a member -- issue #58, slice 4. Same split as
// runLeaveGroup.ts: dependencies come in as arguments so it is unit-testable
// under vitest's node environment.
//
// The request DELETE /api/groups/{gid}/members/{uid} carries depends on two
// facts read FRESH here, not from the roster the admin is looking at:
//   - the subject's role: an admin or ambassador is demoted by the REMOVER's
//     signed grant of `member`, in the same transaction as the delete (so an
//     involuntary departure needs nothing from the removed admin);
//   - the group's revocation mode: a Rotating group's removal also starts the
//     key rotation, so the browser mints the next group key and sends the
//     chain link plus the remover's own wrap of it. Re-wrapping everyone else
//     is runRotation's job, run by the caller after this returns ok.
// A stale view of either is caught by the server (409 subject_role_changed /
// conflict_retry, 400 demotion_required), which this reports as 'stale'.

import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, MemberRole, RemoveMemberRequest } from '@/lib/api/groups'
import type {
  StartGroupRotationRequest,
  StartGroupRotationResult,
} from '@/lib/crypto/worker-protocol'
import { isLiveKeysError } from './runListGroups'

export type RemoveResult =
  /** Removed. `rotating` says whether a rotation was started and must now be run. */
  | { readonly ok: true; readonly rotating: boolean }
  // The roster, the subject's role or the caller's own standing moved. Reload.
  | { readonly ok: false; readonly kind: 'stale' }
  // Another rotation is still running; finish it before removing anyone.
  | { readonly ok: false; readonly kind: 'rotationInProgress' }
  | { readonly ok: false; readonly kind: 'authRequired' | 'forbidden' | 'notFound' }
  // The worker has no live keys to sign or wrap with: nothing was sent.
  | { readonly ok: false; readonly kind: 'coldKeys' }
  // The caller's own admin grant is not on record, so a demotion cannot be signed.
  | { readonly ok: false; readonly kind: 'grantMissing' }
  // A Rotating group whose caller holds no group key to rotate from.
  | { readonly ok: false; readonly kind: 'noGroupKey' }
  // A 4xx validation failure, with the server's own message.
  | { readonly ok: false; readonly kind: 'rejected'; readonly message: string }
  // Network failure or 5xx: the removal may or may not have committed.
  | { readonly ok: false; readonly kind: 'ambiguous' }

export interface RemoveDeps {
  readonly getGroup: (groupId: string) => Promise<GroupDetail>
  readonly signRoleGrant: (req: {
    readonly userId: string
    readonly groupId: string
    readonly subjectUserId: string
    readonly role: 'member'
    readonly grantorGrantRef: string
  }) => Promise<{ grantSortKey: string; signature: string }>
  readonly startGroupRotation: (
    req: Omit<StartGroupRotationRequest, 'kind' | 'id'>,
  ) => Promise<StartGroupRotationResult>
  readonly removeMember: (
    groupId: string,
    userId: string,
    req?: RemoveMemberRequest,
  ) => Promise<void>
  /** The signed-in user's own id. */
  readonly userId: string
}

// 'grantor_grant_missing' is deliberately absent: reloading cannot fix it.
const STALE_CODES = new Set([
  'grantor_ref_stale',
  'grantor_changed',
  'subject_role_changed',
  'conflict_retry',
  'rotation_stale_generation',
  // The request did not match the subject's role or the mode we read: the
  // group moved since the fresh read.
  'demotion_required',
  'rotation_required',
  'rotation_not_applicable',
])

// A collision on a fresh random address is vanishingly rare; one re-sign is plenty.
const MAX_SIGN_ATTEMPTS = 2

/**
 * Removes subjectUserId (whose role the roster shows as subjectRole). The
 * group is re-read first: the demotion and the rotation are both decided by
 * state that may have moved since the roster loaded.
 */
export async function runRemoveMember(
  deps: RemoveDeps,
  groupId: string,
  subjectUserId: string,
  subjectRole: MemberRole,
): Promise<RemoveResult> {
  let detail: GroupDetail
  try {
    detail = await deps.getGroup(groupId)
  } catch (err) {
    return failureOf(err)
  }
  if (detail.role !== 'admin') {
    return { ok: false, kind: 'forbidden' }
  }
  if (detail.rotation !== undefined) {
    // The server refuses too; saying so before minting a key is kinder.
    return { ok: false, kind: 'rotationInProgress' }
  }
  const ref = detail.myGrantSortKey ?? ''
  if (ref === '') {
    return { ok: false, kind: 'grantMissing' }
  }

  const rotating = detail.revocationMode === 'rotating'
  let rotation: RemoveMemberRequest['rotation']
  if (rotating) {
    if (!detail.wrappedGroupKey) {
      return { ok: false, kind: 'noGroupKey' }
    }
    try {
      // Minted once: a re-sign after grant_key_taken resends the same material.
      const minted = await deps.startGroupRotation({
        userId: deps.userId,
        groupId,
        ownWrappedGroupKey: detail.wrappedGroupKey,
        ownGeneration: detail.generation,
      })
      rotation = {
        generation: minted.generation,
        link: minted.link,
        removerWrappedKey: minted.removerWrappedKey,
      }
    } catch (err) {
      // A worker call, not a request: nothing was sent.
      return isLiveKeysError(err)
        ? { ok: false, kind: 'coldKeys' }
        : { ok: false, kind: 'rejected', message: "Couldn't prepare the new group key. Try again." }
    }
  }

  const elevated = subjectRole !== 'member'
  for (let attempt = 1; attempt <= MAX_SIGN_ATTEMPTS; attempt++) {
    let body: RemoveMemberRequest | undefined
    if (elevated) {
      try {
        const signed = await deps.signRoleGrant({
          userId: deps.userId,
          groupId,
          subjectUserId,
          role: 'member',
          grantorGrantRef: ref,
        })
        body = {
          grantSortKey: signed.grantSortKey,
          grantorGrantRef: ref,
          signature: signed.signature,
          ...(rotation === undefined ? {} : { rotation }),
        }
      } catch (err) {
        return isLiveKeysError(err)
          ? { ok: false, kind: 'coldKeys' }
          : { ok: false, kind: 'rejected', message: "Couldn't sign this removal. Try again." }
      }
    } else if (rotation !== undefined) {
      body = { rotation }
    }

    try {
      await deps.removeMember(groupId, subjectUserId, body)
      return { ok: true, rotating }
    } catch (err) {
      if (err instanceof ApiError && err.status === 409 && err.code === 'grant_key_taken') {
        if (attempt < MAX_SIGN_ATTEMPTS) {
          continue
        }
        return { ok: false, kind: 'rejected', message: err.message }
      }
      return failureOf(err)
    }
  }
  return { ok: false, kind: 'ambiguous' }
}

function failureOf(err: unknown): Extract<RemoveResult, { ok: false }> {
  if (err instanceof ApiError) {
    if (err.status === 409 && err.code === 'rotation_in_progress') {
      return { ok: false, kind: 'rotationInProgress' }
    }
    if (err.code !== undefined && STALE_CODES.has(err.code)) {
      return { ok: false, kind: 'stale' }
    }
    if (err.status === 409) {
      return { ok: false, kind: 'rejected', message: err.message }
    }
    if (err.status === 401) {
      return { ok: false, kind: 'authRequired' }
    }
    if (err.status === 403) {
      return { ok: false, kind: 'forbidden' }
    }
    if (err.status === 404) {
      return { ok: false, kind: 'notFound' }
    }
    if (err.status < 500) {
      return { ok: false, kind: 'rejected', message: err.message }
    }
  }
  return { ok: false, kind: 'ambiguous' }
}

export type RotationNeed =
  { readonly run: false } | { readonly run: true; readonly exclude: ReadonlySet<string> }

/**
 * Whether a rotation job must run now, and who it must never wrap to.
 *   - ok in a Rotating group: the removal started a rotation.
 *   - ambiguous in a Rotating group: it may have committed and started one;
 *     running is safe (runRotation says 'none' when there is nothing to do),
 *     and the subject is excluded in case it did.
 *   - rotationInProgress: a marker exists (someone else's, or ours from an
 *     earlier ambiguous attempt); finish it, with no one to exclude.
 * Everything else changed nothing, so there is nothing to run.
 */
export function rotationNeededAfter(
  outcome: RemoveResult,
  rotatingGroup: boolean,
  subjectUserId: string,
): RotationNeed {
  if (outcome.ok) {
    return outcome.rotating ? { run: true, exclude: new Set([subjectUserId]) } : { run: false }
  }
  if (outcome.kind === 'rotationInProgress') {
    return { run: true, exclude: new Set() }
  }
  if (outcome.kind === 'ambiguous' && rotatingGroup) {
    return { run: true, exclude: new Set([subjectUserId]) }
  }
  return { run: false }
}

/** Whether the roster should be reloaded after a removal attempt. */
export function shouldReloadAfterRemove(outcome: RemoveResult): boolean {
  return outcome.ok || (outcome.kind !== 'coldKeys' && outcome.kind !== 'authRequired')
}

const FAILURE_MESSAGES: Record<
  Exclude<Extract<RemoveResult, { ok: false }>['kind'], 'rejected'>,
  string
> = {
  stale:
    'The group changed while you were working, so nobody was removed. The latest roster is shown; try again.',
  rotationInProgress:
    'A key rotation was still running, so nobody was removed. This page is finishing it; try again once it has.',
  authRequired: 'Your session has expired. Log in again and retry.',
  forbidden: 'Only a group admin can remove members.',
  notFound: 'This member or group no longer exists.',
  coldKeys: 'Log in again to remove members.',
  grantMissing: "Your own admin grant isn't on record, so a removal can't be signed from here yet.",
  noGroupKey: "This browser doesn't hold the group's key, so it can't start the key rotation.",
  ambiguous:
    "We couldn't confirm whether the removal went through. The latest roster is shown; check it before trying again.",
}

export function removeFailureMessage(outcome: Extract<RemoveResult, { ok: false }>): string {
  return outcome.kind === 'rejected' ? outcome.message : FAILURE_MESSAGES[outcome.kind]
}

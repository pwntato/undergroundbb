// The flow behind the "Rotate keys" screen (#62, docs/DESIGN.md "What a
// rotation writes"), pulled out as a plain function over its dependencies so
// it can be tested against real ApiError instances without jsdom or a worker,
// the same split runChangePassword.ts made.
//
// preflightKeyRotation reads what the screen has to show before the user
// commits to anything: which groups they administer (and which of those are
// Open, where rotation cannot cut the old keys off), which invites go dead.
//
// runKeyRotation then does, in the order the server enforces:
//   1. revoke the invites the user has sent and nobody accepted (they are keyed
//      to the old signing seed and would stop working);
//   2. mint the new keys in the worker;
//   3. write one handoff row per administered group (the group's current key
//      wrapped to the NEW key), so the self re-key survives a closed tab;
//   4. sign the rotation under both keys and re-wrap the new keys under the new
//      password and a new recovery code;
//   5. POST rotate-keys, answering each 409 the server defines;
//   6. only after the server accepted it, make the new keys the worker's live
//      keys.
// Every outcome is a value, not a throw. A rotation that did not commit keeps
// its signed request in `attempt`, so "try again" resends the same request
// (the epoch makes it single-use) instead of minting a second set of keys.

import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, GroupListEntry } from '@/lib/api/groups'
import { GroupsConflictError, type PutHandoffRequest } from '@/lib/api/keyRotation'
import type { RotateKeysRequest, RotateKeysResponse } from '@/lib/api/keyRotation'
import type { SentInvite } from '@/lib/api/invites'
import type { UserProjection } from '@/lib/api/users'
import { bytesToBase64 } from '@/lib/crypto/base64'
import { rosterEntryId } from '@/lib/crypto/key-rotation'
import type { PinRecord } from '@/lib/crypto/pin'
import type { VerificationRecord } from '@/lib/crypto/verification'
import type { HandoffWrap, SignedKeyRotation } from '@/lib/crypto/rotation-material'
import type { SignupProgressEvent } from '@/lib/crypto/worker-protocol'

export interface AdminGroup {
  readonly groupId: string
  readonly generation: number
  readonly wrappedGroupKey: NonNullable<GroupListEntry['wrappedGroupKey']>
  /** An Open group has no re-key, so a rotation cannot cut the old keys off there. */
  readonly open: boolean
  /** Whether the group is public (always Open). */
  readonly visibility: GroupListEntry['visibility']
}

export interface KeyRotationPreflight {
  readonly userId: string
  readonly keyEpoch: number
  readonly credentialVersion: number
  readonly adminGroups: readonly AdminGroup[]
  /** Sent invites nobody accepted; the flow revokes them. */
  readonly invitesToRevoke: readonly SentInvite[]
  /** Accepted invites still waiting on this user's step 3; they cannot be revoked and will not complete. */
  readonly invitesAwaitingCompletion: number
}

export interface KeyRotationDeps {
  readonly hasLiveKeys: (userId: string) => Promise<boolean>
  readonly getCredentials: () => Promise<{ userId: string; credentialVersion: number }>
  readonly getUser: (userId: string) => Promise<UserProjection>
  readonly listGroups: () => Promise<{ groups: readonly GroupListEntry[] }>
  readonly getGroup: (groupId: string) => Promise<GroupDetail>
  readonly sentInvites: () => Promise<{ invites: readonly SentInvite[] }>
  readonly revokeInvite: (inviteId: string) => Promise<void>
  readonly listAllPins: () => Promise<PinRecord[]>
  readonly listAllVerifications: () => Promise<VerificationRecord[]>
  readonly beginKeyRotation: (userId: string) => Promise<{
    newSigningPublicKey: string
    newWrappingPublicKey: string
  }>
  readonly wrapHandoff: (req: {
    userId: string
    groupId: string
    ownWrappedGroupKey: AdminGroup['wrappedGroupKey']
    generation: number
  }) => Promise<HandoffWrap>
  readonly putHandoff: (groupId: string, req: PutHandoffRequest) => Promise<void>
  readonly signKeyRotation: (
    req: { userId: string; newPassword: string; expectedKeyEpoch: number; roster: string[] },
    onProgress: (event: SignupProgressEvent) => void,
  ) => Promise<SignedKeyRotation>
  readonly rotateKeys: (req: RotateKeysRequest) => Promise<RotateKeysResponse>
  readonly commitKeyRotation: (userId: string) => Promise<void>
  readonly discardKeyRotation: () => Promise<void>
}

export type KeyRotationStep =
  | { readonly name: 'preparing' }
  | { readonly name: 'handoffs'; readonly done: number; readonly total: number }
  | { readonly name: 'signing' }
  | { readonly name: 'committing' }

export type KeyRotationFailure =
  /** The worker has no live keys (the tab was reloaded since login). */
  | { readonly kind: 'needsLogin' }
  | { readonly kind: 'authRequired' }
  /** One rotation per cooldown. */
  | { readonly kind: 'cooldown' }
  /** A group still has a committed rotation's self re-key waiting to run. */
  | { readonly kind: 'handoffPending'; readonly groups: readonly string[] }
  /** Another admin's key change is under way in these groups; wait for it. */
  | { readonly kind: 'groupBusy'; readonly groups: readonly string[] }
  /** The account's keys or credentials changed under this flow (another tab, a password change). */
  | { readonly kind: 'changedElsewhere' }
  /** The server refused the request. Nothing committed. */
  | { readonly kind: 'rejected'; readonly message: string }
  /** No answer, and the account's keys did not change. Retrying resends the same request. */
  | { readonly kind: 'unreachable' }

export type KeyRotationResult =
  | { readonly ok: true; readonly recoveryCode: string; readonly keyEpoch: number }
  | { readonly ok: false; readonly failure: KeyRotationFailure; readonly error?: unknown }

/** What a retry needs to resume: the new keys' public halves and, once built, the signed request. */
export interface KeyRotationAttempt {
  begun?: { newSigningPublicKey: string; newWrappingPublicKey: string }
  signed?: SignedKeyRotation
  request?: RotateKeysRequest
  /** Set once the invites have been revoked, so a retry does not repeat it. */
  invitesRevoked?: boolean
}

/** Handoff rewrites and restarts one run will make before giving up. */
const MAX_ROUNDS = 4

export async function preflightKeyRotation(deps: KeyRotationDeps): Promise<KeyRotationPreflight> {
  const { userId, credentialVersion } = await deps.getCredentials()
  const [user, list, sent] = await Promise.all([
    deps.getUser(userId),
    deps.listGroups(),
    deps.sentInvites(),
  ])
  const adminGroups = await adminGroupsOf(deps, list.groups)
  return {
    userId,
    keyEpoch: user.keyEpoch,
    credentialVersion,
    adminGroups,
    invitesToRevoke: sent.invites.filter((i) => !i.accepted),
    invitesAwaitingCompletion: sent.invites.filter((i) => i.accepted).length,
  }
}

async function adminGroupsOf(
  deps: KeyRotationDeps,
  groups: readonly GroupListEntry[],
): Promise<AdminGroup[]> {
  const out: AdminGroup[] = []
  for (const g of groups) {
    if (g.role !== 'admin') continue
    if (g.wrappedGroupKey === undefined) {
      // The server serves the caller's own wrap for every group they are in;
      // without it no handoff row can be made and the rotation cannot proceed.
      throw new Error(`group ${g.groupId}: your own key for this group was not served`)
    }
    const detail = await deps.getGroup(g.groupId)
    out.push({
      groupId: g.groupId,
      generation: g.generation,
      wrappedGroupKey: g.wrappedGroupKey,
      open: detail.revocationMode === 'open',
      visibility: g.visibility,
    })
  }
  return out
}

function rosterOf(pins: readonly PinRecord[], verifications: readonly VerificationRecord[]) {
  const sig = (b64: string) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
  return [
    ...pins.map((p) => rosterEntryId(`PIN#${p.pinnedUserId}`, sig(p.signature))),
    ...verifications.map((v) => rosterEntryId(`VERIFIED#${v.verifiedUserId}`, sig(v.signature))),
  ].map(bytesToBase64)
}

/**
 * Writes the handoff row for each named group. A group the server calls stale
 * (its key moved, or the caller is not at its generation) is re-read once and
 * retried; a second refusal is that group being busy.
 */
async function writeHandoffs(
  deps: KeyRotationDeps,
  userId: string,
  groupIds: readonly string[],
  onStep: (step: KeyRotationStep) => void,
): Promise<KeyRotationFailure | null> {
  onStep({ name: 'handoffs', done: 0, total: groupIds.length })
  // The wrap and generation to hand off are read fresh: the preflight may be
  // minutes old, and a stale generation is refused anyway.
  const read = async (): Promise<Map<string, GroupListEntry>> =>
    new Map((await deps.listGroups()).groups.map((g) => [g.groupId, g]))
  let groups = await read()
  for (const [i, groupId] of groupIds.entries()) {
    for (let tryNo = 0; ; tryNo++) {
      const group = groups.get(groupId)
      if (group === undefined || group.role !== 'admin') break // no longer an admin there: nothing to hand off
      if (group.wrappedGroupKey === undefined) {
        throw new Error(`group ${groupId}: your own key for this group was not served`)
      }
      const wrapped = await deps.wrapHandoff({
        userId,
        groupId,
        ownWrappedGroupKey: group.wrappedGroupKey,
        generation: group.generation,
      })
      try {
        await deps.putHandoff(groupId, {
          generation: wrapped.generation,
          newWrappingPublicKey: wrapped.newWrappingPublicKey,
          wrappedGroupKey: wrapped.wrappedGroupKey,
        })
        break
      } catch (err) {
        if (err instanceof ApiError && err.code === 'handoff_stale') {
          // The group's key moved or our entry is behind. Re-read once; a second
          // refusal means a key change there is still under way.
          if (tryNo > 0) return { kind: 'groupBusy', groups: [groupId] }
          groups = await read()
          continue
        }
        return classify(err)
      }
    }
    onStep({ name: 'handoffs', done: i + 1, total: groupIds.length })
  }
  return null
}

/** Maps a thrown error to a failure kind. Ambiguous ones (no answer, 5xx) come back as `unreachable`. */
function classify(err: unknown): KeyRotationFailure {
  if (err instanceof GroupsConflictError) {
    if (err.code === 'handoff_pending') return { kind: 'handoffPending', groups: err.groups }
    if (err.code === 'rotation_in_progress') return { kind: 'groupBusy', groups: err.groups }
  }
  if (err instanceof ApiError) {
    if (err.status === 401) return { kind: 'authRequired' }
    if (err.status === 429 && err.code === 'rotation_cooldown') return { kind: 'cooldown' }
    if (err.status === 409) {
      if (err.code === 'handoff_pending') return { kind: 'handoffPending', groups: [] }
      return { kind: 'changedElsewhere' }
    }
    if (err.status < 500) return { kind: 'rejected', message: err.message }
  }
  return { kind: 'unreachable' }
}

export async function runKeyRotation(
  deps: KeyRotationDeps,
  pre: KeyRotationPreflight,
  newPassword: string,
  attempt: KeyRotationAttempt,
  hooks: {
    readonly onStep: (step: KeyRotationStep) => void
    readonly onProgress: (event: SignupProgressEvent) => void
  },
): Promise<KeyRotationResult> {
  const { userId } = pre
  const fail = (failure: KeyRotationFailure, error?: unknown): KeyRotationResult => ({
    ok: false,
    failure,
    ...(error === undefined ? {} : { error }),
  })

  try {
    if (!(await deps.hasLiveKeys(userId))) return fail({ kind: 'needsLogin' })

    hooks.onStep({ name: 'preparing' })
    if (attempt.invitesRevoked !== true) {
      for (const invite of pre.invitesToRevoke) {
        try {
          await deps.revokeInvite(invite.inviteId)
        } catch (err) {
          // Accepted in the meantime: it can no longer be revoked, and it is
          // the same case as the ones already waiting on step 3.
          if (!(err instanceof ApiError && err.code === 'invite_already_accepted')) throw err
        }
      }
      attempt.invitesRevoked = true
    }

    // 2. Mint the new keys, once per attempt.
    attempt.begun ??= await deps.beginKeyRotation(userId)

    // 3. Handoff rows for every administered group.
    const groupIds = pre.adminGroups.map((g) => g.groupId)
    const handoffFailure = await writeHandoffs(deps, userId, groupIds, hooks.onStep)
    if (handoffFailure !== null) return fail(handoffFailure)

    // 4. Sign, once per attempt (a retry resends the same request).
    if (attempt.request === undefined) {
      hooks.onStep({ name: 'signing' })
      const [pins, verifications] = await Promise.all([
        deps.listAllPins(),
        deps.listAllVerifications(),
      ])
      const signed = await deps.signKeyRotation(
        {
          userId,
          newPassword,
          expectedKeyEpoch: pre.keyEpoch,
          roster: rosterOf(pins, verifications),
        },
        hooks.onProgress,
      )
      attempt.signed = signed
      attempt.request = {
        expectedKeyEpoch: pre.keyEpoch,
        expectedCredentialVersion: pre.credentialVersion,
        signedDay: signed.signedDay,
        newSigningPublicKey: signed.newSigningPublicKey,
        newWrappingPublicKey: signed.newWrappingPublicKey,
        roster: signed.roster,
        oldSignature: signed.oldSignature,
        newSignature: signed.newSignature,
        salt: signed.credentials.salt,
        argon2Params: signed.credentials.argon2Params,
        wrappedPrivateKeys: signed.credentials.wrappedPrivateKeys,
        recoverySalt: signed.credentials.recoverySalt,
        recoveryArgon2Params: signed.credentials.recoveryArgon2Params,
        recoveryWrappedPrivateKeys: signed.credentials.recoveryWrappedPrivateKeys,
        recoveryVerifierSalt: signed.credentials.recoveryVerifierSalt,
        recoveryVerifierParams: signed.credentials.recoveryVerifierParams,
        recoveryVerifier: signed.credentials.recoveryVerifier,
      }
    }
    const request = attempt.request
    const signed = attempt.signed
    if (signed === undefined) throw new Error('rotation: signed material missing')

    // 5. Commit, answering the server's 409s.
    hooks.onStep({ name: 'committing' })
    for (let round = 0; round < MAX_ROUNDS; round++) {
      try {
        const res = await deps.rotateKeys(request)
        await deps.commitKeyRotation(userId)
        return { ok: true, recoveryCode: signed.credentials.recoveryCode, keyEpoch: res.keyEpoch }
      } catch (err) {
        if (err instanceof GroupsConflictError && err.code === 'handoff_required') {
          const failure = await writeHandoffs(deps, userId, err.groups, hooks.onStep)
          if (failure !== null) return fail(failure)
          hooks.onStep({ name: 'committing' })
          continue
        }
        if (err instanceof ApiError && err.status === 409 && err.code === 'handoff_changed') {
          // A handoff row moved while the server checked: rewrite them all.
          const failure = await writeHandoffs(deps, userId, groupIds, hooks.onStep)
          if (failure !== null) return fail(failure)
          hooks.onStep({ name: 'committing' })
          continue
        }
        const failure = classify(err)
        if (failure.kind === 'unreachable') {
          // No usable answer: did it commit? The account's epoch and key say.
          const committed = await rotationLanded(deps, userId, pre.keyEpoch, request)
          if (committed) {
            await deps.commitKeyRotation(userId)
            return {
              ok: true,
              recoveryCode: signed.credentials.recoveryCode,
              keyEpoch: pre.keyEpoch + 1,
            }
          }
        }
        return fail(failure, err)
      }
    }
    return fail({ kind: 'groupBusy', groups: [] })
  } catch (err) {
    return fail(classify(err), err)
  }
}

/** Whether rotate-keys committed although its response was lost: epoch moved and the new key is served. */
async function rotationLanded(
  deps: KeyRotationDeps,
  userId: string,
  fromEpoch: number,
  request: RotateKeysRequest,
): Promise<boolean> {
  try {
    const user = await deps.getUser(userId)
    return (
      user.keyEpoch === fromEpoch + 1 && user.wrappingPublicKey === request.newWrappingPublicKey
    )
  } catch {
    return false
  }
}

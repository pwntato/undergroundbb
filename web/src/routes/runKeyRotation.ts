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
// Every outcome is a value, not a throw.
//
// Once rotate-keys has been sent, the outcome can be unknown (the response was
// lost), and then nothing the server says afterwards can be read as "it did not
// happen": a landed rotation ends every session, so the next calls 401, and its
// epoch and day make a resend stale. So from that point the attempt, the pending
// keys and the recovery code are never discarded. The question "did it land?" is
// answered without a session or a password, from the login challenge, which
// serves the account's current wrapped keys: if they are the ones this request
// carried, it landed. (That read is eventually consistent, so "still the old
// ones" proves nothing; the answer is then `unconfirmed`, and a retry checks
// again before it resends the same signed request, which the epoch makes
// single-use.)

import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, GroupListEntry } from '@/lib/api/groups'
import { GroupsConflictError, type PutHandoffRequest } from '@/lib/api/keyRotation'
import type { RotateKeysRequest, RotateKeysResponse } from '@/lib/api/keyRotation'
import type { SentInvite } from '@/lib/api/invites'
import type { UserProjection } from '@/lib/api/users'
import { pendingSelfRekeys, type PendingHandoffDeps } from './pendingHandoffs'
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
  readonly username: string
  readonly keyEpoch: number
  readonly credentialVersion: number
  readonly adminGroups: readonly AdminGroup[]
  /**
   * Groups where a committed rotation's self re-key has not run yet. The server
   * refuses another rotation while any exists, so the screen offers none.
   */
  readonly pendingSelfRekeys: readonly string[]
  /** Sent invites nobody accepted; the flow revokes them. */
  readonly invitesToRevoke: readonly SentInvite[]
  /** Accepted invites still waiting on this user's step 3; they cannot be revoked and will not complete. */
  readonly invitesAwaitingCompletion: number
}

export interface KeyRotationDeps extends PendingHandoffDeps {
  readonly hasLiveKeys: (userId: string) => Promise<boolean>
  readonly getCredentials: () => Promise<{ userId: string; credentialVersion: number }>
  readonly getUser: (userId: string) => Promise<UserProjection>
  /** The unauthenticated login challenge; only the account's current wrapped keys are read from it. */
  readonly challenge: (username: string) => Promise<{
    wrappedPrivateKeys: { nonce: string; ciphertext: string }
  }>
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
  /** Resolves after `ms`; injected so the wait is not real in tests. */
  readonly wait: (ms: number) => Promise<void>
  readonly commitKeyRotation: (userId: string) => Promise<void>
  readonly discardKeyRotation: () => Promise<void>
}

export type KeyRotationStep =
  | { readonly name: 'preparing' }
  | { readonly name: 'handoffs'; readonly done: number; readonly total: number }
  | { readonly name: 'signing' }
  | { readonly name: 'committing' }
  /** Waiting out an earlier send that may still be in flight, then checking the session. */
  | { readonly name: 'settling' }

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
  /**
   * The signed day has passed, so this request cannot commit any more. After an
   * unknown send that is only believed once the in-flight window has gone by
   * and a session-authenticated read still succeeds (a committed rotation ends
   * every session, and the session check reads strongly consistently): then
   * nothing committed and nothing still can.
   */
  | { readonly kind: 'expired' }
  /** No answer before the request was sent, so the account's keys did not change. */
  | { readonly kind: 'unreachable' }
  /**
   * The request was sent and the outcome is unknown. The keys may or may not
   * have changed. `recoveryCode` is the one the new keys' recovery wrap was made
   * from: shown now, it costs nothing if the rotation did not land and is the
   * only copy if it did.
   */
  | { readonly kind: 'unconfirmed'; readonly recoveryCode: string }

export type KeyRotationResult =
  | {
      readonly ok: true
      readonly recoveryCode: string
      readonly keyEpoch: number
      /** The caller has no session or the worker did not switch keys: send them to log in with the new password. */
      readonly needsRelogin: boolean
    }
  | { readonly ok: false; readonly failure: KeyRotationFailure; readonly error?: unknown }

/** What a retry needs to resume: the new keys' public halves and, once built, the signed request. */
export interface KeyRotationAttempt {
  /** Set once rotate-keys has been called with an unknown result; never cleared except by success. */
  ambiguous?: boolean
  /** Set when rotate-keys is first called; an error after it is as unknown as the call. */
  sent?: boolean
  begun?: { newSigningPublicKey: string; newWrappingPublicKey: string }
  signed?: SignedKeyRotation
  request?: RotateKeysRequest
  /** Set once the invites have been revoked, so a retry does not repeat it. */
  invitesRevoked?: boolean
}

/**
 * Longer than a send can stay in flight: the Lambda timeout (10 s) plus the
 * edge's retries. After this, a send that was running when the signed day
 * passed has committed or died.
 */
const IN_FLIGHT_WAIT_MS = 60_000

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
  const pending = await pendingSelfRekeys(deps, list.groups, user.wrappingPublicKey)
  return {
    userId,
    username: user.username,
    keyEpoch: user.keyEpoch,
    credentialVersion,
    adminGroups,
    pendingSelfRekeys: pending,
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

  // A definite failure after the request was built. If an earlier send is
  // unaccounted for it is as unknown as that send (the guard below), so it is
  // settled, not reported. Otherwise nothing landed and the built request is
  // dropped: a retry that shows the password form must sign under the password
  // typed then, not resend one signed under the first.
  const halt = (failure: KeyRotationFailure, error?: unknown): Promise<KeyRotationResult> => {
    const { request: built, signed: builtSigned } = attempt
    if (attempt.ambiguous === true && built !== undefined && builtSigned !== undefined) {
      return settle(deps, pre, attempt, built, builtSigned.credentials.recoveryCode, error)
    }
    delete attempt.request
    delete attempt.signed
    attempt.sent = false
    return Promise.resolve(fail(failure, error))
  }

  try {
    if (!(await deps.hasLiveKeys(userId))) return fail({ kind: 'needsLogin' })

    // A retry of a request already built and sent: nothing before the send is
    // repeated (it all needs a session, which a landed rotation ended).
    if (attempt.request === undefined) {
      const failure = await prepare(deps, pre, newPassword, attempt, hooks)
      if (failure !== null) return fail(failure)
    }
    const request = attempt.request
    const signed = attempt.signed
    if (request === undefined || signed === undefined) {
      throw new Error('rotation: signed material missing')
    }
    const recoveryCode = signed.credentials.recoveryCode

    if (attempt.ambiguous === true && (await rotationLanded(deps, pre, request))) {
      return landed(deps, pre, recoveryCode)
    }

    // Commit, answering the server's 409s.
    hooks.onStep({ name: 'committing' })
    const groupIds = pre.adminGroups.map((g) => g.groupId)
    for (let round = 0; round < MAX_ROUNDS; round++) {
      let res: RotateKeysResponse
      attempt.sent = true
      try {
        res = await deps.rotateKeys(request)
      } catch (err) {
        if (err instanceof GroupsConflictError && err.code === 'handoff_required') {
          attempt.sent = false // a definite answer: this send did not commit
          const failure = await writeHandoffs(deps, userId, err.groups, hooks.onStep)
          if (failure !== null) return halt(failure)
          hooks.onStep({ name: 'committing' })
          continue
        }
        if (err instanceof ApiError && err.status === 409 && err.code === 'handoff_changed') {
          // A handoff row moved while the server checked: rewrite them all.
          attempt.sent = false
          const failure = await writeHandoffs(deps, userId, groupIds, hooks.onStep)
          if (failure !== null) return halt(failure)
          hooks.onStep({ name: 'committing' })
          continue
        }
        if (err instanceof ApiError && err.status === 400 && err.code === 'signed_day_stale') {
          // With an earlier send unaccounted for, the 400 only says THIS request
          // is too old. Wait that send out, then ask a question only a live
          // session can answer; anything else leaves it unknown.
          if (attempt.ambiguous === true) {
            if (!(await sessionStillLive(deps, userId, hooks.onStep))) {
              return settle(deps, pre, attempt, request, recoveryCode, err)
            }
            delete attempt.ambiguous
          }
          return halt({ kind: 'expired' }, err)
        }
        // The server's answer is final only if no earlier send is unaccounted
        // for. Otherwise even a 401 or a stale epoch may be the aftermath of
        // an earlier send that landed.
        if (err instanceof ApiError && err.status < 500 && attempt.ambiguous !== true) {
          return halt(classify(err), err)
        }
        return settle(deps, pre, attempt, request, recoveryCode, err)
      }
      // The server accepted it; the worker switches to the new keys. If that
      // fails the rotation still happened: the code is shown and the user logs
      // in with the new password.
      let needsRelogin = false
      try {
        await deps.commitKeyRotation(userId)
      } catch {
        needsRelogin = true
      }
      return { ok: true, recoveryCode, keyEpoch: res.keyEpoch, needsRelogin }
    }
    return halt({ kind: 'groupBusy', groups: [] })
  } catch (err) {
    // An error while a send is outstanding leaves the outcome as unknown as
    // the send itself. (A definite 409 clears `sent` first, so a failure while
    // answering it is not this case; `halt` still settles it if an earlier
    // send is unaccounted for.)
    if (attempt.request !== undefined && attempt.sent === true) {
      const signed = attempt.signed
      if (signed !== undefined) {
        return settle(deps, pre, attempt, attempt.request, signed.credentials.recoveryCode, err)
      }
    }
    return halt(classify(err), err)
  }
}

/** Waits out any send still in flight, then whether a session-authenticated read still works. */
async function sessionStillLive(
  deps: KeyRotationDeps,
  userId: string,
  onStep: (step: KeyRotationStep) => void,
): Promise<boolean> {
  onStep({ name: 'settling' })
  await deps.wait(IN_FLIGHT_WAIT_MS)
  try {
    await deps.getUser(userId)
    return true
  } catch {
    return false
  }
}

/** Everything before the send: invites, new keys, handoff rows, the signed request. */
async function prepare(
  deps: KeyRotationDeps,
  pre: KeyRotationPreflight,
  newPassword: string,
  attempt: KeyRotationAttempt,
  hooks: {
    readonly onStep: (step: KeyRotationStep) => void
    readonly onProgress: (event: SignupProgressEvent) => void
  },
): Promise<KeyRotationFailure | null> {
  const { userId } = pre
  hooks.onStep({ name: 'preparing' })
  if (attempt.invitesRevoked !== true) {
    for (const invite of pre.invitesToRevoke) {
      try {
        await deps.revokeInvite(invite.inviteId)
      } catch (err) {
        // Accepted in the meantime: it can no longer be revoked, and it is the
        // same case as the ones already waiting on step 3.
        if (!(err instanceof ApiError && err.code === 'invite_already_accepted')) throw err
      }
    }
    attempt.invitesRevoked = true
  }

  // Mint the new keys, once per attempt.
  attempt.begun ??= await deps.beginKeyRotation(userId)

  // Handoff rows for every administered group.
  const groupIds = pre.adminGroups.map((g) => g.groupId)
  const handoffFailure = await writeHandoffs(deps, userId, groupIds, hooks.onStep)
  if (handoffFailure !== null) return handoffFailure

  // Sign, once per attempt.
  hooks.onStep({ name: 'signing' })
  const [pins, verifications] = await Promise.all([deps.listAllPins(), deps.listAllVerifications()])
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
  return null
}

/**
 * The outcome of a send is unknown: it landed (settled by the login challenge)
 * or it is unconfirmed. Marks the attempt ambiguous either way, so nothing is
 * discarded and a retry checks again before it resends.
 */
async function settle(
  deps: KeyRotationDeps,
  pre: KeyRotationPreflight,
  attempt: KeyRotationAttempt,
  request: RotateKeysRequest,
  recoveryCode: string,
  error: unknown,
): Promise<KeyRotationResult> {
  attempt.ambiguous = true
  if (await rotationLanded(deps, pre, request)) {
    return landed(deps, pre, recoveryCode)
  }
  return { ok: false, failure: { kind: 'unconfirmed', recoveryCode }, error }
}

/** The rotation landed but this tab did not see the response, so it has no session for the new keys. */
async function landed(
  deps: KeyRotationDeps,
  pre: KeyRotationPreflight,
  recoveryCode: string,
): Promise<KeyRotationResult> {
  try {
    await deps.commitKeyRotation(pre.userId)
  } catch {
    // Same as any worker failure after the server accepted: the user logs in.
  }
  return { ok: true, recoveryCode, keyEpoch: pre.keyEpoch + 1, needsRelogin: true }
}

/**
 * Whether rotate-keys committed: the login challenge (unauthenticated, so it
 * works with every session ended) serves the account's wrapped keys, and they
 * are this request's if it landed. A failed or stale read is "not known".
 */
async function rotationLanded(
  deps: KeyRotationDeps,
  pre: KeyRotationPreflight,
  request: RotateKeysRequest,
): Promise<boolean> {
  try {
    const { wrappedPrivateKeys: served } = await deps.challenge(pre.username)
    return (
      served.nonce === request.wrappedPrivateKeys.nonce &&
      served.ciphertext === request.wrappedPrivateKeys.ciphertext
    )
  } catch {
    return false
  }
}

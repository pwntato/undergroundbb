// The crypto worker: every Argon2id derivation, keypair generation, wrap and
// signature this app performs runs here, off the main thread, per
// docs/DESIGN.md's "Frontend" section ("Argon2id runs in WebAssembly, and
// all crypto runs in a Web Worker so decrypting a page of posts does not
// block the UI"). The password itself is only ever posted into this worker
// and never returns from it -- only public material, wire-ready wrapped
// blobs, and a signature cross back.
//
// This file is a thin adapter over credential-material.ts's pure functions:
// it owns the postMessage boundary (parsing a request, calling the matching
// pure function, posting its progress events and result back) and nothing
// else. The pure logic lives in credential-material.ts specifically so it
// can be unit-tested directly -- this file's own top-level `self as
// DedicatedWorkerGlobalScope` throws outside a real worker/browser context,
// so nothing in this file itself can ever be imported by a test (PR #129
// review, after `wrapNewCredentials` moved but this file did not).

/// <reference lib="webworker" />

import {
  completeChangePassword as completeChangePasswordPure,
  completeInvite as completeInvitePure,
  completeLogin as completeLoginPure,
  completeRecovery as completeRecoveryPure,
  decryptGroupNames as decryptGroupNamesPure,
  encryptGroupText as encryptGroupTextPure,
  generateSignupMaterial as generateSignupMaterialPure,
  rewrapGroupKey as rewrapGroupKeyPure,
  signLeaveRotationStart as signLeaveRotationStartPure,
  startGroupRotation as startGroupRotationPure,
  signGroupCreation as signGroupCreationPure,
  signInviteAcceptance as signInviteAcceptancePure,
  signInviteCreation as signInviteCreationPure,
  signPin as signPinPure,
  signRoleGrant as signRoleGrantPure,
  signSuccessorClaim as signSuccessorClaimPure,
  signSuccessorDesignation as signSuccessorDesignationPure,
  type LiveKeys,
} from './credential-material.js'
import { base64ToBytes, base64UrlToBytes, bytesToBase64 } from './base64.js'
import type {
  ChangePasswordMaterial,
  ClearLiveKeysRequest,
  CompleteChangePasswordRequest,
  CompleteInviteRequest,
  CompleteLoginRequest,
  CompleteRecoveryRequest,
  DecryptGroupNamesRequest,
  EncryptGroupTextRequest,
  GenerateSignupMaterialRequest,
  GetOwnSigningKeyRequest,
  RecoveryMaterial,
  RewrapGroupKeyRequest,
  SignLeaveRotationStartRequest,
  StartGroupRotationRequest,
  SignGroupCreationRequest,
  SignInviteAcceptanceRequest,
  SignInviteCreationRequest,
  SignPinRequest,
  SignRoleGrantRequest,
  SignSuccessorClaimRequest,
  SignSuccessorDesignationRequest,
  SignupMaterial,
  WorkerRequest,
  WorkerResponse,
} from './worker-protocol.js'

const ctx = self as unknown as DedicatedWorkerGlobalScope

/**
 * The current tab's unwrapped keypair, live only inside this worker instance
 * -- issue #34. Populated as a side effect of a successful completeLogin
 * (which itself only posts back a signature, unchanged from before this
 * cache existed -- see credential-material.ts's completeLogin doc comment),
 * and read by signGroupCreation. Cleared on clearLiveKeys (posted on
 * logout) so a worker instance reused across a logout/login in the same tab
 * never signs under a previous account's keys.
 *
 * This is the ONLY place a live private key exists outside a function's own
 * call stack in this entire app -- it never crosses postMessage in either
 * direction, matching this file's own module doc comment ("only public
 * material, wire-ready wrapped blobs, and a signature cross back"). A main
 * thread compromised by a malicious dependency can ask this worker to sign
 * things, but cannot read the key itself out of it.
 */
let liveKeys: LiveKeys | null = null

ctx.onmessage = (event: MessageEvent<WorkerRequest>) => {
  const req = event.data
  void handle(req).catch((err: unknown) => {
    post({
      kind: 'error',
      id: req.id,
      message: err instanceof Error ? err.message : String(err),
      errorName: err instanceof Error ? err.name : 'Error',
    })
  })
}

async function handle(req: WorkerRequest): Promise<void> {
  switch (req.kind) {
    case 'generateSignupMaterial':
      await generateSignupMaterial(req)
      return
    case 'completeLogin':
      await completeLogin(req)
      return
    case 'completeRecovery':
      await completeRecovery(req)
      return
    case 'completeChangePassword':
      await completeChangePassword(req)
      return
    case 'signGroupCreation':
      await signGroupCreation(req)
      return
    case 'signRoleGrant':
      signRoleGrant(req)
      return
    case 'signSuccessorDesignation':
      signSuccessorDesignation(req)
      return
    case 'signSuccessorClaim':
      signSuccessorClaim(req)
      return
    case 'signPin':
      signPin(req)
      return
    case 'getOwnSigningKey':
      getOwnSigningKey(req)
      return
    case 'decryptGroupNames':
      await decryptGroupNames(req)
      return
    case 'encryptGroupText':
      await encryptGroupText(req)
      return
    case 'signInviteCreation':
      await signInviteCreation(req)
      return
    case 'signInviteAcceptance':
      await signInviteAcceptance(req)
      return
    case 'completeInvite':
      await completeInvite(req)
      return
    case 'startGroupRotation':
      await startGroupRotation(req)
      return
    case 'signLeaveRotationStart':
      signLeaveRotationStart(req)
      return
    case 'rewrapGroupKey':
      await rewrapGroupKey(req)
      return
    case 'clearLiveKeys':
      clearLiveKeys(req)
      return
  }
}

function post(msg: WorkerResponse): void {
  ctx.postMessage(msg)
}

async function generateSignupMaterial(req: GenerateSignupMaterialRequest): Promise<void> {
  const result: SignupMaterial = await generateSignupMaterialPure(req.userId, req.password, (p) => {
    post({ kind: 'signupProgress', id: req.id, ...p })
  })
  post({ kind: 'generateSignupMaterialDone', id: req.id, result })
}

async function completeLogin(req: CompleteLoginRequest): Promise<void> {
  const { signature, keys } = await completeLoginPure(req)
  // Cached AFTER a successful unwrap+sign -- a failed completeLoginPure call
  // (wrong password) throws before reaching here, via handle()'s own
  // try/catch (this file's top-level onmessage), so liveKeys is never
  // populated from a login attempt that didn't actually prove the password.
  liveKeys = keys
  post({ kind: 'completeLoginDone', id: req.id, signature })
}

/**
 * Signs a new group's trust anchor and root role grant, and wraps its
 * generation-0 key to the caller's own wrapping public key, using liveKeys
 * -- issue #34. Throws if liveKeys is unset (no completeLogin has succeeded
 * in this worker instance's lifetime -- e.g. the tab was reloaded since
 * login, which resets this module's state along with everything else) or
 * belongs to a different account than req.userId claims, so a caller
 * cannot accidentally sign as whichever account happened to log in most
 * recently in a worker instance reused across a logout/login in the same
 * tab.
 */
async function signGroupCreation(req: SignGroupCreationRequest): Promise<void> {
  if (liveKeys === null) {
    throw new Error(
      'worker: no live keys cached -- log in again before creating a group (this can happen after a page reload)',
    )
  }
  if (liveKeys.userId !== req.userId) {
    throw new Error('worker: cached keys belong to a different account than requested')
  }
  const result = await signGroupCreationPure(liveKeys, req.groupId, base64ToBytes(req.groupKey))
  post({ kind: 'signGroupCreationDone', id: req.id, result })
}

/**
 * Decrypts a batch of private groups' names/descriptions for the group list
 * -- issue #35, the read-path counterpart of signGroupCreation. Same
 * liveKeys-unset/wrong-account guards as signGroupCreation: those are
 * REQUEST-level failures (this call cannot proceed at all), distinct from a
 * single group's decrypt failing, which decryptGroupNamesPure already
 * handles per-entry (see that function's own doc comment) and never
 * reaches here as a thrown error.
 */
async function decryptGroupNames(req: DecryptGroupNamesRequest): Promise<void> {
  if (liveKeys === null) {
    throw new Error(
      'worker: no live keys cached -- log in again to see private group names (this can happen after a page reload)',
    )
  }
  if (liveKeys.userId !== req.userId) {
    throw new Error('worker: cached keys belong to a different account than requested')
  }
  const results = await decryptGroupNamesPure(liveKeys, req.groups)
  post({ kind: 'decryptGroupNamesDone', id: req.id, results })
}

/**
 * Seals an edited private-group name/description -- issue #36. Same
 * liveKeys-unset/wrong-account guards as decryptGroupNames; any failure
 * inside the pure function propagates as a rejection (top-level try/catch).
 */
async function encryptGroupText(req: EncryptGroupTextRequest): Promise<void> {
  if (liveKeys === null) {
    throw new Error(
      'worker: no live keys cached -- log in again to edit private group settings (this can happen after a page reload)',
    )
  }
  if (liveKeys.userId !== req.userId) {
    throw new Error('worker: cached keys belong to a different account than requested')
  }
  const { nameCiphertext, descriptionCiphertext } = await encryptGroupTextPure(liveKeys, req)
  post({ kind: 'encryptGroupTextDone', id: req.id, nameCiphertext, descriptionCiphertext })
}

/** Signs a role grant -- issue #37. Same liveKeys-unset/wrong-account guards as signGroupCreation. */
function signRoleGrant(req: SignRoleGrantRequest): void {
  if (liveKeys === null) {
    throw new Error(
      'worker: no live keys cached -- log in again before changing a role (this can happen after a page reload)',
    )
  }
  if (liveKeys.userId !== req.userId) {
    throw new Error('worker: cached keys belong to a different account than requested')
  }
  const result = signRoleGrantPure(
    liveKeys,
    req.groupId,
    req.subjectUserId,
    req.role,
    req.grantorGrantRef,
  )
  post({ kind: 'signRoleGrantDone', id: req.id, result })
}

/** Signs a successor designation -- #161. */
function signSuccessorDesignation(req: SignSuccessorDesignationRequest): void {
  const keys = requireLiveKeys(req.userId, 'designate a successor')
  const result = signSuccessorDesignationPure(
    keys,
    req.groupId,
    req.successorUserId,
    req.periodDays,
    req.adminGrantRef,
  )
  post({ kind: 'signSuccessorDesignationDone', id: req.id, result })
}

/** Signs a successor's claim -- #161. */
function signSuccessorClaim(req: SignSuccessorClaimRequest): void {
  const keys = requireLiveKeys(req.userId, 'claim the admin role')
  const result = signSuccessorClaimPure(keys, req.groupId, req.designationSortKey)
  post({ kind: 'signSuccessorClaimDone', id: req.id, result })
}

/** Signs a pin -- issue #63. Same liveKeys-unset/wrong-account guards as signRoleGrant. */
function signPin(req: SignPinRequest): void {
  const keys = requireLiveKeys(req.userId, 'pin a key')
  const result = signPinPure(
    keys,
    req.pinnedUserId,
    req.signingPublicKeys.map((k) => base64ToBytes(k)),
    base64ToBytes(req.wrappingPublicKey),
  )
  post({ kind: 'signPinDone', id: req.id, result })
}

/** Reports the caller's own current signing public key -- issue #63. */
function getOwnSigningKey(req: GetOwnSigningKeyRequest): void {
  const keys = requireLiveKeys(req.userId, 'check keys')
  post({
    kind: 'getOwnSigningKeyDone',
    id: req.id,
    signingPublicKey: bytesToBase64(keys.signingKey.publicKey),
  })
}

function requireLiveKeys(userId: string, doing: string): LiveKeys {
  if (liveKeys === null) {
    throw new Error(
      `worker: no live keys cached -- log in again to ${doing} (this can happen after a page reload)`,
    )
  }
  if (liveKeys.userId !== userId) {
    throw new Error('worker: cached keys belong to a different account than requested')
  }
  return liveKeys
}

/**
 * Signs step 1 of the invite handshake -- issue #38. Same liveKeys-unset/
 * wrong-account guards as signGroupCreation, for the identical reason.
 */
async function signInviteCreation(req: SignInviteCreationRequest): Promise<void> {
  if (liveKeys === null) {
    throw new Error(
      'worker: no live keys cached -- log in again before creating an invite (this can happen after a page reload)',
    )
  }
  if (liveKeys.userId !== req.userId) {
    throw new Error('worker: cached keys belong to a different account than requested')
  }
  const result = await signInviteCreationPure(liveKeys, req.inviteId, req.groupId, req.expiresAt)
  post({ kind: 'signInviteCreationDone', id: req.id, result })
}

/**
 * Signs step 2 of the invite handshake -- issue #39. Same liveKeys-unset/
 * wrong-account guards as signGroupCreation.
 */
async function signInviteAcceptance(req: SignInviteAcceptanceRequest): Promise<void> {
  if (liveKeys === null) {
    throw new Error(
      'worker: no live keys cached -- log in again before accepting an invite (this can happen after a page reload)',
    )
  }
  if (liveKeys.userId !== req.userId) {
    throw new Error('worker: cached keys belong to a different account than requested')
  }
  const inviteMACKey = base64UrlToBytes(req.inviteMACKey)
  const result = await signInviteAcceptancePure(liveKeys, req.inviteId, inviteMACKey)
  post({ kind: 'signInviteAcceptanceDone', id: req.id, result })
}

/**
 * Completes step 3 of the invite handshake -- issue #40. Same liveKeys-unset/
 * wrong-account guards as signGroupCreation.
 */
async function completeInvite(req: CompleteInviteRequest): Promise<void> {
  if (liveKeys === null) {
    throw new Error(
      'worker: no live keys cached -- log in again to complete pending invites (this can happen after a page reload)',
    )
  }
  if (liveKeys.userId !== req.userId) {
    throw new Error('worker: cached keys belong to a different account than requested')
  }
  const ownWrappedGroupKey = {
    ephemeralPub: base64ToBytes(req.ownWrappedGroupKey.ephemeralPub),
    nonce: base64ToBytes(req.ownWrappedGroupKey.nonce),
    ciphertext: base64ToBytes(req.ownWrappedGroupKey.ciphertext),
  }
  const invitedEd25519PublicKey = base64ToBytes(req.invitedEd25519PublicKey)
  const invitedX25519PublicKey = base64ToBytes(req.invitedX25519PublicKey)
  const inviteMAC = base64ToBytes(req.inviteMAC)
  const result = await completeInvitePure(
    liveKeys,
    req.inviteId,
    req.groupId,
    ownWrappedGroupKey,
    req.ownGeneration,
    req.invitedUserId,
    invitedEd25519PublicKey,
    invitedX25519PublicKey,
    inviteMAC,
    req.inviterGrantRef,
    req.day,
  )
  post({ kind: 'completeInviteDone', id: req.id, result })
}

function requireLiveKeysFor(userId: string, action: string): LiveKeys {
  if (liveKeys === null) {
    throw new Error(
      `worker: no live keys cached -- log in again to ${action} (this can happen after a page reload)`,
    )
  }
  if (liveKeys.userId !== userId) {
    throw new Error('worker: cached keys belong to a different account than requested')
  }
  return liveKeys
}

function wrappedFromWire(w: { ephemeralPub: string; nonce: string; ciphertext: string }) {
  return {
    ephemeralPub: base64ToBytes(w.ephemeralPub),
    nonce: base64ToBytes(w.nonce),
    ciphertext: base64ToBytes(w.ciphertext),
  }
}

/** #58: mints a rotation's next key for a Rotating-group removal. Same guards as completeInvite. */
async function startGroupRotation(req: StartGroupRotationRequest): Promise<void> {
  const keys = requireLiveKeysFor(req.userId, 'remove a member')
  const result = await startGroupRotationPure(
    keys,
    req.groupId,
    wrappedFromWire(req.ownWrappedGroupKey),
    req.ownGeneration,
    req.subjectUserId,
  )
  post({ kind: 'startGroupRotationDone', id: req.id, result })
}

/** #178: signs the rotation start a leave carries; mints nothing. */
function signLeaveRotationStart(req: SignLeaveRotationStartRequest): void {
  const keys = requireLiveKeysFor(req.userId, 'sign your leaving')
  const result = signLeaveRotationStartPure(keys, req.groupId, req.ownGeneration)
  post({ kind: 'signLeaveRotationStartDone', id: req.id, result })
}

/** #58: re-wraps the caller's current group key to a batch of members. */
async function rewrapGroupKey(req: RewrapGroupKeyRequest): Promise<void> {
  const keys = requireLiveKeysFor(req.userId, 're-wrap members')
  const wraps = await rewrapGroupKeyPure(
    keys,
    req.groupId,
    wrappedFromWire(req.ownWrappedGroupKey),
    req.ownGeneration,
    req.recipients.map((r) => ({
      userId: r.userId,
      x25519PublicKey: base64ToBytes(r.x25519PublicKey),
    })),
  )
  post({ kind: 'rewrapGroupKeyDone', id: req.id, result: { wraps } })
}

function clearLiveKeys(_req: ClearLiveKeysRequest): void {
  liveKeys = null
}

async function completeRecovery(req: CompleteRecoveryRequest): Promise<void> {
  const wrapped = await completeRecoveryPure(req, (p) => {
    post({ kind: 'signupProgress', id: req.id, ...p })
  })
  const result: RecoveryMaterial = wrapped
  post({ kind: 'completeRecoveryDone', id: req.id, result })
}

async function completeChangePassword(req: CompleteChangePasswordRequest): Promise<void> {
  const wrapped = await completeChangePasswordPure(req, (p) => {
    post({ kind: 'signupProgress', id: req.id, ...p })
  })
  const result: ChangePasswordMaterial = wrapped
  post({ kind: 'completeChangePasswordDone', id: req.id, result })
}

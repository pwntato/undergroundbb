// Pure crypto logic behind every worker.ts request kind -- key generation,
// wraps, unwraps, and signatures -- with no dependency on `self`,
// `postMessage`, or any other Web-Worker-only API. Split out from worker.ts
// (PR #129 review) specifically so this logic can be unit-tested directly:
// worker.ts's top-level `self as unknown as DedicatedWorkerGlobalScope`
// throws in a plain Node test environment, so nothing in worker.ts itself
// could ever be imported by a test. worker.ts is now a thin adapter that
// calls these functions and posts their progress events/results across the
// postMessage boundary; this module knows nothing about that boundary.

import { DEFAULT_PARAMS, deriveKey } from './argon2.js'
import { base64ToBytes, bytesToBase64, bytesToBase64Url } from './base64.js'
import { credentialWrapAAD } from './credential.js'
import {
  generateDesignationSortKey,
  generateGrantSortKey,
  genKeyAAD,
  groupNameAAD,
  memberWrapAAD,
  roleGrantPayload,
  successorClaimPayload,
  admissionPayload,
  rotationStartPayload,
  successorDesignationPayload,
  trustAnchorPayload,
} from './group.js'
import { fingerprint } from './fingerprint.js'
import {
  computeInviteMAC,
  deriveInviteMACKey,
  inviteAcceptancePayload,
  inviteCreationPayload,
  verifyInviteMAC,
} from './invite.js'
import { decodeKeyBundle, encodeKeyBundle } from './keybundle.js'
import { pinPayload } from './pin.js'
import {
  deriveRecoveryVerifier,
  deriveRecoveryWrapKey,
  generateRecoveryCode,
} from './recovery-code.js'
import * as ed25519 from './ed25519.js'
import {
  generateWrappingKey,
  unwrap,
  wrap,
  wrappingKeyFromPrivate,
  KEY_LEN as X25519_KEY_LEN,
  type Wrapped,
  type WrappingKey,
} from './x25519.js'
import { decrypt, encrypt, encryptWithNonce, NONCE_SIZE, KEY_SIZE } from './aesgcm.js'
import type {
  DecryptedGroupName,
  DecryptGroupNamesRequest,
  RecoveryMaterial,
  SignupMaterial,
} from './worker-protocol.js'

/** One step of a call's progress, reported via the onProgress callback as it completes. */
export interface ProgressStep {
  readonly step: number
  readonly totalSteps: number
  readonly label: string
}

function randomSalt(): Uint8Array {
  // 16 bytes: comfortably above Argon2id's own recommended minimum, and
  // matches maxSaltLen's own doc comment in register.go describing a real
  // salt as "on the order of 16 bytes."
  return crypto.getRandomValues(new Uint8Array(16))
}

const SIGNUP_ARGON2_PARAMS = {
  memoryKiB: DEFAULT_PARAMS.memoryKiB,
  iterations: DEFAULT_PARAMS.iterations,
  parallelism: DEFAULT_PARAMS.parallelism,
}

/**
 * Wraps bundle (a plaintext signing/wrapping keypair) under a fresh
 * password-derived key and a fresh, independent recovery code/verifier
 * trio, reporting each of its three Argon2id derivations via onProgress as
 * it completes (#33's "honest progress" requirement). Shared by
 * generateSignupMaterial (a brand-new bundle at signup) and completeRecovery
 * (#128 -- the same existing bundle, unwrapped from the redeemed recovery
 * code, re-wrapped under new secrets so the redeemed code cannot be reused
 * -- docs/DESIGN.md, "It also issues a new recovery code").
 *
 * stepOffset/totalSteps let a caller with steps of its own before this one
 * renumber these three correctly -- completeRecovery's upfront unwrap is a
 * real 4th derivation, so it calls this with stepOffset=1, totalSteps=4 to
 * report steps 2/4, 3/4, 4/4 rather than restarting at 1/3.
 */
export async function wrapNewCredentials(
  userId: string,
  password: string,
  bundle: Uint8Array,
  onProgress: (step: ProgressStep) => void,
  stepOffset = 0,
  totalSteps = 3,
): Promise<RecoveryMaterial> {
  // Step 1 of 3 (offset by the caller, if any): the password-derived key.
  const salt = randomSalt()
  const passwordKey = await deriveKey(password, salt, SIGNUP_ARGON2_PARAMS, KEY_SIZE)
  const profileNonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE))
  const profileCiphertext = await encryptWithNonce(
    passwordKey,
    profileNonce,
    bundle,
    credentialWrapAAD(userId, 'PROFILE'),
  )
  onProgress({ step: stepOffset + 1, totalSteps, label: 'Password key ready' })

  // Step 2 of 3: the recovery-code-derived wrapping key. Independent salt
  // and derivation from the password's, per docs/DESIGN.md.
  //
  // deriveRecoveryWrapKey normalizes recoveryCode internally -- see its own
  // doc comment (recovery-code.ts) for why the canonical bare-uppercase
  // form is load-bearing, not the hyphenated display form generateRecoveryCode
  // returns: CheckRecoveryVerifier (internal/crypto/recovery.go) hashes
  // whatever bytes a recovery endpoint receives with no normalization of
  // its own, so this and the verifier derivation below must always agree
  // with whatever the recovery screen derives from the same code.
  const recoveryCode = generateRecoveryCode()
  const recoverySalt = randomSalt()
  const recoveryKey = await deriveRecoveryWrapKey(recoveryCode, recoverySalt, SIGNUP_ARGON2_PARAMS)
  const recoveryNonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE))
  const recoveryCiphertext = await encryptWithNonce(
    recoveryKey,
    recoveryNonce,
    bundle,
    credentialWrapAAD(userId, 'RECOVERY'),
  )
  onProgress({ step: stepOffset + 2, totalSteps, label: 'Recovery key ready' })

  // Step 3 of 3: the recovery verifier -- a third, independent derivation of
  // the same recovery code, per registerRequest's own doc comment
  // (internal/handlers/register.go) and crypto.VerifierLen server-side.
  // deriveRecoveryVerifier normalizes internally, same as
  // deriveRecoveryWrapKey above -- see that call's own comment.
  const verifierSalt = randomSalt()
  const verifier = await deriveRecoveryVerifier(recoveryCode, verifierSalt, SIGNUP_ARGON2_PARAMS)
  onProgress({ step: stepOffset + 3, totalSteps, label: 'Recovery verifier ready' })

  return {
    salt: bytesToBase64(salt),
    argon2Params: SIGNUP_ARGON2_PARAMS,
    wrappedPrivateKeys: {
      nonce: bytesToBase64(profileNonce),
      ciphertext: bytesToBase64(profileCiphertext),
    },

    recoverySalt: bytesToBase64(recoverySalt),
    recoveryArgon2Params: SIGNUP_ARGON2_PARAMS,
    recoveryWrappedPrivateKeys: {
      nonce: bytesToBase64(recoveryNonce),
      ciphertext: bytesToBase64(recoveryCiphertext),
    },

    recoveryVerifierSalt: bytesToBase64(verifierSalt),
    recoveryVerifierParams: SIGNUP_ARGON2_PARAMS,
    recoveryVerifier: bytesToBase64(verifier),

    recoveryCode,
  }
}

/**
 * Generates a fresh signing/wrapping keypair and wraps it under a new
 * password + fresh recovery code/verifier trio -- signup's crypto path.
 * req.userId must be generated by the caller (see uuid.ts) before this
 * runs -- issue #123 made the user uuid client-generated specifically so
 * it exists before signup wraps under it: POST /api/auth/register's
 * UserID field is this same value, sent as-is, not assigned by the
 * server. credentialWrapAAD binds the real uuid from the first wrap, and
 * there is no placeholder and no later re-wrap step.
 */
export async function generateSignupMaterial(
  userId: string,
  password: string,
  onProgress: (step: ProgressStep) => void,
): Promise<SignupMaterial> {
  const signingKey = ed25519.generateSigningKey()
  const wrappingKey = generateWrappingKey()

  const bundle = encodeKeyBundle({
    signingSeed: signingKey.seed,
    wrappingPrivateKey: wrappingKey.privateKey,
  })

  const wrapped = await wrapNewCredentials(userId, password, bundle, onProgress)

  return {
    signingPublicKey: bytesToBase64(signingKey.publicKey),
    wrappingPublicKey: bytesToBase64(wrappingKey.publicKey),
    ...wrapped,
  }
}

/**
 * Unwraps wrappedPrivateKeys with key against copy's AAD, validating the
 * decoded bundle's shape. Returns both the raw encoded bytes (what a
 * caller re-wrapping this bundle wholesale, e.g. completeRecovery, needs to
 * re-encrypt unchanged) and the decoded form (what a caller reading the
 * private scalars out of it, e.g. completeLogin, needs) -- decoding once
 * here rather than once per caller.
 */
async function unwrapAndValidate(
  key: Uint8Array,
  wrappedPrivateKeys: { readonly nonce: string; readonly ciphertext: string },
  userId: string,
  copy: 'PROFILE' | 'RECOVERY',
): Promise<{ bundle: Uint8Array; decoded: ReturnType<typeof decodeKeyBundle> }> {
  const bundle = await decrypt(
    key,
    base64ToBytes(wrappedPrivateKeys.nonce),
    base64ToBytes(wrappedPrivateKeys.ciphertext),
    credentialWrapAAD(userId, copy),
  )

  // A corrupt or truncated bundle should fail loudly now, not (for
  // completeRecovery) silently get re-wrapped wholesale, or (for
  // completeLogin) silently sign with garbage key material.
  const decoded = decodeKeyBundle(bundle)
  if (decoded.wrappingPrivateKey.length !== X25519_KEY_LEN) {
    throw new Error('crypto: decoded key bundle has an invalid wrapping key length')
  }

  return { bundle, decoded }
}

/**
 * The unwrapped signing and wrapping keypairs for one user, live only for
 * as long as this worker instance keeps them cached (worker.ts's own
 * liveKeys) -- never the raw wrappingPrivateKey/signingSeed on their own,
 * always paired with the userId they belong to so a cache read can confirm
 * it is being used for the account that actually produced it. See
 * worker.ts's own doc comment on liveKeys for why this pair never crosses
 * back out of the worker via postMessage.
 */
export interface LiveKeys {
  readonly userId: string
  readonly signingKey: ed25519.SigningKey
  readonly wrappingKey: WrappingKey
}

/**
 * Completes login step 3: unwraps the PROFILE copy with the password, signs
 * the challenge nonce, and returns the same unwrapped keypair as `keys` --
 * added for issue #34, so worker.ts can cache it (liveKeys) for a later
 * signGroupCreation call in the same worker instance, without a second,
 * redundant Argon2id derivation + decrypt of the same blob. The signature
 * itself is computed here, before this function returns, exactly as before
 * this field was added -- worker.ts's own completeLogin handler still posts
 * only `signature` across postMessage, matching every existing caller's
 * contract unchanged.
 */
export async function completeLogin(req: {
  readonly password: string
  readonly salt: string
  readonly argon2Params: { memoryKiB: number; iterations: number; parallelism: number }
  readonly wrappedPrivateKeys: { readonly nonce: string; readonly ciphertext: string }
  readonly userId: string
  readonly nonce: string
}): Promise<{ signature: string; keys: LiveKeys }> {
  const salt = base64ToBytes(req.salt)
  const key = await deriveKey(req.password, salt, req.argon2Params, KEY_SIZE)
  const { decoded } = await unwrapAndValidate(key, req.wrappedPrivateKeys, req.userId, 'PROFILE')

  const signingKey = ed25519.signingKeyFromSeed(decoded.signingSeed)
  const signature = ed25519.sign(
    signingKey,
    ed25519.SigningContext.LoginChallenge,
    base64ToBytes(req.nonce),
  )

  const wrappingKey = wrappingKeyFromPrivate(decoded.wrappingPrivateKey)

  return {
    signature: bytesToBase64(signature),
    keys: { userId: req.userId, signingKey, wrappingKey },
  }
}

/**
 * #34: signs a new group's trust anchor and self-signed root role grant
 * with keys' signing key, and wraps groupKey to keys' own wrapping public
 * key -- the creator's own entry point, stored on their own MEMBER# item
 * (Go's models.Membership.WrappedGroupKey) exactly like every other
 * member's wrapped copy will be, not duplicated onto META (PR #142 review
 * dropped that duplicate -- see db.CreateGroupInput.GenerationKeyWrapped's
 * own doc comment on the Go side for why).
 *
 * keys comes from worker.ts's own liveKeys cache, populated by an earlier
 * completeLogin call in this same worker instance -- this function itself
 * takes no password and does no unwrapping, unlike every function above it
 * in this file, since the keypair is already live by the time a group
 * creation request reaches here.
 *
 * The AAD for wrapping groupKey is memberWrapAAD(groupId, keys.userId, 0) --
 * see docs/DESIGN.md's AAD table, "Member's wrapped group key," and
 * internal/crypto/group.go's MemberWrapAAD (the Go counterpart this must
 * match byte-for-byte). This is deliberately NOT the same AAD a GENKEY#
 * chain link would use: a member's own wrapped entry point is
 * member-specific (it binds the member uuid), while a chain link is
 * member-independent.
 */
export async function signGroupCreation(
  keys: LiveKeys,
  groupId: string,
  groupKey: Uint8Array,
): Promise<{
  trustAnchorSignature: string
  rootGrantSortKey: string
  rootGrantSignature: string
  groupKeyWrapped: { ephemeralPub: string; nonce: string; ciphertext: string }
}> {
  const anchorPayload = trustAnchorPayload(keys.userId, keys.signingKey.publicKey, groupId)
  const trustAnchorSignature = ed25519.sign(
    keys.signingKey,
    ed25519.SigningContext.TrustAnchor,
    anchorPayload,
  )

  // The root grant has no predecessor to reference -- grantorGrantRef is ""
  // -- see internal/crypto/group.go's RoleGrantPayload and
  // models.RoleGrant's own doc comment on the Go side for why the root
  // grant's shape is exactly this. rootGrantSortKey is generated here,
  // client-side, and signed as part of the payload (see roleGrantPayload's
  // own doc comment for why the grant's own address must be signed) --
  // it is sent to the server alongside the signature so createGroup can
  // write the grant under the exact address that was signed for, rather
  // than picking one after the fact.
  const rootGrantSortKey = generateGrantSortKey(keys.userId)
  const grantPayload = roleGrantPayload(groupId, keys.userId, 'admin', rootGrantSortKey, '')
  const rootGrantSignature = ed25519.sign(
    keys.signingKey,
    ed25519.SigningContext.RoleGrant,
    grantPayload,
  )

  const wrapAAD = memberWrapAAD(groupId, keys.userId, 0)
  const wrapped = await wrap(keys.wrappingKey.publicKey, groupKey, wrapAAD)

  return {
    trustAnchorSignature: bytesToBase64(trustAnchorSignature),
    rootGrantSortKey,
    rootGrantSignature: bytesToBase64(rootGrantSignature),
    groupKeyWrapped: {
      ephemeralPub: bytesToBase64(wrapped.ephemeralPub),
      nonce: bytesToBase64(wrapped.nonce),
      ciphertext: bytesToBase64(wrapped.ciphertext),
    },
  }
}

/**
 * #37: signs a role grant for another member -- the grantor's own Ed25519
 * signature over crypto.RoleGrantPayload (Go)/roleGrantPayload (TS), the
 * same payload and context signGroupCreation uses for the root grant, with
 * the grantor's own CURRENT grant (grantorGrantRef) as its predecessor so
 * the chain of trust can be walked back to the root. grantSortKey is
 * generated here, for the subject, and signed as part of the payload for the
 * reason roleGrantPayload's doc comment gives; the caller sends it back
 * unchanged. A retry after a 'grant_key_taken' conflict must call this again
 * for a fresh key rather than resend.
 */
export function signRoleGrant(
  keys: LiveKeys,
  groupId: string,
  subjectUserId: string,
  role: string,
  grantorGrantRef: string,
): { grantSortKey: string; signature: string } {
  const grantSortKey = generateGrantSortKey(subjectUserId)
  const payload = roleGrantPayload(groupId, subjectUserId, role, grantSortKey, grantorGrantRef)
  const signature = ed25519.sign(keys.signingKey, ed25519.SigningContext.RoleGrant, payload)
  return { grantSortKey, signature: bytesToBase64(signature) }
}

/**
 * #161: signs a successor designation -- the admin's own Ed25519 signature over
 * successorDesignationPayload under SigningContext.SuccessorDesignation. An
 * empty successorUserId is the revocation form. adminGrantRef is the admin's
 * own CURRENT grant (GroupDetail.myGrantSortKey). The row's sort key is
 * generated here, because the payload signs it; a retry after a
 * 'designation_key_taken' conflict must call this again for a fresh one.
 */
export function signSuccessorDesignation(
  keys: LiveKeys,
  groupId: string,
  successorUserId: string,
  periodDays: number,
  adminGrantRef: string,
): { designationSortKey: string; signature: string } {
  const designationSortKey = generateDesignationSortKey(keys.userId)
  const payload = successorDesignationPayload(
    groupId,
    keys.userId,
    successorUserId,
    periodDays,
    designationSortKey,
    adminGrantRef,
  )
  const signature = ed25519.sign(
    keys.signingKey,
    ed25519.SigningContext.SuccessorDesignation,
    payload,
  )
  return { designationSortKey, signature: bytesToBase64(signature) }
}

/**
 * #161: signs a designated successor's claim -- the successor's own signature
 * over successorClaimPayload under SigningContext.SuccessorClaim. The claim
 * row's sort key (a GRANT# key for the successor, dated today UTC) is
 * generated here because the payload signs it, which is also what fixes the
 * claim day; the caller re-checks eligibility against that day before sending.
 */
export function signSuccessorClaim(
  keys: LiveKeys,
  groupId: string,
  designationSortKey: string,
): { claimSortKey: string; signature: string } {
  const claimSortKey = generateGrantSortKey(keys.userId)
  const payload = successorClaimPayload(groupId, keys.userId, designationSortKey, claimSortKey)
  const signature = ed25519.sign(keys.signingKey, ed25519.SigningContext.SuccessorClaim, payload)
  return { claimSortKey, signature: bytesToBase64(signature) }
}

/**
 * #63: signs a pin of another user's key set under the caller's own current
 * signing key. signingPublicKeys is a set (pinPayload sorts it). The result
 * carries the signing key used, which is what the server checks against the
 * caller's profile and what evaluatePin later requires to be the caller's
 * current key.
 */
export function signPin(
  keys: LiveKeys,
  pinnedUserId: string,
  signingPublicKeys: readonly Uint8Array[],
  wrappingPublicKey: Uint8Array,
): { pinnerSigningPublicKey: string; signature: string } {
  const payload = pinPayload(
    keys.userId,
    pinnedUserId,
    keys.signingKey.publicKey,
    wrappingPublicKey,
    signingPublicKeys,
  )
  const signature = ed25519.sign(keys.signingKey, ed25519.SigningContext.Pin, payload)
  return {
    pinnerSigningPublicKey: bytesToBase64(keys.signingKey.publicKey),
    signature: bytesToBase64(signature),
  }
}

/**
 * #38: signs step 1 of the invite handshake -- the inviter's own
 * Ed25519 signature over crypto.InviteCreationPayload (Go)/
 * inviteCreationPayload (TS), binding the invite id, group id, the
 * inviter's own current signing public key, and the signed expiry. See
 * docs/DESIGN.md, "Invites -- the signed handshake," step 1.
 *
 * keys comes from worker.ts's own liveKeys cache, exactly like
 * signGroupCreation -- this function itself never sees a password. inviteId
 * is generated by the CALLER (runCreateInvite.ts, via idgen-shaped
 * crypto.getRandomValues, matching generateGrantSortKey's own "client
 * decides, server validates the shape" split for GroupID/RootGrantSortKey
 * before it), since the signed payload binds it and the client must
 * therefore choose it before ever signing.
 *
 * Also returns the inviter's own fingerprint (fingerprint.ts, over keys'
 * two current public keys) -- issue #38: "the generated link carries the
 * inviter's key fingerprint in the URL fragment, which browsers never send
 * to a server," and "show the invitee's fingerprint at this moment, while
 * the user is paying attention" applies symmetrically to the INVITER at
 * the moment they create the link, per docs/DESIGN.md's own "Verification
 * stays available rather than mandatory" section. Computed here rather
 * than as a separate worker call because keys is already live in this
 * exact call.
 *
 * Also derives and returns inviteMACKey (invite.ts's deriveInviteMACKey,
 * over keys.signingKey.seed and inviteId) -- the per-invite secret that
 * closes the gap plain signature verification leaves open: see
 * deriveInviteMACKey's own doc comment for why a malicious server can
 * otherwise mint its own keypair and pass step 3's check without a real
 * invitee. Nothing about this value is ever sent to any server; the
 * caller's job (CreateInviteScreen.tsx) is to embed it in the link's URL
 * fragment, alongside inviterFingerprint, where only the link's actual
 * holder can read it.
 */
export async function signInviteCreation(
  keys: LiveKeys,
  inviteId: string,
  groupId: string,
  expiresAt: string,
): Promise<{ creationSignature: string; inviterFingerprint: string; inviteMACKey: string }> {
  const payload = inviteCreationPayload(inviteId, groupId, keys.signingKey.publicKey, expiresAt)
  const signature = ed25519.sign(keys.signingKey, ed25519.SigningContext.Invite, payload)
  const inviterFingerprint = fingerprint(keys.signingKey.publicKey, keys.wrappingKey.publicKey)
  const macKey = deriveInviteMACKey(keys.signingKey.seed, inviteId)
  return {
    creationSignature: bytesToBase64(signature),
    inviterFingerprint,
    inviteMACKey: bytesToBase64Url(macKey),
  }
}

/**
 * #39: signs step 2 of the invite handshake -- the invitee's own Ed25519
 * signature over crypto.InviteAcceptancePayload (Go)/inviteAcceptancePayload
 * (TS), binding the invite id and the invitee's own current Ed25519/X25519
 * public keys. See docs/DESIGN.md, "Invites -- the signed handshake," step
 * 2: "Verifies the inviter's signature, then signs {invite_id, ed25519_pub,
 * x25519_pub} with their own key."
 *
 * Verifying the inviter's own creation signature (the first half of step 2)
 * is deliberately NOT this function's job -- it needs only the inviter's
 * signing public key and the step-1 payload, neither of which requires
 * liveKeys or any private material, so it lives as a plain, easily-tested
 * function the caller (runAcceptInvite.ts) invokes directly rather than a
 * worker round trip for no reason. This function is only the half that
 * genuinely needs a live private key.
 *
 * Also computes inviteMAC (invite.ts's computeInviteMAC) over the exact
 * same payload the signature covers, keyed by inviteMACKey -- the invite
 * link's URL fragment, decoded by the caller before this call, never sent
 * to any server. This is what step 3 (the inviter's own client) checks
 * before ever trusting the keys this function signs, closing the gap a
 * malicious server could otherwise exploit -- see deriveInviteMACKey's own
 * doc comment. inviteMACKey is required, not optional: an invite link
 * shared without its fragment (an older format, or a copy that dropped it)
 * cannot be completed with this real proof of possession, and this
 * function has no fallback that silently skips it.
 */
export async function signInviteAcceptance(
  keys: LiveKeys,
  inviteId: string,
  inviteMACKey: Uint8Array,
): Promise<{ acceptanceSignature: string; inviteMAC: string }> {
  const payload = inviteAcceptancePayload(
    inviteId,
    keys.signingKey.publicKey,
    keys.wrappingKey.publicKey,
  )
  const signature = ed25519.sign(keys.signingKey, ed25519.SigningContext.Invite, payload)
  const mac = computeInviteMAC(inviteMACKey, payload)
  return { acceptanceSignature: bytesToBase64(signature), inviteMAC: bytesToBase64(mac) }
}

/**
 * #40: completes step 3 of the invite handshake -- unwraps the inviter's
 * OWN copy of the group key (memberWrapAAD(groupId, keys.userId,
 * ownGeneration), the same AAD signGroupCreation/decryptGroupNames already
 * use for this member's own entry point) and re-wraps it to the invitee's
 * signed X25519 public key under memberWrapAAD(groupId, invitedUserId,
 * ownGeneration) -- the invitee's own future entry point, exactly the shape
 * their MEMBER# item will carry. See docs/DESIGN.md: "wraps the group key
 * to the X25519 key that was signed in step 2 -- never to a key the server
 * offers unilaterally."
 *
 * The AAD's generation is the INVITER's own current generation
 * (ownWrappedGroupKey's), not necessarily 0 -- correct today because no key
 * rotation (#78) exists yet, so every member's generation is always 0 and
 * this parameter is trivially fixed; kept as a real parameter (matching
 * decryptGroupNames' own reasoning) so completing against a rotated group
 * needs no signature change later. This function does NOT itself verify
 * AcceptanceSignature -- see worker.ts's own completeInvite handler for why
 * that verification happens in the caller, using data this function never
 * receives (the invitee's own signed Ed25519 public key, checked against
 * AcceptanceSignature, is a separate value from invitedX25519PublicKey,
 * which THIS function uses only to wrap to, never to verify anything).
 */
/**
 * Thrown by completeInvite when inviteMAC does not verify against the
 * invite's own MAC key -- see completeInvite's own doc comment for what
 * this actually catches: a malicious server presenting keys/a signature
 * it minted itself, rather than a real invitee's. Distinguished from a
 * plain Error so callers (runCompleteInvites.ts) can report it as its own
 * outcome rather than a generic crypto failure.
 */
export class InviteMACError extends Error {
  constructor() {
    super('crypto: invite MAC does not verify -- this response may not be from the real invitee')
    this.name = 'InviteMACError'
  }
}

export async function completeInvite(
  keys: LiveKeys,
  inviteId: string,
  groupId: string,
  ownWrappedGroupKey: Wrapped,
  ownGeneration: number,
  invitedUserId: string,
  invitedEd25519PublicKey: Uint8Array,
  invitedX25519PublicKey: Uint8Array,
  inviteMAC: Uint8Array,
  inviterGrantRef: string,
  day: string,
): Promise<{
  wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
  generation: number
  admission: { inviterGrantRef: string; day: string; signature: string }
}> {
  // The real fix for the gap plain Ed25519 verification leaves open (see
  // deriveInviteMACKey's own doc comment): invitedEd25519PublicKey,
  // invitedX25519PublicKey and the acceptance signature all arrive in the
  // same server response, which a malicious server fully controls -- it
  // can mint its own keypair, self-sign, and pass runCompleteInvites.ts's
  // own signature check with no real invitee involved at all. inviteMAC
  // is the one value that check cannot forge: it is MAC_k(payload) under
  // k, a secret this inviter derives fresh from their OWN long-term seed
  // (never stored, never sent to any server) and the invite link's
  // fragment carried to whoever actually held the real link. Re-deriving
  // k and checking the MAC here -- inside the one place that already
  // holds keys.signingKey.seed -- is what actually binds this completion
  // to the real invitee, rather than to whatever the server chose to
  // serve.
  const macKey = deriveInviteMACKey(keys.signingKey.seed, inviteId)
  const payload = inviteAcceptancePayload(inviteId, invitedEd25519PublicKey, invitedX25519PublicKey)
  if (!verifyInviteMAC(macKey, payload, inviteMAC)) {
    throw new InviteMACError()
  }

  const ownUnwrapAAD = memberWrapAAD(groupId, keys.userId, ownGeneration)
  const groupKey = await unwrap(keys.wrappingKey.privateKey, ownWrappedGroupKey, ownUnwrapAAD)

  const wrapAAD = memberWrapAAD(groupId, invitedUserId, ownGeneration)
  const wrapped = await wrap(invitedX25519PublicKey, groupKey, wrapAAD)

  // The durable record that this inviter admitted this invitee (#178). The
  // invite rows are deleted at completion and a plain member has no grant, so
  // this is the only signed statement of who is a member; a rotating admin
  // checks it before wrapping a new group key to anyone. Signed only after the
  // MAC above has bound these keys to the real invitee.
  const admissionSignature = ed25519.sign(
    keys.signingKey,
    ed25519.SigningContext.Admission,
    admissionPayload(
      groupId,
      keys.userId,
      invitedUserId,
      invitedEd25519PublicKey,
      invitedX25519PublicKey,
      inviteId,
      inviterGrantRef,
      day,
    ),
  )

  return {
    wrappedGroupKey: {
      ephemeralPub: bytesToBase64(wrapped.ephemeralPub),
      nonce: bytesToBase64(wrapped.nonce),
      ciphertext: bytesToBase64(wrapped.ciphertext),
    },
    generation: ownGeneration,
    admission: { inviterGrantRef, day, signature: bytesToBase64(admissionSignature) },
  }
}

/** A Wrapped, base64-encoded for the wire (and for postMessage). */
export interface WireWrapped {
  ephemeralPub: string
  nonce: string
  ciphertext: string
}

function toWireWrapped(w: Wrapped): WireWrapped {
  return {
    ephemeralPub: bytesToBase64(w.ephemeralPub),
    nonce: bytesToBase64(w.nonce),
    ciphertext: bytesToBase64(w.ciphertext),
  }
}

async function unwrapOwnGroupKey(
  keys: LiveKeys,
  groupId: string,
  ownWrappedGroupKey: Wrapped,
  ownGeneration: number,
): Promise<Uint8Array> {
  const groupKey = await unwrap(
    keys.wrappingKey.privateKey,
    ownWrappedGroupKey,
    memberWrapAAD(groupId, keys.userId, ownGeneration),
  )
  if (groupKey.length !== KEY_SIZE) {
    throw new Error('crypto: unwrapped group key has the wrong length')
  }
  return groupKey
}

/**
 * #58: mints the next generation's group key for a Rotating-group removal and
 * returns what DELETE /api/groups/{gid}/members/{uid}'s `rotation` body
 * carries: the new generation (ownGeneration + 1, which the server requires),
 * the GENKEY# chain link, and the new key wrapped for the caller.
 *
 * The link is the OLD key encrypted under the NEW one with genKeyAAD(gid,
 * ownGeneration), so a holder of the new key walks backward and a holder of
 * only the old key learns nothing about the new one. The caller wraps the new
 * key to THEMSELVES: that wrap is the only durable copy of the minted key
 * anywhere, and every later step (re-wrapping members, resuming after a closed
 * tab) re-derives it from the caller's own MEMBER# entry rather than keeping it
 * in memory. The new key never leaves this module in the clear. Also signs
 * the rotation start naming `subjectUserId`, the member being removed.
 */
export async function startGroupRotation(
  keys: LiveKeys,
  groupId: string,
  ownWrappedGroupKey: Wrapped,
  ownGeneration: number,
  subjectUserId: string,
): Promise<{
  generation: number
  link: { nonce: string; ciphertext: string }
  removerWrappedKey: WireWrapped
  startSignature: string
}> {
  const oldKey = await unwrapOwnGroupKey(keys, groupId, ownWrappedGroupKey, ownGeneration)
  const newKey = crypto.getRandomValues(new Uint8Array(KEY_SIZE))
  const generation = ownGeneration + 1

  const link = await encrypt(newKey, oldKey, genKeyAAD(groupId, ownGeneration))
  const removerWrapped = await wrap(
    keys.wrappingKey.publicKey,
    newKey,
    memberWrapAAD(groupId, keys.userId, generation),
  )
  // The signature names whom this rotation removes (#178), so an admin who
  // resumes it later excludes them without trusting the server's member list.
  const startSignature = ed25519.sign(
    keys.signingKey,
    ed25519.SigningContext.RotationStart,
    rotationStartPayload(groupId, keys.userId, subjectUserId, generation),
  )
  return {
    generation,
    link: { nonce: bytesToBase64(link.nonce), ciphertext: bytesToBase64(link.ciphertext) },
    removerWrappedKey: toWireWrapped(removerWrapped),
    startSignature: bytesToBase64(startSignature),
  }
}

/**
 * #58: re-wraps the caller's CURRENT group key (their own entry at
 * ownGeneration, which during a rotation is the new generation) to each
 * recipient, for PUT /api/groups/{gid}/rotation/members. The AAD names the
 * recipient and ownGeneration, matching what that recipient's MEMBER# item
 * will be read with.
 *
 * recipients' public keys arrive from the caller, which has ALREADY checked
 * each against the caller's signed pins; this function cannot (it has no pins)
 * and wrapping to a server-substituted key would hand the server the group key.
 * It refuses the caller's own id (their entry is already current and the
 * server rejects it) and a key that is not 32 bytes.
 */
export async function rewrapGroupKey(
  keys: LiveKeys,
  groupId: string,
  ownWrappedGroupKey: Wrapped,
  ownGeneration: number,
  recipients: readonly { userId: string; x25519PublicKey: Uint8Array }[],
): Promise<{ userId: string; wrappedKey: WireWrapped }[]> {
  const groupKey = await unwrapOwnGroupKey(keys, groupId, ownWrappedGroupKey, ownGeneration)
  const out: { userId: string; wrappedKey: WireWrapped }[] = []
  for (const r of recipients) {
    if (r.userId === keys.userId) {
      throw new Error('crypto: refusing to re-wrap the group key to the caller')
    }
    if (r.x25519PublicKey.length !== X25519_KEY_LEN) {
      throw new Error('crypto: recipient X25519 public key must be 32 bytes')
    }
    const wrapped = await wrap(
      r.x25519PublicKey,
      groupKey,
      memberWrapAAD(groupId, r.userId, ownGeneration),
    )
    out.push({ userId: r.userId, wrappedKey: toWireWrapped(wrapped) })
  }
  return out
}

/**
 * #35: decrypts a batch of private groups' names and descriptions for the
 * group list, using keys' wrapping key -- the read-path counterpart of
 * signGroupCreation's wrap. For each group: unwrap the member's own
 * WrappedGroupKey (memberWrapAAD(groupId, keys.userId, generation), the
 * same AAD signGroupCreation wrapped under) to recover the group key, then
 * decrypt nameCiphertext/descriptionCiphertext under
 * groupNameAAD(groupId, 'NAME'|'DESC', generation).
 *
 * Two generations are involved and must not be conflated: `generation` is
 * the member's own (what their WrappedGroupKey is wrapped for, used to
 * unwrap), `nameGeneration` is the one the name/description ciphertext was
 * encrypted under (used for the AAD). Rotation does not re-encrypt the name,
 * so after one they diverge: the member's key is for the newer generation and
 * the name needs the older one's. The caller supplies the GENKEY# links
 * between the two (`chain`) and walkChainDown follows them back.
 *
 * One group's failure (a stale cache entry, corrupt ciphertext, a
 * generation mismatch) does not throw and does not fail the batch -- see
 * DecryptGroupNamesResponse's own doc comment on the protocol side for why
 * a partial result beats blanking the whole list. Only name/description
 * are best-effort per group; a request-level problem (liveKeys cold or
 * wrong account) is still the caller's job to check before calling this,
 * same as signGroupCreation.
 */
export async function decryptGroupNames(
  keys: LiveKeys,
  groups: DecryptGroupNamesRequest['groups'],
): Promise<DecryptedGroupName[]> {
  const results: DecryptedGroupName[] = []
  for (const group of groups) {
    results.push(await decryptOneGroupName(keys, group))
  }
  return results
}

async function decryptOneGroupName(
  keys: LiveKeys,
  group: DecryptGroupNamesRequest['groups'][number],
): Promise<DecryptedGroupName> {
  try {
    const wrappedGroupKey: Wrapped = {
      ephemeralPub: base64ToBytes(group.wrappedGroupKey.ephemeralPub),
      nonce: base64ToBytes(group.wrappedGroupKey.nonce),
      ciphertext: base64ToBytes(group.wrappedGroupKey.ciphertext),
    }
    const unwrapAAD = memberWrapAAD(group.groupId, keys.userId, group.generation)
    const ownKey = await unwrap(keys.wrappingKey.privateKey, wrappedGroupKey, unwrapAAD)
    // The key for the generation the name was sealed under, which is older
    // than the member's own once the group has rotated since.
    const groupKey = await walkChainDown(
      ownKey,
      group.groupId,
      group.generation,
      group.nameGeneration,
      group.chain ?? [],
    )

    // The name/description AAD binds nameGeneration -- the generation they
    // were encrypted under -- NOT the member's own generation used to
    // unwrap above. Rotation does not re-encrypt the name (DESIGN.md), so
    // once rotation exists the two diverge.
    const name = await decryptGroupText(
      groupKey,
      group.groupId,
      'NAME',
      group.nameGeneration,
      group.nameCiphertext,
    )
    const description = await decryptGroupText(
      groupKey,
      group.groupId,
      'DESC',
      group.nameGeneration,
      group.descriptionCiphertext,
    )
    return { groupId: group.groupId, name, description }
  } catch {
    // Deliberately swallowed -- see this function's own doc comment (on
    // decryptGroupNames) for why one group's decrypt failure surfaces as
    // null fields here rather than rejecting the whole batch.
    return { groupId: group.groupId, name: null, description: null }
  }
}

/**
 * Walks the GENKEY# chain from the key at `fromGeneration` back to the key at
 * `toGeneration`. Link n is generation n's key sealed under generation n+1's
 * with genKeyAAD(groupId, n) (startGroupRotation writes it), so each step
 * opens one link with the key just recovered. Throws if a link is missing or
 * does not open, which decryptOneGroupName reports as an unreadable name; a
 * name from a generation NEWER than the member's own is likewise unreadable,
 * since there is no way forward along the chain.
 */
async function walkChainDown(
  startKey: Uint8Array,
  groupId: string,
  fromGeneration: number,
  toGeneration: number,
  chain: readonly { generation: number; wrapped: { nonce: string; ciphertext: string } }[],
): Promise<Uint8Array> {
  if (toGeneration > fromGeneration) {
    throw new Error('crypto: the name is from a newer generation than the member holds')
  }
  const links = new Map(chain.map((l) => [l.generation, l.wrapped]))
  let key = startKey
  for (let generation = fromGeneration - 1; generation >= toGeneration; generation--) {
    const link = links.get(generation)
    if (link === undefined) {
      throw new Error(`crypto: no chain link for generation ${String(generation)}`)
    }
    key = await decrypt(
      key,
      base64ToBytes(link.nonce),
      base64ToBytes(link.ciphertext),
      genKeyAAD(groupId, generation),
    )
    if (key.length !== KEY_SIZE) {
      throw new Error('crypto: chain link opened to a key of the wrong length')
    }
  }
  return key
}

async function decryptGroupText(
  groupKey: Uint8Array,
  groupId: string,
  field: 'NAME' | 'DESC',
  generation: number,
  ciphertext: { readonly nonce: string; readonly ciphertext: string },
): Promise<string> {
  const aad = groupNameAAD(groupId, field, generation)
  const plaintext = await decrypt(
    groupKey,
    base64ToBytes(ciphertext.nonce),
    base64ToBytes(ciphertext.ciphertext),
    aad,
  )
  return new TextDecoder().decode(plaintext)
}

/**
 * #128: redeems a recovery code. Unwraps RecoveryWrappedPrivateKeys (from
 * POST /api/account/recovery-code/release) with the recovery-code-derived
 * key -- the mirror of completeLogin's unwrap, but keyed by
 * deriveRecoveryWrapKey(recoveryCode, ...) instead of the password, and
 * against the RECOVERY copy's AAD rather than PROFILE's. Recovery re-wraps
 * the same signing/wrapping keypair signup generated under new secrets; it
 * does not rotate the keypair itself (that is #62, key rotation, a separate
 * feature) -- so unlike generateSignupMaterial, no new keypair is generated
 * here, only re-wrapped via the shared wrapNewCredentials.
 *
 * This unwrap is a real 4th Argon2id derivation on top of
 * wrapNewCredentials's own three, so it reports its own progress step (1 of
 * 4) once it completes, rather than leaving the caller's UI showing no
 * progress during real work -- flagged in PR #129 review.
 */
export async function completeRecovery(
  req: {
    readonly recoveryCode: string
    readonly recoverySalt: string
    readonly recoveryArgon2Params: { memoryKiB: number; iterations: number; parallelism: number }
    readonly recoveryWrappedPrivateKeys: { readonly nonce: string; readonly ciphertext: string }
    readonly userId: string
    readonly newPassword: string
  },
  onProgress: (step: ProgressStep) => void,
): Promise<RecoveryMaterial> {
  const TOTAL_STEPS = 4

  const recoverySalt = base64ToBytes(req.recoverySalt)
  const recoveryKey = await deriveRecoveryWrapKey(
    req.recoveryCode,
    recoverySalt,
    req.recoveryArgon2Params,
  )
  const { bundle } = await unwrapAndValidate(
    recoveryKey,
    req.recoveryWrappedPrivateKeys,
    req.userId,
    'RECOVERY',
  )

  onProgress({ step: 1, totalSteps: TOTAL_STEPS, label: 'Recovery code confirmed' })

  return wrapNewCredentials(req.userId, req.newPassword, bundle, onProgress, 1, TOTAL_STEPS)
}

/**
 * #131: changes a logged-in user's password (and, as a side effect, issues
 * a fresh recovery code -- docs/DESIGN.md, "It does, however, issue a new
 * recovery code and re-wrap the recovery copy under it, invalidating the
 * old," same as completeRecovery). Unwraps the PROFILE copy with the OLD
 * password -- GET /api/account/credentials' current
 * Salt/Argon2Params/WrappedPrivateKeys, the mirror of completeLogin's own
 * unwrap but against the caller's already-known userId rather than one
 * handed back by a challenge -- then re-wraps the same bundle under the NEW
 * password via the shared wrapNewCredentials, exactly as completeRecovery's
 * tail does after its own recovery-code unwrap.
 *
 * A wrong old password fails inside this unwrap as a DecryptionFailedError,
 * the same signal completeLogin gives -- there is no separate server-side
 * check of the old password (password.go's changePassword's own doc
 * comment: "there is deliberately no server-side check of the old
 * password"), so this unwrap succeeding is the only proof of it.
 *
 * Like completeRecovery's own upfront unwrap, this old-password unwrap is a
 * real Argon2id derivation in its own right, not free -- so it gets its own
 * progress step (1 of 4) before handing off to wrapNewCredentials's own 3,
 * the same TOTAL_STEPS=4/stepOffset=1 shape completeRecovery uses. PR #132
 * review caught an earlier draft that reported only wrapNewCredentials's 3
 * steps, leaving this unwrap uncounted and silently changing
 * SignupProgressStep's total mid-flow -- exactly the PR #129 regression its
 * own doc comment warns against.
 */
export async function completeChangePassword(
  req: {
    readonly oldPassword: string
    readonly salt: string
    readonly argon2Params: { memoryKiB: number; iterations: number; parallelism: number }
    readonly wrappedPrivateKeys: { readonly nonce: string; readonly ciphertext: string }
    readonly userId: string
    readonly newPassword: string
  },
  onProgress: (step: ProgressStep) => void,
): Promise<RecoveryMaterial> {
  const TOTAL_STEPS = 4

  const salt = base64ToBytes(req.salt)
  const oldKey = await deriveKey(req.oldPassword, salt, req.argon2Params, KEY_SIZE)
  const { bundle } = await unwrapAndValidate(oldKey, req.wrappedPrivateKeys, req.userId, 'PROFILE')

  onProgress({ step: 1, totalSteps: TOTAL_STEPS, label: 'Current password confirmed' })

  return wrapNewCredentials(req.userId, req.newPassword, bundle, onProgress, 1, TOTAL_STEPS)
}

/**
 * #36: encrypts a private group's edited name and description for
 * PUT /api/groups/{id}. Unwraps the caller's own WrappedGroupKey exactly as
 * decryptOneGroupName does, then seals both fields under
 * groupNameAAD(groupId, 'NAME'|'DESC', nameGeneration) with fresh nonces.
 * Unlike decryptGroupNames this THROWS on failure: there is no useful
 * partial result for a write, and the caller must not send half a pair.
 *
 * The server requires nameGeneration to equal the caller's own generation
 * (handlers.updateGroup), so the caller passes the member's current
 * generation for both; they are separate parameters only because they are
 * separate concepts.
 */
export async function encryptGroupText(
  keys: LiveKeys,
  req: {
    readonly groupId: string
    readonly generation: number
    readonly nameGeneration: number
    readonly wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
    readonly name: string
    readonly description: string
  },
): Promise<{
  nameCiphertext: { nonce: string; ciphertext: string }
  descriptionCiphertext: { nonce: string; ciphertext: string }
}> {
  const wrapped: Wrapped = {
    ephemeralPub: base64ToBytes(req.wrappedGroupKey.ephemeralPub),
    nonce: base64ToBytes(req.wrappedGroupKey.nonce),
    ciphertext: base64ToBytes(req.wrappedGroupKey.ciphertext),
  }
  const groupKey = await unwrap(
    keys.wrappingKey.privateKey,
    wrapped,
    memberWrapAAD(req.groupId, keys.userId, req.generation),
  )
  const encoder = new TextEncoder()
  const seal = async (field: 'NAME' | 'DESC', text: string) => {
    const sealed = await encrypt(
      groupKey,
      encoder.encode(text),
      groupNameAAD(req.groupId, field, req.nameGeneration),
    )
    return { nonce: bytesToBase64(sealed.nonce), ciphertext: bytesToBase64(sealed.ciphertext) }
  }
  return {
    nameCiphertext: await seal('NAME', req.name),
    descriptionCiphertext: await seal('DESC', req.description),
  }
}

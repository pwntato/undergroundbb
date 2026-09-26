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
import { base64ToBytes, bytesToBase64 } from './base64.js'
import { credentialWrapAAD } from './credential.js'
import {
  generateGrantSortKey,
  memberWrapAAD,
  roleGrantPayload,
  trustAnchorPayload,
} from './group.js'
import { decodeKeyBundle, encodeKeyBundle } from './keybundle.js'
import {
  deriveRecoveryVerifier,
  deriveRecoveryWrapKey,
  generateRecoveryCode,
} from './recovery-code.js'
import * as ed25519 from './ed25519.js'
import {
  generateWrappingKey,
  wrap,
  wrappingKeyFromPrivate,
  KEY_LEN as X25519_KEY_LEN,
  type WrappingKey,
} from './x25519.js'
import { decrypt, encryptWithNonce, NONCE_SIZE, KEY_SIZE } from './aesgcm.js'
import type { RecoveryMaterial, SignupMaterial } from './worker-protocol.js'

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

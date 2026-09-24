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
import { decodeKeyBundle, encodeKeyBundle } from './keybundle.js'
import {
  deriveRecoveryVerifier,
  deriveRecoveryWrapKey,
  generateRecoveryCode,
} from './recovery-code.js'
import * as ed25519 from './ed25519.js'
import { generateWrappingKey, KEY_LEN as X25519_KEY_LEN } from './x25519.js'
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

/** Completes login step 3: unwraps the PROFILE copy with the password, signs the challenge nonce. */
export async function completeLogin(req: {
  readonly password: string
  readonly salt: string
  readonly argon2Params: { memoryKiB: number; iterations: number; parallelism: number }
  readonly wrappedPrivateKeys: { readonly nonce: string; readonly ciphertext: string }
  readonly userId: string
  readonly nonce: string
}): Promise<string> {
  const salt = base64ToBytes(req.salt)
  const key = await deriveKey(req.password, salt, req.argon2Params, KEY_SIZE)
  const { decoded } = await unwrapAndValidate(key, req.wrappedPrivateKeys, req.userId, 'PROFILE')

  const signingKey = ed25519.signingKeyFromSeed(decoded.signingSeed)
  const signature = ed25519.sign(
    signingKey,
    ed25519.SigningContext.LoginChallenge,
    base64ToBytes(req.nonce),
  )

  return bytesToBase64(signature)
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

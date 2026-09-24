// The crypto worker: every Argon2id derivation, keypair generation, wrap and
// signature this app performs runs here, off the main thread, per
// docs/DESIGN.md's "Frontend" section ("Argon2id runs in WebAssembly, and
// all crypto runs in a Web Worker so decrypting a page of posts does not
// block the UI"). The password itself is only ever posted into this worker
// and never returns from it -- only public material, wire-ready wrapped
// blobs, and a signature cross back.

/// <reference lib="webworker" />

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
import type {
  CompleteLoginRequest,
  CompleteRecoveryRequest,
  GenerateSignupMaterialRequest,
  RecoveryMaterial,
  SignupMaterial,
  WorkerRequest,
  WorkerResponse,
} from './worker-protocol.js'

const ctx = self as unknown as DedicatedWorkerGlobalScope

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
  }
}

function post(msg: WorkerResponse): void {
  ctx.postMessage(msg)
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
 * trio, reporting each of the three Argon2id derivations via signupProgress
 * as it completes (#33's "honest progress" requirement). Shared by
 * generateSignupMaterial (a brand-new bundle at signup) and completeRecovery
 * (#128 -- the same existing bundle, unwrapped from the redeemed recovery
 * code, re-wrapped under new secrets so the redeemed code cannot be reused
 * -- docs/DESIGN.md, "It also issues a new recovery code").
 */
async function wrapNewCredentials(
  id: string,
  userId: string,
  password: string,
  bundle: Uint8Array,
): Promise<Omit<SignupMaterial, 'signingPublicKey' | 'wrappingPublicKey'>> {
  // Step 1 of 3: the password-derived key.
  const salt = randomSalt()
  const passwordKey = await deriveKey(password, salt, SIGNUP_ARGON2_PARAMS, KEY_SIZE)
  const profileNonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE))
  const profileCiphertext = await encryptWithNonce(
    passwordKey,
    profileNonce,
    bundle,
    credentialWrapAAD(userId, 'PROFILE'),
  )
  post({ kind: 'signupProgress', id, step: 1, totalSteps: 3, label: 'Password key ready' })

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
  post({ kind: 'signupProgress', id, step: 2, totalSteps: 3, label: 'Recovery key ready' })

  // Step 3 of 3: the recovery verifier -- a third, independent derivation of
  // the same recovery code, per registerRequest's own doc comment
  // (internal/handlers/register.go) and crypto.VerifierLen server-side.
  // deriveRecoveryVerifier normalizes internally, same as
  // deriveRecoveryWrapKey above -- see that call's own comment.
  const verifierSalt = randomSalt()
  const verifier = await deriveRecoveryVerifier(recoveryCode, verifierSalt, SIGNUP_ARGON2_PARAMS)
  post({ kind: 'signupProgress', id, step: 3, totalSteps: 3, label: 'Recovery verifier ready' })

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

async function generateSignupMaterial(req: GenerateSignupMaterialRequest): Promise<void> {
  const signingKey = ed25519.generateSigningKey()
  const wrappingKey = generateWrappingKey()

  const bundle = encodeKeyBundle({
    signingSeed: signingKey.seed,
    wrappingPrivateKey: wrappingKey.privateKey,
  })

  // req.userId is generated by the caller before this request is sent (see
  // uuid.ts) -- issue #123 made the user uuid client-generated specifically
  // so it exists before signup wraps under it, closing the chicken-and-egg
  // problem an earlier draft of this function had (wrap under a placeholder,
  // then re-wrap once register() returns a server-assigned id). No
  // placeholder and no re-wrap: credentialWrapAAD binds the real uuid from
  // the first wrap, and POST /api/auth/register's UserID field is sent this
  // same value as-is.
  const wrapped = await wrapNewCredentials(req.id, req.userId, req.password, bundle)

  const result: SignupMaterial = {
    signingPublicKey: bytesToBase64(signingKey.publicKey),
    wrappingPublicKey: bytesToBase64(wrappingKey.publicKey),
    ...wrapped,
  }

  post({ kind: 'generateSignupMaterialDone', id: req.id, result })
}

async function completeLogin(req: CompleteLoginRequest): Promise<void> {
  const salt = base64ToBytes(req.salt)
  const key = await deriveKey(req.password, salt, req.argon2Params, KEY_SIZE)

  const plaintext = await decrypt(
    key,
    base64ToBytes(req.wrappedPrivateKeys.nonce),
    base64ToBytes(req.wrappedPrivateKeys.ciphertext),
    credentialWrapAAD(req.userId, 'PROFILE'),
  )
  const bundle = decodeKeyBundle(plaintext)

  if (bundle.wrappingPrivateKey.length !== X25519_KEY_LEN) {
    throw new Error('crypto: decoded key bundle has an invalid wrapping key length')
  }

  const signingKey = ed25519.signingKeyFromSeed(bundle.signingSeed)
  const signature = ed25519.sign(
    signingKey,
    ed25519.SigningContext.LoginChallenge,
    base64ToBytes(req.nonce),
  )

  post({ kind: 'completeLoginDone', id: req.id, signature: bytesToBase64(signature) })
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
 */
async function completeRecovery(req: CompleteRecoveryRequest): Promise<void> {
  const recoverySalt = base64ToBytes(req.recoverySalt)
  const recoveryKey = await deriveRecoveryWrapKey(
    req.recoveryCode,
    recoverySalt,
    req.recoveryArgon2Params,
  )

  const bundle = await decrypt(
    recoveryKey,
    base64ToBytes(req.recoveryWrappedPrivateKeys.nonce),
    base64ToBytes(req.recoveryWrappedPrivateKeys.ciphertext),
    credentialWrapAAD(req.userId, 'RECOVERY'),
  )

  // Decoded only to validate the blob is a real key bundle before it's
  // re-wrapped wholesale below -- completeLogin's own shape check on the
  // wrapping key length applies equally here, since a corrupt or truncated
  // bundle should fail loudly now rather than silently re-wrap garbage.
  const decoded = decodeKeyBundle(bundle)
  if (decoded.wrappingPrivateKey.length !== X25519_KEY_LEN) {
    throw new Error('crypto: decoded key bundle has an invalid wrapping key length')
  }

  const wrapped = await wrapNewCredentials(req.id, req.userId, req.newPassword, bundle)

  const result: RecoveryMaterial = wrapped
  post({ kind: 'completeRecoveryDone', id: req.id, result })
}

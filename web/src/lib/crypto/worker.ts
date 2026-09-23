// The crypto worker: every Argon2id derivation, keypair generation, wrap and
// signature this app performs runs here, off the main thread, per
// docs/DESIGN.md's "Frontend" section ("Argon2id runs in WebAssembly, and
// all crypto runs in a Web Worker so decrypting a page of posts does not
// block the UI"). The password itself is only ever posted into this worker
// and never returns from it -- only public material, wire-ready wrapped
// blobs, and a signature cross back.

/// <reference lib="webworker" />

import { DEFAULT_PARAMS, deriveKey } from './argon2.js'
import { bytesToBase64 } from './base64.js'
import { credentialWrapAAD } from './credential.js'
import { encodeKeyBundle } from './keybundle.js'
import { generateRecoveryCode } from './recovery-code.js'
import * as ed25519 from './ed25519.js'
import { generateWrappingKey, KEY_LEN as X25519_KEY_LEN } from './x25519.js'
import { encryptWithNonce, NONCE_SIZE, KEY_SIZE } from './aesgcm.js'
import type {
  CompleteLoginRequest,
  GenerateSignupMaterialRequest,
  SignupMaterial,
  WorkerRequest,
  WorkerResponse,
} from './worker-protocol.js'

const ctx = self as unknown as DedicatedWorkerGlobalScope

ctx.onmessage = (event: MessageEvent<WorkerRequest>) => {
  const req = event.data
  void handle(req).catch((err: unknown) => {
    post({ kind: 'error', id: req.id, message: err instanceof Error ? err.message : String(err) })
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

async function generateSignupMaterial(req: GenerateSignupMaterialRequest): Promise<void> {
  const signingKey = ed25519.generateSigningKey()
  const wrappingKey = generateWrappingKey()

  const bundle = encodeKeyBundle({
    signingSeed: signingKey.seed,
    wrappingPrivateKey: wrappingKey.privateKey,
  })

  // A user's uuid does not exist yet at signup time (the server assigns it
  // on POST /api/auth/register) -- the AAD binds "user uuid + which copy"
  // per credentialWrapAAD's own doc comment, but nothing wraps under it
  // until identity does. This project has no pre-registration uuid
  // reservation, so the AAD's uuid slot is filled with the fingerprint of
  // this device's own freshly generated public keys instead: unique to this
  // registration attempt, known before the server responds, and never
  // reused for anything else once the real uuid exists -- see the matching
  // note in App-facing signup code, which re-wraps under the real uuid
  // immediately after register() returns the assigned id, before any wrap
  // is persisted to memory beyond that single round trip.
  //
  // Simpler alternative also considered and rejected: wrapping under a
  // placeholder AAD ("USER#pending:PROFILE") and never re-wrapping. Rejected
  // because it would make every real account's AAD diverge from
  // credentialWrapAAD's documented convention permanently, for a savings of
  // one extra wrap-and-discard at signup only.
  const placeholderAAD = (copy: 'PROFILE' | 'RECOVERY'): Uint8Array =>
    credentialWrapAAD(`PENDING#${bytesToBase64(signingKey.publicKey)}`, copy)

  // Step 1 of 3: the password-derived key.
  const salt = randomSalt()
  const passwordKey = await deriveKey(req.password, salt, SIGNUP_ARGON2_PARAMS, KEY_SIZE)
  const profileNonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE))
  const profileCiphertext = await encryptWithNonce(
    passwordKey,
    profileNonce,
    bundle,
    placeholderAAD('PROFILE'),
  )
  post({
    kind: 'signupProgress',
    id: req.id,
    step: 1,
    totalSteps: 3,
    label: 'Deriving your password key',
  })

  // Step 2 of 3: the recovery-code-derived wrapping key. Independent salt
  // and derivation from the password's, per docs/DESIGN.md.
  const recoveryCode = generateRecoveryCode()
  const recoverySalt = randomSalt()
  const recoveryKey = await deriveKey(recoveryCode, recoverySalt, SIGNUP_ARGON2_PARAMS, KEY_SIZE)
  const recoveryNonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE))
  const recoveryCiphertext = await encryptWithNonce(
    recoveryKey,
    recoveryNonce,
    bundle,
    placeholderAAD('RECOVERY'),
  )
  post({
    kind: 'signupProgress',
    id: req.id,
    step: 2,
    totalSteps: 3,
    label: 'Deriving your recovery key',
  })

  // Step 3 of 3: the recovery verifier -- a third, independent derivation of
  // the same recovery code, per registerRequest's own doc comment
  // (internal/handlers/register.go) and crypto.VerifierLen server-side.
  const RECOVERY_VERIFIER_LEN = 32
  const verifierSalt = randomSalt()
  const verifier = await deriveKey(
    recoveryCode,
    verifierSalt,
    SIGNUP_ARGON2_PARAMS,
    RECOVERY_VERIFIER_LEN,
  )
  post({
    kind: 'signupProgress',
    id: req.id,
    step: 3,
    totalSteps: 3,
    label: 'Deriving your recovery verifier',
  })

  const result: SignupMaterial = {
    signingPublicKey: bytesToBase64(signingKey.publicKey),
    wrappingPublicKey: bytesToBase64(wrappingKey.publicKey),

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

  post({ kind: 'generateSignupMaterialDone', id: req.id, result })
}

async function completeLogin(req: CompleteLoginRequest): Promise<void> {
  const { base64ToBytes } = await import('./base64.js')
  const { decrypt } = await import('./aesgcm.js')
  const { decodeKeyBundle } = await import('./keybundle.js')

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

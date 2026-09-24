// The async body of RecoveryScreen's handleCredentials, pulled out to a
// plain function that takes its two network/worker calls as arguments --
// PR #129 round 2: the round-trip test in credential-material.test.ts
// cannot pin the bug that actually shipped (an unnormalized recoveryCode on
// the wire to CheckRecoveryVerifier), because deriveRecoveryWrapKey/
// deriveRecoveryVerifier normalize internally regardless of what this
// function does. Only the *wire* value passed to release/reset is at risk,
// and this function is what decides that value -- so a test that stubs
// release/reset and asserts what they were called with is what actually
// pins it. Needs no jsdom/RTL: these are plain functions, not fetch calls
// through RecoveryScreen's own imports.
//
// The three error-classifier functions below are real exports, not part of
// RecoveryDeps -- round 2 had them injected so RecoveryScreen owned the
// wording decisions, but round 3 caught that meant every runRecovery.test.ts
// case stubbed them, so the actual status-code mapping (e.g. `< 500` vs.
// `< 600`) was never exercised by any test. They're pure and have nothing
// screen-specific about them, so they live here and runRecovery.test.ts
// table-tests them directly against real ApiError/DecryptionFailedError
// instances.

import { ApiError } from '@/lib/api/auth'
import { DecryptionFailedError } from '@/lib/crypto/aesgcm'
import { normalizeRecoveryCode } from '@/lib/crypto/recovery-code'
import type { RecoveryCodeReleaseResponse } from '@/lib/api/auth'
import type { RecoveryMaterial, SignupProgressEvent } from '@/lib/crypto/worker-protocol'

/**
 * Mirrors LoginScreen's isCredentialFailure: a wrong code fails inside the
 * worker's unwrap (DecryptionFailedError) or at release()/reset() as a 401
 * (recovery.go's uniform errRecoveryCodeInvalid). Everything else --
 * network failure, 5xx, or the WAF's 403 rate-limit response -- must not
 * collapse into "wrong code," for the same reason LoginScreen's own comment
 * gives: it risks telling someone who typed it correctly that their only
 * way back into their account doesn't work. Does NOT cover reset()'s own
 * 409 -- that's a distinct, real conflict, handled separately below.
 */
export function isCredentialFailure(err: unknown): boolean {
  if (err instanceof DecryptionFailedError) {
    return true
  }
  if (err instanceof ApiError) {
    return err.status === 401
  }
  return false
}

/** reset()'s stale-credential-version conflict (password.go's errCredentialVersionStale). */
export function isStaleVersionConflict(err: unknown): boolean {
  return err instanceof ApiError && err.status === 409
}

/**
 * Whether err is an ApiError whose status recoveryCodeReset's own handler
 * (internal/handlers/recovery.go) proves happened before its write: every
 * 4xx there -- validation, the 401, and the 409 -- is returned before
 * RewrapCredentials ever runs, so those (and the WAF's 403) definitely did
 * not commit. Only a non-ApiError (network failure, a lost response) or a
 * 5xx (e.g. a Lambda timeout surfacing after the write) is genuinely
 * ambiguous about whether the write landed. PR #129 round 2.
 */
export function isDefinitelyUncommitted(err: unknown): boolean {
  return err instanceof ApiError && err.status < 500
}

export type RecoveryErrorKind = 'credential' | 'staleVersion' | 'resetResponseLost' | 'unreachable'

export type RecoveryResult =
  | { readonly ok: true; readonly material: RecoveryMaterial }
  | { readonly ok: false; readonly kind: RecoveryErrorKind; readonly error: unknown }

export interface RecoveryDeps {
  readonly release: (username: string, recoveryCode: string) => Promise<RecoveryCodeReleaseResponse>
  readonly completeRecovery: (
    req: {
      readonly recoveryCode: string
      readonly recoverySalt: string
      readonly recoveryArgon2Params: {
        memoryKiB: number
        iterations: number
        parallelism: number
      }
      readonly recoveryWrappedPrivateKeys: { readonly nonce: string; readonly ciphertext: string }
      readonly userId: string
      readonly newPassword: string
    },
    onProgress: (event: SignupProgressEvent) => void,
  ) => Promise<RecoveryMaterial>
  readonly reset: (req: {
    readonly username: string
    readonly recoveryCode: string
    readonly expectedCredentialVersion: number
    readonly salt: string
    readonly argon2Params: { memoryKiB: number; iterations: number; parallelism: number }
    readonly wrappedPrivateKeys: { nonce: string; ciphertext: string }
    readonly recoverySalt: string
    readonly recoveryArgon2Params: { memoryKiB: number; iterations: number; parallelism: number }
    readonly recoveryWrappedPrivateKeys: { nonce: string; ciphertext: string }
    readonly recoveryVerifierSalt: string
    readonly recoveryVerifierParams: { memoryKiB: number; iterations: number; parallelism: number }
    readonly recoveryVerifier: string
  }) => Promise<unknown>
  readonly onProgress: (event: SignupProgressEvent) => void
  /**
   * Called for the two step transitions that happen mid-flow, after
   * release() and after the worker's re-wrap -- the caller is assumed to
   * already be in its 'releasing' step before calling runRecovery, so that
   * transition isn't reported here.
   */
  readonly onStep: (
    step:
      | { readonly name: 'recovering'; readonly release: RecoveryCodeReleaseResponse }
      | { readonly name: 'resetting'; readonly material: RecoveryMaterial },
  ) => void
}

/**
 * Runs the full recovery flow: release -> completeRecovery (worker) ->
 * reset. `recoveryCode` is normalized exactly once, here, at the point of
 * use -- recovery-code.ts's own doc comment on normalizeRecoveryCode: this
 * is the one canonical KDF input, on both sides, and CheckRecoveryVerifier
 * (internal/crypto/recovery.go) hashes whatever bytes it's handed with no
 * normalization of its own. Every deps call below gets this same value,
 * never the raw string the user typed.
 */
export async function runRecovery(
  deps: RecoveryDeps,
  username: string,
  enteredCode: string,
  newPassword: string,
): Promise<RecoveryResult> {
  const recoveryCode = normalizeRecoveryCode(enteredCode)

  let release: RecoveryCodeReleaseResponse
  try {
    release = await deps.release(username, recoveryCode)
  } catch (err) {
    return {
      ok: false,
      kind: isCredentialFailure(err) ? 'credential' : 'unreachable',
      error: err,
    }
  }

  deps.onStep({ name: 'recovering', release })
  let material: RecoveryMaterial
  try {
    material = await deps.completeRecovery(
      {
        recoveryCode,
        recoverySalt: release.salt,
        recoveryArgon2Params: release.argon2Params,
        recoveryWrappedPrivateKeys: release.wrappedPrivateKeys,
        userId: release.userId,
        newPassword,
      },
      deps.onProgress,
    )
  } catch (err) {
    // A wrong code surfaces here too (DecryptionFailedError, GCM tag
    // mismatch), not only at release() -- release only checks the Argon2id
    // verifier, unwrapping is a separate, independent check against the
    // same code. Nothing has been submitted to the server yet, so it's
    // safe to go all the way back to credentials.
    return {
      ok: false,
      kind: isCredentialFailure(err) ? 'credential' : 'unreachable',
      error: err,
    }
  }

  deps.onStep({ name: 'resetting', material })
  try {
    await deps.reset({
      username,
      recoveryCode,
      expectedCredentialVersion: release.credentialVersion,
      salt: material.salt,
      argon2Params: material.argon2Params,
      wrappedPrivateKeys: material.wrappedPrivateKeys,
      recoverySalt: material.recoverySalt,
      recoveryArgon2Params: material.recoveryArgon2Params,
      recoveryWrappedPrivateKeys: material.recoveryWrappedPrivateKeys,
      recoveryVerifierSalt: material.recoveryVerifierSalt,
      recoveryVerifierParams: material.recoveryVerifierParams,
      recoveryVerifier: material.recoveryVerifier,
    })
  } catch (err) {
    // Four cases here, per PR #129 review (round 1 + round 2):
    //
    // 1. A genuine 401/DecryptionFailedError-shaped failure: can't actually
    //    happen at reset() (the code already unwrapped successfully
    //    above), but isCredentialFailure is checked first for consistency
    //    with the other catches.
    // 2. A real 409 (isStaleVersionConflict): the server WAS reached,
    //    nothing here committed, and the OLD code is still valid -- safe
    //    to retry from the top.
    // 3. Any other failure isDefinitelyUncommitted proves happened before
    //    recoveryCodeReset's write (a 400, or the WAF's 403): the server
    //    WAS reached and nothing committed, so this is a plain,
    //    unreachable-shaped failure, not the lost-response case.
    // 4. Everything else (network failure, timeout, a 5xx): reset()'s
    //    write may have committed even though this response was lost --
    //    unlike SignupScreen's register(), which is safe to treat as
    //    "never happened" on any failure, this PUT is NOT, because it's
    //    the write that actually changes the account's live password and
    //    invalidates the old recovery code. #124 is register-only and
    //    doesn't cover this; #130 (idempotent retry for this write) and
    //    #131 (a logged-in screen to get a new recovery code) are the real
    //    fixes, and neither exists yet. PR #129 round 3.
    if (isCredentialFailure(err)) {
      return { ok: false, kind: 'credential', error: err }
    }
    if (isStaleVersionConflict(err)) {
      return { ok: false, kind: 'staleVersion', error: err }
    }
    if (isDefinitelyUncommitted(err)) {
      return { ok: false, kind: 'unreachable', error: err }
    }
    return { ok: false, kind: 'resetResponseLost', error: err }
  }

  return { ok: true, material }
}

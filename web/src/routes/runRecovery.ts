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
//
// issue #130 (server side: internal/db/credentials.go, internal/handlers/
// recovery.go) added an idempotency token to reset()'s own retry path: a
// resetResponseLost failure now carries `resume`, and a caller that
// resubmits the SAME username + recoveryCode + newPassword skips
// completeRecovery entirely and resends reset() with the cached material
// and token byte-for-byte -- see PendingRecovery's own doc comment for why
// "exact," not just "same username," is load-bearing here too, mirroring
// runSignup.ts's own `resume` (#124).

import { ApiError } from '@/lib/api/auth'
import { DecryptionFailedError } from '@/lib/crypto/aesgcm'
import { bytesToBase64 } from '@/lib/crypto/base64.js'
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
 *
 * NOTE: issue #130's retry fallback means a genuine 401 is now also
 * reachable for a retry whose OWN earlier write committed -- but that only
 * happens when isOwnRewrap's match fails (wrong/missing token, or the
 * version doesn't line up), which is not this attempt's own retry succeeding
 * either way, so it is correctly still "did not commit, from THIS attempt's
 * perspective" and isDefinitelyUncommitted's classification does not need to
 * change.
 */
export function isDefinitelyUncommitted(err: unknown): boolean {
  return err instanceof ApiError && err.status < 500
}

export type RecoveryErrorKind =
  'credential' | 'staleVersion' | 'resetResponseLost' | 'unreachable' | 'retryConflict'

/**
 * Everything a retry needs to resend reset() byte-for-byte after a
 * resetResponseLost failure, without calling release()/completeRecovery
 * again -- see runRecovery's own header comment and runSignup.ts's
 * PendingSignup for why exact reuse, not regeneration, is required:
 * material is freshly random per completeRecovery call (a new recovery
 * code, new salts/nonces), so a retry that regenerated it would show the
 * user a code that doesn't match what the server actually has stored from
 * the first, possibly-committed attempt -- exactly the PR #133 round 1
 * finding runSignup.ts's own header comment describes, for the same
 * underlying reason.
 */
export interface PendingRecovery {
  readonly username: string
  readonly recoveryCode: string
  readonly newPassword: string
  readonly expectedCredentialVersion: number
  readonly material: RecoveryMaterial
  readonly idempotencyToken: string
}

export type RecoveryResult =
  | { readonly ok: true; readonly material: RecoveryMaterial }
  | {
      readonly ok: false
      readonly kind: RecoveryErrorKind
      readonly error: unknown
      /**
       * Set only when kind is 'resetResponseLost' -- the one failure a plain
       * retry from the top is not safe for (see RecoveryScreen.tsx's own
       * header comment). The caller should hold onto this and pass it back
       * in as `resume` if the user retries, so the retry resends the exact
       * request the first, possibly-committed attempt did.
       */
      readonly resume?: PendingRecovery
    }

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
    readonly idempotencyToken: string
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
  /**
   * Generates a fresh IdempotencyToken for a non-resumed attempt -- injected
   * rather than called directly so a test can supply a deterministic value.
   * Real callers use generateIdempotencyToken (this file's own export),
   * which wraps crypto.getRandomValues the same way every other CSPRNG call
   * in this codebase does (see lib/crypto/credential-material.ts's
   * randomSalt).
   */
  readonly generateIdempotencyToken: () => string
}

/**
 * 16 random bytes, base64-encoded -- matches
 * internal/handlers/recovery.go's idempotencyTokenLen exactly. Not itself a
 * credential or derived from one; its only job is to let a retry be
 * recognized as such, the same role RegisterInput's client-chosen UserID
 * plays for #124's fix. Exported so RecoveryScreen.tsx can supply it as
 * RecoveryDeps.generateIdempotencyToken without duplicating the byte count.
 */
export function generateIdempotencyToken(): string {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(16)))
}

/**
 * Runs the full recovery flow: release -> completeRecovery (worker) ->
 * reset. `recoveryCode` is normalized exactly once, here, at the point of
 * use -- recovery-code.ts's own doc comment on normalizeRecoveryCode: this
 * is the one canonical KDF input, on both sides, and CheckRecoveryVerifier
 * (internal/crypto/recovery.go) hashes whatever bytes it's handed with no
 * normalization of its own. Every deps call below gets this same value,
 * never the raw string the user typed.
 *
 * `resume`, when passed, is only actually used -- skipping release() and
 * completeRecovery entirely, and resending reset() with the cached material
 * and token byte-for-byte -- when its username, recoveryCode, AND
 * newPassword all equal this call's arguments exactly. Any mismatch means
 * this is not a resend of the same attempt (a different username or code is
 * a new attempt; a different newPassword means the user changed something,
 * e.g. fixing a typo), so runRecovery falls back to running the flow fresh
 * from release(), exactly as if no `resume` had been passed -- see
 * PendingRecovery's own doc comment for why resent material must be exact,
 * not regenerated.
 */
export async function runRecovery(
  deps: RecoveryDeps,
  username: string,
  enteredCode: string,
  newPassword: string,
  resume?: PendingRecovery,
): Promise<RecoveryResult> {
  const recoveryCode = normalizeRecoveryCode(enteredCode)

  const resuming =
    resume !== undefined &&
    resume.username === username &&
    resume.recoveryCode === recoveryCode &&
    resume.newPassword === newPassword

  let expectedCredentialVersion: number
  let material: RecoveryMaterial
  let idempotencyToken: string

  if (resuming) {
    // Skip straight to reset() -- release() and completeRecovery already
    // ran for this exact attempt, and re-running completeRecovery would
    // regenerate the recovery code/salts/nonces, defeating the whole point
    // of resending (see PendingRecovery's own doc comment).
    expectedCredentialVersion = resume.expectedCredentialVersion
    material = resume.material
    idempotencyToken = resume.idempotencyToken
    deps.onStep({ name: 'resetting', material })
  } else {
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
    expectedCredentialVersion = release.credentialVersion
    idempotencyToken = deps.generateIdempotencyToken()
  }

  try {
    await deps.reset({
      username,
      recoveryCode,
      expectedCredentialVersion,
      idempotencyToken,
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
    // Five cases here, per PR #129 review (round 1 + round 2), plus issue
    // #130's retry fallback:
    //
    // 1. A 401/DecryptionFailedError-shaped failure on a FRESH (non-resumed)
    //    attempt: a genuine wrong code -- can't actually happen in practice
    //    (the code already unwrapped successfully above), but classified as
    //    'credential' for consistency with every other catch in this flow.
    // 1b. The same 401 shape, but on a RESUMED attempt (`resuming` true):
    //    recoveryCodeReset's own fallback (db.IsOwnRewrap) looked for a
    //    RECOVERY item at exactly this retry's own version and token and
    //    did not find one. Reaching that fallback at all already required
    //    resolveRecovery's code check to fail, which only happens once some
    //    write has rotated the verifier away from the code this retry still
    //    presents -- so a token/version mismatch on top of that means the
    //    write that rotated it was NOT this attempt's own (a genuine
    //    concurrent change: another tab, another device, or a second
    //    recovery attempt), not "the code was wrong." Misclassifying this
    //    as 'credential' would send the user back to a blank form with a
    //    misleading message and no explanation of what actually happened --
    //    'retryConflict' names it accurately instead.
    // 2. A real 409 (isStaleVersionConflict): the server WAS reached,
    //    nothing here committed, and the OLD code is still valid -- safe
    //    to retry from the top. (Not reachable when resuming a retry that
    //    hits the recoveryCodeReset fallback path -- that path returns 200
    //    or 401, never touches RewrapCredentials's own conflict check --
    //    but is reachable on a fresh, non-resumed attempt.)
    // 3. Any other failure isDefinitelyUncommitted proves happened before
    //    recoveryCodeReset's write (a 400, or the WAF's 403): the server
    //    WAS reached and nothing committed, so this is a plain,
    //    unreachable-shaped failure, not the lost-response case.
    // 4. Everything else (network failure, timeout, a 5xx): reset()'s
    //    write may have committed even though this response was lost --
    //    unlike SignupScreen's register(), which is safe to treat as
    //    "never happened" on any failure, this PUT is NOT, because it's
    //    the write that actually changes the account's live password and
    //    invalidates the old recovery code. This is exactly the case
    //    issue #130 exists for: hand back `resume` so a retry can resend
    //    this identical request (same material, same token), which the
    //    server can now recognize as its own earlier write landing late.
    if (isCredentialFailure(err)) {
      if (resuming && err instanceof ApiError && err.status === 401) {
        return { ok: false, kind: 'retryConflict', error: err }
      }
      return { ok: false, kind: 'credential', error: err }
    }
    if (isStaleVersionConflict(err)) {
      return { ok: false, kind: 'staleVersion', error: err }
    }
    if (isDefinitelyUncommitted(err)) {
      return { ok: false, kind: 'unreachable', error: err }
    }
    return {
      ok: false,
      kind: 'resetResponseLost',
      error: err,
      resume: {
        username,
        recoveryCode,
        newPassword,
        expectedCredentialVersion,
        material,
        idempotencyToken,
      },
    }
  }

  return { ok: true, material }
}

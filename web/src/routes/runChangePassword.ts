// The async body of ChangePasswordScreen's handleCredentials, pulled out to
// a plain function that takes its network/worker calls as arguments -- the
// same split runRecovery.ts made from RecoveryScreen (PR #129 round 2), for
// the same reason: this can be unit-tested directly, against real
// ApiError/DecryptionFailedError instances, without jsdom or a stubbed
// worker.
//
// #131's change-password flow: GET /api/account/credentials (this screen's
// own bootstrap -- see auth.ts's own doc comment on why no other
// authenticated endpoint returns this) -> unwrap the PROFILE copy with the
// OLD password and re-wrap under the NEW one in the worker
// (completeChangePassword) -> PUT /api/account/password to commit it and
// issue a new recovery code -> show the new recovery code -> done. Shaped
// almost exactly like runRecovery's release -> completeRecovery -> reset,
// with one real difference: there is no server-side proof of the old
// password to fail on (changePassword's own doc comment -- the server
// never receives it), so a wrong old password can ONLY fail inside the
// worker's unwrap here, never as a 401 from the PUT the way a wrong
// recovery code can fail at either release() or reset(). The PUT's own 409
// (stale CredentialVersion) and its lost-response ambiguity are otherwise
// identical to reset()'s -- same isDefinitelyUncommitted reasoning applies,
// since password.go's changePassword returns every 4xx before its own
// RewrapCredentials write runs, exactly like recovery.go's reset handler.

import { ApiError } from '@/lib/api/auth'
import { DecryptionFailedError } from '@/lib/crypto/aesgcm'
import type { AccountCredentialsResponse, ChangePasswordResponse } from '@/lib/api/auth'
import type { ChangePasswordMaterial, SignupProgressEvent } from '@/lib/crypto/worker-protocol'

/**
 * A wrong old password fails inside the worker's unwrap
 * (DecryptionFailedError) -- there is no server-side check to fail at
 * instead (changePassword's own doc comment). See this file's own header
 * comment for why that's the ONLY route to this classification here, unlike
 * runRecovery's isCredentialFailure, which also covers a 401 from the
 * server.
 */
export function isCredentialFailure(err: unknown): boolean {
  return err instanceof DecryptionFailedError
}

/** The PUT's own 409 (password.go's errCredentialVersionStale). */
export function isStaleVersionConflict(err: unknown): boolean {
  return err instanceof ApiError && err.status === 409
}

/**
 * Whether err is an ApiError whose status proves the PUT's write never ran
 * -- mirrors runRecovery's isDefinitelyUncommitted exactly, and for the
 * same reason: password.go's changePassword returns every 4xx (validation,
 * the 409) before RewrapCredentials ever runs, so those (and the WAF's 403)
 * definitely did not commit. Only a non-ApiError or a 5xx is genuinely
 * ambiguous.
 */
export function isDefinitelyUncommitted(err: unknown): boolean {
  return err instanceof ApiError && err.status < 500
}

export type ChangePasswordErrorKind =
  'credential' | 'staleVersion' | 'changeResponseLost' | 'unreachable'

export type ChangePasswordResult =
  | { readonly ok: true; readonly material: ChangePasswordMaterial }
  | { readonly ok: false; readonly kind: ChangePasswordErrorKind; readonly error: unknown }

export interface ChangePasswordDeps {
  readonly getCredentials: () => Promise<AccountCredentialsResponse>
  readonly completeChangePassword: (
    req: {
      readonly oldPassword: string
      readonly salt: string
      readonly argon2Params: { memoryKiB: number; iterations: number; parallelism: number }
      readonly wrappedPrivateKeys: { nonce: string; ciphertext: string }
      readonly userId: string
      readonly newPassword: string
    },
    onProgress: (event: SignupProgressEvent) => void,
  ) => Promise<ChangePasswordMaterial>
  readonly changePassword: (req: {
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
  }) => Promise<ChangePasswordResponse>
  readonly onProgress: (event: SignupProgressEvent) => void
  /**
   * Called for the two step transitions that happen mid-flow, after
   * getCredentials() and after the worker's re-wrap -- the caller is
   * assumed to already be in its 'loadingCredentials' step before calling
   * runChangePassword, so that transition isn't reported here. Mirrors
   * runRecovery's onStep exactly.
   */
  readonly onStep: (
    step:
      | { readonly name: 'changing'; readonly credentials: AccountCredentialsResponse }
      | { readonly name: 'committing'; readonly material: ChangePasswordMaterial },
  ) => void
}

/**
 * Runs the full change-password flow: getCredentials -> completeChangePassword
 * (worker) -> changePassword. getCredentials() is also where userId comes
 * from -- see auth.ts's own comment on why this response carries it rather
 * than relying on SessionContext's copy, which does not survive a reload.
 */
export async function runChangePassword(
  deps: ChangePasswordDeps,
  oldPassword: string,
  newPassword: string,
): Promise<ChangePasswordResult> {
  let credentials: AccountCredentialsResponse
  try {
    credentials = await deps.getCredentials()
  } catch (err) {
    // Nothing has touched the worker or the write endpoint yet -- a failure
    // here is never a credential failure (there is no password check this
    // early), always network/server-shaped.
    return { ok: false, kind: 'unreachable', error: err }
  }

  deps.onStep({ name: 'changing', credentials })
  let material: ChangePasswordMaterial
  try {
    material = await deps.completeChangePassword(
      {
        oldPassword,
        salt: credentials.salt,
        argon2Params: credentials.argon2Params,
        wrappedPrivateKeys: credentials.wrappedPrivateKeys,
        userId: credentials.userId,
        newPassword,
      },
      deps.onProgress,
    )
  } catch (err) {
    // A wrong old password surfaces here, and only here -- see this file's
    // own header comment. Nothing has been submitted to the server yet, so
    // it's safe to go all the way back to the credentials step.
    return {
      ok: false,
      kind: isCredentialFailure(err) ? 'credential' : 'unreachable',
      error: err,
    }
  }

  deps.onStep({ name: 'committing', material })
  try {
    await deps.changePassword({
      expectedCredentialVersion: credentials.credentialVersion,
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
    // Mirrors runRecovery's identical catch on reset() -- see that file's
    // own comment for the full four-case breakdown. isCredentialFailure is
    // checked first for consistency even though it cannot actually fire
    // here (the unwrap above already proved the old password correct).
    if (isCredentialFailure(err)) {
      return { ok: false, kind: 'credential', error: err }
    }
    if (isStaleVersionConflict(err)) {
      return { ok: false, kind: 'staleVersion', error: err }
    }
    if (isDefinitelyUncommitted(err)) {
      return { ok: false, kind: 'unreachable', error: err }
    }
    return { ok: false, kind: 'changeResponseLost', error: err }
  }

  return { ok: true, material }
}

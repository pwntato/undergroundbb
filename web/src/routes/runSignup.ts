// The async body of SignupScreen's handleCredentials, pulled out to a plain
// function that takes its network/worker calls as arguments -- the same
// split runRecovery.ts and runChangePassword.ts made from their own
// screens, for the same reason: this can be unit-tested directly, against
// real ApiError instances and stubbed generateUserID/register/challenge/
// completeLogin/verify, without jsdom or a real worker.
//
// #124's real subject lives here: SignupScreen used to call generateUserID
// and generateSignupMaterial fresh on every call to handleCredentials, so a
// user who resubmits the form after register()'s response was lost (but the
// write actually committed -- see internal/db/register.go's own fix for the
// server-side half of #124) sent a *different* userId on the retry. The
// server-side fix can only recognize "this is my own earlier write" when
// the retry's UserID matches the first attempt's; a client that regenerates
// defeats it before it ever runs. runSignup keeps the userId (and password,
// needed to re-derive the same wrapped material) from an ambiguous first
// failure and reuses them verbatim if the same username is resubmitted,
// exactly the way a real retry needs to look to the server.
//
// Only ambiguous failures (isDefinitelyUncommitted false: a network error or
// 5xx) preserve the identity for reuse. A clean 4xx (validation, WAF, or a
// genuine username_taken/user_id_taken conflict that isn't this caller's own
// account) proves nothing committed, so there is nothing to retry -- reused
// material there would just resend a doomed request under the same identity
// instead of letting the user pick a different username or fix a validation
// error.

import { ApiError } from '@/lib/api/auth'
import type { ChallengeResponse, RegisterRequest, VerifyResponse } from '@/lib/api/auth'
import type { SignupMaterial, SignupProgressEvent } from '@/lib/crypto/worker-protocol'

/**
 * Whether err is an ApiError whose status proves register()'s write never
 * ran -- mirrors runRecovery's/runChangePassword's isDefinitelyUncommitted
 * exactly. internal/handlers/register.go returns every 4xx (validation, the
 * closed-registration 403, the username/userId conflicts) before
 * db.Register's transaction ever runs, so those (and the WAF's 403)
 * definitely did not commit. Only a non-ApiError (network failure, a lost
 * response) or a 5xx is genuinely ambiguous about whether the account was
 * actually created.
 */
export function isDefinitelyUncommitted(err: unknown): boolean {
  return err instanceof ApiError && err.status < 500
}

export interface PendingSignup {
  readonly username: string
  readonly userId: string
  readonly password: string
}

export type SignupErrorKind = 'definitelyUncommitted' | 'ambiguous'

export type SignupResult =
  | {
      readonly ok: true
      readonly material: SignupMaterial
      readonly loggedIn: boolean
    }
  | {
      readonly ok: false
      readonly kind: SignupErrorKind
      readonly error: unknown
      /**
       * Set only when kind is 'ambiguous' -- the caller should hold onto
       * this and pass it back in as `resume` on the next attempt if the
       * user resubmits with the same username, so the retry carries the
       * same UserID and wrapped material the first, possibly-committed
       * attempt did. Undefined for 'definitelyUncommitted', since there is
       * nothing safe to resend.
       */
      readonly resume?: PendingSignup
    }

export interface SignupDeps {
  readonly generateUserID: () => string
  readonly generateSignupMaterial: (
    password: string,
    userId: string,
    onProgress: (event: SignupProgressEvent) => void,
  ) => Promise<SignupMaterial>
  readonly register: (req: RegisterRequest) => Promise<unknown>
  readonly challenge: (username: string) => Promise<ChallengeResponse>
  readonly completeLogin: (req: {
    readonly password: string
    readonly salt: string
    readonly argon2Params: { memoryKiB: number; iterations: number; parallelism: number }
    readonly wrappedPrivateKeys: { nonce: string; ciphertext: string }
    readonly userId: string
    readonly nonce: string
  }) => Promise<string>
  readonly verify: (username: string, nonce: string, signature: string) => Promise<VerifyResponse>
  readonly onProgress: (event: SignupProgressEvent) => void
  /**
   * Called with the verified userId once login after registration actually
   * succeeds -- SessionContext's session.login, injected rather than
   * imported directly so this stays a plain function callable from a test
   * without React context. Never called if the post-register login fails;
   * see this file's own header comment on why that's still an `ok: true`
   * result rather than a thrown error.
   */
  readonly onLogin: (userId: string) => void
  /**
   * Called once register() succeeds, before the post-register login is
   * attempted -- so the caller can switch its progress UI from "creating
   * your account" to "logging you in" honestly, the same transition
   * SignupScreen made inline before this was extracted.
   */
  readonly onRegistered: (material: SignupMaterial) => void
}

/**
 * Runs registration + immediate login: generateSignupMaterial (worker) ->
 * register() -> challenge -> completeLogin (worker) -> verify. See this
 * file's own header comment for why register() and the post-register login
 * are two separate try blocks -- once register() succeeds the account
 * exists server-side with a real recovery code that must reach the caller
 * regardless of what happens next, so only the first try's failure can
 * produce a SignupResult with ok: false; every path after that resolves
 * `ok: true` with `loggedIn` reflecting whether the follow-up login
 * actually worked.
 *
 * `resume`, when passed, must be the `resume` field from this same
 * username's previous ambiguous failure -- reusing its userId/password
 * (and therefore, once generated, the same wrapped material) is what lets
 * the server-side retry check in internal/db/register.go recognize the
 * retry as the caller's own earlier write instead of a conflict. Passing a
 * `resume` for a different username than the one now being submitted is a
 * caller error; runSignup does not check for it, since the caller (a single
 * per-username pending-signup slot in SignupScreen's state) already
 * guarantees it can't happen.
 */
export async function runSignup(
  deps: SignupDeps,
  username: string,
  password: string,
  resume?: PendingSignup,
): Promise<SignupResult> {
  const userId = resume?.userId ?? deps.generateUserID()

  let material: SignupMaterial
  try {
    material = await deps.generateSignupMaterial(password, userId, deps.onProgress)
    await deps.register({
      username,
      userId,
      signingPublicKey: material.signingPublicKey,
      wrappingPublicKey: material.wrappingPublicKey,
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
    if (isDefinitelyUncommitted(err)) {
      // A real conflict, closed registration, or validation failure --
      // nothing committed, and (for a conflict) reusing this userId would
      // just collide again. Nothing to resume.
      return { ok: false, kind: 'definitelyUncommitted', error: err }
    }
    // Network failure or a 5xx: register()'s write may have committed even
    // though this response was lost. Hand back the identity this attempt
    // used so a resubmission of the SAME username can resend it unchanged.
    return {
      ok: false,
      kind: 'ambiguous',
      error: err,
      resume: { username, userId, password },
    }
  }

  // The account now exists server-side. Everything from here on is a
  // separate try: whatever happens, the caller must still get this
  // material back with ok: true -- see this file's own header comment.
  deps.onRegistered(material)
  let loggedIn = false
  try {
    const ch = await deps.challenge(username)
    const signature = await deps.completeLogin({
      password,
      salt: ch.salt,
      argon2Params: ch.argon2Params,
      wrappedPrivateKeys: ch.wrappedPrivateKeys,
      userId: ch.userId,
      nonce: ch.nonce,
    })
    const result = await deps.verify(username, ch.nonce, signature)
    deps.onLogin(result.userId)
    loggedIn = true
  } catch {
    // Login failed after the account was already created -- the user can
    // always retry logging in themselves afterward with the password they
    // just chose. What must not happen is losing the recovery code over
    // this, so loggedIn stays false and the caller proceeds exactly as it
    // would have on success.
  }

  return { ok: true, material, loggedIn }
}

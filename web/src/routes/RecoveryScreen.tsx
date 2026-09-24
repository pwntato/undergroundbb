// #128: the recovery flow -- username + recovery code + new password ->
// release() to fetch the wrapped private keys -> unwrap + re-wrap under new
// secrets in the worker (with a fresh recovery code) -> reset() to submit
// the new material and invalidate the redeemed code -> show the new
// recovery code -> done.
//
// Every failure mode release()/reset() can return for an unknown username
// or wrong code comes back as resolveRecovery's single uniform "invalid
// username or recovery code" message (recovery.go's own doc comment: this
// endpoint has the same enumeration-resistance requirement /auth/challenge
// does for login). This screen collapses those the same way
// LoginScreen.isCredentialFailure already does, and shows a distinct
// message for anything that is not a credential failure -- a network error
// or a 403 from the WAF's rate-limit rule must not tell someone who typed
// the right code that it was wrong. reset()'s stale-credential-version case
// is NOT one of these uniform failures -- it's a distinct 409
// (errCredentialVersionStale, password.go), handled on its own below.
//
// Once release() resolves, a new recovery code has NOT yet been issued --
// that only happens when reset() commits. So unlike SignupScreen (where the
// account already exists and the shown code must survive at all costs
// after register() succeeds), a failure release()/reset() actually RETURNS
// is safe to send back to the credentials step: the OLD recovery code the
// user typed in is still valid until reset() actually replaces it, so
// nothing is lost by retrying from the top. That does NOT cover reset()'s
// response being lost after the write already committed (network drop,
// Lambda timeout) -- see the reset() catch below, which handles that case
// distinctly rather than claiming the same safety. The one moment that must
// not be interrupted is after reset() succeeds and before the new code is
// acknowledged -- exactly parallel to SignupScreen's recoveryCode step, and
// guarded the same way (beforeunload).

import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router'
import {
  ApiError,
  recoveryCodeRelease,
  recoveryCodeReset,
  type RecoveryCodeReleaseResponse,
} from '@/lib/api/auth'
import { DecryptionFailedError } from '@/lib/crypto/aesgcm'
import { normalizeRecoveryCode } from '@/lib/crypto/recovery-code'
import { completeRecovery } from '@/lib/crypto/worker-client'
import type { RecoveryMaterial, SignupProgressEvent } from '@/lib/crypto/worker-protocol'
import { RecoveryCodeStep } from './RecoveryCodeStep'
import { RecoveryCredentialsStep } from './RecoveryCredentialsStep'
import { SignupProgressStep } from './SignupProgressStep'

const CREDENTIAL_ERROR = 'Incorrect username or recovery code.'
const UNREACHABLE_ERROR = "Couldn't reach the server. Try again."
// reset()'s own 409 (password.go's errCredentialVersionStale): the server
// WAS reached and the code WAS correct -- something else changed the
// account's credentials in the meantime (a concurrent recovery in another
// tab, or a password change on a still-logged-in device). A plain retry
// from the top will succeed, since release() re-reads the current version.
const STALE_VERSION_ERROR =
  "Your account's credentials changed while this was in progress. Please try again."
// The one case a plain retry from the top is NOT safe for: reset()'s
// response was lost after the write already committed (see the reset()
// catch below for why this can't be told apart from an ambiguous network
// failure at that specific step).
const RESET_RESPONSE_LOST_ERROR =
  "We couldn't confirm whether your new password was saved. Try logging in with it before retrying recovery."

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
function isCredentialFailure(err: unknown): boolean {
  if (err instanceof DecryptionFailedError) {
    return true
  }
  if (err instanceof ApiError) {
    return err.status === 401
  }
  return false
}

/** reset()'s stale-credential-version conflict -- see STALE_VERSION_ERROR's own comment. */
function isStaleVersionConflict(err: unknown): boolean {
  return err instanceof ApiError && err.status === 409
}

type Step =
  | { readonly name: 'credentials' }
  | { readonly name: 'releasing' }
  | {
      readonly name: 'recovering'
      readonly release: RecoveryCodeReleaseResponse
      readonly username: string
    }
  | { readonly name: 'resetting'; readonly material: RecoveryMaterial; readonly username: string }
  | { readonly name: 'recoveryCode'; readonly recoveryCode: string }

export function RecoveryScreen() {
  const [step, setStep] = useState<Step>({ name: 'credentials' })
  const [progress, setProgress] = useState<SignupProgressEvent | null>(null)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  // Once reset() has committed a new recovery code, it lives only in
  // component state until the user acknowledges it -- same risk and same
  // guard as SignupScreen's recoveryCode step (that file's own comment).
  useEffect(() => {
    if (step.name !== 'recoveryCode') {
      return
    }
    const handleBeforeUnload = (e: BeforeUnloadEvent): void => {
      e.preventDefault()
    }
    window.addEventListener('beforeunload', handleBeforeUnload)
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload)
    }
  }, [step.name])

  const handleCredentials = (username: string, enteredCode: string, newPassword: string) => {
    setError(null)
    setStep({ name: 'releasing' })
    setProgress(null)

    // Normalized exactly once, here, at the point of collection --
    // recovery-code.ts's own doc comment on normalizeRecoveryCode: this is
    // the one canonical KDF input, on both sides, and CheckRecoveryVerifier
    // (internal/crypto/recovery.go) hashes whatever bytes it's handed with
    // no normalization of its own. Every use below (release, the worker's
    // unwrap, reset) uses this same normalized value, never the raw
    // hyphenated string the user typed.
    const recoveryCode = normalizeRecoveryCode(enteredCode)

    void (async () => {
      let release: RecoveryCodeReleaseResponse
      try {
        release = await recoveryCodeRelease(username, recoveryCode)
      } catch (err) {
        setError(isCredentialFailure(err) ? CREDENTIAL_ERROR : UNREACHABLE_ERROR)
        setStep({ name: 'credentials' })
        return
      }

      setStep({ name: 'recovering', release, username })
      let material: RecoveryMaterial
      try {
        material = await completeRecovery(
          {
            recoveryCode,
            recoverySalt: release.salt,
            recoveryArgon2Params: release.argon2Params,
            recoveryWrappedPrivateKeys: release.wrappedPrivateKeys,
            userId: release.userId,
            newPassword,
          },
          (event) => {
            setProgress(event)
          },
        )
      } catch (err) {
        // A wrong code surfaces here too (DecryptionFailedError, GCM tag
        // mismatch), not only at release() -- release only checks the
        // Argon2id verifier, unwrapping is a separate, independent check
        // against the same code. Nothing has been submitted to the server
        // yet, so it's safe to go all the way back to credentials.
        setError(isCredentialFailure(err) ? CREDENTIAL_ERROR : UNREACHABLE_ERROR)
        setStep({ name: 'credentials' })
        return
      }

      setStep({ name: 'resetting', material, username })
      try {
        await recoveryCodeReset({
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
        // Three distinct cases here, per PR #129 review:
        //
        // 1. A genuine 401/DecryptionFailedError-shaped failure: can't
        //    actually happen at reset() (the code already unwrapped
        //    successfully above), but isCredentialFailure is checked first
        //    for consistency with the other two catches.
        // 2. A real 409 (isStaleVersionConflict): the server WAS reached,
        //    nothing here committed, and the OLD code is still valid --
        //    safe to retry from the top, per STALE_VERSION_ERROR's own
        //    comment.
        // 3. Everything else (network failure, timeout, 5xx): reset()'s
        //    write may have committed even though this response was lost --
        //    unlike SignupScreen's register(), which is safe to treat as
        //    "never happened" on any failure, this PUT is NOT, because it's
        //    the write that actually changes the account's live password
        //    and invalidates the old recovery code. #124 (lost-response
        //    retry idempotency) is the real fix for register(); no
        //    equivalent exists here yet. Telling the user their code was
        //    wrong (UNREACHABLE_ERROR/CREDENTIAL_ERROR) would send them
        //    straight back to a form that's about to fail with "invalid
        //    username or recovery code" on the now-dead old code, so this
        //    case gets its own message instead.
        if (isCredentialFailure(err)) {
          setError(CREDENTIAL_ERROR)
        } else if (isStaleVersionConflict(err)) {
          setError(STALE_VERSION_ERROR)
        } else {
          setError(RESET_RESPONSE_LOST_ERROR)
        }
        setStep({ name: 'credentials' })
        return
      }

      setStep({ name: 'recoveryCode', recoveryCode: material.recoveryCode })
    })()
  }

  switch (step.name) {
    case 'credentials':
      return <RecoveryCredentialsStep onSubmit={handleCredentials} error={error} />
    case 'releasing':
      return (
        <SignupProgressStep
          progress={null}
          initialTotalSteps={4}
          leadingStep="Confirming your code…"
          trailingStep="Saving your new credentials…"
          currentStep="leading"
          heading="Recovering your account"
        />
      )
    case 'recovering':
      return (
        <SignupProgressStep
          progress={progress}
          initialTotalSteps={4}
          leadingStep="Confirming your code…"
          trailingStep="Saving your new credentials…"
          heading="Recovering your account"
        />
      )
    case 'resetting':
      return (
        <SignupProgressStep
          progress={progress}
          initialTotalSteps={4}
          leadingStep="Confirming your code…"
          trailingStep="Saving your new credentials…"
          currentStep="trailing"
          heading="Recovering your account"
        />
      )
    case 'recoveryCode':
      return (
        <RecoveryCodeStep
          recoveryCode={step.recoveryCode}
          onAcknowledged={() => {
            navigate('/login?recoveryComplete=1', { replace: true })
          }}
        />
      )
  }
}

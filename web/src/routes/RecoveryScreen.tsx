// #128: the recovery flow -- username + recovery code + new password ->
// release() to fetch the wrapped private keys -> unwrap + re-wrap under new
// secrets in the worker (with a fresh recovery code) -> reset() to submit
// the new material and invalidate the redeemed code -> show the new
// recovery code -> done. The flow itself (normalizing the code, calling
// release/completeRecovery/reset in order, and classifying what each
// failure means) lives in runRecovery.ts, split out so it can be unit
// tested without jsdom (PR #129 round 2) -- this file wires that function
// to the real API/worker calls, owns the step-machine UI, and picks the
// user-facing copy for each error kind.
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
// response being lost after its write already committed (network drop,
// Lambda timeout) -- runRecovery's isDefinitelyUncommitted is what tells
// that case apart from every other reset() failure, which really is safe
// to retry from the top. The one moment that must not be interrupted is
// after reset() succeeds and before the new code is acknowledged --
// exactly parallel to SignupScreen's recoveryCode step, and guarded the
// same way (beforeunload).

import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router'
import {
  ApiError,
  recoveryCodeRelease,
  recoveryCodeReset,
  type RecoveryCodeReleaseResponse,
} from '@/lib/api/auth'
import { DecryptionFailedError } from '@/lib/crypto/aesgcm'
import { completeRecovery } from '@/lib/crypto/worker-client'
import type { RecoveryMaterial, SignupProgressEvent } from '@/lib/crypto/worker-protocol'
import { RecoveryCodeStep } from './RecoveryCodeStep'
import { RecoveryCredentialsStep } from './RecoveryCredentialsStep'
import { runRecovery, type RecoveryErrorKind } from './runRecovery'
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
// response was lost after the write already committed (see runRecovery's
// own comment on isDefinitelyUncommitted for why every 4xx it can return is
// excluded from reaching this message). The write, if it landed, also
// issued a new recovery code that this message can't hand back -- #124
// (lost-response retry idempotency) is the real fix; until then this at
// least tells the user their old code is gone and they need a new one.
const RESET_RESPONSE_LOST_ERROR =
  "We couldn't confirm whether your new password was saved. Try logging in with it before retrying recovery. If it worked, your recovery code was also reset -- generate a new one from your account settings once you're in."

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

/**
 * Whether err is an ApiError whose status recoveryCodeReset's own handler
 * (internal/handlers/recovery.go) proves happened before its write: every
 * 4xx there (400 validation, 401, 409) is returned before RewrapCredentials
 * ever runs, so those -- and the WAF's 403 -- definitely did not commit.
 * Only a non-ApiError (network failure, a lost response) or a 5xx (e.g. a
 * Lambda timeout surfacing after the write) is genuinely ambiguous. PR #129
 * round 2: RESET_RESPONSE_LOST_ERROR was reaching every non-401/409
 * failure, including ones like this that provably didn't commit.
 */
function isDefinitelyUncommitted(err: unknown): boolean {
  return err instanceof ApiError && err.status < 500
}

function errorMessageFor(kind: RecoveryErrorKind): string {
  switch (kind) {
    case 'credential':
      return CREDENTIAL_ERROR
    case 'staleVersion':
      return STALE_VERSION_ERROR
    case 'resetResponseLost':
      return RESET_RESPONSE_LOST_ERROR
    case 'unreachable':
      return UNREACHABLE_ERROR
  }
}

type Step =
  | { readonly name: 'credentials' }
  | { readonly name: 'releasing' }
  | {
      readonly name: 'recovering'
      readonly release: RecoveryCodeReleaseResponse
    }
  | { readonly name: 'resetting'; readonly material: RecoveryMaterial }
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

    void (async () => {
      const result = await runRecovery(
        {
          release: recoveryCodeRelease,
          completeRecovery,
          reset: recoveryCodeReset,
          isCredentialFailure,
          isStaleVersionConflict,
          isDefinitelyUncommitted,
          onProgress: (event) => {
            setProgress(event)
          },
          onStep: setStep,
        },
        username,
        enteredCode,
        newPassword,
      )

      if (!result.ok) {
        setError(errorMessageFor(result.kind))
        setStep({ name: 'credentials' })
        return
      }

      setStep({ name: 'recoveryCode', recoveryCode: result.material.recoveryCode })
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
          pendingLabel="Checking your recovery code…"
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

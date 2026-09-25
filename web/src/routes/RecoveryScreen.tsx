// #128: the recovery flow -- username + recovery code + new password ->
// release() to fetch the wrapped private keys -> unwrap + re-wrap under new
// secrets in the worker (with a fresh recovery code) -> reset() to submit
// the new material and invalidate the redeemed code -> show the new
// recovery code -> done. The flow itself (normalizing the code, calling
// release/completeRecovery/reset in order) and the error classifiers
// (isCredentialFailure/isStaleVersionConflict/isDefinitelyUncommitted) both
// live in runRecovery.ts, split out so they can be unit tested without
// jsdom and against real ApiError/DecryptionFailedError instances rather
// than stubs (PR #129 rounds 2 and 3) -- this file wires that function to
// the real API/worker calls, owns the step-machine UI, and picks the
// user-facing copy for each error kind.
//
// Every failure mode release()/reset() can return for an unknown username
// or wrong code comes back as resolveRecovery's single uniform "invalid
// username or recovery code" message (recovery.go's own doc comment: this
// endpoint has the same enumeration-resistance requirement /auth/challenge
// does for login). runRecovery.ts's isCredentialFailure collapses those the
// same way LoginScreen's own does, and this screen shows a distinct message
// for anything that is not a credential failure -- a network error or a 403
// from the WAF's rate-limit rule must not tell someone who typed the right
// code that it was wrong. reset()'s stale-credential-version case is NOT
// one of these uniform failures -- it's a distinct 409
// (errCredentialVersionStale, password.go), classified on its own.
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
//
// issue #130 closed the one dead end this flow used to have: a
// resetResponseLost failure used to be a plain message pointing at #131's
// change-password screen, discarding the material (and the new recovery
// code inside it) reset() may have just written server-side with no way
// back to it from here. runRecovery.ts's `resume` now lets this screen
// offer an actual retry -- resending the exact same reset() request,
// recognized server-side by its idempotency token -- instead of only that
// escape hatch. #131 remains the fallback if the retry itself also fails
// ambiguously twice in a row, or the user navigates away before retrying.

import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router'
import {
  recoveryCodeRelease,
  recoveryCodeReset,
  type RecoveryCodeReleaseResponse,
} from '@/lib/api/auth'
import { completeRecovery } from '@/lib/crypto/worker-client'
import type { RecoveryMaterial, SignupProgressEvent } from '@/lib/crypto/worker-protocol'
import { RecoveryCodeStep } from './RecoveryCodeStep'
import { RecoveryCredentialsStep } from './RecoveryCredentialsStep'
import { RecoveryRetryStep } from './RecoveryRetryStep'
import {
  generateIdempotencyToken,
  runRecovery,
  type PendingRecovery,
  type RecoveryErrorKind,
} from './runRecovery'
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
// excluded from reaching this message). RecoveryRetryStep is what offers
// the actual, safe retry now (issue #130) -- but the write may genuinely
// already have committed even before that retry runs, so this first
// message carries the same "your old code may be dead, Change password is
// the fallback" guidance the old dead-end message did, not just a generic
// "might be slow" reassurance -- a user who clicks Start Over (onGiveUp)
// instead of Try Again still needs to know that.
const RESET_RESPONSE_LOST_ERROR =
  "We couldn't confirm whether your new password was saved. Try again below -- it's safe to retry. If you'd rather not: try logging in with the new password first (your old recovery code may no longer work), or use Change password once you're in to get a fresh one."
// Shown if a retry ALSO fails ambiguously -- two lost responses in a row is
// unusual enough that pointing at #131's change-password screen (which
// re-reads the account's actual current state rather than guessing) is a
// better next step than a third blind retry, though Try Again is still
// offered below it.
const RESET_RETRY_FAILED_ERROR =
  "Still couldn't confirm it. Try logging in with your new password -- if it works, your old recovery code no longer does. Once you're in, use Change password to get a new one (you can keep the same password)."
// A retry's own reset() came back 401, but NOT because the code was wrong --
// reaching this classification (runRecovery.ts's own comment on
// 'retryConflict') already requires the verifier to have rotated away from
// this retry's code, and the server's own idempotency check found that
// rotation was not this attempt's own write. That means something else
// changed the account in between -- a genuinely different message from a
// plain wrong code, and pointing at #131 (which re-reads the account's
// actual current state) is more useful than a third blind retry here too.
const RETRY_CONFLICT_ERROR =
  "Your account's credentials changed before this could be confirmed. Try logging in with your original password, or with the new one you just set -- whichever works, use Change password from there to get a fresh recovery code."
// Shown on the credentials form after Start Over from RecoveryRetryStep --
// the write this screen could never confirm may still have committed, and
// that guidance must survive leaving the retry step, not just live in
// RESET_RESPONSE_LOST_ERROR's text while the user is looking at it.
const GAVE_UP_ON_RETRY_ERROR =
  "Starting over. If your last attempt's new password was actually saved, your old recovery code no longer works -- try logging in with the new password, or with the old one if that attempt didn't land, and use Change password to get a fresh code either way."

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
    case 'retryConflict':
      return RETRY_CONFLICT_ERROR
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
  | { readonly name: 'resetResponseLost'; readonly resume: PendingRecovery }
  | { readonly name: 'recoveryCode'; readonly recoveryCode: string }

export function RecoveryScreen() {
  const [step, setStep] = useState<Step>({ name: 'credentials' })
  const [progress, setProgress] = useState<SignupProgressEvent | null>(null)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  // Once reset() has committed a new recovery code, it lives only in
  // component state until the user acknowledges it -- same risk and same
  // guard as SignupScreen's recoveryCode step. resetResponseLost carries an
  // unconfirmed reset()'s material too (it may already be committed
  // server-side), so it gets the same protection: navigating away here
  // means the retry option -- and the new code, if the write actually
  // landed -- is gone for good, same as SignupScreen's own reasoning.
  useEffect(() => {
    if (step.name !== 'recoveryCode' && step.name !== 'resetResponseLost') {
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

  const runAttempt = (
    username: string,
    enteredCode: string,
    newPassword: string,
    resume?: PendingRecovery,
  ) => {
    setError(null)
    setStep(resume ? { name: 'resetting', material: resume.material } : { name: 'releasing' })
    setProgress(null)

    void (async () => {
      const result = await runRecovery(
        {
          release: recoveryCodeRelease,
          completeRecovery,
          reset: recoveryCodeReset,
          onProgress: (event) => {
            setProgress(event)
          },
          onStep: setStep,
          generateIdempotencyToken,
        },
        username,
        enteredCode,
        newPassword,
        resume,
      )

      if (!result.ok) {
        if (result.kind === 'resetResponseLost' && result.resume) {
          setStep({ name: 'resetResponseLost', resume: result.resume })
          // A retry that itself fails ambiguously a second time gets the
          // stronger message pointing at #131 instead of offering a third
          // blind retry -- resume from THIS failure is still attached to
          // the step, so RecoveryRetryStep's button keeps working, but the
          // text steers toward the more reliable path.
          setError(resume ? RESET_RETRY_FAILED_ERROR : RESET_RESPONSE_LOST_ERROR)
          return
        }
        setError(errorMessageFor(result.kind))
        setStep({ name: 'credentials' })
        return
      }

      setStep({ name: 'recoveryCode', recoveryCode: result.material.recoveryCode })
    })()
  }

  const handleCredentials = (username: string, enteredCode: string, newPassword: string) => {
    runAttempt(username, enteredCode, newPassword)
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
    case 'resetResponseLost':
      return (
        <RecoveryRetryStep
          message={error ?? RESET_RESPONSE_LOST_ERROR}
          onRetry={() => {
            runAttempt(
              step.resume.username,
              step.resume.recoveryCode,
              step.resume.newPassword,
              step.resume,
            )
          }}
          onGiveUp={() => {
            setError(GAVE_UP_ON_RETRY_ERROR)
            setStep({ name: 'credentials' })
          }}
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

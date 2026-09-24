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
// issued a new recovery code that this message can't hand back. #130
// (idempotent retry for this write) is still open, but #131 (the logged-in
// change-password/new-recovery-code screen, ChangePasswordScreen.tsx) now
// exists, so this message can point there for the one thing it can't hand
// back directly -- round 3 of PR #129's review caught an earlier draft
// claiming "your account settings" before #131 existed at all, and PR #132
// review caught this draft still not naming the real entry point (the
// Change password button on Home) or saying that changing your password,
// specifically, is how you get a new code.
const RESET_RESPONSE_LOST_ERROR =
  "We couldn't confirm whether your new password was saved. Try logging in with it before retrying recovery. If it works, your old recovery code no longer does. Once you're in, use Change password to get a new one (you can keep the same password)."

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

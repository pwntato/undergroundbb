// #131: the logged-in change-password / new-recovery-code screen. Closes
// the gap RecoveryScreen's own RESET_RESPONSE_LOST_ERROR copy points at
// ("use Change password to get a new one") -- that page didn't exist before
// this file, and "Change password" is this screen's own entry point on
// Home. It's also the natural place for routine credential rotation
// generally, independent of that lost-response edge case (see issue #131's
// own body).
//
// Shaped closely after RecoveryScreen: a credentials step, a progress step
// reusing SignupProgressStep, and the same RecoveryCodeStep for the newly
// issued code -- see runChangePassword.ts's own header comment for how the
// flow itself (and its error classification) mirrors runRecovery.ts, and
// where it genuinely differs (no server-side old-password check to fail
// on).
//
// Unlike RecoveryScreen, this screen requires an existing session --
// SessionContext's own doc comment is explicit that its userId does not
// survive a reload and is not authentication's source of truth, so this
// screen does not gate on it. Instead the initial GET
// /api/account/credentials call (which it needs to run anyway, to bootstrap
// the unwrap) doubles as the real auth check: a 401 sends the visitor to
// /login exactly as if a protected page had rejected them, rather than
// this screen trusting client-side session state it cannot rely on.

import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router'
import {
  ApiError,
  changePassword,
  getAccountCredentials,
  type AccountCredentialsResponse,
} from '@/lib/api/auth'
import { completeChangePassword } from '@/lib/crypto/worker-client'
import type { ChangePasswordMaterial, SignupProgressEvent } from '@/lib/crypto/worker-protocol'
import { ChangePasswordCredentialsStep } from './ChangePasswordCredentialsStep'
import { RecoveryCodeStep } from './RecoveryCodeStep'
import { runChangePassword, type ChangePasswordErrorKind } from './runChangePassword'
import { SignupProgressStep } from './SignupProgressStep'

const CREDENTIAL_ERROR = 'Your current password is incorrect.'
const UNREACHABLE_ERROR = "Couldn't reach the server. Try again."
const STALE_VERSION_ERROR =
  "Your account's credentials changed while this was in progress. Please try again."
// Mirrors RecoveryScreen's RESET_RESPONSE_LOST_ERROR, but for a caller who
// is (and remains) logged in: unlike recovery, there is no separate
// "use Change password" fallback to point at -- this IS that screen -- so
// the only safe advice is to come back and retry. PR #132 review caught an
// earlier draft that didn't say WHICH password to retry with: if the first
// attempt's write actually landed, the account's current password is now
// the NEW one, not the one just typed into "Current password" -- a retry
// with the old one would fail here with CREDENTIAL_ERROR, which is
// confusing without this context (the account is fine; the field just
// needs the other password).
const CHANGE_RESPONSE_LOST_ERROR =
  "We couldn't confirm whether your new password was saved. Try logging in with it in another tab before retrying. If it works, your old recovery code no longer does -- retry here using your NEW password as the current one, to get a new code."

function errorMessageFor(kind: ChangePasswordErrorKind): string {
  switch (kind) {
    case 'credential':
      return CREDENTIAL_ERROR
    case 'staleVersion':
      return STALE_VERSION_ERROR
    case 'changeResponseLost':
      return CHANGE_RESPONSE_LOST_ERROR
    case 'unreachable':
      return UNREACHABLE_ERROR
  }
}

type Step =
  | { readonly name: 'loadingCredentials' }
  | { readonly name: 'authRequired' }
  | { readonly name: 'credentials' }
  | { readonly name: 'changing'; readonly credentials: AccountCredentialsResponse }
  | { readonly name: 'committing'; readonly material: ChangePasswordMaterial }
  | { readonly name: 'recoveryCode'; readonly recoveryCode: string }

export function ChangePasswordScreen() {
  const [step, setStep] = useState<Step>({ name: 'loadingCredentials' })
  const [progress, setProgress] = useState<SignupProgressEvent | null>(null)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  // The initial auth check -- see this file's own header comment for why a
  // 401 here, not SessionContext, is what sends an unauthenticated visitor
  // to /login. A non-401 failure (network, 5xx) is left on this step with
  // an error rather than redirected, since redirecting to /login for an
  // outage would be actively misleading about why the screen isn't working.
  useEffect(() => {
    if (step.name !== 'loadingCredentials') {
      return
    }
    let cancelled = false
    void (async () => {
      try {
        await getAccountCredentials()
        if (!cancelled) {
          setStep({ name: 'credentials' })
        }
      } catch (err) {
        if (cancelled) {
          return
        }
        if (err instanceof ApiError && err.status === 401) {
          setStep({ name: 'authRequired' })
          return
        }
        setError(UNREACHABLE_ERROR)
        setStep({ name: 'credentials' })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [step.name])

  useEffect(() => {
    if (step.name !== 'authRequired') {
      return
    }
    navigate('/login', { replace: true })
  }, [step.name, navigate])

  // Once changePassword() has committed a new recovery code, it lives only
  // in component state until the user acknowledges it -- same risk and same
  // guard as SignupScreen/RecoveryScreen's own recoveryCode step.
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

  const handleCredentials = (oldPassword: string, newPassword: string) => {
    setError(null)
    setProgress(null)

    void (async () => {
      const result = await runChangePassword(
        {
          getCredentials: getAccountCredentials,
          completeChangePassword,
          changePassword,
          onProgress: (event) => {
            setProgress(event)
          },
          onStep: setStep,
        },
        oldPassword,
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
    case 'loadingCredentials':
    case 'authRequired':
      // authRequired renders nothing of its own -- the effect above
      // redirects to /login on the same tick this case would otherwise
      // render for.
      return (
        <SignupProgressStep
          progress={null}
          initialTotalSteps={4}
          leadingStep="Confirming your session…"
          trailingStep="Saving your new password…"
          currentStep="leading"
          heading="Loading"
        />
      )
    case 'credentials':
      return <ChangePasswordCredentialsStep onSubmit={handleCredentials} error={error} />
    case 'changing':
      return (
        <SignupProgressStep
          progress={progress}
          initialTotalSteps={4}
          leadingStep="Confirming your session…"
          trailingStep="Saving your new password…"
          heading="Changing your password"
          pendingLabel="Checking your current password…"
        />
      )
    case 'committing':
      return (
        <SignupProgressStep
          progress={progress}
          initialTotalSteps={4}
          leadingStep="Confirming your session…"
          trailingStep="Saving your new password…"
          currentStep="trailing"
          heading="Changing your password"
        />
      )
    case 'recoveryCode':
      return (
        <RecoveryCodeStep
          recoveryCode={step.recoveryCode}
          onAcknowledged={() => {
            navigate('/', { replace: true })
          }}
        />
      )
  }
}

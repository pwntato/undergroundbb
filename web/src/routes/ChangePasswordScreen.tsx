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
// Unlike RecoveryScreen, this screen requires an existing session. #32 added
// a RequireAuth wrapper around this route (App.tsx), so a visitor with no
// session at all never reaches this component -- but this screen's own
// bootstrap check below is not redundant with that: SessionContext can go
// stale the instant a session expires mid-visit, after RequireAuth's own
// one-time check already passed, which RequireAuth (checked once, on mount)
// cannot catch. The initial GET /api/account/credentials call (which this
// screen needs to run anyway, to bootstrap the unwrap) doubles as that real,
// live auth check: a 401 sends the visitor to /login exactly as if
// RequireAuth had rejected them itself, rather than this screen trusting
// client-side session state that can be wrong. See its own effect below for
// why that path also calls session.logout() -- reviewer-caught on #32's own
// PR, without it RedirectIfAuthenticated on /login bounces straight back
// here on stale session state.

import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import {
  ApiError,
  changePassword,
  getAccountCredentials,
  type AccountCredentialsResponse,
} from '@/lib/api/auth'
import { completeChangePassword } from '@/lib/crypto/worker-client'
import type { ChangePasswordMaterial, SignupProgressEvent } from '@/lib/crypto/worker-protocol'
import { useSession } from '@/lib/session/useSession'
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
// the only safe advice is to come back and retry. PR #132 round 1 caught an
// earlier draft that didn't say WHICH password to retry with: if the first
// attempt's write actually landed, the account's current password is now
// the NEW one, not the one just typed into "Current password" -- a retry
// with the old one would fail here with CREDENTIAL_ERROR, which is
// confusing without this context (the account is fine; the field just
// needs the other password). Round 2 caught that fix putting a "--" back
// into user-facing text -- the same thing round 1 had just removed from
// RESET_RESPONSE_LOST_ERROR.
const CHANGE_RESPONSE_LOST_ERROR =
  "We couldn't confirm whether your new password was saved. Try logging in with it in another tab before retrying. If it works, your old recovery code no longer does. Retry here using your NEW password as the current one, to get a new code."

// Takes every ChangePasswordErrorKind except 'authRequired' -- that one is
// intercepted in handleCredentials before this is ever called (it routes to
// the 'authRequired' step instead of a text error), so excluding it here
// makes that a type-level guarantee: a future kind added to the real union
// without a matching case fails this switch's exhaustiveness check, but
// 'authRequired' itself can never reach here to begin with.
function errorMessageFor(kind: Exclude<ChangePasswordErrorKind, 'authRequired'>): string {
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
  | { readonly name: 'submitting' }
  | { readonly name: 'changing'; readonly credentials: AccountCredentialsResponse }
  | { readonly name: 'committing'; readonly material: ChangePasswordMaterial }
  | { readonly name: 'recoveryCode'; readonly recoveryCode: string }

export function ChangePasswordScreen() {
  const [step, setStep] = useState<Step>({ name: 'loadingCredentials' })
  const [progress, setProgress] = useState<SignupProgressEvent | null>(null)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()
  const session = useSession()
  // See the authRequired effect below for why this exists: it is only ever
  // read/written inside that effect, never during render, so (unlike an
  // earlier draft of RedirectIfAuthenticated's own fix) there's no unsound
  // ref-read-during-render here for oxlint's react-hooks(refs) rule to catch.
  const loggedOutRef = useRef(false)

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
    if (step.name !== 'authRequired' || loggedOutRef.current) {
      return
    }
    // Reviewer-caught, #32's own PR: without this, SessionContext still
    // holds the now-stale userId from before the session expired, so
    // RedirectIfAuthenticated on /login sees an "authenticated" session and
    // bounces straight back to /, which then confusingly claims "You're
    // logged in" to a visitor whose session just failed. session.logout()
    // makes this navigation land on the real login form instead of dead-
    // ending in that loop.
    //
    // loggedOutRef guards against this effect re-running itself: it depends
    // on session (correctly, per exhaustive-deps -- session.logout is what
    // it calls), but session.logout() changes SessionContext's value
    // identity (see its own useMemo), which would otherwise re-fire this
    // same effect and call logout()/navigate() again. Both calls are
    // individually idempotent, but the ref keeps this an intentional
    // once-per-screen-visit effect rather than a self-triggering loop that
    // merely happens to be harmless.
    loggedOutRef.current = true
    session.logout()
    navigate('/login', { replace: true })
  }, [step.name, navigate, session])

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

  // Sets 'submitting' synchronously, before anything async -- PR #132 round
  // 2 caught that this screen stayed on the 'credentials' step (form still
  // mounted, Continue never disabled) until runChangePassword's first
  // await resolved, so a double Enter/click started two full runs. Both
  // read the same credentialVersion, both PUTs went out, the first
  // committed and the second's 409 arrived last, overwriting the
  // recoveryCode step with STALE_VERSION_ERROR -- the committed code was
  // never shown, and the error's "try again" advice made it worse (the old
  // password no longer works either). This can't reuse 'loadingCredentials'
  // -- that step's own effect would re-fire and its setStep({name:
  // 'credentials'}) would override this flow partway through -- so it gets
  // its own step, rendered the same way.
  const handleCredentials = (oldPassword: string, newPassword: string) => {
    setError(null)
    setProgress(null)
    setStep({ name: 'submitting' })

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
        // authRequired routes through the same 'authRequired' step (and the
        // same redirect-to-/login effect) as the bootstrap check, rather
        // than a text error on the credentials step -- PR #132 round 2: a
        // session that expired mid-submit deserves the same handling as
        // one that was already gone when the screen loaded, not
        // UNREACHABLE_ERROR's "couldn't reach the server," which is both
        // wrong and a dead end (retrying keeps failing the same way).
        if (result.kind === 'authRequired') {
          setStep({ name: 'authRequired' })
          return
        }
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
    case 'submitting':
      // Rendered for the one tick between the Continue click and
      // runChangePassword's own first onStep -- same shape as
      // 'loadingCredentials', so there's no visible flicker between them.
      return (
        <SignupProgressStep
          progress={null}
          initialTotalSteps={4}
          leadingStep="Confirming your session…"
          trailingStep="Saving your new password…"
          currentStep="leading"
          heading="Changing your password"
        />
      )
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

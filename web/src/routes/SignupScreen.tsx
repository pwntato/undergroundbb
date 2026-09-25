// #33's signup flow: username/password -> key generation with progress ->
// recovery code (RecoveryCodeStep enforces its own "must not be skimmed"
// requirement) -> theme picker, skippable -> done. The actual work
// (register -> login) is runSignup.ts, a plain function pulled out for the
// same reason runRecovery.ts and runChangePassword.ts were: it can be unit
// tested against real ApiError instances without jsdom or a real worker.
//
// The user uuid is generated in runSignup, before the worker call, per
// #123: the credential-wrap AAD binds it, so it must exist before wrapping,
// and register() sends it back to the server as-is rather than receiving
// one.
//
// register() only creates the account -- it does not establish a session.
// Only POST /api/auth/verify sets the session cookie
// (internal/handlers/login.go:279 is the only SetCookie in internal/), so
// runSignup runs a full login (challenge -> worker unwrap/sign -> verify)
// immediately after register succeeds, using the same password. session's
// onLogin dep is only called once verify actually succeeds -- never on
// register's response alone, which would put the UI in a logged-in state
// with no session behind it.
//
// register() and the post-register login are two SEPARATE try blocks
// inside runSignup, not one -- this is load-bearing, not stylistic. Once
// register() resolves, the account exists server-side with a real recovery
// code that will never be shown again if anything after this point throws
// it away (round-2 review: realistic causes include the WAF's 30 req/5min
// /api/auth/* rule -- signup already spends 3 of those, login spends a
// 4th -- a 64 MiB Argon2id OOM on a low-memory phone, the exact case
// worker-client.ts's error/messageerror handling plans for, or ordinary
// network flakiness between requests). So a failure in
// challenge/completeLogin/verify must still reach the recoveryCode step
// with the material register() already produced, never discard it and
// bounce back to the credentials form (which would also re-submit a
// now-taken username and 409). If login fails, the user still proceeds
// through recoveryCode and theme, then lands on /login instead of Home with
// a note that their account exists and they should log in -- they can
// always retry login themselves with the password they just chose, but
// nobody can ever retry showing them the code.
//
// pendingSignup (issue #124) holds the full identity AND SignupMaterial from
// an ambiguous register() failure (network error or 5xx -- runSignup's own
// isDefinitelyUncommitted) so that if the SAME username AND password are
// resubmitted, the retry resends the exact same request rather than
// generating a fresh UserID and material. Resending it unchanged is what
// lets internal/db/register.go's own #124 fix recognize the retry as this
// caller's own earlier, possibly-already-committed write instead of a
// genuine username conflict -- see runSignup.ts's own header comment (PR
// #133 round 1) for why "exact," not just "same username," is load-bearing:
// regenerating even a single field defeats the point, since the server
// would then be confirming credentials that were never actually stored. A
// different username is a new signup attempt and gets no resume at all.
//
// The same username with a DIFFERENT password is also not resumed as a
// request -- runSignup still generates fresh material and lets that attempt
// stand or fail on its own -- but pendingSignup is still handed to runSignup
// as a candidate (see handleCredentials below), because of issue #134: if
// that fresh attempt comes back with username_taken, it means the FIRST
// attempt (the one pendingSignup is from) already committed, and the user
// most likely mistyped or is unsure which password they used the first
// time. runSignup echoes pendingSignup back unchanged in exactly that case
// (see its own doc comment) so handleCredentials can keep it alive and
// point the user back to their original password instead of silently
// converging on a permanently unrecoverable account -- see its own header
// comment in SignupResult and the "Suggested fix" in issue #134 itself.

import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router'
import { challenge, register, verify } from '@/lib/api/auth'
import { generateUserID } from '@/lib/crypto/uuid'
import { completeLogin, generateSignupMaterial } from '@/lib/crypto/worker-client'
import type { SignupMaterial, SignupProgressEvent } from '@/lib/crypto/worker-protocol'
import { useSession } from '@/lib/session/useSession'
import { RecoveryCodeStep } from './RecoveryCodeStep'
import { SignupCredentialsStep } from './SignupCredentialsStep'
import { SignupProgressStep } from './SignupProgressStep'
import { ThemePickerStep } from './ThemePickerStep'
import { runSignup, signupErrorMessage, type PendingSignup } from './runSignup'

type Step =
  | { readonly name: 'credentials' }
  | { readonly name: 'generating' }
  | { readonly name: 'loggingIn'; readonly material: SignupMaterial }
  | { readonly name: 'recoveryCode'; readonly material: SignupMaterial; readonly loggedIn: boolean }
  | { readonly name: 'theme'; readonly loggedIn: boolean }

export function SignupScreen() {
  const [step, setStep] = useState<Step>({ name: 'credentials' })
  const [progress, setProgress] = useState<SignupProgressEvent | null>(null)
  const [error, setError] = useState<string | null>(null)
  // See this file's own header comment on #124: only ever set from an
  // ambiguous register() failure, and only ever consulted (by runSignup
  // itself, which re-checks both username AND password -- see its own
  // header comment on PR #133 round 1) when the next submission matches it
  // exactly. It holds a plaintext password and a not-yet-shown recovery
  // code -- review non-blocking finding #4 asked that this be cleared on
  // unmount, but that's a no-op in React: unmounting discards the
  // component's state (this included) regardless of what a cleanup
  // function does, since there is no later render for a stale setState to
  // reach. Its actual lifetime is already bounded to this component
  // existing at all -- there is no route away from /signup that leaves
  // SignupScreen mounted with this state still reachable.
  const [pendingSignup, setPendingSignup] = useState<PendingSignup | null>(null)
  const session = useSession()
  const navigate = useNavigate()

  // The account is registered (and the recovery code generated) before this
  // screen shows it -- it lives only in component state until the user
  // acknowledges it. A reload, back button, or closed tab during this step
  // (or loggingIn, which follows the same already-registered account)
  // leaves a real, already-created account whose recovery code nobody will
  // ever see again (the server never stores it in the clear -- only its
  // Argon2id verifier -- and there is no "resend" for something that was
  // never sent). This covers the accidental cases; it can't stop a
  // deliberate close, which no beforeunload prompt can.
  useEffect(() => {
    if (step.name !== 'loggingIn' && step.name !== 'recoveryCode') {
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

  const handleCredentials = (username: string, password: string) => {
    setError(null)
    setStep({ name: 'generating' })
    setProgress(null)

    // See this file's own header comment on #124/#134: hand pendingSignup
    // to runSignup as a CANDIDATE whenever the username matches, even if
    // the password doesn't -- runSignup itself decides whether to actually
    // resend it as this request's material (only on an exact match) versus
    // merely echo it back unchanged if a username_taken 409 shows the first
    // attempt already committed (#134).
    const resume = pendingSignup?.username === username ? pendingSignup : undefined

    void (async () => {
      const result = await runSignup(
        {
          generateUserID,
          generateSignupMaterial,
          register,
          challenge,
          completeLogin,
          verify,
          onProgress: (event) => {
            setProgress(event)
          },
          onRegistered: (material) => {
            setStep({ name: 'loggingIn', material })
          },
          onLogin: (userId) => {
            session.login(userId)
          },
        },
        username,
        password,
        resume,
      )

      if (!result.ok) {
        // See runSignup's own isDefinitelyUncommitted for the distinction:
        // a definite 4xx normally means nothing committed and there's no
        // identity worth preserving (a real conflict resending it would
        // just collide again); an ambiguous failure means register()'s
        // write may have landed, so the full identity + material runSignup
        // returned are kept, to resend unchanged on a matching retry.
        // Issue #134's exception -- a 'definitelyUncommitted' result CAN
        // also carry a resume worth keeping -- lives in, and is tested via,
        // signupErrorMessage's own doc comment.
        setPendingSignup(result.resume ?? null)
        setError(signupErrorMessage(result))
        setStep({ name: 'credentials' })
        return
      }

      setPendingSignup(null)
      setStep({ name: 'recoveryCode', material: result.material, loggedIn: result.loggedIn })
    })()
  }

  switch (step.name) {
    case 'credentials':
      return <SignupCredentialsStep onSubmit={handleCredentials} error={error} />
    case 'generating':
      return <SignupProgressStep progress={progress} trailingStep="Logging you in…" />
    case 'loggingIn':
      return (
        <SignupProgressStep
          progress={progress}
          trailingStep="Logging you in…"
          currentStep="trailing"
        />
      )
    case 'recoveryCode':
      return (
        <RecoveryCodeStep
          recoveryCode={step.material.recoveryCode}
          onAcknowledged={() => {
            setStep({ name: 'theme', loggedIn: step.loggedIn })
          }}
        />
      )
    case 'theme':
      return (
        <ThemePickerStep
          onDone={() => {
            if (step.loggedIn) {
              navigate('/', { replace: true })
              return
            }
            // Login failed earlier despite the account existing -- send
            // them to log in for real rather than Home, which would show
            // an unauthenticated user "You're logged in" was never true
            // for. See this file's own header comment.
            navigate('/login?accountCreated=1', { replace: true })
          }}
        />
      )
  }
}

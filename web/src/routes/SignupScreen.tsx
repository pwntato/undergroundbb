// #33's signup flow: username/password -> key generation with progress ->
// recovery code (RecoveryCodeStep enforces its own "must not be skimmed"
// requirement) -> theme picker, skippable -> done.
//
// The user uuid is generated here, before the worker call, per #123: the
// credential-wrap AAD binds it, so it must exist before wrapping, and
// register() sends it back to the server as-is rather than receiving one.
//
// register() only creates the account -- it does not establish a session.
// Only POST /api/auth/verify sets the session cookie
// (internal/handlers/login.go:279 is the only SetCookie in internal/), so
// signup runs a full login (challenge -> worker unwrap/sign -> verify)
// immediately after register succeeds, using the same password still held
// in this closure. session.login() is only called once verify actually
// succeeds -- never on register's response alone, which would put the UI
// in a logged-in state with no session behind it.
//
// register() and the post-register login are two SEPARATE try blocks, not
// one -- this is load-bearing, not stylistic. Once register() resolves, the
// account exists server-side with a real recovery code that will never be
// shown again if anything after this point throws it away (round-2 review:
// realistic causes include the WAF's 30 req/5min /api/auth/* rule -- signup
// already spends 3 of those, login spends a 4th -- a 64 MiB Argon2id OOM on
// a low-memory phone, the exact case worker-client.ts's error/messageerror
// handling plans for, or ordinary network flakiness between requests). So a
// failure in challenge/completeLogin/verify must still reach the
// recoveryCode step with the material register() already produced, never
// discard it and bounce back to the credentials form (which would also
// re-submit a now-taken username and 409). If login fails, the user still
// proceeds through recoveryCode and theme, then lands on /login instead of
// Home with a note that their account exists and they should log in --
// they can always retry login themselves with the password they just
// chose, but nobody can ever retry showing them the code.

import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router'
import { ApiError, challenge, register, verify } from '@/lib/api/auth'
import { generateUserID } from '@/lib/crypto/uuid'
import { completeLogin, generateSignupMaterial } from '@/lib/crypto/worker-client'
import type { SignupMaterial, SignupProgressEvent } from '@/lib/crypto/worker-protocol'
import { useSession } from '@/lib/session/useSession'
import { RecoveryCodeStep } from './RecoveryCodeStep'
import { SignupCredentialsStep } from './SignupCredentialsStep'
import { SignupProgressStep } from './SignupProgressStep'
import { ThemePickerStep } from './ThemePickerStep'

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

    void (async () => {
      let material: SignupMaterial
      try {
        const userId = generateUserID()
        material = await generateSignupMaterial(password, userId, (event) => {
          setProgress(event)
        })
        await register({
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
        // register() itself failed -- no account exists, nothing to
        // preserve, safe to bounce back to the credentials form exactly
        // like before. (Unless the response was merely lost after the
        // write committed -- see #124. That's a distinct, narrower bug:
        // this catch still can't tell that case apart from a real 4xx.)
        setError(
          err instanceof ApiError && err.status !== 403
            ? err.message
            : 'Could not create your account. Try again.',
        )
        setStep({ name: 'credentials' })
        return
      }

      // The account now exists server-side. Everything from here on is a
      // SEPARATE try: whatever happens, the user must still reach
      // recoveryCode with this material -- see this file's own header
      // comment.
      setStep({ name: 'loggingIn', material })
      let loggedIn = false
      try {
        const ch = await challenge(username)
        const signature = await completeLogin({
          password,
          salt: ch.salt,
          argon2Params: ch.argon2Params,
          wrappedPrivateKeys: ch.wrappedPrivateKeys,
          userId: ch.userId,
          nonce: ch.nonce,
        })
        const result = await verify(username, ch.nonce, signature)
        session.login(result.userId)
        loggedIn = true
      } catch {
        // Login failed after the account was already created -- the user
        // can always retry logging in themselves afterward with the
        // password they just chose. What must not happen is losing the
        // recovery code over this, so loggedIn stays false and the flow
        // continues exactly as it would have on success.
      }

      setStep({ name: 'recoveryCode', material, loggedIn })
    })()
  }

  switch (step.name) {
    case 'credentials':
      return <SignupCredentialsStep onSubmit={handleCredentials} error={error} />
    case 'generating':
      return <SignupProgressStep progress={progress} />
    case 'loggingIn':
      return <SignupProgressStep progress={progress} loggingIn />
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

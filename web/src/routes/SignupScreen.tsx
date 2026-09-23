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
  | { readonly name: 'loggingIn' }
  | { readonly name: 'recoveryCode'; readonly material: SignupMaterial }
  | { readonly name: 'theme' }

export function SignupScreen() {
  const [step, setStep] = useState<Step>({ name: 'credentials' })
  const [progress, setProgress] = useState<SignupProgressEvent | null>(null)
  const [error, setError] = useState<string | null>(null)
  const session = useSession()
  const navigate = useNavigate()

  // The account is registered (and the recovery code generated) before this
  // screen shows it -- it lives only in component state until the user
  // acknowledges it. A reload, back button, or closed tab during this step
  // leaves a real, already-created account whose recovery code nobody will
  // ever see again (the server never stores it in the clear -- only its
  // Argon2id verifier -- and there is no "resend" for something that was
  // never sent). This covers the accidental cases; it can't stop a
  // deliberate close, which no beforeunload prompt can.
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

  const handleCredentials = (username: string, password: string) => {
    setError(null)
    setStep({ name: 'generating' })
    setProgress(null)

    void (async () => {
      try {
        const userId = generateUserID()
        const material = await generateSignupMaterial(password, userId, (event) => {
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

        setStep({ name: 'loggingIn' })
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

        setStep({ name: 'recoveryCode', material })
      } catch (err) {
        setError(
          err instanceof ApiError ? err.message : 'Could not create your account. Try again.',
        )
        setStep({ name: 'credentials' })
      }
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
            setStep({ name: 'theme' })
          }}
        />
      )
    case 'theme':
      return (
        <ThemePickerStep
          onDone={() => {
            navigate('/', { replace: true })
          }}
        />
      )
  }
}

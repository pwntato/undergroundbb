// #33's signup flow: username/password -> key generation with progress ->
// recovery code (RecoveryCodeStep enforces its own "must not be skimmed"
// requirement) -> theme picker, skippable -> done.
//
// The user uuid is generated here, before the worker call, per #123: the
// credential-wrap AAD binds it, so it must exist before wrapping, and
// register() sends it back to the server as-is rather than receiving one.

import { useState } from 'react'
import { useNavigate } from 'react-router'
import { ApiError, register } from '@/lib/api/auth'
import { generateUserID } from '@/lib/crypto/uuid'
import { generateSignupMaterial } from '@/lib/crypto/worker-client'
import type { SignupMaterial, SignupProgressEvent } from '@/lib/crypto/worker-protocol'
import { useSession } from '@/lib/session/useSession'
import { RecoveryCodeStep } from './RecoveryCodeStep'
import { SignupCredentialsStep } from './SignupCredentialsStep'
import { SignupProgressStep } from './SignupProgressStep'
import { ThemePickerStep } from './ThemePickerStep'

type Step =
  | { readonly name: 'credentials' }
  | { readonly name: 'generating' }
  | { readonly name: 'recoveryCode'; readonly material: SignupMaterial }
  | { readonly name: 'theme' }

export function SignupScreen() {
  const [step, setStep] = useState<Step>({ name: 'credentials' })
  const [progress, setProgress] = useState<SignupProgressEvent | null>(null)
  const [error, setError] = useState<string | null>(null)
  const session = useSession()
  const navigate = useNavigate()

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
        session.login(userId)
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

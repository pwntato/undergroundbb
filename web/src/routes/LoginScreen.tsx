// Login step 1-4 per docs/DESIGN.md: challenge -> derive/unwrap/sign in the
// worker -> verify. challengeResponse.userId (issue #125) is what makes
// step 3 possible at all for a fresh device with no prior session -- see
// worker.ts's completeLogin, which needs the uuid to build
// credentialWrapAAD before it can unwrap.
//
// A wrong password and an unknown username surface the same way here: both
// fail inside completeLogin (GCM tag mismatch) or at verify with the same
// verifyErrorChallengeInvalid message the server deliberately uses for
// both, so this screen has nothing more specific to say either -- showing a
// distinct "no such user" error here would undo the server's own
// enumeration defense.

import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { ApiError, challenge, verify } from '@/lib/api/auth'
import { DecryptionFailedError } from '@/lib/crypto/aesgcm'
import { completeLogin } from '@/lib/crypto/worker-client'
import { useSession } from '@/lib/session/useSession'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const CREDENTIAL_ERROR = 'Incorrect username or password.'
const UNREACHABLE_ERROR = "Couldn't reach the server. Try again."

/**
 * Reports whether err is one of login's credential-failure modes: a bad
 * password (DecryptionFailedError, thrown inside completeLogin's unwrap)
 * or verify's 400/401 (bad signature, stale/replayed/missing challenge, or
 * an unknown username mapped to the same response -- see verify's own
 * server-side doc comment). Anything else -- a network failure, a 5xx, or
 * a 403 from terraform/waf.tf's /api/auth/* rate-limit rule (a `block {}`
 * action, which WAF returns as a 403 with an HTML body -- there is no 429
 * anywhere in this stack) -- is NOT a credential failure: showing
 * CREDENTIAL_ERROR for those would tell someone who typed their password
 * correctly that it was wrong, which risks sending them to recovery over an
 * outage rather than a real mistake.
 */
function isCredentialFailure(err: unknown): boolean {
  if (err instanceof DecryptionFailedError) {
    return true
  }
  if (err instanceof ApiError) {
    return err.status === 400 || err.status === 401
  }
  return false
}

export function LoginScreen() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const session = useSession()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  // Set by SignupScreen when the account was created but the automatic
  // post-signup login failed -- see that file's own header comment. The
  // account is real and the password the user just chose is correct; only
  // the session establishment failed, so this is reassurance, not an error.
  const accountCreated = searchParams.get('accountCreated') === '1'
  // Set by RecoveryScreen (#128) once its own recoveryCode step is
  // acknowledged -- the account now has a new password and a new recovery
  // code; this is reassurance, same as accountCreated above.
  const recoveryComplete = searchParams.get('recoveryComplete') === '1'

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setSubmitting(true)

    void (async () => {
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
        navigate('/', { replace: true })
      } catch (err) {
        // Every real credential-failure mode -- unknown username, wrong
        // password (fails inside the worker's decrypt), wrong signature, a
        // stale challenge -- collapses to CREDENTIAL_ERROR. See this file's
        // own header comment for why that's deliberate, not a missed
        // distinction. Everything else (network failure, 5xx, a 403 from
        // the WAF's rate-limit rule) gets UNREACHABLE_ERROR instead -- see
        // isCredentialFailure's own doc comment for why conflating the two
        // is worse than showing a slightly less specific message.
        setError(isCredentialFailure(err) ? CREDENTIAL_ERROR : UNREACHABLE_ERROR)
      } finally {
        setSubmitting(false)
      }
    })()
  }

  return (
    <form onSubmit={handleSubmit} className="flex w-full max-w-sm flex-col gap-4">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Log in</h1>
      </div>
      {accountCreated && !error && (
        <Alert>
          <AlertDescription>Your account was created. Please log in.</AlertDescription>
        </Alert>
      )}
      {recoveryComplete && !error && (
        <Alert>
          <AlertDescription>
            Your account was recovered. Please log in with your new password.
          </AlertDescription>
        </Alert>
      )}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-col gap-2">
        <Label htmlFor="login-username">Username</Label>
        <Input
          id="login-username"
          autoComplete="username"
          value={username}
          onChange={(e) => {
            setUsername(e.target.value)
          }}
          required
        />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="login-password">Password</Label>
        <Input
          id="login-password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => {
            setPassword(e.target.value)
          }}
          required
        />
      </div>
      <Button type="submit" disabled={submitting}>
        {submitting ? 'Logging in…' : 'Log in'}
      </Button>
      <Link to="/recovery" className="text-center text-sm text-muted-foreground underline">
        Forgot your password?
      </Link>
    </form>
  )
}

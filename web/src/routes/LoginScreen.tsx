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
import { useNavigate } from 'react-router'
import { challenge, verify } from '@/lib/api/auth'
import { completeLogin } from '@/lib/crypto/worker-client'
import { useSession } from '@/lib/session/useSession'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const GENERIC_LOGIN_ERROR = 'Incorrect username or password.'

export function LoginScreen() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const session = useSession()
  const navigate = useNavigate()

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
      } catch {
        // Every failure mode here -- unknown username, wrong password
        // (fails inside the worker's decrypt), wrong signature, a stale
        // challenge -- collapses to the same generic message. See this
        // file's own header comment for why that's deliberate, not a
        // missed distinction.
        setError(GENERIC_LOGIN_ERROR)
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
    </form>
  )
}

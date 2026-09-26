// PR #142 review, blocking finding #3: CreateGroupScreen's own liveKeys
// cache lives only in the crypto worker's module scope (worker.ts's own
// doc comment), so a reload, a closed tab, a new tab, or a deploy clears it
// while the session cookie stays valid -- RequireAuth and even a fresh
// createGroup call would both still pass. Before this step existed, the
// screen told the user to "log in again on this tab," but /login is wrapped
// in RedirectIfAuthenticated (App.tsx), which bounces an authenticated
// visitor straight back to /, and there is no logout UI yet
// (SessionContext.tsx's own doc comment) -- so there was no way out short
// of the session cookie itself expiring.
//
// This step re-runs login's own unwrap (challenge -> completeLogin) INLINE,
// without creating a new session or navigating anywhere, purely to
// repopulate the worker's liveKeys cache -- the reviewer's own suggested
// "cleaner option," since it also covers every future signing screen that
// hits the same cold-cache case, not just group creation. It asks for
// username as well as password: nothing in this tab's session state
// remembers which username is logged in (SessionContext only ever tracked
// userId, per issue #32), and adding that would be its own, separate
// change -- see this file's header comment in the PR review reply for why
// that's out of scope here.
//
// challenge()'s response carries userId, which is checked against the
// already-logged-in session's userId before completeLogin ever runs: this
// step exists to recover THIS account's keys, not to let a visitor type in
// a different account's credentials and quietly sign as them while still
// looking like the original session in the UI.

import { useState, type FormEvent } from 'react'
import { ApiError, challenge } from '@/lib/api/auth'
import { DecryptionFailedError } from '@/lib/crypto/aesgcm'
import { completeLogin } from '@/lib/crypto/worker-client'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const CREDENTIAL_ERROR = 'Incorrect username or password.'
const UNREACHABLE_ERROR = "Couldn't reach the server. Try again."
const WRONG_ACCOUNT_ERROR =
  'That username belongs to a different account than this tab is logged in as.'

/** Mirrors LoginScreen's own isCredentialFailure -- see that file's doc comment for why a bad password and an unknown username collapse to the same message. */
function isCredentialFailure(err: unknown): boolean {
  if (err instanceof DecryptionFailedError) {
    return true
  }
  if (err instanceof ApiError) {
    return err.status === 400 || err.status === 401
  }
  return false
}

/**
 * Prompts for username + password, unwraps PROFILE in the crypto worker
 * (populating its liveKeys cache), and calls onDone() once the caller's own
 * sessionUserId is confirmed to be the account that was just unwrapped.
 * Renders nothing but this form -- the parent screen decides when to show
 * it (worker.ts's isLiveKeysError) and what to do once it succeeds.
 */
export function ReauthenticateStep({
  sessionUserId,
  onDone,
}: {
  readonly sessionUserId: string
  readonly onDone: () => void
}) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setSubmitting(true)

    void (async () => {
      try {
        const ch = await challenge(username)
        if (ch.userId !== sessionUserId) {
          setError(WRONG_ACCOUNT_ERROR)
          return
        }
        await completeLogin({
          password,
          salt: ch.salt,
          argon2Params: ch.argon2Params,
          wrappedPrivateKeys: ch.wrappedPrivateKeys,
          userId: ch.userId,
          nonce: ch.nonce,
        })
        // The signature completeLogin returns is for a login challenge this
        // step never submits to /api/auth/verify -- unlike a real login,
        // there is no new session to establish here, only the worker's own
        // liveKeys cache to repopulate (worker.ts's completeLogin handler
        // caches keys as a side effect before this promise even resolves).
        onDone()
      } catch (err) {
        setError(isCredentialFailure(err) ? CREDENTIAL_ERROR : UNREACHABLE_ERROR)
      } finally {
        setSubmitting(false)
      }
    })()
  }

  return (
    <form onSubmit={handleSubmit} className="flex w-full max-w-sm flex-col gap-4">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Confirm your password</h1>
        <p className="text-sm text-muted-foreground">
          This tab needs your password again before it can create a group.
        </p>
      </div>
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-col gap-2">
        <Label htmlFor="reauth-username">Username</Label>
        <Input
          id="reauth-username"
          type="text"
          autoComplete="username"
          value={username}
          onChange={(e) => {
            setUsername(e.target.value)
          }}
          required
        />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="reauth-password">Password</Label>
        <Input
          id="reauth-password"
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
        Continue
      </Button>
    </form>
  )
}

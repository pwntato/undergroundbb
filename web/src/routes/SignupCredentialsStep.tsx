// #33's signup flow, step 1: "username and password". Includes a
// confirm-password field -- reviewed and reconsidered from an earlier draft
// that omitted one on the reasoning that the password never leaves the
// browser, so a typo is caught the same way any typo is, by failing to
// unwrap at the next login. That reasoning undercounts the actual cost
// here: this design has no server-side password reset (the server holds no
// plaintext to check against, by design -- see docs/DESIGN.md), and the
// recovery-code screen that's the only other way back in doesn't exist yet.
// A typo at signup currently means permanently locked out, not merely
// inconvenienced, so the extra field earns its keep until recovery ships.

import { useState, type FormEvent } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

// Mirrors internal/handlers/register.go's usernamePattern -- both sides
// must agree, but this is UX only (catching a doomed request before an
// Argon2id derivation runs for it), not a security boundary: the server's
// own check is what actually matters.
const USERNAME_PATTERN = /^[A-Za-z0-9_-]{3,32}$/

// Not a strength meter -- docs/DESIGN.md sets no floor beyond "a password",
// leaving that to the user. This only stops an accidental empty/near-empty
// submit that Argon2id would otherwise spend real time deriving a key for.
const MIN_PASSWORD_LENGTH = 8

export function SignupCredentialsStep({
  onSubmit,
  error,
}: {
  onSubmit: (username: string, password: string) => void
  error: string | null
}) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [validationError, setValidationError] = useState<string | null>(null)

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!USERNAME_PATTERN.test(username)) {
      setValidationError('Username must be 3-32 characters: letters, digits, _ or -.')
      return
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
      setValidationError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`)
      return
    }
    if (password !== confirmPassword) {
      setValidationError('Passwords do not match.')
      return
    }
    setValidationError(null)
    onSubmit(username, password)
  }

  const shownError = validationError ?? error

  return (
    <form onSubmit={handleSubmit} className="flex w-full max-w-sm flex-col gap-4">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Create an account</h1>
      </div>
      {shownError && (
        <Alert variant="destructive">
          <AlertDescription>{shownError}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-col gap-2">
        <Label htmlFor="signup-username">Username</Label>
        <Input
          id="signup-username"
          autoComplete="username"
          value={username}
          onChange={(e) => {
            setUsername(e.target.value)
          }}
          required
        />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="signup-password">Password</Label>
        <Input
          id="signup-password"
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(e) => {
            setPassword(e.target.value)
          }}
          required
        />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="signup-confirm-password">Confirm password</Label>
        <Input
          id="signup-confirm-password"
          type="password"
          autoComplete="new-password"
          value={confirmPassword}
          onChange={(e) => {
            setConfirmPassword(e.target.value)
          }}
          required
        />
      </div>
      <Button type="submit">Continue</Button>
    </form>
  )
}

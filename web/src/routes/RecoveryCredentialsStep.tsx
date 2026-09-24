// #128's recovery flow, step 1: username, recovery code, and a new
// password. Collects all three up front (rather than releasing first, then
// asking for a new password) because release() has nothing left to check
// once the code is confirmed valid -- both release and reset independently
// re-verify the code against the same verifier (recovery.go's own doc
// comment), so there is no server-side reason to split this into two round
// trips, and one screen means one place to show "wrong code" instead of
// two.

import { useState, type FormEvent } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

// Not a strength meter, same reasoning as SignupCredentialsStep's identical
// constant: this only stops an accidental empty/near-empty submit that
// Argon2id would otherwise spend real time deriving a key for.
const MIN_PASSWORD_LENGTH = 8

export function RecoveryCredentialsStep({
  onSubmit,
  error,
}: {
  onSubmit: (username: string, recoveryCode: string, newPassword: string) => void
  error: string | null
}) {
  const [username, setUsername] = useState('')
  const [recoveryCode, setRecoveryCode] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [validationError, setValidationError] = useState<string | null>(null)

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (recoveryCode.trim().length === 0) {
      setValidationError('Enter your recovery code.')
      return
    }
    if (newPassword.length < MIN_PASSWORD_LENGTH) {
      setValidationError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`)
      return
    }
    if (newPassword !== confirmPassword) {
      setValidationError('Passwords do not match.')
      return
    }
    setValidationError(null)
    onSubmit(username, recoveryCode, newPassword)
  }

  const shownError = validationError ?? error

  return (
    <form onSubmit={handleSubmit} className="flex w-full max-w-sm flex-col gap-4">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Recover your account</h1>
      </div>
      {shownError && (
        <Alert variant="destructive">
          <AlertDescription>{shownError}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-col gap-2">
        <Label htmlFor="recovery-username">Username</Label>
        <Input
          id="recovery-username"
          autoComplete="username"
          value={username}
          onChange={(e) => {
            setUsername(e.target.value)
          }}
          required
        />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="recovery-code">Recovery code</Label>
        <Input
          id="recovery-code"
          autoComplete="off"
          spellCheck={false}
          placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX"
          className="font-mono"
          value={recoveryCode}
          onChange={(e) => {
            setRecoveryCode(e.target.value)
          }}
          required
        />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="recovery-new-password">New password</Label>
        <Input
          id="recovery-new-password"
          type="password"
          autoComplete="new-password"
          value={newPassword}
          onChange={(e) => {
            setNewPassword(e.target.value)
          }}
          required
        />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="recovery-confirm-password">Confirm new password</Label>
        <Input
          id="recovery-confirm-password"
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

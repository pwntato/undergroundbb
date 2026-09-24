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
import { normalizeRecoveryCode } from '@/lib/crypto/recovery-code'

// Not a strength meter, same reasoning as SignupCredentialsStep's identical
// constant: this only stops an accidental empty/near-empty submit that
// Argon2id would otherwise spend real time deriving a key for.
const MIN_PASSWORD_LENGTH = 8

// generateRecoveryCode always produces exactly 26 base32 characters
// (recovery-code.ts's own CODE_LENGTH) once normalized. Checking this here
// -- against the normalized form, not the raw input -- catches a typo'd or
// truncated code (or an input like "-----" that normalizes to empty)
// before it costs a round trip: RecoveryScreen normalizes the same way
// before ever calling release(), so an input that fails this check would
// otherwise reach the server as an empty or wrong-length string and come
// back as an uninformative 400. See PR #129 review.
const RECOVERY_CODE_LENGTH = 26

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
    if (normalizeRecoveryCode(recoveryCode).length !== RECOVERY_CODE_LENGTH) {
      setValidationError(`Recovery codes are ${RECOVERY_CODE_LENGTH} characters.`)
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

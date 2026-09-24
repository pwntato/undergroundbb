// #131's change-password flow, step 1: current password + new password.
// Mirrors RecoveryCredentialsStep's shape (same MIN_PASSWORD_LENGTH/confirm
// -password reasoning as that file and SignupCredentialsStep), but asks for
// the CURRENT password rather than a recovery code -- this screen already
// knows the caller's identity from their session, so there is no username
// field either.

import { useState, type FormEvent } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

// Not a strength meter, same reasoning as SignupCredentialsStep's identical
// constant: this only stops an accidental empty/near-empty submit that
// Argon2id would otherwise spend real time deriving a key for.
const MIN_PASSWORD_LENGTH = 8

export function ChangePasswordCredentialsStep({
  onSubmit,
  error,
}: {
  onSubmit: (oldPassword: string, newPassword: string) => void
  error: string | null
}) {
  const [oldPassword, setOldPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [validationError, setValidationError] = useState<string | null>(null)

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (newPassword.length < MIN_PASSWORD_LENGTH) {
      setValidationError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`)
      return
    }
    if (newPassword !== confirmPassword) {
      setValidationError('Passwords do not match.')
      return
    }
    setValidationError(null)
    onSubmit(oldPassword, newPassword)
  }

  const shownError = validationError ?? error

  return (
    <form onSubmit={handleSubmit} className="flex w-full max-w-sm flex-col gap-4">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Change your password</h1>
        <p className="text-sm text-muted-foreground">
          This also issues a new recovery code and invalidates your old one.
        </p>
      </div>
      {shownError && (
        <Alert variant="destructive">
          <AlertDescription>{shownError}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-col gap-2">
        <Label htmlFor="change-password-old">Current password</Label>
        <Input
          id="change-password-old"
          type="password"
          autoComplete="current-password"
          value={oldPassword}
          onChange={(e) => {
            setOldPassword(e.target.value)
          }}
          required
        />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="change-password-new">New password</Label>
        <Input
          id="change-password-new"
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
        <Label htmlFor="change-password-confirm">Confirm new password</Label>
        <Input
          id="change-password-confirm"
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

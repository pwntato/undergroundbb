// #62: the first step of the "Rotate keys" screen. It says what rotating does
// before it asks for anything (docs/DESIGN.md: the interface must clearly
// distinguish "change password" from "rotate keys", and the flow must list the
// user's groups and which are Open), then collects the new password.

import { useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { validateNewPassword } from './rotateKeysCopy'

export interface ReviewGroup {
  readonly groupId: string
  readonly label: string
  /** Open groups have no re-key, so the old keys keep reading them. */
  readonly open: boolean
}

export function RotateKeysReview({
  groups,
  invitesToRevoke,
  invitesAwaitingCompletion,
  error,
  onSubmit,
}: {
  groups: readonly ReviewGroup[]
  invitesToRevoke: number
  invitesAwaitingCompletion: number
  error: string | null
  onSubmit: (newPassword: string) => void
}) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [understood, setUnderstood] = useState(false)
  const [validationError, setValidationError] = useState<string | null>(null)
  const openGroups = groups.filter((g) => g.open)

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    const problem = validateNewPassword(password, confirm)
    setValidationError(problem)
    if (problem === null) {
      onSubmit(password)
    }
  }

  const shownError = validationError ?? error

  return (
    <form onSubmit={handleSubmit} className="flex w-full max-w-lg flex-col gap-4">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Rotate your keys</h1>
        <p className="text-sm text-muted-foreground">
          This is not the same as changing your password. Only do it if you think someone else has
          your keys, for example a lost laptop or malware. To change your password, use{' '}
          <Link to="/account/password" className="underline">
            Change password
          </Link>
          .
        </p>
      </div>

      <div className="flex flex-col gap-2 text-sm">
        <p className="font-medium">What this does</p>
        <ul className="list-disc pl-5">
          <li>You get a new key pair, a new password and a new recovery code.</li>
          <li>Every other device you are logged in on is signed out. This tab stays signed in.</li>
          <li>
            Your fingerprint changes. Anyone who verified or pinned you will see a key change and
            has to accept it.
          </li>
          <li>
            In groups where you are not an admin, you cannot read new messages until an admin
            approves your new key.
          </li>
          <li>You can rotate once a day.</li>
        </ul>
      </div>

      <div className="flex flex-col gap-2 text-sm">
        <p className="font-medium">Groups you administer</p>
        {groups.length === 0 ? (
          <p className="text-muted-foreground">You do not administer any groups.</p>
        ) : (
          <ul className="list-disc pl-5">
            {groups.map((g) => (
              <li key={g.groupId}>
                {g.label}
                {g.open ? ' (Open)' : ''}
              </li>
            ))}
          </ul>
        )}
        {groups.length > 0 && (
          <p className="text-muted-foreground">
            In these groups your new keys take over right away, with no one else needed. This works
            from your new keys after the change, even if you close this tab.
          </p>
        )}
      </div>

      {openGroups.length > 0 && (
        <Alert>
          <AlertDescription>
            {openGroups.length === 1 ? 'One of your groups is' : 'Some of your groups are'} Open:{' '}
            {openGroups.map((g) => g.label).join(', ')}. An Open group has no way to change its key,
            so whoever holds your old keys can keep reading it. Assume that group&apos;s content is
            known to them.
          </AlertDescription>
        </Alert>
      )}

      {(invitesToRevoke > 0 || invitesAwaitingCompletion > 0) && (
        <Alert>
          <AlertDescription>
            {invitesToRevoke > 0 &&
              `Invites you sent that nobody has accepted (${invitesToRevoke}) will be cancelled, because they only work with your old keys. `}
            {invitesAwaitingCompletion > 0 &&
              `Invites that someone accepted but you have not finished (${invitesAwaitingCompletion}) cannot be cancelled and will not complete. Ask those people to be invited again.`}
          </AlertDescription>
        </Alert>
      )}

      {shownError && (
        <Alert variant="destructive">
          <AlertDescription>{shownError}</AlertDescription>
        </Alert>
      )}

      <div className="flex flex-col gap-2">
        <Label htmlFor="rotate-keys-new">New password</Label>
        <Input
          id="rotate-keys-new"
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
        <Label htmlFor="rotate-keys-confirm">Confirm new password</Label>
        <Input
          id="rotate-keys-confirm"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => {
            setConfirm(e.target.value)
          }}
          required
        />
      </div>
      <label className="flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          checked={understood}
          onChange={(e) => {
            setUnderstood(e.target.checked)
          }}
          className="mt-1"
        />
        <span>I understand this signs out my other devices and changes my fingerprint.</span>
      </label>
      <Button type="submit" disabled={!understood}>
        Rotate my keys
      </Button>
    </form>
  )
}

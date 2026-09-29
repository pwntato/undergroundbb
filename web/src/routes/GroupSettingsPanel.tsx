// The presentational half of GroupSettingsScreen -- issue #36. Prop-driven
// with no effects, context or fetching, so it can be tested with
// renderToStaticMarkup (see GroupList.tsx's header for why that is this
// codebase's pattern). GroupSettingsScreen owns loading and saving.
//
// Everyone in the group, and anyone viewing a public group, sees the
// settings. Only an admin gets the edit form; the server's own 403 is the
// real check. Revocation mode is always shown and never editable, and
// "Open" always spells out what it means (issue #36: "Open groups must
// always show what that means").

import { useState, type FormEvent } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  FALLBACK_EXPIRATION_DAYS,
  MAX_EXPIRATION_DAYS,
  REVOCATION_TEXT,
  validateSettingsForm,
} from './groupSettingsForm'
import type { SettingsForm, SettingsView } from './runGroupSettings'

function nameNotice(status: SettingsView['nameStatus']): string | null {
  switch (status) {
    case 'coldKeys':
      return 'Log in again to see and edit this private group’s name and description.'
    case 'unreadable':
      return 'This group’s name and description could not be decrypted.'
    default:
      return null
  }
}

export function GroupSettingsPanel({
  view,
  onSave,
  saving,
  message,
  error,
}: {
  readonly view: SettingsView
  readonly onSave: (form: SettingsForm) => void
  readonly saving: boolean
  readonly message: string | null
  readonly error: string | null
}) {
  const { detail } = view
  const canEdit =
    detail.role === 'admin' && (view.nameStatus === 'plaintext' || view.nameStatus === 'decrypted')

  const [name, setName] = useState(view.name ?? '')
  const [description, setDescription] = useState(view.description ?? '')
  const [neverExpires, setNeverExpires] = useState(detail.expirationDays === 0)
  const [days, setDays] = useState(
    String(detail.expirationDays === 0 ? FALLBACK_EXPIRATION_DAYS : detail.expirationDays),
  )
  const [validationError, setValidationError] = useState<string | null>(null)

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    const form: SettingsForm = {
      name,
      description,
      // 0 means "never expire" and comes only from the checkbox: an empty
      // or zero days field must fail validation, not silently disable expiry.
      expirationDays: neverExpires ? 0 : Number(days) >= 1 ? Number(days) : Number.NaN,
    }
    const problem = validateSettingsForm(form)
    if (problem !== null) {
      setValidationError(problem)
      return
    }
    setValidationError(null)
    onSave(form)
  }

  const notice = nameNotice(view.nameStatus)
  const shownError = validationError ?? error

  return (
    <div className="flex w-full max-w-md flex-col gap-4 text-left">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">{view.name ?? '(private group)'}</h1>
        {view.description !== null && view.description !== '' && (
          <p className="text-sm text-muted-foreground">{view.description}</p>
        )}
        <p className="text-xs text-muted-foreground">
          {detail.visibility === 'public' ? 'Public group' : 'Private group'}
          {detail.role !== '' &&
            ` · you are ${detail.role === 'admin' ? 'an admin' : `a ${detail.role}`}`}
        </p>
      </div>

      {notice !== null && (
        <Alert>
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      )}

      <section aria-labelledby="revocation-heading" className="flex flex-col gap-1">
        <h2 id="revocation-heading" className="text-sm font-medium">
          Removing a member
        </h2>
        <p className="text-sm text-muted-foreground">{REVOCATION_TEXT[detail.revocationMode]}</p>
      </section>

      <section aria-labelledby="expiration-heading" className="flex flex-col gap-1">
        <h2 id="expiration-heading" className="text-sm font-medium">
          Message expiration
        </h2>
        <p className="text-sm text-muted-foreground">
          {detail.expirationDays === 0
            ? 'Messages never expire.'
            : `Messages expire after ${String(detail.expirationDays)} days.`}
        </p>
      </section>

      {message !== null && (
        <Alert>
          <AlertDescription>{message}</AlertDescription>
        </Alert>
      )}

      {canEdit && (
        <form onSubmit={handleSubmit} className="flex flex-col gap-4 border-t pt-4">
          <h2 className="text-sm font-medium">Edit settings</h2>
          {shownError !== null && (
            <Alert variant="destructive">
              <AlertDescription>{shownError}</AlertDescription>
            </Alert>
          )}
          <div className="flex flex-col gap-2">
            <Label htmlFor="settings-name">Name</Label>
            <Input
              id="settings-name"
              type="text"
              value={name}
              onChange={(e) => {
                setName(e.target.value)
              }}
              required
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="settings-description">Description (optional)</Label>
            <textarea
              id="settings-description"
              className="min-h-20 rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring"
              value={description}
              onChange={(e) => {
                setDescription(e.target.value)
              }}
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="settings-days">Expire messages after (days)</Label>
            <Input
              id="settings-days"
              type="number"
              min={1}
              max={MAX_EXPIRATION_DAYS}
              value={days}
              disabled={neverExpires}
              onChange={(e) => {
                setDays(e.target.value)
              }}
            />
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={neverExpires}
                onChange={(e) => {
                  setNeverExpires(e.target.checked)
                }}
              />
              Never expire messages
            </label>
          </div>
          <Button type="submit" disabled={saving}>
            {saving ? 'Saving…' : 'Save changes'}
          </Button>
        </form>
      )}
      {!canEdit && shownError !== null && (
        <Alert variant="destructive">
          <AlertDescription>{shownError}</AlertDescription>
        </Alert>
      )}
    </div>
  )
}

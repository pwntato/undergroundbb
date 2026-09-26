// #34's create-group form: visibility, name/description, revocation mode,
// expiration policy. No radio/select/textarea primitive exists yet in
// components/ui, so this uses plain styled elements rather than introducing
// new primitives this issue doesn't otherwise need -- matching the
// minimal-footprint spirit of ChangePasswordCredentialsStep's own form
// fields.
//
// This step collects plaintext only -- CreateGroupScreen's own submit
// handler is what encrypts the name/description for a private group
// (ChangePasswordCredentialsStep's equivalent split: this step never
// touches crypto, matching how it never touches Argon2id either).

import { useState, type FormEvent } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const MAX_NAME_LENGTH = 200
const MAX_DESCRIPTION_LENGTH = 2000
const DEFAULT_EXPIRATION_DAYS = 30

export interface GroupFormValues {
  readonly visibility: 'private' | 'public'
  readonly name: string
  readonly description: string
  readonly revocationMode: 'rotating' | 'open'
  readonly expirationDays: number
}

/**
 * initialValues seeds the form's fields when this component mounts fresh
 * with values a previous mount already had -- PR #142 round 3 review found
 * that CreateGroupScreen's ReauthenticateStep branch unmounts this
 * component entirely (it renders instead of, not alongside, the form), so
 * this component's own useState hooks lose everything on Cancel or on a
 * failed resubmit after re-auth. CreateGroupScreen passes `pending?.values`
 * here so the user doesn't have to retype all five fields exactly to reuse
 * a cached groupId/group key -- if they DID have to and got even one field
 * wrong, `formValuesEqual` would fail to match, a fresh groupId would be
 * generated, and an ambiguous failure that actually committed would create
 * the orphaned second group `pending` exists to prevent.
 */
export function CreateGroupFormStep({
  onSubmit,
  error,
  initialValues,
}: {
  onSubmit: (values: GroupFormValues) => void
  error: string | null
  initialValues?: GroupFormValues
}) {
  const [visibility, setVisibility] = useState<'private' | 'public'>(
    initialValues?.visibility ?? 'private',
  )
  const [name, setName] = useState(initialValues?.name ?? '')
  const [description, setDescription] = useState(initialValues?.description ?? '')
  const [revocationMode, setRevocationMode] = useState<'rotating' | 'open'>(
    initialValues?.revocationMode ?? 'rotating',
  )
  const [neverExpires, setNeverExpires] = useState(initialValues?.expirationDays === 0)
  const [validationError, setValidationError] = useState<string | null>(null)

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    // A private group's name is still required client-side even though the
    // server never sees it in plaintext to validate -- see
    // docs/DESIGN.md's "Direct messages" for the one case with no name at
    // all, which #34 doesn't build; every group #34 creates needs one.
    if (name.trim() === '') {
      setValidationError('Group name is required.')
      return
    }
    if (name.length > MAX_NAME_LENGTH) {
      setValidationError(`Group name must be ${String(MAX_NAME_LENGTH)} characters or fewer.`)
      return
    }
    if (description.length > MAX_DESCRIPTION_LENGTH) {
      setValidationError(
        `Description must be ${String(MAX_DESCRIPTION_LENGTH)} characters or fewer.`,
      )
      return
    }
    setValidationError(null)
    onSubmit({
      visibility,
      name,
      description,
      revocationMode,
      expirationDays: neverExpires ? 0 : DEFAULT_EXPIRATION_DAYS,
    })
  }

  const shownError = validationError ?? error

  return (
    <form onSubmit={handleSubmit} className="flex w-full max-w-sm flex-col gap-4">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Create a group</h1>
      </div>
      {shownError && (
        <Alert variant="destructive">
          <AlertDescription>{shownError}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-col gap-2">
        <Label htmlFor="create-group-name">Name</Label>
        <Input
          id="create-group-name"
          type="text"
          value={name}
          onChange={(e) => {
            setName(e.target.value)
          }}
          required
        />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="create-group-description">Description (optional)</Label>
        <textarea
          id="create-group-description"
          className="min-h-20 rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring"
          value={description}
          onChange={(e) => {
            setDescription(e.target.value)
          }}
        />
      </div>
      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm font-medium">Visibility</legend>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="radio"
            name="visibility"
            checked={visibility === 'private'}
            onChange={() => {
              setVisibility('private')
            }}
          />
          Private — only discoverable by invite
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="radio"
            name="visibility"
            checked={visibility === 'public'}
            onChange={() => {
              setVisibility('public')
            }}
          />
          Public — listed in the group directory (posts stay encrypted)
        </label>
      </fieldset>
      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm font-medium">Removing a member</legend>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="radio"
            name="revocationMode"
            checked={revocationMode === 'rotating'}
            onChange={() => {
              setRevocationMode('rotating')
            }}
          />
          Rotating — removal re-keys the group (up to 1,000 members)
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="radio"
            name="revocationMode"
            checked={revocationMode === 'open'}
            onChange={() => {
              setRevocationMode('open')
            }}
          />
          Open — removal is access control only, no cap on members
        </label>
      </fieldset>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={neverExpires}
          onChange={(e) => {
            setNeverExpires(e.target.checked)
          }}
        />
        Never expire messages (default: 30 days)
      </label>
      <Button type="submit">Create group</Button>
    </form>
  )
}

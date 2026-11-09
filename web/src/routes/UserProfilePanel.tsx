// The presentational half of the profile page (#75): username, member-since,
// bio, key fingerprint and the caller's verification state. Prop-driven with
// no effects, so it is tested by calling it and with renderToStaticMarkup (see
// GroupList.tsx's header). The bio is plaintext and visible to every signed-in
// user; the page says so where the owner edits it.

import { Link } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { MAX_BIO_CHARS } from '@/lib/api/users'
import { FingerprintBlock } from './FingerprintBlock'
import { MemberVerificationBadge } from './MemberVerificationControls'
import { bioLength, type ProfileView } from './profileView'
import type { MemberVerifications } from './runMemberVerification'

export interface BioEditProps {
  readonly draft: string
  readonly onDraftChange: (draft: string) => void
  readonly onSave: () => void
  readonly saving: boolean
  readonly message: string | null
  readonly error: string | null
}

export function UserProfilePanel({
  view,
  isSelf,
  verification,
  bioEdit,
}: {
  readonly view: ProfileView
  /** True on the signed-in user's own page: shows the bio editor. */
  readonly isSelf: boolean
  /** The caller's verification state for this user; null while loading or on their own page. */
  readonly verification: MemberVerifications | null
  /** Present only on the caller's own page. */
  readonly bioEdit?: BioEditProps | undefined
}) {
  if (view.deleted) {
    return (
      <div className="flex w-full max-w-md flex-col gap-2">
        <h1 className="text-2xl font-semibold">Deleted user</h1>
        <p className="text-sm text-muted-foreground">This account was deleted.</p>
      </div>
    )
  }
  return (
    <div className="flex w-full max-w-md flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold">
          {view.username}
          {isSelf && <span className="ml-2 text-sm font-normal text-muted-foreground">you</span>}
        </h1>
        {view.memberSince !== null && (
          <p className="text-sm text-muted-foreground">Member since {view.memberSince}</p>
        )}
      </div>

      {view.bio !== '' ? (
        <p className="text-sm whitespace-pre-wrap">{view.bio}</p>
      ) : (
        <p className="text-sm text-muted-foreground">No bio.</p>
      )}

      {isSelf && bioEdit !== undefined && (
        <div className="flex flex-col gap-2">
          <Label htmlFor="profile-bio">Your bio</Label>
          <textarea
            id="profile-bio"
            className="min-h-20 rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring"
            value={bioEdit.draft}
            disabled={bioEdit.saving}
            onChange={(e) => {
              bioEdit.onDraftChange(e.target.value)
            }}
          />
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-muted-foreground">
              {bioLength(bioEdit.draft)} / {MAX_BIO_CHARS}. Anyone signed in can read your bio, like
              your username.
            </span>
            <Button
              type="button"
              size="sm"
              disabled={bioEdit.saving || bioLength(bioEdit.draft) > MAX_BIO_CHARS}
              onClick={bioEdit.onSave}
            >
              {bioEdit.saving ? 'Saving…' : 'Save'}
            </Button>
          </div>
          {bioEdit.error !== null && (
            <Alert variant="destructive">
              <AlertDescription>{bioEdit.error}</AlertDescription>
            </Alert>
          )}
          {bioEdit.message !== null && (
            <p className="text-xs text-muted-foreground">{bioEdit.message}</p>
          )}
        </div>
      )}

      <div className="flex flex-col gap-1">
        <p className="text-sm font-medium">{isSelf ? 'Your key fingerprint' : 'Key fingerprint'}</p>
        {view.fingerprint !== null ? (
          <FingerprintBlock value={view.fingerprint} />
        ) : (
          <p className="text-xs text-muted-foreground">
            The keys the server shows for this account could not be read.
          </p>
        )}
        {!isSelf && <MemberVerificationBadge state={verification} userId={view.userId} />}
        <p className="text-xs text-muted-foreground">
          {isSelf
            ? 'This is what other members see for you. They can compare it with you in person or on a call they know is you.'
            : 'Computed on this device from the keys the server shows. To check it, compare it with them in person or on a call you know is them; you can record the check from a group’s Members screen.'}
        </p>
      </div>

      <Link to="/" className="text-sm underline underline-offset-4">
        Back to your groups
      </Link>
    </div>
  )
}

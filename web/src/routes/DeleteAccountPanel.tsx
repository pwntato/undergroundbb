// The presentational half of deleting the account -- issue #77. Prop-driven,
// no effects, so it is tested with renderToStaticMarkup (see GroupList.tsx's
// header). Deleting is permanent and leaves every group first, so it takes an
// explicit confirmation step, and it says plainly what cannot be undone.

import { Link } from 'react-router'
import { Button } from '@/components/ui/button'

export interface DeleteGroupRow {
  readonly groupId: string
  readonly label: string
  /** Set on blockers: which fix applies to this group. */
  readonly reason?: 'needsSuccessor' | 'grantMissing'
}

export type DeletePanelState =
  | { readonly status: 'loading' }
  | {
      readonly status: 'error'
      /** The groups could not be re-read after a run that may have left some. */
      readonly afterRun?: boolean
    }
  | {
      readonly status: 'ready'
      /** Groups the account will leave. */
      readonly leaving: readonly DeleteGroupRow[]
      /** Groups whose only member is this account: leaving them deletes them. */
      readonly deleting: readonly DeleteGroupRow[]
      /** Groups that must be dealt with first (no successor, grant not on record). */
      readonly blockers: readonly DeleteGroupRow[]
    }

export function DeleteAccountPanel({
  state,
  confirming,
  busy,
  onStart,
  onCancel,
  onConfirm,
}: {
  readonly state: DeletePanelState
  readonly confirming: boolean
  /** The leaves and the delete are running; every control locks. */
  readonly busy: boolean
  readonly onStart: () => void
  readonly onCancel: () => void
  readonly onConfirm: () => void
}) {
  if (state.status === 'loading') {
    return <p className="text-sm text-muted-foreground">Checking your groups…</p>
  }
  if (state.status === 'error') {
    return (
      <p className="text-sm text-destructive">
        {state.afterRun === true
          ? "Couldn't re-check your groups. Reload the page to see what is left."
          : "Couldn't check your groups, so nothing was changed. Try reloading the page."}
      </p>
    )
  }

  const { leaving, deleting, blockers } = state
  return (
    <div className="flex w-full max-w-md flex-col gap-4 text-left">
      <p className="text-sm">
        Deleting your account signs you out everywhere, frees your username, and removes your login.
        It can&apos;t be undone. Anything other members have already read can&apos;t be taken back
        from them.
      </p>

      {blockers.length > 0 && (
        <div className="flex flex-col gap-2 rounded-md border border-destructive px-3 py-3">
          <p className="text-sm">
            You can&apos;t delete your account yet. These groups need your attention first, and
            nothing has been changed:
          </p>
          <ul className="flex flex-col gap-1 text-sm">
            {blockers.map((g) => (
              <li key={g.groupId}>
                <Link className="underline" to={`/groups/${encodeURIComponent(g.groupId)}/members`}>
                  {g.label}
                </Link>
                <span className="text-xs text-muted-foreground">
                  {g.reason === 'grantMissing'
                    ? ": your role here isn't on record, so it can't be left from this page"
                    : ': you are the last admin and others remain, so make someone else an admin first'}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {leaving.length > 0 && (
        <div className="flex flex-col gap-1">
          <p className="text-sm font-medium">You will leave</p>
          <ul className="flex flex-col gap-1 text-sm">
            {leaving.map((g) => (
              <li key={g.groupId}>{g.label}</li>
            ))}
          </ul>
        </div>
      )}

      {deleting.length > 0 && (
        <div className="flex flex-col gap-1 rounded-md border border-destructive px-3 py-3">
          <p className="text-sm font-medium">These groups will be deleted</p>
          <p className="text-xs text-muted-foreground">
            You are the only member, so leaving deletes the group and everything in it, permanently.
          </p>
          <ul className="flex flex-col gap-1 text-sm">
            {deleting.map((g) => (
              <li key={g.groupId}>{g.label}</li>
            ))}
          </ul>
        </div>
      )}

      {leaving.length === 0 && deleting.length === 0 && blockers.length === 0 && (
        <p className="text-sm text-muted-foreground">You aren&apos;t in any groups.</p>
      )}

      {blockers.length === 0 && !confirming && (
        <Button type="button" variant="outline" size="sm" disabled={busy} onClick={onStart}>
          Delete my account
        </Button>
      )}

      {blockers.length === 0 && confirming && (
        <div className="flex flex-col gap-3 rounded-md border border-destructive px-3 py-3">
          <p className="text-sm">Delete your account permanently?</p>
          <div className="flex gap-2">
            <Button
              type="button"
              variant="destructive"
              size="sm"
              disabled={busy}
              onClick={onConfirm}
            >
              {busy ? 'Deleting…' : 'Yes, delete my account'}
            </Button>
            <Button type="button" variant="outline" size="sm" disabled={busy} onClick={onCancel}>
              Cancel
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

// The presentational half of InvitesScreen -- issue #41. Prop-driven with no
// effects or fetching, so it is tested with renderToStaticMarkup (see
// GroupList.tsx's header).
//
// "Sent" splits by whether anyone accepted: a pending invite is a live link
// that can still be revoked; an accepted one is work the inviter still owes
// (step 3 runs on their next login, #40) and cannot be revoked. "Received"
// is only ever accepted invites, shown as waiting on the inviter.

import { Button } from '@/components/ui/button'
import type { ReceivedInvite, SentInvite } from '@/lib/api/invites'
import { memberLabel, unresolvedClass } from './memberLabel'
import type { InvitesView } from './runInvites'

/** A calendar date for an RFC 3339 instant, or the raw string if it does not parse. */
function formatDate(iso: string): string {
  const t = new Date(iso)
  return Number.isNaN(t.getTime()) ? iso : t.toISOString().slice(0, 10)
}

/**
 * True when an RFC 3339 removal date is still ahead. DynamoDB's TTL sweep is
 * lazy, so a row can outlive its removalDate; then "disappears after <past
 * date>" would read as nonsense and the sentence is left out.
 */
function isUpcoming(iso: string | undefined, now: number): boolean {
  if (iso === undefined) {
    return false
  }
  const t = new Date(iso).getTime()
  return !Number.isNaN(t) && t > now
}

export function InvitesPanel({
  view,
  groupLabels,
  busyInviteId,
  onRevoke,
  now,
  usernames,
}: {
  readonly view: InvitesView
  /** groupId to a display name, for groups the caller belongs to. Anything missing renders generically. */
  readonly groupLabels: ReadonlyMap<string, string>
  /** The invite whose revoke is in flight, if any; all revoke buttons lock while one is. */
  readonly busyInviteId: string | null
  readonly onRevoke: (inviteId: string) => void
  /** Epoch ms to compare removal dates against; the screen passes the time its data was loaded. */
  readonly now: number
  /** userId to username; anything missing renders as a short id. */
  readonly usernames?: ReadonlyMap<string, string> | undefined
}) {
  const label = (groupId: string) => groupLabels.get(groupId) ?? 'a group'
  return (
    <div className="flex w-full max-w-md flex-col gap-6">
      <h1 className="text-2xl font-semibold">Invites</h1>

      <section className="flex flex-col gap-2">
        <h2 className="text-lg font-medium">Sent</h2>
        {view.sent.length === 0 ? (
          <p className="text-sm text-muted-foreground">You have no outstanding invites.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {view.sent.map((inv) => (
              <SentRow
                key={inv.inviteId}
                invite={inv}
                groupName={label(inv.groupId)}
                showRemoval={isUpcoming(inv.removalDate, now)}
                busy={busyInviteId === inv.inviteId}
                locked={busyInviteId !== null}
                onRevoke={onRevoke}
              />
            ))}
          </ul>
        )}
      </section>

      <section className="flex flex-col gap-2">
        <h2 className="text-lg font-medium">Waiting on the inviter</h2>
        {view.received.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            You have no accepted invites waiting to be completed.
          </p>
        ) : (
          <ul className="flex flex-col gap-2">
            {view.received.map((inv) => (
              <ReceivedRow
                key={inv.inviteId}
                invite={inv}
                groupName={label(inv.groupId)}
                showRemoval={isUpcoming(inv.removalDate, now)}
                usernames={usernames}
              />
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}

function SentRow({
  invite,
  groupName,
  showRemoval,
  busy,
  locked,
  onRevoke,
}: {
  readonly invite: SentInvite
  readonly groupName: string
  /** Whether removalDate is still ahead; see isUpcoming. */
  readonly showRemoval: boolean
  readonly busy: boolean
  readonly locked: boolean
  readonly onRevoke: (inviteId: string) => void
}) {
  return (
    <li className="flex flex-col gap-2 rounded-md border px-3 py-2 sm:flex-row sm:items-center sm:justify-between">
      <span className="flex flex-col">
        <span className="font-medium">{groupName}</span>
        {invite.accepted ? (
          invite.overdue === true ? (
            <span className="text-xs text-destructive">
              Overdue. This acceptance was due {formatDate(invite.completionDeadline ?? '')} and has
              not completed. It finishes when you log in; if it keeps failing, the invitee will need
              a new invite.
              {showRemoval &&
                invite.removalDate !== undefined &&
                ` It disappears from here after ${formatDate(invite.removalDate)}.`}
            </span>
          ) : (
            <span className="text-xs text-muted-foreground">
              Accepted. Completes the next time you log in, by{' '}
              {formatDate(invite.completionDeadline ?? invite.expiresAt)}.
            </span>
          )
        ) : (
          <span className="text-xs text-muted-foreground">
            Not yet accepted. Expires {formatDate(invite.expiresAt)}.
          </span>
        )}
      </span>
      {!invite.accepted && (
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={locked}
          onClick={() => {
            onRevoke(invite.inviteId)
          }}
        >
          {busy ? 'Revoking…' : 'Revoke'}
        </Button>
      )}
    </li>
  )
}

function ReceivedRow({
  invite,
  groupName,
  showRemoval,
  usernames,
}: {
  readonly invite: ReceivedInvite
  readonly groupName: string
  /** Whether removalDate is still ahead; see isUpcoming. */
  readonly showRemoval: boolean
  readonly usernames?: ReadonlyMap<string, string> | undefined
}) {
  return (
    <li className="flex flex-col rounded-md border px-3 py-2">
      <span className="font-medium">{groupName}</span>
      {invite.overdue === true ? (
        <span className="text-xs text-destructive">
          You accepted an invite from{' '}
          <span
            className={unresolvedClass(invite.inviterUserId, usernames)}
            title={invite.inviterUserId}
          >
            {memberLabel(invite.inviterUserId, usernames)}
          </span>
          , but they have not completed it, and it was due {formatDate(invite.completionDeadline)}.
          You have not joined. Ask them to log in, or ask for a new invite.
          {showRemoval && ` This notice disappears after ${formatDate(invite.removalDate)}.`}
        </span>
      ) : (
        <span className="text-xs text-muted-foreground">
          You accepted an invite from{' '}
          <span
            className={unresolvedClass(invite.inviterUserId, usernames)}
            title={invite.inviterUserId}
          >
            {memberLabel(invite.inviterUserId, usernames)}
          </span>
          . You join once they next log in, by {formatDate(invite.completionDeadline)}.
        </span>
      )}
    </li>
  )
}

// The presentational halves of the three join-request screens (#72). Prop-driven with no effects,
// context or fetching, so they test with renderToStaticMarkup and by calling them as functions.
// Every decision (what may be approved, which message to show) is made in runJoinRequests.ts.

import { Link } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import type { JoinRequestEntry, MyJoinRequest } from '@/lib/api/joinRequests'
import { FingerprintBlock } from './FingerprintBlock'
import { memberLabel, unresolvedClass } from './memberLabel'

const linkClass = 'text-xs text-primary underline-offset-4 hover:underline'

/** The request button on a public group the caller is not in. */
export function JoinGroupPanel({
  groupName,
  isMember,
  busy,
  sent,
  onRequest,
}: {
  readonly groupName: string
  readonly isMember: boolean
  readonly busy: boolean
  readonly sent: boolean
  readonly onRequest: () => void
}) {
  return (
    <div className="flex w-full max-w-md flex-col items-center gap-3">
      <h1 className="text-xl font-semibold [overflow-wrap:anywhere]">{groupName}</h1>
      {isMember ? (
        <p className="text-sm text-muted-foreground">You are already a member of this group.</p>
      ) : sent ? (
        <p className="text-sm text-muted-foreground">
          Request sent. An admin or ambassador will look at it.{' '}
          <Link to="/join-requests" className="text-primary underline-offset-4 hover:underline">
            See your requests
          </Link>
        </p>
      ) : (
        <>
          <p className="text-center text-sm text-muted-foreground">
            This group is public. An admin or ambassador has to approve you before you can read or
            post. Your request shows them your username and your keys.
          </p>
          <Button type="button" disabled={busy} onClick={onRequest}>
            {busy ? 'Sending…' : 'Ask to join'}
          </Button>
        </>
      )}
    </div>
  )
}

/** The caller's own live requests: pending ones can be withdrawn, declined ones say when to retry. */
export function MyJoinRequestsPanel({
  requests,
  busyGroupId,
  hasMore,
  onWithdraw,
  onLoadMore,
}: {
  readonly requests: readonly MyJoinRequest[]
  readonly busyGroupId: string | null
  readonly hasMore: boolean
  readonly onWithdraw: (groupId: string) => void
  readonly onLoadMore: () => void
}) {
  if (requests.length === 0) {
    return <p className="text-sm text-muted-foreground">You have no requests to join a group.</p>
  }
  return (
    <div className="flex w-full max-w-md flex-col gap-2">
      <ul className="flex flex-col gap-2">
        {requests.map((r) => (
          <li
            key={r.requestId}
            className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1 rounded-md border px-3 py-2"
          >
            <span className="min-w-0 [overflow-wrap:anywhere]">
              <span className="font-medium">{r.groupName ?? '(public group)'}</span>
              <span className="block text-xs text-muted-foreground">
                {r.status === 'pending'
                  ? `Waiting since ${r.day}`
                  : `Declined. You can ask again after ${r.retryAfter ?? 'a while'}.`}
              </span>
            </span>
            {r.status === 'pending' ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={busyGroupId !== null}
                onClick={() => {
                  onWithdraw(r.groupId)
                }}
              >
                {busyGroupId === r.groupId ? 'Withdrawing…' : 'Withdraw'}
              </Button>
            ) : (
              <Link to={`/groups/${r.groupId}/join`} className={linkClass}>
                Ask again
              </Link>
            )}
          </li>
        ))}
      </ul>
      {hasMore && (
        <Button type="button" variant="outline" size="sm" onClick={onLoadMore}>
          Show more
        </Button>
      )}
    </div>
  )
}

export interface ReviewPrompt {
  readonly userId: string
  readonly fingerprint: string
  /** No saved copy of their keys yet: this is trust on first use. */
  readonly firstSight: boolean
}

/** The pending queue for one public group, for an admin or ambassador. */
export function PendingJoinRequestsPanel({
  requests,
  usernames,
  review,
  busyUserId,
  hasMore,
  onReview,
  onCancelReview,
  onApprove,
  onDeny,
  onLoadMore,
}: {
  readonly requests: readonly JoinRequestEntry[]
  readonly usernames: ReadonlyMap<string, string>
  readonly review: ReviewPrompt | null
  readonly busyUserId: string | null
  readonly hasMore: boolean
  readonly onReview: (userId: string) => void
  readonly onCancelReview: () => void
  readonly onApprove: (userId: string) => void
  readonly onDeny: (userId: string) => void
  readonly onLoadMore: () => void
}) {
  if (requests.length === 0) {
    return <p className="text-sm text-muted-foreground">No one is waiting to join.</p>
  }
  return (
    <div className="flex w-full max-w-md flex-col gap-2">
      <ul className="flex flex-col gap-2">
        {requests.map((r) => {
          const reviewing = review?.userId === r.userId ? review : null
          const busy = busyUserId !== null
          return (
            <li key={r.requestId} className="flex flex-col gap-2 rounded-md border px-3 py-2">
              <span className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
                <span className="min-w-0 [overflow-wrap:anywhere]">
                  <span className={`font-medium ${unresolvedClass(r.userId, usernames)}`}>
                    {memberLabel(r.userId, usernames)}
                  </span>
                  <span className="block text-xs text-muted-foreground">Asked on {r.day}</span>
                </span>
                {reviewing === null && (
                  <span className="flex flex-wrap gap-2">
                    <Button
                      type="button"
                      size="sm"
                      disabled={busy}
                      onClick={() => {
                        onReview(r.userId)
                      }}
                    >
                      {busyUserId === r.userId ? 'Checking…' : 'Review'}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      disabled={busy}
                      onClick={() => {
                        onDeny(r.userId)
                      }}
                    >
                      Decline
                    </Button>
                  </span>
                )}
              </span>
              {reviewing !== null && (
                <span className="flex flex-col gap-2">
                  <span className="text-xs text-muted-foreground">
                    {reviewing.firstSight
                      ? 'You have never seen this person before, and there is no invite link to vouch for them: whoever sent this request is trusted on first sight. '
                      : 'These keys match the copy you saved earlier. '}
                    Approving gives them the group key, wrapped to the keys below, so first check
                    this fingerprint with them in person or on a call you know is them. They can
                    read theirs under &quot;Your key fingerprint&quot; on any group&apos;s Members
                    page. Do not take it from the group or from a message.
                  </span>
                  <FingerprintBlock value={reviewing.fingerprint} />
                  <span className="flex flex-wrap gap-2">
                    <Button
                      type="button"
                      size="sm"
                      disabled={busy}
                      onClick={() => {
                        onApprove(r.userId)
                      }}
                    >
                      {busyUserId === r.userId ? 'Approving…' : 'It matches, approve'}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      disabled={busy}
                      onClick={onCancelReview}
                    >
                      Cancel
                    </Button>
                  </span>
                </span>
              )}
            </li>
          )
        })}
      </ul>
      {hasMore && (
        <Button type="button" variant="outline" size="sm" onClick={onLoadMore}>
          Show more
        </Button>
      )}
    </div>
  )
}

export function NoticeAlert({
  message,
  destructive,
}: {
  readonly message: string
  readonly destructive?: boolean
}) {
  return (
    <Alert variant={destructive === true ? 'destructive' : 'default'}>
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  )
}

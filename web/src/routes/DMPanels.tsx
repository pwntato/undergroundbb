// The presentational halves of the two direct-message screens (#73). Prop-driven with no effects,
// context or fetching, so they test with renderToStaticMarkup and by calling them as functions.
// Every decision (what may be sent or opened, which message to show) is made in runDMs.ts.

import { Link } from 'react-router'
import { Button } from '@/components/ui/button'
import type { IncomingDM } from '@/lib/api/dms'
import { FingerprintBlock } from './FingerprintBlock'
import { memberLabel, unresolvedClass } from './memberLabel'

const linkClass = 'text-xs text-primary underline-offset-4 hover:underline'

/** What the new-message screen knows about the person being messaged. */
export type NewDMState =
  | { readonly status: 'checking' }
  | {
      readonly status: 'ready'
      readonly fingerprint: string
      /** No saved copy of their keys yet: this is trust on first use. */
      readonly firstSight: boolean
    }
  /** The checks refused: `message` says why, and nothing can be sent. */
  | { readonly status: 'blocked'; readonly message: string }

/** Start a conversation: shows the other person's fingerprint BEFORE anything is sent. */
export function NewDMPanel({
  username,
  state,
  busy,
  onSend,
}: {
  readonly username: string
  readonly state: NewDMState
  readonly busy: boolean
  readonly onSend: () => void
}) {
  return (
    <div className="flex w-full max-w-md flex-col gap-3">
      <h1 className="text-xl font-semibold [overflow-wrap:anywhere]">Message {username}</h1>
      {state.status === 'checking' && (
        <p className="text-sm text-muted-foreground">Checking their keys…</p>
      )}
      {state.status === 'blocked' && <p className="text-sm text-destructive">{state.message}</p>}
      {state.status === 'ready' && (
        <>
          <p className="text-sm text-muted-foreground">
            {state.firstSight
              ? 'You have never messaged this person before, and no invite link vouches for them: whoever answers for this account is trusted on first sight. '
              : 'These keys match the copy you saved earlier. '}
            Starting a conversation gives them the key to it, wrapped to the keys below, so first
            check this fingerprint with them in person or on a call you know is them. They can read
            theirs under &quot;Your key fingerprint&quot; on any group&apos;s Members page. Do not
            take it from a message.
          </p>
          <FingerprintBlock value={state.fingerprint} />
          <p className="text-xs text-muted-foreground">
            They will see your message only if they choose to open it, and nothing about you is
            added to their account until they do.
          </p>
          <div>
            <Button type="button" disabled={busy} onClick={onSend}>
              {busy ? 'Starting…' : 'It matches, start the conversation'}
            </Button>
          </div>
        </>
      )}
    </div>
  )
}

export interface DMReviewPrompt {
  readonly groupId: string
  readonly fingerprint: string
  /** No saved copy of the sender's keys yet: this is trust on first use. */
  readonly firstSight: boolean
}

/** The conversations other people have started with the caller, waiting to be opened. */
export function IncomingDMsPanel({
  dms,
  usernames,
  review,
  busyGroupId,
  onReview,
  onCancelReview,
  onAccept,
  onDecline,
}: {
  readonly dms: readonly IncomingDM[]
  readonly usernames: ReadonlyMap<string, string>
  readonly review: DMReviewPrompt | null
  readonly busyGroupId: string | null
  readonly onReview: (groupId: string) => void
  readonly onCancelReview: () => void
  readonly onAccept: (groupId: string) => void
  readonly onDecline: (groupId: string) => void
}) {
  if (dms.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No one is waiting to message you. When someone starts a conversation, it waits here until
        you accept or decline it.
      </p>
    )
  }
  const busy = busyGroupId !== null
  return (
    <ul className="flex w-full max-w-md flex-col gap-2">
      {dms.map((dm) => {
        const reviewing = review?.groupId === dm.groupId ? review : null
        const sender = memberLabel(dm.senderUserId, usernames)
        return (
          <li key={dm.groupId} className="flex flex-col gap-2 rounded-md border px-3 py-2">
            <span className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
              <span className="min-w-0 [overflow-wrap:anywhere]">
                <span className={`font-medium ${unresolvedClass(dm.senderUserId, usernames)}`}>
                  {sender}
                </span>
                <span className="block text-xs text-muted-foreground">
                  Wants to message you · {dm.admissionDay}
                </span>
              </span>
              {reviewing === null && (
                <span className="flex flex-wrap gap-2">
                  <Button
                    type="button"
                    size="sm"
                    disabled={busy}
                    onClick={() => {
                      onReview(dm.groupId)
                    }}
                  >
                    {busyGroupId === dm.groupId ? 'Checking…' : 'Review'}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={busy}
                    onClick={() => {
                      onDecline(dm.groupId)
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
                    ? 'You have never seen this person before, and no invite link vouches for them: whoever answers for this account is trusted on first sight. '
                    : 'These keys match the copy you saved earlier. '}
                  Opening this makes you a member of a conversation with them, so first check this
                  fingerprint with them in person or on a call you know is them. They can read
                  theirs under &quot;Your key fingerprint&quot; on any group&apos;s Members page. Do
                  not take it from the message.
                </span>
                <FingerprintBlock value={reviewing.fingerprint} />
                <span className="flex flex-wrap gap-2">
                  <Button
                    type="button"
                    size="sm"
                    disabled={busy}
                    onClick={() => {
                      onAccept(dm.groupId)
                    }}
                  >
                    {busyGroupId === dm.groupId ? 'Opening…' : 'It matches, open it'}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={busy}
                    onClick={() => {
                      onDecline(dm.groupId)
                    }}
                  >
                    Decline
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
            {reviewing === null && (
              <Link to={`/users/${dm.senderUserId}`} className={linkClass}>
                See their profile
              </Link>
            )}
          </li>
        )
      })}
    </ul>
  )
}

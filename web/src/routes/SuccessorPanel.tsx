// The presentational half of SuccessorScreen -- #161. Prop-driven with no
// effects, so it is tested with renderToStaticMarkup (see GroupList.tsx's
// header). Two audiences on one page:
//  - an admin sees whether they have a successor designated, whether it still
//    stands or has lapsed, and can designate or revoke;
//  - a member a designation names sees when they could claim, and claims.
// Everything here is advisory (see lib/groups/designation.ts): the server and
// every viewer's grant check make the real decision.

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  adminSuccessorStatus,
  MAX_PERIOD_DAYS,
  MIN_PERIOD_DAYS,
  successorOffers,
  utcDayMs,
} from '@/lib/groups/designation'
import { isDeletedUser, memberLabel } from './memberLabel'
import type { SuccessorView } from './runSuccessor'
import { adminStatusText, offerText } from './successorText'

export interface DesignationChoice {
  readonly successorUserId: string
  /** Kept as typed so a half-edited number is not rewritten under the cursor. */
  readonly periodDays: string
}

const FIELD_CLASS =
  'h-9 rounded-md border border-input bg-transparent px-3 text-sm shadow-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring'

export function SuccessorPanel({
  view,
  userId,
  usernames,
  nowMs,
  busy,
  choice,
  onChoice,
  onDesignate,
  onRevoke,
  confirmingClaim,
  onStartClaim,
  onCancelClaim,
  onConfirmClaim,
}: {
  readonly view: SuccessorView
  readonly userId: string
  readonly usernames?: ReadonlyMap<string, string> | undefined
  /** The clock the status is judged against, ms since the epoch. */
  readonly nowMs: number
  /** A designation or claim is in flight; every control locks. */
  readonly busy: boolean
  readonly choice: DesignationChoice
  readonly onChoice: (next: DesignationChoice) => void
  readonly onDesignate: () => void
  readonly onRevoke: () => void
  /** The designation whose claim is awaiting confirmation, if any. */
  readonly confirmingClaim: string | null
  readonly onStartClaim: (designationSortKey: string) => void
  readonly onCancelClaim: () => void
  readonly onConfirmClaim: (designationSortKey: string) => void
}) {
  if (view.myRole === 'admin') {
    const status = adminSuccessorStatus(userId, view.designations, view.grants, view.members, nowMs)
    const candidates = view.members.filter(
      (m) => m.userId !== userId && m.role !== 'admin' && !isDeletedUser(m.userId, usernames),
    )
    return (
      <div className="flex w-full max-w-md flex-col gap-4">
        <h2 className="text-lg font-semibold">Successor</h2>
        <p className={`text-sm ${status.kind === 'active' ? '' : 'text-destructive'}`}>
          {adminStatusText(status, usernames)}
        </p>
        {candidates.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            There is nobody else in this group to name yet.
          </p>
        ) : (
          <div className="flex flex-col gap-3">
            <label className="flex flex-col gap-1 text-sm">
              Successor
              <select
                className={FIELD_CLASS}
                value={choice.successorUserId}
                disabled={busy}
                onChange={(e) => {
                  onChoice({ ...choice, successorUserId: e.target.value })
                }}
              >
                <option value="">Choose a member</option>
                {candidates.map((m) => (
                  <option key={m.userId} value={m.userId}>
                    {memberLabel(m.userId, usernames)}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-sm">
              Days of inactivity before they can take over ({String(MIN_PERIOD_DAYS)} to{' '}
              {String(MAX_PERIOD_DAYS)})
              <Input
                type="number"
                inputMode="numeric"
                min={MIN_PERIOD_DAYS}
                max={MAX_PERIOD_DAYS}
                step={1}
                value={choice.periodDays}
                disabled={busy}
                onChange={(e) => {
                  onChoice({ ...choice, periodDays: e.target.value })
                }}
              />
            </label>
            <p className="text-xs text-muted-foreground">
              They can only take over if you and every other admin have not logged in for that long.
              Logging in as usual keeps it from ever firing. You can designate once a day, and not
              on the day you were made an admin.
            </p>
            <div className="flex gap-2">
              <Button
                type="button"
                size="sm"
                disabled={busy || choice.successorUserId === ''}
                onClick={onDesignate}
              >
                {status.kind === 'active' ? 'Replace successor' : 'Designate successor'}
              </Button>
              {status.kind === 'active' && (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={busy}
                  onClick={onRevoke}
                >
                  Revoke
                </Button>
              )}
            </div>
          </div>
        )}
      </div>
    )
  }

  const offers = successorOffers(
    userId,
    view.designations,
    view.grants,
    view.members,
    utcDayMs(nowMs),
  )
  if (offers.length === 0) {
    return (
      <p className="max-w-md text-sm text-muted-foreground">
        Nobody has named you as a successor in this group. Only an admin can designate a successor.
      </p>
    )
  }
  return (
    <div className="flex w-full max-w-md flex-col gap-4">
      <h2 className="text-lg font-semibold">You are a designated successor</h2>
      {offers.map((offer) => {
        const key = offer.designation.sortKey
        const adminName = memberLabel(offer.adminUserId, usernames)
        return (
          <div key={key} className="flex flex-col gap-2 rounded-md border px-3 py-3">
            <p className="text-sm">{offerText(offer, adminName)}</p>
            {offer.periodElapsed && confirmingClaim !== key && (
              <Button
                type="button"
                size="sm"
                disabled={busy}
                onClick={() => {
                  onStartClaim(key)
                }}
              >
                Claim admin role
              </Button>
            )}
            {offer.periodElapsed && confirmingClaim === key && (
              <>
                <p className="text-sm">
                  This makes you an admin of this group. The server checks that {adminName} and
                  every other admin have really been inactive and refuses otherwise. You can grant
                  roles yourself from the day after you claim; until then, role changes are refused.
                </p>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    size="sm"
                    disabled={busy}
                    onClick={() => {
                      onConfirmClaim(key)
                    }}
                  >
                    Confirm claim
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={busy}
                    onClick={onCancelClaim}
                  >
                    Cancel
                  </Button>
                </div>
              </>
            )}
          </div>
        )
      })}
    </div>
  )
}

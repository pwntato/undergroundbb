// The presentational half of leaving a group -- issue #66. Prop-driven, no
// effects, so it is tested with renderToStaticMarkup (see GroupList.tsx's
// header). Leaving is destructive and irreversible without a new invite, so
// it takes an explicit confirmation step. The last Admin of a group that
// still has other members cannot leave until they choose a successor; the
// departing admin knows who should take over better than any heuristic.

import { Button } from '@/components/ui/button'
import { memberLabel, unresolvedClass } from './memberLabel'
import type { LeavePlan } from './runLeaveGroup'

export function LeaveGroupPanel({
  plan,
  confirming,
  busy,
  usernames,
  onStart,
  onCancel,
  onConfirm,
}: {
  readonly plan: LeavePlan
  /** Whether the confirmation step is open. */
  readonly confirming: boolean
  /** A leave (or the promotion before it) is in flight; every control locks. */
  readonly busy: boolean
  readonly usernames?: ReadonlyMap<string, string> | undefined
  readonly onStart: () => void
  readonly onCancel: () => void
  /** successorUserId is set only for a 'needsSuccessor' plan. */
  readonly onConfirm: (successorUserId?: string) => void
}) {
  if (!confirming) {
    return (
      <div className="flex w-full max-w-md flex-col gap-2">
        <Button type="button" variant="outline" size="sm" disabled={busy} onClick={onStart}>
          Leave group
        </Button>
      </div>
    )
  }
  return (
    <div className="flex w-full max-w-md flex-col gap-3 rounded-md border border-destructive px-3 py-3">
      {plan.kind === 'deletesGroup' && (
        <p className="text-sm">
          You are the only member. Leaving deletes this group and everything in it, permanently.
        </p>
      )}
      {plan.kind === 'plain' && (
        <p className="text-sm">
          Leave this group? You will lose access to it, and will need a new invite to come back.
        </p>
      )}
      {plan.kind === 'needsSuccessor' && (
        <>
          <p className="text-sm">
            You are the only admin. Choose who takes over before you go; they are made an admin and
            you then leave.
          </p>
          <ul className="flex flex-col gap-2">
            {plan.candidates.map((id) => (
              <li key={id} className="flex items-center justify-between gap-2">
                <span className={`${unresolvedClass(id, usernames)} text-sm`} title={id}>
                  {memberLabel(id, usernames)}
                </span>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={busy}
                  onClick={() => {
                    onConfirm(id)
                  }}
                >
                  Make admin and leave
                </Button>
              </li>
            ))}
          </ul>
        </>
      )}
      <div className="flex flex-wrap gap-2">
        {plan.kind !== 'needsSuccessor' && (
          <Button
            type="button"
            variant="destructive"
            size="sm"
            disabled={busy}
            onClick={() => {
              onConfirm()
            }}
          >
            {busy ? 'Leaving…' : plan.kind === 'deletesGroup' ? 'Delete group' : 'Leave group'}
          </Button>
        )}
        <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </div>
  )
}

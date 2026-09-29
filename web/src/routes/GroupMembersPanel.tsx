// The presentational half of GroupMembersScreen -- issue #37. Prop-driven
// with no effects, context or fetching, so it can be tested with
// renderToStaticMarkup (see GroupList.tsx's header for why that is this
// codebase's pattern).
//
// The roster carries ids only until the users projection (GET
// /api/users/:id) exists, so members are labeled by a shortened id, with the
// signed-in user marked "you". Only an admin sees role controls, and never
// on their own row: the server refuses a self-change, which is also what
// keeps a group from ending up with no admin. Demote/remove of an admin
// beyond a plain role change is M6 (#55-#58).

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import type { MemberRole } from '@/lib/api/groups'
import { memberLabel } from './memberLabel'
import type { MembersView } from './runGroupMembers'

const ROLES: readonly MemberRole[] = ['admin', 'ambassador', 'member']

const ROLE_LABEL: Record<MemberRole, string> = {
  admin: 'Admin',
  ambassador: 'Ambassador',
  member: 'Member',
}

export function GroupMembersPanel({
  view,
  userId,
  busyUserId,
  message,
  error,
  onChangeRole,
}: {
  readonly view: MembersView
  /** The signed-in user's own id. */
  readonly userId: string
  /** The member whose role change is in flight, if any; all controls lock while one is. */
  readonly busyUserId: string | null
  readonly message: string | null
  readonly error: string | null
  readonly onChangeRole: (subjectUserId: string, role: MemberRole) => void
}) {
  const isAdmin = view.myRole === 'admin'
  return (
    <div className="flex w-full max-w-md flex-col gap-4">
      <h1 className="text-2xl font-semibold">Members</h1>
      {message !== null && (
        <Alert>
          <AlertDescription>{message}</AlertDescription>
        </Alert>
      )}
      {error !== null && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <ul className="flex flex-col gap-2">
        {view.members.map((m) => {
          const isSelf = m.userId === userId
          return (
            <li
              key={m.userId}
              className="flex flex-col gap-2 rounded-md border px-3 py-2 sm:flex-row sm:items-center sm:justify-between"
            >
              <span className="flex items-baseline gap-2">
                <span className="font-mono text-sm" title={m.userId}>
                  {memberLabel(m.userId)}
                </span>
                {isSelf && <span className="text-xs text-muted-foreground">you</span>}
                <span className="text-xs text-muted-foreground">{ROLE_LABEL[m.role]}</span>
              </span>
              {isAdmin && !isSelf && (
                <span className="flex flex-wrap gap-2">
                  {ROLES.filter((r) => r !== m.role).map((r) => (
                    <Button
                      key={r}
                      type="button"
                      variant="outline"
                      size="sm"
                      disabled={busyUserId !== null}
                      onClick={() => {
                        onChangeRole(m.userId, r)
                      }}
                    >
                      {busyUserId === m.userId ? 'Saving…' : `Make ${ROLE_LABEL[r].toLowerCase()}`}
                    </Button>
                  ))}
                </span>
              )}
            </li>
          )
        })}
      </ul>
      {isAdmin && view.myGrantSortKey === undefined && (
        <p className="text-xs text-muted-foreground">
          Your own admin grant is not on record, so roles can&apos;t be changed from here yet.
        </p>
      )}
    </div>
  )
}

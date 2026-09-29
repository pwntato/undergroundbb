// The presentational half of GroupMembersScreen -- issue #37. Prop-driven
// with no effects, context or fetching, so it can be tested with
// renderToStaticMarkup (see GroupList.tsx's header for why that is this
// codebase's pattern).
//
// Members are labeled by username (read from the users projection, GET
// /api/users/:id, by the screen and passed in), falling back to a shortened
// id while it loads or if it fails, with the signed-in user marked "you".
// Only an admin sees role controls, and never on their own row: the server refuses a self-change, which is also what
// keeps a group from ending up with no admin. Demote/remove of an admin
// beyond a plain role change is M6 (#55-#58).

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import type { MemberRole } from '@/lib/api/groups'
import { memberLabel, unresolvedClass } from './memberLabel'
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
  onChangeRole,
  usernames,
}: {
  readonly view: MembersView
  /** The signed-in user's own id. */
  readonly userId: string
  /** The member whose role change is in flight, if any; all controls lock while one is. */
  readonly busyUserId: string | null
  readonly onChangeRole: (subjectUserId: string, role: MemberRole) => void
  /** userId to username; anything missing renders as a short id. */
  readonly usernames?: ReadonlyMap<string, string> | undefined
}) {
  const isAdmin = view.myRole === 'admin'
  // Without our own grant on record a change can't be signed, so the buttons
  // would only fail; the note below the list says why they are absent.
  const canChangeRoles = isAdmin && view.myGrantSortKey !== undefined && view.myGrantSortKey !== ''
  return (
    <div className="flex w-full max-w-md flex-col gap-4">
      <h1 className="text-2xl font-semibold">Members</h1>
      <ul className="flex flex-col gap-2">
        {view.members.map((m) => {
          const isSelf = m.userId === userId
          return (
            <li
              key={m.userId}
              className="flex flex-col gap-2 rounded-md border px-3 py-2 sm:flex-row sm:items-center sm:justify-between"
            >
              <span className="flex items-baseline gap-2">
                <span
                  className={`${unresolvedClass(m.userId, usernames)} text-sm`}
                  title={m.userId}
                >
                  {memberLabel(m.userId, usernames)}
                </span>
                {isSelf && <span className="text-xs text-muted-foreground">you</span>}
                <span className="text-xs text-muted-foreground">{ROLE_LABEL[m.role]}</span>
              </span>
              {canChangeRoles && !isSelf && (
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
      {isAdmin && !canChangeRoles && (
        <p className="text-xs text-muted-foreground">
          Your own admin grant is not on record, so roles can&apos;t be changed from here yet.
        </p>
      )}
    </div>
  )
}

/**
 * The outcome of the last change attempt. Rendered by the screen, outside the
 * panel, so it survives the panel unmounting when a reload fails -- which is
 * likeliest right after an ambiguous network failure, the very case where the
 * user most needs to read the message.
 */
export function MembersFeedback({
  message,
  error,
}: {
  readonly message: string | null
  readonly error: string | null
}) {
  return (
    <>
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
    </>
  )
}

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
import type { RoleStatus } from '@/lib/crypto/grant-chain'
import { memberLabel, unresolvedClass } from './memberLabel'
import type { GrantCheck } from './runGrantCheck'
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
  check,
}: {
  readonly view: MembersView
  /** The signed-in user's own id. */
  readonly userId: string
  /** The member whose role change is in flight, if any; all controls lock while one is. */
  readonly busyUserId: string | null
  readonly onChangeRole: (subjectUserId: string, role: MemberRole) => void
  /** userId to username; anything missing renders as a short id. */
  readonly usernames?: ReadonlyMap<string, string> | undefined
  /**
   * The signed-grant-history check, once it has run. Absent while it loads
   * and 'unavailable' when it could not run; either way no marks are shown.
   */
  readonly check?: GrantCheck | null | undefined
}) {
  const checked = check?.state === 'checked' ? check : null
  const isAdmin = view.myRole === 'admin'
  // Without our own grant on record a change can't be signed, so the buttons
  // would only fail; the note below the list says why they are absent.
  const canChangeRoles = isAdmin && view.myGrantSortKey !== undefined && view.myGrantSortKey !== ''
  return (
    <div className="flex w-full max-w-md flex-col gap-4">
      <h1 className="text-2xl font-semibold">Members</h1>
      {checked?.anchor === 'root-unverified' && (
        <p className="text-xs text-amber-700 dark:text-amber-400">
          This group&apos;s root grant couldn&apos;t be checked, so no role below is confirmed. This
          can be a temporary lookup failure, so try reloading; if it persists, don&apos;t rely on
          roles or invites here until you&apos;ve checked with the group another way.
        </p>
      )}
      {checked?.anchor === 'changed' && (
        <Alert variant="destructive">
          <AlertDescription>
            This group&apos;s trust anchor is different from the one this browser first saw, so no
            role below is confirmed. Don&apos;t rely on roles or invites here until you&apos;ve
            checked with the group another way.
          </AlertDescription>
        </Alert>
      )}
      {checked !== null && checked.blockedKeyUsers.length > 0 && (
        <Alert variant="destructive">
          <AlertDescription>
            The keys the server shows for{' '}
            {checked.blockedKeyUsers.map((id) => memberLabel(id, usernames)).join(', ')} don&apos;t
            match the copy you saved earlier (or that saved copy failed its own check), so roles
            they vouch for are not confirmed. Don&apos;t rely on roles or invites here until
            you&apos;ve checked with them another way.
          </AlertDescription>
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
                <span
                  className={`${unresolvedClass(m.userId, usernames)} text-sm`}
                  title={m.userId}
                >
                  {memberLabel(m.userId, usernames)}
                </span>
                {isSelf && <span className="text-xs text-muted-foreground">you</span>}
                <span className="text-xs text-muted-foreground">{ROLE_LABEL[m.role]}</span>
                <RoleMark status={checked?.statuses.get(m.userId)} verified={isVerified(checked)} />
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
      {checked !== null && (
        <p className="text-xs text-muted-foreground">
          {isVerified(checked)
            ? "Roles match the group's signed grant history, and every key matched the copy this browser saved earlier. A server that lied the very first time you saw someone isn't caught by that."
            : checked.keys === 'blocked' ||
                checked.anchor === 'changed' ||
                checked.anchor === 'root-unverified'
              ? "Roles are checked against the group's signed grant history, and this check found a problem (see the warning above)."
              : checked.keys === 'unchecked'
                ? "Roles are checked against the group's signed grant history, but the keys behind it couldn't be checked against your saved copies, so this can't rule out a dishonest server."
                : checked.keys === 'first-seen' || checked.anchor === 'first-seen'
                  ? "Roles are checked against the group's signed grant history. Some keys or the group's creator were saved just now on first sight, so this can't rule out a server that lied to you at first contact."
                  : "Roles are checked against the group's signed grant history."}
          {checked.anchor === 'unpinned' &&
            " This browser couldn't remember the group's creator, so a later swap wouldn't be noticed."}
        </p>
      )}
      {isAdmin && !canChangeRoles && (
        <p className="text-xs text-muted-foreground">
          Your own admin grant is not on record, so roles can&apos;t be changed from here yet.
        </p>
      )}
    </div>
  )
}

/**
 * "Verified" means the chain is consistent AND both the group's creator and
 * every grantor's keys matched something this browser saved earlier. A first
 * sighting is trusted and saved, so it stays "chain consistent".
 */
function isVerified(checked: Extract<GrantCheck, { state: 'checked' }> | null): boolean {
  return checked !== null && checked.anchor === 'pinned' && checked.keys === 'pinned'
}

function RoleMark({
  status,
  verified,
}: {
  readonly status: RoleStatus | undefined
  readonly verified: boolean
}) {
  if (status === undefined) {
    return null
  }
  if (status.status === 'verified') {
    return (
      <span
        className="text-xs text-muted-foreground"
        title={
          verified
            ? "This role matches the group's signed grant history, and every key matched what this browser saved earlier."
            : "This role matches the group's signed grant history."
        }
      >
        {verified ? '✓ verified' : '✓ chain consistent'}
      </span>
    )
  }
  return (
    <span
      className="text-xs text-amber-700 dark:text-amber-400"
      title={`Not confirmed: ${status.reason}.`}
    >
      Role not confirmed
    </span>
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

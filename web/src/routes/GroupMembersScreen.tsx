// #37: member list and role management at /groups/:groupId/members. Wrapped
// by RequireAuth in App.tsx (baseline session check; the server decides who
// may see the roster or change a role, and its 404/403 are this screen's real
// authorization, the same split GroupSettingsScreen has).
//
// Loading and role changes are runGroupMembers.ts's job; this component owns
// state and effects, and GroupMembersPanel owns rendering.

import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { changeMemberRole, getGroup, listMembers, type MemberRole } from '@/lib/api/groups'
import { signRoleGrant } from '@/lib/crypto/worker-client'
import { useSession } from '@/lib/session/useSession'
import { GroupMembersPanel } from './GroupMembersPanel'
import { memberLabel } from './memberLabel'
import { changeRole, loadMembers, type ChangeRoleResult, type MembersView } from './runGroupMembers'

type LoadState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly view: MembersView }
  | { readonly status: 'notFound' | 'authRequired' | 'failed' }

const CHANGE_ERRORS: Record<Exclude<ChangeRoleResult, { ok: true }>['kind'], string> = {
  stale:
    'The group changed while you were working, so nothing was saved. The latest roster is shown; try again.',
  forbidden: 'Only a group admin can change roles.',
  authRequired: 'Your session has expired. Log in again and retry.',
  coldKeys: 'Log in again to change roles.',
  notFound: 'This member or group no longer exists.',
  rejected: 'The server rejected this change.',
  ambiguous:
    "We couldn't confirm whether the change was saved. The latest roster is shown; check it before trying again.",
}

export function GroupMembersScreen() {
  const { groupId } = useParams<{ groupId: string }>()
  const session = useSession()
  const userId = session.userId
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [busyUserId, setBusyUserId] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const reload = useCallback(
    async (isCancelled: () => boolean) => {
      if (groupId === undefined) {
        return
      }
      const result = await loadMembers({ getGroup, listMembers }, groupId)
      if (isCancelled()) {
        return
      }
      setLoad(result.ok ? { status: 'ready', view: result.view } : { status: result.kind })
    },
    [groupId],
  )

  useEffect(() => {
    let cancelled = false
    void (async () => {
      await reload(() => cancelled)
    })()
    return () => {
      cancelled = true
    }
  }, [reload])

  if (groupId === undefined) {
    return (
      <Alert variant="destructive">
        <AlertDescription>Missing group id.</AlertDescription>
      </Alert>
    )
  }

  const handleChangeRole = (subjectUserId: string, role: MemberRole) => {
    if (load.status !== 'ready' || userId === null || busyUserId !== null) {
      return
    }
    const { view } = load
    setBusyUserId(subjectUserId)
    setMessage(null)
    setError(null)
    void (async () => {
      const outcome = await changeRole(
        { signRoleGrant, changeMemberRole, userId },
        view,
        subjectUserId,
        role,
      )
      if (outcome.ok) {
        setMessage(`${memberLabel(subjectUserId)} is now ${role}.`)
      } else {
        setError(outcome.kind === 'rejected' ? outcome.message : CHANGE_ERRORS[outcome.kind])
      }
      // Reload after a success (new role and new grant ref) and after any
      // outcome that says the roster or our own standing moved; the next
      // change must sign on the CURRENT grant, never the one this view holds.
      if (outcome.ok || outcome.kind === 'stale' || outcome.kind === 'ambiguous') {
        await reload(() => false)
      }
      setBusyUserId(null)
    })()
  }

  return (
    <>
      {load.status === 'loading' && <p className="text-sm text-muted-foreground">Loading…</p>}
      {load.status === 'notFound' && (
        <p className="text-sm text-muted-foreground">
          This group doesn&apos;t exist, or you&apos;re not a member of it.
        </p>
      )}
      {load.status === 'authRequired' && (
        <p className="text-sm text-destructive">Your session has expired. Log in again.</p>
      )}
      {load.status === 'failed' && (
        <p className="text-sm text-destructive">
          Couldn&apos;t load the members. Try reloading the page.
        </p>
      )}
      {load.status === 'ready' && userId !== null && (
        <GroupMembersPanel
          view={load.view}
          userId={userId}
          busyUserId={busyUserId}
          message={message}
          error={error}
          onChangeRole={handleChangeRole}
        />
      )}
      <Link to="/" className="text-sm text-primary underline-offset-4 hover:underline">
        Back to your groups
      </Link>
    </>
  )
}

// #37: member list and role management at /groups/:groupId/members. Wrapped
// by RequireAuth in App.tsx (baseline session check; the server decides who
// may see the roster or change a role, and its 404/403 are this screen's real
// authorization, the same split GroupSettingsScreen has).
//
// Loading and role changes are runGroupMembers.ts's job; this component owns
// state and effects, and GroupMembersPanel owns rendering.

import { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  changeMemberRole,
  getGroup,
  leaveGroup,
  listGrants,
  listMembers,
  type MemberRole,
} from '@/lib/api/groups'
import { signRoleGrant } from '@/lib/crypto/worker-client'
import { readAnchorPin, writeAnchorPin } from '@/lib/groups/anchorPin'
import { getUser } from '@/lib/api/users'
import { useSession } from '@/lib/session/useSession'
import { GroupMembersPanel, MembersFeedback } from './GroupMembersPanel'
import { LeaveGroupPanel } from './LeaveGroupPanel'
import { memberLabel } from './memberLabel'
import { useUsernames } from './useUsernames'
import { checkGrants, type GrantCheck } from './runGrantCheck'
import { leaveFailureMessage, leavePlan, runLeave } from './runLeaveGroup'
import {
  changeRole,
  loadMembers,
  shouldReloadAfter,
  type ChangeRoleResult,
  type MembersView,
} from './runGroupMembers'

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
  const navigate = useNavigate()
  const userId = session.userId
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [busyUserId, setBusyUserId] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [confirmingLeave, setConfirmingLeave] = useState(false)
  const [grantCheck, setGrantCheck] = useState<GrantCheck | null>(null)

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

  const usernames = useUsernames(
    load.status === 'ready' ? load.view.members.map((m) => m.userId) : [],
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

  // Re-run whenever the roster (re)loads, since a role change appends a grant.
  const loadedView = load.status === 'ready' ? load.view : null
  useEffect(() => {
    if (loadedView === null || userId === null) {
      return
    }
    let cancelled = false
    void (async () => {
      const result = await checkGrants(
        {
          listGrants,
          getUser,
          readPin: (g) => readAnchorPin(userId, g),
          writePin: (g, pin) => writeAnchorPin(userId, g, pin),
        },
        loadedView.groupId,
        loadedView.members,
      )
      if (!cancelled) {
        setGrantCheck(result)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [loadedView, userId])

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
        setMessage(`${memberLabel(subjectUserId, usernames)} is now ${role}.`)
      } else {
        setError(outcome.kind === 'rejected' ? outcome.message : CHANGE_ERRORS[outcome.kind])
      }
      // Reload so the roster and the grant this view signs on are current
      // (see shouldReloadAfter for the outcomes that skip it).
      if (shouldReloadAfter(outcome)) {
        await reload(() => false)
      }
      setBusyUserId(null)
    })()
  }

  const handleLeave = (successorUserId?: string) => {
    if (load.status !== 'ready' || userId === null || busyUserId !== null) {
      return
    }
    const { view } = load
    setBusyUserId(userId)
    setMessage(null)
    setError(null)
    void (async () => {
      if (successorUserId !== undefined) {
        // Promote first; only a confirmed promotion lets the leave proceed.
        const promoted = await changeRole(
          { signRoleGrant, changeMemberRole, userId },
          view,
          successorUserId,
          'admin',
        )
        if (!promoted.ok) {
          setError(promoted.kind === 'rejected' ? promoted.message : CHANGE_ERRORS[promoted.kind])
          if (shouldReloadAfter(promoted)) {
            await reload(() => false)
          }
          setBusyUserId(null)
          return
        }
      }
      const outcome = await runLeave({ leaveGroup }, view.groupId)
      if (outcome.ok || outcome.kind === 'notFound') {
        // Gone from this group either way; nothing left to show here.
        void navigate('/', { replace: true })
        return
      }
      setError(
        leaveFailureMessage(
          outcome.kind,
          successorUserId === undefined ? undefined : memberLabel(successorUserId, usernames),
        ),
      )
      setConfirmingLeave(false)
      if (outcome.kind === 'lastAdmin' || outcome.kind === 'stale') {
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
          onChangeRole={handleChangeRole}
          check={grantCheck}
        />
      )}
      {load.status === 'ready' && userId !== null && (
        <LeaveGroupPanel
          plan={leavePlan(load.view, userId)}
          confirming={confirmingLeave}
          busy={busyUserId !== null}
          usernames={usernames}
          onStart={() => {
            setConfirmingLeave(true)
          }}
          onCancel={() => {
            setConfirmingLeave(false)
          }}
          onConfirm={handleLeave}
        />
      )}
      <MembersFeedback message={message} error={error} />
      <Link to="/" className="text-sm text-primary underline-offset-4 hover:underline">
        Back to your groups
      </Link>
    </>
  )
}

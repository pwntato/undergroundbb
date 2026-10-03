// #37: member list and role management at /groups/:groupId/members. Wrapped
// by RequireAuth in App.tsx (baseline session check; the server decides who
// may see the roster or change a role, and its 404/403 are this screen's real
// authorization, the same split GroupSettingsScreen has).
//
// Loading and role changes are runGroupMembers.ts's job; this component owns
// state and effects, and GroupMembersPanel owns rendering.

import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  changeMemberRole,
  getGroup,
  leaveGroup,
  listGrants,
  listMembers,
  removeMember,
  type MemberRole,
} from '@/lib/api/groups'
import { ownSigningKeyWithFallback } from '@/lib/session/ownSigningKey'
import { getOwnSigningKey, signRoleGrant, startGroupRotation } from '@/lib/crypto/worker-client'
import { readAnchorPin, writeAnchorPin } from '@/lib/groups/anchorPin'
import { getUser } from '@/lib/api/users'
import { listAllPins } from '@/lib/api/pins'
import { useSession } from '@/lib/session/useSession'
import { GroupMembersPanel, MembersFeedback } from './GroupMembersPanel'
import { LeaveGroupPanel } from './LeaveGroupPanel'
import { memberLabel } from './memberLabel'
import { useUsernames } from './useUsernames'
import { checkForView, checkGrants, type ViewCheck } from './runGrantCheck'
import { makePinKeys, makeRotationDeps } from './rotationDeps'
import { describeRotation, runRotation } from './runRotation'
import { removeFailureMessage, runRemoveMember, shouldReloadAfterRemove } from './runRemoveMember'
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
  const [confirmRemoveUserId, setConfirmRemoveUserId] = useState<string | null>(null)
  // One rotation job at a time per screen: the on-load catch-up and the one a
  // removal starts must not both be re-wrapping.
  const rotationRunning = useRef(false)
  // The check is stored with the exact view it ran against, so a check that
  // belongs to a previous roster or group is never shown against this one.
  const [grantCheck, setGrantCheck] = useState<ViewCheck<MembersView> | null>(null)

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

  const usernamesRef = useRef(usernames)
  useEffect(() => {
    usernamesRef.current = usernames
  }, [usernames])

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
          selfUserId: userId,
          ownSigningKey: () => ownSigningKeyWithFallback(userId, getOwnSigningKey),
          listPins: listAllPins,
          pinKeys: makePinKeys(userId),
        },
        loadedView.groupId,
        loadedView.members,
      )
      if (!cancelled) {
        setGrantCheck({ view: loadedView, result })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [loadedView, userId])

  // An admin who loads the group finishes any rotation left running (this tab
  // or another admin's closed mid-way) and catches up members left behind.
  // runRotation does nothing, and says nothing, when there is nothing to do.
  const isRotatingAdmin =
    loadedView !== null && loadedView.myRole === 'admin' && loadedView.revocationMode === 'rotating'
  const rotationGroupId = isRotatingAdmin ? loadedView.groupId : null
  useEffect(() => {
    if (rotationGroupId === null || userId === null || rotationRunning.current) {
      return
    }
    rotationRunning.current = true
    void (async () => {
      try {
        const outcome = await runRotation(makeRotationDeps(userId), rotationGroupId)
        const note = describeRotation(outcome, (id) => memberLabel(id, usernamesRef.current))
        if (note?.kind === 'error') {
          setError(note.text)
        } else if (note !== null) {
          setMessage(note.text)
        }
      } finally {
        rotationRunning.current = false
      }
    })()
  }, [rotationGroupId, userId])

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

  const handleRemove = (subjectUserId: string) => {
    if (load.status !== 'ready' || userId === null || busyUserId !== null) {
      return
    }
    const { view } = load
    const subject = view.members.find((m) => m.userId === subjectUserId)
    if (subject === undefined) {
      return
    }
    const label = memberLabel(subjectUserId, usernames)
    setBusyUserId(subjectUserId)
    setMessage(null)
    setError(null)
    void (async () => {
      const outcome = await runRemoveMember(
        { getGroup, signRoleGrant, startGroupRotation, removeMember, userId },
        view.groupId,
        subjectUserId,
        subject.role,
      )
      setConfirmRemoveUserId(null)
      if (!outcome.ok) {
        setError(removeFailureMessage(outcome))
      } else if (!outcome.rotating) {
        setMessage(`${label} was removed.`)
      } else {
        // The removal committed and started the rotation; every other
        // member's entry point still has to be re-wrapped, from this tab.
        setMessage(`${label} was removed. Rotating the group key; keep this page open…`)
        rotationRunning.current = true
        try {
          const rotated = await runRotation(makeRotationDeps(userId), view.groupId, {
            exclude: new Set([subjectUserId]),
          })
          const note = describeRotation(rotated, (id) => memberLabel(id, usernamesRef.current))
          setMessage(`${label} was removed.${note?.kind === 'info' ? ` ${note.text}` : ''}`)
          if (note?.kind === 'error') {
            setError(note.text)
          }
        } finally {
          rotationRunning.current = false
        }
      }
      if (shouldReloadAfterRemove(outcome)) {
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
      const outcome = await runLeave(
        { leaveGroup, signRoleGrant, userId },
        view,
        leavePlan(view, userId).kind,
      )
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
          confirmRemoveUserId={confirmRemoveUserId}
          onStartRemove={setConfirmRemoveUserId}
          onCancelRemove={() => {
            setConfirmRemoveUserId(null)
          }}
          onConfirmRemove={handleRemove}
          check={checkForView(grantCheck, load.view)}
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

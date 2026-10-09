// #37: member list and role management at /groups/:groupId/members. Wrapped
// by RequireAuth in App.tsx (baseline session check; the server decides who
// may see the roster or change a role, and its 404/403 are this screen's real
// authorization, the same split GroupSettingsScreen has).
//
// Loading and role changes are runGroupMembers.ts's job; this component owns
// state and effects, and GroupMembersPanel owns rendering.

import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  changeMemberRole,
  getGroup,
  leaveGroup,
  listDesignations,
  listGrants,
  listMembers,
  removeMember,
  type MemberRole,
} from '@/lib/api/groups'
import { ownSigningKeyWithFallback } from '@/lib/session/ownSigningKey'
import { getOwnSigningKey, signRoleGrant, startGroupRotation } from '@/lib/crypto/worker-client'
import { readAnchorPin, writeAnchorPin } from '@/lib/groups/anchorPin'
import { getUsers } from '@/lib/api/users'
import { listAllPins } from '@/lib/api/pins'
import { useSession } from '@/lib/session/useSession'
import { GroupMembersPanel, MembersFeedback, RotationBanner } from './GroupMembersPanel'
import { catchUpResult, rotationNotice } from './rotationStaleness'
import { LeaveGroupPanel } from './LeaveGroupPanel'
import { memberLabel } from './memberLabel'
import { useUsernames } from './useUsernames'
import { checkForView, checkGrants, type ViewCheck } from './runGrantCheck'
import { makePinKeys, makeRotationDeps } from './rotationDeps'
import { catchUpRotation, removeAndRotate, rotationGuardFor } from './rotationJobs'
import { describeRotation, type RotationOutcome } from './runRotation'
import { removeFailureMessage, shouldReloadAfterRemove } from './runRemoveMember'
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
  | { readonly status: 'ready'; readonly view: MembersView; readonly loadedAtMs: number }
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

// Keyed by group: the screen is reused when :groupId changes, and everything
// below (the rotation guard, in-flight messages) belongs to exactly one group.
export function GroupMembersScreen() {
  const { groupId } = useParams<{ groupId: string }>()
  return <GroupMembers key={groupId ?? ''} groupId={groupId} />
}

function GroupMembers({ groupId }: { readonly groupId: string | undefined }) {
  const session = useSession()
  const navigate = useNavigate()
  const userId = session.userId
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [busyUserId, setBusyUserId] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [confirmingLeave, setConfirmingLeave] = useState(false)
  const [confirmRemoveUserId, setConfirmRemoveUserId] = useState<string | null>(null)
  // How this tab's most recent rotation job (on-load catch-up or a removal's)
  // ended; null until one has. The stale-rotation banner's advice depends on it
  // (see rotationNotice).
  const [catchUpStatus, setCatchUpStatus] = useState<RotationOutcome['status'] | null>(null)
  // One rotation job at a time per group, per tab: the on-load catch-up and the
  // one a removal runs must never overlap, even across this screen unmounting
  // and remounting while a job runs (see rotationJobs.ts). The state mirrors
  // the guard so the controls lock and the status line shows.
  const guard = rotationGuardFor(groupId ?? '')
  const subscribeToGuard = useCallback(
    (onChange: () => void) =>
      guard.subscribe(() => {
        onChange()
      }),
    [guard],
  )
  const rotationBusy = useSyncExternalStore(subscribeToGuard, () => guard.held)
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
      setLoad(
        result.ok
          ? { status: 'ready', view: result.view, loadedAtMs: Date.now() }
          : { status: result.kind },
      )
    },
    [groupId],
  )

  // The roster plus whoever started a running rotation, who may have left
  // since and would otherwise show as a short id in the banner.
  const usernames = useUsernames(
    load.status === 'ready'
      ? [
          ...load.view.members.map((m) => m.userId),
          ...(load.view.rotation === undefined ? [] : [load.view.rotation.startedBy]),
        ]
      : [],
  )

  const usernamesRef = useRef(usernames)
  const loadRef = useRef(load)
  useEffect(() => {
    usernamesRef.current = usernames
    loadRef.current = load
  }, [usernames, load])

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
          listDesignations,
          getUsers,
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
    if (rotationGroupId === null || userId === null) {
      return
    }
    void (async () => {
      const result = await catchUpRotation(guard, makeRotationDeps(userId), rotationGroupId)
      if (result.busy) {
        return
      }
      const current = loadRef.current
      const effects = catchUpResult(
        result.outcome,
        current.status === 'ready' ? current.view : null,
        current.status === 'ready' ? current.loadedAtMs : 0,
        (id) => memberLabel(id, usernamesRef.current),
      )
      setCatchUpStatus(effects.status)
      if (effects.error !== null) {
        setError(effects.error)
      } else if (effects.message !== null) {
        setMessage(effects.message)
      }
      // The banner is already suppressed once a rotation completes, so this
      // is only a refresh of the roster.
      if (effects.reload) {
        await reload(() => false)
      }
    })()
  }, [rotationGroupId, userId, guard, reload])

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
    if (load.status !== 'ready' || userId === null || busyUserId !== null || guard.held) {
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
      const result = await removeAndRotate(
        {
          guard,
          remove: { getGroup, signRoleGrant, startGroupRotation, removeMember, userId },
          rotation: makeRotationDeps(userId),
        },
        view.groupId,
        subjectUserId,
        subject.role,
        view.revocationMode === 'rotating',
      )
      setConfirmRemoveUserId(null)
      if (result.busy) {
        setError('A key rotation is still running. Wait for it to finish, then try again.')
        setBusyUserId(null)
        return
      }
      const { removal, rotation } = result
      // A removal can resume a stalled rotation and end differently from the
      // on-load attempt; the banner's advice follows the latest job.
      if (rotation !== undefined) {
        setCatchUpStatus(rotation.status)
      }
      const note =
        rotation === undefined
          ? null
          : describeRotation(rotation, (id) => memberLabel(id, usernamesRef.current))
      if (removal.ok) {
        setMessage(`${label} was removed.${note?.kind === 'info' ? ` ${note.text}` : ''}`)
      } else {
        setError(removeFailureMessage(removal))
      }
      if (note?.kind === 'error') {
        setError(note.text)
      }
      if (shouldReloadAfterRemove(removal)) {
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
        {
          leaveGroup,
          signRoleGrant,
          userId,
          rotation: { rotationDeps: makeRotationDeps(userId), startGroupRotation },
        },
        view,
        leavePlan(view, userId, usernames).kind,
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
          locked={rotationBusy}
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
          plan={leavePlan(load.view, userId, usernames)}
          confirming={confirmingLeave}
          busy={busyUserId !== null || rotationBusy}
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
      {load.status === 'ready' && !rotationBusy && (
        <RotationBanner
          notice={rotationNotice(load.view, load.loadedAtMs, catchUpStatus)}
          startedByLabel={memberLabel(load.view.rotation?.startedBy ?? '', usernames)}
        />
      )}
      <MembersFeedback message={message} error={error} rotating={rotationBusy} />
      {load.status === 'ready' && (
        <Link
          to={`/groups/${encodeURIComponent(load.view.groupId)}/successor`}
          className="text-sm text-primary underline-offset-4 hover:underline"
        >
          Successor for an inactive admin
        </Link>
      )}
      <Link to="/" className="text-sm text-primary underline-offset-4 hover:underline">
        Back to your groups
      </Link>
    </>
  )
}

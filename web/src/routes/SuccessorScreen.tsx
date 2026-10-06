// #161: the successor designation screen at /groups/:groupId/successor. An
// admin designates or revokes the member who takes over if they go inactive
// and sees whether that designation still stands; a designated member sees
// when they can claim and claims. Wrapped by RequireAuth in App.tsx; the
// server's 404/403/409 are the real authorization, as on the members screen.
//
// Loading, signing and submitting are runSuccessor.ts's job; this component
// owns state and effects, and SuccessorPanel owns rendering.

import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  claimDesignation,
  getGroup,
  listDesignations,
  listGrants,
  listMembers,
  putDesignation,
} from '@/lib/api/groups'
import { signSuccessorClaim, signSuccessorDesignation } from '@/lib/crypto/worker-client'
import { SUGGESTED_PERIOD_DAYS } from '@/lib/groups/designation'
import { useSession } from '@/lib/session/useSession'
import { memberLabel } from './memberLabel'
import { SuccessorPanel, type DesignationChoice } from './SuccessorPanel'
import {
  claim,
  designate,
  loadSuccessorView,
  shouldReloadAfterSuccessor,
  type SuccessorActionResult,
  type SuccessorView,
} from './runSuccessor'
import { useUsernames } from './useUsernames'

type LoadState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly view: SuccessorView; readonly loadedAtMs: number }
  | { readonly status: 'notFound' | 'authRequired' | 'failed' }

type Failure = Exclude<SuccessorActionResult, { ok: true }>

const LOAD_DEPS = { getGroup, listMembers, listDesignations, listGrants }

function failureText(outcome: Failure, doing: 'designate' | 'claim'): string {
  switch (outcome.kind) {
    case 'stale':
      return 'The group changed while you were working, so nothing was saved. The latest is shown; check it and try again.'
    case 'forbidden':
      return doing === 'designate'
        ? 'Only a group admin can designate a successor.'
        : 'You cannot claim this.'
    case 'authRequired':
      return 'Your session has expired. Log in again and retry.'
    case 'coldKeys':
      return doing === 'designate'
        ? 'Log in again to designate a successor.'
        : 'Log in again to claim the admin role.'
    case 'notFound':
      return 'This group no longer exists, or you are no longer a member.'
    case 'rejected':
      return outcome.message
    case 'ambiguous':
      return "We couldn't confirm whether that was saved. The latest is shown; check it before trying again."
  }
}

// Keyed by group, like the members screen: everything below belongs to one group.
export function SuccessorScreen() {
  const { groupId } = useParams<{ groupId: string }>()
  return <Successor key={groupId ?? ''} groupId={groupId} />
}

function Successor({ groupId }: { readonly groupId: string | undefined }) {
  const session = useSession()
  const userId = session.userId
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [choice, setChoice] = useState<DesignationChoice>({
    successorUserId: '',
    periodDays: String(SUGGESTED_PERIOD_DAYS),
  })
  const [confirmingClaim, setConfirmingClaim] = useState<string | null>(null)

  const reload = useCallback(
    async (isCancelled: () => boolean) => {
      if (groupId === undefined) return
      const result = await loadSuccessorView(LOAD_DEPS, groupId)
      if (isCancelled()) return
      setLoad(
        result.ok
          ? { status: 'ready', view: result.view, loadedAtMs: Date.now() }
          : { status: result.kind },
      )
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

  const usernames = useUsernames(
    load.status === 'ready' ? load.view.members.map((m) => m.userId) : [],
  )

  if (groupId === undefined) {
    return (
      <Alert variant="destructive">
        <AlertDescription>Missing group id.</AlertDescription>
      </Alert>
    )
  }

  // One action at a time; both end the same way: report, then reload so the
  // status and the grant the next signature binds to are current.
  const run = (
    doing: 'designate' | 'claim',
    action: () => Promise<SuccessorActionResult>,
    success: string,
    onSuccess?: () => void,
  ) => {
    if (busy) return
    setBusy(true)
    setMessage(null)
    setError(null)
    void (async () => {
      const outcome = await action()
      setConfirmingClaim(null)
      if (outcome.ok) {
        setMessage(success)
        onSuccess?.()
      } else {
        setError(failureText(outcome, doing))
      }
      if (shouldReloadAfterSuccessor(outcome)) await reload(() => false)
      setBusy(false)
    })()
  }

  const designateDeps = (uid: string) => ({ signSuccessorDesignation, putDesignation, userId: uid })

  const handleDesignate = () => {
    if (load.status !== 'ready' || userId === null) return
    const { view } = load
    const successor = choice.successorUserId
    run(
      'designate',
      () => designate(designateDeps(userId), view, successor, Number(choice.periodDays)),
      `${memberLabel(successor, usernames)} is now your designated successor.`,
      // Kept on a refusal, so a same-day refusal does not lose the pick.
      () => {
        setChoice((c) => ({ ...c, successorUserId: '' }))
      },
    )
  }

  const handleRevoke = () => {
    if (load.status !== 'ready' || userId === null) return
    const { view } = load
    run(
      'designate',
      () => designate(designateDeps(userId), view, '', SUGGESTED_PERIOD_DAYS),
      'You no longer have a designated successor.',
    )
  }

  const handleClaim = (designationSortKey: string) => {
    if (userId === null) return
    run(
      'claim',
      () =>
        claim(
          { ...LOAD_DEPS, signSuccessorClaim, claimDesignation, userId },
          groupId,
          designationSortKey,
        ),
      'You are now an admin of this group. You can grant roles from tomorrow (UTC); the server refuses role changes until then.',
    )
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
          Couldn&apos;t load the group. Try reloading the page.
        </p>
      )}
      {load.status === 'ready' && userId !== null && (
        <SuccessorPanel
          view={load.view}
          userId={userId}
          usernames={usernames}
          nowMs={load.loadedAtMs}
          busy={busy}
          choice={choice}
          onChoice={setChoice}
          onDesignate={handleDesignate}
          onRevoke={handleRevoke}
          confirmingClaim={confirmingClaim}
          onStartClaim={setConfirmingClaim}
          onCancelClaim={() => {
            setConfirmingClaim(null)
          }}
          onConfirmClaim={handleClaim}
        />
      )}
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
      <Link
        to={`/groups/${encodeURIComponent(groupId)}/members`}
        className="text-sm text-primary underline-offset-4 hover:underline"
      >
        Back to members
      </Link>
    </>
  )
}

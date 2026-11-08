// #72: the pending queue of one public group, at /groups/:groupId/requests, for an admin or
// ambassador. Wrapped by RequireAuth in App.tsx. Review shows the fingerprint of the keys the
// requester signed; Approve wraps the group key to them only after the approver confirmed it (see
// runJoinRequests.ts for every check that comes before the wrap).

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router'
import { listJoinRequests, type JoinRequestEntry } from '@/lib/api/joinRequests'
import { useSession } from '@/lib/session/useSession'
import { NoticeAlert, PendingJoinRequestsPanel, type ReviewPrompt } from './JoinRequestPanels'
import {
  joinApprovalFailureMessage,
  prepareJoinApproval,
  runApproveJoinRequest,
  runDenyJoinRequest,
  shouldReloadAfterJoinApproval,
} from './runJoinRequests'
import { makeJoinApprovalDeps } from './rotationDeps'
import { useUsernames } from './useUsernames'

type LoadState =
  | { readonly status: 'loading' }
  | {
      readonly status: 'ready'
      readonly requests: readonly JoinRequestEntry[]
      readonly nextCursor: string | undefined
    }
  | { readonly status: 'forbidden' | 'failed' }

export function GroupJoinRequestsScreen() {
  const { groupId } = useParams<{ groupId: string }>()
  return <GroupJoinRequests key={groupId ?? ''} groupId={groupId} />
}

function GroupJoinRequests({ groupId }: { readonly groupId: string | undefined }) {
  const session = useSession()
  const userId = session.userId
  const deps = useMemo(() => (userId === null ? null : makeJoinApprovalDeps(userId)), [userId])
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [review, setReview] = useState<ReviewPrompt | null>(null)
  const [busyUserId, setBusyUserId] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const usernames = useUsernames(load.status === 'ready' ? load.requests.map((r) => r.userId) : [])

  const reload = useCallback(
    async (isCancelled: () => boolean) => {
      if (groupId === undefined) return
      try {
        const page = await listJoinRequests(groupId)
        if (!isCancelled()) {
          setLoad({ status: 'ready', requests: page.requests, nextCursor: page.nextCursor })
        }
      } catch (err) {
        if (isCancelled()) return
        setLoad({ status: (err as { status?: number }).status === 403 ? 'forbidden' : 'failed' })
      }
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

  const entryOf = (requesterId: string): JoinRequestEntry | undefined =>
    load.status === 'ready' ? load.requests.find((r) => r.userId === requesterId) : undefined

  const onLoadMore = () => {
    if (load.status !== 'ready' || load.nextCursor === undefined || groupId === undefined) return
    const { requests, nextCursor } = load
    void (async () => {
      try {
        const page = await listJoinRequests(groupId, { cursor: nextCursor })
        setLoad({
          status: 'ready',
          requests: [...requests, ...page.requests],
          nextCursor: page.nextCursor,
        })
      } catch {
        setError("Couldn't load more. Try again.")
      }
    })()
  }

  const onReview = (requesterId: string) => {
    const entry = entryOf(requesterId)
    if (busyUserId !== null || deps === null || groupId === undefined || entry === undefined) return
    setBusyUserId(requesterId)
    setError(null)
    setMessage(null)
    void (async () => {
      const prepared = await prepareJoinApproval(deps, groupId, entry)
      if (prepared.ok) {
        setReview({
          userId: requesterId,
          fingerprint: prepared.fingerprint,
          firstSight: prepared.firstSight,
        })
      } else {
        setReview(null)
        setError(joinApprovalFailureMessage(prepared))
      }
      setBusyUserId(null)
    })()
  }

  const onApprove = (requesterId: string) => {
    const entry = entryOf(requesterId)
    if (
      busyUserId !== null ||
      deps === null ||
      groupId === undefined ||
      entry === undefined ||
      review?.userId !== requesterId
    ) {
      return
    }
    const confirmed = review.fingerprint
    setBusyUserId(requesterId)
    setError(null)
    void (async () => {
      const outcome = await runApproveJoinRequest(deps, groupId, entry, confirmed)
      if (outcome.ok) setMessage('Approved. They are now a member.')
      else setError(joinApprovalFailureMessage(outcome))
      setReview(null)
      if (shouldReloadAfterJoinApproval(outcome)) await reload(() => false)
      setBusyUserId(null)
    })()
  }

  const onDeny = (requesterId: string) => {
    if (busyUserId !== null || deps === null || groupId === undefined) return
    setBusyUserId(requesterId)
    setError(null)
    setMessage(null)
    void (async () => {
      const outcome = await runDenyJoinRequest(deps, groupId, requesterId)
      if (outcome.ok) setMessage('Declined. They can ask again after a few days.')
      else setError(outcome.message)
      setReview(null)
      await reload(() => false)
      setBusyUserId(null)
    })()
  }

  return (
    <>
      <h1 className="text-xl font-semibold">Requests to join</h1>
      {load.status === 'loading' && <p className="text-sm text-muted-foreground">Loading…</p>}
      {load.status === 'forbidden' && (
        <p className="text-sm text-destructive">
          Only a group admin or ambassador can see requests.
        </p>
      )}
      {load.status === 'failed' && (
        <p className="text-sm text-destructive">Couldn&apos;t load requests. Try reloading.</p>
      )}
      {load.status === 'ready' && (
        <PendingJoinRequestsPanel
          requests={load.requests}
          usernames={usernames}
          review={review}
          busyUserId={busyUserId}
          hasMore={load.nextCursor !== undefined}
          onReview={onReview}
          onCancelReview={() => {
            setReview(null)
          }}
          onApprove={onApprove}
          onDeny={onDeny}
          onLoadMore={onLoadMore}
        />
      )}
      {message !== null && <NoticeAlert message={message} />}
      {error !== null && <NoticeAlert message={error} destructive />}
      <Link to="/" className="text-sm text-primary underline-offset-4 hover:underline">
        Back to your groups
      </Link>
    </>
  )
}

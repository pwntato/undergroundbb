// #72: the caller's own requests to join public groups, at /join-requests. Wrapped by RequireAuth in
// App.tsx. Pending ones can be withdrawn; a declined one says which day the cool-off ends.

import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router'
import { myJoinRequests, withdrawJoinRequest, type MyJoinRequest } from '@/lib/api/joinRequests'
import { MyJoinRequestsPanel, NoticeAlert } from './JoinRequestPanels'
import { runWithdrawJoinRequest } from './runJoinRequests'

type LoadState =
  | { readonly status: 'loading' }
  | {
      readonly status: 'ready'
      readonly requests: readonly MyJoinRequest[]
      readonly nextCursor: string | undefined
    }
  | { readonly status: 'failed' }

export function MyJoinRequestsScreen() {
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [busyGroupId, setBusyGroupId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  const reload = useCallback(async (isCancelled: () => boolean) => {
    try {
      const page = await myJoinRequests()
      if (!isCancelled()) {
        setLoad({ status: 'ready', requests: page.requests, nextCursor: page.nextCursor })
      }
    } catch {
      if (!isCancelled()) setLoad({ status: 'failed' })
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    void (async () => {
      await reload(() => cancelled)
    })()
    return () => {
      cancelled = true
    }
  }, [reload])

  const onLoadMore = () => {
    if (load.status !== 'ready' || load.nextCursor === undefined) return
    const { requests, nextCursor } = load
    void (async () => {
      try {
        const page = await myJoinRequests({ cursor: nextCursor })
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

  const onWithdraw = (groupId: string) => {
    if (busyGroupId !== null) return
    setBusyGroupId(groupId)
    setError(null)
    setMessage(null)
    void (async () => {
      const outcome = await runWithdrawJoinRequest({ withdrawJoinRequest }, groupId)
      if (outcome.ok) setMessage('Request withdrawn.')
      else setError(outcome.message)
      await reload(() => false)
      setBusyGroupId(null)
    })()
  }

  return (
    <>
      <h1 className="text-xl font-semibold">Your requests to join</h1>
      {load.status === 'loading' && <p className="text-sm text-muted-foreground">Loading…</p>}
      {load.status === 'failed' && (
        <p className="text-sm text-destructive">Couldn&apos;t load your requests. Try reloading.</p>
      )}
      {load.status === 'ready' && (
        <MyJoinRequestsPanel
          requests={load.requests}
          busyGroupId={busyGroupId}
          hasMore={load.nextCursor !== undefined}
          onWithdraw={onWithdraw}
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

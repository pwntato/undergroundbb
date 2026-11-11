// #72: ask to join a public group, at /groups/:groupId/join. Wrapped by RequireAuth in App.tsx. A
// public group's name is readable by anyone signed in (GET /api/groups/{id}), so this works for a
// non-member; a private group answers 404 exactly like a missing one. The directory (#71) links here.

import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { getGroup, type GroupDetail } from '@/lib/api/groups'
import { createJoinRequest } from '@/lib/api/joinRequests'
import { signJoinRequest } from '@/lib/crypto/worker-client'
import { useSession } from '@/lib/session/useSession'
import { JoinGroupPanel, NoticeAlert } from './JoinRequestPanels'
import { runRequestToJoin } from './runJoinRequests'

type LoadState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly group: GroupDetail }
  | { readonly status: 'notFound' | 'failed' }

export function JoinGroupScreen() {
  const { groupId } = useParams<{ groupId: string }>()
  return <JoinGroup key={groupId ?? ''} groupId={groupId} />
}

function JoinGroup({ groupId }: { readonly groupId: string | undefined }) {
  const session = useSession()
  const userId = session.userId
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [busy, setBusy] = useState(false)
  const [sent, setSent] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (groupId === undefined) return
    let cancelled = false
    void (async () => {
      try {
        const group = await getGroup(groupId)
        if (cancelled) return
        // A private group the caller is in has no plaintext name and nothing to request.
        setLoad(group.visibility === 'public' ? { status: 'ready', group } : { status: 'notFound' })
      } catch (err) {
        if (cancelled) return
        const status = (err as { status?: number }).status
        setLoad({ status: status === 404 ? 'notFound' : 'failed' })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [groupId])

  const onRequest = () => {
    if (busy || groupId === undefined || userId === null) return
    setBusy(true)
    setError(null)
    void (async () => {
      const outcome = await runRequestToJoin(
        {
          selfUserId: userId,
          signJoinRequest,
          createJoinRequest,
          newRequestId: () => crypto.randomUUID(),
        },
        groupId,
      )
      if (outcome.ok || outcome.kind === 'pending') {
        setSent(true)
      } else {
        setError(outcome.message)
      }
      setBusy(false)
    })()
  }

  return (
    <>
      {load.status === 'loading' && <p className="text-sm text-muted-foreground">Loading…</p>}
      {load.status === 'notFound' && (
        <p className="text-sm text-destructive">This group is not open to requests.</p>
      )}
      {load.status === 'failed' && (
        <p className="text-sm text-destructive">Couldn&apos;t load this group. Try reloading.</p>
      )}
      {load.status === 'ready' && (
        <JoinGroupPanel
          groupName={load.group.namePlaintext ?? '(unnamed group)'}
          isMember={load.group.role !== ''}
          busy={busy}
          sent={sent}
          onRequest={onRequest}
        />
      )}
      {error !== null && <NoticeAlert message={error} destructive />}
      <Link
        to="/"
        className="inline-flex min-h-[1.5rem] items-center text-sm text-primary underline-offset-4 hover:underline"
      >
        Back to your groups
      </Link>
    </>
  )
}

// #73: the conversations other people have started with the caller, at /dms. Wrapped by RequireAuth
// in App.tsx. Review checks the sender's admission and keys and shows their fingerprint; Open calls
// accept only after the caller confirmed it (see runDMs.ts for every check that comes before). The
// ones the caller started are in the group list like any other group.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { listIncomingDMs, type IncomingDM } from '@/lib/api/dms'
import { useSession } from '@/lib/session/useSession'
import { IncomingDMsPanel, type DMReviewPrompt } from './DMPanels'
import { NoticeAlert } from './JoinRequestPanels'
import { ReauthenticateStep } from './ReauthenticateStep'
import { makeAcceptDMDeps } from './rotationDeps'
import {
  acceptDMFailureMessage,
  prepareAcceptDM,
  runAcceptDM,
  runDeclineDM,
  shouldReloadAfterAccept,
} from './runDMs'
import { useLiveKeys } from './useLiveKeys'
import { useUsernames } from './useUsernames'

type LoadState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly dms: readonly IncomingDM[] }
  | { readonly status: 'failed' }

export function DirectMessagesScreen() {
  const session = useSession()
  const userId = session.userId
  const navigate = useNavigate()
  // Review needs this tab's keys (it compares the DM with this device's own fingerprint), and a reload
  // or a new tab drops them: ask for the password in place, as the other signing screens do.
  const liveKeys = useLiveKeys(userId)
  const deps = useMemo(() => (userId === null ? null : makeAcceptDMDeps(userId)), [userId])
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [review, setReview] = useState<DMReviewPrompt | null>(null)
  const [busyGroupId, setBusyGroupId] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const usernames = useUsernames(load.status === 'ready' ? load.dms.map((d) => d.senderUserId) : [])

  const reload = useCallback(async (isCancelled: () => boolean) => {
    try {
      const dms = await listIncomingDMs()
      if (!isCancelled()) setLoad({ status: 'ready', dms })
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

  const entryOf = (groupId: string): IncomingDM | undefined =>
    load.status === 'ready' ? load.dms.find((d) => d.groupId === groupId) : undefined

  const onReview = (groupId: string) => {
    const dm = entryOf(groupId)
    if (busyGroupId !== null || deps === null || dm === undefined) return
    setBusyGroupId(groupId)
    setError(null)
    setMessage(null)
    void (async () => {
      const prepared = await prepareAcceptDM(deps, dm)
      if (prepared.ok) {
        setReview({ groupId, fingerprint: prepared.fingerprint, firstSight: prepared.firstSight })
      } else {
        setReview(null)
        if (prepared.kind === 'coldKeys') liveKeys.markCold()
        else setError(acceptDMFailureMessage(prepared))
      }
      setBusyGroupId(null)
    })()
  }

  const onAccept = (groupId: string) => {
    const dm = entryOf(groupId)
    if (busyGroupId !== null || deps === null || dm === undefined || review?.groupId !== groupId) {
      return
    }
    const confirmed = review.fingerprint
    setBusyGroupId(groupId)
    setError(null)
    void (async () => {
      const outcome = await runAcceptDM(deps, dm, confirmed)
      if (outcome.ok) {
        void navigate(`/groups/${outcome.groupId}/posts`)
        return
      }
      setReview(null)
      if (outcome.kind === 'coldKeys') liveKeys.markCold()
      else setError(acceptDMFailureMessage(outcome))
      if (shouldReloadAfterAccept(outcome)) await reload(() => false)
      setBusyGroupId(null)
    })()
  }

  const onDecline = (groupId: string) => {
    const dm = entryOf(groupId)
    if (busyGroupId !== null || deps === null || dm === undefined) return
    setBusyGroupId(groupId)
    setError(null)
    setMessage(null)
    void (async () => {
      const outcome = await runDeclineDM(deps, dm)
      if (outcome.ok) setMessage('Declined. They cannot message you again for a few days.')
      else setError(outcome.message)
      setReview(null)
      await reload(() => false)
      setBusyGroupId(null)
    })()
  }

  if (userId !== null && liveKeys.status === 'checking') return null
  if (userId !== null && liveKeys.status === 'cold') {
    // Cancelling carries on to the list: Review then asks again if the keys are still cold.
    return (
      <ReauthenticateStep
        sessionUserId={userId}
        action="open messages"
        onDone={liveKeys.markWarm}
        onCancel={liveKeys.markWarm}
      />
    )
  }

  return (
    <>
      <h1 className="text-xl font-semibold">Direct messages</h1>
      {load.status === 'loading' && <p className="text-sm text-muted-foreground">Loading…</p>}
      {load.status === 'failed' && (
        <p className="text-sm text-destructive">Couldn&apos;t load your messages. Try reloading.</p>
      )}
      {load.status === 'ready' && (
        <IncomingDMsPanel
          dms={load.dms}
          usernames={usernames}
          review={review}
          busyGroupId={busyGroupId}
          onReview={onReview}
          onCancelReview={() => {
            setReview(null)
          }}
          onAccept={onAccept}
          onDecline={onDecline}
        />
      )}
      {message !== null && <NoticeAlert message={message} />}
      {error !== null && <NoticeAlert message={error} destructive />}
      <p className="max-w-md text-xs text-muted-foreground">
        To start a conversation, open someone&apos;s profile from a group&apos;s Members page and
        choose &quot;Send a message&quot;. Conversations you started are in your group list.
      </p>
      <Link
        to="/"
        className="inline-flex min-h-[1.5rem] items-center text-sm text-primary underline-offset-4 hover:underline"
      >
        Back to your groups
      </Link>
    </>
  )
}

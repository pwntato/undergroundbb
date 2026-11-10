// #73: start a conversation with someone, at /dms/new/:userId. Wrapped by RequireAuth in App.tsx.
// The screen checks the other person's keys first (prepareStartDM) and shows their fingerprint; only
// the button press that follows wraps the key and signs the admission (runStartDM re-checks that the
// keys still give the fingerprint that was shown). The conversation is created empty; the first
// message is written on its page like any other post.

import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { listIncomingDMs } from '@/lib/api/dms'
import { getUser } from '@/lib/api/users'
import { bytesToBase64 } from '@/lib/crypto/base64'
import { generateUUID } from '@/lib/crypto/uuid'
import { useSession } from '@/lib/session/useSession'
import { NewDMPanel, type NewDMState } from './DMPanels'
import { NoticeAlert } from './JoinRequestPanels'
import { ReauthenticateStep } from './ReauthenticateStep'
import { makeStartDMDeps } from './rotationDeps'
import {
  existingDMPath,
  prepareStartDM,
  runStartDM,
  startDMFailureMessage,
  type DMMaterial,
} from './runDMs'
import { useExpiryPolicy } from './useExpiryPolicy'
import { useLiveKeys } from './useLiveKeys'

export function NewDMScreen() {
  const { userId } = useParams<{ userId: string }>()
  return <NewDM key={userId ?? ''} recipientId={userId} />
}

function NewDM({ recipientId }: { readonly recipientId: string | undefined }) {
  const session = useSession()
  const selfId = session.userId
  const navigate = useNavigate()
  const policy = useExpiryPolicy()
  const liveKeys = useLiveKeys(selfId)
  const deps = useMemo(() => (selfId === null ? null : makeStartDMDeps(selfId)), [selfId])
  const [username, setUsername] = useState<string | null>(null)
  const [state, setState] = useState<NewDMState>({ status: 'checking' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // The ids and key of one attempt, kept so a retry after a lost response sends the same
  // conversation instead of creating a second, orphaned one.
  const material = useRef<DMMaterial | null>(null)

  useEffect(() => {
    if (recipientId === undefined || deps === null) return
    let cancelled = false
    void (async () => {
      try {
        const user = await getUser(recipientId)
        if (cancelled) return
        setUsername(user.deleted === true ? '(deleted user)' : user.username)
      } catch {
        if (!cancelled) setUsername('(unknown user)')
      }
      const prepared = await prepareStartDM(deps, recipientId)
      if (cancelled) return
      setState(
        prepared.ok
          ? { status: 'ready', fingerprint: prepared.fingerprint, firstSight: prepared.firstSight }
          : { status: 'blocked', message: startDMFailureMessage(prepared) },
      )
    })()
    return () => {
      cancelled = true
    }
  }, [recipientId, deps])

  const onSend = () => {
    if (busy || deps === null || recipientId === undefined || state.status !== 'ready') return
    const confirmed = state.fingerprint
    material.current ??= {
      groupId: generateUUID(),
      groupKeyB64: bytesToBase64(crypto.getRandomValues(new Uint8Array(32))),
      requestId: generateUUID(),
    }
    const attempt = material.current
    setBusy(true)
    setError(null)
    void (async () => {
      const outcome = await runStartDM(deps, recipientId, confirmed, attempt, policy.defaultDays)
      if (outcome.ok) {
        void navigate(`/groups/${outcome.groupId}/posts`, { replace: true })
        return
      }
      if (outcome.kind === 'exists') {
        // It may be one THEY sent and you have not opened: that lives under Direct messages.
        void navigate(await existingDMPath(listIncomingDMs, outcome.groupId), { replace: true })
        return
      }
      // Nothing was written for any of these, so the next attempt starts over with fresh ids.
      if (outcome.kind !== 'ambiguous' && outcome.kind !== 'conflict') material.current = null
      if (outcome.kind === 'coldKeys') liveKeys.markCold()
      if (outcome.kind === 'keysChanged' || outcome.kind === 'recipientKeysChanged') {
        // Show the new fingerprint instead of the one that was confirmed.
        setState({ status: 'checking' })
        const prepared = await prepareStartDM(deps, recipientId)
        setState(
          prepared.ok
            ? {
                status: 'ready',
                fingerprint: prepared.fingerprint,
                firstSight: prepared.firstSight,
              }
            : { status: 'blocked', message: startDMFailureMessage(prepared) },
        )
      }
      setError(startDMFailureMessage(outcome))
      setBusy(false)
    })()
  }

  if (selfId !== null && liveKeys.status === 'checking') return null
  if (selfId !== null && liveKeys.status === 'cold') {
    return (
      <ReauthenticateStep
        sessionUserId={selfId}
        action="send a message"
        onDone={liveKeys.markWarm}
        onCancel={liveKeys.markWarm}
      />
    )
  }

  return (
    <>
      <NewDMPanel username={username ?? '…'} state={state} busy={busy} onSend={onSend} />
      {error !== null && <NoticeAlert message={error} destructive />}
      {recipientId !== undefined && (
        <Link
          to={`/users/${recipientId}`}
          className="text-sm text-primary underline-offset-4 hover:underline"
        >
          Back to their profile
        </Link>
      )}
    </>
  )
}

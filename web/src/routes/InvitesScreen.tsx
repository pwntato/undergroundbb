// #41: pending invite management at /invites. Wrapped by RequireAuth in
// App.tsx. Loading and revoking are runInvites.ts's job; this component owns
// state and effects, and InvitesPanel owns rendering. Group names come from
// the caller's own group list (the same runListGroups Home uses); an
// invitee's not-yet-joined group is not in it and renders generically.

import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { listGroups } from '@/lib/api/groups'
import { receivedInvites, revokeInvite, sentInvites } from '@/lib/api/invites'
import { decryptGroupNames } from '@/lib/crypto/worker-client'
import { getCachedGroupName, setCachedGroupName } from '@/lib/groups/groupNameCache'
import { useSession } from '@/lib/session/useSession'
import { groupLabel } from './groupLabel'
import { InvitesPanel } from './InvitesPanel'
import { loadInvites, revokePending, type InvitesView, type RevokeResult } from './runInvites'
import { runListGroups } from './runListGroups'

type LoadState =
  | { readonly status: 'loading' }
  | {
      readonly status: 'ready'
      readonly view: InvitesView
      readonly groupLabels: ReadonlyMap<string, string>
      /** When this data was fetched (epoch ms); what removal dates are judged against. */
      readonly loadedAt: number
    }
  | { readonly status: 'authRequired' | 'failed' }

const REVOKE_ERRORS: Record<Exclude<RevokeResult, { ok: true }>['kind'], string> = {
  accepted: 'Someone accepted this invite first, so it can no longer be revoked.',
  gone: 'This invite is already gone.',
  authRequired: 'Your session has expired. Log in again and retry.',
  failed: "We couldn't revoke that invite. Try again.",
}

export function InvitesScreen() {
  const session = useSession()
  const userId = session.userId
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [busyInviteId, setBusyInviteId] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const reload = useCallback(
    async (isCancelled: () => boolean) => {
      const result = await loadInvites({ sentInvites, receivedInvites })
      if (isCancelled()) {
        return
      }
      if (!result.ok) {
        setLoad({ status: result.kind })
        return
      }
      // Names are a nicety: if the group list fails, show the invites with
      // generic labels rather than failing the whole screen.
      const groupLabels = new Map<string, string>()
      if (userId !== null) {
        try {
          const groups = await runListGroups({
            listGroups,
            decryptGroupNames,
            getCachedGroupName,
            setCachedGroupName,
            userId,
          })
          for (const g of groups) {
            groupLabels.set(g.groupId, groupLabel(g))
          }
        } catch {
          // Fall through with an empty map.
        }
      }
      if (isCancelled()) {
        return
      }
      setLoad({ status: 'ready', view: result.view, groupLabels, loadedAt: Date.now() })
    },
    [userId],
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

  const handleRevoke = (inviteId: string) => {
    if (busyInviteId !== null) {
      return
    }
    setBusyInviteId(inviteId)
    setMessage(null)
    setError(null)
    void (async () => {
      const outcome = await revokePending({ revokeInvite }, inviteId)
      if (outcome.ok) {
        setMessage('Invite revoked. Its link no longer works.')
      } else {
        setError(REVOKE_ERRORS[outcome.kind])
      }
      // Reload after anything but a dead session, so a stale row (accepted or
      // already gone) corrects itself.
      if (!outcome.ok && outcome.kind === 'authRequired') {
        // Nothing to refresh: every call would 401.
      } else {
        await reload(() => false)
      }
      setBusyInviteId(null)
    })()
  }

  return (
    <>
      {load.status === 'loading' && <p className="text-sm text-muted-foreground">Loading…</p>}
      {load.status === 'authRequired' && (
        <p className="text-sm text-destructive">Your session has expired. Log in again.</p>
      )}
      {load.status === 'failed' && (
        <p className="text-sm text-destructive">
          Couldn&apos;t load your invites. Try reloading the page.
        </p>
      )}
      {load.status === 'ready' && (
        <InvitesPanel
          view={load.view}
          groupLabels={load.groupLabels}
          now={load.loadedAt}
          busyInviteId={busyInviteId}
          onRevoke={handleRevoke}
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
      <Link to="/" className="text-sm text-primary underline-offset-4 hover:underline">
        Back to your groups
      </Link>
    </>
  )
}

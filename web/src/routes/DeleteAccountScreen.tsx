// #77: delete the account at /account/delete. Wrapped by RequireAuth in
// App.tsx. The planning and the leave-then-delete sequence are
// runDeleteAccount.ts's job; DeleteAccountPanel owns rendering. This
// component owns state and effects only.

import { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { deleteAccount } from '@/lib/api/auth'
import { getKeychain, leaveGroup, listGroups, listMembers, getGroup } from '@/lib/api/groups'
import { decryptGroupNames, signRoleGrant } from '@/lib/crypto/worker-client'
import { getCachedGroupName, setCachedGroupName } from '@/lib/groups/groupNameCache'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { useSession } from '@/lib/session/useSession'
import { DeleteAccountPanel, type DeletePanelState } from './DeleteAccountPanel'
import { groupLabel } from './groupLabel'
import {
  deleteFailureMessage,
  deletionBlockers,
  groupsThatWillBeDeleted,
  planAccountDeletion,
  runDeleteAccount,
  type AccountPlanEntry,
} from './runDeleteAccount'
import { runListGroups } from './runListGroups'

interface Loaded {
  readonly entries: readonly AccountPlanEntry[]
  readonly labels: ReadonlyMap<string, string>
}

type LoadState =
  | { readonly status: 'loading' }
  | { readonly status: 'error' }
  | ({ readonly status: 'ready' } & Loaded)

export function DeleteAccountScreen() {
  const session = useSession()
  const navigate = useNavigate()
  const userId = session.userId
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const reload = useCallback(
    async (isCancelled: () => boolean) => {
      if (userId === null) {
        return
      }
      let next: LoadState
      try {
        const groups = await runListGroups({
          listGroups,
          decryptGroupNames,
          getNameChain: (gid, nameGen, gen) => fetchNameChain(getKeychain, gid, nameGen, gen),
          getCachedGroupName,
          setCachedGroupName,
          userId,
        })
        const plan = await planAccountDeletion(
          { getGroup, listMembers, userId },
          groups.map((g) => g.groupId),
        )
        next = plan.ok
          ? {
              status: 'ready',
              entries: plan.entries,
              labels: new Map(groups.map((g) => [g.groupId, groupLabel(g)])),
            }
          : { status: 'error' }
      } catch {
        next = { status: 'error' }
      }
      if (!isCancelled()) {
        setLoad(next)
      }
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

  if (userId === null) {
    return null
  }

  const labelFor = (groupId: string): string =>
    (load.status === 'ready' ? load.labels.get(groupId) : undefined) ?? '(a group)'
  const rows = (entries: readonly AccountPlanEntry[]) =>
    entries.map((e) => ({ groupId: e.groupId, label: labelFor(e.groupId) }))

  let state: DeletePanelState
  if (load.status === 'ready') {
    const blockers = deletionBlockers(load.entries)
    const deleting = groupsThatWillBeDeleted(load.entries)
    state = {
      status: 'ready',
      blockers: rows(blockers),
      deleting: rows(deleting),
      leaving: rows(load.entries.filter((e) => !blockers.includes(e) && !deleting.includes(e))),
    }
  } else {
    state = { status: load.status }
  }

  const handleConfirm = async () => {
    if (load.status !== 'ready') {
      return
    }
    setBusy(true)
    setError(null)
    const result = await runDeleteAccount(
      { leaveGroup, signRoleGrant, deleteAccount, userId },
      load.entries,
    )
    if (result.ok) {
      session.logout()
      void navigate('/', { replace: true })
      return
    }
    setError(deleteFailureMessage(result, labelFor))
    setConfirming(false)
    // Some groups may already be left; show what remains.
    await reload(() => false)
    setBusy(false)
  }

  return (
    <div className="flex w-full max-w-md flex-col items-center gap-4">
      <h1 className="font-mono text-2xl font-bold tracking-tight text-primary">Delete account</h1>
      {error !== null && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <DeleteAccountPanel
        state={state}
        confirming={confirming}
        busy={busy}
        onStart={() => {
          setConfirming(true)
        }}
        onCancel={() => {
          setConfirming(false)
        }}
        onConfirm={() => {
          void handleConfirm()
        }}
      />
      <Link className="text-sm underline" to="/">
        Back
      </Link>
    </div>
  )
}

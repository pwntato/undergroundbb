// #77: delete the account at /account/delete. Wrapped by RequireAuth in
// App.tsx. The planning and the leave-then-delete sequence are
// runDeleteAccount.ts's job; DeleteAccountPanel owns rendering. This
// component owns state and effects only.

import { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { ApiError, deleteAccount } from '@/lib/api/auth'
import { getKeychain, leaveGroup, listGroups, listMembers, getGroup } from '@/lib/api/groups'
import { decryptGroupNames, signRoleGrant } from '@/lib/crypto/worker-client'
import { getCachedGroupName, setCachedGroupName } from '@/lib/groups/groupNameCache'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { useSession } from '@/lib/session/useSession'
import { DeleteAccountPanel, type DeletePanelState } from './DeleteAccountPanel'
import { groupLabel } from './groupLabel'
import {
  deleteFailureMessage,
  blockerReason,
  deletionBlockers,
  groupsThatWillBeDeleted,
  planAccountDeletion,
  runConfirmedDeletion,
  type AccountPlanEntry,
} from './runDeleteAccount'
import { runListGroups } from './runListGroups'
import { resolveUsernames } from './useUsernames'

interface Loaded {
  readonly entries: readonly AccountPlanEntry[]
  readonly labels: ReadonlyMap<string, string>
}

type LoadState =
  | { readonly status: 'loading' }
  | { readonly status: 'error'; readonly afterRun?: boolean }
  | ({ readonly status: 'ready' } & Loaded)

/** Lists the groups (with display names) and plans leaving each. Never throws. */
async function loadPlan(
  userId: string,
): Promise<{ ok: true; loaded: Loaded } | { ok: false; kind: 'authRequired' | 'failed' }> {
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
      { getGroup, listMembers, userId, resolveUsernames },
      groups.map((g) => g.groupId),
    )
    if (!plan.ok) {
      return plan
    }
    return {
      ok: true,
      loaded: {
        entries: plan.entries,
        labels: new Map(groups.map((g) => [g.groupId, groupLabel(g)])),
      },
    }
  } catch (err) {
    return {
      ok: false,
      kind: err instanceof ApiError && err.status === 401 ? 'authRequired' : 'failed',
    }
  }
}

export function DeleteAccountScreen() {
  const session = useSession()
  const navigate = useNavigate()
  const userId = session.userId
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const reload = useCallback(
    async (isCancelled: boolean | (() => boolean), afterRun = false) => {
      if (userId === null) {
        return
      }
      const result = await loadPlan(userId)
      if (typeof isCancelled === 'function' ? isCancelled() : isCancelled) {
        return
      }
      setLoad(
        result.ok
          ? { status: 'ready', ...result.loaded }
          : { status: 'error', ...(afterRun && { afterRun: true }) },
      )
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
      blockers: blockers.map((e) => ({
        groupId: e.groupId,
        label: labelFor(e.groupId),
        reason: blockerReason(e),
      })),
      deleting: rows(deleting),
      leaving: rows(load.entries.filter((e) => !blockers.includes(e) && !deleting.includes(e))),
    }
  } else {
    state = load
  }

  const handleConfirm = async () => {
    if (load.status !== 'ready') {
      return
    }
    setBusy(true)
    setError(null)
    // The labels of the plan the run is made against, which can differ from
    // the ones on screen if the groups changed since this page loaded.
    let freshLoaded: Loaded | null = null
    const result = await runConfirmedDeletion(
      {
        leaveGroup,
        signRoleGrant,
        deleteAccount,
        userId,
        replan: async () => {
          const planned = await loadPlan(userId)
          if (planned.ok) {
            freshLoaded = planned.loaded
            return { ok: true, entries: planned.loaded.entries }
          }
          return planned
        },
      },
      load.entries,
    )
    if (result.ok) {
      session.logout()
      void navigate('/', { replace: true })
      return
    }
    setConfirming(false)
    if (result.kind === 'planChanged' && freshLoaded !== null) {
      // Show what is true now and make the user confirm that instead.
      setLoad({ status: 'ready', ...(freshLoaded as Loaded) })
      setError(deleteFailureMessage(result, labelFor))
      setBusy(false)
      return
    }
    setError(deleteFailureMessage(result, labelFor))
    // Some groups may already be left; show what remains.
    await reload(false, true)
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

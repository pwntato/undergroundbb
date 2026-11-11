// The group-list fetch that used to live in Home (#35), moved up to the app shell (#47) so the
// sidebar and the Home pane share one load. Behaviour is unchanged except one thing: a later
// navigation refetches WITHOUT going back to 'loading', so the sidebar keeps showing the list it
// has (with fresh unread counts) instead of flashing "Loading" on every click.
//
// A failed refetch of an already-shown list keeps the old list; the first load failing is 'error'.

import { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { getKeychain, listGroups, type GroupListEntry } from '@/lib/api/groups'
import { decryptGroupNames } from '@/lib/crypto/worker-client'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { getCachedGroupName, setCachedGroupName } from '@/lib/groups/groupNameCache'
import type { LoadState } from './GroupList'
import { listGroupsWithUnread } from './listGroupsWithUnread'
import { marksSettled, onMarksSettled } from './markReadTracker'
import { readNewGroupState } from './newGroupNavigationState'
import { runListGroups } from './runListGroups'

/** The load state after a fetch starts: a list already on screen stays; anything else is loading. */
export function loadingFrom(previous: LoadState): LoadState {
  return previous.status === 'ready' ? previous : { status: 'loading' }
}

/** The load state after a fetch fails: a list already on screen stays; anything else is an error. */
export function failedFrom(previous: LoadState): LoadState {
  return previous.status === 'ready' ? previous : { status: 'error' }
}

/**
 * What a navigation refetches on: moving between pages of one group (its posts, a thread, its
 * members) keeps the same key, so it does not refetch the list; any other change of page does (including /join, which can end in membership).
 * Reading and marking inside a group is covered by onMarksSettled in the hook.
 */
export function refetchKey(pathname: string): string {
  const m = /^\/groups\/([^/]+)\/(posts|members|settings|invite|requests|successor)(\/|$)/.exec(
    pathname,
  )
  return m !== null ? `/groups/${m[1]}` : pathname
}

/** A just-created group stays pending until a fetched list includes it (GSI1 lags), then it is dropped. */
export function stillPending(
  pending: GroupListEntry | null,
  fetched: readonly { readonly groupId: string }[],
): GroupListEntry | null {
  return pending !== null && fetched.some((g) => g.groupId === pending.groupId) ? null : pending
}

export function useGroupsLoad(userId: string | null): {
  readonly load: LoadState
  readonly reload: () => void
} {
  const location = useLocation()
  const navigate = useNavigate()
  const locationState = location.state as unknown
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [reloadTick, setReloadTick] = useState(0)

  // The group CreateGroupScreen just created. Consuming it replaces the history entry (so a
  // reload cannot resurrect it), which changes locationState and re-runs the fetch below, so the
  // group is held here and every fetch carries it until a fetched list includes it (#370 review).
  const pendingNew = useRef<GroupListEntry | null>(null)
  useEffect(() => {
    const fresh = readNewGroupState(locationState)
    if (fresh !== undefined) {
      pendingNew.current = fresh
      navigate(location.pathname, { replace: true, state: null })
    }
  }, [locationState, location.pathname, navigate])

  // A finished mark-read changes the counts: refetch, as the header does.
  useEffect(() => onMarksSettled(() => setReloadTick((n) => n + 1)), [])

  const scope = refetchKey(location.pathname)
  useEffect(() => {
    if (userId === null) {
      return
    }
    let cancelled = false
    void (async () => {
      if (!cancelled) {
        setLoad(loadingFrom)
      }
      try {
        const newGroup = pendingNew.current
        const groups = await runListGroups({
          listGroups: () => listGroupsWithUnread({ settled: marksSettled, listGroups }),
          decryptGroupNames,
          getNameChain: (gid, nameGen, gen) => fetchNameChain(getKeychain, gid, nameGen, gen),
          getCachedGroupName,
          setCachedGroupName,
          userId,
          ...(newGroup !== null && { newGroup }),
        })
        if (!cancelled) {
          pendingNew.current = stillPending(pendingNew.current, groups)
          setLoad({ status: 'ready', groups })
        }
      } catch {
        if (!cancelled) {
          setLoad(failedFrom)
        }
      }
    })()
    return () => {
      cancelled = true
    }
  }, [userId, locationState, scope, reloadTick])

  return { load, reload: () => setReloadTick((n) => n + 1) }
}

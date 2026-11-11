// The group-list fetch that used to live in Home (#35), moved up to the app shell (#47) so the
// sidebar and the Home pane share one load. Behaviour is unchanged except one thing: a later
// navigation refetches WITHOUT going back to 'loading', so the sidebar keeps showing the list it
// has (with fresh unread counts) instead of flashing "Loading" on every click.
//
// A failed refetch of an already-shown list keeps the old list; the first load failing is 'error'.

import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { getKeychain, listGroups } from '@/lib/api/groups'
import { decryptGroupNames } from '@/lib/crypto/worker-client'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { getCachedGroupName, setCachedGroupName } from '@/lib/groups/groupNameCache'
import type { LoadState } from './GroupList'
import { listGroupsWithUnread } from './listGroupsWithUnread'
import { marksSettled } from './markReadTracker'
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

export function useGroupsLoad(userId: string | null): {
  readonly load: LoadState
  readonly reload: () => void
} {
  const location = useLocation()
  const navigate = useNavigate()
  const locationState = location.state as unknown
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [reloadTick, setReloadTick] = useState(0)

  useEffect(() => {
    if (userId === null) {
      return
    }
    // A just-created group arrives in history state; consume it once (see git history of Home.tsx,
    // PR #144 round 2: react-router state survives reloads, so a stale one would resurrect a group
    // the user later left).
    const newGroup = readNewGroupState(locationState)
    if (newGroup !== undefined) {
      navigate(location.pathname, { replace: true, state: null })
    }
    let cancelled = false
    void (async () => {
      if (!cancelled) {
        setLoad(loadingFrom)
      }
      try {
        const groups = await runListGroups({
          listGroups: () => listGroupsWithUnread({ settled: marksSettled, listGroups }),
          decryptGroupNames,
          getNameChain: (gid, nameGen, gen) => fetchNameChain(getKeychain, gid, nameGen, gen),
          getCachedGroupName,
          setCachedGroupName,
          userId,
          ...(newGroup !== undefined && { newGroup }),
        })
        if (!cancelled) {
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
  }, [userId, locationState, location.pathname, navigate, reloadTick])

  return { load, reload: () => setReloadTick((n) => n + 1) }
}

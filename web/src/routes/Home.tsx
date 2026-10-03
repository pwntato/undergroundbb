// Issue #35: the authenticated landing page now renders the caller's actual
// group list, replacing #33's placeholder. Logged-out visitors still see
// the original signup/login prompt below, unchanged.
//
// The list itself is runListGroups' job (see that file's own header
// comment) -- this component only owns fetching-on-mount, loading/error
// state, and rendering the DisplayGroup[] it resolves to. A private
// group's name/description are decrypted client-side via the crypto
// worker (decryptGroupNames), never here directly -- this component never
// touches a group key.

import { useEffect, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router'
import { Button } from '@/components/ui/button'
import { getKeychain, listGroups } from '@/lib/api/groups'
import { decryptGroupNames } from '@/lib/crypto/worker-client'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { getCachedGroupName, setCachedGroupName } from '@/lib/groups/groupNameCache'
import { useSession } from '@/lib/session/useSession'
import { GroupList, type LoadState } from './GroupList'
import { readNewGroupState } from './newGroupNavigationState'
import { runListGroups } from './runListGroups'

export function Home() {
  const session = useSession()
  const location = useLocation()
  const navigate = useNavigate()
  const locationState = location.state as unknown
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })

  useEffect(() => {
    if (!session.userId) {
      return
    }
    // Read fresh from locationState (the actual dependency below) rather
    // than a value computed at component-body scope -- readNewGroupState
    // returns a new object reference every render, so using ITS result as
    // a dependency would re-run this effect on every unrelated render;
    // locationState itself only changes on a real navigation.
    const newGroup = readNewGroupState(locationState)
    if (newGroup !== undefined) {
      // Consume the state once, immediately after reading it (PR #144
      // round 2 review) -- react-router's history state does NOT clear
      // itself on reload or back/forward the way this file used to claim
      // (newGroupNavigationState.ts's own header comment was wrong: it
      // persists in window.history.state.usr for as long as this "/"
      // history entry exists, which CreateGroupScreen's replace: true
      // navigation makes indefinite). Harmless today only because the
      // merge dedupes by groupId against an already-caught-up fetch --
      // once leave/remove-member exists, a reload or back/forward to this
      // exact entry would resurrect a group the user actually left, with a
      // stale role and a wrapped key nobody can use anymore. Replacing the
      // history entry with state: null clears it for good, so this only
      // ever fires once per real creation, not on every future visit to
      // this same entry.
      navigate(location.pathname, { replace: true, state: null })
    }
    let cancelled = false
    // Reset to 'loading' from inside the async callback, not synchronously
    // at the top of the effect -- an oxlint react/set-state-in-effect rule
    // flags the latter as a likely cascading-render mistake. This still
    // covers a userId change on an already-mounted Home (e.g. a logout
    // immediately followed by a different login in the same tab): the
    // guard clause above only skips the fetch entirely for a logged-out
    // session, it does not skip re-running this effect for a NEW userId.
    void (async () => {
      if (!cancelled) {
        setLoad({ status: 'loading' })
      }
      try {
        const groups = await runListGroups({
          listGroups,
          decryptGroupNames,
          getNameChain: (gid, nameGen, gen) => fetchNameChain(getKeychain, gid, nameGen, gen),
          getCachedGroupName,
          setCachedGroupName,
          userId: session.userId as string,
          ...(newGroup !== undefined && { newGroup }),
        })
        if (!cancelled) {
          setLoad({ status: 'ready', groups })
        }
      } catch {
        // A failed GET /api/groups itself (network error, 5xx) -- distinct
        // from a per-group or cold-keys decrypt failure, both of which
        // runListGroups already resolves into a renderable DisplayGroup
        // rather than throwing (see that file's own doc comment).
        if (!cancelled) {
          setLoad({ status: 'error' })
        }
      }
    })()
    return () => {
      cancelled = true
    }
    // locationState, not just session.userId -- CreateGroupScreen
    // navigates to this SAME route ("/") with { replace: true }, carrying a
    // new state object, so without this dependency the effect would never
    // re-run to pick up the just-created group on that navigation
    // (session.userId doesn't change across it). navigate/location.pathname
    // are also listed for exhaustive-deps -- react-router v7's useNavigate()
    // is already a stable reference and Home is only ever mounted at "/"
    // today, so neither actually changes across renders in practice; the
    // state:null replace above keeps the same pathname, so it does not
    // itself re-trigger this effect a second time.
  }, [session.userId, locationState, location.pathname, navigate])

  // Renders nothing rather than the logged-out view while the #32 bootstrap
  // is still checking -- otherwise an authenticated visitor reloading this
  // page would see the signup/login prompt flash before session.userId
  // arrives, even though they're already signed in.
  if (session.status === 'loading') {
    return null
  }

  if (!session.userId) {
    return (
      <div className="flex flex-col items-center gap-4 text-center">
        <h1 className="font-mono text-2xl font-bold tracking-tight text-primary">UndergroundBB</h1>
        <p className="text-sm text-muted-foreground">Frontend scaffold. Nothing to see yet.</p>
        <div className="flex gap-2">
          <Button asChild>
            <Link to="/signup">Sign up</Link>
          </Button>
          <Button asChild variant="outline">
            <Link to="/login">Log in</Link>
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex w-full max-w-md flex-col items-center gap-4 text-center">
      <h1 className="font-mono text-2xl font-bold tracking-tight text-primary">UndergroundBB</h1>

      <GroupList load={load} />

      <div className="flex gap-2">
        <Button asChild>
          <Link to="/groups/new">Create a group</Link>
        </Button>
        <Button asChild variant="outline">
          <Link to="/invites">Invites</Link>
        </Button>
        <Button asChild variant="outline">
          <Link to="/account/password">Change password</Link>
        </Button>
      </div>
    </div>
  )
}

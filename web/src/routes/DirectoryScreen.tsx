// #71: the public group directory at /directory. Wrapped by RequireAuth in App.tsx. Browsing and
// searching are GET /api/groups/public (a name prefix, paged); beside each group it shows whether the
// caller is in it or has a request, from their own group list and requests, and links to the request
// screen (#72) otherwise. The two side reads are a nicety: if either fails, the rows show "Ask to
// join" and the server's own answer on that screen is the real check.

import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import { listPublicGroups, type DirectoryEntry } from '@/lib/api/directory'
import { listGroups } from '@/lib/api/groups'
import { myJoinRequests, type MyJoinRequest } from '@/lib/api/joinRequests'
import { DirectoryPanel } from './DirectoryPanel'
import { directoryRows } from './directoryRows'
import { NoticeAlert } from './JoinRequestPanels'

const PAGE = 25

type LoadState =
  | { readonly status: 'loading' }
  | {
      readonly status: 'ready'
      readonly entries: readonly DirectoryEntry[]
      readonly nextCursor: string | undefined
      /** The query these entries are for. */
      readonly searched: string
    }
  | { readonly status: 'failed' }

async function allMyRequests(): Promise<MyJoinRequest[]> {
  const out: MyJoinRequest[] = []
  let cursor: string | undefined
  // A user has at most one request per public group; cap the walk so a huge list cannot loop.
  for (let i = 0; i < 20; i++) {
    const page = await myJoinRequests(
      cursor === undefined ? { limit: 100 } : { limit: 100, cursor },
    )
    out.push(...page.requests)
    if (page.nextCursor === undefined) break
    cursor = page.nextCursor
  }
  return out
}

export function DirectoryScreen() {
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [query, setQuery] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [memberOf, setMemberOf] = useState<ReadonlySet<string>>(new Set())
  const [requests, setRequests] = useState<readonly MyJoinRequest[]>([])
  // Only the newest search may write the list: a slow earlier answer must not replace a later one.
  const latest = useRef(0)

  const search = useCallback(async (q: string) => {
    const mine = ++latest.current
    setBusy(true)
    setError(null)
    try {
      const page = await listPublicGroups({ q, limit: PAGE })
      if (latest.current !== mine) return
      setLoad({ status: 'ready', entries: page.groups, nextCursor: page.nextCursor, searched: q })
    } catch {
      if (latest.current !== mine) return
      setLoad((prev) => (prev.status === 'ready' ? prev : { status: 'failed' }))
      setError("Couldn't load the directory. Try again.")
    } finally {
      if (latest.current === mine) setBusy(false)
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    void (async () => {
      await search('')
      try {
        const [groups, mine] = await Promise.all([listGroups(), allMyRequests()])
        if (cancelled) return
        setMemberOf(new Set(groups.groups.map((g) => g.groupId)))
        setRequests(mine)
      } catch {
        // Decoration only: see the header comment.
      }
    })()
    return () => {
      cancelled = true
    }
  }, [search])

  const onLoadMore = () => {
    if (load.status !== 'ready' || load.nextCursor === undefined || busy) return
    const { entries, nextCursor, searched } = load
    const mine = ++latest.current
    setBusy(true)
    setError(null)
    void (async () => {
      try {
        const page = await listPublicGroups({ q: searched, limit: PAGE, cursor: nextCursor })
        if (latest.current !== mine) return
        setLoad({
          status: 'ready',
          entries: [...entries, ...page.groups],
          nextCursor: page.nextCursor,
          searched,
        })
      } catch {
        if (latest.current === mine) setError("Couldn't load more. Try again.")
      } finally {
        if (latest.current === mine) setBusy(false)
      }
    })()
  }

  return (
    <>
      <h1 className="text-xl font-semibold">Find a public group</h1>
      {load.status === 'loading' && <p className="text-sm text-muted-foreground">Loading…</p>}
      {load.status === 'failed' && (
        <p className="text-sm text-destructive">Couldn&apos;t load the directory. Try reloading.</p>
      )}
      {load.status === 'ready' && (
        <DirectoryPanel
          query={query}
          rows={directoryRows(load.entries, memberOf, requests)}
          searched={load.searched}
          hasMore={load.nextCursor !== undefined}
          busy={busy}
          onQueryChange={setQuery}
          onSearch={() => {
            void search(query)
          }}
          onLoadMore={onLoadMore}
        />
      )}
      {error !== null && <NoticeAlert message={error} destructive />}
      <Link to="/" className="text-sm text-primary underline-offset-4 hover:underline">
        Back to your groups
      </Link>
    </>
  )
}

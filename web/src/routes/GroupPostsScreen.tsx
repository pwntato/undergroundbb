// #43: read a group's posts at /groups/:groupId/posts. Wrapped by RequireAuth in
// App.tsx (baseline session check; the server's 404 is the real check).
//
// Opening and checking are runListPosts.ts's job; this component owns state and
// effects, and GroupPostsPanel owns rendering. Pages load newest day first and
// "Load older posts" asks for the next one by cursor. The list is its own
// component, keyed by group and by re-login, so its state starts fresh by
// remounting rather than by an effect resetting it.

import { useCallback, useEffect, useMemo, useReducer, useState } from 'react'
import { useParams } from 'react-router'
import { getGroup, getKeychain, listPosts } from '@/lib/api/groups'
import { listAllPins } from '@/lib/api/pins'
import { getUserDetail } from '@/lib/api/users'
import { getOwnSigningKey, openPosts } from '@/lib/crypto/worker-client'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { makeOwnKeyHistoryLoader } from '@/lib/session/ownKeyHistory'
import { ownSigningKeyWithFallback } from '@/lib/session/ownSigningKey'
import { useSession } from '@/lib/session/useSession'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { GroupPostsPanel } from './GroupPostsPanel'
import { INITIAL_POSTS_GATE, nextPostsGate } from './postsGate'
import { ReauthenticateStep } from './ReauthenticateStep'
import { makePinKeys } from './rotationDeps'
import {
  loadPostsPage,
  makeAuthorResolver,
  type ListPostsDeps,
  type PageResult,
  type PostView,
} from './runListPosts'

const PAGE_ERRORS: Record<Exclude<PageResult, { ok: true }>['kind'], string> = {
  notFound: 'This group no longer exists, or you are no longer a member.',
  authRequired: 'Your session has expired. Log in again and retry.',
  coldKeys: 'This tab needs your password again to read posts.',
  chain: "Couldn't read this group's older keys, so older posts can't be opened. Try again.",
  failed: "Couldn't load the posts. Try again.",
}

export function GroupPostsScreen() {
  const { groupId } = useParams<{ groupId: string }>()
  const userId = useSession().userId
  const [gate, send] = useReducer(nextPostsGate, INITIAL_POSTS_GATE)
  // Stable, so the list's load effect does not restart when this component re-renders.
  const handleColdKeys = useCallback(() => {
    send('coldKeys')
  }, [])

  if (groupId === undefined) return null
  if (userId === null) return null
  if (gate.step === 'password') {
    return (
      <ReauthenticateStep
        sessionUserId={userId}
        action="read posts"
        onDone={() => {
          send('reauthenticated')
        }}
        onCancel={() => {
          send('cancel')
        }}
      />
    )
  }
  if (gate.step === 'declined') {
    // The list stays unmounted: mounting it loads page 1, which asks again.
    return (
      <>
        <h1 className="text-lg font-semibold">Posts</h1>
        <div className="flex w-full max-w-xl flex-col gap-4 text-left">
          <Alert variant="destructive">
            <AlertDescription>{PAGE_ERRORS.coldKeys}</AlertDescription>
          </Alert>
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              send('askAgain')
            }}
          >
            Enter password
          </Button>
        </div>
      </>
    )
  }
  return (
    <>
      <h1 className="text-lg font-semibold">Posts</h1>
      <PostsList
        key={`${groupId}:${String(gate.round)}`}
        groupId={groupId}
        userId={userId}
        onColdKeys={handleColdKeys}
      />
    </>
  )
}

function PostsList({
  groupId,
  userId,
  onColdKeys,
}: {
  readonly groupId: string
  readonly userId: string
  readonly onColdKeys: () => void
}) {
  // One resolver per visit, so an author is read and pinned once.
  const reader = useMemo(() => {
    const deps: ListPostsDeps = {
      getGroup,
      getChain: (gid, from, to) => fetchNameChain(getKeychain, gid, from, to),
      listPosts,
      openPosts,
      getUserDetail,
      selfUserId: userId,
      ownSigningKey: () => ownSigningKeyWithFallback(userId, getOwnSigningKey),
      loadOwnKeyHistory: makeOwnKeyHistoryLoader(userId),
      listPins: listAllPins,
      pinKeys: makePinKeys(userId),
    }
    return { deps, resolveAuthor: makeAuthorResolver(deps) }
  }, [userId])
  const [posts, setPosts] = useState<readonly PostView[]>([])
  const [cursor, setCursor] = useState<string | undefined>(undefined)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // The first page failed in a way another try can fix: there is no "Load older
  // posts" button yet to try again with.
  const [canRetry, setCanRetry] = useState(false)

  const apply = useCallback(
    (result: PageResult) => {
      setLoading(false)
      setCanRetry(false)
      if (!result.ok) {
        setError(PAGE_ERRORS[result.kind])
        setCanRetry(result.kind === 'failed' || result.kind === 'chain')
        if (result.kind === 'coldKeys') onColdKeys()
        return
      }
      // A post already shown (a cursor served twice) is dropped, not duplicated.
      setPosts((prev) => {
        const seen = new Set(prev.map((p) => p.sortKey))
        return [...prev, ...result.posts.filter((p) => !seen.has(p.sortKey))]
      })
      setCursor(result.nextCursor)
    },
    [onColdKeys],
  )

  useEffect(() => {
    let cancelled = false
    void loadPostsPage(reader.deps, reader.resolveAuthor, groupId).then((result) => {
      if (!cancelled) apply(result)
    })
    return () => {
      cancelled = true
    }
  }, [reader, groupId, apply])

  return (
    <GroupPostsPanel
      groupId={groupId}
      posts={posts}
      loading={loading}
      error={error}
      hasMore={cursor !== undefined}
      onRetry={
        canRetry && cursor === undefined && posts.length === 0
          ? () => {
              setLoading(true)
              setError(null)
              void loadPostsPage(reader.deps, reader.resolveAuthor, groupId).then(apply)
            }
          : undefined
      }
      onLoadMore={() => {
        setLoading(true)
        setError(null)
        void loadPostsPage(reader.deps, reader.resolveAuthor, groupId, cursor).then(apply)
      }}
    />
  )
}

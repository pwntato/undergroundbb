// #43: read a group's posts at /groups/:groupId/posts. Wrapped by RequireAuth in
// App.tsx (baseline session check; the server's 404 is the real check).
//
// Opening and checking are runListPosts.ts's job; this component owns state and
// effects, and GroupPostsPanel owns rendering. Pages load newest day first and
// "Load older posts" asks for the next one by cursor. The list is its own
// component, keyed by group and by re-login, so its state starts fresh by
// remounting rather than by an effect resetting it.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router'
import { getGroup, getKeychain, listPosts } from '@/lib/api/groups'
import { listAllPins } from '@/lib/api/pins'
import { getUserDetail } from '@/lib/api/users'
import { getOwnSigningKey, openPosts } from '@/lib/crypto/worker-client'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { makeOwnKeyHistoryLoader } from '@/lib/session/ownKeyHistory'
import { ownSigningKeyWithFallback } from '@/lib/session/ownSigningKey'
import { useSession } from '@/lib/session/useSession'
import { GroupPostsPanel } from './GroupPostsPanel'
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
  const [needsReauth, setNeedsReauth] = useState(false)
  // Bumped after a re-login so the list remounts and loads from the first page.
  const [round, setRound] = useState(0)
  // Stable, so the list's load effect does not restart when this component re-renders.
  const handleColdKeys = useCallback(() => {
    setNeedsReauth(true)
  }, [])

  if (groupId === undefined) return null
  if (needsReauth && userId !== null) {
    return (
      <ReauthenticateStep
        sessionUserId={userId}
        action="read posts"
        onDone={() => {
          setNeedsReauth(false)
          setRound((n) => n + 1)
        }}
        onCancel={() => {
          setNeedsReauth(false)
        }}
      />
    )
  }
  if (userId === null) return null
  return (
    <>
      <h1 className="text-lg font-semibold">Posts</h1>
      <PostsList
        key={`${groupId}:${String(round)}`}
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

  const apply = useCallback(
    (result: PageResult) => {
      setLoading(false)
      if (!result.ok) {
        setError(PAGE_ERRORS[result.kind])
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
      onLoadMore={() => {
        setLoading(true)
        setError(null)
        void loadPostsPage(reader.deps, reader.resolveAuthor, groupId, cursor).then(apply)
      }}
    />
  )
}

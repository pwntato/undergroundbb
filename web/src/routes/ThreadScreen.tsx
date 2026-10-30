// #44: read a post's comments at /groups/:groupId/posts/:postId. Wrapped by
// RequireAuth in App.tsx (baseline session check; the server's 404 is the real
// check). The `#`s in a post id travel as %23 in the URL.
//
// Opening and checking are runLoadThread.ts's job and paging is threadState.ts's;
// this component owns effects, and ThreadPanel owns rendering. Like the post list,
// the thread is its own component keyed by post and by re-login, so its state
// starts fresh by remounting rather than by an effect resetting it, and the
// password step reuses postsGate.

import { useCallback, useEffect, useMemo, useReducer } from 'react'
import { useLocation, useParams } from 'react-router'
import { getGroup, getKeychain, getThread } from '@/lib/api/groups'
import { listAllPins } from '@/lib/api/pins'
import { getUserDetail } from '@/lib/api/users'
import { getOwnSigningKey, openComments } from '@/lib/crypto/worker-client'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { makeOwnKeyHistoryLoader } from '@/lib/session/ownKeyHistory'
import { ownSigningKeyWithFallback } from '@/lib/session/ownSigningKey'
import { useSession } from '@/lib/session/useSession'
import { INITIAL_POSTS_GATE, nextPostsGate } from './postsGate'
import { PostsPasswordDeclined } from './PostsPasswordDeclined'
import { ReauthenticateStep } from './ReauthenticateStep'
import { makePinKeys } from './rotationDeps'
import { makeAuthorResolver } from './runListPosts'
import { loadThreadPage, type LoadThreadDeps, type ThreadPageResult } from './runLoadThread'
import { ThreadPanel } from './ThreadPanel'
import { canRetryFailure, INITIAL_THREAD_STATE, nextThreadState } from './threadState'

const PAGE_ERRORS: Record<Exclude<ThreadPageResult, { ok: true }>['kind'], string> = {
  notFound: 'This post no longer exists, or you are no longer a member of its group.',
  authRequired: 'Your session has expired. Log in again and retry.',
  coldKeys: 'This tab needs your password again to read comments.',
  chain: "Couldn't read this group's older keys, so older comments can't be opened. Try again.",
  failed: "Couldn't load the comments. Try again.",
}

/** What the post list passes along so the thread can name the post; display only. */
interface ThreadLocationState {
  readonly postTitle?: string
}

export function ThreadScreen() {
  const { groupId, postId } = useParams<{ groupId: string; postId: string }>()
  const userId = useSession().userId
  const location = useLocation()
  const [gate, send] = useReducer(nextPostsGate, INITIAL_POSTS_GATE)
  // Stable, so the thread's load effect does not restart when this component re-renders.
  const handleColdKeys = useCallback(() => {
    send('coldKeys')
  }, [])

  if (groupId === undefined || postId === undefined) return null
  if (userId === null) return null
  if (gate.step === 'password') {
    return (
      <ReauthenticateStep
        sessionUserId={userId}
        action="read comments"
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
    // The thread stays unmounted: mounting it loads page 1, which asks again.
    return (
      <>
        <h1 className="text-lg font-semibold">Comments</h1>
        <PostsPasswordDeclined
          message={PAGE_ERRORS.coldKeys}
          onAskAgain={() => {
            send('askAgain')
          }}
        />
      </>
    )
  }
  const postTitle = (location.state as ThreadLocationState | null)?.postTitle
  return (
    <>
      <h1 className="text-lg font-semibold">Comments</h1>
      <Thread
        key={`${postId}:${String(gate.round)}`}
        groupId={groupId}
        postId={postId}
        userId={userId}
        postTitle={typeof postTitle === 'string' ? postTitle : undefined}
        onColdKeys={handleColdKeys}
      />
    </>
  )
}

function Thread({
  groupId,
  postId,
  userId,
  postTitle,
  onColdKeys,
}: {
  readonly groupId: string
  readonly postId: string
  readonly userId: string
  readonly postTitle: string | undefined
  readonly onColdKeys: () => void
}) {
  // One resolver per visit, so an author is read and pinned once.
  const reader = useMemo(() => {
    const deps: LoadThreadDeps & Parameters<typeof makeAuthorResolver>[0] = {
      getGroup,
      getChain: (gid, from, to) => fetchNameChain(getKeychain, gid, from, to),
      getThread,
      openComments,
      getUserDetail,
      selfUserId: userId,
      ownSigningKey: () => ownSigningKeyWithFallback(userId, getOwnSigningKey),
      loadOwnKeyHistory: makeOwnKeyHistoryLoader(userId),
      listPins: listAllPins,
      pinKeys: makePinKeys(userId),
    }
    return { deps, resolveAuthor: makeAuthorResolver(deps) }
  }, [userId])
  const [state, dispatch] = useReducer(nextThreadState, INITIAL_THREAD_STATE)

  const apply = useCallback(
    (result: ThreadPageResult) => {
      dispatch({ type: 'pageLoaded', result })
      if (!result.ok && result.kind === 'coldKeys') onColdKeys()
    },
    [onColdKeys],
  )
  const load = useCallback(
    (cursor: string | undefined) => {
      dispatch({ type: 'loadStarted' })
      void loadThreadPage(reader.deps, reader.resolveAuthor, groupId, postId, cursor).then(apply)
    },
    [reader, groupId, postId, apply],
  )

  useEffect(() => {
    let cancelled = false
    void loadThreadPage(reader.deps, reader.resolveAuthor, groupId, postId).then((result) => {
      if (!cancelled) apply(result)
    })
    return () => {
      cancelled = true
    }
  }, [reader, groupId, postId, apply])

  return (
    <ThreadPanel
      groupId={groupId}
      postTitle={postTitle}
      comments={state.comments}
      loading={state.loading}
      error={state.failure === null ? null : PAGE_ERRORS[state.failure]}
      hasMore={state.cursor !== undefined}
      onRetry={
        canRetryFailure(state.failure)
          ? () => {
              load(state.cursor)
            }
          : undefined
      }
      onLoadMore={() => {
        load(state.cursor)
      }}
    />
  )
}

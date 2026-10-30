// #44: read a post's comments at /groups/:groupId/posts/:postId. Wrapped by
// RequireAuth in App.tsx (baseline session check; the server's 404 is the real
// check). The `#`s in a post id travel as %23 in the URL.
//
// Opening and checking are runLoadThread.ts's job and paging is threadState.ts's;
// this component owns effects, and ThreadPanel owns rendering. Like the post list,
// the thread is its own component keyed by post and by re-login, so its state
// starts fresh by remounting rather than by an effect resetting it, and the
// password step reuses postsGate.

import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react'
import { useLocation, useParams } from 'react-router'
import { getPublicConfig } from '@/lib/api/config'
import { createComment, getGroup, getKeychain, getThread } from '@/lib/api/groups'
import { listAllPins } from '@/lib/api/pins'
import { getUserDetail } from '@/lib/api/users'
import { getOwnSigningKey, openComments, sealComment } from '@/lib/crypto/worker-client'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { makeOwnKeyHistoryLoader } from '@/lib/session/ownKeyHistory'
import { ownSigningKeyWithFallback } from '@/lib/session/ownSigningKey'
import { useSession } from '@/lib/session/useSession'
import { INITIAL_POSTS_GATE, nextPostsGate } from './postsGate'
import { PostsPasswordDeclined } from './PostsPasswordDeclined'
import { ReauthenticateStep } from './ReauthenticateStep'
import { INITIAL_REPLY_STATE, nextReplyState } from './replyState'
import { makePinKeys } from './rotationDeps'
import { DEFAULT_MAX_COMMENT_BYTES } from './runCreateComment'
import { makeAuthorResolver } from './runListPosts'
import { loadThreadPage, type LoadThreadDeps, type ThreadPageResult } from './runLoadThread'
import { ThreadPanel, type ThreadReply } from './ThreadPanel'
import { canRetryFailure, INITIAL_THREAD_STATE, nextThreadState } from './threadState'
import {
  loadPageInto,
  sendReply,
  type PendingReply,
  type SavedReply,
  type ThreadIO,
} from './threadWiring'

const PAGE_ERRORS: Record<Exclude<ThreadPageResult, { ok: true }>['kind'], string> = {
  notFound: 'This post no longer exists, or you are no longer a member of its group.',
  authRequired: 'Your session has expired. Log in again and retry.',
  coldKeys: 'This tab needs your password again to read or write comments.',
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
  // The reply in the box when the password step was asked for, so it comes back
  // after it. Replaced on every ask, with nothing when the box was empty, so an
  // old draft that was already sent is never brought back.
  const [saved, setSaved] = useState<SavedReply | undefined>(undefined)
  // Stable, so the thread's load effect does not restart when this component re-renders.
  const handleColdKeys = useCallback((reply?: SavedReply) => {
    setSaved(reply)
    send('coldKeys')
  }, [])

  if (groupId === undefined || postId === undefined) return null
  if (userId === null) return null
  if (gate.step === 'password') {
    return (
      <ReauthenticateStep
        sessionUserId={userId}
        action="read or write comments"
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
        initialReply={saved}
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
  initialReply,
  onColdKeys,
}: {
  readonly groupId: string
  readonly postId: string
  readonly userId: string
  readonly postTitle: string | undefined
  readonly initialReply: SavedReply | undefined
  readonly onColdKeys: (reply?: SavedReply) => void
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
  const [replyState, dispatchReply] = useReducer(
    nextReplyState,
    initialReply === undefined
      ? INITIAL_REPLY_STATE
      : { ...INITIAL_REPLY_STATE, replyTo: initialReply.replyTo, draft: initialReply.draft },
  )
  const [maxBytes, setMaxBytes] = useState(DEFAULT_MAX_COMMENT_BYTES)
  // Bumped when the thread starts over, so a page still in flight is dropped.
  const epoch = useRef(0)
  // The comment a send left unanswered; sent again unchanged while the box still matches.
  const pending = useRef<PendingReply | null>(null)
  // What the reply box holds right now, for a password step asked for by a page load.
  const replyNow = useRef(replyState)
  useEffect(() => {
    replyNow.current = replyState
  })
  const io: ThreadIO = useMemo(
    () => ({
      dispatch,
      dispatchReply,
      onColdKeys,
      liveReply: () =>
        replyNow.current.draft === ''
          ? undefined
          : { replyTo: replyNow.current.replyTo, draft: replyNow.current.draft },
    }),
    [onColdKeys],
  )
  const loadPage = useCallback(
    (cursor: string | undefined) =>
      loadThreadPage(reader.deps, reader.resolveAuthor, groupId, postId, cursor),
    [reader, groupId, postId],
  )
  const load = useCallback(
    (cursor: string | undefined) => {
      const mine = epoch.current
      void loadPageInto(io, loadPage, () => mine === epoch.current, cursor, true)
    },
    [io, loadPage],
  )
  // Starts over from the first page: a new comment may sit on any page.
  const reload = useCallback(() => {
    epoch.current += 1
    dispatch({ type: 'reset' })
    load(undefined)
  }, [load])

  useEffect(() => {
    let cancelled = false
    void getPublicConfig()
      .then((c) => {
        if (!cancelled) setMaxBytes(c.maxCommentBytes)
      })
      .catch(() => {
        // The default matches the server's; it enforces its own limit regardless.
      })
    return () => {
      cancelled = true
    }
  }, [])

  const handleSend = () => {
    void sendReply(
      { ...io, reload },
      { context: reader.deps, submit: { userId, sealComment, createComment }, pending },
      {
        groupId,
        postId,
        replyTo: replyState.replyTo,
        text: replyState.draft,
        loadedPaths: state.comments.map((c) => c.path),
      },
    )
  }

  const reply: ThreadReply = {
    replyTo: replyState.replyTo,
    draft: replyState.draft,
    maxBytes,
    sending: replyState.sending,
    error: replyState.error,
    notice: replyState.notice,
    onOpen: (replyTo) => {
      dispatchReply({ type: 'opened', replyTo })
    },
    onEdit: (draft) => {
      dispatchReply({ type: 'edited', draft })
    },
    onSend: handleSend,
  }

  useEffect(() => {
    let cancelled = false
    void loadPageInto(io, loadPage, () => !cancelled && epoch.current === 0, undefined, false)
    return () => {
      cancelled = true
    }
  }, [io, loadPage])

  return (
    <ThreadPanel
      groupId={groupId}
      postTitle={postTitle}
      comments={state.comments}
      loading={state.loading}
      error={state.failure === null ? null : PAGE_ERRORS[state.failure]}
      reply={state.failure === 'notFound' ? undefined : reply}
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

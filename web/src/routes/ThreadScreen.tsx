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
import type { SealedComment } from '@/lib/crypto/worker-protocol'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { makeOwnKeyHistoryLoader } from '@/lib/session/ownKeyHistory'
import { ownSigningKeyWithFallback } from '@/lib/session/ownSigningKey'
import { useSession } from '@/lib/session/useSession'
import { INITIAL_POSTS_GATE, nextPostsGate } from './postsGate'
import { PostsPasswordDeclined } from './PostsPasswordDeclined'
import { ReauthenticateStep } from './ReauthenticateStep'
import { INITIAL_REPLY_STATE, nextReplyState } from './replyState'
import { makePinKeys } from './rotationDeps'
import {
  attachParent,
  DEFAULT_MAX_COMMENT_BYTES,
  guessPath,
  loadSealContext,
  submitComment,
  type SubmitResult,
} from './runCreateComment'
import { makeAuthorResolver } from './runListPosts'
import { loadThreadPage, type LoadThreadDeps, type ThreadPageResult } from './runLoadThread'
import { ThreadPanel, type ThreadReply } from './ThreadPanel'
import { canRetryFailure, INITIAL_THREAD_STATE, nextThreadState } from './threadState'

const PAGE_ERRORS: Record<Exclude<ThreadPageResult, { ok: true }>['kind'], string> = {
  notFound: 'This post no longer exists, or you are no longer a member of its group.',
  authRequired: 'Your session has expired. Log in again and retry.',
  coldKeys: 'This tab needs your password again to read comments.',
  chain: "Couldn't read this group's older keys, so older comments can't be opened. Try again.",
  failed: "Couldn't load the comments. Try again.",
}

const SEND_ERRORS: Record<Exclude<SubmitResult, { ok: true }>['kind'], string> = {
  reseal: 'The group changed while you were writing. Press Send again to send it with the new key.',
  behind:
    'Your key for this group is behind. Wait for the key rotation to reach you, then try again.',
  dormant:
    'You rotated your keys and an admin has not approved them for this group yet. Ask an admin to approve you from Members.',
  authRequired: 'Your session has expired. Log in again and retry.',
  notFound: 'This post no longer exists, or you are no longer a member of its group.',
  coldKeys: 'This tab needs your password again to write a comment.',
  unreadable:
    "Couldn't open this group's key, so the comment was not sent. Reload the page and try again.",
  repliesFull: "This comment can't take any more replies.",
  parentGone: 'The comment you replied to is no longer there. The comments have been reloaded.',
  busy: 'Others are replying at the same moment. Press Send again.',
  rejected: 'The server rejected the comment.',
  ambiguous:
    "We couldn't confirm whether the comment was saved. Press Send again to send the same comment; it will not be sent twice.",
}

const CONTEXT_ERRORS = {
  notFound: SEND_ERRORS.notFound,
  authRequired: SEND_ERRORS.authRequired,
  behind: SEND_ERRORS.behind,
  unreadable: SEND_ERRORS.unreadable,
  failed: "Couldn't load this group. Try again.",
} as const

/** A reply in progress, kept across the password step. */
interface SavedReply {
  readonly replyTo: string | null
  readonly draft: string
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
  const [saved, setSaved] = useState<SavedReply | undefined>(undefined)
  const handleColdKeys = useCallback((reply?: SavedReply) => {
    // A reply typed before the password step is asked for comes back after it.
    if (reply !== undefined) setSaved(reply)
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
  // The comment a send left unanswered, with what it came from; sent again
  // unchanged while the box still matches.
  const pending = useRef<{
    sealed: SealedComment
    text: string
    replyTo: string | null
  } | null>(null)

  const apply = useCallback(
    (result: ThreadPageResult) => {
      dispatch({ type: 'pageLoaded', result })
      if (!result.ok && result.kind === 'coldKeys') onColdKeys()
    },
    [onColdKeys],
  )
  const load = useCallback(
    (cursor: string | undefined) => {
      const mine = epoch.current
      dispatch({ type: 'loadStarted' })
      void loadThreadPage(reader.deps, reader.resolveAuthor, groupId, postId, cursor).then(
        (result) => {
          if (mine === epoch.current) apply(result)
        },
      )
    },
    [reader, groupId, postId, apply],
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
    const { replyTo, draft: text } = replyState
    dispatchReply({ type: 'sendStarted' })
    void (async () => {
      const again = pending.current
      const resend = again?.text === text && again.replyTo === replyTo ? again.sealed : undefined
      if (resend === undefined) pending.current = null
      const fail = (message: string) => {
        dispatchReply({ type: 'sendFailed', error: message })
      }
      const loaded = await loadSealContext(reader.deps, groupId)
      if (!loaded.ok) {
        fail(CONTEXT_ERRORS[loaded.kind])
        return
      }
      const result = await submitComment(
        { userId, sealComment, createComment },
        {
          groupId,
          postId,
          context: loaded.context,
          text,
          firstPath:
            resend?.path ??
            guessPath(
              attachParent(replyTo),
              state.comments.map((c) => c.path),
            ),
          ...(resend !== undefined && { resend }),
        },
      )
      if (result.ok) {
        pending.current = null
        dispatchReply({ type: 'sent', notice: 'Comment sent.' })
        reload()
        return
      }
      pending.current =
        result.kind === 'ambiguous' && result.sealed !== undefined
          ? { sealed: result.sealed, text, replyTo }
          : null
      fail(
        result.kind === 'rejected'
          ? (result.message ?? SEND_ERRORS.rejected)
          : SEND_ERRORS[result.kind],
      )
      if (result.kind === 'coldKeys') onColdKeys({ replyTo, draft: text })
      // The comment replied to is gone: show the thread as it is now.
      if (result.kind === 'parentGone') reload()
    })()
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
    void loadThreadPage(reader.deps, reader.resolveAuthor, groupId, postId).then((result) => {
      if (!cancelled && epoch.current === 0) apply(result)
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

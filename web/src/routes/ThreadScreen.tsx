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
import {
  createComment,
  deleteComment,
  deletePost,
  deleteReaction,
  editComment,
  editPost,
  getGroup,
  getKeychain,
  getPost,
  getThread,
  putReaction,
} from '@/lib/api/groups'
import { listAllPins } from '@/lib/api/pins'
import { getUserDetail } from '@/lib/api/users'
import {
  getOwnSigningKey,
  openComments,
  openPosts,
  openReactions,
  sealComment,
  sealCommentEdit,
  sealPostEdit,
  sealReaction,
} from '@/lib/crypto/worker-client'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { makeOwnKeyHistoryLoader } from '@/lib/session/ownKeyHistory'
import { ownSigningKeyWithFallback } from '@/lib/session/ownSigningKey'
import { useSession } from '@/lib/session/useSession'
import { nextControlsState, replyOffered } from './commentControls'
import { nextPostControlsState } from './postControls'
import { INITIAL_POSTS_GATE, nextPostsGate } from './postsGate'
import { confirmDeletePost, saveEditPost, type PendingPostEdit } from './postWiring'
import { PostsPasswordDeclined } from './PostsPasswordDeclined'
import { ReauthenticateStep } from './ReauthenticateStep'
import {
  restoredCommentControls,
  restoredPostControls,
  snapshotEdits,
  type SavedEdits,
} from './savedEdits'
import { seekForm } from './formSeek'
import { INITIAL_REPLY_STATE, nextReplyState } from './replyState'
import { makePinKeys } from './rotationDeps'
import { DEFAULT_MAX_COMMENT_BYTES } from './runCreateComment'
import { DEFAULT_POST_LIMITS, type PostLimits } from './runCreatePost'
import {
  isDeletedPost,
  loadPost,
  makeAuthorResolver,
  type LoadPostDeps,
  type PostEntry,
} from './runListPosts'
import {
  isDeletedComment,
  loadThreadPage,
  type LoadThreadDeps,
  type ThreadPageResult,
} from './runLoadThread'
import { applyPostResult } from './threadPost'
import {
  ThreadPanel,
  type ThreadControls,
  type ThreadPost,
  type ThreadReactions,
  type ThreadReply,
} from './ThreadPanel'
import type { PostListControls } from './GroupPostsPanel'
import { canRetryFailure, INITIAL_THREAD_STATE, nextThreadState } from './threadState'
import {
  confirmDelete,
  loadPageInto,
  saveEdit,
  sendReply,
  toggleReaction,
  type PendingEdit,
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
  // Likewise the edit forms open then (#319): what was typed into them comes back too.
  const [savedEdits, setSavedEdits] = useState<SavedEdits | undefined>(undefined)
  // Stable, so the thread's load effect does not restart when this component re-renders.
  const handleColdKeys = useCallback((reply?: SavedReply, edits?: SavedEdits) => {
    setSaved(reply)
    setSavedEdits(edits)
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
        initialEdits={savedEdits}
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
  initialEdits,
  onColdKeys: askForPassword,
}: {
  readonly groupId: string
  readonly postId: string
  readonly userId: string
  readonly postTitle: string | undefined
  readonly initialReply: SavedReply | undefined
  readonly initialEdits: SavedEdits | undefined
  readonly onColdKeys: (reply?: SavedReply, edits?: SavedEdits) => void
}) {
  // One resolver per visit, so an author is read and pinned once.
  const reader = useMemo(() => {
    const deps: LoadThreadDeps & Parameters<typeof makeAuthorResolver>[0] = {
      getGroup,
      getChain: (gid, from, to) => fetchNameChain(getKeychain, gid, from, to),
      getThread,
      openComments,
      openReactions,
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
  const [controlsState, dispatchControls] = useReducer(
    nextControlsState,
    restoredCommentControls(initialEdits, postId),
  )
  // Whether the reader is an admin of the group, who may delete anyone's comment. The
  // server decides; this only decides whether to offer the button.
  const [isAdmin, setIsAdmin] = useState(false)
  const [maxBytes, setMaxBytes] = useState(DEFAULT_MAX_COMMENT_BYTES)
  // The post the thread hangs on (#318), with the Edit and Delete controls on it.
  const [post, setPost] = useState<PostEntry | null>(null)
  // Whether a post is on screen, for a load that finds it gone to know it vanished.
  const postShown = useRef(false)
  const [postProblem, setPostProblem] = useState<string | null>(null)
  const [postControlsState, dispatchPostControls] = useReducer(
    nextPostControlsState,
    restoredPostControls(initialEdits, postId),
  )
  const [limits, setLimits] = useState<PostLimits>(DEFAULT_POST_LIMITS)
  // Bumped when the post is read again, so a read still in flight is dropped.
  const postEpoch = useRef(0)
  // The edit of the post a send left unanswered; sent again unchanged while the form still matches.
  const pendingPostEdit = useRef<PendingPostEdit | null>(null)
  // Bumped when the thread starts over, so a page still in flight is dropped.
  const epoch = useRef(0)
  // The comment a send left unanswered; sent again unchanged while the box still matches.
  const pending = useRef<PendingReply | null>(null)
  // Likewise an edit a send left unanswered.
  const pendingEdit = useRef<PendingEdit | null>(null)
  // What the reply box holds right now, for a password step asked for by a page load.
  const replyNow = useRef(replyState)
  useEffect(() => {
    replyNow.current = replyState
  })
  // The edit forms open right now, for the same (#319).
  const editsNow = useRef({ comment: controlsState.mode, post: postControlsState.mode })
  useEffect(() => {
    editsNow.current = { comment: controlsState.mode, post: postControlsState.mode }
  })
  // Asks for the password, taking along the reply and the edit forms open at this moment.
  const onColdKeys = useCallback(
    (reply?: SavedReply) => {
      askForPassword(reply, snapshotEdits(postId, editsNow.current.comment, editsNow.current.post))
    },
    [askForPassword, postId],
  )
  const io: ThreadIO = useMemo(
    () => ({
      dispatch,
      dispatchReply,
      dispatchControls,
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
        if (!cancelled) {
          setMaxBytes(c.maxCommentBytes)
          setLimits({ maxTitleBytes: c.maxPostTitleBytes, maxBodyBytes: c.maxPostBodyBytes })
        }
      })
      .catch(() => {
        // The default matches the server's; it enforces its own limit regardless.
      })
    return () => {
      cancelled = true
    }
  }, [])

  const postDeps: LoadPostDeps = useMemo(() => ({ ...reader.deps, getPost, openPosts }), [reader])
  const postIo = useMemo(
    () => ({
      setPost: (next: PostEntry | null) => {
        postShown.current = next !== null
        setPost(next)
      },
      hadPost: () => postShown.current,
      setProblem: setPostProblem,
      dispatchPostControls,
      dispatchControls,
      onColdKeys: () => {
        onColdKeys(
          replyNow.current.draft === ''
            ? undefined
            : { replyTo: replyNow.current.replyTo, draft: replyNow.current.draft },
        )
      },
    }),
    [onColdKeys],
  )
  // Reads the post again, e.g. after it was edited or deleted.
  const reloadPost = useCallback(() => {
    postEpoch.current += 1
    const mine = postEpoch.current
    void loadPost(postDeps, reader.resolveAuthor, groupId, postId).then((result) => {
      if (mine === postEpoch.current) applyPostResult(postIo, result)
    })
  }, [postDeps, reader, groupId, postId, postIo])

  useEffect(() => {
    let cancelled = false
    void loadPost(postDeps, reader.resolveAuthor, groupId, postId).then((result) => {
      if (!cancelled && postEpoch.current === 0) applyPostResult(postIo, result)
    })
    return () => {
      cancelled = true
    }
  }, [postDeps, reader, groupId, postId, postIo])

  useEffect(() => {
    let cancelled = false
    void getGroup(groupId)
      .then((g) => {
        if (!cancelled) setIsAdmin(g.role === 'admin')
      })
      .catch(() => {
        // No Delete for others' comments; the server enforces who may delete regardless.
      })
    return () => {
      cancelled = true
    }
  }, [groupId])

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

  const handleReact = (target: string, index: number) => {
    void toggleReaction(
      { ...io, reload },
      {
        userId,
        context: reader.deps,
        sealReaction,
        putReaction,
        deleteReaction,
      },
      { groupId, postId, target, index, reactions: state.reactions },
    )
  }

  const reactions: ThreadReactions = {
    reactions: state.reactions,
    selfUserId: userId,
    reacting: state.reacting,
    error: state.reactionError,
    notice: state.notice,
    ready: state.loaded,
    readOnly: controlsState.readOnly,
    onPress: handleReact,
  }

  // A form restored after the password step (or kept over a reload) can hang on a comment
  // that is on a later page: load on, one page at a time, until it shows. When the thread
  // ends without it, the comment is gone and the form closes (#328).
  const formPath = controlsState.mode.kind === 'idle' ? undefined : controlsState.mode.path
  const lastAutoCursor = useRef<string | undefined>(undefined)
  useEffect(() => {
    const seek = seekForm({
      formKey: formPath,
      settled: state.loaded && !state.loading && state.failure === null,
      shown: state.comments.map((c) => c.path),
      cursor: state.cursor,
      lastAsked: lastAutoCursor.current,
    })
    if (seek.kind === 'gone') {
      dispatchControls({
        type: 'endReached',
        livePaths: state.comments.filter((c) => !isDeletedComment(c)).map((c) => c.path),
      })
    } else if (seek.kind === 'loadMore') {
      lastAutoCursor.current = seek.cursor
      load(seek.cursor)
    }
  }, [formPath, state.loaded, state.loading, state.failure, state.comments, state.cursor, load])

  const handleSave = () => {
    const mode = controlsState.mode
    if (mode.kind !== 'editing') return
    const target = state.comments.find((c) => c.path === mode.path)
    if (target === undefined || isDeletedComment(target) || target.content.kind !== 'opened') return
    void saveEdit(
      { ...io, reload },
      {
        edit: { userId, context: reader.deps, sealCommentEdit, editComment },
        pending: pendingEdit,
      },
      { groupId, postId, path: mode.path, text: mode.draft, at: target.content.at },
    )
  }

  const handleDeleteConfirm = () => {
    const mode = controlsState.mode
    if (mode.kind !== 'confirmDelete') return
    void confirmDelete({ ...io, reload }, { deleteComment }, { postId, path: mode.path })
  }

  const controls: ThreadControls = {
    selfUserId: userId,
    isAdmin,
    readOnly: controlsState.readOnly,
    mode: controlsState.mode,
    busy: controlsState.busy,
    error: controlsState.error,
    maxBytes,
    onEditOpen: (path, text) => {
      dispatchControls({ type: 'editOpened', path, text })
    },
    onDraft: (draft) => {
      dispatchControls({ type: 'draftEdited', draft })
    },
    onSave: handleSave,
    onDeleteAsk: (path) => {
      dispatchControls({ type: 'deleteAsked', path })
    },
    onDeleteConfirm: handleDeleteConfirm,
    onClose: () => {
      dispatchControls({ type: 'closed' })
    },
  }

  const handleSavePost = (title: string, body: string) => {
    const mode = postControlsState.mode
    if (mode.kind !== 'editing' || post === null || isDeletedPost(post)) return
    if (post.sortKey !== mode.sortKey || post.content.kind !== 'opened') return
    void saveEditPost(
      { dispatchControls: dispatchPostControls, reload: reloadPost, onColdKeys: postIo.onColdKeys },
      {
        edit: {
          userId,
          getGroup,
          getChain: reader.deps.getChain,
          sealPostEdit,
          editPost,
        },
        pending: pendingPostEdit,
      },
      { groupId, postId, sortKey: mode.sortKey, title, body, at: post.content.at },
    )
  }

  const postControls: PostListControls = {
    selfUserId: userId,
    isAdmin,
    mode: postControlsState.mode,
    busy: postControlsState.busy,
    error: postControlsState.error,
    limits,
    onEditOpen: (sortKey, title, body) => {
      dispatchPostControls({ type: 'editOpened', sortKey, title, body })
    },
    onSave: handleSavePost,
    onDraft: (title, body) => {
      dispatchPostControls({ type: 'draftEdited', title, body })
    },
    onDeleteAsk: (sortKey) => {
      dispatchPostControls({ type: 'deleteAsked', sortKey })
    },
    onDeleteConfirm: () => {
      if (postControlsState.mode.kind !== 'confirmDelete') return
      void confirmDeletePost(
        { dispatchControls: dispatchPostControls, reload: reloadPost },
        { deletePost },
        { postId },
      )
    },
    onClose: () => {
      dispatchPostControls({ type: 'closed' })
    },
  }
  const threadPost: ThreadPost | undefined =
    post === null ? undefined : { entry: post, controls: postControls }

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
      post={threadPost}
      postProblem={postProblem}
      comments={state.comments}
      loading={state.loading}
      error={state.failure === null ? null : PAGE_ERRORS[state.failure]}
      reply={replyOffered(state.failure, controlsState.readOnly) ? reply : undefined}
      controls={state.failure === 'notFound' ? undefined : controls}
      reactions={state.failure === 'notFound' ? undefined : reactions}
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

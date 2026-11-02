// #43: read a group's posts at /groups/:groupId/posts. Wrapped by RequireAuth in
// App.tsx (baseline session check; the server's 404 is the real check).
//
// Opening and checking are runListPosts.ts's job; this component owns state and
// effects, and GroupPostsPanel owns rendering. Pages load newest day first and
// "Load older posts" asks for the next one by cursor. The list is its own
// component, keyed by group and by re-login, so its state starts fresh by
// remounting rather than by an effect resetting it.

import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react'
import { useParams } from 'react-router'
import { getPublicConfig } from '@/lib/api/config'
import { deletePost, editPost, getGroup, getKeychain, listPosts } from '@/lib/api/groups'
import { listAllPins } from '@/lib/api/pins'
import { getUserDetail } from '@/lib/api/users'
import { postIdOf } from '@/lib/crypto/post-check'
import { getOwnSigningKey, openPosts, sealPostEdit } from '@/lib/crypto/worker-client'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { makeOwnKeyHistoryLoader } from '@/lib/session/ownKeyHistory'
import { ownSigningKeyWithFallback } from '@/lib/session/ownSigningKey'
import { useSession } from '@/lib/session/useSession'
import { GroupPostsPanel, type PostListControls } from './GroupPostsPanel'
import { nextPostControlsState } from './postControls'
import { INITIAL_POSTS_GATE, nextPostsGate } from './postsGate'
import { confirmDeletePost, saveEditPost, type PendingPostEdit } from './postWiring'
import { PostsPasswordDeclined } from './PostsPasswordDeclined'
import { ReauthenticateStep } from './ReauthenticateStep'
import { makePinKeys } from './rotationDeps'
import { seekForm } from './formSeek'
import { restoredPostControls, snapshotEdits, type SavedEdits } from './savedEdits'
import { DEFAULT_POST_LIMITS, type PostLimits } from './runCreatePost'
import {
  isDeletedPost,
  loadPostsPage,
  makeAuthorResolver,
  type ListPostsDeps,
  type PageResult,
  type PostEntry,
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
  // The edit form open when the password was asked for (#319): what was typed into it
  // comes back with the list. Replaced on every ask, with nothing when none was open.
  const [savedEdits, setSavedEdits] = useState<SavedEdits | undefined>(undefined)
  // Stable, so the list's load effect does not restart when this component re-renders.
  const handleColdKeys = useCallback((edits?: SavedEdits) => {
    setSavedEdits(edits)
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
        <PostsPasswordDeclined
          message={PAGE_ERRORS.coldKeys}
          onAskAgain={() => {
            send('askAgain')
          }}
        />
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
        initialEdits={savedEdits}
        onColdKeys={handleColdKeys}
      />
    </>
  )
}

function PostsList({
  groupId,
  userId,
  initialEdits,
  onColdKeys: askForPassword,
}: {
  readonly groupId: string
  readonly userId: string
  readonly initialEdits: SavedEdits | undefined
  readonly onColdKeys: (edits?: SavedEdits) => void
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
  const [posts, setPosts] = useState<readonly PostEntry[]>([])
  const [cursor, setCursor] = useState<string | undefined>(undefined)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // The first page failed in a way another try can fix: there is no "Load older
  // posts" button yet to try again with.
  const [canRetry, setCanRetry] = useState(false)
  const [controlsState, dispatchControls] = useReducer(
    nextPostControlsState,
    restoredPostControls(initialEdits, groupId),
  )
  // The edit form open right now, for the password step.
  const modeNow = useRef(controlsState.mode)
  useEffect(() => {
    modeNow.current = controlsState.mode
  })
  const onColdKeys = useCallback(() => {
    askForPassword(snapshotEdits(groupId, undefined, modeNow.current))
  }, [askForPassword, groupId])
  // Whether the reader is an admin of the group, who may delete anyone's post. The
  // server decides; this only decides whether to offer the button.
  const [isAdmin, setIsAdmin] = useState(false)
  const [limits, setLimits] = useState<PostLimits>(DEFAULT_POST_LIMITS)
  // Bumped when the list starts over, so a page still in flight is dropped.
  const epoch = useRef(0)
  // The cursor the form-seek last loaded, so one page is not asked for twice in a row.
  const lastAutoCursor = useRef<string | undefined>(undefined)
  // The edit a send left unanswered; sent again unchanged while the form still matches.
  const pendingEdit = useRef<PendingPostEdit | null>(null)

  const apply = useCallback(
    (result: PageResult, first: boolean) => {
      setLoading(false)
      setCanRetry(false)
      if (!result.ok) {
        setError(PAGE_ERRORS[result.kind])
        setCanRetry(result.kind === 'failed' || result.kind === 'chain')
        if (result.kind === 'coldKeys') onColdKeys()
        if (first) dispatchControls({ type: 'firstPageFailed' })
        return
      }
      // A post already shown (a cursor served twice) is dropped, not duplicated.
      setPosts((prev) => {
        const seen = new Set(prev.map((p) => p.sortKey))
        return [...prev, ...result.posts.filter((p) => !seen.has(p.sortKey))]
      })
      setCursor(result.nextCursor)
      // The first page is everything on screen, so an edit or delete aimed at a post
      // that is not live on it is aimed at one that is gone.
      if (first) {
        dispatchControls({
          type: 'firstPageLoaded',
          liveKeys: result.posts.filter((p) => !isDeletedPost(p)).map((p) => p.sortKey),
          hasMore: result.nextCursor !== undefined,
        })
      }
    },
    [onColdKeys],
  )

  const load = useCallback(
    (from: string | undefined) => {
      const mine = epoch.current
      setLoading(true)
      setError(null)
      void loadPostsPage(reader.deps, reader.resolveAuthor, groupId, from).then((result) => {
        if (mine === epoch.current) apply(result, from === undefined)
      })
    },
    [reader, groupId, apply],
  )

  // Starts over from the first page, e.g. after a post was edited or deleted.
  const reload = useCallback(() => {
    epoch.current += 1
    // The list starts over, so its first page may end at a cursor already asked for.
    lastAutoCursor.current = undefined
    setPosts([])
    setCursor(undefined)
    load(undefined)
  }, [load])

  useEffect(() => {
    let cancelled = false
    void loadPostsPage(reader.deps, reader.resolveAuthor, groupId).then((result) => {
      if (!cancelled && epoch.current === 0) apply(result, true)
    })
    return () => {
      cancelled = true
    }
  }, [reader, groupId, apply])

  useEffect(() => {
    let cancelled = false
    void getGroup(groupId)
      .then((g) => {
        if (!cancelled) setIsAdmin(g.role === 'admin')
      })
      .catch(() => {
        // No Delete for others' posts; the server enforces who may delete regardless.
      })
    void getPublicConfig()
      .then((c) => {
        if (!cancelled) {
          setLimits({ maxTitleBytes: c.maxPostTitleBytes, maxBodyBytes: c.maxPostBodyBytes })
        }
      })
      .catch(() => {
        // The defaults match the server's; it enforces its own limits regardless.
      })
    return () => {
      cancelled = true
    }
  }, [groupId])

  // A form restored after the password step (or kept over a reload) can hang on a post that
  // is on an older page: load on, one page at a time, until it shows. When the list ends
  // without it, the post is gone and the form closes (#328).
  const formKey = controlsState.mode.kind === 'idle' ? undefined : controlsState.mode.sortKey
  useEffect(() => {
    const seek = seekForm({
      formKey,
      settled: !loading && error === null && posts.length > 0,
      shown: posts.map((p) => p.sortKey),
      live: posts.filter((p) => !isDeletedPost(p)).map((p) => p.sortKey),
      cursor,
      lastAsked: lastAutoCursor.current,
    })
    if (seek.kind === 'gone') {
      dispatchControls({
        type: 'endReached',
        liveKeys: posts.filter((p) => !isDeletedPost(p)).map((p) => p.sortKey),
      })
    } else if (seek.kind === 'loadMore') {
      lastAutoCursor.current = seek.cursor
      load(seek.cursor)
    }
  }, [formKey, loading, error, posts, cursor, load])

  const controls: PostListControls = {
    selfUserId: userId,
    isAdmin,
    mode: controlsState.mode,
    busy: controlsState.busy,
    error: controlsState.error,
    limits,
    onEditOpen: (sortKey, title, body) => {
      dispatchControls({ type: 'editOpened', sortKey, title, body })
    },
    onDraft: (title, body) => {
      dispatchControls({ type: 'draftEdited', title, body })
    },
    onSave: (title, body) => {
      const mode = controlsState.mode
      if (mode.kind !== 'editing') return
      const target = posts.find((p) => p.sortKey === mode.sortKey)
      const postId = postIdOf(groupId, mode.sortKey)
      if (
        target === undefined ||
        isDeletedPost(target) ||
        target.content.kind !== 'opened' ||
        postId === undefined
      ) {
        return
      }
      void saveEditPost(
        { dispatchControls, reload, onColdKeys },
        {
          edit: { userId, getGroup, getChain: reader.deps.getChain, sealPostEdit, editPost },
          pending: pendingEdit,
        },
        { groupId, postId, sortKey: mode.sortKey, title, body, at: target.content.at },
      )
    },
    onDeleteAsk: (sortKey) => {
      dispatchControls({ type: 'deleteAsked', sortKey })
    },
    onDeleteConfirm: () => {
      const mode = controlsState.mode
      if (mode.kind !== 'confirmDelete') return
      const postId = postIdOf(groupId, mode.sortKey)
      if (postId === undefined) return
      void confirmDeletePost({ dispatchControls, reload }, { deletePost }, { postId })
    },
    onClose: () => {
      dispatchControls({ type: 'closed' })
    },
  }

  return (
    <GroupPostsPanel
      groupId={groupId}
      posts={posts}
      loading={loading}
      error={error}
      controls={controls}
      hasMore={cursor !== undefined}
      onRetry={
        canRetry && cursor === undefined && posts.length === 0
          ? () => {
              load(undefined)
            }
          : undefined
      }
      onLoadMore={() => {
        load(cursor)
      }}
    />
  )
}

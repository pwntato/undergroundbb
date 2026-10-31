// The two async bodies ThreadScreen runs, pulled out of the component so they can
// be tested without a DOM (web/ has none) -- #44. Plain functions over injected
// dispatchers and deps, like runCreateComment.ts.
//
//   - loadPageInto: one page load. A page that arrives after the thread started
//     over (or after the screen went away) is dropped. The first page also tells
//     the reply box which comments are on screen, so a reply aimed at one that is
//     not (deleted, or restored from before the password step) is dropped.
//   - sendReply: one press of Send. The send target comes from the reply state,
//     the path guess from the comments on screen, and a gone parent reloads the
//     thread.
//   - toggleReaction: one press of a reaction button (#46). Pressing your own
//     reaction takes it back; pressing another sets it, replacing the one you
//     had. What is shown changes only after the server said yes.

import { ApiError } from '@/lib/api/auth'
import type { PutReactionRequest } from '@/lib/api/groups'
import type { SealedComment, SealedReaction } from '@/lib/crypto/worker-protocol'
import { TARGET_GONE_MESSAGE, type ReplyEvent } from './replyState'
import {
  attachParent,
  guessPath,
  loadSealContext,
  submitComment,
  type ContextDeps,
  type SealContext,
  type SubmitDeps,
  type SubmitResult,
} from './runCreateComment'
import { isLiveKeysError } from './runListGroups'
import { summarizeReactions } from './reactionSummary'
import type { ReactionView, ThreadPageResult } from './runLoadThread'
import type { ThreadEvent } from './threadState'

/** A reply in progress, kept across the password step. */
export interface SavedReply {
  readonly replyTo: string | null
  readonly draft: string
}

export interface ThreadIO {
  readonly dispatch: (event: ThreadEvent) => void
  readonly dispatchReply: (event: ReplyEvent) => void
  /**
   * The password step is needed. `reply` is what is in the box right now (absent
   * when it is empty), so the screen always holds the live draft and never an old one.
   */
  readonly onColdKeys: (reply?: SavedReply) => void
  /** What is in the reply box right now, or undefined when it is empty. */
  readonly liveReply: () => SavedReply | undefined
}

/** Loads one page (`cursor` undefined is the first) and applies it unless it is stale. */
export async function loadPageInto(
  io: ThreadIO,
  loadPage: (cursor: string | undefined) => Promise<ThreadPageResult>,
  isCurrent: () => boolean,
  cursor: string | undefined,
  announce: boolean,
): Promise<void> {
  if (announce) io.dispatch({ type: 'loadStarted' })
  const result = await loadPage(cursor)
  if (!isCurrent()) return
  io.dispatch({ type: 'pageLoaded', result })
  // The first page is everything on screen, so a reply target missing from it is gone from view.
  if (cursor === undefined && result.ok) {
    io.dispatchReply({ type: 'firstPageLoaded', paths: result.comments.map((c) => c.path) })
  }
  if (!result.ok && result.kind === 'coldKeys') io.onColdKeys(io.liveReply())
}

export const SEND_ERRORS: Record<Exclude<SubmitResult, { ok: true }>['kind'], string> = {
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
  parentGone: TARGET_GONE_MESSAGE,
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

/** The comment a send left unanswered, with what it came from. */
export interface PendingReply {
  readonly sealed: SealedComment
  readonly text: string
  readonly replyTo: string | null
}

export async function sendReply(
  io: Pick<ThreadIO, 'dispatchReply' | 'onColdKeys'> & { readonly reload: () => void },
  deps: {
    readonly context: ContextDeps
    readonly submit: SubmitDeps
    /** Sent again unchanged while the box still matches. */
    readonly pending: { current: PendingReply | null }
  },
  input: {
    readonly groupId: string
    readonly postId: string
    readonly replyTo: string | null
    readonly text: string
    /** The paths on screen, for the first guess at the new comment's number. */
    readonly loadedPaths: readonly string[]
  },
): Promise<void> {
  const { replyTo, text } = input
  io.dispatchReply({ type: 'sendStarted' })
  const again = deps.pending.current
  const resend = again?.text === text && again.replyTo === replyTo ? again.sealed : undefined
  if (resend === undefined) deps.pending.current = null
  const fail = (message: string) => {
    io.dispatchReply({ type: 'sendFailed', error: message })
  }
  const loaded = await loadSealContext(deps.context, input.groupId)
  if (!loaded.ok) {
    fail(CONTEXT_ERRORS[loaded.kind])
    return
  }
  const result = await submitComment(deps.submit, {
    groupId: input.groupId,
    postId: input.postId,
    context: loaded.context,
    text,
    firstPath: resend?.path ?? guessPath(attachParent(replyTo), input.loadedPaths),
    ...(resend !== undefined && { resend }),
  })
  if (result.ok) {
    deps.pending.current = null
    io.dispatchReply({ type: 'sent', notice: 'Comment sent.' })
    io.reload()
    return
  }
  deps.pending.current =
    result.kind === 'ambiguous' && result.sealed !== undefined
      ? { sealed: result.sealed, text, replyTo }
      : null
  fail(
    result.kind === 'rejected'
      ? (result.message ?? SEND_ERRORS.rejected)
      : SEND_ERRORS[result.kind],
  )
  if (result.kind === 'coldKeys') io.onColdKeys({ replyTo, draft: text })
  // The comment replied to is gone: show the thread as it is now.
  if (result.kind === 'parentGone') io.reload()
}

/** Seals again at most this many times for one press, after the group's key moved. */
export const MAX_REACTION_RESEALS = 2
/** Sends the same bytes again at most this many times after a write collision. */
export const MAX_REACTION_RETRIES = 3

export const REACTION_ERRORS = {
  authRequired: SEND_ERRORS.authRequired,
  notFound: SEND_ERRORS.notFound,
  behind: SEND_ERRORS.behind,
  dormant: SEND_ERRORS.dormant,
  coldKeys: 'This tab needs your password again to react.',
  unreadable:
    "Couldn't open this group's key, so the reaction was not saved. Reload the page and try again.",
  parentGone: 'The comment you reacted to is gone. The thread was reloaded.',
  reseal: 'The group changed while you were reacting. Try again.',
  busy: 'Others are reacting at the same moment. Try again.',
  failed: "Couldn't save your reaction. Try again.",
  removeFailed: "Couldn't take your reaction back. Try again.",
  rejected: 'The server rejected the reaction.',
} as const

type ReactionFailure = Exclude<
  keyof typeof REACTION_ERRORS,
  'coldKeys' | 'unreadable' | 'removeFailed'
>

/**
 * What an error from PUT or DELETE reaction means. `retry` is a write collision:
 * the same bytes go again. `reseal` is the group's key or the member's entry
 * having moved: load the context and seal again.
 */
export function classifyReactionError(err: unknown): ReactionFailure | 'retry' | 'reseal' {
  if (!(err instanceof ApiError) || err.status >= 500) return 'failed'
  if (err.status === 401) return 'authRequired'
  if (err.status === 404) return 'notFound'
  if (err.status === 409) {
    switch (err.code) {
      case 'conflict_retry':
        return 'retry'
      case 'generation_stale':
      case 'membership_changed':
      case 'key_epoch_stale':
        return 'reseal'
      case 'member_behind':
        return 'behind'
      case 'member_dormant':
        return 'dormant'
      case 'parent_gone':
        return 'parentGone'
    }
  }
  return 'rejected'
}

export interface ReactDeps {
  readonly userId: string
  readonly context: ContextDeps
  readonly sealReaction: (req: {
    readonly userId: string
    readonly groupId: string
    readonly postId: string
    readonly target: string
    readonly generation: number
    readonly reactionGeneration: number
    readonly wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
    readonly chain?: NonNullable<SealContext['chain']>
    readonly index: number
  }) => Promise<SealedReaction>
  readonly putReaction: (postId: string, target: string, req: PutReactionRequest) => Promise<void>
  readonly deleteReaction: (postId: string, target: string) => Promise<void>
}

/**
 * One press of reaction button `index` on `target` (the post's 0000, or a comment
 * path). `reactions` is what is on screen: the reader's own reaction on the
 * target decides whether this press sets a reaction (it differs, or there is
 * none) or takes it back (it is the same one). Never throws.
 */
export async function toggleReaction(
  io: Pick<ThreadIO, 'dispatch' | 'onColdKeys' | 'liveReply'> & { readonly reload: () => void },
  deps: ReactDeps,
  input: {
    readonly groupId: string
    readonly postId: string
    readonly target: string
    readonly index: number
    readonly reactions: readonly ReactionView[]
  },
): Promise<void> {
  const { target, index } = input
  const removing = summarizeReactions(input.reactions, target, deps.userId).mine === index
  io.dispatch({ type: 'reactionStarted', target })
  const fail = (message: string) => {
    io.dispatch({ type: 'reactionFailed', target, message })
  }
  const done = () => {
    io.dispatch(
      removing
        ? { type: 'reactionRemoved', target, reactorUserId: deps.userId }
        : { type: 'reactionSaved', target, reactorUserId: deps.userId, index },
    )
  }
  // Decides what a failed write means; returns true when the write should go again.
  const settle = (err: unknown, retries: number, reseals: number): 'again' | 'reseal' | 'stop' => {
    const kind = classifyReactionError(err)
    if (kind === 'retry') {
      if (retries < MAX_REACTION_RETRIES) return 'again'
      fail(REACTION_ERRORS.busy)
    } else if (kind === 'reseal') {
      if (!removing && reseals < MAX_REACTION_RESEALS) return 'reseal'
      fail(REACTION_ERRORS.reseal)
    } else if (kind === 'failed') {
      fail(removing ? REACTION_ERRORS.removeFailed : REACTION_ERRORS.failed)
    } else if (kind === 'rejected') {
      fail(err instanceof ApiError ? err.message : REACTION_ERRORS.rejected)
    } else if (kind === 'parentGone') {
      // The comment reacted to is gone: say so for the page (its own row is about
      // to disappear), then show the thread as it is now.
      io.dispatch({ type: 'reactionTargetGone', target, message: REACTION_ERRORS.parentGone })
      io.reload()
    } else {
      fail(REACTION_ERRORS[kind])
    }
    return 'stop'
  }

  if (removing) {
    for (let retries = 0; ; retries++) {
      try {
        await deps.deleteReaction(input.postId, target)
        done()
        return
      } catch (err) {
        if (settle(err, retries, 0) === 'stop') return
      }
    }
  }

  for (let reseals = 0; ; reseals++) {
    const loaded = await loadSealContext(deps.context, input.groupId)
    if (!loaded.ok) {
      fail(CONTEXT_ERRORS[loaded.kind])
      return
    }
    let sealed: SealedReaction
    try {
      sealed = await deps.sealReaction({
        userId: deps.userId,
        groupId: input.groupId,
        postId: input.postId,
        target,
        generation: loaded.context.generation,
        reactionGeneration: loaded.context.commentGeneration,
        wrappedGroupKey: loaded.context.wrappedGroupKey,
        ...(loaded.context.chain !== undefined && { chain: loaded.context.chain }),
        index,
      })
    } catch (err) {
      if (isLiveKeysError(err)) {
        fail(REACTION_ERRORS.coldKeys)
        io.onColdKeys(io.liveReply())
      } else {
        fail(REACTION_ERRORS.unreadable)
      }
      return
    }
    // The same bytes go again after a collision: a resend is one reaction.
    for (let retries = 0; ; retries++) {
      try {
        await deps.putReaction(input.postId, target, {
          generation: sealed.generation,
          nonce: sealed.nonce,
          ciphertext: sealed.ciphertext,
        })
        done()
        return
      } catch (err) {
        const next = settle(err, retries, reseals)
        if (next === 'stop') return
        if (next === 'reseal') break
      }
    }
  }
}

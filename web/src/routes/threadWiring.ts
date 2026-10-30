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

import type { SealedComment } from '@/lib/crypto/worker-protocol'
import { TARGET_GONE_MESSAGE, type ReplyEvent } from './replyState'
import {
  attachParent,
  guessPath,
  loadSealContext,
  submitComment,
  type ContextDeps,
  type SubmitDeps,
  type SubmitResult,
} from './runCreateComment'
import type { ThreadPageResult } from './runLoadThread'
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

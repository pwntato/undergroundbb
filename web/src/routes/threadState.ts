// What the thread screen is showing -- #44. A reducer, so the paging rules are
// tested without a DOM (web/ has none). The screen sends `loadStarted` before a
// request and `pageLoaded` with its result.
//
// Paging rules:
//   - A cursor means there is more, whatever the page held. A page can be short
//     or empty and still carry one (the server stops a page at its read limit),
//     so "no comments here" is never the end of a thread; only a missing cursor is.
//   - A comment already shown (same path), or repeated within one page, is
//     dropped, never shown twice, so a cursor served twice or an untrusted page
//     cannot duplicate it (two rows with one key would also confuse React).
//   - A failed page keeps what is already shown and the cursor it was loaded
//     with, so the same page can be asked for again.
//   - Reactions (#46) arrive with the comments they are on, so a page adds its
//     own. One per reactor per target: a repeat is dropped, the first kept, so a
//     page cannot override what this reader just did. What this reader does is
//     applied only after the server accepted it (reactionSaved / reactionRemoved),
//     never ahead of it.

import type { CommentView, ReactionView, ThreadPageResult } from './runLoadThread'

export interface ThreadState {
  readonly comments: readonly CommentView[]
  /** Where the next page starts; undefined once the last page has been read. */
  readonly cursor: string | undefined
  readonly loading: boolean
  /** Why the last page failed, or null. */
  readonly failure: Extract<ThreadPageResult, { ok: false }>['kind'] | null
  readonly reactions: readonly ReactionView[]
  /** Targets whose reaction is being saved or taken back right now. */
  readonly reacting: readonly string[]
  /** Why the last reaction on `target` did not go through, or null. */
  readonly reactionError: { readonly target: string; readonly message: string } | null
}

export const INITIAL_THREAD_STATE: ThreadState = {
  comments: [],
  cursor: undefined,
  loading: true,
  failure: null,
  reactions: [],
  reacting: [],
  reactionError: null,
}

export type ThreadEvent =
  | { readonly type: 'loadStarted' }
  /** Start over from the first page, e.g. after a comment was added. */
  | { readonly type: 'reset' }
  | { readonly type: 'pageLoaded'; readonly result: ThreadPageResult }
  | { readonly type: 'reactionStarted'; readonly target: string }
  | { readonly type: 'reactionFailed'; readonly target: string; readonly message: string }
  /** The server accepted this reader's reaction (set, or changed to another). */
  | {
      readonly type: 'reactionSaved'
      readonly target: string
      readonly reactorUserId: string
      readonly index: number
    }
  /** The server accepted taking this reader's reaction back. */
  | {
      readonly type: 'reactionRemoved'
      readonly target: string
      readonly reactorUserId: string
    }

export function nextThreadState(state: ThreadState, event: ThreadEvent): ThreadState {
  if (event.type === 'reset') return INITIAL_THREAD_STATE
  if (event.type === 'loadStarted') return { ...state, loading: true, failure: null }
  if (event.type === 'reactionStarted') {
    return {
      ...state,
      reacting: state.reacting.includes(event.target)
        ? state.reacting
        : [...state.reacting, event.target],
      reactionError: null,
    }
  }
  if (event.type === 'reactionFailed') {
    return {
      ...state,
      reacting: state.reacting.filter((t) => t !== event.target),
      reactionError: { target: event.target, message: event.message },
    }
  }
  if (event.type === 'reactionSaved' || event.type === 'reactionRemoved') {
    const others = state.reactions.filter(
      (x) => !(x.target === event.target && x.reactorUserId === event.reactorUserId),
    )
    return {
      ...state,
      reactions:
        event.type === 'reactionSaved'
          ? [
              ...others,
              { target: event.target, reactorUserId: event.reactorUserId, index: event.index },
            ]
          : others,
      reacting: state.reacting.filter((t) => t !== event.target),
      reactionError: null,
    }
  }
  const { result } = event
  if (!result.ok) return { ...state, loading: false, failure: result.kind }
  // A path is added as it is kept, so a repeat inside one page is dropped too.
  const seen = new Set(state.comments.map((c) => c.path))
  const fresh = result.comments.filter((c) => {
    if (seen.has(c.path)) return false
    seen.add(c.path)
    return true
  })
  const have = new Set(state.reactions.map(reactionKey))
  const freshReactions = result.reactions.filter((x) => {
    const key = reactionKey(x)
    if (have.has(key)) return false
    have.add(key)
    return true
  })
  return {
    ...state,
    comments: [...state.comments, ...fresh],
    reactions: [...state.reactions, ...freshReactions],
    cursor: result.nextCursor,
    loading: false,
    failure: null,
  }
}

function reactionKey(x: ReactionView): string {
  return `${x.target}|${x.reactorUserId}`
}

/** Another try can fix these; the rest need a login or mean the thread is gone. */
export function canRetryFailure(failure: ThreadState['failure']): boolean {
  return failure === 'failed' || failure === 'chain'
}

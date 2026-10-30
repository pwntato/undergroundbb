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

import type { CommentView, ThreadPageResult } from './runLoadThread'

export interface ThreadState {
  readonly comments: readonly CommentView[]
  /** Where the next page starts; undefined once the last page has been read. */
  readonly cursor: string | undefined
  readonly loading: boolean
  /** Why the last page failed, or null. */
  readonly failure: Extract<ThreadPageResult, { ok: false }>['kind'] | null
}

export const INITIAL_THREAD_STATE: ThreadState = {
  comments: [],
  cursor: undefined,
  loading: true,
  failure: null,
}

export type ThreadEvent =
  | { readonly type: 'loadStarted' }
  | { readonly type: 'pageLoaded'; readonly result: ThreadPageResult }

export function nextThreadState(state: ThreadState, event: ThreadEvent): ThreadState {
  if (event.type === 'loadStarted') return { ...state, loading: true, failure: null }
  const { result } = event
  if (!result.ok) return { ...state, loading: false, failure: result.kind }
  // A path is added as it is kept, so a repeat inside one page is dropped too.
  const seen = new Set(state.comments.map((c) => c.path))
  const fresh = result.comments.filter((c) => {
    if (seen.has(c.path)) return false
    seen.add(c.path)
    return true
  })
  return {
    comments: [...state.comments, ...fresh],
    cursor: result.nextCursor,
    loading: false,
    failure: null,
  }
}

/** Another try can fix these; the rest need a login or mean the thread is gone. */
export function canRetryFailure(failure: ThreadState['failure']): boolean {
  return failure === 'failed' || failure === 'chain'
}

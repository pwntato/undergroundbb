// What the Edit and Delete controls on a comment are doing -- #45. A reducer, so
// the rules are tested without a DOM (web/ has none).
//
//   - One thing at a time: editing one comment, or asking to delete one, or
//     nothing. Opening another replaces it (an edit draft is dropped with it).
//   - Nothing opens or changes while a send is in flight.
//   - A failure keeps the form open with its draft and says why; typing or
//     closing drops the message, since it was about something else.
//   - Success closes the form.
//   - When the first page of the thread (re)loads and the comment being edited or
//     deleted is not a live one on it and there is no later page, or when the last page
//     is reached without it (someone deleted it), the form closes. While later pages
//     exist the form stays and the screen loads them to find its comment (#328).
//   - A write the server answers 404 for means the post is gone for writing (it
//     was deleted, or the reader left the group): the thread turns read-only,
//     which hides Edit. Delete stays: an author may still delete their own comment.

export type ControlMode =
  | { readonly kind: 'idle' }
  | {
      readonly kind: 'editing'
      readonly path: string
      readonly draft: string
      readonly original: string
    }
  | { readonly kind: 'confirmDelete'; readonly path: string }

export interface ControlsState {
  readonly mode: ControlMode
  readonly busy: boolean
  readonly error: string | null
  /** The error says the item the form is about is gone (see `firstPageFailed`). */
  readonly gone: boolean
  readonly readOnly: boolean
}

export const INITIAL_CONTROLS_STATE: ControlsState = {
  mode: { kind: 'idle' },
  busy: false,
  error: null,
  gone: false,
  readOnly: false,
}

export type ControlsEvent =
  | { readonly type: 'editOpened'; readonly path: string; readonly text: string }
  | { readonly type: 'draftEdited'; readonly draft: string }
  | { readonly type: 'deleteAsked'; readonly path: string }
  | { readonly type: 'closed' }
  | { readonly type: 'started' }
  | { readonly type: 'failed'; readonly message: string; readonly gone?: boolean }
  | { readonly type: 'finished' }
  | { readonly type: 'madeReadOnly'; readonly message: string | null }
  /**
   * The first page of the thread was loaded; `livePaths` are its comments that are not deleted.
   * `hasMore`: more pages exist, so a comment not on this one may still be on a later one.
   */
  | {
      readonly type: 'firstPageLoaded'
      readonly livePaths: readonly string[]
      readonly hasMore: boolean
    }
  /** The last page is loaded; `livePaths` are every comment on screen that is not deleted. */
  | { readonly type: 'endReached'; readonly livePaths: readonly string[] }
  /** The first page could not be loaded: the comments the form hangs on are gone from the screen. */
  | { readonly type: 'firstPageFailed' }

export function nextControlsState(state: ControlsState, event: ControlsEvent): ControlsState {
  switch (event.type) {
    case 'editOpened':
      if (state.busy || state.readOnly) return state
      return {
        ...state,
        mode: { kind: 'editing', path: event.path, draft: event.text, original: event.text },
        error: null,
        gone: false,
      }
    case 'draftEdited':
      if (state.busy || state.mode.kind !== 'editing') return state
      return { ...state, mode: { ...state.mode, draft: event.draft }, error: null, gone: false }
    case 'deleteAsked':
      if (state.busy) return state
      return {
        ...state,
        mode: { kind: 'confirmDelete', path: event.path },
        error: null,
        gone: false,
      }
    case 'closed':
      if (state.busy) return state
      return { ...state, mode: { kind: 'idle' }, error: null, gone: false }
    case 'started':
      return { ...state, busy: true, error: null, gone: false }
    case 'failed':
      return { ...state, busy: false, error: event.message, gone: event.gone === true }
    case 'finished':
      return { ...state, mode: { kind: 'idle' }, busy: false, error: null, gone: false }
    case 'madeReadOnly':
      return {
        ...state,
        mode: { kind: 'idle' },
        busy: false,
        readOnly: true,
        error: event.message,
        gone: false,
      }
    case 'firstPageLoaded':
      // A comment not on this page may be on a later one (a form restored after the password
      // step can hang on one): the screen loads on, and `endReached` closes it if it never shows.
      if (
        state.busy ||
        state.mode.kind === 'idle' ||
        event.hasMore ||
        event.livePaths.includes(state.mode.path)
      ) {
        return state
      }
      // The error stays: it may be the very reason the comment is gone.
      return { ...state, mode: { kind: 'idle' } }
    case 'endReached':
      if (state.busy || state.mode.kind === 'idle' || event.livePaths.includes(state.mode.path)) {
        return state
      }
      return { ...state, mode: { kind: 'idle' } }
    case 'firstPageFailed':
      // The form is drawn inside the comment it is about, and a reload empties the thread
      // first, so a form left open would be invisible and stuck. Close it, keep the error.
      // Only a form whose error says the item is gone is closed. A reload that something else
      // caused (a sent reply, say) must not throw away a draft being typed, even when an older,
      // unrelated error is still showing; when the retry works, `firstPageLoaded` puts a form
      // whose item is still live back.
      if (state.busy || state.mode.kind === 'idle' || !state.gone) return state
      return { ...state, mode: { kind: 'idle' } }
  }
}

/**
 * Whether the reply box is offered: not when the thread itself failed as "not
 * found", and not once a write showed the post is gone for writing.
 */
export function replyOffered(failure: string | null, readOnly: boolean): boolean {
  return failure !== 'notFound' && !readOnly
}

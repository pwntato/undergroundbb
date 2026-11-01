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
//     deleted is no longer a live one on it (someone deleted it), the form closes.
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
  readonly readOnly: boolean
}

export const INITIAL_CONTROLS_STATE: ControlsState = {
  mode: { kind: 'idle' },
  busy: false,
  error: null,
  readOnly: false,
}

export type ControlsEvent =
  | { readonly type: 'editOpened'; readonly path: string; readonly text: string }
  | { readonly type: 'draftEdited'; readonly draft: string }
  | { readonly type: 'deleteAsked'; readonly path: string }
  | { readonly type: 'closed' }
  | { readonly type: 'started' }
  | { readonly type: 'failed'; readonly message: string }
  | { readonly type: 'finished' }
  | { readonly type: 'madeReadOnly'; readonly message: string }
  /** The first page of the thread was loaded; `livePaths` are its comments that are not deleted. */
  | { readonly type: 'firstPageLoaded'; readonly livePaths: readonly string[] }

export function nextControlsState(state: ControlsState, event: ControlsEvent): ControlsState {
  switch (event.type) {
    case 'editOpened':
      if (state.busy || state.readOnly) return state
      return {
        ...state,
        mode: { kind: 'editing', path: event.path, draft: event.text, original: event.text },
        error: null,
      }
    case 'draftEdited':
      if (state.busy || state.mode.kind !== 'editing') return state
      return { ...state, mode: { ...state.mode, draft: event.draft }, error: null }
    case 'deleteAsked':
      if (state.busy) return state
      return { ...state, mode: { kind: 'confirmDelete', path: event.path }, error: null }
    case 'closed':
      if (state.busy) return state
      return { ...state, mode: { kind: 'idle' }, error: null }
    case 'started':
      return { ...state, busy: true, error: null }
    case 'failed':
      return { ...state, busy: false, error: event.message }
    case 'finished':
      return { ...state, mode: { kind: 'idle' }, busy: false, error: null }
    case 'madeReadOnly':
      return { ...state, mode: { kind: 'idle' }, busy: false, readOnly: true, error: event.message }
    case 'firstPageLoaded':
      if (state.busy || state.mode.kind === 'idle' || event.livePaths.includes(state.mode.path)) {
        return state
      }
      // The error stays: it may be the very reason the comment is gone.
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

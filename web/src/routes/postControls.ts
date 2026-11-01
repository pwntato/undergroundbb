// What the Edit and Delete controls on a post are doing -- #45. A reducer, so the
// rules are tested without a DOM (web/ has none). The same rules as
// commentControls.ts, for a form with a title and a body:
//
//   - One thing at a time: editing one post, or asking to delete one, or nothing.
//     Opening another replaces it (an edit draft is dropped with it).
//   - Nothing opens or changes while a send is in flight.
//   - A failure keeps the form open with its draft and says why; typing or
//     closing drops the message, since it was about something else.
//   - Success closes the form.
//   - When the first page of the list (re)loads and the post being edited or
//     deleted is no longer a live one on it (someone deleted it), the form
//     closes; the error stays, since it may be the very reason.

export type PostControlMode =
  | { readonly kind: 'idle' }
  | {
      readonly kind: 'editing'
      readonly sortKey: string
      /** What the form was opened with; the form holds the draft itself. */
      readonly title: string
      readonly body: string
    }
  | { readonly kind: 'confirmDelete'; readonly sortKey: string }

export interface PostControlsState {
  readonly mode: PostControlMode
  readonly busy: boolean
  readonly error: string | null
}

export const INITIAL_POST_CONTROLS_STATE: PostControlsState = {
  mode: { kind: 'idle' },
  busy: false,
  error: null,
}

export type PostControlsEvent =
  | {
      readonly type: 'editOpened'
      readonly sortKey: string
      readonly title: string
      readonly body: string
    }
  | { readonly type: 'closed' }
  | { readonly type: 'deleteAsked'; readonly sortKey: string }
  | { readonly type: 'started' }
  | { readonly type: 'failed'; readonly message: string }
  | { readonly type: 'finished' }
  /** The first page of the list was loaded; `liveKeys` are its posts that are not deleted. */
  | { readonly type: 'firstPageLoaded'; readonly liveKeys: readonly string[] }
  /** The first page could not be loaded: the posts the form hangs on are gone from the screen. */
  | { readonly type: 'firstPageFailed' }

export function nextPostControlsState(
  state: PostControlsState,
  event: PostControlsEvent,
): PostControlsState {
  switch (event.type) {
    case 'editOpened':
      if (state.busy) return state
      return {
        ...state,
        mode: { kind: 'editing', sortKey: event.sortKey, title: event.title, body: event.body },
        error: null,
      }
    case 'deleteAsked':
      if (state.busy) return state
      return { ...state, mode: { kind: 'confirmDelete', sortKey: event.sortKey }, error: null }
    case 'closed':
      if (state.busy) return state
      return { ...state, mode: { kind: 'idle' }, error: null }
    case 'started':
      return { ...state, busy: true, error: null }
    case 'failed':
      return { ...state, busy: false, error: event.message }
    case 'finished':
      return { mode: { kind: 'idle' }, busy: false, error: null }
    case 'firstPageLoaded':
      if (state.busy || state.mode.kind === 'idle' || event.liveKeys.includes(state.mode.sortKey)) {
        return state
      }
      return { ...state, mode: { kind: 'idle' } }
    case 'firstPageFailed':
      // The form is drawn inside the post it is about, and a reload empties the list
      // first, so a form left open would be invisible and stuck. Close it, keep the error.
      if (state.busy || state.mode.kind === 'idle') return state
      return { ...state, mode: { kind: 'idle' } }
  }
}

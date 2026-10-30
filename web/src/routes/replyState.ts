// What the reply box is doing -- #44. A reducer, so the rules are tested without
// a DOM (web/ has none).
//
//   - One box is open at a time: under the comment being replied to, or at the
//     bottom for a new top-level comment (`replyTo` null). There is one draft,
//     so moving the box to another comment keeps what was typed.
//   - Editing the text or moving the box drops the last error, since it was
//     about something else.
//   - A send that succeeds clears the draft and closes the inline box.
//   - The comment being replied to must be on the page. When the first page of
//     the thread (re)loads and the target is not in it -- the comment was deleted,
//     or a reply restored after the password step points at one on a later page --
//     the target is dropped, the draft is kept, and the box says it is now a new
//     comment. Otherwise the bottom box would be labelled as a new comment while
//     still sealing under the missing one, and fail the same way every time.

export interface ReplyState {
  /** The path being replied to, or null for a new top-level comment. */
  readonly replyTo: string | null
  readonly draft: string
  readonly sending: boolean
  readonly error: string | null
  /** Shown after a send went through. */
  readonly notice: string | null
}

export const INITIAL_REPLY_STATE: ReplyState = {
  replyTo: null,
  draft: '',
  sending: false,
  error: null,
  notice: null,
}

export type ReplyEvent =
  | { readonly type: 'opened'; readonly replyTo: string | null }
  | { readonly type: 'edited'; readonly draft: string }
  | { readonly type: 'sendStarted' }
  | { readonly type: 'sendFailed'; readonly error: string }
  | { readonly type: 'sent'; readonly notice: string }
  /** The first page of the thread was loaded; `paths` are all the comments on screen. */
  | { readonly type: 'firstPageLoaded'; readonly paths: readonly string[] }

export const TARGET_GONE_MESSAGE =
  'The comment you were replying to is no longer here, so your reply will go in as a new comment at the bottom.'

export function nextReplyState(state: ReplyState, event: ReplyEvent): ReplyState {
  switch (event.type) {
    case 'opened':
      // Not while a send is in flight: the box it came from would move under it.
      if (state.sending) return state
      return { ...state, replyTo: event.replyTo, error: null, notice: null }
    case 'edited':
      if (state.sending) return state
      return { ...state, draft: event.draft, error: null, notice: null }
    case 'sendStarted':
      return { ...state, sending: true, error: null, notice: null }
    case 'sendFailed':
      return { ...state, sending: false, error: event.error }
    case 'firstPageLoaded':
      if (state.sending || state.replyTo === null || event.paths.includes(state.replyTo)) {
        return state
      }
      return { ...state, replyTo: null, error: TARGET_GONE_MESSAGE }
    case 'sent':
      return { replyTo: null, draft: '', sending: false, error: null, notice: event.notice }
  }
}

// What the reply box is doing -- #44. A reducer, so the rules are tested without
// a DOM (web/ has none).
//
//   - One box is open at a time: under the comment being replied to, or at the
//     bottom for a new top-level comment (`replyTo` null). There is one draft,
//     so moving the box to another comment keeps what was typed.
//   - Editing the text or moving the box drops the last error, since it was
//     about something else.
//   - A send that succeeds clears the draft and closes the inline box.
//   - The comment being replied to must be on the page. When the thread's last page is
//     loaded and the target is not on screen -- the comment was deleted -- the target is
//     dropped, the draft is kept, and the box says it is now a new comment. Otherwise the
//     bottom box would be labelled as a new comment while still sealing under the missing
//     one, and fail the same way every time.
//   - A target missing from a first page that has a later page is not gone yet (a reply
//     restored after the password step can point at one): the screen loads on until it
//     shows, and only the last page without it drops it (#330). Meanwhile the bottom box
//     cannot send (replyFallbackBox.ts).

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
  | {
      readonly type: 'firstPageLoaded'
      readonly paths: readonly string[]
      /** A later page exists, so a target missing from this one may still be on it. */
      readonly hasMore: boolean
    }
  /** The last page is loaded; `paths` are all the comments on screen. */
  | { readonly type: 'endReached'; readonly paths: readonly string[] }

/** The server refused the signing day: this device's clock is off, or the write was sealed too long ago. */
export const CLOCK_SKEW_MESSAGE =
  "This device's date or time looks wrong, or this was prepared too long ago. Check the date and time on this device, then try again."

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
      // A target not on this page may be on a later one: the screen loads on (formSeek.ts),
      // and `endReached` drops it if it never shows (#330).
      if (
        state.sending ||
        state.replyTo === null ||
        event.hasMore ||
        event.paths.includes(state.replyTo)
      ) {
        return state
      }
      return { ...state, replyTo: null, error: TARGET_GONE_MESSAGE }
    case 'endReached':
      if (state.sending || state.replyTo === null || event.paths.includes(state.replyTo)) {
        return state
      }
      return { ...state, replyTo: null, error: TARGET_GONE_MESSAGE }
    case 'sent':
      return { replyTo: null, draft: '', sending: false, error: null, notice: event.notice }
  }
}

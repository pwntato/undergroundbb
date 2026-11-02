// An edit form open when the password step interrupts -- #319. The password step
// unmounts the screen, and a screen that comes back starts fresh, so what was typed
// into an open edit form was lost. The parent screen keeps a snapshot of the open
// edit forms from the moment it asks for the password and hands it to the screen
// that remounts, which starts with those forms open and filled, as it already does
// for a reply in the box (threadWiring.ts's SavedReply).
//
//   - Only an edit form being filled is kept. Nothing else is worth restoring (a
//     delete question is one press away) and nothing sent is kept: a snapshot is
//     replaced on every ask, with nothing when no form was open, so an edit that
//     was saved is never brought back.
//   - A snapshot belongs to one screen's subject (a post's thread, a group's list)
//     and is not used for any other.
//   - It is the form's mode alone, never a busy or error state: the screen that
//     comes back is idle. Whether what it hangs on is still there is the screen's
//     own check when its first page loads (the reducers' `firstPageLoaded`), which
//     closes a form whose comment or post was deleted meanwhile.

import { INITIAL_CONTROLS_STATE, type ControlMode, type ControlsState } from './commentControls'
import {
  INITIAL_POST_CONTROLS_STATE,
  type PostControlMode,
  type PostControlsState,
} from './postControls'

type Editing<M extends { readonly kind: string }> = Extract<M, { readonly kind: 'editing' }>

export interface SavedEdits {
  /** What the forms hang on: a thread's post id, or a list's group id. */
  readonly scope: string
  readonly comment?: Editing<ControlMode>
  readonly post?: Editing<PostControlMode>
}

/** The open edit forms, or undefined when there are none. */
export function snapshotEdits(
  scope: string,
  comment: ControlMode | undefined,
  post: PostControlMode,
): SavedEdits | undefined {
  const c = comment?.kind === 'editing' ? comment : undefined
  const p = post.kind === 'editing' ? post : undefined
  if (c === undefined && p === undefined) return undefined
  return { scope, ...(c !== undefined && { comment: c }), ...(p !== undefined && { post: p }) }
}

/** The comment controls a remounted thread starts with. */
export function restoredCommentControls(
  saved: SavedEdits | undefined,
  scope: string,
): ControlsState {
  return saved?.scope === scope && saved.comment !== undefined
    ? { ...INITIAL_CONTROLS_STATE, mode: saved.comment }
    : INITIAL_CONTROLS_STATE
}

/** The post controls a remounted thread or list starts with. */
export function restoredPostControls(
  saved: SavedEdits | undefined,
  scope: string,
): PostControlsState {
  return saved?.scope === scope && saved.post !== undefined
    ? { ...INITIAL_POST_CONTROLS_STATE, mode: saved.post }
    : INITIAL_POST_CONTROLS_STATE
}

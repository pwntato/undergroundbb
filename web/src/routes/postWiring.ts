// The two async bodies Edit and Delete on a post run, pulled out of the screen so
// they can be tested without a DOM (web/ has none) -- #45. Plain functions over
// injected dispatchers and deps, like threadWiring.ts's saveEdit / confirmDelete.
//
//   - saveEditPost: one press of Save on the edit form. An edit a send left
//     unanswered goes again as the exact same bytes while the form still holds the
//     same text; a deleted post reloads the list.
//   - confirmDeletePost: one press of Delete on the confirmation. Deleting is safe
//     to repeat (a tombstone answers the same 204), so a failure with no clear
//     answer is simply tried again.

import { ApiError } from '@/lib/api/auth'
import type { SealedPostEdit } from '@/lib/crypto/worker-protocol'
import type { PostControlsEvent } from './postControls'
import { CLOCK_SKEW_MESSAGE } from './replyState'
import type { EditFailure } from './runEdit'
import { submitPostEdit, type EditPostDeps } from './runEditPost'

export interface PostControlsIO {
  readonly dispatchControls: (event: PostControlsEvent) => void
  /** Reads the list again from its first page. */
  readonly reload: () => void
  /** The password step is needed. */
  readonly onColdKeys: () => void
}

export const POST_EDIT_ERRORS: Record<EditFailure, string> = {
  authRequired: 'Your session has expired. Log in again and retry.',
  notFound: 'This post no longer exists, or you are no longer a member of its group.',
  behind:
    'Your key for this group is behind. Wait for the key rotation to reach you, then try again.',
  dormant:
    'You rotated your keys and an admin has not approved them for this group yet. Ask an admin to approve you from Members.',
  coldKeys: 'This tab needs your password again to edit a post.',
  unreadable:
    "Couldn't open this group's key, so the edit was not sent. Reload the page and try again.",
  failed: "Couldn't load this group. Try again.",
  gone: 'This post was deleted, so it can no longer be edited.',
  busy: 'Others are changing this post at the same moment. Press Save again.',
  clockSkew: CLOCK_SKEW_MESSAGE,
  rejected: 'The server rejected the edit.',
  ambiguous:
    "We couldn't confirm whether the edit was saved. Press Save again to send the same edit; it will not be applied twice.",
}

/** An edit a send left unanswered, with what it came from. */
export interface PendingPostEdit {
  readonly sealed: SealedPostEdit
  readonly sortKey: string
  readonly title: string
  readonly body: string
}

export async function saveEditPost(
  io: PostControlsIO,
  deps: { readonly edit: EditPostDeps; readonly pending: { current: PendingPostEdit | null } },
  input: {
    readonly groupId: string
    readonly postId: string
    readonly sortKey: string
    readonly title: string
    readonly body: string
    /** The post's original write time, kept by the edit. */
    readonly at: string
  },
): Promise<void> {
  io.dispatchControls({ type: 'started' })
  const again = deps.pending.current
  const resend =
    again?.sortKey === input.sortKey && again.title === input.title && again.body === input.body
      ? again.sealed
      : undefined
  if (resend === undefined) deps.pending.current = null
  const result = await submitPostEdit(deps.edit, {
    ...input,
    ...(resend !== undefined && { resend }),
  })
  if (result.ok) {
    deps.pending.current = null
    io.dispatchControls({ type: 'finished' })
    io.reload()
    return
  }
  deps.pending.current =
    result.kind === 'ambiguous' && result.sealed !== undefined
      ? { sealed: result.sealed, sortKey: input.sortKey, title: input.title, body: input.body }
      : null
  io.dispatchControls({
    type: 'failed',
    message:
      result.kind === 'rejected'
        ? (result.message ?? POST_EDIT_ERRORS.rejected)
        : POST_EDIT_ERRORS[result.kind],
    gone: result.kind === 'gone',
  })
  if (result.kind === 'coldKeys') io.onColdKeys()
  // The post was deleted meanwhile: show the list as it is now.
  if (result.kind === 'gone') io.reload()
}

export const POST_DELETE_ERRORS = {
  authRequired: POST_EDIT_ERRORS.authRequired,
  gone: 'This post is gone.',
  failed: "Couldn't delete the post. Try again.",
} as const

export async function confirmDeletePost(
  io: Pick<PostControlsIO, 'dispatchControls' | 'reload'>,
  deps: { readonly deletePost: (postId: string) => Promise<void> },
  input: { readonly postId: string },
): Promise<void> {
  io.dispatchControls({ type: 'started' })
  try {
    await deps.deletePost(input.postId)
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      io.dispatchControls({ type: 'failed', message: POST_DELETE_ERRORS.authRequired })
    } else if (err instanceof ApiError && err.status === 404) {
      io.dispatchControls({ type: 'failed', message: POST_DELETE_ERRORS.gone, gone: true })
      io.reload()
    } else if (err instanceof ApiError && err.status === 403) {
      io.dispatchControls({ type: 'failed', message: err.message })
    } else {
      io.dispatchControls({ type: 'failed', message: POST_DELETE_ERRORS.failed })
    }
    return
  }
  io.dispatchControls({ type: 'finished' })
  io.reload()
}

// What the thread page does with the post it hangs on -- #318. The post is read on
// its own (GET /api/posts/{pid}) so the page can show it and offer Edit and Delete
// with the same controls as the list. Plain functions over injected setters, so the
// rules are tested without a DOM (web/ has none).
//
//   - A post that loads becomes the one on screen. The form open on it (the post
//     controls, postControls.ts) is told whether the post is still live, exactly as
//     the list tells it about its first page.
//   - A post that is gone (a tombstone) makes the thread read-only at once: nothing
//     new can be added to it, so the reply box goes and the reaction buttons stop,
//     as they would after the server refused the first attempt.
//   - A post that cannot be loaded leaves the thread as it was, with a line saying
//     why Edit and Delete are missing.

import type { ControlsEvent } from './commentControls'
import type { PostControlsEvent } from './postControls'
import { isDeletedPost, type PostEntry, type PostResult } from './runListPosts'

export const POST_PROBLEMS = {
  authRequired: 'Your session has expired. Log in again and retry.',
  coldKeys: 'This tab needs your password again to read this post.',
  chain: "Couldn't read this group's older keys, so the post can't be opened. Reload to try again.",
  failed: "Couldn't load the post itself, so Edit and Delete are not shown. Reload to try again.",
} as const

export interface ThreadPostIO {
  readonly setPost: (post: PostEntry | null) => void
  readonly setProblem: (message: string | null) => void
  readonly dispatchPostControls: (event: PostControlsEvent) => void
  readonly dispatchControls: (event: ControlsEvent) => void
  /** The password step is needed. */
  readonly onColdKeys: () => void
}

/** Applies one load of the post. `notFound` is left to the comments, which say it already. */
export function applyPostResult(io: ThreadPostIO, result: PostResult): void {
  if (result.ok) {
    io.setPost(result.post)
    io.setProblem(null)
    io.dispatchPostControls({
      type: 'firstPageLoaded',
      liveKeys: isDeletedPost(result.post) ? [] : [result.post.sortKey],
    })
    if (isDeletedPost(result.post)) io.dispatchControls({ type: 'madeReadOnly', message: null })
    return
  }
  io.setPost(null)
  io.dispatchPostControls({ type: 'firstPageFailed' })
  if (result.kind === 'notFound') {
    io.setProblem(null)
    return
  }
  io.setProblem(POST_PROBLEMS[result.kind])
  if (result.kind === 'coldKeys') io.onColdKeys()
}

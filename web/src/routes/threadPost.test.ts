import { describe, expect, it, vi } from 'vitest'
import type { ControlsEvent } from './commentControls'
import type { PostControlsEvent } from './postControls'
import type { DeletedPostView, PostView } from './runListPosts'
import { applyPostResult, POST_PROBLEMS, type ThreadPostIO } from './threadPost'

const LIVE = { sortKey: 'POST#2026-10-28#0000000000000001' } as unknown as PostView
const GONE: DeletedPostView = { deleted: true, sortKey: LIVE.sortKey, day: '2026-10-28' }

function io() {
  const postEvents: PostControlsEvent[] = []
  const threadEvents: ControlsEvent[] = []
  const fake = {
    setPost: vi.fn(),
    setProblem: vi.fn(),
    dispatchPostControls: (e: PostControlsEvent) => postEvents.push(e),
    dispatchControls: (e: ControlsEvent) => threadEvents.push(e),
    onColdKeys: vi.fn(),
  } satisfies ThreadPostIO
  return { fake, postEvents, threadEvents }
}

describe('applyPostResult', () => {
  it('shows a post that loaded, clears any problem, and tells the open form the post is live', () => {
    const { fake, postEvents, threadEvents } = io()
    applyPostResult(fake, { ok: true, post: LIVE })
    expect(fake.setPost).toHaveBeenCalledWith(LIVE)
    expect(fake.setProblem).toHaveBeenCalledWith(null)
    expect(postEvents).toEqual([{ type: 'firstPageLoaded', liveKeys: [LIVE.sortKey] }])
    expect(threadEvents).toEqual([])
  })

  it('makes the thread read-only, silently, when the post is deleted, and closes a form open on it', () => {
    const { fake, postEvents, threadEvents } = io()
    applyPostResult(fake, { ok: true, post: GONE })
    expect(fake.setPost).toHaveBeenCalledWith(GONE)
    expect(postEvents).toEqual([{ type: 'firstPageLoaded', liveKeys: [] }])
    expect(threadEvents).toEqual([{ type: 'madeReadOnly', message: null }])
  })

  it('words each failure, drops the post, and closes only a form that was about a gone post', () => {
    for (const kind of ['authRequired', 'chain', 'failed'] as const) {
      const { fake, postEvents, threadEvents } = io()
      applyPostResult(fake, { ok: false, kind })
      expect(fake.setPost).toHaveBeenCalledWith(null)
      expect(fake.setProblem).toHaveBeenCalledWith(POST_PROBLEMS[kind])
      expect(postEvents).toEqual([{ type: 'firstPageFailed' }])
      expect(threadEvents).toEqual([])
      expect(fake.onColdKeys).not.toHaveBeenCalled()
    }
  })

  it('asks for the password on cold keys', () => {
    const { fake } = io()
    applyPostResult(fake, { ok: false, kind: 'coldKeys' })
    expect(fake.setProblem).toHaveBeenCalledWith(POST_PROBLEMS.coldKeys)
    expect(fake.onColdKeys).toHaveBeenCalledTimes(1)
  })

  it('leaves a missing post to the comments, which already say so', () => {
    const { fake } = io()
    applyPostResult(fake, { ok: false, kind: 'notFound' })
    expect(fake.setPost).toHaveBeenCalledWith(null)
    expect(fake.setProblem).toHaveBeenCalledWith(null)
    expect(fake.onColdKeys).not.toHaveBeenCalled()
  })
})

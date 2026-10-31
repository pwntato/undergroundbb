import { describe, expect, it } from 'vitest'
import {
  canRetryFailure,
  INITIAL_THREAD_STATE,
  nextThreadState,
  type ThreadState,
} from './threadState'
import type { CommentView, ThreadPageResult } from './runLoadThread'

const view = (path: string): CommentView => ({
  path,
  depth: path.split('.').length,
  authorUserId: 'u',
  authorName: 'alice',
  signedDay: '2026-10-29',
  content: { kind: 'opened', text: path, at: '2026-10-29T00:00:00.000Z', timeSuspect: false },
  signature: { kind: 'valid' },
})

const page = (paths: string[], nextCursor?: string): ThreadPageResult => ({
  ok: true,
  comments: paths.map(view),
  reactions: [],
  ...(nextCursor !== undefined && { nextCursor }),
})

const apply = (s: ThreadState, result: ThreadPageResult) =>
  nextThreadState(s, { type: 'pageLoaded', result })

describe('nextThreadState', () => {
  it('starts loading with nothing shown and no more to fetch', () => {
    expect(INITIAL_THREAD_STATE).toMatchObject({ comments: [], loading: true, failure: null })
    expect(INITIAL_THREAD_STATE.cursor).toBeUndefined()
  })

  it('appends pages in order and keeps the cursor of the latest', () => {
    let s = apply(INITIAL_THREAD_STATE, page(['0001', '0001.0001'], 'c1'))
    expect(s.cursor).toBe('c1')
    s = apply(nextThreadState(s, { type: 'loadStarted' }), page(['0002'], 'c2'))
    expect(s.comments.map((c) => c.path)).toEqual(['0001', '0001.0001', '0002'])
    expect([s.cursor, s.loading]).toEqual(['c2', false])
    s = apply(s, page(['0003']))
    expect(s.cursor).toBeUndefined()
  })

  it('keeps going past an empty page that carries a cursor', () => {
    const s = apply(INITIAL_THREAD_STATE, page([], 'more'))
    expect(s.comments).toEqual([])
    expect(s.cursor).toBe('more')
    expect(s.loading).toBe(false)
  })

  it('does not show a comment twice when a page is served again', () => {
    const first = apply(INITIAL_THREAD_STATE, page(['0001', '0002'], 'c1'))
    const again = apply(first, page(['0002', '0003']))
    expect(again.comments.map((c) => c.path)).toEqual(['0001', '0002', '0003'])
  })

  it('does not show a comment twice when one page repeats a path', () => {
    const s = apply(INITIAL_THREAD_STATE, page(['0001', '0001', '0002', '0001']))
    expect(s.comments.map((c) => c.path)).toEqual(['0001', '0002'])
  })

  it('marks a load as started and clears the last failure', () => {
    const failed = apply(INITIAL_THREAD_STATE, { ok: false, kind: 'failed' })
    expect(nextThreadState(failed, { type: 'loadStarted' })).toMatchObject({
      loading: true,
      failure: null,
    })
  })

  it('keeps what is shown and the cursor to ask again with when a page fails', () => {
    const s = apply(INITIAL_THREAD_STATE, page(['0001'], 'c1'))
    const failed = apply(nextThreadState(s, { type: 'loadStarted' }), { ok: false, kind: 'failed' })
    expect(failed.comments.map((c) => c.path)).toEqual(['0001'])
    expect([failed.cursor, failed.loading, failed.failure]).toEqual(['c1', false, 'failed'])
  })

  it('offers a retry only for failures another try can fix', () => {
    expect(canRetryFailure('failed')).toBe(true)
    expect(canRetryFailure('chain')).toBe(true)
    for (const f of ['notFound', 'authRequired', 'coldKeys', null] as const) {
      expect(canRetryFailure(f), String(f)).toBe(false)
    }
  })
})

describe('reset', () => {
  it('goes back to the first page, dropping comments, cursor and failure', () => {
    const loaded = nextThreadState(INITIAL_THREAD_STATE, {
      type: 'pageLoaded',
      result: page(['0001', '0002'], 'cur'),
    })
    expect(loaded.comments).toHaveLength(2)
    expect(nextThreadState(loaded, { type: 'reset' })).toEqual(INITIAL_THREAD_STATE)
  })
})

describe('reactions in the thread state (#46)', () => {
  const rx = (target: string, reactorUserId: string, index: number | null = 1) => ({
    target,
    reactorUserId,
    index,
  })
  const withReactions = (paths: string[], reactions: ReturnType<typeof rx>[], cursor?: string) =>
    ({ ...page(paths, cursor), reactions }) as ThreadPageResult

  it('starts with none and nothing in flight', () => {
    expect(INITIAL_THREAD_STATE).toMatchObject({ reactions: [], reacting: [], reactionError: null })
  })

  it('is loaded once a page has been read, even an empty one, and not before or after a reset', () => {
    expect(INITIAL_THREAD_STATE.loaded).toBe(false)
    const failed = apply(INITIAL_THREAD_STATE, { ok: false, kind: 'failed' })
    expect(failed.loaded).toBe(false)
    const empty = apply(INITIAL_THREAD_STATE, page([]))
    expect(empty.loaded).toBe(true)
    expect(nextThreadState(empty, { type: 'reset' }).loaded).toBe(false)
  })

  it("adds each page's reactions to those already shown, in order", () => {
    let s = apply(
      INITIAL_THREAD_STATE,
      withReactions(['0001'], [rx('0000', 'a'), rx('0001', 'a')], 'c'),
    )
    s = apply(s, withReactions(['0002'], [rx('0002', 'b', 3)]))
    expect(s.reactions).toEqual([rx('0000', 'a'), rx('0001', 'a'), rx('0002', 'b', 3)])
  })

  it('keeps the first of a repeated reactor on a target, within a page and across pages', () => {
    let s = apply(
      INITIAL_THREAD_STATE,
      withReactions(['0001'], [rx('0001', 'a', 1), rx('0001', 'a', 2)], 'c'),
    )
    s = apply(s, withReactions(['0002'], [rx('0001', 'a', 4), rx('0001', 'b', 5)]))
    expect(s.reactions).toEqual([rx('0001', 'a', 1), rx('0001', 'b', 5)])
  })

  it("keeps one reactor's reactions on different targets apart", () => {
    const s = apply(
      INITIAL_THREAD_STATE,
      withReactions(['0001'], [rx('0001', 'a'), rx('0000', 'a'), rx('0002', 'a')]),
    )
    expect(s.reactions).toHaveLength(3)
  })

  it('keeps the reactions when a page fails, and drops them on a reset', () => {
    let s = apply(INITIAL_THREAD_STATE, withReactions(['0001'], [rx('0001', 'a')], 'c'))
    s = apply(s, { ok: false, kind: 'failed' })
    expect(s.reactions).toHaveLength(1)
    expect(nextThreadState(s, { type: 'reset' })).toEqual(INITIAL_THREAD_STATE)
  })

  it('marks a target busy once, and clears any earlier error', () => {
    let s = nextThreadState(INITIAL_THREAD_STATE, {
      type: 'reactionFailed',
      target: '0001',
      message: 'no',
    })
    s = nextThreadState(s, { type: 'reactionStarted', target: '0001' })
    s = nextThreadState(s, { type: 'reactionStarted', target: '0001' })
    s = nextThreadState(s, { type: 'reactionStarted', target: '0002' })
    expect(s.reacting).toEqual(['0001', '0002'])
    expect(s.reactionError).toBeNull()
  })

  it('shows a failure on its target, frees only that target, and changes no reaction', () => {
    let s = apply(INITIAL_THREAD_STATE, withReactions(['0001'], [rx('0001', 'me', 2)]))
    s = nextThreadState(s, { type: 'reactionStarted', target: '0001' })
    s = nextThreadState(s, { type: 'reactionStarted', target: '0002' })
    s = nextThreadState(s, { type: 'reactionFailed', target: '0001', message: 'nope' })
    expect(s.reacting).toEqual(['0002'])
    expect(s.reactionError).toEqual({ target: '0001', message: 'nope' })
    expect(s.reactions).toEqual([rx('0001', 'me', 2)])
  })

  it("applies a saved reaction by replacing the reactor's own on that target only", () => {
    let s = apply(
      INITIAL_THREAD_STATE,
      withReactions(['0001'], [rx('0001', 'me', 2), rx('0001', 'you', 2), rx('0000', 'me', 4)]),
    )
    s = nextThreadState(s, { type: 'reactionStarted', target: '0001' })
    s = nextThreadState(s, { type: 'reactionSaved', target: '0001', reactorUserId: 'me', index: 6 })
    expect(s.reactions).toContainEqual(rx('0001', 'me', 6))
    expect(s.reactions).not.toContainEqual(rx('0001', 'me', 2))
    expect(s.reactions).toContainEqual(rx('0001', 'you', 2))
    expect(s.reactions).toContainEqual(rx('0000', 'me', 4))
    expect(s.reactions).toHaveLength(3)
    expect(s.reacting).toEqual([])
  })

  it('adds a saved reaction when there was none, and clears a stale error', () => {
    let s = nextThreadState(INITIAL_THREAD_STATE, {
      type: 'reactionFailed',
      target: '0001',
      message: 'old',
    })
    s = nextThreadState(s, { type: 'reactionSaved', target: '0001', reactorUserId: 'me', index: 1 })
    expect(s.reactions).toEqual([rx('0001', 'me', 1)])
    expect(s.reactionError).toBeNull()
  })

  it("removes only the reactor's own reaction on that target", () => {
    let s = apply(
      INITIAL_THREAD_STATE,
      withReactions(['0001'], [rx('0001', 'me'), rx('0001', 'you'), rx('0000', 'me')]),
    )
    s = nextThreadState(s, { type: 'reactionStarted', target: '0001' })
    s = nextThreadState(s, { type: 'reactionRemoved', target: '0001', reactorUserId: 'me' })
    expect(s.reactions).toEqual([rx('0001', 'you'), rx('0000', 'me')])
    expect(s.reacting).toEqual([])
  })

  it('does not let a later page undo what this reader just did', () => {
    let s = apply(INITIAL_THREAD_STATE, withReactions(['0001'], [rx('0001', 'me', 2)], 'c'))
    s = nextThreadState(s, { type: 'reactionRemoved', target: '0001', reactorUserId: 'me' })
    s = apply(s, withReactions(['0002'], [rx('0002', 'you')]))
    expect(s.reactions).toEqual([rx('0002', 'you')])
  })
})

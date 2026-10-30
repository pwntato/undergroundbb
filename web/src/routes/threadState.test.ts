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

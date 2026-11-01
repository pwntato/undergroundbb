import { describe, expect, it } from 'vitest'
import {
  INITIAL_POST_CONTROLS_STATE,
  nextPostControlsState,
  type PostControlsEvent,
  type PostControlsState,
} from './postControls'

const run = (events: PostControlsEvent[], from: PostControlsState = INITIAL_POST_CONTROLS_STATE) =>
  events.reduce(nextPostControlsState, from)
const open = (sortKey: string): PostControlsEvent => ({
  type: 'editOpened',
  sortKey,
  title: 't',
  body: 'b',
})

describe('nextPostControlsState', () => {
  it('opens an edit with what the post holds now', () => {
    expect(run([open('P1')]).mode).toEqual({
      kind: 'editing',
      sortKey: 'P1',
      title: 't',
      body: 'b',
    })
  })

  it('does one thing at a time: opening another replaces the first', () => {
    expect(
      run([open('P1'), { type: 'deleteAsked', sortKey: 'P2' }, open('P3')]).mode,
    ).toMatchObject({
      kind: 'editing',
      sortKey: 'P3',
    })
  })

  it('ignores every change while a send is in flight', () => {
    const busy = run([open('P1'), { type: 'started' }])
    for (const e of [
      open('P2'),
      { type: 'deleteAsked', sortKey: 'P2' },
      { type: 'closed' },
    ] as PostControlsEvent[]) {
      expect(nextPostControlsState(busy, e), e.type).toBe(busy)
    }
  })

  it('keeps the form on a failure and says why, and drops the message once the reader closes', () => {
    const failed = run([open('P1'), { type: 'started' }, { type: 'failed', message: 'nope' }])
    expect(failed).toMatchObject({ busy: false, error: 'nope', mode: { kind: 'editing' } })
    expect(nextPostControlsState(failed, { type: 'closed' })).toMatchObject({
      error: null,
      mode: { kind: 'idle' },
    })
  })

  it('closes the form on success', () => {
    expect(
      run([{ type: 'deleteAsked', sortKey: 'P1' }, { type: 'started' }, { type: 'finished' }]),
    ).toEqual(INITIAL_POST_CONTROLS_STATE)
  })

  it('closes a form whose post is not live on the first page, keeping the reason, and not during a send', () => {
    const editing = run([open('P1')])
    expect(
      nextPostControlsState(editing, { type: 'firstPageLoaded', liveKeys: ['P2'] }).mode,
    ).toEqual({
      kind: 'idle',
    })
    expect(nextPostControlsState(editing, { type: 'firstPageLoaded', liveKeys: ['P1'] })).toBe(
      editing,
    )
    const gone = run([open('P1'), { type: 'failed', message: 'it was deleted' }])
    expect(nextPostControlsState(gone, { type: 'firstPageLoaded', liveKeys: [] })).toMatchObject({
      mode: { kind: 'idle' },
      error: 'it was deleted',
    })
    const busy = run([open('P1'), { type: 'started' }])
    expect(nextPostControlsState(busy, { type: 'firstPageLoaded', liveKeys: [] })).toBe(busy)
  })

  it.each<[string, PostControlsEvent]>([
    ['editOpened', open('P2')],
    ['deleteAsked', { type: 'deleteAsked', sortKey: 'P2' }],
    ['closed', { type: 'closed' }],
    ['started', { type: 'started' }],
    ['finished', { type: 'finished' }],
  ])('%s clears the gone mark together with the error', (_name, event) => {
    const gone = run([open('P1'), { type: 'failed', message: 'it was deleted', gone: true }])
    expect(gone).toMatchObject({ gone: true, error: 'it was deleted' })
    expect(nextPostControlsState(gone, event)).toMatchObject({ gone: false, error: null })
  })

  it('keeps a form that holds no error when the first page fails: the reload had another cause', () => {
    const editing = run([open('P1')])
    expect(nextPostControlsState(editing, { type: 'firstPageFailed' })).toBe(editing)
    const asking = run([{ type: 'deleteAsked', sortKey: 'P1' }])
    expect(nextPostControlsState(asking, { type: 'firstPageFailed' })).toBe(asking)
    // Opening another edit clears the mark: after a gone failure whose reload worked and
    // closed the form, a new form must not be closed by a reload it had nothing to do with.
    const reopened = run([
      open('P1'),
      { type: 'failed', message: 'it was deleted', gone: true },
      { type: 'firstPageLoaded', liveKeys: [] },
      open('P2'),
    ])
    expect(reopened).toMatchObject({ mode: { kind: 'editing', sortKey: 'P2' }, error: null })
    expect(nextPostControlsState(reopened, { type: 'firstPageFailed' })).toBe(reopened)
    // A later failure that is not "gone" replaces the mark.
    const goneThenOther = run([
      open('P1'),
      { type: 'failed', message: 'it was deleted', gone: true },
      { type: 'failed', message: "Couldn't save. Try again." },
    ])
    expect(nextPostControlsState(goneThenOther, { type: 'firstPageFailed' })).toBe(goneThenOther)
    // An error that does not say "gone" (a failed save, say) does not close a form either.
    const failedSave = run([open('P1'), { type: 'failed', message: "Couldn't save. Try again." }])
    expect(nextPostControlsState(failedSave, { type: 'firstPageFailed' })).toBe(failedSave)
  })

  it('closes a form when the first page fails to load, keeping the reason, and not during a send', () => {
    const gone = run([open('P1'), { type: 'failed', message: 'it was deleted', gone: true }])
    expect(nextPostControlsState(gone, { type: 'firstPageFailed' })).toMatchObject({
      mode: { kind: 'idle' },
      error: 'it was deleted',
    })
    const asking = run([
      { type: 'deleteAsked', sortKey: 'P1' },
      { type: 'failed', message: 'it was deleted', gone: true },
    ])
    expect(nextPostControlsState(asking, { type: 'firstPageFailed' }).mode).toEqual({
      kind: 'idle',
    })
    const idle = run([])
    expect(nextPostControlsState(idle, { type: 'firstPageFailed' })).toBe(idle)
    // Through events a request in flight has no gone mark (`started` clears it), so build the
    // state by hand to check the busy guard itself.
    const busy: PostControlsState = { ...gone, busy: true }
    expect(busy).toMatchObject({ busy: true, gone: true })
    expect(nextPostControlsState(busy, { type: 'firstPageFailed' })).toBe(busy)
    const started = run([open('P1'), { type: 'started' }])
    expect(nextPostControlsState(started, { type: 'firstPageFailed' })).toBe(started)
  })
})

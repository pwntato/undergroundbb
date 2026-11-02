import { describe, expect, it } from 'vitest'
import {
  INITIAL_CONTROLS_STATE,
  nextControlsState,
  replyOffered,
  type ControlsEvent,
  type ControlsState,
} from './commentControls'

const run = (events: ControlsEvent[], from: ControlsState = INITIAL_CONTROLS_STATE) =>
  events.reduce(nextControlsState, from)

describe('nextControlsState', () => {
  it('opens an edit with the current text as both the draft and the original', () => {
    expect(run([{ type: 'editOpened', path: '0001', text: 'hi' }]).mode).toEqual({
      kind: 'editing',
      path: '0001',
      draft: 'hi',
      original: 'hi',
    })
  })

  it('does one thing at a time: opening another replaces the first and drops its draft', () => {
    const s = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'draftEdited', draft: 'a changed' },
      { type: 'deleteAsked', path: '0002' },
      { type: 'editOpened', path: '0003', text: 'c' },
    ])
    expect(s.mode).toEqual({ kind: 'editing', path: '0003', draft: 'c', original: 'c' })
  })

  it('ignores every change while a send is in flight', () => {
    const editing = run([{ type: 'editOpened', path: '0001', text: 'a' }, { type: 'started' }])
    for (const e of [
      { type: 'draftEdited', draft: 'x' },
      { type: 'editOpened', path: '0002', text: 'b' },
      { type: 'deleteAsked', path: '0002' },
      { type: 'closed' },
    ] as ControlsEvent[]) {
      expect(nextControlsState(editing, e), e.type).toBe(editing)
    }
  })

  it('keeps the form and the draft on a failure, says why, and drops the message once the reader types or closes', () => {
    const failed = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'draftEdited', draft: 'a2' },
      { type: 'started' },
      { type: 'failed', message: 'nope' },
    ])
    expect(failed).toMatchObject({
      busy: false,
      error: 'nope',
      mode: { kind: 'editing', draft: 'a2' },
    })
    expect(nextControlsState(failed, { type: 'draftEdited', draft: 'a3' }).error).toBeNull()
    expect(nextControlsState(failed, { type: 'closed' })).toMatchObject({
      error: null,
      mode: { kind: 'idle' },
    })
  })

  it('closes the form on success', () => {
    const s = run([
      { type: 'deleteAsked', path: '0001' },
      { type: 'started' },
      { type: 'finished' },
    ])
    expect(s).toEqual(INITIAL_CONTROLS_STATE)
  })

  it('turns read-only: closes the form, keeps the reason, and refuses to open an edit again, but still lets a delete ask', () => {
    const s = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'started' },
      { type: 'madeReadOnly', message: 'deleted post' },
    ])
    expect(s).toMatchObject({
      readOnly: true,
      busy: false,
      error: 'deleted post',
      mode: { kind: 'idle' },
    })
    expect(nextControlsState(s, { type: 'editOpened', path: '0002', text: 'b' })).toBe(s)
    expect(nextControlsState(s, { type: 'deleteAsked', path: '0002' }).mode).toEqual({
      kind: 'confirmDelete',
      path: '0002',
    })
  })

  it('keeps a form whose comment is not on the first page while later pages exist (#328)', () => {
    const open = run([{ type: 'editOpened', path: '0090', text: 'a' }])
    expect(
      nextControlsState(open, { type: 'firstPageLoaded', livePaths: ['0001'], hasMore: true }),
    ).toBe(open)
  })

  it('closes a form at the end of the thread when its comment never showed, keeping the reason', () => {
    const open = run([{ type: 'editOpened', path: '0090', text: 'a' }])
    expect(nextControlsState(open, { type: 'endReached', livePaths: ['0001'] }).mode).toEqual({
      kind: 'idle',
    })
    expect(nextControlsState(open, { type: 'endReached', livePaths: ['0090'] })).toBe(open)
    const gone = run([
      { type: 'editOpened', path: '0090', text: 'a' },
      { type: 'failed', message: 'it was deleted' },
    ])
    expect(nextControlsState(gone, { type: 'endReached', livePaths: [] })).toMatchObject({
      mode: { kind: 'idle' },
      error: 'it was deleted',
    })
    const busy = run([{ type: 'editOpened', path: '0090', text: 'a' }, { type: 'started' }])
    expect(nextControlsState(busy, { type: 'endReached', livePaths: [] })).toBe(busy)
  })

  it('closes a form whose comment is not live on the first page, and keeps the reason it was given', () => {
    const open = run([{ type: 'editOpened', path: '0001', text: 'a' }])
    expect(
      nextControlsState(open, { type: 'firstPageLoaded', livePaths: ['0002'], hasMore: false })
        .mode,
    ).toEqual({
      kind: 'idle',
    })
    expect(
      nextControlsState(open, { type: 'firstPageLoaded', livePaths: ['0001'], hasMore: false }),
    ).toBe(open)
    const gone = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'failed', message: 'it was deleted' },
    ])
    expect(
      nextControlsState(gone, { type: 'firstPageLoaded', livePaths: [], hasMore: false }),
    ).toMatchObject({
      mode: { kind: 'idle' },
      error: 'it was deleted',
    })
  })

  it('closes a form when the first page fails to load, keeping the reason, and not during a send', () => {
    const gone = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'failed', message: 'it was deleted', gone: true },
    ])
    expect(nextControlsState(gone, { type: 'firstPageFailed' })).toMatchObject({
      mode: { kind: 'idle' },
      error: 'it was deleted',
    })
    const asking = run([
      { type: 'deleteAsked', path: '0001' },
      { type: 'failed', message: 'it was deleted', gone: true },
    ])
    expect(nextControlsState(asking, { type: 'firstPageFailed' }).mode).toEqual({ kind: 'idle' })
    const idle = run([])
    expect(nextControlsState(idle, { type: 'firstPageFailed' })).toBe(idle)
    // Through events a request in flight has no gone mark (`started` clears it), so build the
    // state by hand to check the busy guard itself.
    const busy: ControlsState = { ...gone, busy: true }
    expect(busy).toMatchObject({ busy: true, gone: true })
    expect(nextControlsState(busy, { type: 'firstPageFailed' })).toBe(busy)
    const started = run([{ type: 'editOpened', path: '0001', text: 'a' }, { type: 'started' }])
    expect(nextControlsState(started, { type: 'firstPageFailed' })).toBe(started)
  })

  it('keeps a form that holds no error when the first page fails: the reload had another cause', () => {
    const typing = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'draftEdited', draft: 'half-typed edit' },
    ])
    expect(nextControlsState(typing, { type: 'firstPageFailed' })).toBe(typing)
    const asking = run([{ type: 'deleteAsked', path: '0001' }])
    expect(nextControlsState(asking, { type: 'firstPageFailed' })).toBe(asking)
    // An error that does not say "gone" (a failed save, say) does not close a form either.
    const failedSave = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'failed', message: "Couldn't save the comment. Try again." },
    ])
    expect(nextControlsState(failedSave, { type: 'firstPageFailed' })).toBe(failedSave)
    // A later failure that is not "gone" replaces the mark; typing clears it with the error.
    const goneThenOther = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'failed', message: 'it was deleted', gone: true },
      { type: 'failed', message: "Couldn't save the comment. Try again." },
    ])
    expect(nextControlsState(goneThenOther, { type: 'firstPageFailed' })).toBe(goneThenOther)
    const goneThenTyped = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'failed', message: 'it was deleted', gone: true },
      { type: 'draftEdited', draft: 'more' },
    ])
    expect(nextControlsState(goneThenTyped, { type: 'firstPageFailed' })).toBe(goneThenTyped)
    // Opening another edit clears the mark: after a gone failure whose reload worked and
    // closed the form, a new form must not be closed by a reload it had nothing to do with.
    const reopened = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'failed', message: 'it was deleted', gone: true },
      { type: 'firstPageLoaded', livePaths: ['0002'], hasMore: false },
      { type: 'editOpened', path: '0002', text: 'b' },
    ])
    expect(reopened).toMatchObject({ mode: { kind: 'editing', path: '0002' }, error: null })
    expect(nextControlsState(reopened, { type: 'firstPageFailed' })).toBe(reopened)
    // Typing clears an older error, so a draft is never closed because of a stale one.
    const typedAfterError = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'failed', message: 'busy' },
      { type: 'draftEdited', draft: 'more' },
    ])
    expect(nextControlsState(typedAfterError, { type: 'firstPageFailed' })).toBe(typedAfterError)
  })

  it.each<[string, ControlsEvent]>([
    ['editOpened', { type: 'editOpened', path: '0002', text: 'b' }],
    ['draftEdited', { type: 'draftEdited', draft: 'more' }],
    ['deleteAsked', { type: 'deleteAsked', path: '0002' }],
    ['closed', { type: 'closed' }],
    ['started', { type: 'started' }],
    ['finished', { type: 'finished' }],
    ['madeReadOnly', { type: 'madeReadOnly', message: null }],
  ])('%s clears the gone mark together with the error', (_name, event) => {
    const gone = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'failed', message: 'it was deleted', gone: true },
    ])
    expect(gone).toMatchObject({ gone: true, error: 'it was deleted' })
    expect(nextControlsState(gone, event)).toMatchObject({ gone: false, error: null })
  })

  it('does not close a form during a send, since the answer is still coming', () => {
    const busy = run([{ type: 'editOpened', path: '0001', text: 'a' }, { type: 'started' }])
    expect(
      nextControlsState(busy, { type: 'firstPageLoaded', livePaths: [], hasMore: false }),
    ).toBe(busy)
  })
})

describe('replyOffered', () => {
  it('offers the reply box unless the thread was not found or turned read-only', () => {
    expect(replyOffered(null, false)).toBe(true)
    expect(replyOffered('failed', false)).toBe(true)
    expect(replyOffered('notFound', false)).toBe(false)
    expect(replyOffered(null, true)).toBe(false)
  })
})

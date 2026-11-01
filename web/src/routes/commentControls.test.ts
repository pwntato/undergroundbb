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

  it('closes a form whose comment is not live on the first page, and keeps the reason it was given', () => {
    const open = run([{ type: 'editOpened', path: '0001', text: 'a' }])
    expect(nextControlsState(open, { type: 'firstPageLoaded', livePaths: ['0002'] }).mode).toEqual({
      kind: 'idle',
    })
    expect(nextControlsState(open, { type: 'firstPageLoaded', livePaths: ['0001'] })).toBe(open)
    const gone = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'failed', message: 'it was deleted' },
    ])
    expect(nextControlsState(gone, { type: 'firstPageLoaded', livePaths: [] })).toMatchObject({
      mode: { kind: 'idle' },
      error: 'it was deleted',
    })
  })

  it('closes a form when the first page fails to load, keeping the reason, and not during a send', () => {
    const gone = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'failed', message: 'it was deleted' },
    ])
    expect(nextControlsState(gone, { type: 'firstPageFailed' })).toMatchObject({
      mode: { kind: 'idle' },
      error: 'it was deleted',
    })
    const asking = run([
      { type: 'deleteAsked', path: '0001' },
      { type: 'failed', message: 'it was deleted' },
    ])
    expect(nextControlsState(asking, { type: 'firstPageFailed' }).mode).toEqual({ kind: 'idle' })
    const idle = run([])
    expect(nextControlsState(idle, { type: 'firstPageFailed' })).toBe(idle)
    const busy = run([{ type: 'editOpened', path: '0001', text: 'a' }, { type: 'started' }])
    expect(nextControlsState(busy, { type: 'firstPageFailed' })).toBe(busy)
  })

  it('keeps a form that holds no error when the first page fails: the reload had another cause', () => {
    const typing = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'draftEdited', draft: 'half-typed edit' },
    ])
    expect(nextControlsState(typing, { type: 'firstPageFailed' })).toBe(typing)
    const asking = run([{ type: 'deleteAsked', path: '0001' }])
    expect(nextControlsState(asking, { type: 'firstPageFailed' })).toBe(asking)
    // Typing clears an older error, so a draft is never closed because of a stale one.
    const typedAfterError = run([
      { type: 'editOpened', path: '0001', text: 'a' },
      { type: 'failed', message: 'busy' },
      { type: 'draftEdited', draft: 'more' },
    ])
    expect(nextControlsState(typedAfterError, { type: 'firstPageFailed' })).toBe(typedAfterError)
  })

  it('does not close a form during a send, since the answer is still coming', () => {
    const busy = run([{ type: 'editOpened', path: '0001', text: 'a' }, { type: 'started' }])
    expect(nextControlsState(busy, { type: 'firstPageLoaded', livePaths: [] })).toBe(busy)
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

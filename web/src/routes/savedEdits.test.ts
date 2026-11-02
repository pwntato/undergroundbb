import { describe, expect, it } from 'vitest'
import {
  INITIAL_CONTROLS_STATE,
  nextControlsState,
  type ControlMode,
  type ControlsEvent,
} from './commentControls'
import {
  INITIAL_POST_CONTROLS_STATE,
  nextPostControlsState,
  type PostControlMode,
  type PostControlsEvent,
} from './postControls'
import { restoredCommentControls, restoredPostControls, snapshotEdits } from './savedEdits'

const IDLE: ControlMode = { kind: 'idle' }
const POST_IDLE: PostControlMode = { kind: 'idle' }
const commentEditing: ControlMode = { kind: 'editing', path: '0001', draft: 'new', original: 'old' }
const postEditing: PostControlMode = {
  kind: 'editing',
  sortKey: 'POST#2026-10-28#00112233445566ff',
  title: 'T',
  body: 'B',
  draft: { title: 'T2', body: 'B2' },
}

describe('snapshotEdits', () => {
  it('keeps nothing when no edit form is open', () => {
    expect(snapshotEdits('P', IDLE, POST_IDLE)).toBeUndefined()
    expect(snapshotEdits('P', undefined, POST_IDLE)).toBeUndefined()
  })

  it('does not keep a delete question, which is one press away', () => {
    expect(
      snapshotEdits(
        'P',
        { kind: 'confirmDelete', path: '0001' },
        {
          kind: 'confirmDelete',
          sortKey: 'POST#2026-10-28#00112233445566ff',
        },
      ),
    ).toBeUndefined()
  })

  it('keeps each open edit form, alone or together, with the scope they hang on', () => {
    expect(snapshotEdits('P', commentEditing, POST_IDLE)).toEqual({
      scope: 'P',
      comment: commentEditing,
    })
    expect(snapshotEdits('P', IDLE, postEditing)).toEqual({ scope: 'P', post: postEditing })
    expect(snapshotEdits('P', commentEditing, postEditing)).toEqual({
      scope: 'P',
      comment: commentEditing,
      post: postEditing,
    })
  })
})

describe('restoredCommentControls and restoredPostControls', () => {
  const saved = snapshotEdits('P', commentEditing, postEditing)

  it('start idle and empty when nothing was saved', () => {
    expect(restoredCommentControls(undefined, 'P')).toBe(INITIAL_CONTROLS_STATE)
    expect(restoredPostControls(undefined, 'P')).toBe(INITIAL_POST_CONTROLS_STATE)
  })

  it('bring back the open form with its text, not busy and with no message', () => {
    expect(restoredCommentControls(saved, 'P')).toEqual({
      ...INITIAL_CONTROLS_STATE,
      mode: commentEditing,
    })
    expect(restoredPostControls(saved, 'P')).toEqual({
      ...INITIAL_POST_CONTROLS_STATE,
      mode: postEditing,
    })
  })

  it('bring back only the form that was open', () => {
    const onlyPost = snapshotEdits('P', IDLE, postEditing)
    expect(restoredCommentControls(onlyPost, 'P')).toBe(INITIAL_CONTROLS_STATE)
    const onlyComment = snapshotEdits('P', commentEditing, POST_IDLE)
    expect(restoredPostControls(onlyComment, 'P')).toBe(INITIAL_POST_CONTROLS_STATE)
  })

  it('are not used for any other subject', () => {
    expect(restoredCommentControls(saved, 'Q')).toBe(INITIAL_CONTROLS_STATE)
    expect(restoredPostControls(saved, 'Q')).toBe(INITIAL_POST_CONTROLS_STATE)
  })
})

describe('an edit across the password step, with the real reducers', () => {
  const runComment = (events: ControlsEvent[]) =>
    events.reduce(nextControlsState, INITIAL_CONTROLS_STATE)
  const runPost = (events: PostControlsEvent[]) =>
    events.reduce(nextPostControlsState, INITIAL_POST_CONTROLS_STATE)

  it('brings a comment edit back with what was typed, ready to save', () => {
    const before = runComment([
      { type: 'editOpened', path: '0001', text: 'old' },
      { type: 'draftEdited', draft: 'old, edited' },
      { type: 'started' },
      { type: 'failed', message: 'This tab needs your password again.' },
    ])
    const after = restoredCommentControls(snapshotEdits('P', before.mode, POST_IDLE), 'P')
    expect(after.mode).toEqual({
      kind: 'editing',
      path: '0001',
      draft: 'old, edited',
      original: 'old',
    })
    expect(after).toMatchObject({ busy: false, error: null })
  })

  it('brings a post edit back with what was typed, still compared against the original', () => {
    const sortKey = 'POST#2026-10-28#00112233445566ff'
    const before = runPost([
      { type: 'editOpened', sortKey, title: 'T', body: 'B' },
      { type: 'draftEdited', title: 'T', body: 'B and more' },
    ])
    const after = restoredPostControls(snapshotEdits('P', undefined, before.mode), 'P')
    expect(after.mode).toEqual({
      kind: 'editing',
      sortKey,
      title: 'T',
      body: 'B',
      draft: { title: 'T', body: 'B and more' },
    })
  })

  it('closes a restored form whose comment or post was deleted while the password was asked', () => {
    const commentBack = restoredCommentControls(snapshotEdits('P', commentEditing, POST_IDLE), 'P')
    expect(
      nextControlsState(commentBack, { type: 'firstPageLoaded', livePaths: ['0002'] }).mode,
    ).toEqual(IDLE)
    const postBack = restoredPostControls(snapshotEdits('P', undefined, postEditing), 'P')
    expect(nextPostControlsState(postBack, { type: 'firstPageLoaded', liveKeys: [] }).mode).toEqual(
      POST_IDLE,
    )
  })

  it('does not bring back an edit that was saved: the form closed, so the next snapshot is empty', () => {
    const saved = runPost([
      { type: 'editOpened', sortKey: 'P1', title: 'T', body: 'B' },
      { type: 'draftEdited', title: 'T2', body: 'B' },
      { type: 'started' },
      { type: 'finished' },
    ])
    expect(snapshotEdits('P', undefined, saved.mode)).toBeUndefined()
  })
})

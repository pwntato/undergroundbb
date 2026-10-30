import { describe, expect, it } from 'vitest'
import {
  INITIAL_REPLY_STATE,
  nextReplyState,
  TARGET_GONE_MESSAGE,
  type ReplyEvent,
  type ReplyState,
} from './replyState'
import { attachParent, guessPath } from './runCreateComment'

const typed: ReplyState = { ...INITIAL_REPLY_STATE, draft: 'half a thought' }

describe('nextReplyState', () => {
  it('keeps the draft when the box moves to another comment or to the bottom', () => {
    const under = nextReplyState(typed, { type: 'opened', replyTo: '0001' })
    expect(under).toMatchObject({ replyTo: '0001', draft: 'half a thought' })
    expect(nextReplyState(under, { type: 'opened', replyTo: '0002.0001' }).draft).toBe(
      'half a thought',
    )
    expect(nextReplyState(under, { type: 'opened', replyTo: null })).toMatchObject({
      replyTo: null,
      draft: 'half a thought',
    })
  })

  it('drops the last error or notice when the box moves or the text changes', () => {
    const failed = nextReplyState(typed, { type: 'sendFailed', error: 'nope' })
    expect(failed.error).toBe('nope')
    expect(nextReplyState(failed, { type: 'edited', draft: 'x' }).error).toBeNull()
    expect(nextReplyState(failed, { type: 'opened', replyTo: '0001' }).error).toBeNull()
    const sent = nextReplyState(typed, { type: 'sent', notice: 'Comment sent.' })
    expect(nextReplyState(sent, { type: 'edited', draft: 'next' }).notice).toBeNull()
  })

  it('ignores edits and moves while a send is in flight', () => {
    const sending = nextReplyState({ ...typed, replyTo: '0001' }, { type: 'sendStarted' })
    expect(sending.sending).toBe(true)
    expect(nextReplyState(sending, { type: 'edited', draft: 'other' })).toBe(sending)
    expect(nextReplyState(sending, { type: 'opened', replyTo: null })).toBe(sending)
  })

  it('keeps the draft and the target after a failed send so it can be pressed again', () => {
    const sending = nextReplyState({ ...typed, replyTo: '0001' }, { type: 'sendStarted' })
    expect(nextReplyState(sending, { type: 'sendFailed', error: 'e' })).toEqual({
      replyTo: '0001',
      draft: 'half a thought',
      sending: false,
      error: 'e',
      notice: null,
    })
  })

  it('clears the draft and closes the inline box after a send', () => {
    const sending = nextReplyState({ ...typed, replyTo: '0001' }, { type: 'sendStarted' })
    expect(nextReplyState(sending, { type: 'sent', notice: 'Comment sent.' })).toEqual({
      replyTo: null,
      draft: '',
      sending: false,
      error: null,
      notice: 'Comment sent.',
    })
  })
})

describe('firstPageLoaded', () => {
  const run = (events: ReplyEvent[], from: ReplyState = INITIAL_REPLY_STATE) =>
    events.reduce(nextReplyState, from)

  it('after parent_gone, drops the gone target, keeps the draft and sends as top-level', () => {
    // The sequence the reviewer reproduced: open 0001, type, send, the parent is gone, reload.
    const failed = run([
      { type: 'opened', replyTo: '0001' },
      { type: 'edited', draft: 'my reply' },
      { type: 'sendStarted' },
      { type: 'sendFailed', error: TARGET_GONE_MESSAGE },
    ])
    expect(failed.replyTo).toBe('0001')
    const reloaded = nextReplyState(failed, { type: 'firstPageLoaded', paths: ['0002'] })
    expect(reloaded).toMatchObject({ replyTo: null, draft: 'my reply', error: TARGET_GONE_MESSAGE })
    // The next Send aims at the top level, not under the gone comment.
    expect(guessPath(attachParent(reloaded.replyTo), ['0002'])).toBe('0003')
  })

  it('drops a restored target that is on a later page', () => {
    const restored: ReplyState = { ...INITIAL_REPLY_STATE, replyTo: '0060', draft: 'typed before' }
    expect(
      nextReplyState(restored, { type: 'firstPageLoaded', paths: ['0001', '0002'] }),
    ).toMatchObject({ replyTo: null, draft: 'typed before', error: TARGET_GONE_MESSAGE })
  })

  it('keeps a target that is on the page, and leaves a top-level box alone', () => {
    const under: ReplyState = { ...INITIAL_REPLY_STATE, replyTo: '0001', draft: 'x' }
    expect(nextReplyState(under, { type: 'firstPageLoaded', paths: ['0001'] })).toBe(under)
    expect(nextReplyState(typed, { type: 'firstPageLoaded', paths: [] })).toBe(typed)
  })

  it('does not move the target under a send in flight', () => {
    const sending = run([{ type: 'opened', replyTo: '0001' }, { type: 'sendStarted' }])
    expect(nextReplyState(sending, { type: 'firstPageLoaded', paths: [] })).toBe(sending)
  })
})

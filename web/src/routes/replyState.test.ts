import { describe, expect, it } from 'vitest'
import { INITIAL_REPLY_STATE, nextReplyState, type ReplyState } from './replyState'

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

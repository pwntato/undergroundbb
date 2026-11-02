import { describe, expect, it } from 'vitest'
import { SEND_ERRORS } from './runCreatePost'
import { CLOCK_SKEW_MESSAGE } from './replyState'

describe('CreatePostScreen messages', () => {
  it("tells the writer this device's clock looks wrong when the post day is refused", () => {
    expect(SEND_ERRORS.clockSkew).toBe(CLOCK_SKEW_MESSAGE)
  })
})

import { describe, expect, it } from 'vitest'
import { COMMENT_ENVELOPE_BYTES, decodeComment, encodeComment } from './comment'

const AT = '2026-10-30T12:34:56.789Z'

describe('comment plaintext layout', () => {
  it('round-trips text, including multi-byte characters and the empty comment', () => {
    for (const text of ['hello', 'héllo ✓ 日本', '']) {
      expect(decodeComment(encodeComment({ text, at: AT }))).toEqual({ text, at: AT })
    }
  })

  it('adds exactly the documented envelope', () => {
    expect(encodeComment({ text: '', at: AT }).length).toBe(COMMENT_ENVELOPE_BYTES)
    expect(COMMENT_ENVELOPE_BYTES).toBe(33)
    expect(encodeComment({ text: 'abc', at: AT }).length).toBe(33 + 3)
  })

  it('refuses a time that is not RFC 3339 UTC with milliseconds', () => {
    expect(() => encodeComment({ text: 'x', at: '2026-10-30T12:34:56Z' })).toThrow()
  })

  it('refuses every deviation from the layout instead of guessing', () => {
    const good = encodeComment({ text: 'hi', at: AT })
    const bad: Record<string, Uint8Array> = {
      empty: new Uint8Array(0),
      'wrong version': Uint8Array.from(good, (b, i) => (i === 0 ? 2 : b)),
      truncated: good.subarray(0, good.length - 1),
      trailing: Uint8Array.from([...good, 0]),
      'length past the end': Uint8Array.from(good, (b, i) => (i === 4 ? 0xff : b)),
      'invalid utf-8': Uint8Array.from(good, (b, i) => (i === 5 ? 0xff : b)),
    }
    for (const [name, bytes] of Object.entries(bad)) {
      expect(() => decodeComment(bytes), name).toThrow()
    }
  })
})

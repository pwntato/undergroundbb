import { describe, expect, it } from 'vitest'
import { COMMENT_ENVELOPE_BYTES, decodeComment, encodeComment } from './comment'
import { EDITED_AT_BYTES } from './post'

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

const EDITED = '2026-10-31T08:00:00.000Z'
const ascii = (t: string) => [...t].map((c) => c.charCodeAt(0))

describe('edited comment layout (version 2, #45)', () => {
  it('has a fixed layout: version 2, text, at, then edited_at', () => {
    expect([...encodeComment({ text: 'hi', at: AT, editedAt: EDITED })]).toEqual([
      2,
      ...[0, 0, 0, 2, ...ascii('hi')],
      ...[0, 0, 0, 24, ...ascii(AT)],
      ...[0, 0, 0, 24, ...ascii(EDITED)],
    ])
  })

  it('round-trips, and a comment with no editedAt stays version 1', () => {
    const edited = { text: 'héllo ✓', at: AT, editedAt: EDITED }
    expect(decodeComment(encodeComment(edited))).toEqual(edited)
    const plain = encodeComment({ text: 'x', at: AT })
    expect(plain[0]).toBe(1)
    expect('editedAt' in decodeComment(plain)).toBe(false)
  })

  it('costs exactly the 28 bytes the server allows an edit', () => {
    expect(
      encodeComment({ text: 'abc', at: AT, editedAt: EDITED }).length -
        encodeComment({ text: 'abc', at: AT }).length,
    ).toBe(EDITED_AT_BYTES)
  })

  it('refuses a malformed editedAt, and never reads one version as the other', () => {
    expect(() => encodeComment({ text: 'x', at: AT, editedAt: '2026-10-31T08:00:00Z' })).toThrow()
    const v1 = encodeComment({ text: 'hi', at: AT })
    const v2 = encodeComment({ text: 'hi', at: AT, editedAt: EDITED })
    const badTime = Uint8Array.from(v2)
    badTime[badTime.length - 1] = 0x58
    for (const bytes of [
      badTime,
      Uint8Array.from(v1, (b, i) => (i === 0 ? 2 : b)),
      Uint8Array.from(v2, (b, i) => (i === 0 ? 1 : b)),
      Uint8Array.from(v2, (b, i) => (i === 0 ? 3 : b)),
      new Uint8Array([...v2, 0]),
      v2.subarray(0, v2.length - 1),
    ]) {
      expect(() => decodeComment(bytes)).toThrow()
    }
  })
})

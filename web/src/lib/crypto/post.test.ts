import { describe, expect, it } from 'vitest'
import {
  decodePost,
  encodePost,
  GCM_TAG_BYTES,
  POST_ENVELOPE_BYTES,
  postCiphertextLength,
  SERVER_ENVELOPE_ALLOWANCE,
  utf8Length,
} from './post.js'

const AT = '2026-10-28T12:34:56.789Z'

describe('post plaintext layout', () => {
  it('round-trips, including non-ASCII and empty fields', () => {
    for (const [title, body] of [
      ['Hello', 'First post'],
      ['日本語のタイトル', 'emoji 🎉 and\nnewlines\u0000and a NUL'],
      ['', ''],
    ] as const) {
      expect(decodePost(encodePost({ title, body, at: AT }))).toEqual({ title, body, at: AT })
    }
  })

  it('has a fixed layout (changing it strands every stored post)', () => {
    const bytes = encodePost({ title: 'ab', body: 'c', at: AT })
    expect([...bytes.subarray(0, 12)]).toEqual([1, 0, 0, 0, 2, 97, 98, 0, 0, 0, 1, 99])
    expect(bytes.length).toBe(POST_ENVELOPE_BYTES + 3)
  })

  it('keeps the ciphertext within the server allowance whatever the content', () => {
    // NUL and quote bytes are the ones JSON would have inflated.
    const title = '\u0000"\\'.repeat(10)
    const body = '\u0001\n\t"'.repeat(100)
    const t = utf8Length(title)
    const b = utf8Length(body)
    const len = encodePost({ title, body, at: AT }).length + GCM_TAG_BYTES
    expect(len).toBe(postCiphertextLength(t, b))
    expect(len).toBeLessThanOrEqual(t + b + SERVER_ENVELOPE_ALLOWANCE)
  })

  it('counts bytes, not characters', () => {
    expect(utf8Length('é')).toBe(2)
    expect(utf8Length('日')).toBe(3)
    expect(utf8Length('🎉')).toBe(4)
  })

  it('refuses a malformed time on the way in', () => {
    expect(() => encodePost({ title: 'a', body: 'b', at: '2026-10-28' })).toThrow()
    expect(() => encodePost({ title: 'a', body: 'b', at: '2026-10-28T12:34:56Z' })).toThrow()
  })

  it('refuses anything that deviates from the layout on the way out', () => {
    const good = encodePost({ title: 'a', body: 'b', at: AT })
    const wrongVersion = Uint8Array.from(good)
    wrongVersion[0] = 2
    const trailing = new Uint8Array([...good, 0])
    const lengthPastEnd = Uint8Array.from(good)
    lengthPastEnd[4] = 200
    const badUtf8 = Uint8Array.from(good)
    badUtf8[5] = 0xff
    const badTime = encodePost({ title: 'a', body: 'b', at: AT })
    badTime[badTime.length - 1] = 0x58
    for (const bad of [
      new Uint8Array(),
      good.subarray(0, 8),
      wrongVersion,
      trailing,
      lengthPastEnd,
      badUtf8,
      badTime,
    ]) {
      expect(() => decodePost(bad)).toThrow()
    }
  })
})

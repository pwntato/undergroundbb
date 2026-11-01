import { describe, expect, it } from 'vitest'
import {
  decodePost,
  EDITED_AT_BYTES,
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

const EDITED = '2026-10-30T09:12:00.000Z'
const ascii = (t: string) => [...t].map((c) => c.charCodeAt(0))

describe('edited post layout (version 2, #45)', () => {
  it('has a fixed layout: version 2, the three fields, then edited_at', () => {
    const bytes = encodePost({ title: 'ab', body: 'c', at: AT, editedAt: EDITED })
    expect([...bytes]).toEqual([
      2,
      ...[0, 0, 0, 2, ...ascii('ab')],
      ...[0, 0, 0, 1, ...ascii('c')],
      ...[0, 0, 0, 24, ...ascii(AT)],
      ...[0, 0, 0, 24, ...ascii(EDITED)],
    ])
  })

  it('round-trips, and a post with no editedAt stays version 1', () => {
    const edited = { title: 'T', body: 'é\n🎉', at: AT, editedAt: EDITED }
    expect(decodePost(encodePost(edited))).toEqual(edited)
    const plain = encodePost({ title: 'T', body: 'b', at: AT })
    expect(plain[0]).toBe(1)
    expect('editedAt' in decodePost(plain)).toBe(false)
  })

  it('costs exactly the 28 bytes the server allows an edit', () => {
    expect(EDITED_AT_BYTES).toBe(28)
    const v1 = encodePost({ title: 'ab', body: 'c', at: AT })
    const v2 = encodePost({ title: 'ab', body: 'c', at: AT, editedAt: EDITED })
    expect(v2.length - v1.length).toBe(EDITED_AT_BYTES)
    // handlers.postEditCiphertextLimit = postCiphertextLimit + editedAtOverhead (28).
    expect(v2.length + GCM_TAG_BYTES).toBeLessThanOrEqual(
      utf8Length('ab') + utf8Length('c') + SERVER_ENVELOPE_ALLOWANCE + 28,
    )
  })

  it('refuses a malformed editedAt on the way in and on the way out', () => {
    expect(() => encodePost({ title: 'a', body: 'b', at: AT, editedAt: '2026-10-30' })).toThrow()
    const bad = encodePost({ title: 'a', body: 'b', at: AT, editedAt: EDITED })
    bad[bad.length - 1] = 0x58
    expect(() => decodePost(bad)).toThrow()
  })

  it('never reads one version as the other', () => {
    const v1 = encodePost({ title: 'a', body: 'b', at: AT })
    const v2 = encodePost({ title: 'a', body: 'b', at: AT, editedAt: EDITED })
    // Version 1 bytes labelled 2 are one field short; version 2 bytes labelled 1 have one too many.
    expect(() => decodePost(Uint8Array.from(v1, (b, i) => (i === 0 ? 2 : b)))).toThrow()
    expect(() => decodePost(Uint8Array.from(v2, (b, i) => (i === 0 ? 1 : b)))).toThrow()
    expect(() => decodePost(Uint8Array.from(v2, (b, i) => (i === 0 ? 3 : b)))).toThrow()
    expect(() => decodePost(new Uint8Array([...v2, 0]))).toThrow()
    expect(() => decodePost(v2.subarray(0, v2.length - 1))).toThrow()
  })
})

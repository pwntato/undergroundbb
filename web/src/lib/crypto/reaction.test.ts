import { describe, expect, it } from 'vitest'
import {
  decodeReaction,
  encodeReaction,
  REACTION_CIPHERTEXT_BYTES,
  REACTION_PLAINTEXT_BYTES,
  REACTIONS,
  reactionOf,
} from './reaction'

// The table is a wire format: these are the stored meanings and must never change.
// Add a row for a new reaction; never edit or remove one.
const PINNED: readonly (readonly [number, string, string])[] = [
  [1, '1f44d', 'Thumbs up'],
  [2, '2764-fe0f', 'Heart'],
  [3, '1f602', 'Laughing'],
  [4, '1f62e', 'Surprised'],
  [5, '1f622', 'Sad'],
  [6, '1f389', 'Celebrate'],
  [7, '1f621', 'Angry'],
]

const codePoints = (s: string) => [...s].map((c) => (c.codePointAt(0) ?? 0).toString(16)).join('-')

describe('reaction table', () => {
  it('pins every index to its code points and label', () => {
    expect(REACTIONS.map((r) => [r.index, codePoints(r.emoji), r.label])).toEqual(PINNED)
  })

  it('has no index 0, no gaps and no repeats', () => {
    const indexes = REACTIONS.map((r) => r.index)
    expect(indexes).toEqual(indexes.map((_, i) => i + 1))
    expect(new Set(REACTIONS.map((r) => r.emoji)).size).toBe(REACTIONS.length)
    expect(reactionOf(0)).toBeUndefined()
  })

  it('does not know bytes past the table', () => {
    expect(reactionOf(REACTIONS.length + 1)).toBeUndefined()
    expect(reactionOf(255)).toBeUndefined()
    expect(reactionOf(-1)).toBeUndefined()
  })

  it('seals to a fixed size: one byte plus the 16-byte tag', () => {
    expect(REACTION_PLAINTEXT_BYTES).toBe(1)
    expect(REACTION_CIPHERTEXT_BYTES).toBe(REACTION_PLAINTEXT_BYTES + 16)
  })
})

describe('reaction plaintext', () => {
  it('round-trips every reaction as a single byte', () => {
    for (const r of REACTIONS) {
      const bytes = encodeReaction(r.index)
      expect(Array.from(bytes)).toEqual([r.index])
      expect(decodeReaction(bytes)).toBe(r.index)
    }
  })

  it('refuses to encode 0 or an unknown index', () => {
    for (const bad of [0, REACTIONS.length + 1, 255, -1, 1.5]) {
      expect(() => encodeReaction(bad)).toThrow()
    }
  })

  it('refuses to decode 0, an unknown byte, or the wrong length', () => {
    for (const bad of [[0], [REACTIONS.length + 1], [255], [], [1, 1], [1, 0]]) {
      expect(() => decodeReaction(new Uint8Array(bad))).toThrow()
    }
  })
})
